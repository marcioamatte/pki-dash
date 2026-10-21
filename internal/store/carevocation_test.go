package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func inter(t *testing.T, s *Store, root, name string) string {
	t.Helper()
	return mustCA(t, s, CA{Name: name, Kind: KindIntermediate, ParentID: root, CertPEM: []byte("c"), KeyBlob: []byte("k"),
		NotBefore: time.Unix(1000, 0), NotAfter: time.Unix(1500, 0)})
}

func TestRevokeCA(t *testing.T) {
	s := open(t)
	rootID := mustCA(t, s, root("Root"))
	a, b := inter(t, s, rootID, "Inter A"), inter(t, s, rootID, "Inter B")
	at := time.Unix(1_800_000_000, 0)

	got, err := s.RevokeCA(ctx, "admin", a, 2, at) // cACompromise is allowed for a CA
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked() || !got.RevokedAt.Equal(at) || got.RevocationReason != 2 {
		t.Fatalf("returned = %+v", got)
	}
	if ca, _ := s.GetCA(ctx, a); !ca.Revoked() || ca.RevocationReason != 2 {
		t.Fatalf("stored = %+v", ca)
	}
	if ca, _ := s.GetCA(ctx, b); ca.Revoked() {
		t.Fatal("revoking one intermediate must not touch its sibling")
	}
	if ca, _ := s.GetCA(ctx, rootID); ca.Revoked() {
		t.Fatal("nor the Root")
	}

	if _, err := s.RevokeCA(ctx, "admin", a, 1, at); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("again: %v", err)
	}
	if ca, _ := s.GetCA(ctx, a); ca.RevocationReason != 2 {
		t.Fatal("a second attempt must not change the reason")
	}
	if _, err := s.RevokeCA(ctx, "admin", rootID, 1, at); !errors.Is(err, ErrNotIntermediate) {
		t.Fatalf("a Root: %v", err)
	}
	if _, err := s.RevokeCA(ctx, "admin", "ghost", 1, at); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	for _, bad := range []int{6, 8, 99, -1} {
		if _, err := s.RevokeCA(ctx, "admin", b, bad, at); !errors.Is(err, ErrInvalid) {
			t.Errorf("reason %d: %v", bad, err)
		}
	}
	if ca, _ := s.GetCA(ctx, b); ca.Revoked() {
		t.Fatal("a refused revocation must leave the CA in good standing")
	}

	kids, err := s.Children(ctx, rootID)
	if err != nil || len(kids) != 2 {
		t.Fatalf("children = %v, %v", kids, err)
	}
	revoked := 0
	for _, k := range kids {
		if k.Revoked() {
			revoked++
		}
	}
	if revoked != 1 {
		t.Fatalf("%d revoked children", revoked)
	}
	es, _ := s.Audit(ctx, 20)
	found := false
	for _, e := range es {
		found = found || (e.Action == "ca.revoke" && e.Target == a)
	}
	if !found {
		t.Fatal("must be audited")
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPutImportedCRL(t *testing.T) {
	s := open(t)
	rootID := mustCA(t, s, root("Root"))
	a := inter(t, s, rootID, "Inter A")
	in := func(n int64, this int64) ImportedCRL {
		return ImportedCRL{Number: n, ThisUpdate: time.Unix(this, 0), NextUpdate: time.Unix(this+1000, 0), RevokedCount: 1, DER: []byte("der")}
	}
	accept := func(*ImportedCRL, []CA) error { return nil }

	// Nothing yet.
	if _, err := s.GetImportedCRL(ctx, rootID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before: %v", err)
	}
	var seenPrev *ImportedCRL
	var seenKids int
	got, err := s.PutImportedCRL(ctx, "admin", rootID, in(7, 5000), func(prev *ImportedCRL, kids []CA) error {
		seenPrev, seenKids = prev, len(kids)
		return nil
	})
	if err != nil || got.Number != 7 || got.CAID != rootID {
		t.Fatalf("first import = %+v, %v", got, err)
	}
	if seenPrev != nil || seenKids != 1 {
		t.Fatalf("check saw prev=%v children=%d", seenPrev, seenKids)
	}

	// The check sees what is already there, and a refusal changes nothing.
	_, err = s.PutImportedCRL(ctx, "admin", rootID, in(8, 6000), func(prev *ImportedCRL, _ []CA) error {
		if prev == nil || prev.Number != 7 {
			t.Errorf("prev = %+v", prev)
		}
		return errors.New("refused")
	})
	if err == nil {
		t.Fatal("expected the refusal to propagate")
	}
	if cur, _ := s.GetImportedCRL(ctx, rootID); cur.Number != 7 {
		t.Fatalf("a refused import must leave the list alone: %+v", cur)
	}

	// A CRL without a number (cfssl's) is stored as such.
	if _, err := s.PutImportedCRL(ctx, "admin", rootID, in(0, 7000), accept); err != nil {
		t.Fatal(err)
	}
	if cur, _ := s.GetImportedCRL(ctx, rootID); cur.Number != 0 || !cur.ThisUpdate.Equal(time.Unix(7000, 0)) || string(cur.DER) != "der" {
		t.Fatalf("stored = %+v", cur)
	}

	// Only a Root has one, and it must exist.
	if _, err := s.PutImportedCRL(ctx, "admin", a, in(1, 1), accept); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an intermediate: %v", err)
	}
	if _, err := s.PutImportedCRL(ctx, "admin", "ghost", in(1, 1), accept); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}

	// What gets served: the imported list for a Root, the generated one for an intermediate.
	pub, err := s.GetPublishedCRL(ctx, rootID)
	if err != nil || !pub.Imported || string(pub.DER) != "der" {
		t.Fatalf("root published = %+v, %v", pub, err)
	}
	if _, err := s.GetPublishedCRL(ctx, a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nothing for an intermediate yet: %v", err)
	}
	s.PutNextCRL(ctx, "system", a, func(n int64, _ []RevokedEntry) ([]byte, time.Time, time.Time, error) {
		return []byte("generated"), time.Unix(1, 0), time.Unix(2, 0), nil
	})
	if pub, err := s.GetPublishedCRL(ctx, a); err != nil || pub.Imported || string(pub.DER) != "generated" {
		t.Fatalf("intermediate published = %+v, %v", pub, err)
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeFromSchemaV4KeepsCAsInGoodStanding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v4.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := raw.Exec(migrations[i]); err != nil {
			t.Fatal(err)
		}
	}
	raw.Exec(`PRAGMA user_version = 4`)
	raw.Exec(`INSERT INTO cas (id,name,kind,cert_pem,not_before,not_after,created_at) VALUES ('r','Root','root',x'01',0,1,0)`)
	raw.Exec(`INSERT INTO cas (id,name,kind,parent_id,cert_pem,not_before,not_after,created_at) VALUES ('i','Inter','intermediate','r',x'01',0,1,0)`)
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer s.Close()
	c, _ := s.GetCA(ctx, "i")
	if c.Revoked() || c.RevocationReason != 0 {
		t.Fatalf("an existing CA must stay in good standing: %+v", c)
	}
	if _, err := s.RevokeCA(ctx, "admin", "i", 5, time.Now()); err != nil {
		t.Fatalf("revoking after the upgrade: %v", err)
	}
}
