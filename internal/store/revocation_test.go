package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func issued(t *testing.T, s *Store, caID, cn, serial string) string {
	t.Helper()
	id, err := s.AddCertificate(ctx, "ops", Certificate{
		CAID: caID, Serial: serial, CommonName: cn, SANs: []string{cn}, Profile: "server", CertPEM: []byte("pem"),
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRevokeCertificate(t *testing.T) {
	s := open(t)
	ca := mustCA(t, s, root("Root"))
	id := issued(t, s, ca, "app.lab", "0a")
	other := issued(t, s, ca, "other.lab", "0b")

	at := time.Unix(1_800_000_000, 0)
	c, err := s.RevokeCertificate(ctx, "ops", id, 1, at)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Revoked() || !c.RevokedAt.Equal(at) || c.RevocationReason != 1 {
		t.Fatalf("returned = %+v", c)
	}
	got, _ := s.GetCertificate(ctx, id)
	if !got.Revoked() || got.RevocationReason != 1 {
		t.Fatalf("stored = %+v", got)
	}
	if o, _ := s.GetCertificate(ctx, other); o.Revoked() {
		t.Fatal("revoking one certificate must not touch another")
	}

	if _, err := s.RevokeCertificate(ctx, "ops", id, 4, at); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("second revocation: %v", err)
	}
	if got, _ := s.GetCertificate(ctx, id); got.RevocationReason != 1 {
		t.Fatal("a second attempt must not change the reason")
	}
	if _, err := s.RevokeCertificate(ctx, "ops", "ghost", 0, at); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	// The database refuses reason codes we do not support (certificateHold, cACompromise, junk).
	for _, bad := range []int{2, 6, 8, 99, -1} {
		if _, err := s.RevokeCertificate(ctx, "ops", other, bad, at); !errors.Is(err, ErrInvalid) {
			t.Errorf("reason %d: %v", bad, err)
		}
	}
	if o, _ := s.GetCertificate(ctx, other); o.Revoked() {
		t.Fatal("a refused revocation must leave the certificate valid")
	}

	list, _ := s.ListRevoked(ctx, ca)
	if len(list) != 1 || list[0].Serial != "0a" || list[0].Reason != 1 || !list[0].RevokedAt.Equal(at) {
		t.Fatalf("revoked = %+v", list)
	}
	if n, _ := s.RevokedCount(ctx, ca); n != 1 {
		t.Fatalf("count = %d", n)
	}
	es, _ := s.Audit(ctx, 50)
	found := false
	for _, e := range es {
		found = found || (e.Action == "cert.revoke" && e.Target == id)
	}
	if !found {
		t.Fatal("revocation must be audited")
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPutNextCRL(t *testing.T) {
	s := open(t)
	ca := mustCA(t, s, root("Root"))
	a := issued(t, s, ca, "a.lab", "01")
	build := func(number int64, revoked []RevokedEntry) ([]byte, time.Time, time.Time, error) {
		return []byte(fmt.Sprintf("crl-%d-%d", number, len(revoked))), time.Unix(1000, 0), time.Unix(2000, 0), nil
	}

	if _, err := s.GetCRL(ctx, ca); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before any CRL: %v", err)
	}
	c1, err := s.PutNextCRL(ctx, "system", ca, build)
	if err != nil || c1.Number != 1 || c1.RevokedCount != 0 || string(c1.DER) != "crl-1-0" {
		t.Fatalf("first CRL = %+v, %v", c1, err)
	}
	s.RevokeCertificate(ctx, "ops", a, 1, time.Unix(1500, 0))
	c2, _ := s.PutNextCRL(ctx, "system", ca, build)
	if c2.Number != 2 || c2.RevokedCount != 1 || string(c2.DER) != "crl-2-1" {
		t.Fatalf("second CRL = %+v", c2)
	}
	got, _ := s.GetCRL(ctx, ca)
	if got.Number != 2 || string(got.DER) != "crl-2-1" || !got.NextUpdate.Equal(time.Unix(2000, 0)) || got.RevokedCount != 1 {
		t.Fatalf("stored = %+v", got)
	}

	// A failing build leaves the stored CRL and its number alone.
	if _, err := s.PutNextCRL(ctx, "system", ca, func(int64, []RevokedEntry) ([]byte, time.Time, time.Time, error) {
		return nil, time.Time{}, time.Time{}, errors.New("signing failed")
	}); err == nil {
		t.Fatal("expected failure")
	}
	if got, _ := s.GetCRL(ctx, ca); got.Number != 2 {
		t.Fatalf("number after a failed build = %d", got.Number)
	}
	if c3, _ := s.PutNextCRL(ctx, "system", ca, build); c3.Number != 3 {
		t.Fatalf("number after the failure = %d, want 3 (no gap, no reuse)", c3.Number)
	}
	if _, err := s.PutNextCRL(ctx, "system", "ghost", build); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown CA: %v", err)
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

// Numbers must never repeat or skip, even when several callers race.
func TestCRLNumbersUnderConcurrency(t *testing.T) {
	s := open(t)
	ca := mustCA(t, s, root("Root"))
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[int64]bool{}
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.PutNextCRL(ctx, "system", ca, func(n int64, _ []RevokedEntry) ([]byte, time.Time, time.Time, error) {
				return []byte("x"), time.Unix(1, 0), time.Unix(2, 0), nil
			})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[c.Number] {
				t.Errorf("number %d issued twice", c.Number)
			}
			seen[c.Number] = true
		}()
	}
	wg.Wait()
	for n := int64(1); n <= 12; n++ {
		if !seen[n] {
			t.Errorf("number %d missing", n)
		}
	}
}

// A database from before revocation existed upgrades in place; its certificates are all valid.
func TestUpgradeFromSchemaV3KeepsCertificatesValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := raw.Exec(migrations[i]); err != nil {
			t.Fatal(err)
		}
	}
	raw.Exec(`PRAGMA user_version = 3`)
	raw.Exec(`INSERT INTO cas (id,name,kind,cert_pem,not_before,not_after,created_at) VALUES ('r','Root','root',x'01',0,1,0)`)
	if _, err := raw.Exec(`INSERT INTO certificates (id,ca_id,serial,common_name,sans,profile,cert_pem,not_before,not_after,key_generated,created_at)
		VALUES ('c1','r','01','old.lab','[]','server',x'01',0,1,0,0)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer s.Close()
	c, err := s.GetCertificate(ctx, "c1")
	if err != nil || c.Revoked() || c.RevocationReason != 0 {
		t.Fatalf("old certificate = %+v, %v", c, err)
	}
	if _, err := s.RevokeCertificate(ctx, "ops", "c1", 5, time.Now()); err != nil {
		t.Fatalf("revoking after the upgrade: %v", err)
	}
}
