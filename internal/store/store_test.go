package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "data", "pki.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustCA(t *testing.T, s *Store, ca CA) string {
	t.Helper()
	id, err := s.CreateCA(ctx, "admin", ca)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func root(name string) CA {
	return CA{Name: name, Kind: KindRoot, CertPEM: []byte("cert"), KeyBlob: []byte("enc-key"),
		NotBefore: time.Unix(1000, 0), NotAfter: time.Unix(2000, 0)}
}

func TestOpenCreatesPrivateFilesAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "pki.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("db mode = %v, want 0600", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, want 0700", fi.Mode().Perm())
	}
	// Reopening must not re-run migrations or fail.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var v int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != len(migrations) {
		t.Fatalf("user_version = %d", v)
	}
	var fk int
	s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	if fk != 1 {
		t.Fatal("foreign keys must be enforced")
	}
	s.Close()
}

func TestRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pki.db")
	s, _ := Open(path)
	s.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)+1))
	s.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("must refuse a database from a newer version")
	}
}

func TestVaultHeaderSetOnce(t *testing.T) {
	s := open(t)
	if _, err := s.VaultHeader(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if err := s.SetVaultHeader(ctx, "admin", []byte("h1")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVaultHeader(ctx, "admin", []byte("h2")); !errors.Is(err, ErrExists) {
		t.Fatalf("second set: err = %v, want ErrExists", err)
	}
	if h, _ := s.VaultHeader(ctx); string(h) != "h1" {
		t.Fatalf("header = %q", h)
	}
}

func TestCAHierarchyAndConstraints(t *testing.T) {
	s := open(t)
	rid := mustCA(t, s, root("Lab Root"))
	iid := mustCA(t, s, CA{Name: "Lab Inter", Kind: KindIntermediate, ParentID: rid, CertPEM: []byte("c"), KeyBlob: []byte("k"),
		NotBefore: time.Unix(1000, 0), NotAfter: time.Unix(1500, 0)})

	got, err := s.GetCA(ctx, iid)
	if err != nil || got.ParentID != rid || got.Kind != KindIntermediate || !got.NotAfter.Equal(time.Unix(1500, 0)) {
		t.Fatalf("GetCA = %+v, %v", got, err)
	}
	if r, _ := s.GetCA(ctx, rid); r.ParentID != "" {
		t.Fatalf("root parent = %q", r.ParentID)
	}
	if list, _ := s.ListCAs(ctx); len(list) != 2 || list[0].Name != "Lab Inter" {
		t.Fatalf("ListCAs = %+v", list)
	}
	if _, err := s.GetCA(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}

	bad := map[string]CA{
		"duplicate name":       root("Lab Root"),
		"root with parent":     {Name: "x", Kind: KindRoot, ParentID: rid, CertPEM: []byte("c")},
		"intermediate no par.": {Name: "y", Kind: KindIntermediate, CertPEM: []byte("c")},
		"unknown parent":       {Name: "z", Kind: KindIntermediate, ParentID: "ghost", CertPEM: []byte("c")},
		"no cert":              {Name: "w", Kind: KindRoot},
		"bad kind":             {Name: "v", Kind: "sub", CertPEM: []byte("c")},
	}
	for name, ca := range bad {
		if _, err := s.CreateCA(ctx, "admin", ca); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// The database itself enforces the hierarchy rule, not only the Go code.
	if _, err := s.db.Exec(`INSERT INTO cas (id,name,kind,parent_id,cert_pem,not_before,not_after,created_at) VALUES ('a','n','root','x',x'00',0,0,0)`); err == nil {
		t.Fatal("DB must reject a root with a parent")
	}
}

func TestDropCAKey(t *testing.T) {
	s := open(t)
	id := mustCA(t, s, root("Root"))
	if err := s.DropCAKey(ctx, "admin", id, ""); err != nil {
		t.Fatal(err)
	}
	if ca, _ := s.GetCA(ctx, id); ca.KeyBlob != nil {
		t.Fatal("key blob must be gone")
	}
	if err := s.DropCAKey(ctx, "admin", id, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second drop: err = %v, want ErrNotFound", err)
	}
	// The row is still there, and only one drop was audited.
	entries, _ := s.Audit(ctx, 10)
	n := 0
	for _, e := range entries {
		if e.Action == "ca.drop_key" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("drop_key audited %d times", n)
	}
}

func TestCertificates(t *testing.T) {
	s := open(t)
	ca := mustCA(t, s, root("Root"))
	add := func(cn, serial string, notAfter int64) string {
		id, err := s.AddCertificate(ctx, "ops", Certificate{
			CAID: ca, Serial: serial, CommonName: cn, SANs: []string{cn, "10.0.0.1"}, Profile: "server",
			CertPEM: []byte("pem"), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(notAfter, 0), KeyGenerated: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	late := add("late.lab", "02", 900)
	soon := add("soon.lab", "01", 100)

	got, err := s.GetCertificate(ctx, soon)
	if err != nil || got.CommonName != "soon.lab" || len(got.SANs) != 2 || got.SANs[1] != "10.0.0.1" || !got.KeyGenerated {
		t.Fatalf("GetCertificate = %+v, %v", got, err)
	}
	list, _ := s.ListCertificates(ctx, "")
	if len(list) != 2 || list[0].ID != soon || list[1].ID != late {
		t.Fatalf("expected soonest-to-expire first, got %+v", list)
	}
	if l, _ := s.ListCertificates(ctx, "other-ca"); len(l) != 0 {
		t.Fatal("filter by CA failed")
	}
	if exp, _ := s.ExpiringBefore(ctx, time.Unix(500, 0)); len(exp) != 1 || exp[0].ID != soon {
		t.Fatalf("ExpiringBefore = %+v", exp)
	}

	if _, err := s.AddCertificate(ctx, "ops", Certificate{CAID: ca, Serial: "01", CommonName: "dup", CertPEM: []byte("p")}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate serial: err = %v, want ErrExists", err)
	}
	if _, err := s.AddCertificate(ctx, "ops", Certificate{CAID: "ghost", Serial: "09", CommonName: "x", CertPEM: []byte("p")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown CA: err = %v, want ErrInvalid", err)
	}
	// A CA with issued certificates cannot be deleted from under them.
	if _, err := s.db.Exec(`DELETE FROM cas WHERE id = ?`, ca); err == nil {
		t.Fatal("DB must refuse to delete a CA that has certificates")
	}
}

func TestAuditChain(t *testing.T) {
	s := open(t)
	mustCA(t, s, root("A"))
	mustCA(t, s, root("B"))
	s.SetVaultHeader(ctx, "admin", []byte("h"))
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	entries, _ := s.Audit(ctx, 10)
	if len(entries) != 3 || entries[0].Seq != 3 || entries[2].Action != "ca.create" || entries[2].Actor != "admin" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestAuditIsAppendOnly(t *testing.T) {
	s := open(t)
	mustCA(t, s, root("A"))
	if _, err := s.db.Exec(`UPDATE audit_log SET actor = 'mallory'`); err == nil {
		t.Fatal("UPDATE on the audit log must fail")
	}
	if _, err := s.db.Exec(`DELETE FROM audit_log`); err == nil {
		t.Fatal("DELETE on the audit log must fail")
	}
}

// Someone who bypasses the triggers (e.g. editing the file directly) is caught
// by the hash chain.
func TestAuditChainDetectsEditsAndDeletions(t *testing.T) {
	tamper := map[string]string{
		"edited actor":  `UPDATE audit_log SET actor = 'mallory' WHERE seq = 2`,
		"edited detail": `UPDATE audit_log SET detail = 'nothing here' WHERE seq = 2`,
		"deleted entry": `DELETE FROM audit_log WHERE seq = 2`,
		"edited time":   `UPDATE audit_log SET ts = ts + 1 WHERE seq = 3`,
	}
	for name, stmt := range tamper {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			for _, n := range []string{"A", "B", "C"} {
				mustCA(t, s, root(n))
			}
			s.db.Exec(`DROP TRIGGER audit_log_no_update`)
			s.db.Exec(`DROP TRIGGER audit_log_no_delete`)
			if _, err := s.db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			if err := s.VerifyAudit(ctx); !errors.Is(err, ErrAuditTampered) {
				t.Fatalf("err = %v, want ErrAuditTampered", err)
			}
		})
	}
}

func TestFailedOperationLeavesNoAuditTrace(t *testing.T) {
	s := open(t)
	mustCA(t, s, root("A"))
	before, _ := s.Audit(ctx, 100)
	if _, err := s.CreateCA(ctx, "admin", root("A")); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	after, _ := s.Audit(ctx, 100)
	if len(after) != len(before) {
		t.Fatal("a rolled-back operation must not leave an audit record")
	}
}

func TestRewrapKeysIsAtomic(t *testing.T) {
	s := open(t)
	s.SetVaultHeader(ctx, "admin", []byte("old-header"))
	a := mustCA(t, s, root("A"))
	b := mustCA(t, s, root("B"))
	mustCA(t, s, CA{Name: "Offline", Kind: KindRoot, CertPEM: []byte("c")}) // no key: must be skipped

	// Failure halfway: nothing may change.
	calls := 0
	err := s.RewrapKeys(ctx, "admin", []byte("new-header"), func(id string, blob []byte) ([]byte, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("boom")
		}
		return []byte("rewrapped-" + id), nil
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	if h, _ := s.VaultHeader(ctx); string(h) != "old-header" {
		t.Fatalf("header changed despite failure: %q", h)
	}
	for _, id := range []string{a, b} {
		if ca, _ := s.GetCA(ctx, id); !bytes.Equal(ca.KeyBlob, []byte("enc-key")) {
			t.Fatalf("blob of %s changed despite failure", id)
		}
	}

	// Success: everything moves together.
	if err := s.RewrapKeys(ctx, "admin", []byte("new-header"), func(id string, blob []byte) ([]byte, error) {
		return []byte("rewrapped-" + id), nil
	}); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.VaultHeader(ctx); string(h) != "new-header" {
		t.Fatalf("header = %q", h)
	}
	for _, id := range []string{a, b} {
		if ca, _ := s.GetCA(ctx, id); string(ca.KeyBlob) != "rewrapped-"+id {
			t.Fatalf("blob of %s = %q", id, ca.KeyBlob)
		}
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentWritersKeepAChain(t *testing.T) {
	s := open(t)
	ca := mustCA(t, s, root("Root"))
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.AddCertificate(ctx, "ops", Certificate{
				CAID: ca, Serial: fmt.Sprintf("%02x", i), CommonName: "c", CertPEM: []byte("p"),
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.Audit(ctx, 100); len(e) != 21 {
		t.Fatalf("audit entries = %d, want 21", len(e))
	}
}
