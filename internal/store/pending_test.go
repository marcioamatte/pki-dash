package store

import (
	"errors"
	"testing"
	"time"
)

func pending(parent, name string) PendingCA {
	return PendingCA{ID: NewID(), Name: name, ParentID: parent, CSRPEM: []byte("csr"), KeyBlob: []byte("enc-key")}
}

func TestPendingLifecycle(t *testing.T) {
	s := open(t)
	root := mustCA(t, s, root("Root"))

	p := pending(root, "Inter A")
	id, err := s.CreatePendingCA(ctx, "admin", p)
	if err != nil || id != p.ID {
		t.Fatalf("create = %q, %v", id, err)
	}
	got, err := s.GetPendingCA(ctx, id)
	if err != nil || got.Name != "Inter A" || got.ParentID != root || string(got.CSRPEM) != "csr" || string(got.KeyBlob) != "enc-key" {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if list, _ := s.ListPendingCAs(ctx); len(list) != 1 || list[0].ID != id {
		t.Fatalf("list = %+v", list)
	}
	if _, err := s.GetPendingCA(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	bad := map[string]PendingCA{
		"duplicate pending name": pending(root, "Inter A"),
		"name of an existing CA": pending(root, "Root"),
		"unknown parent":         pending("ghost", "Inter B"),
		"no key":                 {ID: NewID(), Name: "Inter C", ParentID: root, CSRPEM: []byte("csr")},
		"no id":                  {Name: "Inter D", ParentID: root, CSRPEM: []byte("csr"), KeyBlob: []byte("k")},
	}
	for name, b := range bad {
		if _, err := s.CreatePendingCA(ctx, "admin", b); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A parent with pending requests cannot be deleted from under them.
	if _, err := s.db.Exec(`DELETE FROM cas WHERE id = ?`, root); err == nil {
		t.Fatal("the database must keep a parent that has pending requests")
	}

	if err := s.DeletePendingCA(ctx, "admin", id); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePendingCA(ctx, "admin", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCompletePendingIsAtomic(t *testing.T) {
	s := open(t)
	rootID := mustCA(t, s, root("Root"))
	p := pending(rootID, "Inter A")
	s.CreatePendingCA(ctx, "admin", p)

	done := CA{ID: p.ID, Name: p.Name, Kind: KindIntermediate, ParentID: rootID, CertPEM: []byte("signed"), KeyBlob: p.KeyBlob,
		NotBefore: time.Unix(1000, 0), NotAfter: time.Unix(1500, 0)}

	// Wrong ID, wrong kind, no certificate: refused, and the request survives.
	for name, c := range map[string]CA{
		"different id": func() CA { c := done; c.ID = NewID(); return c }(),
		"root kind":    func() CA { c := done; c.Kind = KindRoot; return c }(),
		"no cert":      func() CA { c := done; c.CertPEM = nil; return c }(),
	} {
		if err := s.CompletePendingCA(ctx, "admin", p.ID, c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := s.GetPendingCA(ctx, p.ID); err != nil {
		t.Fatalf("the request must survive a refused completion: %v", err)
	}

	// A name clash created in the meantime rolls everything back, keeping the request.
	s.db.Exec(`INSERT INTO cas (id,name,kind,cert_pem,not_before,not_after,created_at) VALUES ('x','Inter A','root',x'01',0,1,0)`)
	if err := s.CompletePendingCA(ctx, "admin", p.ID, done); !errors.Is(err, ErrExists) {
		t.Fatalf("clash: %v", err)
	}
	if _, err := s.GetPendingCA(ctx, p.ID); err != nil {
		t.Fatalf("a failed completion must not lose the request: %v", err)
	}
	s.db.Exec(`DELETE FROM cas WHERE id = 'x'`)

	if err := s.CompletePendingCA(ctx, "admin", p.ID, done); err != nil {
		t.Fatal(err)
	}
	ca, err := s.GetCA(ctx, p.ID)
	if err != nil || ca.Kind != KindIntermediate || ca.ParentID != rootID || string(ca.KeyBlob) != "enc-key" || string(ca.CertPEM) != "signed" {
		t.Fatalf("CA = %+v, %v", ca, err)
	}
	if _, err := s.GetPendingCA(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("the request must be gone once completed")
	}
	if err := s.CompletePendingCA(ctx, "admin", p.ID, done); !errors.Is(err, ErrNotFound) {
		t.Fatalf("completing twice: %v", err)
	}
	es, _ := s.Audit(ctx, 20)
	found := false
	for _, e := range es {
		found = found || e.Action == "ca.import_intermediate"
	}
	if !found {
		t.Fatal("the import must be audited")
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

// A passphrase change must move the keys of pending requests too, or they would
// become unreadable.
func TestRewrapKeysCoversPendingRequests(t *testing.T) {
	s := open(t)
	s.SetVaultHeader(ctx, "admin", []byte("old"))
	rootID := mustCA(t, s, root("Root"))
	p := pending(rootID, "Inter A")
	s.CreatePendingCA(ctx, "admin", p)

	seen := map[string]bool{}
	err := s.RewrapKeys(ctx, "admin", []byte("new"), func(id string, blob []byte) ([]byte, error) {
		seen[id] = true
		return []byte("rewrapped-" + id), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !seen[p.ID] || !seen[rootID] {
		t.Fatalf("rewrapped ids = %v", seen)
	}
	if got, _ := s.GetPendingCA(ctx, p.ID); string(got.KeyBlob) != "rewrapped-"+p.ID {
		t.Fatalf("pending key = %q", got.KeyBlob)
	}

	// A failure while rewrapping a pending key leaves everything as it was.
	err = s.RewrapKeys(ctx, "admin", []byte("newer"), func(id string, blob []byte) ([]byte, error) {
		if id == p.ID {
			return nil, errors.New("boom")
		}
		return []byte("again-" + id), nil
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	if h, _ := s.VaultHeader(ctx); string(h) != "new" {
		t.Fatalf("header = %q", h)
	}
	if ca, _ := s.GetCA(ctx, rootID); string(ca.KeyBlob) != "rewrapped-"+rootID {
		t.Fatalf("root key changed despite the failure: %q", ca.KeyBlob)
	}
}
