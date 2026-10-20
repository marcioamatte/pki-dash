package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/store"
	"github.com/marcioamatte/pki-dash/internal/vault"
)

var ctx = context.Background()

const (
	pass = "correct horse battery staple"
	year = 365 * 24 * time.Hour
)

var fastKDF = vault.Params{Time: 2, Memory: 19 * 1024, Threads: 1}

func openStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newSvc(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st := openStore(t, filepath.Join(t.TempDir(), "pki.db"))
	s := New(st, Options{KDF: fastKDF})
	if err := s.Init(ctx, "admin", pass); err != nil {
		t.Fatal(err)
	}
	return s, st
}

func caParams(name string, validity time.Duration, algo ca.KeyAlgo) CAParams {
	return CAParams{Name: name, Organization: "Lab", Validity: validity, KeyAlgo: algo}
}

// hierarchy creates Root and Intermediate and returns their IDs.
func hierarchy(t *testing.T, s *Service) (rootID, interID string) {
	t.Helper()
	var err error
	if rootID, err = s.CreateRoot(ctx, "admin", caParams("Lab Root", 10*year, ca.ECDSAP384)); err != nil {
		t.Fatal(err)
	}
	if interID, err = s.CreateIntermediate(ctx, "admin", rootID, caParams("Lab Intermediate", 5*year, ca.ECDSAP256)); err != nil {
		t.Fatal(err)
	}
	return
}

func leafReq(cn string) ca.LeafRequest {
	return ca.LeafRequest{CommonName: cn, DNSNames: []string{cn}, IPs: []string{"10.0.0.7"},
		Profile: ca.ProfileServer, Validity: year, KeyAlgo: ca.ECDSAP256}
}

func certOf(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func auditActions(t *testing.T, st *store.Store) []string {
	t.Helper()
	if err := st.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	es, _ := st.Audit(ctx, 1000)
	var out []string
	for i := len(es) - 1; i >= 0; i-- {
		out = append(out, es[i].Action)
	}
	return out
}

func TestFullFlow(t *testing.T) {
	s, st := newSvc(t)
	rootID, interID := hierarchy(t, s)

	res, err := s.IssueCertificate(ctx, "ops", interID, leafReq("app.lab"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Bundle.KeyPEM) == 0 || len(res.Warnings) != 0 {
		t.Fatalf("unexpected result: key=%d warnings=%v", len(res.Bundle.KeyPEM), res.Warnings)
	}

	// What the user downloads must verify as a TLS client would: leaf plus the
	// chain we hand out, rooted at the Root certificate alone.
	leaf := certOf(t, res.Bundle.CertPEM)
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	rootCA, _ := s.GetCA(ctx, rootID)
	roots.AppendCertsFromPEM(rootCA.CertPEM)
	inters.AppendCertsFromPEM(res.ChainPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "app.lab"}); err != nil {
		t.Fatalf("issued bundle does not verify: %v", err)
	}
	// The chain is intermediate first, then root.
	chain, _ := s.CAChainPEM(ctx, interID)
	if !bytes.Equal(chain, res.ChainPEM) || bytes.Count(chain, []byte("BEGIN CERTIFICATE")) != 2 {
		t.Fatal("chain should hold intermediate then root")
	}

	// It is recorded, with its SANs, and the private key is not.
	certs, _ := s.ListCertificates(ctx, "")
	if len(certs) != 1 || certs[0].ID != res.ID || !slices.Equal(certs[0].SANs, []string{"app.lab", "10.0.0.7"}) || !certs[0].KeyGenerated {
		t.Fatalf("stored certs = %+v", certs)
	}
	if bytes.Contains(certs[0].CertPEM, []byte("PRIVATE")) {
		t.Fatal("stored certificate PEM must not hold a key")
	}

	want := []string{"vault.init", "ca.create", "ca.create", "cert.issue"}
	if got := auditActions(t, st); !slices.Equal(got, want) {
		t.Fatalf("audit = %v, want %v", got, want)
	}
}

func TestVaultStateAndLocking(t *testing.T) {
	st := openStore(t, filepath.Join(t.TempDir(), "pki.db"))
	s := New(st, Options{KDF: fastKDF})

	if state, _ := s.State(ctx); state.Initialized {
		t.Fatal("fresh store must be uninitialised")
	}
	if err := s.Unlock(ctx, "admin", pass); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("unlock before init: err = %v", err)
	}
	if err := s.Init(ctx, "admin", "short"); !errors.Is(err, vault.ErrWeakPassphrase) {
		t.Fatalf("weak passphrase: err = %v", err)
	}
	if err := s.Init(ctx, "admin", pass); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx, "admin", pass); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("double init: err = %v", err)
	}
	if state, _ := s.State(ctx); !state.Initialized || !state.Unlocked {
		t.Fatalf("state = %+v", state)
	}

	rootID, _ := s.CreateRoot(ctx, "admin", caParams("Root", 10*year, ca.ECDSAP256))
	if err := s.Lock(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	// While locked, nothing that needs a key works.
	if _, err := s.CreateRoot(ctx, "admin", caParams("R2", year, ca.ECDSAP256)); !errors.Is(err, ErrLocked) {
		t.Fatalf("CreateRoot: err = %v", err)
	}
	if _, err := s.CreateIntermediate(ctx, "admin", rootID, caParams("I", year, ca.ECDSAP256)); !errors.Is(err, ErrLocked) {
		t.Fatalf("CreateIntermediate: err = %v", err)
	}
	if _, err := s.ExportCAKey(ctx, "admin", rootID); !errors.Is(err, ErrLocked) {
		t.Fatalf("ExportCAKey: err = %v", err)
	}
	if _, err := s.IssueCertificate(ctx, "ops", rootID, leafReq("x.lab")); !errors.Is(err, ErrLocked) {
		t.Fatalf("IssueCertificate: err = %v", err)
	}
	// Reading public data is fine.
	if cas, err := s.ListCAs(ctx); err != nil || len(cas) != 1 {
		t.Fatalf("ListCAs while locked: %v %v", cas, err)
	}

	if err := s.Unlock(ctx, "mallory", "wrong passphrase!!"); !errors.Is(err, vault.ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: err = %v", err)
	}
	if state, _ := s.State(ctx); state.Unlocked {
		t.Fatal("failed unlock must leave the vault locked")
	}
	if err := s.Unlock(ctx, "admin", pass); err != nil {
		t.Fatal(err)
	}

	got := auditActions(t, st)
	for _, a := range []string{"vault.lock", "vault.unlock_failed", "vault.unlock"} {
		if !slices.Contains(got, a) {
			t.Errorf("audit lacks %q: %v", a, got)
		}
	}
	es, _ := st.Audit(ctx, 100)
	for _, e := range es {
		if e.Action == "vault.unlock_failed" && e.Actor != "mallory" {
			t.Errorf("failed unlock attributed to %q", e.Actor)
		}
	}
}

func TestHierarchyPolicy(t *testing.T) {
	s, _ := newSvc(t)
	rootID, interID := hierarchy(t, s)

	if _, err := s.IssueCertificate(ctx, "ops", rootID, leafReq("x.lab")); !errors.Is(err, ErrIssueFromRoot) {
		t.Fatalf("issue from root: err = %v, want ErrIssueFromRoot", err)
	}
	if _, err := s.CreateIntermediate(ctx, "admin", interID, caParams("Deeper", year, ca.ECDSAP256)); !errors.Is(err, ErrBadParent) {
		t.Fatalf("intermediate under intermediate: err = %v, want ErrBadParent", err)
	}
	if _, err := s.CreateIntermediate(ctx, "admin", "ghost", caParams("X", year, ca.ECDSAP256)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown parent: err = %v", err)
	}
	if _, err := s.CreateRoot(ctx, "admin", caParams("Lab Root", year, ca.ECDSAP256)); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate name: err = %v, want ErrExists", err)
	}
}

func TestOfflineRootWorkflow(t *testing.T) {
	s, st := newSvc(t)
	rootID, interID := hierarchy(t, s)

	keyPEM, err := s.ExportCAKey(ctx, "admin", rootID)
	if err != nil {
		t.Fatal(err)
	}
	// The exported key is the Root's: it loads against the Root certificate.
	rootCA, _ := s.GetCA(ctx, rootID)
	if _, err := ca.Load(rootCA.CertPEM, keyPEM); err != nil {
		t.Fatalf("exported key does not match the root: %v", err)
	}

	if err := s.RemoveRootKey(ctx, "admin", interID); !errors.Is(err, ErrNotARoot) {
		t.Fatalf("remove key of an intermediate: err = %v, want ErrNotARoot", err)
	}
	if err := s.RemoveRootKey(ctx, "admin", rootID); err != nil {
		t.Fatal(err)
	}

	// The Root is now offline: it can no longer sign or be exported...
	if _, err := s.CreateIntermediate(ctx, "admin", rootID, caParams("Another", year, ca.ECDSAP256)); !errors.Is(err, ErrKeyOffline) {
		t.Fatalf("sign with offline root: err = %v, want ErrKeyOffline", err)
	}
	if _, err := s.ExportCAKey(ctx, "admin", rootID); !errors.Is(err, ErrKeyOffline) {
		t.Fatalf("export of removed key: err = %v", err)
	}
	// ...while the existing intermediate carries on, and the chain is intact.
	res, err := s.IssueCertificate(ctx, "ops", interID, leafReq("still.works"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(res.ChainPEM, []byte("BEGIN CERTIFICATE")) != 2 {
		t.Fatal("chain must still include the root certificate")
	}

	got := auditActions(t, st)
	if !slices.Contains(got, "ca.export_key") || !slices.Contains(got, "ca.drop_key") {
		t.Fatalf("export and removal must be audited: %v", got)
	}
}

func TestChangePassphraseThroughService(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pki.db")
	st := openStore(t, path)
	s := New(st, Options{KDF: fastKDF})
	if err := s.Init(ctx, "admin", pass); err != nil {
		t.Fatal(err)
	}
	_, interID := hierarchy(t, s)

	newPass := "a brand new passphrase!"
	if err := s.ChangePassphrase(ctx, "admin", "short"); !errors.Is(err, vault.ErrWeakPassphrase) {
		t.Fatalf("weak new passphrase: err = %v", err)
	}
	if err := s.ChangePassphrase(ctx, "admin", newPass); err != nil {
		t.Fatal(err)
	}
	// Still unlocked and usable right after the change.
	if _, err := s.IssueCertificate(ctx, "ops", interID, leafReq("a.lab")); err != nil {
		t.Fatal(err)
	}

	// A fresh process (new Service over the same file) needs the new passphrase.
	s2 := New(openStore(t, path), Options{KDF: fastKDF})
	if err := s2.Unlock(ctx, "admin", pass); !errors.Is(err, vault.ErrBadPassphrase) {
		t.Fatalf("old passphrase: err = %v", err)
	}
	if err := s2.Unlock(ctx, "admin", newPass); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.IssueCertificate(ctx, "ops", interID, leafReq("b.lab")); err != nil {
		t.Fatalf("issuing after restart + new passphrase: %v", err)
	}
}

func TestIssueFromCSRRecordsNoGeneratedKey(t *testing.T) {
	s, _ := newSvc(t)
	_, interID := hierarchy(t, s)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	r := leafReq("csr.lab")
	r.CSRPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	res, err := s.IssueCertificate(ctx, "ops", interID, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Bundle.KeyPEM) != 0 {
		t.Fatal("no key should be returned for a CSR")
	}
	if certs, _ := s.ListCertificates(ctx, interID); len(certs) != 1 || certs[0].KeyGenerated {
		t.Fatalf("stored = %+v", certs)
	}
}

func TestFailedIssueIsNotRecorded(t *testing.T) {
	s, st := newSvc(t)
	_, interID := hierarchy(t, s)
	r := leafReq("long.lab")
	r.Validity = 6 * year // intermediate only lives 5 years
	if _, err := s.IssueCertificate(ctx, "ops", interID, r); !errors.Is(err, ca.ErrExceedsParent) {
		t.Fatalf("err = %v, want ErrExceedsParent", err)
	}
	if certs, _ := s.ListCertificates(ctx, ""); len(certs) != 0 {
		t.Fatal("a failed issuance must not be recorded")
	}
	if slices.Contains(auditActions(t, st), "cert.issue") {
		t.Fatal("a failed issuance must not be audited as issued")
	}
}

func TestLongValidityWarns(t *testing.T) {
	s, _ := newSvc(t)
	_, interID := hierarchy(t, s)
	r := leafReq("long.lab")
	r.Validity = 2 * year
	res, err := s.IssueCertificate(ctx, "ops", interID, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings = %v", res.Warnings)
	}
}

func TestExpiring(t *testing.T) {
	s, _ := newSvc(t)
	_, interID := hierarchy(t, s)
	for cn, v := range map[string]time.Duration{"soon.lab": 10 * 24 * time.Hour, "later.lab": 200 * 24 * time.Hour} {
		r := leafReq(cn)
		r.Validity = v
		if _, err := s.IssueCertificate(ctx, "ops", interID, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Expiring(ctx, 30*24*time.Hour)
	if err != nil || len(got) != 1 || got[0].CommonName != "soon.lab" {
		t.Fatalf("Expiring(30d) = %+v, %v", got, err)
	}
}
