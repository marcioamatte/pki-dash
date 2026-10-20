package service

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/store"
)

// offlineSign plays the part of the offline Root: it signs a request with the
// Root's key outside this service, the way openssl or cfssl would.
func offlineSign(t *testing.T, rootCertPEM, rootKeyPEM, csrPEM []byte) []byte {
	t.Helper()
	root := parseCertT(t, rootCertPEM)
	kb, _ := pem.Decode(rootKeyPEM)
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode(csrPEM)
	req, err := x509.ParseCertificateRequest(cb.Bytes)
	if err != nil || req.CheckSignature() != nil {
		t.Fatalf("bad CSR: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: req.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: root.NotAfter.Add(-time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, req.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func parseCertT(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func interParams(name string) IntermediateRequestParams {
	return IntermediateRequestParams{Name: name, Organization: "Lab", KeyAlgo: ca.ECDSAP256}
}

func leafOK(t *testing.T, s *Service, interID, rootPEM string) {
	t.Helper()
	res, err := s.IssueCertificate(ctx, "ops", interID, leafReq("svc.lab"))
	if err != nil {
		t.Fatalf("issuing from the imported intermediate: %v", err)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(rootPEM))
	inters.AppendCertsFromPEM(res.ChainPEM)
	if _, err := parseCertT(t, res.Bundle.CertPEM).Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "svc.lab"}); err != nil {
		t.Fatalf("the certificate does not verify against the original Root: %v", err)
	}
}

// The user's own workflow: a Root made here, exported and removed (offline); a
// new intermediate is requested, signed offline, and imported.
func TestSignedOfflineWithAnExportedRoot(t *testing.T) {
	s, st := newSvc(t)
	rootID, err := s.CreateRoot(ctx, "admin", caParams("Lab Root", 10*year, ca.ECDSAP384))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := s.ExportCAKey(ctx, "admin", rootID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveRootKey(ctx, "admin", rootID); err != nil {
		t.Fatal(err)
	}
	root, _ := s.GetCA(ctx, rootID)

	req, err := s.RequestIntermediate(ctx, "admin", rootID, interParams("Lab Services"))
	if err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListPendingRequests(ctx); len(list) != 1 || list[0].ID != req.ID {
		t.Fatalf("pending = %+v", list)
	}
	signed := offlineSign(t, root.CertPEM, rootKey, req.CSRPEM)

	id, err := s.ImportIntermediate(ctx, "admin", req.ID, signed)
	if err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListPendingRequests(ctx); len(list) != 0 {
		t.Fatalf("the request must be gone: %+v", list)
	}
	c, _ := s.GetCA(ctx, id)
	if c.Kind != store.KindIntermediate || c.ParentID != rootID || c.KeyBlob == nil || c.Name != "Lab Services" {
		t.Fatalf("imported CA = %+v", c)
	}
	leafOK(t, s, id, string(root.CertPEM))

	actions := auditActions(t, st)
	for _, want := range []string{"ca.request_intermediate", "ca.import_intermediate"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit lacks %q: %v", want, actions)
		}
	}
}

// A Root that never touched this service: only its public certificate arrives.
func TestRootCreatedElsewhere(t *testing.T) {
	s, _ := newSvc(t)
	b, err := ca.NewRoot(ca.CARequest{CommonName: "Home Root", Validity: 10 * year, KeyAlgo: ca.ECDSAP384})
	if err != nil {
		t.Fatal(err)
	}
	rootID, err := s.ImportRoot(ctx, "admin", "Home Root", b.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := s.GetCA(ctx, rootID)
	if root.Kind != store.KindRoot || root.KeyBlob != nil {
		t.Fatalf("an imported Root has no key here: %+v", root)
	}

	// Registering it again, under any name, is refused.
	if _, err := s.ImportRoot(ctx, "admin", "Home Root", b.CertPEM); !errors.Is(err, store.ErrExists) {
		t.Errorf("same name: %v", err)
	}
	if _, err := s.ImportRoot(ctx, "admin", "Another Name", b.CertPEM); !errors.Is(err, store.ErrExists) {
		t.Errorf("same certificate, new name: %v", err)
	}
	// It cannot sign here, but it can be the parent of an offline-signed intermediate.
	if _, err := s.CreateIntermediate(ctx, "admin", rootID, caParams("Direct", year, ca.ECDSAP256)); !errors.Is(err, ErrKeyOffline) {
		t.Errorf("signing with a key we never had: %v", err)
	}
	req, err := s.RequestIntermediate(ctx, "admin", rootID, interParams("Home Services"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.ImportIntermediate(ctx, "admin", req.ID, offlineSign(t, b.CertPEM, b.KeyPEM, req.CSRPEM))
	if err != nil {
		t.Fatal(err)
	}
	leafOK(t, s, id, string(b.CertPEM))
}

func TestImportRootRejections(t *testing.T) {
	s, _ := newSvc(t)
	rootID, interID := hierarchy(t, s)
	inter, _ := s.GetCA(ctx, interID)
	_ = rootID

	for name, in := range map[string][]byte{
		"an intermediate": inter.CertPEM,
		"garbage":         []byte("not a certificate"),
		"empty":           nil,
	} {
		if _, err := s.ImportRoot(ctx, "admin", "Not A Root", in); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	res, _ := s.IssueCertificate(ctx, "ops", interID, leafReq("x.lab"))
	if _, err := s.ImportRoot(ctx, "admin", "A Leaf", res.Bundle.CertPEM); !errors.Is(err, ca.ErrPolicy) {
		t.Errorf("a leaf: %v", err)
	}
	b, _ := ca.NewRoot(ca.CARequest{CommonName: "Real", Validity: year, KeyAlgo: ca.ECDSAP256})
	for _, bad := range []string{"", "   "} {
		if _, err := s.ImportRoot(ctx, "admin", bad, b.CertPEM); !errors.Is(err, ca.ErrInvalidRequest) {
			t.Errorf("name %q: %v", bad, err)
		}
	}
}

func TestRequestAndImportRules(t *testing.T) {
	s, _ := newSvc(t)
	rootID, interID := hierarchy(t, s)
	root, _ := s.GetCA(ctx, rootID)
	rootKey, _ := s.ExportCAKey(ctx, "admin", rootID)

	if _, err := s.RequestIntermediate(ctx, "admin", interID, interParams("Under An Intermediate")); !errors.Is(err, ErrBadParent) {
		t.Errorf("under an intermediate: %v", err)
	}
	if _, err := s.RequestIntermediate(ctx, "admin", "ghost", interParams("X")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown parent: %v", err)
	}
	if _, err := s.RequestIntermediate(ctx, "admin", rootID, interParams("Lab Intermediate")); !errors.Is(err, store.ErrExists) {
		t.Errorf("name of an existing CA: %v", err)
	}
	a, err := s.RequestIntermediate(ctx, "admin", rootID, interParams("Req A"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.RequestIntermediate(ctx, "admin", rootID, interParams("Req B"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestIntermediate(ctx, "admin", rootID, interParams("Req A")); !errors.Is(err, store.ErrExists) {
		t.Errorf("duplicate pending name: %v", err)
	}

	// A certificate issued for request B must not complete request A.
	forB := offlineSign(t, root.CertPEM, rootKey, b.CSRPEM)
	if _, err := s.ImportIntermediate(ctx, "admin", a.ID, forB); !errors.Is(err, ca.ErrKeyMismatch) {
		t.Fatalf("wrong certificate for request A: %v", err)
	}
	if _, err := s.GetPendingRequest(ctx, a.ID); err != nil {
		t.Fatalf("a refused import must leave the request in place: %v", err)
	}
	// A certificate signed by a different Root is refused.
	other, _ := ca.NewRoot(ca.CARequest{CommonName: "Other Root", Validity: 10 * year, KeyAlgo: ca.ECDSAP384})
	if _, err := s.ImportIntermediate(ctx, "admin", a.ID, offlineSign(t, other.CertPEM, other.KeyPEM, a.CSRPEM)); !errors.Is(err, ca.ErrPolicy) {
		t.Fatalf("foreign issuer: %v", err)
	}
	// A normal, correctly signed certificate works.
	if _, err := s.ImportIntermediate(ctx, "admin", a.ID, offlineSign(t, root.CertPEM, rootKey, a.CSRPEM)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportIntermediate(ctx, "admin", a.ID, forB); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("importing twice: %v", err)
	}

	// Cancelling discards the request.
	if err := s.CancelPendingRequest(ctx, "admin", b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPendingRequest(ctx, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cancelled request still there: %v", err)
	}
}

func TestRequestsNeedAnUnlockedVault(t *testing.T) {
	s, _ := newSvc(t)
	rootID, _ := hierarchy(t, s)
	req, _ := s.RequestIntermediate(ctx, "admin", rootID, interParams("Req"))
	s.Lock(ctx, "admin")
	if _, err := s.RequestIntermediate(ctx, "admin", rootID, interParams("Req2")); !errors.Is(err, ErrLocked) {
		t.Errorf("request while locked: %v", err)
	}
	if _, err := s.ImportIntermediate(ctx, "admin", req.ID, []byte("x")); !errors.Is(err, ErrLocked) {
		t.Errorf("import while locked: %v", err)
	}
	// Public information stays readable.
	if list, err := s.ListPendingRequests(ctx); err != nil || len(list) != 1 {
		t.Errorf("list while locked: %v %v", list, err)
	}
}

// The request's key is encrypted like any other, so a passphrase change has to
// carry it along: otherwise the signed certificate could never be imported.
func TestPendingKeySurvivesAPassphraseChange(t *testing.T) {
	s, _ := newSvc(t)
	b, _ := ca.NewRoot(ca.CARequest{CommonName: "Home Root", Validity: 10 * year, KeyAlgo: ca.ECDSAP384})
	rootID, _ := s.ImportRoot(ctx, "admin", "Home Root", b.CertPEM)
	req, err := s.RequestIntermediate(ctx, "admin", rootID, interParams("Home Services"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassphrase(ctx, "admin", "a brand new passphrase!"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportIntermediate(ctx, "admin", req.ID, offlineSign(t, b.CertPEM, b.KeyPEM, req.CSRPEM)); err != nil {
		t.Fatalf("importing after the passphrase changed: %v", err)
	}
}

func TestRequestDoesNotExposeTheKey(t *testing.T) {
	s, _ := newSvc(t)
	rootID, _ := hierarchy(t, s)
	req, _ := s.RequestIntermediate(ctx, "admin", rootID, interParams("Req"))
	if string(req.CSRPEM) == "" || !contains(req.CSRPEM, "CERTIFICATE REQUEST") || contains(req.CSRPEM, "PRIVATE") {
		t.Fatalf("the request must hold a CSR and no key: %s", req.CSRPEM)
	}
}

func contains(b []byte, sub string) bool { return strings.Contains(string(b), sub) }
