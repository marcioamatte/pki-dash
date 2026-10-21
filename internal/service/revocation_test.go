package service

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/store"
)

const publicURL = "http://pki.lab:8080"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newPKI returns a service that publishes CRL addresses, with a controllable clock
// shared by the service and the store.
func newPKI(t *testing.T) (*Service, *store.Store, *clock) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "pki.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	st.SetClock(clk.Now)
	s := New(st, Options{KDF: fastKDF, PublicURL: publicURL, Now: clk.Now})
	if err := s.Init(ctx, "admin", pass); err != nil {
		t.Fatal(err)
	}
	return s, st, clk
}

func issueN(t *testing.T, s *Service, interID, cn string) (id string, cert *x509.Certificate) {
	t.Helper()
	res, err := s.IssueCertificate(ctx, "ops", interID, leafReq(cn))
	if err != nil {
		t.Fatal(err)
	}
	return res.ID, certOf(t, res.Bundle.CertPEM)
}

func parseCRL(t *testing.T, s *Service, caID string) *x509.RevocationList {
	t.Helper()
	pub, err := s.PublicCRL(ctx, caID)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(pub.DER)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func serials(crl *x509.RevocationList) []string {
	var out []string
	for _, e := range crl.RevokedCertificateEntries {
		out = append(out, e.SerialNumber.Text(16))
	}
	return out
}

func TestRevokePublishesACRLThatClientsCanVerify(t *testing.T) {
	s, st, _ := newPKI(t)
	_, interID := hierarchy(t, s)
	aID, a := issueN(t, s, interID, "a.lab")
	_, b := issueN(t, s, interID, "b.lab")

	// Certificates carry the addresses clients need, pointing at this issuer.
	for _, c := range []*x509.Certificate{a, b} {
		if !slices.Equal(c.CRLDistributionPoints, []string{publicURL + "/crl/" + interID + ".crl"}) {
			t.Fatalf("CRL distribution points = %v", c.CRLDistributionPoints)
		}
		if !slices.Equal(c.IssuingCertificateURL, []string{publicURL + "/ca/" + interID + ".crt"}) {
			t.Fatalf("issuer URL = %v", c.IssuingCertificateURL)
		}
	}
	// The list those addresses lead to exists from the first certificate on, and is empty.
	first := parseCRL(t, s, interID)
	if first.Number.Int64() != 1 || len(first.RevokedCertificateEntries) != 0 {
		t.Fatalf("initial CRL: number %v, %d entries", first.Number, len(first.RevokedCertificateEntries))
	}

	res, err := s.RevokeCertificate(ctx, "ops", aID, ca.ReasonKeyCompromise)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Published || !res.Certificate.Revoked() {
		t.Fatalf("result = %+v", res)
	}

	inter, _ := s.GetCA(ctx, interID)
	issuer := certOf(t, inter.CertPEM)
	crl := parseCRL(t, s, interID)
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("the CRL does not verify against its issuer: %v", err)
	}
	if crl.Number.Int64() != 2 {
		t.Fatalf("number = %v, want 2", crl.Number)
	}
	if got := serials(crl); !slices.Equal(got, []string{a.SerialNumber.Text(16)}) {
		t.Fatalf("revoked serials = %v, want only %s (not %s)", got, a.SerialNumber.Text(16), b.SerialNumber.Text(16))
	}
	if crl.RevokedCertificateEntries[0].ReasonCode != ca.ReasonKeyCompromise {
		t.Fatalf("reason = %d", crl.RevokedCertificateEntries[0].ReasonCode)
	}
	if crl.NextUpdate.Sub(s.opts.Now()) < 6*24*time.Hour {
		t.Fatalf("the CRL must be valid for about a week, nextUpdate = %v", crl.NextUpdate)
	}

	st1, _ := s.CRLStatus(ctx)
	if len(st1) != 1 || st1[0].Revoked != 1 || st1[0].InList != 1 || st1[0].Stale || st1[0].Expired || !st1[0].Published || !st1[0].CanSign {
		t.Fatalf("status = %+v", st1)
	}
	if _, err := s.RevokeCertificate(ctx, "ops", aID, ca.ReasonSuperseded); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("second revocation: %v", err)
	}
	if _, err := s.RevokeCertificate(ctx, "ops", "ghost", 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown certificate: %v", err)
	}
	for _, bad := range []int{2, 6, 99, -1} {
		if _, err := s.RevokeCertificate(ctx, "ops", aID, bad); !errors.Is(err, ca.ErrInvalidRequest) {
			t.Errorf("reason %d: %v", bad, err)
		}
	}
	actions := auditActions(t, st)
	for _, want := range []string{"cert.revoke", "crl.publish"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit lacks %q: %v", want, actions)
		}
	}
}

// The case that matters in an incident: the vault is locked, a key leaks, and the
// revocation must still be recorded, then published as soon as the vault opens.
func TestRevocationWhileLockedIsRecordedThenPublishedOnUnlock(t *testing.T) {
	s, _, _ := newPKI(t)
	_, interID := hierarchy(t, s)
	aID, a := issueN(t, s, interID, "a.lab")
	if err := s.Lock(ctx, "admin"); err != nil {
		t.Fatal(err)
	}

	res, err := s.RevokeCertificate(ctx, "ops", aID, ca.ReasonKeyCompromise)
	if err != nil {
		t.Fatalf("revoking while locked must work: %v", err)
	}
	if res.Published || !res.Certificate.Revoked() {
		t.Fatalf("result = %+v: recorded but not yet published", res)
	}
	if len(parseCRL(t, s, interID).RevokedCertificateEntries) != 0 {
		t.Fatal("the published CRL cannot know about it yet")
	}
	info, _ := s.CRLStatus(ctx)
	if !info[0].Stale || info[0].Revoked != 1 || info[0].InList != 0 {
		t.Fatalf("the dashboard must show the CRL as stale: %+v", info[0])
	}

	if err := s.Unlock(ctx, "admin", pass); err != nil {
		t.Fatal(err)
	}
	crl := parseCRL(t, s, interID)
	if !slices.Equal(serials(crl), []string{a.SerialNumber.Text(16)}) {
		t.Fatalf("after unlocking, the CRL must list the revocation: %v", serials(crl))
	}
	if info, _ := s.CRLStatus(ctx); info[0].Stale {
		t.Fatal("no longer stale")
	}
}

func TestCRLsAreRenewedBeforeTheyExpire(t *testing.T) {
	s, _, clk := newPKI(t)
	_, interID := hierarchy(t, s)
	issueN(t, s, interID, "a.lab")
	number := func() int64 { return parseCRL(t, s, interID).Number.Int64() }
	if number() != 1 {
		t.Fatalf("number = %d", number())
	}

	// Nothing changed and it is fresh: nothing to do.
	clk.Add(2 * time.Hour)
	if err := s.RefreshCRLs(ctx, "system", false); err != nil || number() != 1 {
		t.Fatalf("a fresh CRL must be left alone: %v, number %d", err, number())
	}
	// A day later it is renewed, long before its nextUpdate.
	clk.Add(23 * time.Hour)
	if err := s.RefreshCRLs(ctx, "system", false); err != nil || number() != 2 {
		t.Fatalf("daily renewal: %v, number %d", err, number())
	}
	if err := s.RefreshCRLs(ctx, "system", true); err != nil || number() != 3 {
		t.Fatalf("forced refresh: %v, number %d", err, number())
	}
	// Numbers only ever grow.
	prev := number()
	clk.Add(48 * time.Hour)
	s.RefreshCRLs(ctx, "system", false)
	if number() <= prev {
		t.Fatal("CRL numbers must increase")
	}
	if info, _ := s.CRLStatus(ctx); info[0].Expired {
		t.Fatal("a renewed CRL is not expired")
	}
	// If nobody renews it for more than a week, the dashboard says so.
	clk.Add(8 * 24 * time.Hour)
	if info, _ := s.CRLStatus(ctx); !info[0].Expired {
		t.Fatal("an unrenewed CRL must be reported as expired")
	}

	s.Lock(ctx, "admin")
	if err := s.RefreshCRLs(ctx, "system", false); !errors.Is(err, ErrLocked) {
		t.Fatalf("refreshing while locked: %v", err)
	}
}

func TestWithoutAPublicURLCertificatesCarryNoAddresses(t *testing.T) {
	s, _ := newSvc(t) // no PublicURL
	_, interID := hierarchy(t, s)
	id, c := issueN(t, s, interID, "a.lab")
	if len(c.CRLDistributionPoints) != 0 || len(c.IssuingCertificateURL) != 0 {
		t.Fatal("no public URL, no addresses in the certificate")
	}
	// Revocation still works and still produces a signed CRL.
	res, err := s.RevokeCertificate(ctx, "ops", id, ca.ReasonCessationOfOperation)
	if err != nil || !res.Published {
		t.Fatalf("%+v, %v", res, err)
	}
}

// An intermediate signed elsewhere without the cRLSign key usage cannot publish
// a list. Certificates must then not promise one, and nothing may break.
func TestAnIntermediateThatCannotSignCRLs(t *testing.T) {
	s, _, _ := newPKI(t)
	b, _ := ca.NewRoot(ca.CARequest{CommonName: "Home Root", Validity: 10 * year, KeyAlgo: ca.ECDSAP384})
	rootID, _ := s.ImportRoot(ctx, "admin", "Home Root", b.CertPEM)
	req, _ := s.RequestIntermediate(ctx, "admin", rootID, interParams("No CRL"))

	root := parseCertT(t, b.CertPEM)
	kb, _ := pem.Decode(b.KeyPEM)
	key, _ := x509.ParsePKCS8PrivateKey(kb.Bytes)
	cb, _ := pem.Decode(req.CSRPEM)
	csr, _ := x509.ParseCertificateRequest(cb.Bytes)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(4242), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: root.NotAfter.Add(-time.Hour),
		KeyUsage:              x509.KeyUsageCertSign, // deliberately no cRLSign
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}, root, csr.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	interID, err := s.ImportIntermediate(ctx, "admin", req.ID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.IssueCertificate(ctx, "ops", interID, leafReq("x.lab"))
	if err != nil {
		t.Fatal(err)
	}
	c := certOf(t, res.Bundle.CertPEM)
	if len(c.CRLDistributionPoints) != 0 || len(res.Warnings) == 0 {
		t.Fatalf("a CA that cannot publish must not promise a CRL: cdp=%v warnings=%v", c.CRLDistributionPoints, res.Warnings)
	}
	rev, err := s.RevokeCertificate(ctx, "ops", res.ID, ca.ReasonKeyCompromise)
	if err != nil || rev.Published || !rev.Certificate.Revoked() {
		t.Fatalf("revocation must still be recorded: %+v, %v", rev, err)
	}
	if err := s.RefreshCRLs(ctx, "system", true); err != nil {
		t.Fatalf("a CA that cannot sign must be skipped quietly: %v", err)
	}
	info, _ := s.CRLStatus(ctx)
	if len(info) != 1 || info[0].CanSign || info[0].Published {
		t.Fatalf("status = %+v", info)
	}
	if _, err := s.PublicCRL(ctx, interID); !errors.Is(err, ErrNoCRL) {
		t.Fatalf("no CRL to serve: %v", err)
	}
}

func TestPublicCACertificate(t *testing.T) {
	s, _, _ := newPKI(t)
	rootID, interID := hierarchy(t, s)
	for _, id := range []string{rootID, interID} {
		der, err := s.PublicCACertificate(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil || !c.IsCA {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if _, err := s.PublicCACertificate(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown CA: %v", err)
	}
}

func TestNormalizePublicURL(t *testing.T) {
	ok := map[string]string{
		"":                          "",
		"  ":                        "",
		"http://pki.lab:8080":       "http://pki.lab:8080",
		"http://pki.lab:8080/":      "http://pki.lab:8080",
		"https://pki.example.com//": "https://pki.example.com",
		"http://10.0.0.5:8080":      "http://10.0.0.5:8080",
		" http://pki.lab ":          "http://pki.lab",
	}
	for in, want := range ok {
		if got, err := NormalizePublicURL(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"pki.lab:8080", "ftp://pki.lab", "http://", "http://user:pw@pki.lab", "http://pki.lab/?x=1", "http://pki.lab/#f",
		"javascript:alert(1)", "http://pki lab",
	} {
		if got, err := NormalizePublicURL(bad); err == nil {
			t.Errorf("%q must be refused, got %q", bad, got)
		}
	}
}
