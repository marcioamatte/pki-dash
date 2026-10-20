package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// signOpts describes how a stand-in "offline Root" signs a CSR, the way
// openssl or cfssl would outside this service.
type signOpts struct {
	isCA      bool
	pathLen   int // 0 with pathZero means "pathlen:0"; -1 means unset
	pathZero  bool
	usage     x509.KeyUsage
	notBefore time.Time
	notAfter  time.Time
}

func goodOpts(parent *x509.Certificate) signOpts {
	return signOpts{
		isCA: true, pathLen: 0, pathZero: true,
		usage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		notBefore: time.Now().Add(-time.Minute), notAfter: parent.NotAfter.Add(-time.Hour),
	}
}

func externalSign(t *testing.T, parent *x509.Certificate, parentKey crypto.Signer, csrPEM []byte, o signOpts) []byte {
	t.Helper()
	blk, _ := pem.Decode(csrPEM)
	req, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || req.CheckSignature() != nil {
		t.Fatalf("bad CSR: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: req.Subject,
		NotBefore: o.notBefore, NotAfter: o.notAfter,
		KeyUsage: o.usage, BasicConstraintsValid: true, IsCA: o.isCA,
		MaxPathLen: o.pathLen, MaxPathLenZero: o.pathZero,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, req.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return pemCert(der)
}

type fixture struct {
	rootPEM []byte
	root    *x509.Certificate
	rootKey crypto.Signer
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	b, err := NewRoot(CARequest{CommonName: "Offline Root", Validity: 10 * year, KeyAlgo: ECDSAP384})
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseKey(b.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{b.CertPEM, mustCert(t, b.CertPEM), key}
}

func request(t *testing.T, name string) (csrPEM, keyPEM []byte) {
	t.Helper()
	csrPEM, keyPEM, err := NewIntermediateRequest(CARequest{CommonName: name, Organization: "Lab", KeyAlgo: ECDSAP256})
	if err != nil {
		t.Fatal(err)
	}
	return csrPEM, keyPEM
}

func TestNewIntermediateRequest(t *testing.T) {
	csrPEM, keyPEM := request(t, "Lab Intermediate")
	blk, _ := pem.Decode(csrPEM)
	req, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || req.CheckSignature() != nil {
		t.Fatalf("CSR invalid: %v", err)
	}
	if req.Subject.CommonName != "Lab Intermediate" || len(req.Subject.Organization) != 1 {
		t.Fatalf("subject = %v", req.Subject)
	}
	key, err := parseKey(keyPEM)
	if err != nil || !publicKeysEqual(req.PublicKey, key.Public()) {
		t.Fatal("the returned key must be the one in the CSR")
	}
	if _, _, err := NewIntermediateRequest(CARequest{CommonName: " ", KeyAlgo: ECDSAP256}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty name: %v", err)
	}
	if _, _, err := NewIntermediateRequest(CARequest{CommonName: "x", KeyAlgo: "dsa"}); !errors.Is(err, ErrUnsupportedAlgo) {
		t.Fatalf("bad algo: %v", err)
	}
}

func TestVerifyIntermediateAcceptsAProperCertificate(t *testing.T) {
	f := newFixture(t)
	csrPEM, keyPEM := request(t, "Lab Intermediate")
	certPEM := externalSign(t, f.root, f.rootKey, csrPEM, goodOpts(f.root))
	got, err := VerifyIntermediate(f.rootPEM, certPEM, keyPEM, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject.CommonName != "Lab Intermediate" {
		t.Fatalf("subject = %v", got.Subject)
	}
	// Surrounding text is dropped: the canonical form is what we would store.
	noisy := append([]byte("# pasted from an email\n"), append(certPEM, []byte("\n-----BEGIN JUNK-----\n")...)...)
	again, err := VerifyIntermediate(f.rootPEM, noisy, keyPEM, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if string(CertPEM(again)) != string(certPEM) {
		t.Fatal("CertPEM must give back the canonical PEM")
	}
}

func TestVerifyIntermediateRejections(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	csrPEM, keyPEM := request(t, "Lab Intermediate")
	now := time.Now()

	type tc struct {
		name   string
		mutate func(o *signOpts)
		want   error
	}
	cases := []tc{
		{"not a CA", func(o *signOpts) { o.isCA = false; o.pathZero = false; o.pathLen = 0 }, ErrPolicy},
		{"path length unset", func(o *signOpts) { o.pathLen = -1; o.pathZero = false }, ErrPolicy},
		{"path length 1", func(o *signOpts) { o.pathLen = 1; o.pathZero = false }, ErrPolicy},
		{"cannot sign certificates", func(o *signOpts) { o.usage = x509.KeyUsageDigitalSignature }, ErrPolicy},
		{"already expired", func(o *signOpts) {
			o.notBefore, o.notAfter = f.root.NotBefore, now.Add(-time.Hour)
		}, ErrPolicy},
		{"not valid yet", func(o *signOpts) {
			o.notBefore, o.notAfter = now.Add(2*time.Hour), f.root.NotAfter.Add(-time.Hour)
		}, ErrPolicy},
		{"outlives the Root", func(o *signOpts) { o.notAfter = f.root.NotAfter.Add(24 * time.Hour) }, ErrExceedsParent},
		{"starts before the Root", func(o *signOpts) { o.notBefore = f.root.NotBefore.Add(-24 * time.Hour) }, ErrExceedsParent},
	}
	for _, c := range cases {
		o := goodOpts(f.root)
		c.mutate(&o)
		certPEM := externalSign(t, f.root, f.rootKey, csrPEM, o)
		_, err := VerifyIntermediate(f.rootPEM, certPEM, keyPEM, now)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}

	// Signed by a different Root.
	foreign := externalSign(t, other.root, other.rootKey, csrPEM, goodOpts(other.root))
	if _, err := VerifyIntermediate(f.rootPEM, foreign, keyPEM, now); !errors.Is(err, ErrPolicy) {
		t.Errorf("foreign issuer: %v", err)
	}
	// A certificate for somebody else's key.
	otherCSR, _ := request(t, "Someone Else")
	theirs := externalSign(t, f.root, f.rootKey, otherCSR, goodOpts(f.root))
	if _, err := VerifyIntermediate(f.rootPEM, theirs, keyPEM, now); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("wrong key: %v", err)
	}
	// Garbage.
	if _, err := VerifyIntermediate(f.rootPEM, []byte("nope"), keyPEM, now); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("garbage: %v", err)
	}
}

func TestVerifyIntermediateUnderARootThatCannotHaveOne(t *testing.T) {
	// A Root whose path length is 0 may only sign leaves.
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Flat Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * year),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	root := pemCert(der)
	rc := mustCert(t, root)
	csrPEM, keyPEM := request(t, "Lab Intermediate")
	certPEM := externalSign(t, rc, key, csrPEM, goodOpts(rc))
	if _, err := VerifyIntermediate(root, certPEM, keyPEM, time.Now()); !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestParseRoot(t *testing.T) {
	f := newFixture(t)
	if c, err := ParseRoot(f.rootPEM, time.Now()); err != nil || c.Subject.CommonName != "Offline Root" {
		t.Fatalf("a proper Root: %v", err)
	}

	// An intermediate is not a Root.
	csrPEM, _ := request(t, "Inter")
	inter := externalSign(t, f.root, f.rootKey, csrPEM, goodOpts(f.root))
	if _, err := ParseRoot(inter, time.Now()); !errors.Is(err, ErrPolicy) {
		t.Errorf("intermediate as Root: %v", err)
	}
	// Neither is a leaf.
	_, ia := newChain(t)
	lb, _ := ia.IssueLeaf(LeafRequest{CommonName: "x", DNSNames: []string{"x.lab"}, Profile: ProfileServer, Validity: year, KeyAlgo: ECDSAP256}, time.Now())
	if _, err := ParseRoot(lb.CertPEM, time.Now()); !errors.Is(err, ErrPolicy) {
		t.Errorf("leaf as Root: %v", err)
	}
	// Expired.
	if _, err := ParseRoot(f.rootPEM, time.Now().Add(11*year)); !errors.Is(err, ErrPolicy) {
		t.Errorf("expired Root: %v", err)
	}
	// Path length 0 cannot sign intermediates.
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	flat := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Flat"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(year),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true}
	der, _ := x509.CreateCertificate(rand.Reader, flat, flat, key.Public(), key)
	if _, err := ParseRoot(pemCert(der), time.Now()); !errors.Is(err, ErrPolicy) {
		t.Errorf("path length 0: %v", err)
	}
	// A weak key is refused even on a self-signed Root.
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	wt := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Weak"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(year),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1}
	wder, _ := x509.CreateCertificate(rand.Reader, wt, wt, &weak.PublicKey, weak)
	if _, err := ParseRoot(pemCert(wder), time.Now()); !errors.Is(err, ErrWeakKey) {
		t.Errorf("weak key: %v", err)
	}
	// An unsigned-by-itself certificate claiming to be a Root (issuer is someone else).
	if _, err := ParseRoot([]byte("garbage"), time.Now()); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("garbage: %v", err)
	}
}
