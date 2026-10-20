package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

const year = 365 * 24 * time.Hour

func mustCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	c, err := parseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustAuthority(t *testing.T, b *Bundle) *Authority {
	t.Helper()
	a, err := Load(b.CertPEM, b.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// newChain returns a root and an intermediate Authority.
func newChain(t *testing.T) (root, inter *Authority) {
	t.Helper()
	rb, err := NewRoot(CARequest{CommonName: "Lab Root", Organization: "Lab", Validity: 10 * year, KeyAlgo: ECDSAP384})
	if err != nil {
		t.Fatal(err)
	}
	root = mustAuthority(t, rb)
	ib, err := root.NewIntermediate(CARequest{CommonName: "Lab Intermediate", Validity: 5 * year, KeyAlgo: ECDSAP256}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return root, mustAuthority(t, ib)
}

func TestRootConstraints(t *testing.T) {
	root, _ := newChain(t)
	c := root.Certificate()
	if !c.IsCA || !c.BasicConstraintsValid {
		t.Fatal("root must be a CA with valid basic constraints")
	}
	if c.MaxPathLen != 1 {
		t.Fatalf("root path length = %d, want 1", c.MaxPathLen)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; c.KeyUsage != want {
		t.Fatalf("root key usage = %v, want %v", c.KeyUsage, want)
	}
	if c.ExtKeyUsage != nil {
		t.Fatalf("root must not carry extended key usages: %v", c.ExtKeyUsage)
	}
	if pk, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P384() {
		t.Fatal("root key should be ECDSA P-384")
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Fatalf("root is not self-signed: %v", err)
	}
	if got := c.NotAfter.Sub(c.NotBefore); got < 10*year || got > 10*year+time.Hour {
		t.Fatalf("root validity = %v", got)
	}
}

func TestIntermediateConstraints(t *testing.T) {
	root, inter := newChain(t)
	c := inter.Certificate()
	if !c.IsCA || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Fatalf("intermediate must be a CA with path length 0: CA=%v len=%d zero=%v", c.IsCA, c.MaxPathLen, c.MaxPathLenZero)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; c.KeyUsage != want {
		t.Fatalf("intermediate key usage = %v, want %v", c.KeyUsage, want)
	}
	if err := c.CheckSignatureFrom(root.Certificate()); err != nil {
		t.Fatalf("intermediate not signed by root: %v", err)
	}
	if c.NotAfter.After(root.Certificate().NotAfter) {
		t.Fatal("intermediate outlives root")
	}

	// An intermediate must not be able to create another CA.
	_, err := inter.NewIntermediate(CARequest{CommonName: "Too Deep", Validity: year, KeyAlgo: ECDSAP256}, time.Now())
	if !errors.Is(err, ErrPathLenExhausted) {
		t.Fatalf("err = %v, want ErrPathLenExhausted", err)
	}
}

func TestLeafGeneratedKeyVerifiesAgainstChain(t *testing.T) {
	root, inter := newChain(t)
	b, err := inter.IssueLeaf(LeafRequest{
		CommonName: "app.lab.test",
		DNSNames:   []string{"App.Lab.Test", "*.apps.lab.test"},
		IPs:        []string{"192.168.10.5", "fd00::5"},
		Profile:    ProfileServer,
		Validity:   year,
		KeyAlgo:    ECDSAP256,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.KeyPEM) == 0 {
		t.Fatal("generated key must be returned")
	}
	leaf := mustCert(t, b.CertPEM)

	if leaf.IsCA {
		t.Fatal("leaf must not be a CA")
	}
	if leaf.Subject.CommonName != "app.lab.test" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	if want := []string{"app.lab.test", "*.apps.lab.test"}; !slices.Equal(leaf.DNSNames, want) {
		t.Fatalf("DNS SANs = %v, want %v", leaf.DNSNames, want)
	}
	var ips []string
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	if want := []string{"192.168.10.5", "fd00::5"}; !slices.Equal(ips, want) {
		t.Fatalf("IP SANs = %v, want %v", ips, want)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatalf("EKU = %v", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Fatal("ECDSA leaf must not assert keyEncipherment")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("leaf needs digitalSignature")
	}
	if leaf.NotAfter.After(inter.Certificate().NotAfter) {
		t.Fatal("leaf outlives intermediate")
	}

	// The key we returned must match the certificate.
	k, err := parseKey(b.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(leaf.PublicKey, k.Public()) {
		t.Fatal("returned key does not match certificate")
	}

	// Full chain verification, as a TLS client would do it.
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.Certificate())
	inters.AddCert(inter.Certificate())
	for _, name := range []string{"app.lab.test", "x.apps.lab.test"} {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inters, DNSName: name,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatalf("verify %s: %v", name, err)
		}
	}
	// Without the intermediate the chain must not verify.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err == nil {
		t.Fatal("verification must fail without the intermediate")
	}
}

func TestLeafProfiles(t *testing.T) {
	_, inter := newChain(t)
	cases := map[Profile][]x509.ExtKeyUsage{
		ProfileServer: {x509.ExtKeyUsageServerAuth},
		ProfileClient: {x509.ExtKeyUsageClientAuth},
		ProfileBoth:   {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for p, want := range cases {
		b, err := inter.IssueLeaf(LeafRequest{CommonName: "x", DNSNames: []string{"x.lab"}, Profile: p, Validity: year, KeyAlgo: RSA3072}, time.Now())
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		leaf := mustCert(t, b.CertPEM)
		if !slices.Equal(leaf.ExtKeyUsage, want) {
			t.Fatalf("%s: EKU = %v, want %v", p, leaf.ExtKeyUsage, want)
		}
		if leaf.PublicKey.(*rsa.PublicKey).N.BitLen() != 3072 {
			t.Fatalf("%s: expected RSA 3072", p)
		}
	}
}

func csrWith(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// A requester-supplied CSR contributes its public key and nothing else.
func TestLeafFromCSRIgnoresRequesterContent(t *testing.T) {
	_, inter := newChain(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Ask for a CA certificate, extra SANs and a spoofed subject.
	bcDER, _ := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{true})
	csrPEM := csrWith(t, key, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "evil", Organization: []string{"Spoofed Corp"}},
		DNSNames:    []string{"victim.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bcDER},
		},
	})

	b, err := inter.IssueLeaf(LeafRequest{
		CommonName: "good.lab", DNSNames: []string{"good.lab"}, Profile: ProfileServer,
		Validity: year, CSRPEM: csrPEM,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.KeyPEM) != 0 {
		t.Fatal("no key should be returned for a CSR flow")
	}
	leaf := mustCert(t, b.CertPEM)
	if leaf.IsCA {
		t.Fatal("CSR must not be able to request CA status")
	}
	if leaf.Subject.CommonName != "good.lab" || len(leaf.Subject.Organization) != 0 {
		t.Fatalf("subject must come from the request, got %v", leaf.Subject)
	}
	if !slices.Equal(leaf.DNSNames, []string{"good.lab"}) || len(leaf.IPAddresses) != 0 {
		t.Fatalf("SANs must come from the request, got %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		t.Fatal("certificate must carry the CSR's public key")
	}
}

func TestCSRRejections(t *testing.T) {
	_, inter := newChain(t)
	req := func(csr []byte) LeafRequest {
		return LeafRequest{CommonName: "x", DNSNames: []string{"x.lab"}, Profile: ProfileServer, Validity: year, CSRPEM: csr}
	}

	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, err := inter.IssueLeaf(req(csrWith(t, weak, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}})), time.Now())
	if !errors.Is(err, ErrWeakKey) {
		t.Fatalf("RSA-1024: err = %v, want ErrWeakKey", err)
	}

	// Tamper with the signed content: proof of possession must fail.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := csrWith(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "abcdefgh"}})
	block, _ := pem.Decode(good)
	i := slices.Index(block.Bytes, 'a')
	block.Bytes[i] = 'z'
	_, err = inter.IssueLeaf(req(pem.EncodeToMemory(block)), time.Now())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("tampered CSR: err = %v, want ErrInvalidRequest", err)
	}

	_, err = inter.IssueLeaf(req([]byte("not pem")), time.Now())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("garbage CSR: err = %v, want ErrInvalidRequest", err)
	}
}

func TestLeafRequestValidation(t *testing.T) {
	_, inter := newChain(t)
	ok := LeafRequest{CommonName: "x", DNSNames: []string{"x.lab"}, Profile: ProfileServer, Validity: year, KeyAlgo: ECDSAP256}
	mut := map[string]func(*LeafRequest){
		"no common name": func(r *LeafRequest) { r.CommonName = " " },
		"no SANs":        func(r *LeafRequest) { r.DNSNames = nil },
		"bad DNS":        func(r *LeafRequest) { r.DNSNames = []string{"bad name.lab"} },
		"bad DNS slash":  func(r *LeafRequest) { r.DNSNames = []string{"a/b.lab"} },
		"bare wildcard":  func(r *LeafRequest) { r.DNSNames = []string{"*"} },
		"bad IP":         func(r *LeafRequest) { r.IPs = []string{"300.1.1.1"} },
		"bad profile":    func(r *LeafRequest) { r.Profile = "ca" },
		"zero validity":  func(r *LeafRequest) { r.Validity = 0 },
	}
	for name, f := range mut {
		r := ok
		f(&r)
		if _, err := inter.IssueLeaf(r, time.Now()); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
	r := ok
	r.KeyAlgo = "dsa-1024"
	if _, err := inter.IssueLeaf(r, time.Now()); !errors.Is(err, ErrUnsupportedAlgo) {
		t.Errorf("bad algo: err = %v", err)
	}
}

func TestValidityCannotExceedIssuer(t *testing.T) {
	root, inter := newChain(t)
	_, err := inter.IssueLeaf(LeafRequest{CommonName: "x", DNSNames: []string{"x.lab"}, Profile: ProfileServer, Validity: 6 * year, KeyAlgo: ECDSAP256}, time.Now())
	if !errors.Is(err, ErrExceedsParent) {
		t.Fatalf("leaf: err = %v, want ErrExceedsParent", err)
	}
	_, err = root.NewIntermediate(CARequest{CommonName: "x", Validity: 11 * year, KeyAlgo: ECDSAP256}, time.Now())
	if !errors.Is(err, ErrExceedsParent) {
		t.Fatalf("intermediate: err = %v, want ErrExceedsParent", err)
	}
}

func TestLoadChecks(t *testing.T) {
	root, inter := newChain(t)
	rb, _ := NewRoot(CARequest{CommonName: "Other", Validity: year, KeyAlgo: ECDSAP256})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Certificate().Raw})

	// Key from a different CA.
	if _, err := Load(rootPEM, rb.KeyPEM); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("mismatch: err = %v", err)
	}
	// A leaf certificate is not a CA.
	lb, err := inter.IssueLeaf(LeafRequest{CommonName: "x", DNSNames: []string{"x.lab"}, Profile: ProfileServer, Validity: year, KeyAlgo: ECDSAP256}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(lb.CertPEM, lb.KeyPEM); !errors.Is(err, ErrNotACA) {
		t.Fatalf("leaf as CA: err = %v", err)
	}
	if _, err := Load([]byte("x"), []byte("y")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("garbage: err = %v", err)
	}
}

func TestSerialNumbersAreUniqueAndLarge(t *testing.T) {
	_, inter := newChain(t)
	seen := map[string]bool{}
	for range 5 {
		b, err := inter.IssueLeaf(LeafRequest{CommonName: "x", DNSNames: []string{"x.lab"}, Profile: ProfileServer, Validity: year, KeyAlgo: ECDSAP256}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		sn := mustCert(t, b.CertPEM).SerialNumber
		if sn.BitLen() < 64 {
			t.Fatalf("serial too small (%d bits): predictable serials weaken the CA", sn.BitLen())
		}
		if sn.Sign() <= 0 {
			t.Fatal("serial must be positive")
		}
		if seen[sn.String()] {
			t.Fatal("duplicate serial")
		}
		seen[sn.String()] = true
	}
}
