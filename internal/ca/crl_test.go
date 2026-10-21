package ca

import (
	"bytes"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestIssueCRL(t *testing.T) {
	_, inter := newChain(t)
	now := time.Now().UTC().Truncate(time.Second)
	revokedAt := now.Add(-2 * time.Hour)
	entries := []Revoked{
		{Serial: big.NewInt(1001), RevokedAt: revokedAt, Reason: ReasonKeyCompromise},
		{Serial: new(big.Int).Lsh(big.NewInt(1), 150), RevokedAt: revokedAt.Add(time.Minute), Reason: ReasonUnspecified},
		{Serial: big.NewInt(1003), RevokedAt: revokedAt.Add(2 * time.Minute), Reason: ReasonSuperseded},
	}
	der, this, next, err := inter.IssueCRL(entries, 7, now, CRLValidity)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	// A client verifies the list against the issuing CA, nothing else.
	if err := crl.CheckSignatureFrom(inter.Certificate()); err != nil {
		t.Fatalf("CRL signature does not verify against the issuer: %v", err)
	}
	if crl.Number.Int64() != 7 {
		t.Fatalf("number = %v", crl.Number)
	}
	if !crl.ThisUpdate.Equal(this) || !crl.NextUpdate.Equal(next) || !this.Before(now) || next.Sub(now) != CRLValidity {
		t.Fatalf("validity: this=%v next=%v (now=%v)", this, next, now)
	}
	if !bytes.Equal(crl.AuthorityKeyId, inter.Certificate().SubjectKeyId) {
		t.Fatal("the CRL must name its issuer through the authority key identifier")
	}
	if len(crl.RevokedCertificateEntries) != 3 {
		t.Fatalf("entries = %d", len(crl.RevokedCertificateEntries))
	}
	for i, want := range entries {
		got := crl.RevokedCertificateEntries[i]
		if got.SerialNumber.Cmp(want.Serial) != 0 || got.ReasonCode != want.Reason || !got.RevocationTime.Equal(want.RevokedAt) {
			t.Errorf("entry %d = %v %d %v, want %v %d %v", i, got.SerialNumber, got.ReasonCode, got.RevocationTime, want.Serial, want.Reason, want.RevokedAt)
		}
	}
	// It does not verify against some other CA.
	other, _ := newChain(t)
	if crl.CheckSignatureFrom(other.Certificate()) == nil {
		t.Fatal("a CRL must not verify against a different issuer")
	}
}

func TestEmptyCRLIsValid(t *testing.T) {
	_, inter := newChain(t)
	der, _, _, err := inter.IssueCRL(nil, 1, time.Now(), CRLValidity)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil || len(crl.RevokedCertificateEntries) != 0 || crl.CheckSignatureFrom(inter.Certificate()) != nil {
		t.Fatalf("empty CRL: %v", err)
	}
}

func TestIssueCRLRejectsBadInput(t *testing.T) {
	_, inter := newChain(t)
	now := time.Now()
	good := Revoked{Serial: big.NewInt(5), RevokedAt: now, Reason: ReasonSuperseded}
	for name, c := range map[string]struct {
		entries  []Revoked
		number   int64
		validity time.Duration
	}{
		"number zero":      {[]Revoked{good}, 0, CRLValidity},
		"negative number":  {[]Revoked{good}, -3, CRLValidity},
		"no validity":      {[]Revoked{good}, 1, 0},
		"nil serial":       {[]Revoked{{RevokedAt: now}}, 1, CRLValidity},
		"zero serial":      {[]Revoked{{Serial: big.NewInt(0), RevokedAt: now}}, 1, CRLValidity},
		"unknown reason":   {[]Revoked{{Serial: big.NewInt(5), RevokedAt: now, Reason: 99}}, 1, CRLValidity},
		"certificate hold": {[]Revoked{{Serial: big.NewInt(5), RevokedAt: now, Reason: 6}}, 1, CRLValidity},
	} {
		if _, _, _, err := inter.IssueCRL(c.entries, c.number, now, c.validity); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
	for code, want := range map[int]bool{0: true, 1: true, 2: false, 3: true, 4: true, 5: true, 6: false, 8: false, 9: false, -1: false} {
		if ValidReason(code) != want {
			t.Errorf("ValidReason(%d) = %v", code, !want)
		}
	}
}

// A CA certificate made elsewhere may lack the cRLSign key usage; that must be a
// clear error, not a malformed CRL.
func TestCRLNeedsTheCRLSignUsage(t *testing.T) {
	f := newFixture(t)
	csrPEM, keyPEM := request(t, "No CRL Usage")
	o := goodOpts(f.root)
	o.usage = x509.KeyUsageCertSign // no cRLSign
	certPEM := externalSign(t, f.root, f.rootKey, csrPEM, o)
	a, err := Load(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := a.IssueCRL(nil, 1, time.Now(), CRLValidity); !errors.Is(err, ErrNotCRLSigner) {
		t.Fatalf("err = %v, want ErrNotCRLSigner", err)
	}
}

func TestLeafCarriesTheRevocationAndIssuerURLs(t *testing.T) {
	_, inter := newChain(t)
	issue := func(crl, issuer string) *x509.Certificate {
		b, err := inter.IssueLeaf(LeafRequest{
			CommonName: "app.lab", DNSNames: []string{"app.lab"}, Profile: ProfileServer,
			Validity: year, KeyAlgo: ECDSAP256, CRLURL: crl, IssuerURL: issuer,
		}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return mustCert(t, b.CertPEM)
	}
	c := issue("http://pki.lab:8080/crl/abc.crl", "http://pki.lab:8080/ca/abc.crt")
	if len(c.CRLDistributionPoints) != 1 || c.CRLDistributionPoints[0] != "http://pki.lab:8080/crl/abc.crl" {
		t.Fatalf("CRL distribution points = %v", c.CRLDistributionPoints)
	}
	if len(c.IssuingCertificateURL) != 1 || c.IssuingCertificateURL[0] != "http://pki.lab:8080/ca/abc.crt" {
		t.Fatalf("issuing certificate URL = %v", c.IssuingCertificateURL)
	}
	plain := issue("", "")
	if len(plain.CRLDistributionPoints) != 0 || len(plain.IssuingCertificateURL) != 0 {
		t.Fatal("without URLs, a certificate must not carry the extensions")
	}
}
