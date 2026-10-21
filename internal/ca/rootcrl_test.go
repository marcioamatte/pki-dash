package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	cfsslcrl "github.com/cloudflare/cfssl/crl"
)

// rootCRLFixture is a Root whose key is at hand, standing in for the offline
// machine that signs the Root's CRL.
type rootCRLFixture struct {
	rootPEM []byte
	auth    *Authority
}

func newRootCRLFixture(t *testing.T) rootCRLFixture {
	t.Helper()
	b, err := NewRoot(CARequest{CommonName: "Offline Root", Validity: 10 * year, KeyAlgo: ECDSAP384})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Load(b.CertPEM, b.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return rootCRLFixture{b.CertPEM, a}
}

func (f rootCRLFixture) crl(t *testing.T, number int64, entries ...Revoked) []byte {
	t.Helper()
	der, _, _, err := f.auth.IssueCRL(entries, number, time.Now(), CRLValidity)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func entry(serial int64, reason int) Revoked {
	return Revoked{Serial: big.NewInt(serial), RevokedAt: time.Now().Add(-time.Hour), Reason: reason}
}

func TestVerifyRootCRLAcceptsEveryFormat(t *testing.T) {
	f := newRootCRLFixture(t)
	der := f.crl(t, 5, entry(1001, ReasonCACompromise), entry(1002, ReasonSuperseded))
	pemData := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	b64 := base64.StdEncoding.EncodeToString(der)
	wrapped := ""
	for i := 0; i < len(b64); i += 64 {
		wrapped += b64[i:min(i+64, len(b64))] + "\n"
	}
	for name, in := range map[string][]byte{
		"PEM":                 pemData,
		"PEM with noise":      append([]byte("  \n"), append(pemData, '\n', '\n')...),
		"raw DER":             der,
		"base64 of the DER":   []byte(b64),
		"wrapped base64":      []byte(wrapped),
		"base64 with newline": []byte(b64 + "\n"),
	} {
		got, err := VerifyRootCRL(f.rootPEM, in, time.Now())
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.Number != 5 || len(got.Entries) != 2 || got.Entries[0].Serial.Int64() != 1001 || got.Entries[0].Reason != ReasonCACompromise {
			t.Errorf("%s: parsed %+v", name, got)
		}
		if string(got.DER) != string(der) {
			t.Errorf("%s: the DER must come out unchanged, it is what gets signed-checked and served", name)
		}
	}
}

// "cfssl gencrl" writes base64 of a CRL with no CRL number and no reason codes.
func TestVerifyRootCRLAcceptsWhatCfsslProduces(t *testing.T) {
	f := newRootCRLFixture(t)
	der, err := cfsslcrl.CreateGenericCRL([]pkix.RevokedCertificate{
		{SerialNumber: big.NewInt(42), RevocationTime: time.Now()},
		{SerialNumber: new(big.Int).Lsh(big.NewInt(1), 100), RevocationTime: time.Now()},
	}, f.auth.key, f.auth.cert, time.Now().Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyRootCRL(f.rootPEM, []byte(base64.StdEncoding.EncodeToString(der)), time.Now())
	if err != nil {
		t.Fatalf("a cfssl-style CRL must be accepted: %v", err)
	}
	if got.Number != 0 || len(got.Entries) != 2 || got.Entries[0].Reason != 0 {
		t.Fatalf("parsed %+v", got)
	}
}

func TestVerifyRootCRLRejections(t *testing.T) {
	f := newRootCRLFixture(t)
	other := newRootCRLFixture(t)
	now := time.Now()
	good := f.crl(t, 1)

	// Another Root's list, even though it has the same shape.
	if _, err := VerifyRootCRL(f.rootPEM, other.crl(t, 1), now); !errors.Is(err, ErrPolicy) {
		t.Errorf("a different Root's CRL: %v", err)
	}
	// Expired and not yet valid.
	if _, err := VerifyRootCRL(f.rootPEM, good, now.Add(CRLValidity+time.Hour)); !errors.Is(err, ErrPolicy) {
		t.Errorf("expired: %v", err)
	}
	if _, err := VerifyRootCRL(f.rootPEM, good, now.Add(-time.Hour)); !errors.Is(err, ErrPolicy) {
		t.Errorf("dated in the future: %v", err)
	}
	// A list altered after signing.
	tampered := append([]byte{}, good...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := VerifyRootCRL(f.rootPEM, tampered, now); err == nil {
		t.Error("a tampered CRL must not verify")
	}
	// Delta and partial lists are not a Root's complete CRL.
	for name, oid := range map[string]asn1.ObjectIdentifier{"delta": oidDeltaCRLIndicator, "partial": oidIssuingDistributionPoint} {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: oid, Critical: true, Value: []byte{0x02, 0x01, 0x01}}},
		}, f.auth.cert, f.auth.key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRootCRL(f.rootPEM, der, now); !errors.Is(err, ErrPolicy) {
			t.Errorf("%s CRL: %v", name, err)
		}
	}
	// Not a CRL at all.
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.auth.cert.Raw})
	for name, in := range map[string][]byte{"empty": nil, "blank": []byte("  \n "), "text": []byte("not a crl"), "a certificate": cert, "bad base64": []byte("%%%%")} {
		if _, err := VerifyRootCRL(f.rootPEM, in, now); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := VerifyRootCRL([]byte("junk"), good, now); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("bad Root certificate: %v", err)
	}
}

func TestNewerThan(t *testing.T) {
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	mk := func(n int64, at time.Time) *ParsedCRL { return &ParsedCRL{Number: n, ThisUpdate: at} }
	cases := []struct {
		name       string
		c          *ParsedCRL
		prevNumber int64
		prevThis   time.Time
		ok         bool
	}{
		{"nothing published yet", mk(1, t0), 0, time.Time{}, true},
		{"higher number", mk(6, t0), 5, t0.Add(time.Hour), true}, // the number rules, even if the clock disagrees
		{"same number", mk(5, t0.Add(time.Hour)), 5, t0, false},
		{"lower number replayed", mk(4, t0.Add(48*time.Hour)), 5, t0, false},
		{"no numbers, later date", mk(0, t0.Add(time.Minute)), 0, t0, true},
		{"no numbers, same date", mk(0, t0), 0, t0, false},
		{"no numbers, older date (replay)", mk(0, t0.Add(-time.Hour)), 0, t0, false},
		{"new has a number, old had none, later date", mk(3, t0.Add(time.Hour)), 0, t0, true},
		{"new has a number, old had none, older date", mk(3, t0.Add(-time.Hour)), 0, t0, false},
		{"new has none, old had one: judged by date", mk(0, t0.Add(time.Hour)), 5, t0, true},
	}
	for _, c := range cases {
		err := c.c.NewerThan(c.prevNumber, c.prevThis)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrCRLNotNewer)) {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestCAReasons(t *testing.T) {
	for code, want := range map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true, 5: true, 6: false, 8: false, 9: false, -1: false} {
		if ValidCAReason(code) != want {
			t.Errorf("ValidCAReason(%d) = %v", code, !want)
		}
	}
	if ValidReason(ReasonCACompromise) {
		t.Fatal("cACompromise must stay invalid for a service certificate")
	}
}
