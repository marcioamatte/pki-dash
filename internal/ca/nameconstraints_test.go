package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// constrainedAuthority is a self-signed CA carrying nameConstraints, the way an
// intermediate signed offline with the openssl recipe has them.
func constrainedAuthority(t *testing.T, domains []string, ranges []*net.IPNet) *Authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Constrained"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * year),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains:         domains,
		PermittedDNSDomainsCritical: true,
		PermittedIPRanges:           ranges,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return mustAuthority(t, &Bundle{CertPEM: pemCert(der), KeyPEM: keyPEM})
}

func TestIssueLeafHonoursTheCAsNameConstraints(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.20.0.0/16")
	a := constrainedAuthority(t, []string{"lab", "mattegroup.example"}, []*net.IPNet{ipNet})
	issue := func(dns, ip string) error {
		r := LeafRequest{CommonName: "svc", Profile: ProfileServer, Validity: 30 * 24 * time.Hour, KeyAlgo: ECDSAP256}
		if dns != "" {
			r.DNSNames = []string{dns}
		}
		if ip != "" {
			r.IPs = []string{ip}
		}
		_, err := a.IssueLeaf(r, time.Now())
		return err
	}
	for _, ok := range [][2]string{{"grafana.lab", ""}, {"lab", ""}, {"*.lab", ""}, {"api.mattegroup.example", "10.20.1.2"}, {"", "10.20.30.40"}} {
		if err := issue(ok[0], ok[1]); err != nil {
			t.Errorf("%v should be allowed: %v", ok, err)
		}
	}
	for _, bad := range [][2]string{{"example.com", ""}, {"evilmattegroup.example", ""}, {"grafana.lab.evil.com", ""}, {"grafana.lab", "192.168.1.1"}, {"", "8.8.8.8"}} {
		if err := issue(bad[0], bad[1]); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%v should be refused, got %v", bad, err)
		}
	}
}

func TestIssueLeafWithoutConstraintsIsUnchanged(t *testing.T) {
	_, inter := newChain(t)
	if _, err := inter.IssueLeaf(LeafRequest{CommonName: "x", DNSNames: []string{"anything.example.org"}, Profile: ProfileServer, Validity: 24 * time.Hour, KeyAlgo: ECDSAP256}, time.Now()); err != nil {
		t.Fatal(err)
	}
}
