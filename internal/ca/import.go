package ca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/csr"
)

// ErrPolicy means a certificate is well-formed but not acceptable as a CA in
// this PKI: wrong constraints, wrong issuer, wrong key, outside its validity.
var ErrPolicy = errors.New("ca: certificate violates the CA policy")

func policyf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicy, fmt.Sprintf(format, a...))
}

// skew tolerates small clock differences between the signer and this host.
const skew = 5 * time.Minute

// NewIntermediateRequest generates a key and a certificate request for an
// intermediate CA that will be signed somewhere else, typically by an offline
// Root. The private key stays with us; only the CSR goes out.
func NewIntermediateRequest(r CARequest) (csrPEM, keyPEM []byte, err error) {
	if strings.TrimSpace(r.CommonName) == "" {
		return nil, nil, fmt.Errorf("%w: common name is required", ErrInvalidRequest)
	}
	key, err := generateKey(r.KeyAlgo)
	if err != nil {
		return nil, nil, err
	}
	csrPEM, err = csr.Generate(key, r.csr())
	if err != nil {
		return nil, nil, fmt.Errorf("ca: create intermediate csr: %w", err)
	}
	if keyPEM, err = marshalKey(key); err != nil {
		return nil, nil, err
	}
	return csrPEM, keyPEM, nil
}

// ParseRoot validates a public Root certificate that was created elsewhere and
// is to be used as a trust anchor: self-signed, a CA allowed to sign
// intermediates, using a key we accept, and currently valid.
func ParseRoot(certPEM []byte, now time.Time) (*x509.Certificate, error) {
	c, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	if !c.BasicConstraintsValid || !c.IsCA {
		return nil, policyf("not a CA certificate")
	}
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, policyf("key usage does not allow signing certificates")
	}
	if c.CheckSignatureFrom(c) != nil || c.Subject.String() != c.Issuer.String() {
		return nil, policyf("not self-signed: a Root must be its own issuer")
	}
	if c.MaxPathLen == 0 && c.MaxPathLenZero {
		return nil, policyf("this Root's path length is 0, so it cannot sign intermediates")
	}
	if err := checkPublicKey(c.PublicKey); err != nil {
		return nil, err
	}
	if err := checkValidNow(c, now); err != nil {
		return nil, err
	}
	return c, nil
}

// VerifyIntermediate checks a certificate that an external Root issued for the
// key we hold. It must be signed by parent, bind exactly that key, be a CA that
// can only sign leaf certificates, and live inside its issuer's validity.
func VerifyIntermediate(parentCertPEM, certPEM, keyPEM []byte, now time.Time) (*x509.Certificate, error) {
	parent, err := parseCert(parentCertPEM)
	if err != nil {
		return nil, err
	}
	c, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(c.PublicKey, key.Public()) {
		return nil, fmt.Errorf("%w: the certificate is not for the key that made the request", ErrKeyMismatch)
	}
	if err := c.CheckSignatureFrom(parent); err != nil {
		return nil, policyf("not signed by the chosen Root")
	}
	if !c.BasicConstraintsValid || !c.IsCA {
		return nil, policyf("not a CA certificate")
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, policyf("key usage does not allow signing certificates")
	}
	// Our hierarchy is Root, intermediate, leaf: an intermediate must not be
	// able to create further CAs.
	if !(c.MaxPathLen == 0 && c.MaxPathLenZero) {
		return nil, policyf("an intermediate must have a path length of 0 (it may only sign service certificates)")
	}
	if parent.MaxPathLen == 0 && parent.MaxPathLenZero {
		return nil, policyf("the Root's path length does not allow an intermediate below it")
	}
	if err := checkValidNow(c, now); err != nil {
		return nil, err
	}
	if c.NotBefore.Before(parent.NotBefore) || c.NotAfter.After(parent.NotAfter) {
		return nil, fmt.Errorf("%w: %w", ErrPolicy, ErrExceedsParent)
	}
	return c, nil
}

func checkValidNow(c *x509.Certificate, now time.Time) error {
	if now.After(c.NotAfter) {
		return policyf("the certificate has expired")
	}
	if now.Add(skew).Before(c.NotBefore) {
		return policyf("the certificate is not valid yet")
	}
	return nil
}

// CertPEM returns c in canonical PEM form, dropping anything around it in the
// text that was submitted.
func CertPEM(c *x509.Certificate) []byte { return pemCert(c.Raw) }
