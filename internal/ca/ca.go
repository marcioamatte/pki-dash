// Package ca isolates the cfssl library behind pki-dash's own interface.
// No other package may import cfssl directly.
//
// The package is stateless and never touches the disk: private keys come in
// and go out as PEM bytes, so the caller decides how they are encrypted and
// stored.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/log"
)

func init() {
	// cfssl logs every signing operation. Our audit log is the source of
	// truth, so silence the library's own logger.
	log.Level = log.LevelFatal
}

// KeyAlgo selects the algorithm and size of a generated private key.
type KeyAlgo string

const (
	ECDSAP256 KeyAlgo = "ecdsa-p256"
	ECDSAP384 KeyAlgo = "ecdsa-p384"
	RSA3072   KeyAlgo = "rsa-3072"
	RSA4096   KeyAlgo = "rsa-4096"
)

// backdate absorbs small clock differences between the CA and its clients.
const backdate = 5 * time.Minute

var (
	ErrInvalidRequest   = errors.New("ca: invalid request")
	ErrNotACA           = errors.New("ca: certificate is not a usable CA")
	ErrKeyMismatch      = errors.New("ca: private key does not match certificate")
	ErrExceedsParent    = errors.New("ca: validity exceeds the issuer's validity")
	ErrWeakKey          = errors.New("ca: public key is too weak")
	ErrUnsupportedAlgo  = errors.New("ca: unsupported key algorithm")
	ErrPathLenExhausted = errors.New("ca: issuer's path length does not allow a CA below it")
)

// Bundle is an issued certificate. KeyPEM is empty when the caller supplied
// a CSR, because the private key never reached us.
type Bundle struct {
	CertPEM []byte
	KeyPEM  []byte
}

// Authority is a CA that can sign: its certificate plus its private key.
type Authority struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// Load builds an Authority from PEM-encoded certificate and PKCS#8 key.
func Load(certPEM, keyPEM []byte) (*Authority, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrNotACA
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, ErrKeyMismatch
	}
	return &Authority{cert: cert, key: key}, nil
}

// Certificate returns the CA certificate.
func (a *Authority) Certificate() *x509.Certificate { return a.cert }

func generateKey(algo KeyAlgo) (crypto.Signer, error) {
	switch algo {
	case ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgo, algo)
}

func marshalKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%w: key must be PKCS#8 PEM", ErrInvalidRequest)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: key cannot sign", ErrInvalidRequest)
	}
	return s, nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: certificate must be PEM", ErrInvalidRequest)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return c, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ae, ok := a.(equaler)
	return ok && ae.Equal(b)
}

// checkPublicKey rejects keys weaker than we are willing to certify.
func checkPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("%w: RSA below 2048 bits", ErrWeakKey)
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			return fmt.Errorf("%w: ECDSA below 256 bits", ErrWeakKey)
		}
	default:
		return fmt.Errorf("%w: only RSA and ECDSA keys are accepted", ErrWeakKey)
	}
	return nil
}

// validityWindow computes [notBefore, notAfter] for a certificate issued
// now, never starting before the issuer's own start nor ending after it.
func validityWindow(now time.Time, validity time.Duration, issuer *x509.Certificate) (nb, na time.Time, err error) {
	if validity <= 0 {
		return nb, na, fmt.Errorf("%w: validity must be positive", ErrInvalidRequest)
	}
	nb = now.Add(-backdate)
	if issuer != nil && nb.Before(issuer.NotBefore) {
		nb = issuer.NotBefore
	}
	na = now.Add(validity)
	if issuer != nil && na.After(issuer.NotAfter) {
		return nb, na, ErrExceedsParent
	}
	return nb.UTC(), na.UTC(), nil
}
