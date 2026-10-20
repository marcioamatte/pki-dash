package ca

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

// CARequest describes a new Root or intermediate CA.
type CARequest struct {
	CommonName   string
	Organization string
	Validity     time.Duration
	KeyAlgo      KeyAlgo
}

func (r CARequest) validate() error {
	if strings.TrimSpace(r.CommonName) == "" {
		return fmt.Errorf("%w: common name is required", ErrInvalidRequest)
	}
	if r.Validity <= 0 {
		return fmt.Errorf("%w: validity must be positive", ErrInvalidRequest)
	}
	return nil
}

func (r CARequest) csr() *csr.CertificateRequest {
	req := &csr.CertificateRequest{CN: r.CommonName}
	if r.Organization != "" {
		req.Names = []csr.Name{{O: r.Organization}}
	}
	return req
}

// NewRoot creates a self-signed Root CA. Its path length is 1: it may sign
// intermediates, which in turn may only sign leaf certificates.
func NewRoot(r CARequest) (*Bundle, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	key, err := generateKey(r.KeyAlgo)
	if err != nil {
		return nil, err
	}
	req := r.csr()
	req.CA = &csr.CAConfig{PathLength: 1, Expiry: r.Validity.String()}
	certPEM, _, err := initca.NewFromSigner(req, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create root: %w", err)
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return nil, err
	}
	return &Bundle{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// NewIntermediate creates a CA signed by a. It can only sign leaf
// certificates (path length 0).
func (a *Authority) NewIntermediate(r CARequest, now time.Time) (*Bundle, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	if a.cert.MaxPathLen == 0 && a.cert.MaxPathLenZero {
		return nil, ErrPathLenExhausted
	}
	nb, na, err := validityWindow(now, r.Validity, a.cert)
	if err != nil {
		return nil, err
	}
	key, err := generateKey(r.KeyAlgo)
	if err != nil {
		return nil, err
	}
	csrPEM, err := csr.Generate(key, r.csr())
	if err != nil {
		return nil, fmt.Errorf("ca: create intermediate csr: %w", err)
	}
	policy := &config.Signing{Default: &config.SigningProfile{
		Usage:        []string{"cert sign", "crl sign"},
		Expiry:       r.Validity,
		CAConstraint: config.CAConstraint{IsCA: true, MaxPathLen: 0, MaxPathLenZero: true},
	}}
	certPEM, err := a.sign(policy, signer.SignRequest{
		Request:   string(csrPEM),
		NotBefore: nb,
		NotAfter:  na,
	})
	if err != nil {
		return nil, fmt.Errorf("ca: sign intermediate: %w", err)
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return nil, err
	}
	return &Bundle{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// Profile selects the extended key usages of a leaf certificate.
type Profile string

const (
	ProfileServer Profile = "server"
	ProfileClient Profile = "client"
	ProfileBoth   Profile = "both"
)

// LeafRequest describes a service certificate. If CSRPEM is set, only its
// public key is used: subject and SANs always come from this request. If it
// is empty, a key is generated with KeyAlgo and returned in the Bundle.
type LeafRequest struct {
	CommonName string
	DNSNames   []string
	IPs        []string
	Profile    Profile
	Validity   time.Duration
	KeyAlgo    KeyAlgo
	CSRPEM     []byte
}

var dnsLabel = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (r LeafRequest) hosts() ([]string, error) {
	var hosts []string
	for _, n := range r.DNSNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if len(n) > 253 || !dnsLabel.MatchString(n) {
			return nil, fmt.Errorf("%w: invalid DNS name %q", ErrInvalidRequest, n)
		}
		hosts = append(hosts, n)
	}
	for _, s := range r.IPs {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return nil, fmt.Errorf("%w: invalid IP address %q", ErrInvalidRequest, s)
		}
		hosts = append(hosts, ip.String())
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("%w: at least one DNS name or IP is required", ErrInvalidRequest)
	}
	return hosts, nil
}

// usage lists the cfssl usage names for a leaf. keyEncipherment is only
// meaningful (and only asserted) for RSA keys.
func (p Profile) usage(pub crypto.PublicKey) ([]string, error) {
	usage := []string{"digital signature"}
	if _, isRSA := pub.(*rsa.PublicKey); isRSA {
		usage = append(usage, "key encipherment")
	}
	switch p {
	case ProfileServer:
		usage = append(usage, "server auth")
	case ProfileClient:
		usage = append(usage, "client auth")
	case ProfileBoth:
		usage = append(usage, "server auth", "client auth")
	default:
		return nil, fmt.Errorf("%w: unknown profile %q", ErrInvalidRequest, p)
	}
	return usage, nil
}

// IssueLeaf signs a service certificate.
func (a *Authority) IssueLeaf(r LeafRequest, now time.Time) (*Bundle, error) {
	if strings.TrimSpace(r.CommonName) == "" {
		return nil, fmt.Errorf("%w: common name is required", ErrInvalidRequest)
	}
	hosts, err := r.hosts()
	if err != nil {
		return nil, err
	}
	nb, na, err := validityWindow(now, r.Validity, a.cert)
	if err != nil {
		return nil, err
	}

	var keyPEM, csrPEM []byte
	var pub crypto.PublicKey
	if len(r.CSRPEM) > 0 {
		if pub, err = checkCSR(r.CSRPEM); err != nil {
			return nil, err
		}
		csrPEM = r.CSRPEM
	} else {
		key, err := generateKey(r.KeyAlgo)
		if err != nil {
			return nil, err
		}
		if csrPEM, err = csr.Generate(key, &csr.CertificateRequest{CN: r.CommonName, Hosts: hosts}); err != nil {
			return nil, fmt.Errorf("ca: create csr: %w", err)
		}
		if keyPEM, err = marshalKey(key); err != nil {
			return nil, err
		}
		pub = key.Public()
	}

	usage, err := r.Profile.usage(pub)
	if err != nil {
		return nil, err
	}
	policy := &config.Signing{Default: &config.SigningProfile{
		Usage:  usage,
		Expiry: r.Validity,
		// Take nothing but the public key from the CSR. Subject and SANs are
		// ours; any extension the requester smuggled in is dropped.
		CSRWhitelist: &config.CSRWhitelist{
			PublicKey:          true,
			PublicKeyAlgorithm: true,
			SignatureAlgorithm: true,
		},
	}}
	certPEM, err := a.sign(policy, signer.SignRequest{
		Request:   string(csrPEM),
		Hosts:     hosts,
		Subject:   &signer.Subject{CN: r.CommonName},
		NotBefore: nb,
		NotAfter:  na,
	})
	if err != nil {
		return nil, fmt.Errorf("ca: sign leaf: %w", err)
	}
	return &Bundle{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func (a *Authority) sign(policy *config.Signing, req signer.SignRequest) ([]byte, error) {
	s, err := local.NewSigner(a.key, a.cert, signer.DefaultSigAlgo(a.key), policy)
	if err != nil {
		return nil, err
	}
	return s.Sign(req)
}

// checkCSR validates a requester-supplied CSR: well-formed, self-signature
// valid (proof of possession) and a public key we accept. It returns that key.
func checkCSR(csrPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, fmt.Errorf("%w: CSR must be PEM", ErrInvalidRequest)
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: CSR signature: %v", ErrInvalidRequest, err)
	}
	if err := checkPublicKey(req.PublicKey); err != nil {
		return nil, err
	}
	return req.PublicKey, nil
}
