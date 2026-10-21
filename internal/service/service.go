// Package service holds pki-dash's business rules. It joins the three lower
// layers: ca (cryptography), vault (keys at rest) and store (persistence).
// The HTTP API will be a thin layer over this package.
//
// Policy enforced here, not in the lower layers:
//   - the Root only signs intermediates; service certificates come from an
//     intermediate;
//   - nothing is handed to the caller unless it was also recorded;
//   - every sensitive action is audited with the acting user.
package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/store"
	"github.com/marcioamatte/pki-dash/internal/vault"
)

var (
	ErrNotInitialized     = errors.New("service: vault not initialised")
	ErrAlreadyInitialized = errors.New("service: vault already initialised")
	ErrLocked             = errors.New("service: vault is locked")
	ErrKeyOffline         = errors.New("service: this CA's private key is not held by the service")
	ErrNotARoot           = errors.New("service: operation only applies to a Root CA")
	// ErrNotRevoked means an intermediate's key cannot be destroyed while the CA is in good standing.
	ErrNotRevoked = errors.New("service: only the key of a revoked intermediate can be destroyed")
	// ErrRevocationNotPublished means the Root's CRL that lists this intermediate has not been imported yet.
	ErrRevocationNotPublished = errors.New("service: the revocation is not published in the Root's CRL yet")
	ErrIssueFromRoot          = errors.New("service: service certificates must be issued by an intermediate, not the Root")
	ErrBadParent              = errors.New("service: an intermediate must be signed by a Root CA")
)

// MaxBrowserValidity is the longest validity browsers accept for publicly
// trusted certificates. It is not required for a private CA, so exceeding it
// only produces a warning.
const MaxBrowserValidity = 398 * 24 * time.Hour

// Options configure a Service.
type Options struct {
	// KDF overrides the Argon2id cost for new vaults (the floor is still
	// enforced). The zero value means vault.DefaultParams.
	KDF vault.Params
	// PublicURL is where clients reach the public PKI listener, for example
	// http://pki.lab:8080. When set, issued certificates carry the address of the
	// issuer's CRL and certificate. Use NormalizePublicURL to validate it.
	PublicURL string
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Service is safe for concurrent use.
type Service struct {
	st   *store.Store
	opts Options

	mu sync.RWMutex
	v  *vault.Vault // nil while locked
}

// New creates a Service over an open store. The vault starts locked.
func New(st *store.Store, opts Options) *Service {
	if opts.KDF == (vault.Params{}) {
		opts.KDF = vault.DefaultParams
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{st: st, opts: opts}
}

// ---- vault lifecycle ----

// State describes the vault.
type State struct {
	Initialized bool
	Unlocked    bool
}

func (s *Service) State(ctx context.Context) (State, error) {
	_, err := s.st.VaultHeader(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return State{}, nil
	case err != nil:
		return State{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return State{Initialized: true, Unlocked: s.v != nil}, nil
}

// Init creates the vault with the master passphrase and leaves it unlocked.
func (s *Service) Init(ctx context.Context, actor, passphrase string) error {
	if _, err := s.st.VaultHeader(ctx); err == nil {
		return ErrAlreadyInitialized
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	h, v, err := vault.InitWithParams(passphrase, s.opts.KDF)
	if err != nil {
		return err
	}
	if err := s.st.SetVaultHeader(ctx, actor, h.Marshal()); err != nil {
		v.Lock()
		if errors.Is(err, store.ErrExists) {
			return ErrAlreadyInitialized
		}
		return err
	}
	s.setVault(v)
	return nil
}

// Unlock derives the master key from the passphrase.
func (s *Service) Unlock(ctx context.Context, actor, passphrase string) error {
	raw, err := s.st.VaultHeader(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotInitialized
	}
	if err != nil {
		return err
	}
	h, err := vault.ParseHeader(raw)
	if err != nil {
		return err
	}
	v, err := vault.Unlock(h, passphrase)
	if err != nil {
		// Failed unlocks are security events: record them (best effort).
		_ = s.st.AuditEvent(ctx, actor, "vault.unlock_failed", "vault", "")
		return err
	}
	if err := s.st.AuditEvent(ctx, actor, "vault.unlock", "vault", ""); err != nil {
		v.Lock() // no unaudited unlock
		return err
	}
	s.setVault(v)
	// Revocations recorded while the vault was locked can be published now. A
	// failure here must not stop the unlock: the next scheduled refresh retries.
	_ = s.RefreshCRLs(ctx, actor, false)
	return nil
}

// Lock wipes the master key from memory.
func (s *Service) Lock(ctx context.Context, actor string) error {
	s.setVault(nil)
	return s.st.AuditEvent(ctx, actor, "vault.lock", "vault", "")
}

func (s *Service) setVault(v *vault.Vault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v != nil {
		s.v.Lock()
	}
	s.v = v
}

func (s *Service) unlocked() (*vault.Vault, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.v == nil {
		return nil, ErrLocked
	}
	return s.v, nil
}

// ChangePassphrase moves every CA key to a new master passphrase. The
// operation is atomic; on error the old passphrase keeps working.
func (s *Service) ChangePassphrase(ctx context.Context, actor, newPassphrase string) error {
	v, err := s.unlocked()
	if err != nil {
		return err
	}
	h, rewrap, err := v.ChangePassphrase(newPassphrase)
	if err != nil {
		return err
	}
	if err := s.st.RewrapKeys(ctx, actor, h.Marshal(), rewrap); err != nil {
		return err
	}
	nv, err := vault.Unlock(h, newPassphrase)
	if err != nil {
		// The database already holds the new header; keeping the old vault
		// would only produce confusing failures.
		s.setVault(nil)
		return fmt.Errorf("service: passphrase changed but re-unlock failed, unlock again: %w", err)
	}
	s.setVault(nv)
	return nil
}

// ---- CAs ----

// CAParams describes a new CA. Name is both the display name and the CN.
type CAParams struct {
	Name         string
	Organization string
	Validity     time.Duration
	KeyAlgo      ca.KeyAlgo
}

func (p CAParams) req() ca.CARequest {
	return ca.CARequest{CommonName: p.Name, Organization: p.Organization, Validity: p.Validity, KeyAlgo: p.KeyAlgo}
}

// CreateRoot creates a Root CA and stores its encrypted key.
func (s *Service) CreateRoot(ctx context.Context, actor string, p CAParams) (string, error) {
	v, err := s.unlocked()
	if err != nil {
		return "", err
	}
	b, err := ca.NewRoot(p.req())
	if err != nil {
		return "", err
	}
	return s.storeCA(ctx, v, actor, p.Name, store.KindRoot, "", b)
}

// CreateIntermediate creates an intermediate CA signed by the Root parentID.
func (s *Service) CreateIntermediate(ctx context.Context, actor, parentID string, p CAParams) (string, error) {
	v, err := s.unlocked()
	if err != nil {
		return "", err
	}
	parent, err := s.st.GetCA(ctx, parentID)
	if err != nil {
		return "", err
	}
	if parent.Kind != store.KindRoot {
		return "", ErrBadParent
	}
	auth, err := s.authority(v, parent)
	if err != nil {
		return "", err
	}
	b, err := auth.NewIntermediate(p.req(), s.opts.Now())
	if err != nil {
		return "", err
	}
	return s.storeCA(ctx, v, actor, p.Name, store.KindIntermediate, parentID, b)
}

func (s *Service) storeCA(ctx context.Context, v *vault.Vault, actor, name, kind, parentID string, b *ca.Bundle) (string, error) {
	defer clear(b.KeyPEM)
	cert, err := parseCert(b.CertPEM)
	if err != nil {
		return "", err
	}
	// The blob is bound to the ID, so the ID is chosen before inserting.
	id := store.NewID()
	blob, err := v.Seal(id, b.KeyPEM)
	if err != nil {
		return "", err
	}
	return s.st.CreateCA(ctx, actor, store.CA{
		ID: id, Name: name, Kind: kind, ParentID: parentID,
		CertPEM: b.CertPEM, KeyBlob: blob,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
	})
}

// authority decrypts a stored CA key and loads it for signing.
func (s *Service) authority(v *vault.Vault, c store.CA) (*ca.Authority, error) {
	if c.KeyBlob == nil {
		return nil, ErrKeyOffline
	}
	keyPEM, err := v.Open(c.ID, c.KeyBlob)
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	return ca.Load(c.CertPEM, keyPEM)
}

// ExportCAKey returns a CA's private key in clear PKCS#8 PEM and audits the
// export. Treat the result as the most sensitive data in the system.
func (s *Service) ExportCAKey(ctx context.Context, actor, id string) ([]byte, error) {
	v, err := s.unlocked()
	if err != nil {
		return nil, err
	}
	c, err := s.st.GetCA(ctx, id)
	if err != nil {
		return nil, err
	}
	if c.KeyBlob == nil {
		return nil, ErrKeyOffline
	}
	keyPEM, err := v.Open(c.ID, c.KeyBlob)
	if err != nil {
		return nil, err
	}
	if err := s.st.AuditEvent(ctx, actor, "ca.export_key", id, c.Name); err != nil {
		clear(keyPEM)
		return nil, err
	}
	return keyPEM, nil
}

// RemoveRootKey erases the Root's private key from the service, leaving only
// its public certificate. It is irreversible: export and safely store the key
// first (ExportCAKey), or the Root can never sign again.
func (s *Service) RemoveRootKey(ctx context.Context, actor, id string) error {
	c, err := s.st.GetCA(ctx, id)
	if err != nil {
		return err
	}
	if c.Kind != store.KindRoot {
		return ErrNotARoot
	}
	return s.st.DropCAKey(ctx, actor, id, "")
}

// RemoveKey destroys a CA's private key for good: a Root's, once it is kept
// offline (see RemoveRootKey), or a revoked intermediate's.
//
// An intermediate's key is destroyed only after its revocation has been
// published, that is, after the Root's CRL listing it has been imported (see
// ImportRootCRL). Before that, no client could learn that the CA is revoked,
// and the key is the only proof of control over it that may still be needed.
func (s *Service) RemoveKey(ctx context.Context, actor, id string) error {
	c, err := s.st.GetCA(ctx, id)
	if err != nil {
		return err
	}
	if c.Kind == store.KindRoot {
		return s.RemoveRootKey(ctx, actor, id)
	}
	if c.KeyBlob == nil {
		return ErrKeyOffline
	}
	if !c.Revoked() {
		return ErrNotRevoked
	}
	serial, err := serialOf(c)
	if err != nil {
		return err
	}
	crl, err := s.st.GetImportedCRL(ctx, c.ParentID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && listedInCRL(crl.DER, []*big.Int{serial}) != 1) {
		return ErrRevocationNotPublished
	}
	if err != nil {
		return err
	}
	return s.st.DropCAKey(ctx, actor, id, fmt.Sprintf("revoked intermediate; listed in the Root's CRL number %d", crl.Number))
}

func (s *Service) ListCAs(ctx context.Context) ([]store.CA, error) { return s.st.ListCAs(ctx) }
func (s *Service) GetCA(ctx context.Context, id string) (store.CA, error) {
	return s.st.GetCA(ctx, id)
}

// CAChainPEM returns the CA's certificate followed by its issuers up to and
// including the Root: what a server presents, and what clients install.
func (s *Service) CAChainPEM(ctx context.Context, id string) ([]byte, error) {
	var out []byte
	for range 8 { // the hierarchy is at most 2 deep; the bound guards against corrupt data
		c, err := s.st.GetCA(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, c.CertPEM...)
		if c.ParentID == "" {
			return out, nil
		}
		id = c.ParentID
	}
	return nil, errors.New("service: CA hierarchy is too deep or cyclic")
}

// ---- certificates ----

// Issued is the result of issuing a service certificate. Bundle.KeyPEM is set
// only when the service generated the key, and it is the only time it exists.
type Issued struct {
	ID       string
	Bundle   *ca.Bundle
	ChainPEM []byte // issuing CA chain, excluding the leaf
	Warnings []string
}

// IssueCertificate signs a service certificate with the intermediate caID.
func (s *Service) IssueCertificate(ctx context.Context, actor, caID string, r ca.LeafRequest) (*Issued, error) {
	v, err := s.unlocked()
	if err != nil {
		return nil, err
	}
	issuer, err := s.st.GetCA(ctx, caID)
	if err != nil {
		return nil, err
	}
	if issuer.Kind == store.KindRoot {
		return nil, ErrIssueFromRoot
	}
	if issuer.Revoked() {
		return nil, ErrCARevoked
	}
	auth, err := s.authority(v, issuer)
	if err != nil {
		return nil, err
	}
	var warnings []string
	if s.opts.PublicURL != "" {
		if canSignCRL(issuer) {
			// Clients that check revocation will look for this list, so it must
			// exist before the first certificate that points to it.
			if _, err := s.st.GetCRL(ctx, caID); errors.Is(err, store.ErrNotFound) {
				if _, err := s.refreshCRL(ctx, actor, caID); err != nil {
					return nil, err
				}
			} else if err != nil {
				return nil, err
			}
			r.CRLURL, r.IssuerURL = s.crlURL(caID), s.issuerURL(caID)
		} else {
			warnings = append(warnings, "this CA's certificate has no cRLSign key usage, so it cannot publish a CRL: the certificate carries no revocation address")
		}
	}
	b, err := auth.IssueLeaf(r, s.opts.Now())
	if err != nil {
		return nil, err
	}
	cert, err := parseCert(b.CertPEM)
	if err != nil {
		return nil, err
	}
	sans := append([]string(nil), cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	// Record first: a certificate we cannot account for is never handed out.
	id, err := s.st.AddCertificate(ctx, actor, store.Certificate{
		CAID: caID, Serial: cert.SerialNumber.Text(16), CommonName: cert.Subject.CommonName,
		SANs: sans, Profile: string(r.Profile), CertPEM: b.CertPEM,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, KeyGenerated: len(b.KeyPEM) > 0,
	})
	if err != nil {
		clear(b.KeyPEM)
		return nil, err
	}
	chain, err := s.CAChainPEM(ctx, caID)
	if err != nil {
		clear(b.KeyPEM)
		return nil, err
	}
	out := &Issued{ID: id, Bundle: b, ChainPEM: chain, Warnings: warnings}
	if r.Validity > MaxBrowserValidity {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"validity exceeds %d days; browsers and many clients reject longer-lived certificates",
			int(MaxBrowserValidity.Hours()/24)))
	}
	return out, nil
}

func (s *Service) ListCertificates(ctx context.Context, caID string) ([]store.Certificate, error) {
	return s.st.ListCertificates(ctx, caID)
}

// Expiring lists certificates ending within the given window (or already
// expired), soonest first.
func (s *Service) Expiring(ctx context.Context, within time.Duration) ([]store.Certificate, error) {
	return s.st.ExpiringBefore(ctx, s.opts.Now().Add(within))
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE") {
		return nil, errors.New("service: invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Audit returns up to limit audit entries, newest first.
func (s *Service) Audit(ctx context.Context, limit int) ([]store.AuditEntry, error) {
	return s.st.Audit(ctx, limit)
}

// VerifyAudit checks the integrity of the audit log's hash chain.
func (s *Service) VerifyAudit(ctx context.Context) error { return s.st.VerifyAudit(ctx) }

// GetCertificate returns one issued certificate.
func (s *Service) GetCertificate(ctx context.Context, id string) (store.Certificate, error) {
	return s.st.GetCertificate(ctx, id)
}

// VerifyPassphrase checks the master passphrase without changing the vault's
// state. Use it to re-authenticate before the most dangerous operations
// (exporting or removing a key, changing the passphrase), so that a stolen
// login session alone is not enough. Failures are audited.
func (s *Service) VerifyPassphrase(ctx context.Context, actor, passphrase string) error {
	raw, err := s.st.VaultHeader(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotInitialized
	}
	if err != nil {
		return err
	}
	h, err := vault.ParseHeader(raw)
	if err != nil {
		return err
	}
	v, err := vault.Unlock(h, passphrase)
	if err != nil {
		_ = s.st.AuditEvent(ctx, actor, "vault.reauth_failed", "vault", "")
		return err
	}
	v.Lock()
	return nil
}
