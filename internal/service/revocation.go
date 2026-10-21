package service

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/store"
)

var (
	// ErrAlreadyRevoked means the certificate was revoked before.
	ErrAlreadyRevoked = errors.New("service: certificate is already revoked")
	// ErrNotCRLSigner means the CA cannot publish CRLs because its certificate lacks cRLSign.
	ErrNotCRLSigner = ca.ErrNotCRLSigner
	// ErrNoCRL means the CA has not published a CRL.
	ErrNoCRL = errors.New("service: no CRL published for this CA")
)

// CRLRefreshAfter is how old a CRL may get before it is reissued even though
// nothing changed. The list stays valid for ca.CRLValidity (7 days), so a
// weekend with a locked vault does not make it expire.
const CRLRefreshAfter = 24 * time.Hour

// NormalizePublicURL checks the address clients use to reach the public PKI
// listener (for example http://pki.lab:8080) and returns it without a trailing
// slash. It is what ends up inside certificates, so it must be a plain
// http(s) base URL.
func NormalizePublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("service: public URL must look like http://host[:port] (got %q)", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func (s *Service) crlURL(caID string) string    { return s.opts.PublicURL + "/crl/" + caID + ".crl" }
func (s *Service) issuerURL(caID string) string { return s.opts.PublicURL + "/ca/" + caID + ".crt" }

// canSignCRL reports whether a CA's certificate allows signing revocation lists.
func canSignCRL(c store.CA) bool {
	cert, err := parseCert(c.CertPEM)
	return err == nil && cert.KeyUsage&x509.KeyUsageCRLSign != 0
}

// RevokeResult is the outcome of a revocation.
type RevokeResult struct {
	Certificate store.Certificate
	// Published is true when the CRL that lists this revocation has been signed
	// and is being served. False means the revocation is recorded but clients
	// will not see it until the CRL is refreshed (the vault is locked, or the
	// issuing CA cannot sign CRLs).
	Published bool
}

// RevokeCertificate revokes a service certificate for good. The revocation is
// recorded first and always, even if the vault is locked: a certificate whose
// key leaked must stop being valid here at once. Publishing it needs the CA's
// key, so it happens right away when the vault is unlocked, and otherwise as
// soon as it is.
func (s *Service) RevokeCertificate(ctx context.Context, actor, certID string, reason int) (RevokeResult, error) {
	if !ca.ValidReason(reason) {
		return RevokeResult{}, fmt.Errorf("%w: unsupported revocation reason", ca.ErrInvalidRequest)
	}
	c, err := s.st.RevokeCertificate(ctx, actor, certID, reason, s.opts.Now())
	if errors.Is(err, store.ErrAlreadyRevoked) {
		return RevokeResult{}, ErrAlreadyRevoked
	}
	if err != nil {
		return RevokeResult{}, err
	}
	res := RevokeResult{Certificate: c}
	if _, err := s.refreshCRL(ctx, actor, c.CAID); err == nil {
		res.Published = true
	} else if !errors.Is(err, ErrLocked) && !errors.Is(err, ErrNotCRLSigner) && !errors.Is(err, ErrCARevoked) {
		return res, err
	}
	return res, nil
}

// refreshCRL signs and stores a new CRL for an intermediate whose key we hold.
func (s *Service) refreshCRL(ctx context.Context, actor, caID string) (store.CRL, error) {
	v, err := s.unlocked()
	if err != nil {
		return store.CRL{}, err
	}
	c, err := s.st.GetCA(ctx, caID)
	if err != nil {
		return store.CRL{}, err
	}
	if c.Revoked() {
		return store.CRL{}, ErrCARevoked // a revoked CA's key signs nothing more
	}
	auth, err := s.authority(v, c)
	if err != nil {
		return store.CRL{}, err
	}
	now := s.opts.Now()
	return s.st.PutNextCRL(ctx, actor, caID, func(number int64, revoked []store.RevokedEntry) ([]byte, time.Time, time.Time, error) {
		entries := make([]ca.Revoked, 0, len(revoked))
		for _, r := range revoked {
			serial, ok := new(big.Int).SetString(r.Serial, 16)
			if !ok {
				return nil, time.Time{}, time.Time{}, fmt.Errorf("service: stored serial %q is not hex", r.Serial)
			}
			entries = append(entries, ca.Revoked{Serial: serial, RevokedAt: r.RevokedAt, Reason: r.Reason})
		}
		return auth.IssueCRL(entries, number, now, ca.CRLValidity)
	})
}

// RefreshCRLs brings every CRL up to date: it publishes one for any CA that has
// none, reissues those that miss a revocation or are older than CRLRefreshAfter,
// and with force reissues them all. It needs the vault unlocked. One CA's
// failure does not stop the others; the errors are returned together.
func (s *Service) RefreshCRLs(ctx context.Context, actor string, force bool) error {
	if _, err := s.unlocked(); err != nil {
		return err
	}
	cas, err := s.st.ListCAs(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range cas {
		if c.Kind != store.KindIntermediate || c.KeyBlob == nil || c.Revoked() || !canSignCRL(c) {
			continue
		}
		due, err := s.crlDue(ctx, c.ID, force)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !due {
			continue
		}
		if _, err := s.refreshCRL(ctx, actor, c.ID); err != nil {
			errs = append(errs, fmt.Errorf("CRL of %s: %w", c.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) crlDue(ctx context.Context, caID string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	crl, err := s.st.GetCRL(ctx, caID)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	n, err := s.st.RevokedCount(ctx, caID)
	if err != nil {
		return false, err
	}
	return n != crl.RevokedCount || !s.opts.Now().Before(crl.GeneratedAt.Add(CRLRefreshAfter)), nil
}

// CRLInfo describes the revocation list of one CA, for the dashboard.
type CRLInfo struct {
	CAID, CAName string
	Kind         string // "intermediate" (this service signs it) or "root" (signed offline and imported)
	CARevoked    bool   // the CA itself is revoked
	External     bool   // the list is made elsewhere and imported
	KeyHeld      bool   // the service holds the key, so it can sign
	CanSign      bool   // the CA certificate allows signing CRLs
	Published    bool
	Number       int64
	ThisUpdate   time.Time
	NextUpdate   time.Time
	Revoked      int  // revoked certificates now
	InList       int  // revoked certificates in the published CRL
	Stale        bool // a revocation is not in the published CRL yet
	Expired      bool // the published CRL is past its nextUpdate: clients that check will refuse
}

// CRLStatus reports on the revocation lists: each intermediate's, and a Root's
// when it has revoked intermediates to account for or a list already imported.
func (s *Service) CRLStatus(ctx context.Context) ([]CRLInfo, error) {
	cas, err := s.st.ListCAs(ctx)
	if err != nil {
		return nil, err
	}
	var out []CRLInfo
	for _, c := range cas {
		switch c.Kind {
		case store.KindIntermediate:
			info := CRLInfo{CAID: c.ID, CAName: c.Name, Kind: c.Kind, CARevoked: c.Revoked(), KeyHeld: c.KeyBlob != nil, CanSign: canSignCRL(c)}
			if info.Revoked, err = s.st.RevokedCount(ctx, c.ID); err != nil {
				return nil, err
			}
			switch crl, err := s.st.GetCRL(ctx, c.ID); {
			case err == nil:
				info.Published, info.Number = true, crl.Number
				info.ThisUpdate, info.NextUpdate, info.InList = crl.ThisUpdate, crl.NextUpdate, crl.RevokedCount
				info.Stale = info.Revoked != crl.RevokedCount && !c.Revoked()
				info.Expired = !s.opts.Now().Before(crl.NextUpdate) && !c.Revoked()
			case !errors.Is(err, store.ErrNotFound):
				return nil, err
			}
			out = append(out, info)
		case store.KindRoot:
			info, include, err := s.rootCRLInfo(ctx, c)
			if err != nil {
				return nil, err
			}
			if include {
				out = append(out, info)
			}
		}
	}
	return out, nil
}

// rootCRLInfo describes a Root's list. Roots appear only once there is
// something to say: an intermediate was revoked, or a list was imported.
func (s *Service) rootCRLInfo(ctx context.Context, root store.CA) (CRLInfo, bool, error) {
	kids, err := s.st.Children(ctx, root.ID)
	if err != nil {
		return CRLInfo{}, false, err
	}
	var serials []*big.Int
	for _, k := range kids {
		if k.Revoked() {
			sn, err := serialOf(k)
			if err != nil {
				return CRLInfo{}, false, err
			}
			serials = append(serials, sn)
		}
	}
	info := CRLInfo{CAID: root.ID, CAName: root.Name, Kind: root.Kind, External: true, KeyHeld: root.KeyBlob != nil, Revoked: len(serials)}
	switch imp, err := s.st.GetImportedCRL(ctx, root.ID); {
	case err == nil:
		info.Published, info.Number = true, imp.Number
		info.ThisUpdate, info.NextUpdate = imp.ThisUpdate, imp.NextUpdate
		info.InList = listedInCRL(imp.DER, serials)
		info.Stale = info.InList < info.Revoked
		info.Expired = !s.opts.Now().Before(imp.NextUpdate)
	case errors.Is(err, store.ErrNotFound):
		if len(serials) == 0 {
			return info, false, nil
		}
	default:
		return CRLInfo{}, false, err
	}
	return info, true, nil
}

// PublicCRL returns the list published for a CA in DER form, as served to
// clients: the one this service signed for an intermediate, or the one imported
// for a Root.
func (s *Service) PublicCRL(ctx context.Context, caID string) (store.PublishedCRL, error) {
	crl, err := s.st.GetPublishedCRL(ctx, caID)
	if errors.Is(err, store.ErrNotFound) {
		return store.PublishedCRL{}, ErrNoCRL
	}
	return crl, err
}

// PublicCACertificate returns a CA's certificate in DER form, as served to clients.
func (s *Service) PublicCACertificate(ctx context.Context, caID string) ([]byte, error) {
	c, err := s.st.GetCA(ctx, caID)
	if err != nil {
		return nil, err
	}
	cert, err := parseCert(c.CertPEM)
	if err != nil {
		return nil, err
	}
	return cert.Raw, nil
}
