package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/store"
)

var (
	// ErrCARevoked means the CA has been revoked, so it no longer issues or signs.
	ErrCARevoked = errors.New("service: this CA is revoked")
	// ErrNotIntermediate means the CA is not an intermediate, the only kind that can be revoked.
	ErrNotIntermediate = store.ErrNotIntermediate
	// ErrAlreadyImported means this exact CRL is already the published one.
	ErrAlreadyImported = errors.New("service: this exact CRL is already published")
)

// RevokeCA revokes an intermediate CA, for good. From then on the service
// refuses to issue from it or to sign anything with its key.
//
// The statement that clients can check, though, is the Root's CRL, and the Root
// stays offline. The revocation is therefore recorded here at once, and
// published when you bring back a CRL the Root signed (see RootCRLRequest and
// ImportRootCRL). Until then clients that check the Root's list do not know.
func (s *Service) RevokeCA(ctx context.Context, actor, caID string, reason int) (store.CA, error) {
	if !ca.ValidCAReason(reason) {
		return store.CA{}, fmt.Errorf("%w: unsupported revocation reason", ca.ErrInvalidRequest)
	}
	c, err := s.st.RevokeCA(ctx, actor, caID, reason, s.opts.Now())
	if errors.Is(err, store.ErrAlreadyRevoked) {
		return store.CA{}, ErrAlreadyRevoked
	}
	return c, err
}

// RootCRLEntry is one revoked intermediate, as it must appear in the Root's CRL.
type RootCRLEntry struct {
	ChildID   string
	ChildName string
	SerialHex string
	SerialDec string // cfssl gencrl wants decimal
	RevokedAt time.Time
	Reason    int
}

// RootCRLRequest is what to put into the Root's next CRL.
type RootCRLRequest struct {
	RootID     string
	RootName   string
	Entries    []RootCRLEntry
	NextNumber int64 // the CRL number to use: one above the last one imported, or 1
	Published  *store.ImportedCRL
}

// RootCRLRequest lists the revoked intermediates a Root's CRL must contain.
func (s *Service) RootCRLRequest(ctx context.Context, rootID string) (RootCRLRequest, error) {
	root, err := s.st.GetCA(ctx, rootID)
	if err != nil {
		return RootCRLRequest{}, err
	}
	if root.Kind != store.KindRoot {
		return RootCRLRequest{}, ErrNotARoot
	}
	kids, err := s.st.Children(ctx, rootID)
	if err != nil {
		return RootCRLRequest{}, err
	}
	out := RootCRLRequest{RootID: root.ID, RootName: root.Name, NextNumber: 1}
	for _, k := range kids {
		if !k.Revoked() {
			continue
		}
		serial, err := serialOf(k)
		if err != nil {
			return RootCRLRequest{}, err
		}
		out.Entries = append(out.Entries, RootCRLEntry{
			ChildID: k.ID, ChildName: k.Name, SerialHex: serial.Text(16), SerialDec: serial.String(),
			RevokedAt: k.RevokedAt, Reason: k.RevocationReason,
		})
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].RevokedAt.Before(out.Entries[j].RevokedAt) })
	switch prev, err := s.st.GetImportedCRL(ctx, rootID); {
	case err == nil:
		out.Published = &prev
		if prev.Number > 0 {
			out.NextNumber = prev.Number + 1
		}
	case !errors.Is(err, store.ErrNotFound):
		return RootCRLRequest{}, err
	}
	return out, nil
}

func serialOf(c store.CA) (*big.Int, error) {
	cert, err := parseCert(c.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("service: certificate of %s: %w", c.Name, err)
	}
	return cert.SerialNumber, nil
}

// ImportRootCRL publishes a CRL that the Root signed offline. It is checked
// before anything is served in the Root's name:
//   - signed by this Root, complete (not a delta or partial list), and current;
//   - newer than the one already published, so an old list cannot be put back;
//   - it lists every intermediate revoked here, and none that is not.
//
// PEM, DER and the base64 that "cfssl gencrl" prints are all accepted.
func (s *Service) ImportRootCRL(ctx context.Context, actor, rootID string, data []byte) (store.ImportedCRL, error) {
	root, err := s.st.GetCA(ctx, rootID)
	if err != nil {
		return store.ImportedCRL{}, err
	}
	if root.Kind != store.KindRoot {
		return store.ImportedCRL{}, ErrNotARoot
	}
	parsed, err := ca.VerifyRootCRL(root.CertPEM, data, s.opts.Now())
	if err != nil {
		return store.ImportedCRL{}, err
	}
	listed := map[string]bool{}
	for _, e := range parsed.Entries {
		listed[e.Serial.Text(16)] = true
	}
	return s.st.PutImportedCRL(ctx, actor, rootID, store.ImportedCRL{
		Number: parsed.Number, ThisUpdate: parsed.ThisUpdate, NextUpdate: parsed.NextUpdate,
		RevokedCount: len(parsed.Entries), DER: parsed.DER,
	}, func(prev *store.ImportedCRL, kids []store.CA) error {
		if prev != nil {
			if bytes.Equal(prev.DER, parsed.DER) {
				return ErrAlreadyImported
			}
			if err := parsed.NewerThan(prev.Number, prev.ThisUpdate); err != nil {
				return err
			}
		}
		var missing, extra []string
		for _, k := range kids {
			serial, err := serialOf(k)
			if err != nil {
				return err
			}
			switch inList := listed[serial.Text(16)]; {
			case k.Revoked() && !inList:
				missing = append(missing, k.Name)
			case !k.Revoked() && inList:
				extra = append(extra, k.Name)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("%w: the CRL does not list the revoked intermediate(s) %s", ca.ErrPolicy, strings.Join(missing, ", "))
		}
		if len(extra) > 0 {
			return fmt.Errorf("%w: the CRL lists %s, which is not revoked here: revoke it first, or make a CRL without it",
				ca.ErrPolicy, strings.Join(extra, ", "))
		}
		return nil
	})
}

// listedInCRL counts how many of the serials appear in a CRL given as DER.
func listedInCRL(der []byte, serials []*big.Int) int {
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return 0
	}
	have := map[string]bool{}
	for _, e := range list.RevokedCertificateEntries {
		have[e.SerialNumber.Text(16)] = true
	}
	n := 0
	for _, s := range serials {
		if have[s.Text(16)] {
			n++
		}
	}
	return n
}

// PublicURL is the address clients use to reach the public listener, or "".
func (s *Service) PublicURL() string { return s.opts.PublicURL }
