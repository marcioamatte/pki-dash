package ca

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// RFC 5280 section 5.3.1 reason codes that make sense for a service certificate.
// certificateHold (6) is left out on purpose: it needs "remove from CRL" and a
// way to lift a revocation, which this service does not offer. cACompromise (2)
// is for CAs and arrives with CA revocation.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
)

// ValidReason reports whether code may be used to revoke a service certificate.
func ValidReason(code int) bool {
	switch code {
	case ReasonUnspecified, ReasonKeyCompromise, ReasonAffiliationChanged, ReasonSuperseded, ReasonCessationOfOperation:
		return true
	}
	return false
}

// ErrNotCRLSigner means the CA's certificate cannot sign revocation lists.
var ErrNotCRLSigner = errors.New("ca: this CA's certificate does not allow signing CRLs (no cRLSign key usage)")

// Revoked is one entry of a CRL.
type Revoked struct {
	Serial    *big.Int
	RevokedAt time.Time
	Reason    int
}

// CRLValidity is how long a CRL stays valid, from the moment it is issued.
const CRLValidity = 7 * 24 * time.Hour

// IssueCRL signs a revocation list for the CA's certificates. Reasons may be any
// that suit what the CA issues: a Root's list names CAs, so cACompromise is allowed here. number must grow
// with each list the CA publishes (RFC 5280 section 5.2.3). The list is valid
// from slightly before now, to absorb clock differences, until now+validity.
func (a *Authority) IssueCRL(entries []Revoked, number int64, now time.Time, validity time.Duration) (der []byte, thisUpdate, nextUpdate time.Time, err error) {
	if a.cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, thisUpdate, nextUpdate, ErrNotCRLSigner
	}
	if number < 1 || validity <= 0 {
		return nil, thisUpdate, nextUpdate, fmt.Errorf("%w: CRL number and validity must be positive", ErrInvalidRequest)
	}
	thisUpdate, nextUpdate = now.Add(-backdate).UTC(), now.Add(validity).UTC()
	list := make([]x509.RevocationListEntry, 0, len(entries))
	for _, e := range entries {
		if e.Serial == nil || e.Serial.Sign() <= 0 || !ValidCAReason(e.Reason) {
			return nil, thisUpdate, nextUpdate, fmt.Errorf("%w: bad CRL entry", ErrInvalidRequest)
		}
		list = append(list, x509.RevocationListEntry{SerialNumber: e.Serial, RevocationTime: e.RevokedAt.UTC(), ReasonCode: e.Reason})
	}
	der, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: list,
	}, a.cert, a.key)
	if err != nil {
		return nil, thisUpdate, nextUpdate, fmt.Errorf("ca: sign CRL: %w", err)
	}
	return der, thisUpdate, nextUpdate, nil
}
