package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ReasonCACompromise (RFC 5280 reason 2) applies to certificates of CAs only.
const ReasonCACompromise = 2

// ValidCAReason reports whether code may be used to revoke an intermediate CA.
func ValidCAReason(code int) bool { return ValidReason(code) || code == ReasonCACompromise }

// ErrCRLNotNewer means a CRL is not newer than the one already in place.
var ErrCRLNotNewer = errors.New("ca: this CRL is not newer than the one already published")

// Extensions that make a CRL something other than a complete list of one issuer's
// revocations. We cannot serve those as the Root's CRL.
var (
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// ParsedCRL is a CRL that passed VerifyRootCRL.
type ParsedCRL struct {
	DER        []byte
	Number     int64 // 0 when the CRL carries none (cfssl's does not)
	ThisUpdate time.Time
	NextUpdate time.Time
	Entries    []Revoked
}

// decodeCRL turns what a person might paste or upload into DER. It accepts PEM
// ("X509 CRL"), raw DER, and bare base64 of the DER, which is what
// "cfssl gencrl" prints.
func decodeCRL(data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty CRL", ErrInvalidRequest)
	}
	if blk, _ := pem.Decode(data); blk != nil {
		if blk.Type != "X509 CRL" {
			return nil, fmt.Errorf("%w: expected an X509 CRL, found %q", ErrInvalidRequest, blk.Type)
		}
		return blk.Bytes, nil
	}
	if data[0] == 0x30 { // an ASN.1 SEQUENCE: already DER
		return data, nil
	}
	clean := strings.Join(strings.Fields(string(data)), "")
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil || len(der) == 0 || der[0] != 0x30 {
		return nil, fmt.Errorf("%w: not a CRL (expected PEM, DER or base64 of the DER)", ErrInvalidRequest)
	}
	return der, nil
}

// VerifyRootCRL checks a CRL that the Root signed offline before we publish it
// in the Root's name. It must be signed by this Root, be a complete list (not
// a delta or a partial one), and be current. It does not judge the contents:
// whether the list agrees with what is revoked here is the caller's business.
func VerifyRootCRL(rootCertPEM, data []byte, now time.Time) (*ParsedCRL, error) {
	root, err := parseCert(rootCertPEM)
	if err != nil {
		return nil, err
	}
	der, err := decodeCRL(data)
	if err != nil {
		return nil, err
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if !bytes.Equal(list.RawIssuer, root.RawSubject) {
		return nil, policyf("this CRL was not issued by this Root (issuer name differs)")
	}
	if err := list.CheckSignatureFrom(root); err != nil {
		return nil, policyf("the CRL is not signed by this Root's key")
	}
	for _, ext := range list.Extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) || ext.Id.Equal(oidIssuingDistributionPoint) {
			return nil, policyf("delta and partial CRLs are not supported: generate a complete CRL")
		}
	}
	if list.NextUpdate.IsZero() {
		return nil, policyf("the CRL has no next-update time")
	}
	if now.After(list.NextUpdate) {
		return nil, policyf("the CRL has already expired")
	}
	if list.ThisUpdate.After(now.Add(skew)) {
		return nil, policyf("the CRL is dated in the future")
	}
	out := &ParsedCRL{DER: der, ThisUpdate: list.ThisUpdate.UTC(), NextUpdate: list.NextUpdate.UTC()}
	if list.Number != nil && list.Number.IsInt64() {
		out.Number = list.Number.Int64()
	}
	for _, e := range list.RevokedCertificateEntries {
		out.Entries = append(out.Entries, Revoked{Serial: e.SerialNumber, RevokedAt: e.RevocationTime.UTC(), Reason: e.ReasonCode})
	}
	return out, nil
}

// NewerThan reports whether c may replace a CRL that is already published, so
// an old list cannot be put back (which would quietly un-revoke things). With a
// CRL number on both sides, the number must grow. Without one (cfssl does not
// write it), the issue time must be strictly later. prevNumber is 0 when the
// published list has no number.
func (c *ParsedCRL) NewerThan(prevNumber int64, prevThis time.Time) error {
	if prevThis.IsZero() {
		return nil // nothing published yet
	}
	if c.Number > 0 && prevNumber > 0 {
		if c.Number <= prevNumber {
			return fmt.Errorf("%w: CRL number %d is not above the published %d", ErrCRLNotNewer, c.Number, prevNumber)
		}
		return nil
	}
	if !c.ThisUpdate.After(prevThis) {
		return fmt.Errorf("%w: it is dated %s, the published one %s", ErrCRLNotNewer,
			c.ThisUpdate.Format(time.RFC3339), prevThis.UTC().Format(time.RFC3339))
	}
	return nil
}
