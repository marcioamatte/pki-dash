package service

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/store"
)

// This file is the path for a Root that never touches this service: it is made
// and kept elsewhere, and only its public certificate comes here.
//
//	ImportRoot            register the Root's public certificate
//	RequestIntermediate   make a key and a signing request; the key stays here
//	(sign the request offline with the Root)
//	ImportIntermediate    bring the signed certificate back

// ImportRoot registers a Root created elsewhere, from its public certificate
// only. The service will never hold its key, so it can verify and distribute
// the Root but not sign with it.
func (s *Service) ImportRoot(ctx context.Context, actor, name string, certPEM []byte) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return "", ca.ErrInvalidRequest
	}
	cert, err := ca.ParseRoot(certPEM, s.opts.Now())
	if err != nil {
		return "", err
	}
	canonical := ca.CertPEM(cert)
	existing, err := s.st.ListCAs(ctx)
	if err != nil {
		return "", err
	}
	for _, e := range existing {
		if bytes.Equal(e.CertPEM, canonical) {
			return "", store.ErrExists // the same certificate is already registered
		}
	}
	id := store.NewID()
	return s.st.CreateCA(ctx, actor, store.CA{
		ID: id, Name: name, Kind: store.KindRoot, CertPEM: canonical, // no key: it lives offline
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
	})
}

// IntermediateRequestParams describes an intermediate that will be signed elsewhere.
type IntermediateRequestParams struct {
	Name         string
	Organization string
	KeyAlgo      ca.KeyAlgo
}

// PendingRequest is an intermediate waiting for its certificate.
type PendingRequest struct {
	ID        string
	Name      string
	ParentID  string
	CSRPEM    []byte
	CreatedAt time.Time
}

func toPending(p store.PendingCA) PendingRequest {
	return PendingRequest{ID: p.ID, Name: p.Name, ParentID: p.ParentID, CSRPEM: p.CSRPEM, CreatedAt: p.CreatedAt}
}

// RequestIntermediate generates a key and a certificate request for an
// intermediate under the Root parentID. The key is encrypted and kept here;
// the request is what you take to the Root to be signed. The Root need not be
// offline: this also works for one whose key the service holds.
func (s *Service) RequestIntermediate(ctx context.Context, actor, parentID string, p IntermediateRequestParams) (*PendingRequest, error) {
	v, err := s.unlocked()
	if err != nil {
		return nil, err
	}
	parent, err := s.st.GetCA(ctx, parentID)
	if err != nil {
		return nil, err
	}
	if parent.Kind != store.KindRoot {
		return nil, ErrBadParent
	}
	p.Name = strings.TrimSpace(p.Name)
	csrPEM, keyPEM, err := ca.NewIntermediateRequest(ca.CARequest{CommonName: p.Name, Organization: p.Organization, KeyAlgo: p.KeyAlgo})
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	id := store.NewID() // the encrypted key is bound to this ID
	blob, err := v.Seal(id, keyPEM)
	if err != nil {
		return nil, err
	}
	if _, err := s.st.CreatePendingCA(ctx, actor, store.PendingCA{
		ID: id, Name: p.Name, ParentID: parentID, CSRPEM: csrPEM, KeyBlob: blob,
	}); err != nil {
		return nil, err
	}
	pending, err := s.st.GetPendingCA(ctx, id)
	if err != nil {
		return nil, err
	}
	r := toPending(pending)
	return &r, nil
}

// ListPendingRequests returns the intermediates waiting for a certificate.
func (s *Service) ListPendingRequests(ctx context.Context) ([]PendingRequest, error) {
	ps, err := s.st.ListPendingCAs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PendingRequest, 0, len(ps))
	for _, p := range ps {
		out = append(out, toPending(p))
	}
	return out, nil
}

// GetPendingRequest returns one waiting request, for downloading its CSR again.
func (s *Service) GetPendingRequest(ctx context.Context, id string) (PendingRequest, error) {
	p, err := s.st.GetPendingCA(ctx, id)
	if err != nil {
		return PendingRequest{}, err
	}
	return toPending(p), nil
}

// CancelPendingRequest discards a request together with its key.
func (s *Service) CancelPendingRequest(ctx context.Context, actor, id string) error {
	return s.st.DeletePendingCA(ctx, actor, id)
}

// ImportIntermediate completes a request with the certificate the Root signed.
// The certificate must be for the request's key, signed by the request's Root,
// a CA that can only sign leaves, and inside the Root's validity. On success
// the intermediate becomes a normal CA that issues certificates.
func (s *Service) ImportIntermediate(ctx context.Context, actor, id string, certPEM []byte) (string, error) {
	v, err := s.unlocked()
	if err != nil {
		return "", err
	}
	pending, err := s.st.GetPendingCA(ctx, id)
	if err != nil {
		return "", err
	}
	parent, err := s.st.GetCA(ctx, pending.ParentID)
	if err != nil {
		return "", err
	}
	keyPEM, err := v.Open(pending.ID, pending.KeyBlob)
	if err != nil {
		return "", err
	}
	defer clear(keyPEM)
	cert, err := ca.VerifyIntermediate(parent.CertPEM, certPEM, keyPEM, s.opts.Now())
	if err != nil {
		return "", err
	}
	// The key blob is already bound to this ID, so the same ID and blob carry over.
	err = s.st.CompletePendingCA(ctx, actor, id, store.CA{
		ID: pending.ID, Name: pending.Name, Kind: store.KindIntermediate, ParentID: parent.ID,
		CertPEM: ca.CertPEM(cert), KeyBlob: pending.KeyBlob,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
	})
	if err != nil {
		return "", err
	}
	return pending.ID, nil
}
