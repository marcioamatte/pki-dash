package api

import (
	"encoding/pem"
	"net/http"

	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/ca"
)

// Reasons are named in the API (not numbered), so a typo cannot silently become
// a different code. They are the RFC 5280 reasons that suit a service certificate.
var reasons = map[string]int{
	"unspecified":            ca.ReasonUnspecified,
	"key_compromise":         ca.ReasonKeyCompromise,
	"affiliation_changed":    ca.ReasonAffiliationChanged,
	"superseded":             ca.ReasonSuperseded,
	"cessation_of_operation": ca.ReasonCessationOfOperation,
}

func reasonName(code int) string {
	for n, c := range reasons {
		if c == code {
			return n
		}
	}
	return "unspecified"
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	code, ok := reasons[in.Reason]
	if !ok {
		return badRequest("reason must be one of: unspecified, key_compromise, affiliation_changed, superseded, cessation_of_operation")
	}
	res, err := s.svc.RevokeCertificate(r.Context(), p.Username, r.PathValue("id"), code)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revoked_at":    rfc3339(res.Certificate.RevokedAt),
		"reason":        reasonName(res.Certificate.RevocationReason),
		"crl_published": res.Published,
	})
	return nil
}

type crlDTO struct {
	CAID       string `json:"ca_id"`
	CAName     string `json:"ca_name"`
	KeyHeld    bool   `json:"key_held"`
	CanSign    bool   `json:"can_sign"`
	Published  bool   `json:"published"`
	Number     int64  `json:"number,omitempty"`
	ThisUpdate string `json:"this_update,omitempty"`
	NextUpdate string `json:"next_update,omitempty"`
	Revoked    int    `json:"revoked"`
	InList     int    `json:"in_list"`
	Stale      bool   `json:"stale"`
	Expired    bool   `json:"expired"`
}

func (s *Server) crlStatus(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	infos, err := s.svc.CRLStatus(r.Context())
	if err != nil {
		return err
	}
	out := make([]crlDTO, 0, len(infos))
	for _, i := range infos {
		d := crlDTO{CAID: i.CAID, CAName: i.CAName, KeyHeld: i.KeyHeld, CanSign: i.CanSign, Published: i.Published,
			Revoked: i.Revoked, InList: i.InList, Stale: i.Stale, Expired: i.Expired}
		if i.Published {
			d.Number, d.ThisUpdate, d.NextUpdate = i.Number, rfc3339(i.ThisUpdate), rfc3339(i.NextUpdate)
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// crlRefresh reissues every CRL now, for example after unlocking the vault.
func (s *Server) crlRefresh(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	if err := s.svc.RefreshCRLs(r.Context(), p.Username, true); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) crlDownload(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	crl, err := s.svc.PublicCRL(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	c, err := s.svc.GetCA(r.Context(), crl.CAID)
	if err != nil {
		return err
	}
	writePEM(w, c.Name+".crl", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.DER}))
	return nil
}
