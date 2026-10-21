package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/service"
	"github.com/marcioamatte/pki-dash/internal/store"
)

type caDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	ParentID  string `json:"parent_id,omitempty"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	CreatedAt string `json:"created_at"`
	KeyHeld   bool   `json:"key_held"` // false once a Root's key has been removed
	Revoked   bool   `json:"revoked"`
	RevokedAt string `json:"revoked_at,omitempty"`
	Reason    string `json:"revocation_reason,omitempty"`
}

func toCA(c store.CA) caDTO {
	d := caDTO{ID: c.ID, Name: c.Name, Kind: c.Kind, ParentID: c.ParentID, NotBefore: rfc3339(c.NotBefore),
		NotAfter: rfc3339(c.NotAfter), CreatedAt: rfc3339(c.CreatedAt), KeyHeld: c.KeyBlob != nil}
	if c.Revoked() {
		d.Revoked, d.RevokedAt, d.Reason = true, rfc3339(c.RevokedAt), caReasonName(c.RevocationReason)
	}
	return d
}

func (s *Server) listCAs(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	cas, err := s.svc.ListCAs(r.Context())
	if err != nil {
		return err
	}
	out := make([]caDTO, 0, len(cas))
	for _, c := range cas {
		out = append(out, toCA(c))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) getCA(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	c, err := s.svc.GetCA(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, toCA(c))
	return nil
}

func (s *Server) createCA(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Kind         string `json:"kind"`
		ParentID     string `json:"parent_id"`
		Name         string `json:"name"`
		Organization string `json:"organization"`
		ValidityDays int    `json:"validity_days"`
		KeyAlgo      string `json:"key_algo"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	validity, err := days(in.ValidityDays, maxCAValidity, "validity_days")
	if err != nil {
		return err
	}
	params := service.CAParams{Name: in.Name, Organization: in.Organization, Validity: validity}
	var id string
	switch in.Kind {
	case store.KindRoot:
		if err := auth.Authorize(p, auth.PermCreateRoot); err != nil {
			return err
		}
		if params.KeyAlgo, err = parseAlgo(in.KeyAlgo, ca.ECDSAP384); err != nil {
			return err
		}
		id, err = s.svc.CreateRoot(r.Context(), p.Username, params)
	case store.KindIntermediate:
		if err := auth.Authorize(p, auth.PermCreateIntermediate); err != nil {
			return err
		}
		if in.ParentID == "" {
			return badRequest("parent_id is required for an intermediate")
		}
		if params.KeyAlgo, err = parseAlgo(in.KeyAlgo, ca.ECDSAP256); err != nil {
			return err
		}
		id, err = s.svc.CreateIntermediate(r.Context(), p.Username, in.ParentID, params)
	default:
		return badRequest(`kind must be "root" or "intermediate"`)
	}
	if err != nil {
		return err
	}
	c, err := s.svc.GetCA(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, toCA(c))
	return nil
}

func (s *Server) caCert(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	c, err := s.svc.GetCA(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writePEM(w, c.Name+".crt", c.CertPEM)
	return nil
}

func (s *Server) caChain(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	c, err := s.svc.GetCA(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	chain, err := s.svc.CAChainPEM(r.Context(), c.ID)
	if err != nil {
		return err
	}
	writePEM(w, c.Name+"-chain.pem", chain)
	return nil
}

// Exporting or removing a key asks for the master passphrase again: a stolen
// login session alone must not be enough to take the most sensitive data.
func (s *Server) exportKey(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in passphraseIn
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := s.svc.VerifyPassphrase(r.Context(), p.Username, in.Passphrase); err != nil {
		return err
	}
	c, err := s.svc.GetCA(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	key, err := s.svc.ExportCAKey(r.Context(), p.Username, c.ID)
	if err != nil {
		return err
	}
	defer clear(key)
	writePEM(w, c.Name+".key", key)
	return nil
}

func (s *Server) removeKey(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Passphrase  string `json:"master_passphrase"`
		ConfirmName string `json:"confirm_name"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	c, err := s.svc.GetCA(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	// Irreversible, so the caller must type the CA's name.
	if in.ConfirmName != c.Name {
		return badRequest("confirm_name must match the CA's name exactly")
	}
	if err := s.svc.VerifyPassphrase(r.Context(), p.Username, in.Passphrase); err != nil {
		return err
	}
	if err := s.svc.RemoveKey(r.Context(), p.Username, c.ID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- certificates ----

func (s *Server) issue(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		CommonName   string   `json:"common_name"`
		DNSNames     []string `json:"dns_names"`
		IPAddresses  []string `json:"ip_addresses"`
		Profile      string   `json:"profile"`
		ValidityDays int      `json:"validity_days"`
		KeyAlgo      string   `json:"key_algo"`
		CSR          string   `json:"csr_pem"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if len(in.DNSNames)+len(in.IPAddresses) > maxSANs {
		return badRequest("too many subject alternative names")
	}
	validity, err := days(in.ValidityDays, maxLeafValidity, "validity_days")
	if err != nil {
		return err
	}
	algo, err := parseAlgo(in.KeyAlgo, ca.ECDSAP256)
	if err != nil {
		return err
	}
	profile := ca.Profile(in.Profile)
	if in.Profile == "" {
		profile = ca.ProfileServer
	}
	res, err := s.svc.IssueCertificate(r.Context(), p.Username, r.PathValue("id"), ca.LeafRequest{
		CommonName: in.CommonName, DNSNames: in.DNSNames, IPs: in.IPAddresses,
		Profile: profile, Validity: validity, KeyAlgo: algo, CSRPEM: []byte(in.CSR),
	})
	if err != nil {
		return err
	}
	defer clear(res.Bundle.KeyPEM)
	out := map[string]any{
		"id":              res.ID,
		"certificate_pem": string(res.Bundle.CertPEM),
		"chain_pem":       string(res.ChainPEM),
		"warnings":        res.Warnings,
	}
	if len(res.Bundle.KeyPEM) > 0 { // present only when we generated it; it is never stored
		out["private_key_pem"] = string(res.Bundle.KeyPEM)
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

type certDTO struct {
	ID           string   `json:"id"`
	CAID         string   `json:"ca_id"`
	Serial       string   `json:"serial"`
	CommonName   string   `json:"common_name"`
	SANs         []string `json:"sans"`
	Profile      string   `json:"profile"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	KeyGenerated bool     `json:"key_generated"`
	CreatedAt    string   `json:"created_at"`
	Revoked      bool     `json:"revoked"`
	RevokedAt    string   `json:"revoked_at,omitempty"`
	Reason       string   `json:"revocation_reason,omitempty"`
}

func toCerts(cs []store.Certificate) []certDTO {
	out := make([]certDTO, 0, len(cs))
	for _, c := range cs {
		d := certDTO{ID: c.ID, CAID: c.CAID, Serial: c.Serial, CommonName: c.CommonName, SANs: c.SANs, Profile: c.Profile,
			NotBefore: rfc3339(c.NotBefore), NotAfter: rfc3339(c.NotAfter), KeyGenerated: c.KeyGenerated, CreatedAt: rfc3339(c.CreatedAt)}
		if c.Revoked() {
			d.Revoked, d.RevokedAt, d.Reason = true, rfc3339(c.RevokedAt), reasonName(c.RevocationReason)
		}
		out = append(out, d)
	}
	return out
}

func (s *Server) listCerts(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	cs, err := s.svc.ListCertificates(r.Context(), r.URL.Query().Get("ca_id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, toCerts(cs))
	return nil
}

func (s *Server) expiring(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	n, err := queryInt(r, "days", 30, 1, 3650)
	if err != nil {
		return err
	}
	cs, err := s.svc.Expiring(r.Context(), time.Duration(n)*day)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, toCerts(cs))
	return nil
}

func (s *Server) certPEM(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	c, err := s.svc.GetCertificate(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writePEM(w, c.CommonName+".crt", c.CertPEM)
	return nil
}

// certFullchain is the leaf followed by its issuing chain: what a server presents.
func (s *Server) certFullchain(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	c, err := s.svc.GetCertificate(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	chain, err := s.svc.CAChainPEM(r.Context(), c.CAID)
	if err != nil {
		return err
	}
	writePEM(w, c.CommonName+"-fullchain.pem", append(append([]byte{}, c.CertPEM...), chain...))
	return nil
}

// ---- users and audit ----

type userDTO struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	AuthSource string `json:"auth_source"`
	Disabled   bool   `json:"disabled"`
	CreatedAt  string `json:"created_at"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	us, err := s.auth.ListUsers(r.Context(), p)
	if err != nil {
		return err
	}
	out := make([]userDTO, 0, len(us))
	for _, u := range us {
		out = append(out, userDTO{u.ID, u.Username, u.Role, u.AuthSource, u.Disabled, rfc3339(u.CreatedAt)})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	id, err := s.auth.CreateUser(r.Context(), p, in.Username, in.Password, in.Role)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	return nil
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if in.Role == nil && in.Disabled == nil {
		return badRequest("nothing to change: give role and/or disabled")
	}
	id := r.PathValue("id")
	if in.Role != nil {
		if err := s.auth.SetRole(r.Context(), p, id, *in.Role); err != nil {
			return err
		}
	}
	if in.Disabled != nil {
		if err := s.auth.SetDisabled(r.Context(), p, id, *in.Disabled); err != nil {
			return err
		}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		New string `json:"new_password"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := s.auth.ResetPassword(r.Context(), p, r.PathValue("id"), in.New); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	n, err := queryInt(r, "limit", 100, 1, 1000)
	if err != nil {
		return err
	}
	es, err := s.svc.Audit(r.Context(), n)
	if err != nil {
		return err
	}
	type entry struct {
		Seq    int64  `json:"seq"`
		Time   string `json:"time"`
		Actor  string `json:"actor"`
		Action string `json:"action"`
		Target string `json:"target"`
		Detail string `json:"detail"`
	}
	out := make([]entry, 0, len(es))
	for _, e := range es {
		out = append(out, entry{e.Seq, rfc3339(e.Time), e.Actor, e.Action, e.Target, e.Detail})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	err := s.svc.VerifyAudit(r.Context())
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case errors.Is(err, store.ErrAuditTampered):
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
	default:
		return err
	}
	return nil
}

// ---- CAs signed elsewhere ----

// importRoot registers a Root made elsewhere, from its public certificate.
func (s *Server) importRoot(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Name string `json:"name"`
		Cert string `json:"certificate_pem"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	id, err := s.svc.ImportRoot(r.Context(), p.Username, in.Name, []byte(in.Cert))
	if err != nil {
		return err
	}
	c, err := s.svc.GetCA(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, toCA(c))
	return nil
}

type requestDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ParentID  string `json:"parent_id"`
	CreatedAt string `json:"created_at"`
	CSR       string `json:"csr_pem,omitempty"` // only in the response that creates it
}

func toRequest(p service.PendingRequest, withCSR bool) requestDTO {
	d := requestDTO{ID: p.ID, Name: p.Name, ParentID: p.ParentID, CreatedAt: rfc3339(p.CreatedAt)}
	if withCSR {
		d.CSR = string(p.CSRPEM)
	}
	return d
}

func (s *Server) requestIntermediate(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Name         string `json:"name"`
		Organization string `json:"organization"`
		KeyAlgo      string `json:"key_algo"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	algo, err := parseAlgo(in.KeyAlgo, ca.ECDSAP256)
	if err != nil {
		return err
	}
	req, err := s.svc.RequestIntermediate(r.Context(), p.Username, r.PathValue("id"),
		service.IntermediateRequestParams{Name: in.Name, Organization: in.Organization, KeyAlgo: algo})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, toRequest(*req, true))
	return nil
}

func (s *Server) listRequests(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	ps, err := s.svc.ListPendingRequests(r.Context())
	if err != nil {
		return err
	}
	out := make([]requestDTO, 0, len(ps))
	for _, p := range ps {
		out = append(out, toRequest(p, false))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) requestCSR(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	p, err := s.svc.GetPendingRequest(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writePEM(w, p.Name+".csr", p.CSRPEM)
	return nil
}

func (s *Server) importIntermediate(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Cert string `json:"certificate_pem"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	id, err := s.svc.ImportIntermediate(r.Context(), p.Username, r.PathValue("id"), []byte(in.Cert))
	if err != nil {
		return err
	}
	c, err := s.svc.GetCA(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, toCA(c))
	return nil
}

func (s *Server) cancelRequest(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	if err := s.svc.CancelPendingRequest(r.Context(), p.Username, r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
