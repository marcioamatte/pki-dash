package api

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/vault"
)

const (
	maxSANs         = 100
	maxCAValidity   = 7300 // days (20 years)
	maxLeafValidity = 3650 // days (10 years)
	day             = 24 * time.Hour
)

func (s *Server) routes(mux *http.ServeMux) {
	const v1 = "/api/v1"
	pub := route{public: true}
	pubStrict := route{public: true, strict: true}
	any := route{}

	s.handle(mux, "GET "+v1+"/status", pub, s.status)
	s.handle(mux, "POST "+v1+"/setup", pubStrict, s.setup)
	s.handle(mux, "POST "+v1+"/login", pubStrict, s.login)
	s.handle(mux, "POST "+v1+"/logout", any, s.logout)
	s.handle(mux, "GET "+v1+"/me", any, s.me)
	s.handle(mux, "POST "+v1+"/me/password", route{strict: true}, s.changeOwnPassword)

	s.handle(mux, "POST "+v1+"/vault/init", route{perm: auth.PermManageVault, strict: true}, s.vaultInit)
	s.handle(mux, "POST "+v1+"/vault/unlock", route{perm: auth.PermManageVault, strict: true}, s.vaultUnlock)
	s.handle(mux, "POST "+v1+"/vault/lock", route{perm: auth.PermManageVault}, s.vaultLock)
	s.handle(mux, "POST "+v1+"/vault/passphrase", route{perm: auth.PermManageVault, strict: true}, s.vaultPassphrase)

	s.handle(mux, "GET "+v1+"/cas", route{perm: auth.PermViewCAs}, s.listCAs)
	s.handle(mux, "POST "+v1+"/cas", any, s.createCA) // permission depends on the kind, checked inside
	s.handle(mux, "GET "+v1+"/cas/{id}", route{perm: auth.PermViewCAs}, s.getCA)
	s.handle(mux, "GET "+v1+"/cas/{id}/cert", route{perm: auth.PermViewCAs}, s.caCert)
	s.handle(mux, "GET "+v1+"/cas/{id}/chain", route{perm: auth.PermViewCAs}, s.caChain)
	s.handle(mux, "POST "+v1+"/cas/{id}/export-key", route{perm: auth.PermExportCAKey, strict: true}, s.exportKey)
	s.handle(mux, "POST "+v1+"/cas/{id}/remove-key", route{perm: auth.PermRemoveRootKey, strict: true}, s.removeKey)
	s.handle(mux, "POST "+v1+"/cas/{id}/certificates", route{perm: auth.PermIssueCert}, s.issue)

	s.handle(mux, "GET "+v1+"/certificates", route{perm: auth.PermViewCerts}, s.listCerts)
	s.handle(mux, "GET "+v1+"/certificates/expiring", route{perm: auth.PermViewCerts}, s.expiring)
	s.handle(mux, "GET "+v1+"/certificates/{id}/pem", route{perm: auth.PermViewCerts}, s.certPEM)
	s.handle(mux, "GET "+v1+"/certificates/{id}/fullchain", route{perm: auth.PermViewCerts}, s.certFullchain)

	s.handle(mux, "GET "+v1+"/users", route{perm: auth.PermManageUsers}, s.listUsers)
	s.handle(mux, "POST "+v1+"/users", route{perm: auth.PermManageUsers}, s.createUser)
	s.handle(mux, "PATCH "+v1+"/users/{id}", route{perm: auth.PermManageUsers}, s.patchUser)
	s.handle(mux, "POST "+v1+"/users/{id}/password", route{perm: auth.PermManageUsers, strict: true}, s.resetPassword)

	s.handle(mux, "GET "+v1+"/audit", route{perm: auth.PermViewAudit}, s.audit)
	s.handle(mux, "GET "+v1+"/audit/verify", route{perm: auth.PermViewAudit}, s.auditVerify)

	s.uiRoutes(mux)

	// Anything unmatched: 405 if the path exists for another method, else 404.
	// (A catch-all pattern would otherwise swallow the mux's own 405.)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var allow []string
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
			probe := r.Clone(r.Context())
			probe.Method = m
			if _, pattern := mux.Handler(probe); pattern != "" && pattern != "/" {
				allow = append(allow, m)
			}
		}
		if len(allow) > 0 {
			w.Header().Set("Allow", strings.Join(allow, ", "))
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		writeErr(w, http.StatusNotFound, "not_found", "not found")
	})
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ---- status, setup, sessions ----

func (s *Server) status(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	st, err := s.svc.State(r.Context())
	if err != nil {
		return err
	}
	needs, err := s.auth.NeedsSetup(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"needs_setup": needs, "vault_initialized": st.Initialized, "vault_unlocked": st.Unlocked,
	})
	return nil
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	var in struct {
		SetupToken string `json:"setup_token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Passphrase string `json:"master_passphrase"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	needs, err := s.auth.NeedsSetup(r.Context())
	if err != nil {
		return err
	}
	if !needs {
		return auth.ErrSetupDone
	}
	if s.setupToken != "" && subtle.ConstantTimeCompare([]byte(in.SetupToken), []byte(s.setupToken)) != 1 {
		return &apiError{http.StatusForbidden, "bad_setup_token", "invalid setup token"}
	}
	// Check the passphrase before creating the admin, so a typo cannot leave a
	// half-finished setup behind.
	if utf8.RuneCountInString(in.Passphrase) < vault.MinPassphraseLen {
		return fmt.Errorf("%w: need at least %d characters", vault.ErrWeakPassphrase, vault.MinPassphraseLen)
	}
	if err := s.auth.Setup(r.Context(), in.Username, in.Password); err != nil {
		return err
	}
	if err := s.svc.Init(r.Context(), in.Username, in.Passphrase); err != nil {
		s.log.Error("setup: admin created but vault init failed", "err", err)
		return &apiError{http.StatusInternalServerError, "vault_init_failed",
			"the admin account was created but the vault could not be initialised; sign in and initialise it"}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"username": in.Username, "vault_initialized": true})
	return nil
}

type sessionDTO struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	CSRFToken string `json:"csrf_token"`
	ExpiresAt string `json:"expires_at"`
}

func dto(p *auth.Session) sessionDTO {
	return sessionDTO{p.Username, p.Role, p.CSRF, rfc3339(p.ExpiresAt)}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	sess, err := s.auth.Login(r.Context(), in.Username, in.Password)
	if err != nil {
		return err
	}
	s.setCookie(w, sess)
	writeJSON(w, http.StatusOK, dto(sess))
	return nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		if err := s.auth.Logout(r.Context(), c.Value); err != nil {
			return err
		}
	}
	s.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, p *auth.Session) error {
	writeJSON(w, http.StatusOK, dto(p))
	return nil
}

func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := s.auth.ChangeOwnPassword(r.Context(), p, in.Current, in.New); err != nil {
		return err
	}
	s.clearCookie(w) // every session of this user, including this one, has ended
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- vault ----

type passphraseIn struct {
	Passphrase string `json:"master_passphrase"`
}

func (s *Server) vaultInit(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in passphraseIn
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := s.svc.Init(r.Context(), p.Username, in.Passphrase); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) vaultUnlock(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in passphraseIn
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := s.svc.Unlock(r.Context(), p.Username, in.Passphrase); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) vaultLock(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	if err := s.svc.Lock(r.Context(), p.Username); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) vaultPassphrase(w http.ResponseWriter, r *http.Request, p *auth.Session) error {
	var in struct {
		Current string `json:"current_master_passphrase"`
		New     string `json:"new_master_passphrase"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := s.svc.VerifyPassphrase(r.Context(), p.Username, in.Current); err != nil {
		return err
	}
	if err := s.svc.ChangePassphrase(r.Context(), p.Username, in.New); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- helpers ----

func queryInt(r *http.Request, name string, def, min, max int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, badRequest(fmt.Sprintf("%s must be an integer from %d to %d", name, min, max))
	}
	return n, nil
}

func parseAlgo(s string, def ca.KeyAlgo) (ca.KeyAlgo, error) {
	if s == "" {
		return def, nil
	}
	switch a := ca.KeyAlgo(s); a {
	case ca.ECDSAP256, ca.ECDSAP384, ca.RSA3072, ca.RSA4096:
		return a, nil
	}
	return "", badRequest("key_algo must be one of ecdsa-p256, ecdsa-p384, rsa-3072, rsa-4096")
}

func days(n, max int, field string) (time.Duration, error) {
	if n < 1 || n > max {
		return 0, badRequest(fmt.Sprintf("%s must be from 1 to %d", field, max))
	}
	return time.Duration(n) * day, nil
}

func writePEM(w http.ResponseWriter, name string, pem []byte) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+pemName(name)+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pem)
}
