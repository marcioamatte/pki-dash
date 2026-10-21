package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/oidc"
)

// The browser, not a script, follows these two routes, so they answer with
// redirects instead of JSON. A failure sends the person back to the login
// page with a short fixed code (never text from the provider), which the UI
// turns into a message.
const oidcErrorPath = "/?sso_error="

func (s *Server) oidcCookieName() string {
	if s.secure {
		return "__Host-pki_oidc"
	}
	return "pki_oidc"
}

func (s *Server) setOIDCCookie(w http.ResponseWriter, value string, maxAge int) {
	// Lax, not Strict: the provider sends the browser back here from another
	// site, and a Strict cookie would not travel with that navigation.
	http.SetCookie(w, &http.Cookie{
		Name: s.oidcCookieName(), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	if s.oidc == nil {
		return &apiError{http.StatusNotFound, "not_found", "not found"}
	}
	authURL, binder, err := s.oidc.Begin(r.Context())
	if err != nil {
		s.log.Error("oidc: begin login", "err", err)
		http.Redirect(w, r, oidcErrorPath+oidcCode(err), http.StatusFound)
		return nil
	}
	s.setOIDCCookie(w, binder, int((10 * time.Minute).Seconds()))
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request, _ *auth.Session) error {
	if s.oidc == nil {
		return &apiError{http.StatusNotFound, "not_found", "not found"}
	}
	var binder string
	if c, err := r.Cookie(s.oidcCookieName()); err == nil {
		binder = c.Value
	}
	s.setOIDCCookie(w, "", -1) // single use
	fail := func(err error) error {
		s.log.Warn("oidc: login refused", "err", err, "ip", s.clientIP(r))
		http.Redirect(w, r, oidcErrorPath+oidcCode(err), http.StatusFound)
		return nil
	}

	id, err := s.oidc.Complete(r.Context(), r.URL.Query(), binder)
	if err != nil {
		return fail(err)
	}
	sess, err := s.auth.LoginExternal(r.Context(), auth.ExternalIdentity{
		Issuer: id.Issuer, Subject: id.Subject, Username: id.Username, Groups: id.Groups, IDToken: id.IDToken,
	})
	if err != nil {
		return fail(err)
	}
	s.setCookie(w, sess)
	http.Redirect(w, r, "/", http.StatusFound)
	return nil
}

// oidcCode maps an error to the fixed code the UI understands.
func oidcCode(err error) string {
	switch {
	case errors.Is(err, auth.ErrNoAccess):
		return "no_access"
	case errors.Is(err, oidc.ErrDenied):
		return "denied"
	case errors.Is(err, oidc.ErrState):
		return "state"
	case errors.Is(err, oidc.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, oidc.ErrBusy):
		return "busy"
	case errors.Is(err, oidc.ErrToken):
		return "token"
	}
	return "failed"
}
