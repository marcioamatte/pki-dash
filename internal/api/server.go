// Package api is pki-dash's HTTP interface: a JSON API under /api/v1.
//
// Every request passes through, in order: security headers, panic recovery,
// request ID and access log, per-IP rate limit, then (for non-public routes)
// session authentication, CSRF verification for state-changing methods, and a
// permission check. Handlers see only an authenticated, authorized principal.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/service"
)

// Options configure a Server.
type Options struct {
	Service *service.Service
	Auth    *auth.Auth
	Logger  *slog.Logger
	// SecureCookies must be true whenever the server is reached over TLS.
	// It selects the __Host- cookie prefix and the Secure attribute, and
	// enables HSTS.
	SecureCookies bool
	// SetupToken, when set, must accompany the first-run setup request. It
	// stops whoever reaches a fresh instance first from claiming it.
	SetupToken string
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Server is the HTTP handler tree.
type Server struct {
	svc        *service.Service
	auth       *auth.Auth
	log        *slog.Logger
	secure     bool
	setupToken string
	general    *limiter
	strict     *limiter // login, passphrase and other credential-guessing targets
}

// New builds a Server.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Server{
		svc: o.Service, auth: o.Auth, log: o.Logger, secure: o.SecureCookies, setupToken: o.SetupToken,
		general: newLimiter(30, 120, o.Now),   // 30 req/s sustained, bursts of 120
		strict:  newLimiter(1.0/6, 10, o.Now), // 10 per minute sustained, bursts of 10
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

type handlerFunc func(w http.ResponseWriter, r *http.Request, p *auth.Session) error

// route describes the protection of one endpoint.
type route struct {
	public bool            // no session needed
	strict bool            // use the strict rate limit
	perm   auth.Permission // required permission; empty means any signed-in user
}

type ctxKey int

const reqIDKey ctxKey = 1

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(reqIDKey).(string)
	return id
}

// Handler returns the full handler tree.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	return s.wrap(mux)
}

func (s *Server) handle(mux *http.ServeMux, pattern string, rt route, h handlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		lim := s.general
		if rt.strict {
			lim = s.strict
		}
		if !lim.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "10")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		if unsafeMethod(r.Method) && !sameOrigin(r) {
			writeErr(w, http.StatusForbidden, "bad_origin", "cross-origin request refused")
			return
		}
		var p *auth.Session
		if !rt.public {
			var err error
			if p, err = s.authenticate(r); err != nil {
				s.clearCookie(w)
				mapError(w, r, s.log, err)
				return
			}
			if unsafeMethod(r.Method) && !validCSRF(r, p) {
				writeErr(w, http.StatusForbidden, "bad_csrf", "missing or invalid CSRF token")
				return
			}
			if rt.perm != "" {
				if err := auth.Authorize(p, rt.perm); err != nil {
					mapError(w, r, s.log, err)
					return
				}
			}
		}
		if err := h(w, r, p); err != nil {
			mapError(w, r, s.log, err)
		}
	})
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// sameOrigin rejects browser requests that come from another origin. Requests
// without an Origin header (non-browser clients) pass; they still need the
// CSRF token, which a cross-site page cannot read.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func validCSRF(r *http.Request, p *auth.Session) bool {
	got := r.Header.Get("X-CSRF-Token")
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(p.CSRF)) == 1
}

// ---- cookies ----

func (s *Server) cookieName() string {
	if s.secure {
		return "__Host-pki_session" // __Host-: Secure, Path=/, no Domain, so it cannot be set by a sibling host
	}
	return "pki_session"
}

func (s *Server) setCookie(w http.ResponseWriter, sess *auth.Session) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: sess.Token, Path: "/",
		Expires: sess.ExpiresAt, HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) authenticate(r *http.Request) (*auth.Session, error) {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return nil, auth.ErrInvalidSession
	}
	return s.auth.Validate(r.Context(), c.Value)
}

// ---- middleware ----

func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		r = r.WithContext(context.WithValue(r.Context(), reqIDKey, id))

		h := rec.Header()
		h.Set("X-Request-ID", id)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		if s.secure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic in handler", "request_id", id, "panic", v)
				if !rec.wrote {
					writeErr(rec, http.StatusInternalServerError, "internal", "internal error")
				}
			}
			s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(), "ip", clientIP(r), "request_id", id)
		}()
		next.ServeHTTP(rec, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status, r.wrote = code, true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// pemName makes a CA name safe for a download filename.
func pemName(name string) string {
	var b strings.Builder
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
