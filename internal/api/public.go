package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/marcioamatte/pki-dash/internal/service"
	"github.com/marcioamatte/pki-dash/internal/store"
)

// The public handler is the other face of the server. It serves only what any
// client of the PKI must be able to fetch without logging in, and nothing else:
//
//	GET /crl/<ca-id>.crl   the CA's latest revocation list (DER)
//	GET /ca/<ca-id>.crt    the CA's certificate (DER), where certificates point
//
// Both are public, signed or self-describing data. There is no API, no cookie,
// no session and no write path here, which is why it can be a separate plain
// HTTP listener: CRLs are fetched over HTTP by design, and a client that cannot
// yet trust our TLS certificate must still be able to fetch them.

var publicName = regexp.MustCompile(`^([0-9a-f]{32})\.(crl|crt)$`)

// PublicHandler returns the handler for the public listener.
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /crl/{name}", s.publicFile("crl"))
	mux.HandleFunc("GET /ca/{name}", s.publicFile("crt"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Reads of anything else are simply not here. Other methods on the two
		// routes above are refused as such.
		if r.Method != http.MethodGet && r.Method != http.MethodHead &&
			(strings.HasPrefix(r.URL.Path, "/crl/") || strings.HasPrefix(r.URL.Path, "/ca/")) {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.NotFound(w, r)
	})
	return s.wrapPublic(mux)
}

func (s *Server) wrapPublic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h := rec.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "cross-origin") // clients, not pages, fetch these
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic in public handler", "panic", v)
				if !rec.wrote {
					http.Error(rec, "internal error", http.StatusInternalServerError)
				}
			}
			s.log.Info("public request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(), "ip", clientIP(r))
		}()
		if !s.public.allow(clientIP(r)) {
			rec.Header().Set("Retry-After", "10")
			http.Error(rec, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(rec, r)
	})
}

func (s *Server) publicFile(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := publicName.FindStringSubmatch(r.PathValue("name"))
		if m == nil || m[2] != kind {
			http.NotFound(w, r)
			return
		}
		var (
			der      []byte
			modified time.Time
			ctype    string
			maxAge   string
			err      error
		)
		switch kind {
		case "crl":
			var crl store.PublishedCRL
			if crl, err = s.svc.PublicCRL(r.Context(), m[1]); err == nil {
				der, modified, ctype, maxAge = crl.DER, crl.ModifiedAt, "application/pkix-crl", "max-age=300"
			}
		default:
			if der, err = s.svc.PublicCACertificate(r.Context(), m[1]); err == nil {
				ctype, maxAge = "application/pkix-cert", "max-age=3600"
			}
		}
		switch {
		case errors.Is(err, service.ErrNoCRL), errors.Is(err, store.ErrNotFound):
			http.NotFound(w, r)
			return
		case err != nil:
			s.log.Error("public request failed", "path", r.URL.Path, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(der)
		h := w.Header()
		h.Set("Content-Type", ctype)
		h.Set("Cache-Control", "public, "+maxAge)
		h.Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
		// ServeContent answers conditional requests (If-None-Match, If-Modified-Since) with 304.
		http.ServeContent(w, r, "", modified, bytes.NewReader(der))
	}
}
