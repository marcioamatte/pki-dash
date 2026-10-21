package api

import (
	"bytes"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// uiCSP is strict: only our own origin, no inline script, no inline style, no
// plugins, no framing. The bundle is built to satisfy it (no inline scripts,
// no preload polyfill).
const uiCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func init() {
	// The runtime image has no /etc/mime.types, and fonts are not in Go's built-in
	// table, so say what they are instead of leaving it to content sniffing.
	_ = mime.AddExtensionType(".woff2", "font/woff2")
	_ = mime.AddExtensionType(".woff", "font/woff")
}

// uiRoutes serves the single-page app: index.html at "/", and hashed assets.
// The app uses hash routing, so no other path ever needs index.html.
func (s *Server) uiRoutes(mux *http.ServeMux) {
	if s.ui == nil {
		return
	}
	mux.HandleFunc("GET /{$}", s.serveUI("index.html", false))
	mux.HandleFunc("GET /favicon.svg", s.serveUI("favicon.svg", false))
	mux.HandleFunc("GET /assets/{file...}", func(w http.ResponseWriter, r *http.Request) {
		// Validate the requested part on its own: joining first would let "../"
		// climb out of assets/ (still inside the embedded FS, but wrong).
		file := r.PathValue("file")
		if file == "." || !fs.ValidPath(file) {
			writeErr(w, http.StatusNotFound, "not_found", "not found")
			return
		}
		s.serveUI(path.Join("assets", file), true)(w, r)
	})
}

func (s *Server) serveUI(name string, immutable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !fs.ValidPath(name) || strings.HasPrefix(path.Base(name), ".") {
			writeErr(w, http.StatusNotFound, "not_found", "not found")
			return
		}
		data, err := fs.ReadFile(s.ui, name)
		if err != nil {
			if name == "index.html" {
				http.Error(w, "The web UI is not built into this binary.\nRun: cd web && npm ci && npm run build, then rebuild the server.", http.StatusServiceUnavailable)
				return
			}
			writeErr(w, http.StatusNotFound, "not_found", "not found")
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", uiCSP)
		if immutable { // asset file names carry a content hash
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	}
}
