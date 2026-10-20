package api

import (
	"strings"
	"testing"
	"testing/fstest"
)

func uiFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":            {Data: []byte(`<!doctype html><div id="app"></div><script type="module" src="/assets/app-abc123.js"></script>`)},
		"favicon.svg":           {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
		"assets/app-abc123.js":  {Data: []byte(`console.log("hi")`)},
		"assets/app-abc123.css": {Data: []byte(`body{margin:0}`)},
		".gitkeep":              {Data: nil},
	}
}

func TestUIServing(t *testing.T) {
	e := newEnv(t, true, func(o *Options) { o.UI = uiFS() })
	c := e.client()

	r := c.raw("GET", "/", nil, nil)
	if r.status != 200 || !strings.Contains(string(r.body), `id="app"`) {
		t.Fatalf("index: %d %s", r.status, r.body)
	}
	csp := r.header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe") {
		t.Errorf("CSP must not allow unsafe-*: %s", csp)
	}
	if r.header.Get("Cache-Control") != "no-cache" || r.header.Get("Strict-Transport-Security") == "" || r.header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("index headers: %v", r.header)
	}
	if !strings.Contains(r.header.Get("Permissions-Policy"), "camera=()") {
		t.Errorf("Permissions-Policy = %q", r.header.Get("Permissions-Policy"))
	}

	js := c.raw("GET", "/assets/app-abc123.js", nil, nil)
	if js.status != 200 || !strings.Contains(js.header.Get("Content-Type"), "javascript") ||
		js.header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("asset: %d %v", js.status, js.header)
	}
	if css := c.raw("GET", "/assets/app-abc123.css", nil, nil); css.status != 200 || !strings.Contains(css.header.Get("Content-Type"), "text/css") {
		t.Errorf("css: %d %v", css.status, css.header)
	}
	if fav := c.raw("GET", "/favicon.svg", nil, nil); fav.status != 200 || fav.header.Get("Content-Type") != "image/svg+xml" {
		t.Errorf("favicon: %d %v", fav.status, fav.header)
	}
	// The API keeps its own, stricter policy.
	if api := c.raw("GET", "/api/v1/status", nil, nil); !strings.Contains(api.header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("API CSP = %q", api.header.Get("Content-Security-Policy"))
	}
}

func TestUIDoesNotServeAnythingElse(t *testing.T) {
	e := newEnv(t, false, func(o *Options) { o.UI = uiFS() })
	c := e.client()
	for _, p := range []string{
		"/assets/missing.js", "/assets/", "/assets/../index.html", "/assets/%2e%2e/index.html", "/assets/.gitkeep",
		"/index.html", "/.gitkeep", "/etc/passwd", "/assets/..%2f..%2fetc/passwd",
	} {
		r := c.raw("GET", p, nil, nil)
		// Either refused, or a JSON 404; never file content, and never the SPA shell for unknown paths.
		if r.status == 200 {
			t.Errorf("GET %s returned 200: %.60s", p, r.body)
		}
	}
	if r := c.raw("POST", "/", strings.NewReader("{}"), nil); r.status != 405 {
		t.Errorf("POST /: %d", r.status)
	}
}

func TestUINotBuiltExplainsItself(t *testing.T) {
	e := newEnv(t, false, func(o *Options) { o.UI = fstestEmpty() })
	r := e.client().raw("GET", "/", nil, nil)
	if r.status != 503 || !strings.Contains(string(r.body), "npm run build") {
		t.Fatalf("status %d: %s", r.status, r.body)
	}
	// The API is unaffected.
	if r := e.client().raw("GET", "/api/v1/status", nil, nil); r.status != 200 {
		t.Fatalf("API status: %d", r.status)
	}
}

func fstestEmpty() fstest.MapFS { return fstest.MapFS{".gitkeep": {}} }

func TestAPIOnlyModeHasNoUI(t *testing.T) {
	e := newEnv(t, false)
	if r := e.client().raw("GET", "/", nil, nil); r.status != 404 {
		t.Fatalf("GET / without UI: %d", r.status)
	}
}
