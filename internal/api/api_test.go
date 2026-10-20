package api

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/service"
	"github.com/marcioamatte/pki-dash/internal/store"
	"github.com/marcioamatte/pki-dash/internal/vault"
)

const (
	setupToken = "test-setup-token"
	adminPW    = "lantern kettle orchid 123"
	userPW     = "river stone velvet 456"
	masterPW   = "granite harbor lantern 789"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type env struct {
	t    *testing.T
	srv  *httptest.Server
	api  *Server
	logs *syncBuf
	st   *store.Store
}

func newEnv(t *testing.T, secure bool, mods ...func(*Options)) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "pki.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := service.New(st, service.Options{KDF: vault.Params{Time: 2, Memory: 19 * 1024, Threads: 1}})
	au, err := auth.New(st, auth.Options{Password: auth.PasswordParams{Time: 2, Memory: 19 * 1024, Threads: 1}})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	o := Options{Service: svc, Auth: au, Logger: slog.New(slog.NewJSONHandler(logs, nil)), SecureCookies: secure, SetupToken: setupToken}
	for _, m := range mods {
		m(&o)
	}
	a := New(o)
	// Tests make many credential calls from one address.
	a.strict = newLimiter(1000, 1000, time.Now)
	a.general = newLimiter(1000, 1000, time.Now)
	ts := httptest.NewServer(a.Handler())
	t.Cleanup(ts.Close)
	return &env{t, ts, a, logs, st}
}

// client keeps cookies and the CSRF token, like a browser session would.
type client struct {
	e    *env
	http *http.Client
	csrf string
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, http: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("bad JSON %q: %v", r.body, err)
	}
}

func (r resp) errCode(t *testing.T) string {
	t.Helper()
	var e struct {
		Error struct{ Code string }
	}
	r.json(t, &e)
	return e.Error.Code
}

func (c *client) raw(method, path string, body io.Reader, hdr map[string]string) resp {
	c.e.t.Helper()
	req, _ := http.NewRequest(method, c.e.srv.URL+path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

func (c *client) do(method, path string, body any) resp {
	c.e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	return c.raw(method, path, r, nil)
}

func (c *client) mustOK(method, path string, body any, want int) resp {
	c.e.t.Helper()
	r := c.do(method, path, body)
	if r.status != want {
		c.e.t.Fatalf("%s %s = %d (want %d): %s", method, path, r.status, want, r.body)
	}
	return r
}

type m = map[string]any

func (c *client) login(user, pw string) {
	c.e.t.Helper()
	var s struct {
		CSRF string `json:"csrf_token"`
	}
	c.mustOK("POST", "/api/v1/login", m{"username": user, "password": pw}, 200).json(c.e.t, &s)
	c.csrf = s.CSRF
}

// bootstrap runs first-run setup and returns an admin client.
func (e *env) bootstrap() *client {
	e.t.Helper()
	c := e.client()
	c.mustOK("POST", "/api/v1/setup", m{"setup_token": setupToken, "username": "root-admin", "password": adminPW, "master_passphrase": masterPW}, 201)
	c.login("root-admin", adminPW)
	return c
}

// userClient creates a user through admin and returns a client logged in as them.
func (e *env) userClient(admin *client, name, role string) *client {
	e.t.Helper()
	admin.mustOK("POST", "/api/v1/users", m{"username": name, "password": userPW, "role": role}, 201)
	c := e.client()
	c.login(name, userPW)
	return c
}

func (c *client) createCA(kind, parent, name string, daysValid int) string {
	c.e.t.Helper()
	var out struct{ ID string }
	body := m{"kind": kind, "name": name, "validity_days": daysValid}
	if parent != "" {
		body["parent_id"] = parent
	}
	c.mustOK("POST", "/api/v1/cas", body, 201).json(c.e.t, &out)
	return out.ID
}

func (c *client) issue(caID, cn string) (id, certPEM, keyPEM, chainPEM string) {
	c.e.t.Helper()
	var out struct {
		ID    string `json:"id"`
		Cert  string `json:"certificate_pem"`
		Key   string `json:"private_key_pem"`
		Chain string `json:"chain_pem"`
	}
	c.mustOK("POST", "/api/v1/cas/"+caID+"/certificates",
		m{"common_name": cn, "dns_names": []string{cn}, "ip_addresses": []string{"10.0.0.9"}, "validity_days": 90}, 201).json(c.e.t, &out)
	return out.ID, out.Cert, out.Key, out.Chain
}

// ---------------------------------------------------------------------------

func TestSetupAndLoginFlow(t *testing.T) {
	e := newEnv(t, false)
	c := e.client()

	var st map[string]bool
	c.mustOK("GET", "/api/v1/status", nil, 200).json(t, &st)
	if !st["needs_setup"] || st["vault_initialized"] {
		t.Fatalf("fresh status = %v", st)
	}

	body := m{"setup_token": setupToken, "username": "root-admin", "password": adminPW, "master_passphrase": masterPW}
	bad := func(k string, v any) m {
		b := m{}
		for kk, vv := range body {
			b[kk] = vv
		}
		b[k] = v
		return b
	}
	if r := c.do("POST", "/api/v1/setup", bad("setup_token", "guess")); r.status != 403 || r.errCode(t) != "bad_setup_token" {
		t.Fatalf("wrong setup token: %d %s", r.status, r.body)
	}
	if r := c.do("POST", "/api/v1/setup", bad("setup_token", "")); r.status != 403 {
		t.Fatalf("missing setup token: %d", r.status)
	}
	// A weak master passphrase must not leave a half-created admin behind.
	if r := c.do("POST", "/api/v1/setup", bad("master_passphrase", "short")); r.status != 400 {
		t.Fatalf("weak passphrase: %d %s", r.status, r.body)
	}
	c.mustOK("GET", "/api/v1/status", nil, 200).json(t, &st)
	if !st["needs_setup"] {
		t.Fatal("a failed setup must not consume the first-run state")
	}

	c.mustOK("POST", "/api/v1/setup", body, 201)
	if r := c.do("POST", "/api/v1/setup", body); r.status != 409 {
		t.Fatalf("second setup: %d", r.status)
	}
	c.mustOK("GET", "/api/v1/status", nil, 200).json(t, &st)
	if st["needs_setup"] || !st["vault_initialized"] || !st["vault_unlocked"] {
		t.Fatalf("status after setup = %v", st)
	}

	if r := c.do("GET", "/api/v1/me", nil); r.status != 401 {
		t.Fatalf("me before login: %d", r.status)
	}
	c.login("root-admin", adminPW)
	var me struct{ Username, Role string }
	c.mustOK("GET", "/api/v1/me", nil, 200).json(t, &me)
	if me.Username != "root-admin" || me.Role != "admin" {
		t.Fatalf("me = %+v", me)
	}
	c.mustOK("POST", "/api/v1/logout", nil, 204)
	if r := c.do("GET", "/api/v1/me", nil); r.status != 401 {
		t.Fatalf("me after logout: %d", r.status)
	}
}

func TestCookieAndHeaders(t *testing.T) {
	for _, secure := range []bool{true, false} {
		e := newEnv(t, secure)
		c := e.client()
		c.mustOK("POST", "/api/v1/setup", m{"setup_token": setupToken, "username": "root-admin", "password": adminPW, "master_passphrase": masterPW}, 201)
		r := c.do("POST", "/api/v1/login", m{"username": "root-admin", "password": adminPW})

		var cookie *http.Cookie
		for _, ck := range (&http.Response{Header: r.header}).Cookies() {
			cookie = ck
		}
		if cookie == nil {
			t.Fatal("no session cookie")
		}
		wantName := "pki_session"
		if secure {
			wantName = "__Host-pki_session"
		}
		if cookie.Name != wantName || !cookie.HttpOnly || cookie.Secure != secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
			t.Fatalf("secure=%v cookie = %+v", secure, cookie)
		}

		h := r.header
		for k, want := range map[string]string{
			"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
			"X-Frame-Options": "DENY", "Cross-Origin-Opener-Policy": "same-origin",
		} {
			if h.Get(k) != want {
				t.Errorf("%s = %q, want %q", k, h.Get(k), want)
			}
		}
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP = %q", csp)
		}
		if (h.Get("Strict-Transport-Security") != "") != secure {
			t.Errorf("secure=%v HSTS = %q", secure, h.Get("Strict-Transport-Security"))
		}
		if h.Get("X-Request-ID") == "" {
			t.Error("no request id")
		}
	}
}

// Every protected route must refuse an anonymous caller.
func TestProtectedRoutesRequireLogin(t *testing.T) {
	e := newEnv(t, false)
	e.bootstrap()
	anon := e.client()
	for _, rt := range []string{
		"POST /api/v1/logout", "GET /api/v1/me", "POST /api/v1/me/password",
		"POST /api/v1/vault/init", "POST /api/v1/vault/unlock", "POST /api/v1/vault/lock", "POST /api/v1/vault/passphrase",
		"GET /api/v1/cas", "POST /api/v1/cas", "GET /api/v1/cas/x", "GET /api/v1/cas/x/cert", "GET /api/v1/cas/x/chain",
		"POST /api/v1/cas/x/export-key", "POST /api/v1/cas/x/remove-key", "POST /api/v1/cas/x/certificates",
		"GET /api/v1/certificates", "GET /api/v1/certificates/expiring", "GET /api/v1/certificates/x/pem", "GET /api/v1/certificates/x/fullchain",
		"GET /api/v1/users", "POST /api/v1/users", "PATCH /api/v1/users/x", "POST /api/v1/users/x/password",
		"GET /api/v1/audit", "GET /api/v1/audit/verify",
	} {
		method, path, _ := strings.Cut(rt, " ")
		var body io.Reader
		if method != "GET" {
			body = strings.NewReader("{}")
		}
		if r := anon.raw(method, path, body, nil); r.status != 401 {
			t.Errorf("%s: status %d, want 401", rt, r.status)
		}
	}
}

func TestCSRFAndOriginProtection(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	body := func() io.Reader {
		b, _ := json.Marshal(m{"kind": "root", "name": "R", "validity_days": 30})
		return bytes.NewReader(b)
	}

	if r := admin.raw("POST", "/api/v1/cas", body(), map[string]string{"X-CSRF-Token": ""}); r.status != 403 || r.errCode(t) != "bad_csrf" {
		t.Fatalf("missing CSRF token: %d %s", r.status, r.body)
	}
	if r := admin.raw("POST", "/api/v1/cas", body(), map[string]string{"X-CSRF-Token": "wrong"}); r.status != 403 {
		t.Fatalf("wrong CSRF token: %d", r.status)
	}
	// A valid token is not enough from a foreign origin.
	if r := admin.raw("POST", "/api/v1/cas", body(), map[string]string{"Origin": "https://evil.example"}); r.status != 403 || r.errCode(t) != "bad_origin" {
		t.Fatalf("foreign origin: %d %s", r.status, r.body)
	}
	if r := admin.raw("POST", "/api/v1/cas", body(), map[string]string{"Origin": e.srv.URL}); r.status != 201 {
		t.Fatalf("same origin: %d %s", r.status, r.body)
	}
	// Reads need no token.
	admin.mustOK("GET", "/api/v1/cas", nil, 200)
	// The login endpoint is also protected against cross-origin posts.
	anon := e.client()
	b, _ := json.Marshal(m{"username": "root-admin", "password": adminPW})
	if r := anon.raw("POST", "/api/v1/login", bytes.NewReader(b), map[string]string{"Origin": "https://evil.example"}); r.status != 403 {
		t.Fatalf("cross-origin login: %d", r.status)
	}
}

func TestRoleAuthorization(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	viewer := e.userClient(admin, "view-only", "viewer")
	oper := e.userClient(admin, "oper-user", "operator")

	root := admin.createCA("root", "", "Lab Root", 3650)
	inter := admin.createCA("intermediate", root, "Lab Inter", 1825)

	cases := []struct {
		who    string
		c      *client
		method string
		path   string
		body   any
		want   int
	}{
		{"viewer lists CAs", viewer, "GET", "/api/v1/cas", nil, 200},
		{"viewer downloads CA cert", viewer, "GET", "/api/v1/cas/" + root + "/cert", nil, 200},
		{"viewer cannot issue", viewer, "POST", "/api/v1/cas/" + inter + "/certificates", m{"common_name": "a.lab", "dns_names": []string{"a.lab"}, "validity_days": 30}, 403},
		{"viewer cannot create CA", viewer, "POST", "/api/v1/cas", m{"kind": "root", "name": "X", "validity_days": 30}, 403},
		{"viewer cannot read users", viewer, "GET", "/api/v1/users", nil, 403},
		{"viewer cannot read audit", viewer, "GET", "/api/v1/audit", nil, 403},
		{"operator issues", oper, "POST", "/api/v1/cas/" + inter + "/certificates", m{"common_name": "a.lab", "dns_names": []string{"a.lab"}, "validity_days": 30}, 201},
		{"operator cannot create root", oper, "POST", "/api/v1/cas", m{"kind": "root", "name": "X", "validity_days": 30}, 403},
		{"operator cannot create intermediate", oper, "POST", "/api/v1/cas", m{"kind": "intermediate", "parent_id": root, "name": "Y", "validity_days": 30}, 403},
		{"operator cannot export a key", oper, "POST", "/api/v1/cas/" + root + "/export-key", m{"master_passphrase": masterPW}, 403},
		{"operator cannot remove a key", oper, "POST", "/api/v1/cas/" + root + "/remove-key", m{"master_passphrase": masterPW, "confirm_name": "Lab Root"}, 403},
		{"operator cannot lock the vault", oper, "POST", "/api/v1/vault/lock", nil, 403},
		{"operator cannot create users", oper, "POST", "/api/v1/users", m{"username": "zed-user", "password": userPW + "x", "role": "admin"}, 403},
		{"operator cannot promote self", oper, "PATCH", "/api/v1/users/anything", m{"role": "admin"}, 403},
		{"admin reads audit", admin, "GET", "/api/v1/audit", nil, 200},
	}
	for _, tc := range cases {
		if r := tc.c.do(tc.method, tc.path, tc.body); r.status != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.who, r.status, tc.want, r.body)
		}
	}
}

func TestFullPKIFlowOverAPI(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	rootID := admin.createCA("root", "", "Lab Root", 3650)
	interID := admin.createCA("intermediate", rootID, "Lab Intermediate", 1825)

	// A Root cannot issue service certificates.
	if r := admin.do("POST", "/api/v1/cas/"+rootID+"/certificates", m{"common_name": "x.lab", "dns_names": []string{"x.lab"}, "validity_days": 30}); r.status != 422 {
		t.Fatalf("issue from root: %d %s", r.status, r.body)
	}

	certID, certPEM, keyPEM, chainPEM := admin.issue(interID, "app.lab")
	if !strings.Contains(keyPEM, "PRIVATE KEY") {
		t.Fatal("a generated key must be returned on issuance")
	}
	// What the user receives verifies as a TLS client would.
	rootPEM := admin.mustOK("GET", "/api/v1/cas/"+rootID+"/cert", nil, 200).body
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	inters.AppendCertsFromPEM([]byte(chainPEM))
	blk, _ := pem.Decode([]byte(certPEM))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "app.lab"}); err != nil {
		t.Fatalf("issued certificate does not verify: %v", err)
	}
	full := admin.mustOK("GET", "/api/v1/certificates/"+certID+"/fullchain", nil, 200).body
	if bytes.Count(full, []byte("BEGIN CERTIFICATE")) != 3 {
		t.Fatal("fullchain should hold leaf, intermediate and root")
	}
	pemResp := admin.mustOK("GET", "/api/v1/certificates/"+certID+"/pem", nil, 200)
	if pemResp.header.Get("Content-Disposition") == "" || !strings.HasPrefix(string(pemResp.body), "-----BEGIN CERTIFICATE") {
		t.Fatal("bad PEM download")
	}

	// Listing and expiry.
	var certs []map[string]any
	admin.mustOK("GET", "/api/v1/certificates?ca_id="+interID, nil, 200).json(t, &certs)
	if len(certs) != 1 {
		t.Fatalf("certs = %v", certs)
	}
	admin.mustOK("GET", "/api/v1/certificates/expiring?days=120", nil, 200).json(t, &certs)
	if len(certs) != 1 {
		t.Fatalf("expiring(120d) = %v", certs)
	}
	admin.mustOK("GET", "/api/v1/certificates/expiring?days=30", nil, 200).json(t, &certs)
	if len(certs) != 0 {
		t.Fatalf("expiring(30d) = %v", certs)
	}
	if r := admin.do("GET", "/api/v1/certificates/expiring?days=abc", nil); r.status != 400 {
		t.Fatalf("bad days: %d", r.status)
	}

	// Taking the Root offline requires the master passphrase and a typed confirmation.
	if r := admin.do("POST", "/api/v1/cas/"+rootID+"/export-key", m{"master_passphrase": "wrong passphrase!!"}); r.status != 401 {
		t.Fatalf("export with wrong passphrase: %d", r.status)
	}
	exp := admin.mustOK("POST", "/api/v1/cas/"+rootID+"/export-key", m{"master_passphrase": masterPW}, 200)
	if !strings.Contains(string(exp.body), "PRIVATE KEY") || exp.header.Get("Cache-Control") != "no-store" {
		t.Fatal("export must return the key, uncached")
	}
	if r := admin.do("POST", "/api/v1/cas/"+rootID+"/remove-key", m{"master_passphrase": masterPW, "confirm_name": "wrong"}); r.status != 400 {
		t.Fatalf("remove without confirmation: %d", r.status)
	}
	if r := admin.do("POST", "/api/v1/cas/"+rootID+"/remove-key", m{"master_passphrase": "wrong passphrase!!", "confirm_name": "Lab Root"}); r.status != 401 {
		t.Fatalf("remove with wrong passphrase: %d", r.status)
	}
	admin.mustOK("POST", "/api/v1/cas/"+rootID+"/remove-key", m{"master_passphrase": masterPW, "confirm_name": "Lab Root"}, 204)

	var ca struct {
		KeyHeld bool `json:"key_held"`
	}
	admin.mustOK("GET", "/api/v1/cas/"+rootID, nil, 200).json(t, &ca)
	if ca.KeyHeld {
		t.Fatal("key_held should be false after removal")
	}
	if r := admin.do("POST", "/api/v1/cas/"+rootID+"/export-key", m{"master_passphrase": masterPW}); r.status != 409 || r.errCode(t) != "key_offline" {
		t.Fatalf("export after removal: %d %s", r.status, r.body)
	}
	admin.issue(interID, "still.lab") // the intermediate carries on
}

func TestPrivateMaterialNeverInReadResponses(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)
	certID, _, _, _ := admin.issue(inter, "app.lab")
	for _, p := range []string{
		"/api/v1/cas", "/api/v1/cas/" + root, "/api/v1/cas/" + root + "/cert", "/api/v1/cas/" + inter + "/chain",
		"/api/v1/certificates", "/api/v1/certificates/" + certID + "/pem", "/api/v1/certificates/" + certID + "/fullchain",
		"/api/v1/users", "/api/v1/audit?limit=1000", "/api/v1/me", "/api/v1/status",
	} {
		body := string(admin.mustOK("GET", p, nil, 200).body)
		for _, secret := range []string{"PRIVATE KEY", "$argon2", masterPW, adminPW, "key_blob"} {
			if strings.Contains(body, secret) {
				t.Errorf("GET %s leaks %q", p, secret)
			}
		}
	}
}

func TestInputHandling(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	post := func(ct, body string) resp {
		return admin.raw("POST", "/api/v1/cas", strings.NewReader(body), map[string]string{"Content-Type": ct})
	}
	good := `{"kind":"root","name":"R","validity_days":30}`
	if r := post("text/plain", good); r.status != 415 {
		t.Errorf("wrong content type: %d", r.status)
	}
	if r := post("application/json", `{"kind":"root","name":"R","validity_days":30,"surprise":1}`); r.status != 400 {
		t.Errorf("unknown field: %d", r.status)
	}
	if r := post("application/json", good+` {"x":1}`); r.status != 400 {
		t.Errorf("trailing data: %d", r.status)
	}
	if r := post("application/json", `{not json`); r.status != 400 || strings.Contains(string(r.body), "not json") {
		t.Errorf("malformed: %d %s", r.status, r.body)
	}
	big := `{"kind":"root","name":"` + strings.Repeat("a", maxBody+10) + `","validity_days":30}`
	if r := post("application/json", big); r.status != 413 {
		t.Errorf("oversized body: %d", r.status)
	}
	for name, body := range map[string]m{
		"validity zero":           {"kind": "root", "name": "R2", "validity_days": 0},
		"validity huge":           {"kind": "root", "name": "R2", "validity_days": 100000},
		"unknown kind":            {"kind": "sub", "name": "R2", "validity_days": 30},
		"unknown algo":            {"kind": "root", "name": "R2", "validity_days": 30, "key_algo": "dsa-1024"},
		"intermediate sin parent": {"kind": "intermediate", "name": "R2", "validity_days": 30},
		"empty name":              {"kind": "root", "name": " ", "validity_days": 30},
	} {
		if r := admin.do("POST", "/api/v1/cas", body); r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	// Unknown route and wrong method.
	if r := admin.do("GET", "/api/v1/nope", nil); r.status != 404 || r.errCode(t) != "not_found" || r.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("unknown route: %d %s", r.status, r.body)
	}
	if r := admin.do("DELETE", "/api/v1/cas", nil); r.status != 405 {
		t.Errorf("wrong method: %d", r.status)
	}
	// Too many SANs.
	root := admin.createCA("root", "", "R3", 3650)
	inter := admin.createCA("intermediate", root, "I3", 1825)
	names := make([]string, maxSANs+1)
	for i := range names {
		names[i] = "h.lab"
	}
	if r := admin.do("POST", "/api/v1/cas/"+inter+"/certificates", m{"common_name": "x", "dns_names": names, "validity_days": 30}); r.status != 400 {
		t.Errorf("too many SANs: %d", r.status)
	}
}

func TestLoginErrorsDoNotRevealAccounts(t *testing.T) {
	e := newEnv(t, false)
	e.bootstrap()
	c := e.client()
	a := c.do("POST", "/api/v1/login", m{"username": "root-admin", "password": "not the password!!"})
	b := c.do("POST", "/api/v1/login", m{"username": "nobody-here", "password": "not the password!!"})
	if a.status != 401 || b.status != 401 || !bytes.Equal(a.body, b.body) {
		t.Fatalf("responses differ:\n%d %s\n%d %s", a.status, a.body, b.status, b.body)
	}
}

func TestRateLimitOnCredentialEndpoints(t *testing.T) {
	e := newEnv(t, false)
	e.bootstrap()
	e.api.strict = newLimiter(1.0/6, 10, time.Now) // production values
	c := e.client()
	limited := 0
	for range 14 {
		r := c.do("POST", "/api/v1/login", m{"username": "nobody-here", "password": "x"})
		if r.status == 429 {
			limited++
			if r.header.Get("Retry-After") == "" || r.errCode(t) != "rate_limited" {
				t.Fatalf("bad 429: %v %s", r.header, r.body)
			}
		}
	}
	if limited < 3 {
		t.Fatalf("only %d of 14 rapid logins were limited", limited)
	}
}

func TestLimiterRefillAndBounds(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLimiter(1, 3, func() time.Time { return now })
	for i := range 3 {
		if !l.allow("a") {
			t.Fatalf("burst request %d refused", i)
		}
	}
	if l.allow("a") {
		t.Fatal("4th request must be refused")
	}
	if !l.allow("b") {
		t.Fatal("another key has its own bucket")
	}
	now = now.Add(2 * time.Second)
	if !l.allow("a") || !l.allow("a") || l.allow("a") {
		t.Fatal("two tokens should have refilled")
	}
	// Idle buckets are swept; a full table refuses new keys rather than growing.
	now = now.Add(time.Hour)
	l.allow("c")
	if len(l.buckets) != 1 {
		t.Fatalf("sweep left %d buckets", len(l.buckets))
	}
	l.max = 1
	if l.allow("d") {
		t.Fatal("a full table must refuse new keys")
	}
}

func TestLockedVaultAndPassphraseHandling(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)

	admin.mustOK("POST", "/api/v1/vault/lock", nil, 204)
	if r := admin.do("POST", "/api/v1/cas/"+inter+"/certificates", m{"common_name": "a.lab", "dns_names": []string{"a.lab"}, "validity_days": 30}); r.status != 409 || r.errCode(t) != "vault_locked" {
		t.Fatalf("issue while locked: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/vault/unlock", m{"master_passphrase": "wrong passphrase!!"}); r.status != 401 || r.errCode(t) != "invalid_passphrase" {
		t.Fatalf("wrong passphrase: %d %s", r.status, r.body)
	}
	admin.mustOK("POST", "/api/v1/vault/unlock", m{"master_passphrase": masterPW}, 204)
	admin.issue(inter, "a.lab")

	// Changing the master passphrase needs the current one.
	newPW := "a brand new master phrase"
	if r := admin.do("POST", "/api/v1/vault/passphrase", m{"current_master_passphrase": "wrong passphrase!!", "new_master_passphrase": newPW}); r.status != 401 {
		t.Fatalf("change with wrong current: %d", r.status)
	}
	if r := admin.do("POST", "/api/v1/vault/passphrase", m{"current_master_passphrase": masterPW, "new_master_passphrase": "short"}); r.status != 400 {
		t.Fatalf("weak new passphrase: %d", r.status)
	}
	admin.mustOK("POST", "/api/v1/vault/passphrase", m{"current_master_passphrase": masterPW, "new_master_passphrase": newPW}, 204)
	admin.mustOK("POST", "/api/v1/vault/lock", nil, 204)
	if r := admin.do("POST", "/api/v1/vault/unlock", m{"master_passphrase": masterPW}); r.status != 401 {
		t.Fatalf("old passphrase after change: %d", r.status)
	}
	admin.mustOK("POST", "/api/v1/vault/unlock", m{"master_passphrase": newPW}, 204)
	admin.issue(inter, "b.lab")
}

func TestOwnPasswordChangeEndsSession(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	if r := admin.do("POST", "/api/v1/me/password", m{"current_password": "wrong password!!", "new_password": "another good passphrase 1"}); r.status != 401 {
		t.Fatalf("wrong current: %d", r.status)
	}
	admin.mustOK("POST", "/api/v1/me/password", m{"current_password": adminPW, "new_password": "another good passphrase 1"}, 204)
	if r := admin.do("GET", "/api/v1/me", nil); r.status != 401 {
		t.Fatalf("session must end after a password change: %d", r.status)
	}
	e.client().login("root-admin", "another good passphrase 1")
}

func TestUsersAPI(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	id := ""
	var out struct{ ID string }
	admin.mustOK("POST", "/api/v1/users", m{"username": "new-user", "password": userPW, "role": "viewer"}, 201).json(t, &out)
	id = out.ID

	if r := admin.do("POST", "/api/v1/users", m{"username": "weak-user", "password": "short", "role": "viewer"}); r.status != 400 {
		t.Errorf("weak password: %d", r.status)
	}
	if r := admin.do("POST", "/api/v1/users", m{"username": "NEW-USER", "password": userPW, "role": "viewer"}); r.status != 409 {
		t.Errorf("duplicate: %d", r.status)
	}
	if r := admin.do("POST", "/api/v1/users", m{"username": "odd-role", "password": userPW, "role": "root"}); r.status != 400 {
		t.Errorf("bad role: %d", r.status)
	}
	if r := admin.do("PATCH", "/api/v1/users/"+id, m{}); r.status != 400 {
		t.Errorf("empty patch: %d", r.status)
	}
	admin.mustOK("PATCH", "/api/v1/users/"+id, m{"role": "operator"}, 204)
	admin.mustOK("POST", "/api/v1/users/"+id+"/password", m{"new_password": "reset passphrase 999"}, 204)
	e.client().login("new-user", "reset passphrase 999")
	admin.mustOK("PATCH", "/api/v1/users/"+id, m{"disabled": true}, 204)
	if r := e.client().do("POST", "/api/v1/login", m{"username": "new-user", "password": "reset passphrase 999"}); r.status != 401 {
		t.Errorf("disabled user logged in: %d", r.status)
	}
	// The only admin cannot be demoted or disabled.
	var me struct{ Username string }
	admin.mustOK("GET", "/api/v1/me", nil, 200).json(t, &me)
	var users []struct{ ID, Username string }
	admin.mustOK("GET", "/api/v1/users", nil, 200).json(t, &users)
	var adminID string
	for _, u := range users {
		if u.Username == me.Username {
			adminID = u.ID
		}
	}
	if r := admin.do("PATCH", "/api/v1/users/"+adminID, m{"role": "viewer"}); r.status != 409 || r.errCode(t) != "last_admin" {
		t.Errorf("demote last admin: %d %s", r.status, r.body)
	}
}

func TestAuditAPI(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	admin.createCA("root", "", "R", 3650)
	var entries []struct{ Action, Actor string }
	admin.mustOK("GET", "/api/v1/audit?limit=50", nil, 200).json(t, &entries)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	for _, want := range []string{"user.create", "vault.init", "user.login", "ca.create"} {
		if !seen[want] {
			t.Errorf("audit lacks %q", want)
		}
	}
	var v struct{ OK bool }
	admin.mustOK("GET", "/api/v1/audit/verify", nil, 200).json(t, &v)
	if !v.OK {
		t.Fatal("audit chain should verify")
	}
	if r := admin.do("GET", "/api/v1/audit?limit=0", nil); r.status != 400 {
		t.Errorf("limit 0: %d", r.status)
	}
}

func TestLogsContainNoSecrets(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)
	_, _, key, _ := admin.issue(inter, "app.lab")
	admin.do("POST", "/api/v1/login", m{"username": "root-admin", "password": "a wrong password!!"})
	admin.do("POST", "/api/v1/vault/unlock", m{"master_passphrase": "a wrong passphrase!!"})
	admin.do("POST", "/api/v1/cas/"+root+"/export-key", m{"master_passphrase": masterPW})

	logs := e.logs.String()
	if !strings.Contains(logs, `"request_id"`) {
		t.Fatal("expected access log lines")
	}
	secrets := []string{adminPW, masterPW, "a wrong password", "a wrong passphrase", "PRIVATE KEY", admin.csrf, setupToken}
	if line := strings.TrimSpace(strings.Split(key, "\n")[1]); line != "" {
		secrets = append(secrets, line)
	}
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Errorf("log output leaks %q", s)
		}
	}
}
