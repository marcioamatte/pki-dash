// Package oidctest is a minimal OpenID provider for tests: discovery, signing
// keys and a token endpoint that checks PKCE, the client secret and the
// redirect URI the way a real one does. It is only ever imported by tests.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IdP is a minimal OpenID provider: discovery, keys and a token endpoint
// that checks PKCE, the client secret and the redirect URI like a real one.
type IdP struct {
	t      testing.TB
	srv    *httptest.Server
	key    *rsa.PrivateKey
	other  *rsa.PrivateKey // a key the provider does not publish
	Secret string

	mu       sync.Mutex
	codes    map[string]codeInfo
	override func(c map[string]any)
	signWith *rsa.PrivateKey
}

type codeInfo struct{ nonce, challenge, redirect string }

// New starts a provider that stops with the test.
func New(t testing.TB) *IdP {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	o, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &IdP{t: t, key: k, other: o, Secret: "s3cret", codes: map[string]codeInfo{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *IdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	user, pass, _ := r.BasicAuth()
	if user == "" {
		user, pass = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	f.mu.Lock()
	ci, ok := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code"))
	override, signWith := f.override, f.signWith
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || user != ClientID || pass != f.Secret || r.PostForm.Get("redirect_uri") != ci.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != ci.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	claims := map[string]any{
		"iss": f.srv.URL, "sub": "user-1", "aud": ClientID, "nonce": ci.nonce,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"preferred_username": "ana.souza", "groups": []string{"/pki-admins", "other"},
		"realm_access": map[string]any{"roles": []string{"pki-operator"}},
	}
	if override != nil {
		override(claims)
	}
	if signWith == nil {
		signWith = f.key
	}
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: signWith, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
	raw, _ := jwt.Signed(sig).Claims(claims).Serialize()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
}

// Browse plays the browser: it reads the authorization URL, "logs in", and
// returns the callback query the provider would send back.
func (f *IdP) Browse(authURL string) url.Values {
	u, err := url.Parse(authURL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := u.Query()
	code := "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.codes[code] = codeInfo{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	f.mu.Unlock()
	return url.Values{"state": {q.Get("state")}, "code": {code}}
}

// URL is the provider's issuer address.
func (f *IdP) URL() string { return f.srv.URL }

// ClientID is the only client this provider knows.
const ClientID = "pki"

// Tweak changes the claims of the tokens issued from now on (nil restores them).
func (f *IdP) Tweak(fn func(claims map[string]any)) {
	f.mu.Lock()
	f.override = fn
	f.mu.Unlock()
}

// SignWithUnpublishedKey makes the next tokens carry a signature the
// published keys cannot verify.
func (f *IdP) SignWithUnpublishedKey(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signWith = nil
	if on {
		f.signWith = f.other
	}
}

// Close stops the provider early, to test an outage.
func (f *IdP) Close() { f.srv.Close() }
