// Package oidc signs users in through an external OpenID Connect provider
// (Keycloak and the like) using the authorization-code flow with PKCE.
//
// What it guarantees, and what it leaves to others:
//   - the redirect carries a random state, a nonce and a PKCE challenge; the
//     state is single-use, expires, and only completes in the browser that
//     started it (a cookie holds a second secret bound to it), so a login
//     cannot be forced onto someone else's browser;
//   - the ID token's signature, issuer, audience, expiry and nonce are checked
//     by the go-oidc library, against keys fetched from the provider;
//   - only the verified ID token is trusted: nothing is read from the userinfo
//     endpoint or from unverified tokens;
//   - it never decides who may do what. It hands back who the person is and
//     which groups the provider says they belong to; package auth maps those
//     to a role.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	// ErrState means the callback does not match a login this server started
	// (unknown, expired, replayed, or from another browser).
	ErrState = errors.New("oidc: invalid or expired login state")
	// ErrDenied means the provider refused or the user cancelled.
	ErrDenied = errors.New("oidc: the provider did not grant access")
	// ErrToken means the code could not be exchanged or the ID token is not valid.
	ErrToken = errors.New("oidc: invalid token")
	// ErrUnavailable means the provider could not be reached or is misconfigured.
	ErrUnavailable = errors.New("oidc: provider unavailable")
	// ErrBusy means too many logins are in progress.
	ErrBusy = errors.New("oidc: too many logins in progress")
)

const (
	stateTTL   = 10 * time.Minute
	maxPending = 1000
)

// Config describes the provider and this application as its client.
type Config struct {
	Issuer       string // https://keycloak.lab/realms/lab
	ClientID     string
	ClientSecret string // empty for a public client (PKCE only)
	RedirectURL  string // https://pki.lab:8443/api/v1/auth/oidc/callback
	// GroupsClaim names the ID-token claim holding the user's groups or roles.
	// A dotted path reaches into objects: "realm_access.roles". Default "groups".
	GroupsClaim string
	// UsernameClaim is preferred for the account name. Default "preferred_username".
	UsernameClaim string
	// HTTPClient reaches the provider; use it to trust a private CA. Default http.DefaultClient.
	HTTPClient *http.Client
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Identity is what the provider vouched for.
type Identity struct {
	Issuer   string
	Subject  string // stable per user at this issuer: the only thing identity is keyed on
	Username string // suggested account name, not trusted to be unique
	Groups   []string
}

type pending struct {
	nonce, verifier, binder string
	expires                 time.Time
}

// Provider is safe for concurrent use.
type Provider struct {
	cfg    Config
	client *http.Client
	now    func() time.Time

	mu       sync.Mutex
	prov     *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth    *oauth2.Config
	pend     map[string]pending
}

// New validates the configuration. It does not contact the provider: that
// happens on first use and is retried, so the dashboard starts even while the
// provider is down.
func New(cfg Config) (*Provider, error) {
	if err := checkURL("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	if err := checkURL("redirect URL", cfg.RedirectURL); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("oidc: client id is required")
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	p := &Provider{cfg: cfg, client: cfg.HTTPClient, now: cfg.Now, pend: map[string]pending{}}
	if p.client == nil {
		p.client = http.DefaultClient
	}
	if p.now == nil {
		p.now = time.Now
	}
	return p, nil
}

// checkURL insists on https, except for a loopback host (development).
func checkURL(what, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("oidc: %s %q is not a valid URL", what, raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return fmt.Errorf("oidc: %s must use https (http is only accepted for localhost)", what)
		}
	default:
		return fmt.Errorf("oidc: %s must use https", what)
	}
	return nil
}

// discover contacts the provider once and keeps the result.
func (p *Provider) discover(ctx context.Context) (*oauth2.Config, *gooidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.prov != nil {
		return p.oauth, p.verifier, nil
	}
	ctx = gooidc.ClientContext(ctx, p.client)
	prov, err := gooidc.NewProvider(ctx, p.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	p.prov = prov
	p.verifier = prov.Verifier(&gooidc.Config{ClientID: p.cfg.ClientID})
	p.oauth = &oauth2.Config{
		ClientID: p.cfg.ClientID, ClientSecret: p.cfg.ClientSecret, RedirectURL: p.cfg.RedirectURL,
		Endpoint: prov.Endpoint(), Scopes: []string{gooidc.ScopeOpenID, "profile"},
	}
	return p.oauth, p.verifier, nil
}

// Check contacts the provider, for a startup log line.
func (p *Provider) Check(ctx context.Context) error {
	_, _, err := p.discover(ctx)
	return err
}

func random() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Begin starts a login. The caller redirects the browser to authURL and stores
// binder in a cookie that Complete will ask for.
func (p *Provider) Begin(ctx context.Context) (authURL, binder string, err error) {
	oc, _, err := p.discover(ctx)
	if err != nil {
		return "", "", err
	}
	state, err := random()
	if err != nil {
		return "", "", err
	}
	nonce, err := random()
	if err != nil {
		return "", "", err
	}
	binder, err = random()
	if err != nil {
		return "", "", err
	}
	verifier := oauth2.GenerateVerifier()

	now := p.now()
	p.mu.Lock()
	for k, v := range p.pend { // forget abandoned logins
		if !now.Before(v.expires) {
			delete(p.pend, k)
		}
	}
	if len(p.pend) >= maxPending {
		p.mu.Unlock()
		return "", "", ErrBusy
	}
	p.pend[state] = pending{nonce: nonce, verifier: verifier, binder: binder, expires: now.Add(stateTTL)}
	p.mu.Unlock()

	u := oc.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))
	return u, binder, nil
}

// Complete finishes a login from the callback's query and the binder cookie.
func (p *Provider) Complete(ctx context.Context, q url.Values, binder string) (*Identity, error) {
	state := q.Get("state")
	p.mu.Lock()
	pd, ok := p.pend[state]
	delete(p.pend, state) // single use, whatever happens next
	p.mu.Unlock()
	if !ok || !p.now().Before(pd.expires) || binder == "" ||
		subtle.ConstantTimeCompare([]byte(binder), []byte(pd.binder)) != 1 {
		return nil, ErrState
	}
	if q.Get("error") != "" {
		return nil, ErrDenied
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		return nil, ErrState
	}

	oc, verifier, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	ctx = gooidc.ClientContext(ctx, p.client)
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(pd.verifier))
	if err != nil {
		return nil, fmt.Errorf("%w: code exchange failed", ErrToken)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, fmt.Errorf("%w: no ID token", ErrToken)
	}
	idt, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrToken, err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(pd.nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrToken)
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrToken, err)
	}
	if idt.Subject == "" {
		return nil, fmt.Errorf("%w: no subject", ErrToken)
	}
	return &Identity{
		Issuer:   idt.Issuer,
		Subject:  idt.Subject,
		Username: firstString(claims, p.cfg.UsernameClaim, "email"),
		Groups:   stringList(lookup(claims, p.cfg.GroupsClaim)),
	}, nil
}

// lookup follows a dotted path through nested objects. A claim whose own name
// contains dots wins over the path, as some providers use such names.
func lookup(claims map[string]any, path string) any {
	if v, ok := claims[path]; ok {
		return v
	}
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

func firstString(claims map[string]any, names ...string) string {
	for _, n := range names {
		if s, ok := lookup(claims, n).(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// stringList reads a claim that is an array of strings, or one string.
func stringList(v any) []string {
	switch x := v.(type) {
	case string:
		if x != "" {
			return []string{x}
		}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
