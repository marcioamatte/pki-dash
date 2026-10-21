package oidc

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/oidc/oidctest"
)

func newProvider(t *testing.T, f *oidctest.IdP, mod func(*Config)) *Provider {
	t.Helper()
	cfg := Config{Issuer: f.URL(), ClientID: oidctest.ClientID, ClientSecret: f.Secret, RedirectURL: "http://127.0.0.1:9/api/v1/auth/oidc/callback"}
	if mod != nil {
		mod(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoginHappyPath(t *testing.T) {
	f := oidctest.New(t)
	p := newProvider(t, f, nil)
	authURL, binder, err := p.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(authURL)
	v := q.Query()
	if v.Get("code_challenge_method") != "S256" || v.Get("code_challenge") == "" || v.Get("nonce") == "" || v.Get("state") == "" {
		t.Fatalf("the redirect lacks PKCE, nonce or state: %s", authURL)
	}
	id, err := p.Complete(context.Background(), f.Browse(authURL), binder)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "user-1" || id.Username != "ana.souza" || id.Issuer != f.URL() {
		t.Fatalf("identity: %+v", id)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "/pki-admins" {
		t.Fatalf("groups: %v", id.Groups)
	}
}

func TestGroupsFromANestedClaim(t *testing.T) {
	f := oidctest.New(t)
	p := newProvider(t, f, func(c *Config) { c.GroupsClaim = "realm_access.roles" })
	authURL, binder, _ := p.Begin(context.Background())
	id, err := p.Complete(context.Background(), f.Browse(authURL), binder)
	if err != nil || len(id.Groups) != 1 || id.Groups[0] != "pki-operator" {
		t.Fatalf("%v %+v", err, id)
	}
}

func TestStateIsSingleUseAndBoundToTheBrowser(t *testing.T) {
	f := oidctest.New(t)
	p := newProvider(t, f, nil)

	authURL, binder, _ := p.Begin(context.Background())
	q := f.Browse(authURL)
	if _, err := p.Complete(context.Background(), q, "someone-elses-cookie"); !errors.Is(err, ErrState) {
		t.Fatalf("another browser must be refused, got %v", err)
	}
	// The failed attempt used the state up: even the right browser cannot retry it.
	if _, err := p.Complete(context.Background(), q, binder); !errors.Is(err, ErrState) {
		t.Fatalf("a state must work once, got %v", err)
	}

	authURL, binder, _ = p.Begin(context.Background())
	q = f.Browse(authURL)
	if _, err := p.Complete(context.Background(), q, binder); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Complete(context.Background(), q, binder); !errors.Is(err, ErrState) {
		t.Fatalf("a replay must be refused, got %v", err)
	}

	for _, bad := range []url.Values{{}, {"state": {"nope"}, "code": {"x"}}} {
		if _, err := p.Complete(context.Background(), bad, binder); !errors.Is(err, ErrState) {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	if _, err := p.Complete(context.Background(), f.Browse(authURL), ""); !errors.Is(err, ErrState) {
		t.Fatalf("no cookie must be refused, got %v", err)
	}
}

func TestStatesExpire(t *testing.T) {
	f := oidctest.New(t)
	now := time.Now()
	p := newProvider(t, f, func(c *Config) { c.Now = func() time.Time { return now } })
	authURL, binder, _ := p.Begin(context.Background())
	q := f.Browse(authURL)
	now = now.Add(stateTTL + time.Second)
	if _, err := p.Complete(context.Background(), q, binder); !errors.Is(err, ErrState) {
		t.Fatalf("an expired login must be refused, got %v", err)
	}
}

func TestPendingLoginsAreBounded(t *testing.T) {
	f := oidctest.New(t)
	p := newProvider(t, f, nil)
	for i := 0; i < maxPending; i++ {
		if _, _, err := p.Begin(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := p.Begin(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v", err)
	}
}

func TestProviderRefusalAndBadTokens(t *testing.T) {
	f := oidctest.New(t)
	p := newProvider(t, f, nil)
	ctx := context.Background()

	authURL, binder, _ := p.Begin(ctx)
	st, _ := url.Parse(authURL)
	if _, err := p.Complete(ctx, url.Values{"state": {st.Query().Get("state")}, "error": {"access_denied"}}, binder); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}

	cases := map[string]func(f *oidctest.IdP){
		"wrong audience": func(f *oidctest.IdP) { f.Tweak(func(c map[string]any) { c["aud"] = "someone-else" }) },
		"wrong issuer":   func(f *oidctest.IdP) { f.Tweak(func(c map[string]any) { c["iss"] = "https://evil.example" }) },
		"expired": func(f *oidctest.IdP) {
			f.Tweak(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
		},
		"wrong nonce":     func(f *oidctest.IdP) { f.Tweak(func(c map[string]any) { c["nonce"] = "replayed" }) },
		"no subject":      func(f *oidctest.IdP) { f.Tweak(func(c map[string]any) { delete(c, "sub") }) },
		"unpublished key": func(f *oidctest.IdP) { f.SignWithUnpublishedKey(true) },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			f.Tweak(nil)
			f.SignWithUnpublishedKey(false)
			mod(f)
			authURL, binder, _ := p.Begin(ctx)
			if _, err := p.Complete(ctx, f.Browse(authURL), binder); !errors.Is(err, ErrToken) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestWrongClientSecretIsRefusedByTheProvider(t *testing.T) {
	f := oidctest.New(t)
	p := newProvider(t, f, func(c *Config) { c.ClientSecret = "wrong" })
	authURL, binder, _ := p.Begin(context.Background())
	if _, err := p.Complete(context.Background(), f.Browse(authURL), binder); !errors.Is(err, ErrToken) {
		t.Fatalf("got %v", err)
	}
}

func TestUnavailableProviderIsRetried(t *testing.T) {
	f := oidctest.New(t)
	issuer := f.URL()
	f.Close()
	p := newProvider(t, f, func(c *Config) { c.Issuer = issuer })
	if _, _, err := p.Begin(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestConfigRejectsUnsafeURLs(t *testing.T) {
	good := Config{Issuer: "https://kc.lab/realms/x", ClientID: "c", RedirectURL: "https://pki.lab/api/v1/auth/oidc/callback"}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"plain http issuer":   func(c *Config) { c.Issuer = "http://kc.lab/realms/x" },
		"plain http redirect": func(c *Config) { c.RedirectURL = "http://pki.lab/cb" },
		"no scheme":           func(c *Config) { c.Issuer = "kc.lab" },
		"credentials in url":  func(c *Config) { c.Issuer = "https://u:p@kc.lab" },
		"fragment":            func(c *Config) { c.Issuer = "https://kc.lab/#x" },
		"javascript":          func(c *Config) { c.Issuer = "javascript:alert(1)" },
		"no client id":        func(c *Config) { c.ClientID = " " },
	} {
		c := good
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	local := good
	local.Issuer, local.RedirectURL = "http://localhost:8080/realms/x", "http://127.0.0.1:8443/cb"
	if _, err := New(local); err != nil {
		t.Errorf("loopback http should be allowed: %v", err)
	}
}

func TestClaimHelpers(t *testing.T) {
	c := map[string]any{"a": map[string]any{"b": []any{"x", 1, "y", ""}}, "dotted.name": "z", "s": "one", "e": "  "}
	if got := stringList(lookup(c, "a.b")); strings.Join(got, ",") != "x,y" {
		t.Fatal(got)
	}
	if got := stringList(lookup(c, "s")); len(got) != 1 || got[0] != "one" {
		t.Fatal(got)
	}
	if lookup(c, "dotted.name") != "z" || lookup(c, "a.zzz") != nil || lookup(c, "s.x") != nil {
		t.Fatal("lookup")
	}
	if firstString(c, "e", "s") != "one" {
		t.Fatal("firstString")
	}
	if stringList(42) != nil || stringList(nil) != nil {
		t.Fatal("non-lists must be empty")
	}
}
