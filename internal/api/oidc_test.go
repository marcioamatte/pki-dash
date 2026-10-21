package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/oidc"
	"github.com/marcioamatte/pki-dash/internal/oidc/oidctest"
)

const cb = "/api/v1/auth/oidc/callback"

func ssoEnv(t *testing.T, secure bool) (*env, *oidctest.IdP) {
	t.Helper()
	idp := oidctest.New(t)
	p, err := oidc.New(oidc.Config{
		Issuer: idp.URL(), ClientID: oidctest.ClientID, ClientSecret: idp.Secret,
		RedirectURL: "http://127.0.0.1:1" + cb,
	})
	if err != nil {
		t.Fatal(err)
	}
	roles := auth.RoleMap{Admin: []string{"pki-admins"}, Operator: []string{"pki-operators"}}
	e := newEnvAuth(t, secure, auth.Options{ExternalRoles: roles}, func(o *Options) { o.OIDC, o.OIDCName = p, "Keycloak" })
	return e, idp
}

// startLogin follows /auth/oidc/login and returns the callback query the provider would send.
func startLogin(t *testing.T, c *client, idp *oidctest.IdP) url.Values {
	t.Helper()
	r := c.do("GET", "/api/v1/auth/oidc/login", nil)
	if r.status != http.StatusFound {
		t.Fatalf("login = %d: %s", r.status, r.body)
	}
	return idp.Browse(r.header.Get("Location"))
}

func location(r resp) string { return r.header.Get("Location") }

func TestOIDCStatusAnd404WhenOff(t *testing.T) {
	e, _ := ssoEnv(t, false)
	var st map[string]any
	e.client().mustOK("GET", "/api/v1/status", nil, 200).json(t, &st)
	if o, _ := st["oidc"].(map[string]any); o["name"] != "Keycloak" {
		t.Fatalf("status: %v", st)
	}

	off := newEnv(t, false)
	var st2 map[string]any
	off.client().mustOK("GET", "/api/v1/status", nil, 200).json(t, &st2)
	if _, has := st2["oidc"]; has {
		t.Fatalf("SSO must not be advertised when it is off: %v", st2)
	}
	for _, p := range []string{"/api/v1/auth/oidc/login", cb} {
		if r := off.client().do("GET", p, nil); r.status != 404 {
			t.Errorf("%s = %d, want 404", p, r.status)
		}
	}
}

func TestOIDCFullLogin(t *testing.T) {
	e, idp := ssoEnv(t, false)
	e.bootstrap()
	c := e.client()

	r := c.do("GET", "/api/v1/auth/oidc/login", nil)
	if r.status != 302 || !strings.HasPrefix(location(r), idp.URL()+"/auth") {
		t.Fatalf("login must redirect to the provider: %d %q", r.status, location(r))
	}
	ck := r.header.Get("Set-Cookie")
	if !strings.Contains(ck, "pki_oidc=") || !strings.Contains(ck, "HttpOnly") || !strings.Contains(ck, "SameSite=Lax") {
		t.Fatalf("the binding cookie is wrong: %q", ck)
	}
	q := idp.Browse(location(r))

	cbr := c.do("GET", cb+"?"+q.Encode(), nil)
	if cbr.status != 302 || location(cbr) != "/" {
		t.Fatalf("callback = %d %q: %s", cbr.status, location(cbr), cbr.body)
	}
	var me struct{ Username, Role string }
	c.mustOK("GET", "/api/v1/me", nil, 200).json(t, &me)
	if me.Username != "ana.souza" || me.Role != "admin" {
		t.Fatalf("me: %+v", me)
	}

	// The session works like any other, including the CSRF rule.
	if r := c.do("POST", "/api/v1/vault/lock", nil); r.status != 403 || r.errCode(t) != "bad_csrf" {
		t.Fatalf("a state-changing call without CSRF must be refused: %d %s", r.status, r.body)
	}
	// Replaying the callback fails and leaves the session alone.
	again := c.do("GET", cb+"?"+q.Encode(), nil)
	if !strings.HasPrefix(location(again), "/?sso_error=state") {
		t.Fatalf("replay: %q", location(again))
	}
}

func TestOIDCRefusals(t *testing.T) {
	e, idp := ssoEnv(t, false)
	e.bootstrap()

	t.Run("no access: not in any mapped group", func(t *testing.T) {
		idp.Tweak(func(c map[string]any) { c["groups"] = []string{"staff"} })
		defer idp.Tweak(nil)
		c := e.client()
		q := startLogin(t, c, idp)
		r := c.do("GET", cb+"?"+q.Encode(), nil)
		if location(r) != "/?sso_error=no_access" || strings.Contains(strings.Join(r.header.Values("Set-Cookie"), ";"), "pki_session=") {
			t.Fatalf("%d %q %v", r.status, location(r), r.header["Set-Cookie"])
		}
		if c.do("GET", "/api/v1/me", nil).status != 401 {
			t.Fatal("no session must exist")
		}
	})

	t.Run("callback without the cookie of the browser that started it", func(t *testing.T) {
		starter, attacker := e.client(), e.client()
		q := startLogin(t, starter, idp)
		r := attacker.do("GET", cb+"?"+q.Encode(), nil)
		if location(r) != "/?sso_error=state" {
			t.Fatalf("%q", location(r))
		}
		if attacker.do("GET", "/api/v1/me", nil).status != 401 {
			t.Fatal("login CSRF: the attacker's browser got a session")
		}
	})

	t.Run("the provider says no", func(t *testing.T) {
		c := e.client()
		q := startLogin(t, c, idp)
		r := c.do("GET", cb+"?state="+url.QueryEscape(q.Get("state"))+"&error=access_denied&error_description=%3Cscript%3E", nil)
		if location(r) != "/?sso_error=denied" {
			t.Fatalf("%q", location(r))
		}
		if strings.Contains(location(r), "script") {
			t.Fatal("provider text must never be reflected")
		}
	})

	t.Run("a forged token", func(t *testing.T) {
		idp.SignWithUnpublishedKey(true)
		defer idp.SignWithUnpublishedKey(false)
		c := e.client()
		q := startLogin(t, c, idp)
		if r := c.do("GET", cb+"?"+q.Encode(), nil); location(r) != "/?sso_error=token" {
			t.Fatalf("%q", location(r))
		}
	})

	t.Run("garbage", func(t *testing.T) {
		for _, qs := range []string{"", "?code=x", "?state=x&code=y", "?state=" + strings.Repeat("a", 5000)} {
			if r := e.client().do("GET", cb+qs, nil); location(r) != "/?sso_error=state" {
				t.Errorf("%q -> %q", qs, location(r))
			}
		}
	})
}

func TestOIDCAccountsAreManagedByTheProvider(t *testing.T) {
	e, idp := ssoEnv(t, false)
	admin := e.bootstrap()
	c := e.client()
	if r := c.do("GET", cb+"?"+startLogin(t, c, idp).Encode(), nil); location(r) != "/" {
		t.Fatalf("%q", location(r))
	}
	var users []struct {
		ID         string `json:"id"`
		Username   string `json:"username"`
		AuthSource string `json:"auth_source"`
	}
	admin.mustOK("GET", "/api/v1/users", nil, 200).json(t, &users)
	var id string
	for _, u := range users {
		if u.Username == "ana.souza" {
			if u.AuthSource != "oidc" {
				t.Fatalf("source: %q", u.AuthSource)
			}
			id = u.ID
		}
	}
	if id == "" {
		t.Fatal("the SSO user is not listed")
	}
	if r := admin.do("PATCH", "/api/v1/users/"+id, m{"role": "viewer"}); r.status != 409 || r.errCode(t) != "external_user" {
		t.Fatalf("role change: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/users/"+id+"/password", m{"new_password": "a brand new long password"}); r.status != 409 || r.errCode(t) != "external_user" {
		t.Fatalf("password reset: %d %s", r.status, r.body)
	}
	// Disabling is allowed and ends the SSO user's session at once.
	admin.mustOK("PATCH", "/api/v1/users/"+id, m{"disabled": true}, 204)
	if c.do("GET", "/api/v1/me", nil).status != 401 {
		t.Fatal("a disabled SSO user must lose the session")
	}
}

func TestOIDCSecureCookiesUseTheHostPrefix(t *testing.T) {
	e, _ := ssoEnv(t, true)
	r := e.client().do("GET", "/api/v1/auth/oidc/login", nil)
	if ck := r.header.Get("Set-Cookie"); !strings.HasPrefix(ck, "__Host-pki_oidc=") || !strings.Contains(ck, "Secure") {
		t.Fatalf("%q", ck)
	}
}
