package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func good() oidcFlags {
	return oidcFlags{
		issuer: "https://kc.lab/realms/lab", clientID: "pki-dash", externalURL: "https://pki.lab:8443",
		adminGroups: "pki-admins, /other", viewerGroups: "pki-viewers", name: "Keycloak",
	}
}

func TestOIDCFlagsOffByDefault(t *testing.T) {
	p, roles, err := (&oidcFlags{}).build()
	if err != nil || p != nil || roles.Enabled() {
		t.Fatalf("%v %v %v", p, roles, err)
	}
}

func TestOIDCFlagsGoodConfig(t *testing.T) {
	o := good()
	p, roles, err := o.build()
	if err != nil || p == nil {
		t.Fatal(err)
	}
	if len(roles.Admin) != 2 || roles.Admin[1] != "/other" || len(roles.Viewer) != 1 {
		t.Fatalf("%+v", roles)
	}
}

func TestOIDCFlagsHalfConfiguredIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		mod  func(*oidcFlags)
		want string
	}{
		"settings without an issuer": {func(o *oidcFlags) { o.issuer = "" }, "-oidc-issuer is missing"},
		"no client id":               {func(o *oidcFlags) { o.clientID = "" }, "-oidc-client-id"},
		"no external url":            {func(o *oidcFlags) { o.externalURL = "" }, "-external-url"},
		"nobody could sign in":       {func(o *oidcFlags) { o.adminGroups, o.viewerGroups = "", "" }, "nobody could sign in"},
		"default role admin":         {func(o *oidcFlags) { o.defaultRole = "admin" }, "default role"},
		"external url with a path":   {func(o *oidcFlags) { o.externalURL = "https://pki.lab/app" }, "scheme and host"},
		"plain http issuer":          {func(o *oidcFlags) { o.issuer = "http://kc.lab/realms/lab" }, "https"},
		"missing secret file":        {func(o *oidcFlags) { o.secretFile = "/nonexistent/secret" }, "client secret"},
		"missing ca file":            {func(o *oidcFlags) { o.caFile = "/nonexistent/ca.pem" }, "oidc-ca-file"},
	} {
		o := good()
		tc.mod(&o)
		if _, _, err := o.build(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error mentioning %q", name, err, tc.want)
		}
	}
}

func TestOIDCFlagsRejectACAFileWithoutCertificates(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(f, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := good()
	o.caFile = f
	if _, _, err := o.build(); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatalf("got %v", err)
	}
}

func TestOIDCFlagsReadTheSecretFromAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(f, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := good()
	o.secretFile = f
	if _, _, err := o.build(); err != nil {
		t.Fatal(err)
	}
}

func TestEnvBool(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "true": true, "TRUE": true, " yes ": true, "on": true, "": false, "0": false, "false": false, "no": false, "maybe": false} {
		t.Setenv("PKI_DASH_TEST_BOOL", v)
		if got := envBool("PKI_DASH_TEST_BOOL"); got != want {
			t.Errorf("%q: got %v", v, got)
		}
	}
}
