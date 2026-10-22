package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func status(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/status" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(code)
	})
}

func hostport(url string) string {
	return strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
}

func TestProbe(t *testing.T) {
	tlsOK := httptest.NewTLSServer(status(200))
	defer tlsOK.Close()
	plainOK := httptest.NewServer(status(200))
	defer plainOK.Close()
	broken := httptest.NewServer(status(500))
	defer broken.Close()
	redirecting := httptest.NewServer(http.RedirectHandler("http://evil.example/", http.StatusFound))
	defer redirecting.Close()

	if err := probe(hostport(tlsOK.URL)); err != nil {
		t.Errorf("TLS server (self-signed certificate): %v", err)
	}
	if err := probe(hostport(plainOK.URL)); err != nil {
		t.Errorf("plain HTTP server: %v", err)
	}
	if err := probe(hostport(broken.URL)); err == nil {
		t.Error("a 500 must be unhealthy")
	}
	if err := probe(hostport(redirecting.URL)); err == nil {
		t.Error("a redirect must not count as healthy")
	}
	if err := probe("127.0.0.1:1"); err == nil {
		t.Error("nothing listening must be unhealthy")
	}
	if err := probe("not an address"); err == nil {
		t.Error("a malformed address must be an error")
	}
}

func TestProbeWildcardAddressUsesLoopback(t *testing.T) {
	srv := httptest.NewServer(status(200))
	defer srv.Close()
	port := hostport(srv.URL)[strings.LastIndex(hostport(srv.URL), ":")+1:]
	for _, listen := range []string{"0.0.0.0:" + port, ":" + port} {
		if err := probe(listen); err != nil {
			t.Errorf("%s: %v", listen, err)
		}
	}
}

func TestCheckServingMode(t *testing.T) {
	for name, tc := range map[string]struct {
		cert, key         string
		self, plain       bool
		wantErr, mentions []string
	}{
		"certificate only":   {cert: "c", key: "k"},
		"self-signed only":   {self: true},
		"plain only":         {plain: true},
		"none":               {wantErr: []string{"none of the ways"}},
		"certificate + self": {cert: "c", key: "k", self: true, wantErr: []string{"2 ways", "-tls-cert/-tls-key", "-tls-self-signed", "PKI_DASH_TLS_SELF_SIGNED"}},
		"self + plain":       {self: true, plain: true, wantErr: []string{"2 ways", "-tls-self-signed", "-insecure-http"}},
		"all three":          {cert: "c", key: "k", self: true, plain: true, wantErr: []string{"3 ways", "-tls-cert/-tls-key", "-tls-self-signed", "-insecure-http"}},
		"only a cert path":   {cert: "c"},
	} {
		err := checkServingMode(tc.cert, tc.key, tc.self, tc.plain)
		if len(tc.wantErr) == 0 {
			if err != nil {
				t.Errorf("%s: unexpected error %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		for _, w := range tc.wantErr {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q does not mention %q", name, err, w)
			}
		}
	}
}

func TestRunRefusesTwoWaysOfServingFromTheEnvironment(t *testing.T) {
	// The situation of a settings file with the certificate lines and the
	// self-signed line all switched on.
	t.Setenv("PKI_DASH_TLS_CERT", "/etc/pki-dash/tls.crt")
	t.Setenv("PKI_DASH_TLS_KEY", "/etc/pki-dash/tls.key")
	t.Setenv("PKI_DASH_TLS_SELF_SIGNED", "true")
	err := run(context.Background(), []string{"-data-dir", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "2 ways of serving are set at once") {
		t.Fatalf("got %v", err)
	}
}
