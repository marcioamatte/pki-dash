package main

import (
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
