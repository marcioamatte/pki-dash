package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func srvWith(t *testing.T, list string) *Server {
	t.Helper()
	p, err := ParseTrustedProxies(list)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{proxies: p}
}

func req(remote string, hdr ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	return r
}

func TestParseTrustedProxies(t *testing.T) {
	ps, err := ParseTrustedProxies(" 10.0.0.5 , 172.18.0.0/16,fd00::/8, ::ffff:192.168.1.1 ,,")
	if err != nil || len(ps) != 4 {
		t.Fatalf("%v %v", ps, err)
	}
	want := []string{"10.0.0.5/32", "172.18.0.0/16", "fd00::/8", "192.168.1.1/32"}
	for i, p := range ps {
		if p.String() != want[i] {
			t.Errorf("%d: got %s, want %s", i, p, want[i])
		}
	}
	if ps, err := ParseTrustedProxies(""); err != nil || len(ps) != 0 {
		t.Fatalf("empty list must mean no proxy: %v %v", ps, err)
	}
	// 10.1.2.3/8 means the whole 10/8, normalised.
	if ps, _ := ParseTrustedProxies("10.1.2.3/8"); ps[0].String() != "10.0.0.0/8" {
		t.Errorf("not masked: %s", ps[0])
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "::ffff:0:0/80", "10.0.0.0/33", "proxy.lab", "10.0.0", "10.0.0.1/", "1.2.3.4;5.6.7.8"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestClientIP(t *testing.T) {
	s := srvWith(t, "10.0.0.5,172.18.0.0/16")
	for _, c := range []struct {
		name string
		r    *http.Request
		want string
	}{
		{"direct connection", req("203.0.113.9:5000"), "203.0.113.9"},
		{"a client forging the header on a direct connection is ignored", req("203.0.113.9:5000", "X-Forwarded-For", "1.1.1.1"), "203.0.113.9"},
		{"trusted proxy without the header", req("10.0.0.5:4000"), "10.0.0.5"},
		{"trusted proxy: the client", req("10.0.0.5:4000", "X-Forwarded-For", "198.51.100.7"), "198.51.100.7"},
		{"the client's own forged entry is ignored", req("10.0.0.5:4000", "X-Forwarded-For", "1.1.1.1, 198.51.100.7"), "198.51.100.7"},
		{"two proxies in the chain", req("10.0.0.5:4000", "X-Forwarded-For", "198.51.100.7, 172.18.0.3"), "198.51.100.7"},
		{"header split across lines", req("10.0.0.5:4000", "X-Forwarded-For", "9.9.9.9", "X-Forwarded-For", "198.51.100.7"), "198.51.100.7"},
		{"every hop trusted: the leftmost", req("10.0.0.5:4000", "X-Forwarded-For", "172.18.0.9, 172.18.0.3"), "172.18.0.9"},
		{"a port on the entry", req("10.0.0.5:4000", "X-Forwarded-For", "198.51.100.7:51234"), "198.51.100.7"},
		{"IPv6", req("10.0.0.5:4000", "X-Forwarded-For", "2001:db8::7"), "2001:db8::7"},
		{"IPv6 in brackets with a port", req("10.0.0.5:4000", "X-Forwarded-For", "[2001:db8::7]:443"), "2001:db8::7"},
		{"garbage stops the walk at the last believable address", req("10.0.0.5:4000", "X-Forwarded-For", "evil, 198.51.100.7, not-an-ip"), "10.0.0.5"},
		{"garbage left of a good entry is never reached", req("10.0.0.5:4000", "X-Forwarded-For", "evil, 198.51.100.7"), "198.51.100.7"},
		{"IPv4-mapped peer is still the proxy", req("[::ffff:10.0.0.5]:4000", "X-Forwarded-For", "198.51.100.7"), "198.51.100.7"},
		{"empty header", req("10.0.0.5:4000", "X-Forwarded-For", ""), "10.0.0.5"},
	} {
		if got := s.clientIP(c.r); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}

	none := srvWith(t, "")
	if got := none.clientIP(req("10.0.0.5:4000", "X-Forwarded-For", "198.51.100.7")); got != "10.0.0.5" {
		t.Errorf("without trusted proxies every header is ignored, got %q", got)
	}
}

func TestRequestHostAndForwardedProto(t *testing.T) {
	s := srvWith(t, "10.0.0.5")
	s.secure = true
	r := req("10.0.0.5:4000", "X-Forwarded-Host", "pki.lab:8443, other")
	if s.requestHost(r) != "pki.lab:8443" {
		t.Errorf("trusted proxy host: %q", s.requestHost(r))
	}
	r = req("203.0.113.9:4000", "X-Forwarded-Host", "pki.lab")
	r.Host = "real.example"
	if s.requestHost(r) != "real.example" {
		t.Errorf("a forged forwarded host from anywhere else must be ignored: %q", s.requestHost(r))
	}
	r = req("10.0.0.5:4000", "X-Forwarded-Host", "evil.example/x y")
	r.Host = "inner"
	if s.requestHost(r) != "inner" {
		t.Errorf("a malformed forwarded host must be ignored: %q", s.requestHost(r))
	}

	if !s.forwardedPlain(req("10.0.0.5:4000", "X-Forwarded-Proto", "http")) {
		t.Error("a proxy forwarding plain http must be caught")
	}
	for _, ok := range []*http.Request{
		req("10.0.0.5:4000", "X-Forwarded-Proto", "https"),
		req("10.0.0.5:4000", "X-Forwarded-Proto", "HTTPS"),
		req("10.0.0.5:4000"), // the proxy host's own health check
		req("203.0.113.9:4000", "X-Forwarded-Proto", "http"), // not a proxy: header ignored
	} {
		if s.forwardedPlain(ok) {
			t.Errorf("wrongly refused %v", ok.Header)
		}
	}
	s.secure = false
	if s.forwardedPlain(req("10.0.0.5:4000", "X-Forwarded-Proto", "http")) {
		t.Error("with plain-http mode there is nothing to refuse")
	}
}

func TestRateLimitIsPerRealClientBehindAProxy(t *testing.T) {
	prefix, _ := ParseTrustedProxies("127.0.0.0/8")
	e := newEnv(t, true, func(o *Options) { o.TrustedProxies = prefix })
	e.api.strict = newLimiter(1.0/60, 3, e.api.strict.now) // 3 attempts, then wait

	post := func(ip string) int {
		r, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/login", strings.NewReader(`{"username":"x","password":"y"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", ip)
		r.Header.Set("X-Forwarded-Proto", "https")
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	for i := 0; i < 3; i++ {
		if post("198.51.100.1") == 429 {
			t.Fatalf("attempt %d limited too early", i)
		}
	}
	if post("198.51.100.1") != 429 {
		t.Fatal("the 4th attempt of the same client must be limited")
	}
	if post("198.51.100.2") == 429 {
		t.Fatal("another client behind the same proxy must have its own allowance")
	}
	// Forging more entries on the left does not buy a fresh allowance.
	if post("1.2.3.4, 198.51.100.1") != 429 {
		t.Fatal("a client cannot dodge the limit by prefixing the header")
	}
}

func TestDirectClientsCannotUseForwardedHeadersToDodgeTheLimit(t *testing.T) {
	e := newEnv(t, false) // no trusted proxies
	e.api.strict = newLimiter(1.0/60, 2, e.api.strict.now)
	post := func(ip string) int {
		r, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/login", strings.NewReader(`{"username":"x","password":"y"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", ip)
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	post("1.1.1.1")
	post("2.2.2.2")
	if post("3.3.3.3") != 429 {
		t.Fatal("with no trusted proxy, a new forwarded address must not give a new allowance")
	}
}

func TestCrossOriginCheckUsesTheBrowsersHostBehindAProxy(t *testing.T) {
	prefix, _ := ParseTrustedProxies("127.0.0.0/8")
	e := newEnv(t, true, func(o *Options) { o.TrustedProxies = prefix })
	login := func(origin, xfh string) int {
		r, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/login", strings.NewReader(`{"username":"x","password":"y"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Forwarded-Proto", "https")
		if xfh != "" {
			r.Header.Set("X-Forwarded-Host", xfh)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if got := login("https://pki.lab:8443", "pki.lab:8443"); got == 403 {
		t.Fatalf("the browser's own origin must pass behind a proxy that rewrites Host: %d", got)
	}
	if got := login("https://evil.example", "pki.lab:8443"); got != 403 {
		t.Fatalf("a foreign origin must still be refused: %d", got)
	}
}

func TestPlainHTTPFromAProxyIsRefusedWithAnExplanation(t *testing.T) {
	prefix, _ := ParseTrustedProxies("127.0.0.0/8")
	e := newEnv(t, true, func(o *Options) { o.TrustedProxies = prefix })
	r, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/status", nil)
	r.Header.Set("X-Forwarded-Proto", "http")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("status %d", res.StatusCode)
	}
	r2, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/status", nil)
	r2.Header.Set("X-Forwarded-Proto", "https")
	res2, err := http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != 200 {
		t.Fatalf("https forwarded must work: %d", res2.StatusCode)
	}
}
