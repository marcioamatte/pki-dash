package api

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// publicGet fetches from the public listener, with no cookies and no client state.
func publicGet(t *testing.T, srv *httptest.Server, method, path string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

type revokeResp struct {
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason"`
	Published bool   `json:"crl_published"`
}

func TestRevokeOverTheAPI(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)
	idA, certA, _, _ := admin.issue(inter, "a.lab")
	idB, certB, _, _ := admin.issue(inter, "b.lab")

	var out revokeResp
	admin.mustOK("POST", "/api/v1/certificates/"+idA+"/revoke", m{"reason": "key_compromise"}, 200).json(t, &out)
	if out.Reason != "key_compromise" || !out.Published || out.RevokedAt == "" {
		t.Fatalf("response = %+v", out)
	}

	// The certificate list shows who is revoked and why.
	var list []struct {
		ID      string `json:"id"`
		Revoked bool   `json:"revoked"`
		Reason  string `json:"revocation_reason"`
		At      string `json:"revoked_at"`
	}
	admin.mustOK("GET", "/api/v1/certificates", nil, 200).json(t, &list)
	state := map[string]bool{}
	for _, c := range list {
		state[c.ID] = c.Revoked
		if c.ID == idA && (c.Reason != "key_compromise" || c.At == "") {
			t.Errorf("revoked entry = %+v", c)
		}
		if c.ID == idB && (c.Reason != "" || c.At != "") {
			t.Errorf("valid entry must carry no revocation data: %+v", c)
		}
	}
	if !state[idA] || state[idB] {
		t.Fatalf("revoked flags = %v", state)
	}

	// Refusals.
	for name, c := range map[string]struct {
		id   string
		body any
		want int
		code string
	}{
		"again":          {idA, m{"reason": "superseded"}, 409, "already_revoked"},
		"unknown":        {"ghost", m{"reason": "superseded"}, 404, "not_found"},
		"no reason":      {idB, m{}, 400, "bad_request"},
		"bad reason":     {idB, m{"reason": "certificate_hold"}, 400, "bad_request"},
		"numeric reason": {idB, m{"reason": 1}, 400, "bad_request"},
		"unknown field":  {idB, m{"reason": "superseded", "force": true}, 400, "bad_request"},
	} {
		r := admin.do("POST", "/api/v1/certificates/"+c.id+"/revoke", c.body)
		if r.status != c.want || r.errCode(t) != c.code {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	// A rejected request must not have revoked anything.
	admin.mustOK("GET", "/api/v1/certificates", nil, 200).json(t, &list)
	for _, c := range list {
		if c.ID == idB && c.Revoked {
			t.Fatal("a refused revocation revoked the certificate anyway")
		}
	}

	// The CRL download is a verifiable PEM that names exactly the revoked serial.
	dl := admin.mustOK("GET", "/api/v1/cas/"+inter+"/crl", nil, 200)
	blk, _ := pem.Decode(dl.body)
	if blk == nil || blk.Type != "X509 CRL" {
		t.Fatalf("not a CRL PEM: %.80s", dl.body)
	}
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ib, _ := pem.Decode(admin.mustOK("GET", "/api/v1/cas/"+inter+"/cert", nil, 200).body)
	issuer, _ := x509.ParseCertificate(ib.Bytes)
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("CRL does not verify: %v", err)
	}
	ba, _ := pem.Decode([]byte(certA))
	ca, _ := x509.ParseCertificate(ba.Bytes)
	bb, _ := pem.Decode([]byte(certB))
	cb, _ := x509.ParseCertificate(bb.Bytes)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(ca.SerialNumber) != 0 ||
		crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cb.SerialNumber) == 0 {
		t.Fatalf("CRL entries = %v", crl.RevokedCertificateEntries)
	}

	var status []struct {
		CAID    string `json:"ca_id"`
		Revoked int    `json:"revoked"`
		InList  int    `json:"in_list"`
		Stale   bool   `json:"stale"`
		Expired bool   `json:"expired"`
		Number  int64  `json:"number"`
	}
	admin.mustOK("GET", "/api/v1/crls", nil, 200).json(t, &status)
	if len(status) != 1 || status[0].CAID != inter || status[0].Revoked != 1 || status[0].InList != 1 || status[0].Stale || status[0].Expired || status[0].Number < 2 {
		t.Fatalf("status = %+v", status)
	}
	admin.mustOK("POST", "/api/v1/crls/refresh", nil, 204)
	var after []struct{ Number int64 }
	admin.mustOK("GET", "/api/v1/crls", nil, 200).json(t, &after)
	if after[0].Number <= status[0].Number {
		t.Fatal("a refresh must publish a new, higher-numbered CRL")
	}
}

func TestRevokeAuthorization(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	viewer := e.userClient(admin, "view-only", "viewer")
	oper := e.userClient(admin, "oper-user", "operator")
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)
	id, _, _, _ := admin.issue(inter, "a.lab")
	id2, _, _, _ := admin.issue(inter, "b.lab")

	if r := viewer.do("POST", "/api/v1/certificates/"+id+"/revoke", m{"reason": "superseded"}); r.status != 403 {
		t.Errorf("viewer revoking: %d", r.status)
	}
	if r := viewer.do("POST", "/api/v1/crls/refresh", nil); r.status != 403 {
		t.Errorf("viewer refreshing CRLs: %d", r.status)
	}
	// Viewers may read the revocation state.
	viewer.mustOK("GET", "/api/v1/crls", nil, 200)
	viewer.mustOK("GET", "/api/v1/cas/"+inter+"/crl", nil, 200)
	// An operator, who can issue, can also revoke.
	oper.mustOK("POST", "/api/v1/certificates/"+id+"/revoke", m{"reason": "superseded"}, 200)
	// CSRF applies as to any state change.
	admin.csrf = ""
	if r := admin.do("POST", "/api/v1/certificates/"+id2+"/revoke", m{"reason": "superseded"}); r.status != 403 || r.errCode(t) != "bad_csrf" {
		t.Errorf("without CSRF: %d %s", r.status, r.body)
	}
}

func TestRevokingWhileTheVaultIsLocked(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)
	id, cert, _, _ := admin.issue(inter, "a.lab")
	pub := httptest.NewServer(e.api.PublicHandler())
	defer pub.Close()

	admin.mustOK("POST", "/api/v1/vault/lock", nil, 204)
	var out revokeResp
	admin.mustOK("POST", "/api/v1/certificates/"+id+"/revoke", m{"reason": "key_compromise"}, 200).json(t, &out)
	if out.Published {
		t.Fatal("with the vault locked the CRL cannot be signed yet")
	}
	var status []struct {
		Stale bool `json:"stale"`
	}
	admin.mustOK("GET", "/api/v1/crls", nil, 200).json(t, &status)
	if !status[0].Stale {
		t.Fatal("the dashboard must flag the CRL as behind")
	}
	if r := admin.do("POST", "/api/v1/crls/refresh", nil); r.status != 409 || r.errCode(t) != "vault_locked" {
		t.Fatalf("refresh while locked: %d %s", r.status, r.body)
	}
	_, der := publicGet(t, pub, "GET", "/crl/"+inter+".crl", nil)
	if crl, err := x509.ParseRevocationList(der); err != nil || len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("clients still see the old list: %v", err)
	}

	admin.mustOK("POST", "/api/v1/vault/unlock", m{"master_passphrase": masterPW}, 204)
	_, der = publicGet(t, pub, "GET", "/crl/"+inter+".crl", nil)
	crl, err := x509.ParseRevocationList(der)
	if err != nil || len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("after unlocking, clients must see the revocation: %v", err)
	}
	blk, _ := pem.Decode([]byte(cert))
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("wrong serial in the CRL")
	}
}

func TestPublicListener(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)
	noCRL := admin.createCA("intermediate", root, "I2", 1825)
	id, _, _, _ := admin.issue(inter, "a.lab")
	admin.mustOK("POST", "/api/v1/certificates/"+id+"/revoke", m{"reason": "superseded"}, 200)
	pub := httptest.NewServer(e.api.PublicHandler())
	defer pub.Close()

	// The CRL: DER, the right type, cacheable, and conditional requests answered with 304.
	res, der := publicGet(t, pub, "GET", "/crl/"+inter+".crl", nil)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/pkix-crl" ||
		!strings.Contains(res.Header.Get("Cache-Control"), "public") || res.Header.Get("ETag") == "" {
		t.Fatalf("CRL response: %d %v", res.StatusCode, res.Header)
	}
	if crl, err := x509.ParseRevocationList(der); err != nil || len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL body: %v", err)
	}
	if r2, body := publicGet(t, pub, "GET", "/crl/"+inter+".crl", map[string]string{"If-None-Match": res.Header.Get("ETag")}); r2.StatusCode != 304 || len(body) != 0 {
		t.Fatalf("conditional GET: %d, %d bytes", r2.StatusCode, len(body))
	}
	if r2, body := publicGet(t, pub, "HEAD", "/crl/"+inter+".crl", nil); r2.StatusCode != 200 || len(body) != 0 {
		t.Fatalf("HEAD: %d, %d bytes", r2.StatusCode, len(body))
	}

	// The CA certificate, where issued certificates point.
	res, body := publicGet(t, pub, "GET", "/ca/"+inter+".crt", nil)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/pkix-cert" {
		t.Fatalf("CA cert: %d %v", res.StatusCode, res.Header)
	}
	if c, err := x509.ParseCertificate(body); err != nil || !c.IsCA {
		t.Fatalf("CA cert body: %v", err)
	}

	// Everything the listener does not serve is not there.
	missing := []string{
		"/crl/" + strings.Repeat("0", 32) + ".crl", // no such CA
		"/crl/" + noCRL + ".crl",                   // CA exists, nothing published yet
		"/crl/" + inter + ".crt",                   // wrong extension for the route
		"/ca/" + inter + ".crl",
		"/crl/" + strings.ToUpper(inter) + ".crl",
		"/crl/../api/v1/status", "/crl/%2e%2e/api/v1/status", "/crl/" + inter, "/crl/", "/ca/", "/",
		"/api/v1/status", "/api/v1/cas", "/index.html", "/favicon.svg", "/assets/x.js",
	}
	for _, p := range missing {
		if res, _ := publicGet(t, pub, "GET", p, nil); res.StatusCode != 404 {
			t.Errorf("GET %s: %d, want 404", p, res.StatusCode)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if res, _ := publicGet(t, pub, m, "/crl/"+inter+".crl", nil); res.StatusCode != 405 || res.Header.Get("Allow") == "" {
			t.Errorf("%s: %d", m, res.StatusCode)
		}
	}
	// No cookies, nothing a browser could keep, and the usual hardening.
	res, _ = publicGet(t, pub, "GET", "/crl/"+inter+".crl", nil)
	if len(res.Header.Values("Set-Cookie")) != 0 || res.Header.Get("X-Content-Type-Options") != "nosniff" ||
		res.Header.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Fatalf("headers: %v", res.Header)
	}
}

func TestPublicListenerIsRateLimited(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)
	admin.issue(inter, "a.lab")
	e.api.public = newLimiter(1.0/60, 5, time.Now)
	pub := httptest.NewServer(e.api.PublicHandler())
	defer pub.Close()
	limited := 0
	for range 12 {
		if res, _ := publicGet(t, pub, "GET", "/crl/"+inter+".crl", nil); res.StatusCode == 429 {
			limited++
		}
	}
	if limited < 5 {
		t.Fatalf("only %d of 12 rapid requests were limited", limited)
	}
}
