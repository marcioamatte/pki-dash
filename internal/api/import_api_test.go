package api

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
)

// offlineSign signs a CSR with a Root key outside the service, as openssl or
// cfssl would on the machine that keeps the Root.
func offlineSign(t *testing.T, rootCertPEM, rootKeyPEM, csrPEM string) string {
	t.Helper()
	rb, _ := pem.Decode([]byte(rootCertPEM))
	root, err := x509.ParseCertificate(rb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode([]byte(rootKeyPEM))
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode([]byte(csrPEM))
	req, err := x509.ParseCertificateRequest(cb.Bytes)
	if err != nil || req.CheckSignature() != nil {
		t.Fatalf("bad CSR: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, Subject: req.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: root.NotAfter.Add(-time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
		IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}, root, req.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type reqResp struct {
	ID  string `json:"id"`
	CSR string `json:"csr_pem"`
}

func TestOfflineRootWorkflowOverTheAPI(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()

	// A Root made elsewhere: only the public certificate is sent.
	b, err := ca.NewRoot(ca.CARequest{CommonName: "Home Root", Validity: 10 * 365 * 24 * time.Hour, KeyAlgo: ca.ECDSAP384})
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		ID      string `json:"id"`
		Kind    string `json:"kind"`
		KeyHeld bool   `json:"key_held"`
	}
	admin.mustOK("POST", "/api/v1/cas/import-root", m{"name": "Home Root", "certificate_pem": string(b.CertPEM)}, 201).json(t, &root)
	if root.Kind != "root" || root.KeyHeld {
		t.Fatalf("imported root = %+v", root)
	}
	if r := admin.do("POST", "/api/v1/cas/import-root", m{"name": "Again", "certificate_pem": string(b.CertPEM)}); r.status != 409 {
		t.Fatalf("same certificate twice: %d %s", r.status, r.body)
	}

	// A signing request: the CSR comes back once, the key never does.
	var req reqResp
	r := admin.mustOK("POST", "/api/v1/cas/"+root.ID+"/intermediate-requests", m{"name": "Home Services", "organization": "Lab"}, 201)
	r.json(t, &req)
	if !strings.Contains(req.CSR, "CERTIFICATE REQUEST") || strings.Contains(string(r.body), "PRIVATE") {
		t.Fatalf("response: %s", r.body)
	}
	var list []map[string]any
	admin.mustOK("GET", "/api/v1/intermediate-requests", nil, 200).json(t, &list)
	if len(list) != 1 || list[0]["id"] != req.ID {
		t.Fatalf("list = %v", list)
	}
	if _, has := list[0]["csr_pem"]; has {
		t.Fatal("the list must not repeat the CSR")
	}
	dl := admin.mustOK("GET", "/api/v1/intermediate-requests/"+req.ID+"/csr", nil, 200)
	if string(dl.body) != req.CSR || !strings.Contains(dl.header.Get("Content-Disposition"), "home_services.csr") && !strings.Contains(dl.header.Get("Content-Disposition"), "Home_Services.csr") {
		t.Fatalf("CSR download: %q %q", dl.header.Get("Content-Disposition"), dl.body)
	}

	// Refusals leave the request in place.
	if r := admin.do("POST", "/api/v1/intermediate-requests/"+req.ID+"/import", m{"certificate_pem": "nonsense"}); r.status != 400 {
		t.Fatalf("garbage certificate: %d %s", r.status, r.body)
	}
	other, _ := ca.NewRoot(ca.CARequest{CommonName: "Other Root", Validity: 10 * 365 * 24 * time.Hour, KeyAlgo: ca.ECDSAP384})
	foreign := offlineSign(t, string(other.CertPEM), string(other.KeyPEM), req.CSR)
	if r := admin.do("POST", "/api/v1/intermediate-requests/"+req.ID+"/import", m{"certificate_pem": foreign}); r.status != 422 || r.errCode(t) != "policy_violation" {
		t.Fatalf("foreign issuer: %d %s", r.status, r.body)
	}

	// The real thing.
	signed := offlineSign(t, string(b.CertPEM), string(b.KeyPEM), req.CSR)
	var inter struct {
		ID      string `json:"id"`
		Kind    string `json:"kind"`
		KeyHeld bool   `json:"key_held"`
	}
	admin.mustOK("POST", "/api/v1/intermediate-requests/"+req.ID+"/import", m{"certificate_pem": signed}, 201).json(t, &inter)
	if inter.Kind != "intermediate" || !inter.KeyHeld {
		t.Fatalf("intermediate = %+v", inter)
	}
	admin.mustOK("GET", "/api/v1/intermediate-requests", nil, 200).json(t, &list)
	if len(list) != 0 {
		t.Fatalf("the request must be gone: %v", list)
	}

	// It issues certificates that verify against the Root we never held.
	_, certPEM, _, chainPEM := admin.issue(inter.ID, "svc.lab")
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AppendCertsFromPEM(b.CertPEM)
	inters.AppendCertsFromPEM([]byte(chainPEM))
	blk, _ := pem.Decode([]byte(certPEM))
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "svc.lab"}); err != nil {
		t.Fatalf("the certificate does not verify against the external Root: %v", err)
	}

	// Cancelling.
	var req2 reqResp
	admin.mustOK("POST", "/api/v1/cas/"+root.ID+"/intermediate-requests", m{"name": "Throwaway"}, 201).json(t, &req2)
	admin.mustOK("DELETE", "/api/v1/intermediate-requests/"+req2.ID, nil, 204)
	if r := admin.do("DELETE", "/api/v1/intermediate-requests/"+req2.ID, nil); r.status != 404 {
		t.Fatalf("second delete: %d", r.status)
	}
	var actions []struct{ Action string }
	admin.mustOK("GET", "/api/v1/audit?limit=100", nil, 200).json(t, &actions)
	seen := map[string]bool{}
	for _, a := range actions {
		seen[a.Action] = true
	}
	for _, want := range []string{"ca.request_intermediate", "ca.import_intermediate", "ca.request_cancel"} {
		if !seen[want] {
			t.Errorf("audit lacks %q", want)
		}
	}
}

func TestImportEndpointsAreProtected(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	viewer := e.userClient(admin, "view-only", "viewer")
	oper := e.userClient(admin, "oper-user", "operator")
	anon := e.client()
	root := admin.createCA("root", "", "R", 3650)

	calls := []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/cas/import-root", m{"name": "X", "certificate_pem": "x"}},
		{"POST", "/api/v1/cas/" + root + "/intermediate-requests", m{"name": "X"}},
		{"GET", "/api/v1/intermediate-requests", nil},
		{"GET", "/api/v1/intermediate-requests/x/csr", nil},
		{"POST", "/api/v1/intermediate-requests/x/import", m{"certificate_pem": "x"}},
		{"DELETE", "/api/v1/intermediate-requests/x", nil},
	}
	for _, c := range calls {
		if r := anon.do(c.method, c.path, c.body); r.status != 401 {
			t.Errorf("anonymous %s %s: %d", c.method, c.path, r.status)
		}
		for who, cl := range map[string]*client{"viewer": viewer, "operator": oper} {
			if r := cl.do(c.method, c.path, c.body); r.status != 403 {
				t.Errorf("%s %s %s: %d, want 403", who, c.method, c.path, r.status)
			}
		}
	}
	// Changing state needs the CSRF token, DELETE included.
	admin.csrf = ""
	if r := admin.do("DELETE", "/api/v1/intermediate-requests/x", nil); r.status != 403 || r.errCode(t) != "bad_csrf" {
		t.Errorf("DELETE without CSRF: %d %s", r.status, r.body)
	}
}

func TestImportValidation(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	inter := admin.createCA("intermediate", root, "I", 1825)

	for name, c := range map[string]struct {
		path string
		body any
		want int
	}{
		"import-root without a certificate": {"/api/v1/cas/import-root", m{"name": "X", "certificate_pem": ""}, 400},
		"import-root without a name":        {"/api/v1/cas/import-root", m{"name": "", "certificate_pem": "x"}, 400},
		"import-root unknown field":         {"/api/v1/cas/import-root", m{"name": "X", "certificate_pem": "x", "key": "y"}, 400},
		"request under an intermediate":     {"/api/v1/cas/" + inter + "/intermediate-requests", m{"name": "X"}, 422},
		"request under an unknown parent":   {"/api/v1/cas/ghost/intermediate-requests", m{"name": "X"}, 404},
		"request with an empty name":        {"/api/v1/cas/" + root + "/intermediate-requests", m{"name": " "}, 400},
		"request with an unknown algorithm": {"/api/v1/cas/" + root + "/intermediate-requests", m{"name": "X", "key_algo": "dsa-1024"}, 400},
		"import into an unknown request":    {"/api/v1/intermediate-requests/ghost/import", m{"certificate_pem": "x"}, 404},
	} {
		if r := admin.do("POST", c.path, c.body); r.status != c.want {
			t.Errorf("%s: %d, want %d (%s)", name, r.status, c.want, r.body)
		}
	}
	// An intermediate certificate is not a Root.
	var cas []struct{ ID string }
	admin.mustOK("GET", "/api/v1/cas", nil, 200).json(t, &cas)
	pemResp := admin.mustOK("GET", "/api/v1/cas/"+inter+"/cert", nil, 200)
	if r := admin.do("POST", "/api/v1/cas/import-root", m{"name": "Not a root", "certificate_pem": string(pemResp.body)}); r.status != 422 {
		t.Errorf("intermediate as Root: %d %s", r.status, r.body)
	}
}

func TestRequestsNeedAnUnlockedVaultOverTheAPI(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	root := admin.createCA("root", "", "R", 3650)
	admin.mustOK("POST", "/api/v1/vault/lock", nil, 204)
	if r := admin.do("POST", "/api/v1/cas/"+root+"/intermediate-requests", m{"name": "X"}); r.status != 409 || r.errCode(t) != "vault_locked" {
		t.Fatalf("%d %s", r.status, r.body)
	}
}
