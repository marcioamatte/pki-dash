package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/ca"
)

// offlineWorld sets up what the user has: a Root made and kept elsewhere, imported
// by its public certificate, and two intermediates it signed.
type offlineWorld struct {
	root         *ca.Bundle
	rootAuth     *ca.Authority
	rootID       string
	aID, bID     string
	aCert, bCert *x509.Certificate
}

func newOfflineWorld(t *testing.T, admin *client) *offlineWorld {
	t.Helper()
	b, err := ca.NewRoot(ca.CARequest{CommonName: "Home Root", Validity: 10 * 365 * 24 * time.Hour, KeyAlgo: ca.ECDSAP384})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := ca.Load(b.CertPEM, b.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	w := &offlineWorld{root: b, rootAuth: auth}
	var c struct {
		ID string `json:"id"`
	}
	admin.mustOK("POST", "/api/v1/cas/import-root", m{"name": "Home Root", "certificate_pem": string(b.CertPEM)}, 201).json(t, &c)
	w.rootID = c.ID
	for _, name := range []string{"Inter A", "Inter B"} {
		var req reqResp
		admin.mustOK("POST", "/api/v1/cas/"+w.rootID+"/intermediate-requests", m{"name": name}, 201).json(t, &req)
		signed := offlineSign(t, string(b.CertPEM), string(b.KeyPEM), req.CSR)
		admin.mustOK("POST", "/api/v1/intermediate-requests/"+req.ID+"/import", m{"certificate_pem": signed}, 201).json(t, &c)
		blk, _ := pem.Decode([]byte(signed))
		cert, _ := x509.ParseCertificate(blk.Bytes)
		if name == "Inter A" {
			w.aID, w.aCert = c.ID, cert
		} else {
			w.bID, w.bCert = c.ID, cert
		}
	}
	return w
}

func (w *offlineWorld) rootCRL(t *testing.T, number int64, certs ...*x509.Certificate) string {
	t.Helper()
	var entries []ca.Revoked
	for _, c := range certs {
		entries = append(entries, ca.Revoked{Serial: c.SerialNumber, RevokedAt: time.Now(), Reason: ca.ReasonCACompromise})
	}
	der, _, _, err := w.rootAuth.IssueCRL(entries, number, time.Now(), ca.CRLValidity)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

func TestRevokingAnIntermediateAndPublishingTheRootCRL(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	w := newOfflineWorld(t, admin)
	pub := httptest.NewServer(e.api.PublicHandler())
	defer pub.Close()
	admin.issue(w.aID, "a.lab")

	// Revoke Inter A.
	var rev struct {
		RootID string `json:"root_id"`
		Reason string `json:"reason"`
	}
	admin.mustOK("POST", "/api/v1/cas/"+w.aID+"/revoke", m{"reason": "ca_compromise"}, 200).json(t, &rev)
	if rev.RootID != w.rootID || rev.Reason != "ca_compromise" {
		t.Fatalf("response = %+v", rev)
	}
	var cas []struct {
		ID      string `json:"id"`
		Revoked bool   `json:"revoked"`
		Reason  string `json:"revocation_reason"`
	}
	admin.mustOK("GET", "/api/v1/cas", nil, 200).json(t, &cas)
	for _, c := range cas {
		if c.ID == w.aID && (!c.Revoked || c.Reason != "ca_compromise") {
			t.Fatalf("revoked CA = %+v", c)
		}
		if c.ID == w.bID && c.Revoked {
			t.Fatal("the sibling must not be revoked")
		}
	}
	// It issues nothing any more; the sibling does.
	if r := admin.do("POST", "/api/v1/cas/"+w.aID+"/certificates", m{"common_name": "late.lab", "dns_names": []string{"late.lab"}, "validity_days": 30}); r.status != 409 || r.errCode(t) != "ca_revoked" {
		t.Fatalf("issuing from a revoked CA: %d %s", r.status, r.body)
	}
	admin.issue(w.bID, "b.lab")
	if r := admin.do("POST", "/api/v1/cas/"+w.aID+"/revoke", m{"reason": "superseded"}); r.status != 409 || r.errCode(t) != "already_revoked" {
		t.Fatalf("revoking twice: %d %s", r.status, r.body)
	}

	// What the offline machine needs.
	var req struct {
		RootID     string `json:"root_id"`
		NextNumber int64  `json:"next_number"`
		Entries    []struct {
			CAID      string `json:"ca_id"`
			SerialHex string `json:"serial_hex"`
			SerialDec string `json:"serial_dec"`
			Reason    string `json:"reason"`
		} `json:"entries"`
		Published any `json:"published"`
	}
	admin.mustOK("GET", "/api/v1/cas/"+w.rootID+"/crl-request", nil, 200).json(t, &req)
	if len(req.Entries) != 1 || req.Entries[0].CAID != w.aID || req.NextNumber != 1 || req.Published != nil ||
		req.Entries[0].SerialHex != w.aCert.SerialNumber.Text(16) || req.Entries[0].SerialDec != w.aCert.SerialNumber.String() || req.Entries[0].Reason != "ca_compromise" {
		t.Fatalf("request = %+v", req)
	}
	// Status: the Root is waiting for its list.
	var status []struct {
		CAID      string `json:"ca_id"`
		Kind      string `json:"kind"`
		External  bool   `json:"external"`
		Published bool   `json:"published"`
		Stale     bool   `json:"stale"`
		CARevoked bool   `json:"ca_revoked"`
		Revoked   int    `json:"revoked"`
		InList    int    `json:"in_list"`
	}
	admin.mustOK("GET", "/api/v1/crls", nil, 200).json(t, &status)
	var rootStatus, aStatus *struct {
		CAID      string `json:"ca_id"`
		Kind      string `json:"kind"`
		External  bool   `json:"external"`
		Published bool   `json:"published"`
		Stale     bool   `json:"stale"`
		CARevoked bool   `json:"ca_revoked"`
		Revoked   int    `json:"revoked"`
		InList    int    `json:"in_list"`
	}
	for i := range status {
		switch status[i].CAID {
		case w.rootID:
			rootStatus = &status[i]
		case w.aID:
			aStatus = &status[i]
		}
	}
	if rootStatus == nil || !rootStatus.External || rootStatus.Kind != "root" || rootStatus.Published || rootStatus.Revoked != 1 {
		t.Fatalf("root status = %+v", rootStatus)
	}
	if aStatus == nil || !aStatus.CARevoked || aStatus.Stale {
		t.Fatalf("revoked CA status = %+v", aStatus)
	}

	// Refusals, none of which may change anything.
	for name, body := range map[string]string{
		"omits the revoked CA":        w.rootCRL(t, 1),
		"lists a CA in good standing": w.rootCRL(t, 1, w.aCert, w.bCert),
		"garbage":                     "not a crl",
	} {
		if r := admin.do("POST", "/api/v1/cas/"+w.rootID+"/crl/import", m{"crl": body}); r.status != 422 && r.status != 400 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if r := publicGet2(t, pub, "/crl/"+w.rootID+".crl"); r != 404 {
		t.Fatalf("nothing is published for the Root yet, got %d", r)
	}

	// The CRL the Root signed offline goes in, in PEM first.
	var imp struct {
		Number  int64 `json:"number"`
		Revoked int   `json:"revoked"`
	}
	first := w.rootCRL(t, 1, w.aCert)
	admin.mustOK("POST", "/api/v1/cas/"+w.rootID+"/crl/import", m{"crl": first}, 200).json(t, &imp)
	if imp.Number != 1 || imp.Revoked != 1 {
		t.Fatalf("import = %+v", imp)
	}
	res, der := publicGet(t, pub, "GET", "/crl/"+w.rootID+".crl", nil)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/pkix-crl" {
		t.Fatalf("public CRL: %d %v", res.StatusCode, res.Header)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := pem.Decode(w.root.CertPEM)
	rootCert, _ := x509.ParseCertificate(rb.Bytes)
	if err := crl.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("the CRL served for the Root must verify against the Root: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(w.aCert.SerialNumber) != 0 {
		t.Fatalf("served entries = %v", crl.RevokedCertificateEntries)
	}
	admin.mustOK("GET", "/api/v1/crls", nil, 200).json(t, &status)
	for _, st := range status {
		if st.CAID == w.rootID && (!st.Published || st.InList != 1 || st.Stale) {
			t.Fatalf("root status after import = %+v", st)
		}
	}

	// Replays and repeats.
	if r := admin.do("POST", "/api/v1/cas/"+w.rootID+"/crl/import", m{"crl": first}); r.status != 409 || r.errCode(t) != "already_imported" {
		t.Errorf("the same list: %d %s", r.status, r.body)
	}
	if r := admin.do("POST", "/api/v1/cas/"+w.rootID+"/crl/import", m{"crl": w.rootCRL(t, 1, w.aCert)}); r.status != 409 || r.errCode(t) != "crl_not_newer" {
		t.Errorf("same number: %d %s", r.status, r.body)
	}
	// A newer one, this time the way "cfssl gencrl" prints it (base64 of the DER).
	second := w.rootCRL(t, 2, w.aCert)
	blk, _ := pem.Decode([]byte(second))
	admin.mustOK("POST", "/api/v1/cas/"+w.rootID+"/crl/import", m{"crl": base64.StdEncoding.EncodeToString(blk.Bytes)}, 200)
	admin.mustOK("GET", "/api/v1/cas/"+w.rootID+"/crl-request", nil, 200).json(t, &req)
	if req.NextNumber != 3 {
		t.Fatalf("next number = %d, want 3", req.NextNumber)
	}
	// An intermediate has no such list to import.
	if r := admin.do("POST", "/api/v1/cas/"+w.aID+"/crl/import", m{"crl": second}); r.status != 422 {
		t.Errorf("importing into an intermediate: %d %s", r.status, r.body)
	}
	if r := admin.do("GET", "/api/v1/cas/"+w.aID+"/crl-request", nil); r.status != 422 {
		t.Errorf("crl-request of an intermediate: %d", r.status)
	}
}

func publicGet2(t *testing.T, srv *httptest.Server, path string) int {
	res, _ := publicGet(t, srv, "GET", path, nil)
	return res.StatusCode
}

func TestRevokingACAIsForAdminsOnly(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	viewer := e.userClient(admin, "view-only", "viewer")
	oper := e.userClient(admin, "oper-user", "operator")
	w := newOfflineWorld(t, admin)
	crlBody := w.rootCRL(t, 1)

	calls := []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/cas/" + w.bID + "/revoke", m{"reason": "superseded"}},
		{"GET", "/api/v1/cas/" + w.rootID + "/crl-request", nil},
		{"POST", "/api/v1/cas/" + w.rootID + "/crl/import", m{"crl": crlBody}},
	}
	for _, c := range calls {
		if r := e.client().do(c.method, c.path, c.body); r.status != 401 {
			t.Errorf("anonymous %s %s: %d", c.method, c.path, r.status)
		}
		for who, cl := range map[string]*client{"viewer": viewer, "operator": oper} {
			if r := cl.do(c.method, c.path, c.body); r.status != 403 {
				t.Errorf("%s %s %s: %d, want 403", who, c.method, c.path, r.status)
			}
		}
	}
	if r := admin.do("GET", "/api/v1/cas/"+w.bID, nil); r.status != 200 || strings.Contains(string(r.body), `"revoked":true`) {
		t.Fatal("a refused call must not have revoked anything")
	}
	// CSRF as for any change.
	admin.csrf = ""
	if r := admin.do("POST", "/api/v1/cas/"+w.bID+"/revoke", m{"reason": "superseded"}); r.status != 403 || r.errCode(t) != "bad_csrf" {
		t.Errorf("without CSRF: %d %s", r.status, r.body)
	}
}

func TestRevokeCAValidation(t *testing.T) {
	e := newEnv(t, false)
	admin := e.bootstrap()
	w := newOfflineWorld(t, admin)
	for name, c := range map[string]struct {
		id   string
		body any
		want int
	}{
		"a Root cannot be revoked": {w.rootID, m{"reason": "superseded"}, 422},
		"unknown CA":               {"ghost", m{"reason": "superseded"}, 404},
		"no reason":                {w.bID, m{}, 400},
		"certificate hold":         {w.bID, m{"reason": "certificate_hold"}, 400},
		"numeric reason":           {w.bID, m{"reason": 2}, 400},
	} {
		if r := admin.do("POST", "/api/v1/cas/"+c.id+"/revoke", c.body); r.status != c.want {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	// ca_compromise is for CAs only: a service certificate refuses it.
	root := admin.createCA("root", "", "Local Root", 3650)
	inter := admin.createCA("intermediate", root, "Local Inter", 1825)
	id, _, _, _ := admin.issue(inter, "x.lab")
	if r := admin.do("POST", "/api/v1/certificates/"+id+"/revoke", m{"reason": "ca_compromise"}); r.status != 400 {
		t.Errorf("ca_compromise on a service certificate: %d %s", r.status, r.body)
	}
	if c := admin.mustOK("GET", "/api/v1/config", nil, 200); !strings.Contains(string(c.body), "http://pki.test:8080") {
		t.Errorf("config = %s", c.body)
	}
	viewer := e.userClient(admin, "view-only", "viewer")
	viewer.mustOK("GET", "/api/v1/config", nil, 200)
}
