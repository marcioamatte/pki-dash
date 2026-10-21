package service

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	// Test only: cfssl's own CRL generator, to prove we accept what "cfssl gencrl" really writes.
	cfsslcrl "github.com/cloudflare/cfssl/crl"

	"github.com/marcioamatte/pki-dash/internal/ca"
	"github.com/marcioamatte/pki-dash/internal/store"
)

// offlinePKI is a Root made and kept elsewhere, with two intermediates it signed
// and that were imported, so that revoking one of them involves the Root's CRL.
type offlinePKI struct {
	s      *Service
	st     *store.Store
	clk    *clock
	root   *ca.Bundle // the Root's certificate and key, which only the "offline machine" has
	rootID string
	a, b   string // intermediate IDs
	certA  *x509.Certificate
	certB  *x509.Certificate
	rootCA *ca.Authority
}

func newOffline(t *testing.T) *offlinePKI {
	t.Helper()
	s, st, clk := newPKI(t)
	root, err := ca.NewRoot(ca.CARequest{CommonName: "Home Root", Validity: 10 * year, KeyAlgo: ca.ECDSAP384})
	if err != nil {
		t.Fatal(err)
	}
	rootID, err := s.ImportRoot(ctx, "admin", "Home Root", root.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	rootCA, err := ca.Load(root.CertPEM, root.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	p := &offlinePKI{s: s, st: st, clk: clk, root: root, rootID: rootID, rootCA: rootCA}
	for _, name := range []string{"Inter A", "Inter B"} {
		req, err := s.RequestIntermediate(ctx, "admin", rootID, interParams(name))
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.ImportIntermediate(ctx, "admin", req.ID, offlineSign(t, root.CertPEM, root.KeyPEM, req.CSRPEM))
		if err != nil {
			t.Fatal(err)
		}
		c, _ := s.GetCA(ctx, id)
		if name == "Inter A" {
			p.a, p.certA = id, certOf(t, c.CertPEM)
		} else {
			p.b, p.certB = id, certOf(t, c.CertPEM)
		}
	}
	return p
}

// rootCRL is what the offline machine produces: a CRL signed by the Root.
func (p *offlinePKI) rootCRL(t *testing.T, number int64, certs ...*x509.Certificate) []byte {
	t.Helper()
	var entries []ca.Revoked
	for _, c := range certs {
		entries = append(entries, ca.Revoked{Serial: c.SerialNumber, RevokedAt: p.clk.Now(), Reason: ca.ReasonKeyCompromise})
	}
	der, _, _, err := p.rootCA.IssueCRL(entries, number, p.clk.Now(), ca.CRLValidity)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRevokingAnIntermediateStopsItButNotItsSibling(t *testing.T) {
	p := newOffline(t)
	s := p.s
	aLeaf, _ := issueN(t, s, p.a, "a.lab")
	issueN(t, s, p.b, "b.lab")

	if _, err := s.RevokeCA(ctx, "admin", p.a, 99); !errors.Is(err, ca.ErrInvalidRequest) {
		t.Fatalf("bad reason: %v", err)
	}
	if _, err := s.RevokeCA(ctx, "admin", p.rootID, ca.ReasonKeyCompromise); !errors.Is(err, ErrNotIntermediate) {
		t.Fatalf("a Root: %v", err)
	}
	if _, err := s.RevokeCA(ctx, "admin", "ghost", 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	c, err := s.RevokeCA(ctx, "admin", p.a, ca.ReasonCACompromise)
	if err != nil || !c.Revoked() || c.RevocationReason != ca.ReasonCACompromise {
		t.Fatalf("revoke: %+v, %v", c, err)
	}
	if _, err := s.RevokeCA(ctx, "admin", p.a, 1); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("again: %v", err)
	}

	// The revoked CA issues nothing; its sibling carries on.
	if _, err := s.IssueCertificate(ctx, "ops", p.a, leafReq("late.lab")); !errors.Is(err, ErrCARevoked) {
		t.Fatalf("issuing from a revoked CA: %v", err)
	}
	if _, err := s.IssueCertificate(ctx, "ops", p.b, leafReq("fine.lab")); err != nil {
		t.Fatalf("the sibling must still issue: %v", err)
	}

	// Its key signs no more CRLs, but a revocation of its leaf is still recorded.
	before := parseCRL(t, s, p.a).Number.Int64()
	if err := s.RefreshCRLs(ctx, "system", true); err != nil {
		t.Fatal(err)
	}
	if parseCRL(t, s, p.a).Number.Int64() != before {
		t.Fatal("a revoked CA's key must not sign a new CRL")
	}
	res, err := s.RevokeCertificate(ctx, "ops", aLeaf, ca.ReasonKeyCompromise)
	if err != nil || res.Published || !res.Certificate.Revoked() {
		t.Fatalf("revoking a leaf of a revoked CA: %+v, %v", res, err)
	}

	st, _ := s.CRLStatus(ctx)
	byID := map[string]CRLInfo{}
	for _, i := range st {
		byID[i.CAID] = i
	}
	if i := byID[p.a]; !i.CARevoked || i.Stale || i.Expired {
		t.Fatalf("status of the revoked CA = %+v: it is retired, not 'behind'", i)
	}
	if i := byID[p.b]; i.CARevoked {
		t.Fatalf("status of the sibling = %+v", i)
	}
	if i, ok := byID[p.rootID]; !ok || !i.External || i.Kind != "root" || i.Revoked != 1 || i.Published || i.InList != 0 {
		t.Fatalf("the Root must appear, waiting for its CRL: %+v (listed: %v)", i, ok)
	}
}

func TestRootCRLRequest(t *testing.T) {
	p := newOffline(t)
	s := p.s
	if _, err := s.RootCRLRequest(ctx, p.a); !errors.Is(err, ErrNotARoot) {
		t.Fatalf("an intermediate: %v", err)
	}
	req, err := s.RootCRLRequest(ctx, p.rootID)
	if err != nil || len(req.Entries) != 0 || req.NextNumber != 1 || req.Published != nil {
		t.Fatalf("empty request: %+v, %v", req, err)
	}

	s.RevokeCA(ctx, "admin", p.b, ca.ReasonSuperseded)
	p.clk.Add(time.Minute)
	s.RevokeCA(ctx, "admin", p.a, ca.ReasonCACompromise)
	req, _ = s.RootCRLRequest(ctx, p.rootID)
	if len(req.Entries) != 2 || req.Entries[0].ChildID != p.b || req.Entries[1].ChildID != p.a {
		t.Fatalf("entries must be in revocation order: %+v", req.Entries)
	}
	e := req.Entries[1]
	if e.SerialHex != p.certA.SerialNumber.Text(16) || e.SerialDec != p.certA.SerialNumber.String() || e.Reason != ca.ReasonCACompromise {
		t.Fatalf("entry = %+v", e)
	}
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 9, p.certA, p.certB)); err != nil {
		t.Fatal(err)
	}
	req, _ = s.RootCRLRequest(ctx, p.rootID)
	if req.NextNumber != 10 || req.Published == nil || req.Published.Number != 9 {
		t.Fatalf("after importing number 9, the next must be 10: %+v", req)
	}
}

func TestImportRootCRL(t *testing.T) {
	p := newOffline(t)
	s := p.s
	s.RevokeCA(ctx, "admin", p.a, ca.ReasonCACompromise)

	// The happy path, and it is what gets served in the Root's name.
	first := p.rootCRL(t, 1, p.certA)
	imp, err := s.ImportRootCRL(ctx, "admin", p.rootID, first)
	if err != nil || imp.Number != 1 || imp.RevokedCount != 1 {
		t.Fatalf("import: %+v, %v", imp, err)
	}
	pub, err := s.PublicCRL(ctx, p.rootID)
	if err != nil || !pub.Imported {
		t.Fatalf("served: %+v, %v", pub, err)
	}
	crl, _ := x509.ParseRevocationList(pub.DER)
	if err := crl.CheckSignatureFrom(certOf(t, mustCAPEM(t, s, p.rootID))); err != nil {
		t.Fatalf("the served list must verify against the Root: %v", err)
	}
	st, _ := s.CRLStatus(ctx)
	for _, i := range st {
		if i.CAID == p.rootID && (!i.Published || i.InList != 1 || i.Revoked != 1 || i.Stale || i.Expired) {
			t.Fatalf("root status = %+v", i)
		}
	}

	// The same list again, an older one, and one with the same number: none replaces it.
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, first); !errors.Is(err, ErrAlreadyImported) {
		t.Errorf("same list: %v", err)
	}
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 1, p.certA)); !errors.Is(err, ca.ErrCRLNotNewer) {
		t.Errorf("same number: %v", err)
	}
	// A newer one does.
	p.clk.Add(time.Hour)
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 2, p.certA)); err != nil {
		t.Fatalf("a newer list: %v", err)
	}
	// Putting number 1 back (replay of an old list) is refused, and number 2 stays.
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, first); !errors.Is(err, ca.ErrCRLNotNewer) {
		t.Errorf("replaying an old list: %v", err)
	}
	if cur, _ := s.st.GetImportedCRL(ctx, p.rootID); cur.Number != 2 {
		t.Fatalf("published number = %d, want 2", cur.Number)
	}
}

func mustCAPEM(t *testing.T, s *Service, id string) []byte {
	t.Helper()
	c, err := s.GetCA(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return c.CertPEM
}

// "cfssl gencrl" writes base64 of a CRL that has no number, so freshness is judged by date.
func TestImportingACfsslStyleCRL(t *testing.T) {
	p := newOffline(t)
	s := p.s
	s.RevokeCA(ctx, "admin", p.a, ca.ReasonCACompromise)
	cfssl := func() []byte {
		der, err := cfsslcrl.CreateGenericCRL([]pkix.RevokedCertificate{{SerialNumber: p.certA.SerialNumber, RevocationTime: time.Now()}},
			rootSigner(t, p), certOf(t, p.root.CertPEM), time.Now().Add(30*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return []byte(base64.StdEncoding.EncodeToString(der))
	}
	// Move our clock forward so the CRL (stamped with the real "now") is not future-dated.
	p.clk.t = time.Now().UTC().Truncate(time.Second)
	one := cfssl()
	imp, err := s.ImportRootCRL(ctx, "admin", p.rootID, one)
	if err != nil || imp.Number != 0 || imp.RevokedCount != 1 {
		t.Fatalf("cfssl CRL: %+v, %v", imp, err)
	}
	// Importing it again is refused as the same list; a second one in the same second is not newer.
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, one); !errors.Is(err, ErrAlreadyImported) {
		t.Errorf("same cfssl CRL: %v", err)
	}
	req, _ := s.RootCRLRequest(ctx, p.rootID)
	if req.NextNumber != 1 || req.Published == nil {
		t.Fatalf("with no CRL number to follow, the suggestion stays at 1: %+v", req)
	}
}

func rootSigner(t *testing.T, p *offlinePKI) crypto.Signer {
	t.Helper()
	blk, _ := pem.Decode(p.root.KeyPEM)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(crypto.Signer)
}

func TestRootCRLRefusals(t *testing.T) {
	p := newOffline(t)
	s := p.s
	s.RevokeCA(ctx, "admin", p.a, ca.ReasonCACompromise)
	good := p.rootCRL(t, 1, p.certA)
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, good); err != nil {
		t.Fatal(err)
	}
	published := func() int64 { c, _ := s.st.GetImportedCRL(ctx, p.rootID); return c.Number }
	p.clk.Add(time.Hour)

	// It must list every intermediate revoked here...
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 2)); !errors.Is(err, ca.ErrPolicy) || !strings.Contains(err.Error(), "Inter A") {
		t.Errorf("a CRL that omits a revoked intermediate: %v", err)
	}
	// ...and must not revoke one that is in good standing here.
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 2, p.certA, p.certB)); !errors.Is(err, ca.ErrPolicy) || !strings.Contains(err.Error(), "Inter B") {
		t.Errorf("a CRL that lists a CA not revoked here: %v", err)
	}
	// Another Root's list, a stale one and garbage.
	other, _ := ca.NewRoot(ca.CARequest{CommonName: "Other Root", Validity: year, KeyAlgo: ca.ECDSAP256})
	otherCA, _ := ca.Load(other.CertPEM, other.KeyPEM)
	foreign, _, _, _ := otherCA.IssueCRL(nil, 5, p.clk.Now(), ca.CRLValidity)
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, foreign); !errors.Is(err, ca.ErrPolicy) {
		t.Errorf("another Root's CRL: %v", err)
	}
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, []byte("junk")); !errors.Is(err, ca.ErrInvalidRequest) {
		t.Errorf("garbage: %v", err)
	}
	// Only a Root has such a list.
	if _, err := s.ImportRootCRL(ctx, "admin", p.a, good); !errors.Is(err, ErrNotARoot) {
		t.Errorf("an intermediate: %v", err)
	}
	if _, err := s.ImportRootCRL(ctx, "admin", "ghost", good); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	if published() != 1 {
		t.Fatalf("every refusal must leave the published list alone, number = %d", published())
	}
}

// Before clients can follow a pointer to the Root's CRL there must be a list,
// even an empty one.
func TestAnEmptyRootCRLCanBePublished(t *testing.T) {
	p := newOffline(t)
	s := p.s
	st, _ := s.CRLStatus(ctx)
	for _, i := range st {
		if i.CAID == p.rootID {
			t.Fatalf("a Root with nothing to say does not clutter the status: %+v", i)
		}
	}
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 1)); err != nil {
		t.Fatalf("an empty CRL: %v", err)
	}
	st, _ = s.CRLStatus(ctx)
	found := false
	for _, i := range st {
		if i.CAID == p.rootID {
			found = true
			if !i.Published || i.Revoked != 0 || i.InList != 0 || i.Stale {
				t.Fatalf("status = %+v", i)
			}
		}
	}
	if !found {
		t.Fatal("once published, the Root's list is reported")
	}
}

func TestRootCRLAndCARevocationAreAudited(t *testing.T) {
	p := newOffline(t)
	p.s.RevokeCA(ctx, "admin", p.a, ca.ReasonCACompromise)
	p.s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 1, p.certA))
	actions := auditActions(t, p.st)
	for _, want := range []string{"ca.revoke", "crl.import"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit lacks %q: %v", want, actions)
		}
	}
}

func TestDestroyingTheKeyOfARevokedIntermediate(t *testing.T) {
	p := newOffline(t)
	s := p.s

	// A CA in good standing keeps its key: nothing here can destroy it by mistake.
	if err := s.RemoveKey(ctx, "admin", p.a); !errors.Is(err, ErrNotRevoked) {
		t.Fatalf("a CA in good standing: %v", err)
	}
	if err := s.RemoveKey(ctx, "admin", "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}

	// An older Root CRL (empty) is already published; then A is revoked.
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeCA(ctx, "admin", p.a, ca.ReasonCACompromise); err != nil {
		t.Fatal(err)
	}
	// Clients cannot learn of the revocation yet, so the key stays.
	if err := s.RemoveKey(ctx, "admin", p.a); !errors.Is(err, ErrRevocationNotPublished) {
		t.Fatalf("revoked but not published: %v", err)
	}
	if c, _ := s.GetCA(ctx, p.a); c.KeyBlob == nil {
		t.Fatal("the key must still be there after a refusal")
	}

	// Publishing the Root's CRL that lists A opens the way. The sibling is untouched.
	p.clk.Add(time.Minute)
	if _, err := s.ImportRootCRL(ctx, "admin", p.rootID, p.rootCRL(t, 2, p.certA)); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveKey(ctx, "admin", p.a); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if c, _ := s.GetCA(ctx, p.a); c.KeyBlob != nil || !c.Revoked() || len(c.CertPEM) == 0 {
		t.Fatalf("the key is gone, the certificate and the revocation stay: %+v", c)
	}
	if b, _ := s.GetCA(ctx, p.b); b.KeyBlob == nil {
		t.Fatal("the sibling lost its key")
	}
	if _, err := s.IssueCertificate(ctx, "ops", p.b, leafReq("still.lab")); err != nil {
		t.Fatalf("the sibling must still issue: %v", err)
	}
	if _, err := s.IssueCertificate(ctx, "ops", p.a, leafReq("never.lab")); !errors.Is(err, ErrCARevoked) {
		t.Fatalf("a revoked CA without a key issues nothing: %v", err)
	}
	// Doing it again has nothing left to destroy.
	if err := s.RemoveKey(ctx, "admin", p.a); !errors.Is(err, ErrKeyOffline) {
		t.Fatalf("second time: %v", err)
	}
	// The CRL job copes with a keyless, revoked CA.
	if err := s.RefreshCRLs(ctx, "system", true); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	entries, _ := s.Audit(ctx, 20)
	var found bool
	for _, e := range entries {
		if e.Action == "ca.drop_key" && e.Target == p.a && strings.Contains(e.Detail, "number 2") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the destruction must be audited with the CRL that allowed it: %+v", entries)
	}
}

func TestRemoveKeyOnARootKeepsWorking(t *testing.T) {
	s, _, _ := newPKI(t)
	rootID, err := s.CreateRoot(ctx, "admin", caParams("Lab Root", 10*year, ca.ECDSAP256))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveKey(ctx, "admin", rootID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveKey(ctx, "admin", rootID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a Root whose key is already gone: %v", err)
	}
}
