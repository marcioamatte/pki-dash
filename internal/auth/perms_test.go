package auth

import (
	"testing"

	"github.com/marcioamatte/pki-dash/internal/store"
)

func TestPermissionMatrix(t *testing.T) {
	all := []Permission{PermViewCAs, PermViewCerts, PermIssueCert, PermCreateIntermediate, PermCreateRoot,
		PermExportCAKey, PermRemoveRootKey, PermManageVault, PermManageUsers, PermViewAudit}
	want := map[string]map[Permission]bool{
		store.RoleViewer:   {PermViewCAs: true, PermViewCerts: true},
		store.RoleOperator: {PermViewCAs: true, PermViewCerts: true, PermIssueCert: true},
	}
	for _, p := range all {
		if !Can(store.RoleAdmin, p) {
			t.Errorf("admin lacks %s", p)
		}
		for _, role := range []string{store.RoleViewer, store.RoleOperator} {
			if Can(role, p) != want[role][p] {
				t.Errorf("%s / %s = %v, want %v", role, p, Can(role, p), want[role][p])
			}
		}
		if Can("", p) || Can("superuser", p) {
			t.Errorf("an unknown role must hold nothing (%s)", p)
		}
	}
	// The operator list must not alias the viewer list.
	if Can(store.RoleViewer, PermIssueCert) {
		t.Fatal("viewer gained cert.issue through slice aliasing")
	}
}

func TestAuthorize(t *testing.T) {
	if err := Authorize(nil, PermViewCAs); err != ErrForbidden {
		t.Fatalf("nil session: %v", err)
	}
	if err := Authorize(&Session{Role: store.RoleViewer}, PermIssueCert); err != ErrForbidden {
		t.Fatalf("viewer: %v", err)
	}
	if err := Authorize(&Session{Role: store.RoleOperator}, PermIssueCert); err != nil {
		t.Fatalf("operator: %v", err)
	}
}
