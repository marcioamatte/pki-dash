package auth

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/store"
)

func setupSSO(t *testing.T, m RoleMap) (*Auth, *store.Store, *clock) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "pki.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clk := &clock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	st.SetClock(clk.Now)
	a, err := New(st, Options{Now: clk.Now, Password: fast, ExternalRoles: m})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Setup(ctx, "root-admin", adminPW); err != nil {
		t.Fatal(err)
	}
	return a, st, clk
}

var roles = RoleMap{Admin: []string{"pki-admins"}, Operator: []string{"/pki-operators"}, Viewer: []string{"pki-viewers"}}

func ident(sub, name string, groups ...string) ExternalIdentity {
	return ExternalIdentity{Issuer: "https://kc.lab/realms/lab", Subject: sub, Username: name, Groups: groups}
}

func TestRoleMapResolve(t *testing.T) {
	m := RoleMap{Admin: []string{"Admins"}, Operator: []string{"ops"}, Viewer: []string{"/view"}}
	for _, c := range []struct {
		groups []string
		role   string
		ok     bool
	}{
		{[]string{"admins"}, "admin", true},
		{[]string{"/Admins"}, "admin", true}, // Keycloak full path, any case
		{[]string{"view", "ops"}, "operator", true},
		{[]string{"view", "ops", "admins"}, "admin", true}, // the highest wins
		{[]string{"view"}, "viewer", true},
		{[]string{"staff"}, "", false},
		{nil, "", false},
		{[]string{"administrators", "admins-old"}, "", false}, // no prefix matching
	} {
		role, ok := m.Resolve(c.groups)
		if role != c.role || ok != c.ok {
			t.Errorf("%v: got %q %v", c.groups, role, ok)
		}
	}
	m.Default = "viewer"
	if role, ok := m.Resolve([]string{"staff"}); role != "viewer" || !ok {
		t.Errorf("default role: %q %v", role, ok)
	}
	if (RoleMap{Default: "admin"}).Validate() == nil || (RoleMap{Default: "root"}).Validate() == nil {
		t.Error("a default of admin (or nonsense) must be refused")
	}
	if (RoleMap{}).Enabled() || !m.Enabled() {
		t.Error("Enabled")
	}
}

func TestExternalLoginProvisionsAndSetsTheRole(t *testing.T) {
	a, st, _ := setupSSO(t, roles)
	s, err := a.LoginExternal(ctx, ident("sub-1", "ana.souza", "pki-operators"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Role != "operator" || s.Username != "ana.souza" || s.Token == "" || s.CSRF == "" {
		t.Fatalf("%+v", s)
	}
	u, err := st.GetUserByUsername(ctx, "ana.souza")
	if err != nil || u.AuthSource != store.SourceOIDC || u.PasswordHash != "" || u.ExternalID != "https://kc.lab/realms/lab#sub-1" {
		t.Fatalf("%v %+v", err, u)
	}
	if got, err := a.Validate(ctx, s.Token); err != nil || got.Role != "operator" {
		t.Fatalf("the session must work: %v %+v", err, got)
	}
	// Same person again: the same account, not a second one.
	if _, err := a.LoginExternal(ctx, ident("sub-1", "ana.souza", "pki-operators")); err != nil {
		t.Fatal(err)
	}
	if us, _ := st.ListUsers(ctx); len(us) != 2 {
		t.Fatalf("want admin + ana, got %d users", len(us))
	}
}

func TestExternalLoginWithoutAMappedGroupGrantsNothingAndCreatesNothing(t *testing.T) {
	a, st, _ := setupSSO(t, roles)
	if _, err := a.LoginExternal(ctx, ident("sub-2", "bob", "everyone", "staff")); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("got %v", err)
	}
	if _, err := st.GetUserByUsername(ctx, "bob"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a person with no access must not be provisioned: %v", err)
	}
	if _, err := a.LoginExternal(ctx, ExternalIdentity{Username: "x", Groups: []string{"pki-admins"}}); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("an identity without issuer/subject must be refused: %v", err)
	}
}

func TestExternalRoleFollowsTheProviderAtEachLogin(t *testing.T) {
	a, _, _ := setupSSO(t, roles)
	s1, err := a.LoginExternal(ctx, ident("sub-3", "carla", "pki-admins"))
	if err != nil || s1.Role != "admin" {
		t.Fatal(err, s1)
	}
	s2, err := a.LoginExternal(ctx, ident("sub-3", "carla", "pki-viewers"))
	if err != nil || s2.Role != "viewer" {
		t.Fatal(err, s2)
	}
	if _, err := a.Validate(ctx, s1.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("the session of the old role must have ended: %v", err)
	}
	if _, err := a.LoginExternal(ctx, ident("sub-3", "carla", "nothing")); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("removed from every group = locked out at the next login: %v", err)
	}
}

func TestExternalLoginCannotTakeOverAnExistingAccount(t *testing.T) {
	a, st, _ := setupSSO(t, roles)
	// The provider claims to be "root-admin", the local admin's name.
	s, err := a.LoginExternal(ctx, ident("sub-4", "root-admin", "pki-admins"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Username == "root-admin" || !strings.HasPrefix(s.Username, "root-admin-") {
		t.Fatalf("the newcomer must get a different name, got %q", s.Username)
	}
	local, _ := st.GetUserByUsername(ctx, "root-admin")
	if local.AuthSource != store.SourceLocal || local.ExternalID != "" {
		t.Fatalf("the local account was touched: %+v", local)
	}
	// A different issuer with the same subject is a different person.
	other := ExternalIdentity{Issuer: "https://other.lab", Subject: "sub-4", Username: "root-admin", Groups: []string{"pki-admins"}}
	s2, err := a.LoginExternal(ctx, other)
	if err != nil || s2.UserID == s.UserID {
		t.Fatalf("%v %+v", err, s2)
	}
}

func TestExternalUsernamesAreSanitised(t *testing.T) {
	for in, want := range map[string]string{
		"ana souza":               "ana_souza",
		"  Ana/../Souza  ":        "Ana_.._Souza",
		"x":                       "", // too short: replaced by sso-<hash>
		"":                        "",
		"a'; DROP TABLE users;--": "a_DROP_TABLE_users_--",
		strings.Repeat("a", 100):  strings.Repeat("a", 59),
	} {
		got := accountName(in, "iss#sub")
		if want == "" {
			want = "sso-" + shortHash("iss#sub")
		}
		if got != want || checkUsername(got) != nil {
			t.Errorf("%q -> %q (want %q)", in, got, want)
		}
	}
}

func TestExternalUsersAreManagedByTheProvider(t *testing.T) {
	a, st, _ := setupSSO(t, roles)
	if _, err := a.LoginExternal(ctx, ident("sub-5", "dora", "pki-viewers")); err != nil {
		t.Fatal(err)
	}
	admin := login(t, a, "root-admin", adminPW)
	dora, _ := st.GetUserByUsername(ctx, "dora")
	if err := a.SetRole(ctx, admin, dora.ID, "admin"); !errors.Is(err, ErrExternalUser) {
		t.Fatalf("role of an SSO user must come from the provider: %v", err)
	}
	if err := a.ResetPassword(ctx, admin, dora.ID, "a brand new long password"); !errors.Is(err, ErrExternalUser) {
		t.Fatalf("an SSO user has no password: %v", err)
	}
	// ...but an admin can still block them here.
	if err := a.SetDisabled(ctx, admin, dora.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LoginExternal(ctx, ident("sub-5", "dora", "pki-viewers")); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("a disabled SSO user must stay out: %v", err)
	}
	// And the password form never lets an SSO account in.
	if _, err := a.Login(ctx, "dora", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
}

func TestExternalDemotionCannotRemoveTheLastAdmin(t *testing.T) {
	a, st, _ := setupSSO(t, roles)
	if _, err := a.LoginExternal(ctx, ident("sub-6", "eli", "pki-admins")); err != nil {
		t.Fatal(err)
	}
	local, _ := st.GetUserByUsername(ctx, "root-admin")
	admin := login(t, a, "root-admin", adminPW)
	eli, _ := st.GetUserByUsername(ctx, "eli")
	if err := a.SetDisabled(ctx, admin, local.ID, true); err != nil { // eli is now the only admin
		t.Fatal(err)
	}
	if _, err := a.LoginExternal(ctx, ident("sub-6", "eli", "pki-viewers")); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("demoting the last admin must be refused: %v", err)
	}
	if u, _ := st.GetUser(ctx, eli.ID); u.Role != "admin" {
		t.Fatalf("role changed anyway: %s", u.Role)
	}
}
