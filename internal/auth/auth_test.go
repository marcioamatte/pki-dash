package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marcioamatte/pki-dash/internal/store"
)

var ctx = context.Background()

const (
	adminPW = "lantern kettle orchid 123"
	userPW  = "river stone velvet 456"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func setup(t *testing.T) (*Auth, *store.Store, *clock) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "pki.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clk := &clock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	st.SetClock(clk.Now)
	a, err := New(st, Options{Now: clk.Now, Password: fast})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Setup(ctx, "root-admin", adminPW); err != nil {
		t.Fatal(err)
	}
	return a, st, clk
}

func login(t *testing.T, a *Auth, user, pw string) *Session {
	t.Helper()
	s, err := a.Login(ctx, user, pw)
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	return s
}

// addUser creates a user through an admin session and returns their ID.
func addUser(t *testing.T, a *Auth, admin *Session, name, pw, role string) string {
	t.Helper()
	id, err := a.CreateUser(ctx, admin, name, pw, role)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSetup(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "pki.db"))
	defer st.Close()
	a, _ := New(st, Options{Password: fast})
	if need, _ := a.NeedsSetup(ctx); !need {
		t.Fatal("fresh store needs setup")
	}
	for name, c := range map[string][2]string{
		"short password":        {"admin", "short"},
		"bad username":          {"a b", adminPW},
		"password has username": {"administrator", "my administrator pw"},
	} {
		if err := a.Setup(ctx, c[0], c[1]); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := a.Setup(ctx, "admin", adminPW); err != nil {
		t.Fatal(err)
	}
	if err := a.Setup(ctx, "other", adminPW+"x"); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("second setup: err = %v, want ErrSetupDone", err)
	}
	if need, _ := a.NeedsSetup(ctx); need {
		t.Fatal("setup is done")
	}
	if u, _ := st.GetUserByUsername(ctx, "ADMIN"); u.Role != store.RoleAdmin {
		t.Fatalf("username lookup must be case-insensitive and role admin: %+v", u)
	}
}

func TestConcurrentSetupHasOneWinner(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "pki.db"))
	defer st.Close()
	a, _ := New(st, Options{Password: fast})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := "admin" + string(rune('a'+i)) + "xx"
			if err := a.Setup(ctx, name, adminPW); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, ErrSetupDone) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d setups succeeded, want exactly 1", wins)
	}
}

func TestLoginAndSession(t *testing.T) {
	a, st, _ := setup(t)
	s := login(t, a, "root-admin", adminPW)
	if s.Token == "" || s.CSRF == "" || s.Role != store.RoleAdmin {
		t.Fatalf("session = %+v", s)
	}
	v, err := a.Validate(ctx, s.Token)
	if err != nil || v.Username != "root-admin" || v.Token != "" || v.CSRF != s.CSRF {
		t.Fatalf("Validate = %+v, %v", v, err)
	}
	// The raw token is not what is stored: only its hash is.
	if _, err := st.GetSession(ctx, []byte(s.Token)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the session must not be findable by the raw token")
	}
	if _, err := a.Validate(ctx, s.Token+"x"); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("tampered token: %v", err)
	}
	if _, err := a.Validate(ctx, ""); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("empty token: %v", err)
	}
	if err := a.Logout(ctx, s.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Validate(ctx, s.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatal("a logged-out session must be dead")
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	a, _, _ := setup(t)
	admin := login(t, a, "root-admin", adminPW)
	id := addUser(t, a, admin, "disabled-user", userPW, store.RoleViewer)
	if err := a.SetDisabled(ctx, admin, id, true); err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"unknown user":   {"nobody", userPW},
		"wrong password": {"root-admin", "not the password!!"},
		"disabled user":  {"disabled-user", userPW}, // correct password, still refused
		"empty":          {"", ""},
		"oversized":      {"root-admin", strings.Repeat("x", 5000)},
	}
	for name, c := range cases {
		s, err := a.Login(ctx, c[0], c[1])
		if s != nil || err != ErrInvalidCredentials {
			t.Errorf("%s: session=%v err=%v, want ErrInvalidCredentials", name, s, err)
		}
	}
}

func TestLockout(t *testing.T) {
	a, st, clk := setup(t)
	for range 5 {
		if _, err := a.Login(ctx, "root-admin", "wrong wrong wrong"); err != ErrInvalidCredentials {
			t.Fatal(err)
		}
	}
	// Locked: even the right password is refused.
	if _, err := a.Login(ctx, "root-admin", adminPW); err != ErrInvalidCredentials {
		t.Fatalf("locked account accepted the right password: %v", err)
	}
	clk.Advance(14 * time.Minute)
	if _, err := a.Login(ctx, "root-admin", adminPW); err != ErrInvalidCredentials {
		t.Fatal("lock must hold for the full period")
	}
	clk.Advance(2 * time.Minute)
	login(t, a, "root-admin", adminPW) // lock over

	// Success resets the counter: four failures after it do not lock.
	for range 4 {
		a.Login(ctx, "root-admin", "wrong wrong wrong")
	}
	login(t, a, "root-admin", adminPW)

	es, _ := st.Audit(ctx, 500)
	locked := 0
	for _, e := range es {
		if e.Action == "user.locked" {
			locked++
		}
	}
	if locked != 1 {
		t.Fatalf("lock events = %d, want 1", locked)
	}
}

func TestSessionTimeouts(t *testing.T) {
	a, _, clk := setup(t)

	// Idle timeout: activity keeps a session alive, silence ends it.
	s := login(t, a, "root-admin", adminPW)
	for range 3 {
		clk.Advance(20 * time.Minute)
		if _, err := a.Validate(ctx, s.Token); err != nil {
			t.Fatalf("active session expired: %v", err)
		}
	}
	clk.Advance(31 * time.Minute)
	if _, err := a.Validate(ctx, s.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatal("idle session must expire")
	}

	// Absolute lifetime: constant activity still ends at 12h.
	s = login(t, a, "root-admin", adminPW)
	var last error
	for range 40 {
		clk.Advance(20 * time.Minute)
		_, last = a.Validate(ctx, s.Token)
		if last != nil {
			break
		}
	}
	if !errors.Is(last, ErrInvalidSession) {
		t.Fatal("a session must not outlive its absolute lifetime")
	}
}

func TestPurgeExpired(t *testing.T) {
	a, _, clk := setup(t)
	login(t, a, "root-admin", adminPW)
	clk.Advance(time.Hour)
	live := login(t, a, "root-admin", adminPW)
	n, err := a.PurgeExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("purged %d, %v; want 1", n, err)
	}
	if _, err := a.Validate(ctx, live.Token); err != nil {
		t.Fatalf("live session purged: %v", err)
	}
}

func TestSessionsRevokedOnAccountChanges(t *testing.T) {
	a, _, _ := setup(t)
	admin := login(t, a, "root-admin", adminPW)
	id := addUser(t, a, admin, "oper", userPW, store.RoleOperator)

	changes := map[string]func(){
		"role change":    func() { a.SetRole(ctx, admin, id, store.RoleViewer) },
		"disable":        func() { a.SetDisabled(ctx, admin, id, true) },
		"password reset": func() { a.ResetPassword(ctx, admin, id, "brand new password 789") },
	}
	for name, change := range changes {
		a.SetDisabled(ctx, admin, id, false)
		s := login(t, a, "oper", currentPW(name))
		if _, err := a.Validate(ctx, s.Token); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		change()
		if _, err := a.Validate(ctx, s.Token); !errors.Is(err, ErrInvalidSession) {
			t.Errorf("%s: the old session must be revoked", name)
		}
		// Restore a known state for the next case.
		a.ResetPassword(ctx, admin, id, userPW)
		a.SetRole(ctx, admin, id, store.RoleOperator)
	}
}

func currentPW(string) string { return userPW }

func TestChangeOwnPassword(t *testing.T) {
	a, _, _ := setup(t)
	admin := login(t, a, "root-admin", adminPW)
	id := addUser(t, a, admin, "oper", userPW, store.RoleOperator)
	_ = id
	s := login(t, a, "oper", userPW)

	if err := a.ChangeOwnPassword(ctx, s, "wrong current pw", "a new passphrase 000"); err != ErrInvalidCredentials {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := a.ChangeOwnPassword(ctx, s, userPW, "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak new password: %v", err)
	}
	if err := a.ChangeOwnPassword(ctx, s, userPW, "a new passphrase 000"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Validate(ctx, s.Token); !errors.Is(err, ErrInvalidSession) {
		t.Fatal("changing the password must end every session")
	}
	if _, err := a.Login(ctx, "oper", userPW); err != ErrInvalidCredentials {
		t.Fatal("old password must stop working")
	}
	login(t, a, "oper", "a new passphrase 000")
}

func TestLastAdminIsProtected(t *testing.T) {
	a, _, _ := setup(t)
	admin := login(t, a, "root-admin", adminPW)
	if err := a.SetRole(ctx, admin, admin.UserID, store.RoleViewer); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := a.SetDisabled(ctx, admin, admin.UserID, true); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("disable last admin: %v", err)
	}
	second := addUser(t, a, admin, "second-admin", userPW, store.RoleAdmin)
	if err := a.SetRole(ctx, admin, second, store.RoleViewer); err != nil {
		t.Fatalf("demoting one of two admins must work: %v", err)
	}
	// Back to a single admin: protected again.
	if err := a.SetDisabled(ctx, admin, admin.UserID, true); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("disable last admin (after demotion): %v", err)
	}
}

func TestAuthorizationOnManagement(t *testing.T) {
	a, _, _ := setup(t)
	admin := login(t, a, "root-admin", adminPW)
	addUser(t, a, admin, "oper", userPW, store.RoleOperator)
	oper := login(t, a, "oper", userPW)

	if _, err := a.CreateUser(ctx, oper, "x-user", userPW, store.RoleViewer); err != ErrForbidden {
		t.Errorf("operator CreateUser: %v", err)
	}
	if err := a.SetRole(ctx, oper, oper.UserID, store.RoleAdmin); err != ErrForbidden {
		t.Errorf("operator self-promotion: %v", err)
	}
	if err := a.SetDisabled(ctx, oper, admin.UserID, true); err != ErrForbidden {
		t.Errorf("operator SetDisabled: %v", err)
	}
	if err := a.ResetPassword(ctx, oper, admin.UserID, "takeover password 1"); err != ErrForbidden {
		t.Errorf("operator ResetPassword: %v", err)
	}
	if _, err := a.ListUsers(ctx, oper); err != ErrForbidden {
		t.Errorf("operator ListUsers: %v", err)
	}
	if _, err := a.CreateUser(ctx, nil, "x-user", userPW, store.RoleViewer); err != ErrForbidden {
		t.Errorf("anonymous CreateUser: %v", err)
	}
	if _, err := a.CreateUser(ctx, admin, "x-user", userPW, "superuser"); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("invalid role: %v", err)
	}
	if _, err := a.CreateUser(ctx, admin, "oper", userPW, store.RoleViewer); !errors.Is(err, store.ErrExists) {
		t.Errorf("duplicate username (case-insensitive): %v", err)
	}
	if _, err := a.CreateUser(ctx, admin, "OPER", userPW, store.RoleViewer); !errors.Is(err, store.ErrExists) {
		t.Errorf("duplicate username differing in case: %v", err)
	}
	us, err := a.ListUsers(ctx, admin)
	if err != nil || len(us) != 2 {
		t.Fatalf("ListUsers = %v, %v", us, err)
	}
	for _, u := range us {
		if u.PasswordHash != "" {
			t.Fatal("ListUsers must not expose password hashes")
		}
	}
}

func TestRehashOnLogin(t *testing.T) {
	a, st, clk := setup(t) // fast params
	stronger := PasswordParams{Time: 3, Memory: 32 * 1024, Threads: 1}
	b, _ := New(st, Options{Now: clk.Now, Password: stronger})
	before, _ := st.GetUserByUsername(ctx, "root-admin")
	login(t, b, "root-admin", adminPW)
	after, _ := st.GetUserByUsername(ctx, "root-admin")
	if before.PasswordHash == after.PasswordHash || !strings.Contains(after.PasswordHash, "m=32768,t=3,p=1") {
		t.Fatalf("hash was not upgraded: %s", after.PasswordHash)
	}
	login(t, a, "root-admin", adminPW) // still verifies
}

func TestAuditTrailHasNoSecrets(t *testing.T) {
	a, st, _ := setup(t)
	admin := login(t, a, "root-admin", adminPW)
	addUser(t, a, admin, "oper", userPW, store.RoleOperator)
	a.Login(ctx, "nobody", "guess number one!!")
	a.Login(ctx, "oper", "guess number two!!")
	a.Logout(ctx, admin.Token)

	if err := st.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	es, _ := st.Audit(ctx, 500)
	seen := map[string]bool{}
	for _, e := range es {
		seen[e.Action] = true
		line := e.Actor + e.Action + e.Target + e.Detail
		for _, secret := range []string{adminPW, userPW, "guess number", "$argon2", admin.Token, admin.CSRF} {
			if strings.Contains(line, secret) {
				t.Fatalf("audit entry %d leaks %q", e.Seq, secret)
			}
		}
		if e.Action == "user.login_failed" && e.Actor != "nobody" && e.Actor != "oper" {
			t.Errorf("failed login attributed to %q", e.Actor)
		}
	}
	for _, want := range []string{"user.create", "user.login", "user.login_failed", "user.logout"} {
		if !seen[want] {
			t.Errorf("audit lacks %q", want)
		}
	}
}
