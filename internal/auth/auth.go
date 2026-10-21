// Package auth implements local accounts, sessions and role-based access.
//
// Security properties:
//   - passwords are stored as Argon2id hashes and verified in constant time;
//   - a login for an unknown, disabled or locked account costs the same as a
//     real one and returns the same error, so it reveals nothing;
//   - repeated failures lock the account, and a correct password does not
//     bypass a lock;
//   - only the SHA-256 of a session token is stored;
//   - sessions have an idle timeout and an absolute lifetime, and are revoked
//     when the password, role or enabled state of their user changes;
//   - the number of concurrent password hashes is bounded, so login floods
//     cannot exhaust memory.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marcioamatte/pki-dash/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid username or password")
	ErrInvalidSession     = errors.New("auth: invalid or expired session")
	ErrForbidden          = errors.New("auth: not allowed")
	ErrWeakPassword       = errors.New("auth: weak password")
	ErrInvalidUsername    = errors.New("auth: invalid username")
	ErrInvalidRole        = errors.New("auth: invalid role")
	ErrSetupDone          = errors.New("auth: setup already completed")
	ErrNoAccess           = errors.New("auth: the identity provider granted no access to this application")
	ErrExternalUser       = errors.New("auth: this user is managed by the identity provider")
)

const (
	MinPasswordLen = 12
	MaxPasswordLen = 128
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{3,64}$`)

// Options configure Auth. Zero values take the defaults noted.
type Options struct {
	Now            func() time.Time // time.Now
	Password       PasswordParams   // DefaultPasswordParams
	MaxAttempts    int              // 5 failures lock the account
	LockFor        time.Duration    // 15 minutes
	IdleTimeout    time.Duration    // 30 minutes
	SessionTTL     time.Duration    // 12 hours, absolute
	MaxConcurrency int              // 4 simultaneous password hashes
	ExternalRoles  RoleMap          // how identity-provider groups become roles; empty means no external sign-in
}

// Session is an authenticated principal. Token is set only on the Session
// returned by Login: it is shown once and never stored in clear.
type Session struct {
	Token     string
	UserID    string
	Username  string
	Role      string
	CSRF      string
	ExpiresAt time.Time
}

// Auth is safe for concurrent use.
type Auth struct {
	st    *store.Store
	opts  Options
	sem   chan struct{}
	dummy string // a valid hash to verify against when the account does not exist
}

// New creates an Auth over an open store.
func New(st *store.Store, opts Options) (*Auth, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Password == (PasswordParams{}) {
		opts.Password = DefaultPasswordParams
	}
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = 5
	}
	if opts.LockFor == 0 {
		opts.LockFor = 15 * time.Minute
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 30 * time.Minute
	}
	if opts.SessionTTL == 0 {
		opts.SessionTTL = 12 * time.Hour
	}
	if opts.MaxConcurrency == 0 {
		opts.MaxConcurrency = 4
	}
	random, err := token()
	if err != nil {
		return nil, err
	}
	dummy, err := hashPassword(random, opts.Password)
	if err != nil {
		return nil, err
	}
	return &Auth{st: st, opts: opts, sem: make(chan struct{}, opts.MaxConcurrency), dummy: dummy}, nil
}

func token() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

// hash and verify run under the concurrency bound.
func (a *Auth) hash(ctx context.Context, pw string) (string, error) {
	if err := a.acquire(ctx); err != nil {
		return "", err
	}
	defer a.release()
	return hashPassword(pw, a.opts.Password)
}

func (a *Auth) verify(ctx context.Context, pw, encoded string) (ok, rehash bool, err error) {
	if err := a.acquire(ctx); err != nil {
		return false, false, err
	}
	defer a.release()
	return verifyPassword(pw, encoded, a.opts.Password)
}

func (a *Auth) acquire(ctx context.Context) error {
	select {
	case a.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (a *Auth) release() { <-a.sem }

func checkUsername(u string) error {
	if !usernameRE.MatchString(u) {
		return fmt.Errorf("%w: 3-64 characters from letters, digits, . _ @ -", ErrInvalidUsername)
	}
	return nil
}

func checkPassword(pw, username string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLen || n > MaxPasswordLen {
		return fmt.Errorf("%w: length must be %d to %d characters", ErrWeakPassword, MinPasswordLen, MaxPasswordLen)
	}
	if strings.Contains(strings.ToLower(pw), strings.ToLower(username)) {
		return fmt.Errorf("%w: must not contain the username", ErrWeakPassword)
	}
	return nil
}

// ---- setup and user management ----

// NeedsSetup reports whether no account exists yet.
func (a *Auth) NeedsSetup(ctx context.Context) (bool, error) {
	us, err := a.st.ListUsers(ctx)
	return len(us) == 0, err
}

// Setup creates the first admin. It succeeds only while no user exists, and
// the check is atomic, so two concurrent requests cannot both win.
func (a *Auth) Setup(ctx context.Context, username, password string) error {
	username = strings.TrimSpace(username)
	if err := checkUsername(username); err != nil {
		return err
	}
	if err := checkPassword(password, username); err != nil {
		return err
	}
	h, err := a.hash(ctx, password)
	if err != nil {
		return err
	}
	_, err = a.st.CreateUser(ctx, "setup", store.User{Username: username, PasswordHash: h, Role: store.RoleAdmin}, true)
	if errors.Is(err, store.ErrNotEmpty) {
		return ErrSetupDone
	}
	return err
}

// Authorize returns ErrForbidden unless p's role holds perm.
func Authorize(p *Session, perm Permission) error {
	if p == nil || !Can(p.Role, perm) {
		return ErrForbidden
	}
	return nil
}

// CreateUser adds a local user. Requires user.manage.
func (a *Auth) CreateUser(ctx context.Context, p *Session, username, password, role string) (string, error) {
	if err := Authorize(p, PermManageUsers); err != nil {
		return "", err
	}
	username = strings.TrimSpace(username)
	if err := checkUsername(username); err != nil {
		return "", err
	}
	if !validRole(role) {
		return "", ErrInvalidRole
	}
	if err := checkPassword(password, username); err != nil {
		return "", err
	}
	h, err := a.hash(ctx, password)
	if err != nil {
		return "", err
	}
	return a.st.CreateUser(ctx, p.Username, store.User{Username: username, PasswordHash: h, Role: role}, false)
}

// SetRole changes a user's role. Requires user.manage; the last admin cannot be demoted.
func (a *Auth) SetRole(ctx context.Context, p *Session, userID, role string) error {
	if err := Authorize(p, PermManageUsers); err != nil {
		return err
	}
	if !validRole(role) {
		return ErrInvalidRole
	}
	if u, err := a.st.GetUser(ctx, userID); err == nil && u.AuthSource != store.SourceLocal {
		return ErrExternalUser
	}
	return a.st.SetRole(ctx, p.Username, userID, role)
}

// SetDisabled enables or disables a user. Requires user.manage; the last admin cannot be disabled.
func (a *Auth) SetDisabled(ctx context.Context, p *Session, userID string, disabled bool) error {
	if err := Authorize(p, PermManageUsers); err != nil {
		return err
	}
	return a.st.SetDisabled(ctx, p.Username, userID, disabled)
}

// ResetPassword sets a new password for another user. Requires user.manage.
func (a *Auth) ResetPassword(ctx context.Context, p *Session, userID, newPassword string) error {
	if err := Authorize(p, PermManageUsers); err != nil {
		return err
	}
	u, err := a.st.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.AuthSource != store.SourceLocal {
		return ErrExternalUser
	}
	if err := checkPassword(newPassword, u.Username); err != nil {
		return err
	}
	h, err := a.hash(ctx, newPassword)
	if err != nil {
		return err
	}
	return a.st.SetPasswordHash(ctx, p.Username, userID, h, true)
}

// ListUsers returns all users. Requires user.manage. Password hashes are blanked.
func (a *Auth) ListUsers(ctx context.Context, p *Session) ([]store.User, error) {
	if err := Authorize(p, PermManageUsers); err != nil {
		return nil, err
	}
	us, err := a.st.ListUsers(ctx)
	for i := range us {
		us[i].PasswordHash = ""
	}
	return us, err
}

// ChangeOwnPassword verifies the current password, sets the new one and ends
// all of the user's sessions, including this one: the user logs in again.
func (a *Auth) ChangeOwnPassword(ctx context.Context, p *Session, current, next string) error {
	if p == nil {
		return ErrForbidden
	}
	u, err := a.st.GetUser(ctx, p.UserID)
	if err != nil {
		return err
	}
	ok, _, err := a.verify(ctx, current, u.PasswordHash)
	if err != nil || !ok {
		_ = a.st.AuditEvent(ctx, u.Username, "user.password_change_failed", u.ID, "")
		return ErrInvalidCredentials
	}
	if err := checkPassword(next, u.Username); err != nil {
		return err
	}
	h, err := a.hash(ctx, next)
	if err != nil {
		return err
	}
	return a.st.SetPasswordHash(ctx, u.Username, u.ID, h, true)
}

// ---- login and sessions ----

// Login authenticates a local user and opens a session. Every failure returns
// ErrInvalidCredentials, whatever the cause.
func (a *Auth) Login(ctx context.Context, username, password string) (*Session, error) {
	username = strings.TrimSpace(username)
	fail := func(reason string) (*Session, error) {
		_ = a.st.AuditEvent(ctx, username, "user.login_failed", "", reason)
		return nil, ErrInvalidCredentials
	}
	if len(password) > maxPwBytes || len(username) > 64 {
		return fail("oversized input")
	}

	u, err := a.st.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (u.AuthSource != store.SourceLocal || u.PasswordHash == "")) {
		// Spend the same time as a real check so existence is not observable.
		if _, _, verr := a.verify(ctx, password, a.dummy); verr != nil && !errors.Is(verr, errBadHash) {
			return nil, verr
		}
		return fail("unknown user")
	}
	if err != nil {
		return nil, err
	}

	ok, rehash, err := a.verify(ctx, password, u.PasswordHash)
	if err != nil && !errors.Is(err, errBadHash) {
		return nil, err
	}
	now := a.opts.Now()
	switch {
	case u.Disabled:
		return fail("account disabled")
	case now.Before(u.LockedUntil):
		// A correct password must not unlock an account: that would make the
		// lock useless against guessing.
		return fail("account locked")
	case !ok:
		locked, ferr := a.st.RecordLoginFailure(ctx, u.ID, a.opts.MaxAttempts, a.opts.LockFor)
		if ferr != nil {
			return nil, ferr
		}
		if locked {
			_ = a.st.AuditEvent(ctx, u.Username, "user.locked", u.ID, fmt.Sprintf("after %d failed logins", a.opts.MaxAttempts))
		}
		return fail("wrong password")
	}

	if rehash {
		if h, herr := a.hash(ctx, password); herr == nil {
			_ = a.st.SetPasswordHash(ctx, u.Username, u.ID, h, false)
		}
	}
	return a.openSession(ctx, u, u.Role, "")
}

// openSession records a successful login and creates the session. detail goes
// into the audit entry (for example how the user signed in).
func (a *Auth) openSession(ctx context.Context, u store.User, role, detail string) (*Session, error) {
	now := a.opts.Now()
	if err := a.st.RecordLoginSuccess(ctx, u.ID); err != nil {
		return nil, err
	}
	tok, err := token()
	if err != nil {
		return nil, err
	}
	csrf, err := token()
	if err != nil {
		return nil, err
	}
	exp := now.Add(a.opts.SessionTTL)
	if err := a.st.CreateSession(ctx, hashToken(tok), u.ID, csrf, exp); err != nil {
		return nil, err
	}
	if err := a.st.AuditEvent(ctx, u.Username, "user.login", u.ID, detail); err != nil {
		_ = a.st.DeleteSession(ctx, hashToken(tok)) // no unaudited session
		return nil, err
	}
	return &Session{Token: tok, UserID: u.ID, Username: u.Username, Role: role, CSRF: csrf, ExpiresAt: exp}, nil
}

// Validate resolves a session token. It enforces both timeouts and the
// user's current state, and counts the call as activity.
func (a *Auth) Validate(ctx context.Context, tok string) (*Session, error) {
	if tok == "" || len(tok) > 256 {
		return nil, ErrInvalidSession
	}
	h := hashToken(tok)
	s, err := a.st.GetSession(ctx, h)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, err
	}
	now := a.opts.Now()
	if !now.Before(s.ExpiresAt) || !now.Before(s.LastSeen.Add(a.opts.IdleTimeout)) || s.User.Disabled {
		_ = a.st.DeleteSession(ctx, h)
		return nil, ErrInvalidSession
	}
	if err := a.st.TouchSession(ctx, h); err != nil {
		return nil, err
	}
	return &Session{UserID: s.User.ID, Username: s.User.Username, Role: s.User.Role, CSRF: s.CSRF, ExpiresAt: s.ExpiresAt}, nil
}

// Logout ends a session. An unknown token is not an error.
func (a *Auth) Logout(ctx context.Context, tok string) error {
	h := hashToken(tok)
	if s, err := a.st.GetSession(ctx, h); err == nil {
		_ = a.st.AuditEvent(ctx, s.User.Username, "user.logout", s.User.ID, "")
	}
	return a.st.DeleteSession(ctx, h)
}

// PurgeExpired deletes expired and idle sessions. Run it periodically.
func (a *Auth) PurgeExpired(ctx context.Context) (int64, error) {
	return a.st.PurgeSessions(ctx, a.opts.Now().Add(-a.opts.IdleTimeout))
}
