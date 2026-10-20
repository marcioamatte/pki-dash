package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrLastAdmin is returned when a change would leave no active admin.
	ErrLastAdmin = errors.New("store: cannot remove the last active admin")
	// ErrNotEmpty is returned by CreateUser(onlyIfEmpty) when users exist.
	ErrNotEmpty = errors.New("store: users already exist")
)

// Roles and authentication sources.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"

	SourceLocal = "local"
	SourceOIDC  = "oidc"
)

// User is an account. PasswordHash is empty for externally authenticated users.
type User struct {
	ID             string
	Username       string
	PasswordHash   string
	Role           string
	AuthSource     string
	ExternalID     string
	Disabled       bool
	FailedAttempts int
	LockedUntil    time.Time
	CreatedAt      time.Time
}

// userCols lists the user columns, qualified with a table alias (may be empty).
func userCols(alias string) string {
	if alias != "" {
		alias += "."
	}
	return alias + "id, " + alias + "username, COALESCE(" + alias + "password_hash, ''), " + alias + "role, " +
		alias + "auth_source, COALESCE(" + alias + "external_id, ''), " + alias + "disabled, " +
		alias + "failed_attempts, " + alias + "locked_until, " + alias + "created_at"
}

var userColumns = userCols("")

func scanUser(r scanner) (User, error) {
	var u User
	var locked, created int64
	if err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.AuthSource, &u.ExternalID, &u.Disabled, &u.FailedAttempts, &locked, &created); err != nil {
		return User{}, err
	}
	u.LockedUntil, u.CreatedAt = time.Unix(locked, 0).UTC(), time.Unix(created, 0).UTC()
	return u, nil
}

// CreateUser adds a user. With onlyIfEmpty the insert happens only if there
// are no users at all, atomically: this is what makes first-run setup safe
// against a race between two requests.
func (s *Store) CreateUser(ctx context.Context, actor string, u User, onlyIfEmpty bool) (string, error) {
	if u.Username == "" || u.Role == "" {
		return "", fmt.Errorf("%w: username and role are required", ErrInvalid)
	}
	if u.AuthSource == "" {
		u.AuthSource = SourceLocal
	}
	id := NewID()
	var ext any
	if u.ExternalID != "" {
		ext = u.ExternalID
	}
	var hash any
	if u.PasswordHash != "" {
		hash = u.PasswordHash
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if onlyIfEmpty {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return ErrNotEmpty
			}
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO users (id, username, password_hash, role, auth_source, external_id, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, u.Username, hash, u.Role, u.AuthSource, ext, s.now().Unix())
		if err != nil {
			if isUnique(err) {
				return ErrExists
			}
			if strings.Contains(err.Error(), "CHECK constraint") {
				return fmt.Errorf("%w: %v", ErrInvalid, err)
			}
			return err
		}
		return s.appendAudit(ctx, tx, actor, "user.create", id, u.Username+" "+u.Role)
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) getUser(ctx context.Context, where string, arg any) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// GetUser returns a user by ID.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	return s.getUser(ctx, `id = ?`, id)
}

// GetUserByUsername looks a user up case-insensitively.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return s.getUser(ctx, `username = ?`, username)
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// RecordLoginFailure counts a failed attempt and locks the account once it
// reaches max failures. It reports whether the account is now locked.
func (s *Store) RecordLoginFailure(ctx context.Context, id string, max int, lockFor time.Duration) (locked bool, err error) {
	now := s.now()
	err = s.tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`UPDATE users SET
			   failed_attempts = CASE WHEN failed_attempts + 1 >= ? THEN 0 ELSE failed_attempts + 1 END,
			   locked_until    = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END
			 WHERE id = ? RETURNING locked_until > ?`,
			max, max, now.Add(lockFor).Unix(), id, now.Unix()).Scan(&locked)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	return locked, err
}

// RecordLoginSuccess clears the failure counter.
func (s *Store) RecordLoginSuccess(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?`, id)
	return err
}

// SetPasswordHash replaces a user's password hash and revokes all of their
// sessions. With audit false it is a silent rehash (stronger parameters).
func (s *Store) SetPasswordHash(ctx context.Context, actor, id, hash string, audit bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = 0 WHERE id = ? AND auth_source = 'local'`, hash, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		if !audit {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, "user.password_change", id, "")
	})
}

// SetRole changes a user's role and revokes their sessions.
func (s *Store) SetRole(ctx context.Context, actor, id, role string) error {
	return s.changeUser(ctx, actor, id, "user.role_change", role,
		func(tx *sql.Tx) (sql.Result, error) {
			return tx.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id)
		}, role != RoleAdmin)
}

// SetDisabled enables or disables a user and revokes their sessions.
func (s *Store) SetDisabled(ctx context.Context, actor, id string, disabled bool) error {
	action := "user.enable"
	if disabled {
		action = "user.disable"
	}
	return s.changeUser(ctx, actor, id, action, "",
		func(tx *sql.Tx) (sql.Result, error) {
			return tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, id)
		}, disabled)
}

// changeUser runs an update that may remove an admin: if it would (removes),
// it first checks that another active admin remains.
func (s *Store) changeUser(ctx context.Context, actor, id, action, detail string, update func(*sql.Tx) (sql.Result, error), removes bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if removes {
			var target string
			if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ? AND disabled = 0`, id).Scan(&target); err == nil && target == RoleAdmin {
				var others int
				if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id <> ?`, id).Scan(&others); err != nil {
					return err
				}
				if others == 0 {
					return ErrLastAdmin
				}
			}
		}
		res, err := update(tx)
		if err != nil {
			if strings.Contains(err.Error(), "CHECK constraint") {
				return fmt.Errorf("%w: %v", ErrInvalid, err)
			}
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, action, id, detail)
	})
}

// ---- sessions ----

// Session is a login session joined with its user.
type Session struct {
	TokenHash []byte
	User      User
	CSRF      string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// CreateSession stores a session. Callers pass the hash of the token, never
// the token itself.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID, csrf string, expires time.Time) error {
	now := s.now().Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, csrf, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		tokenHash, userID, csrf, now, now, expires.Unix())
	return err
}

// GetSession returns the session for a token hash, or ErrNotFound.
func (s *Store) GetSession(ctx context.Context, tokenHash []byte) (Session, error) {
	var sess Session
	var created, seen, exp int64
	row := s.db.QueryRowContext(ctx,
		`SELECT s.csrf, s.created_at, s.last_seen, s.expires_at, `+userCols("u")+`
		   FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`, tokenHash)
	var u User
	var locked, ucreated int64
	err := row.Scan(&sess.CSRF, &created, &seen, &exp,
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.AuthSource, &u.ExternalID, &u.Disabled, &u.FailedAttempts, &locked, &ucreated)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	u.LockedUntil, u.CreatedAt = time.Unix(locked, 0).UTC(), time.Unix(ucreated, 0).UTC()
	sess.TokenHash, sess.User = tokenHash, u
	sess.CreatedAt, sess.LastSeen, sess.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(seen, 0).UTC(), time.Unix(exp, 0).UTC()
	return sess, nil
}

// TouchSession records activity, for the idle timeout.
func (s *Store) TouchSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE token_hash = ?`, s.now().Unix(), tokenHash)
	return err
}

// DeleteSession ends one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// PurgeSessions deletes sessions that expired, or were idle since before idleCutoff.
func (s *Store) PurgeSessions(ctx context.Context, idleCutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?`, s.now().Unix(), idleCutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
