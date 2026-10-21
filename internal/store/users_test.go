package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestUserConstraintsEnforcedByTheDatabase(t *testing.T) {
	s := open(t)
	bad := map[string]string{
		"unknown role":        `INSERT INTO users (id,username,password_hash,role,created_at) VALUES ('1','alice','h','root',0)`,
		"local without hash":  `INSERT INTO users (id,username,role,created_at) VALUES ('2','bobby','admin',0)`,
		"short username":      `INSERT INTO users (id,username,password_hash,role,created_at) VALUES ('3','ab','h','admin',0)`,
		"unknown auth source": `INSERT INTO users (id,username,password_hash,role,auth_source,created_at) VALUES ('4','carol','h','admin','ldap',0)`,
	}
	for name, stmt := range bad {
		if _, err := s.db.Exec(stmt); err == nil {
			t.Errorf("%s: the database must reject this", name)
		}
	}
	// OIDC users have no local password.
	if _, err := s.db.Exec(`INSERT INTO users (id,username,role,auth_source,external_id,created_at) VALUES ('5','dave','viewer','oidc','sub-1',0)`); err != nil {
		t.Fatalf("oidc user without a hash: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO users (id,username,role,auth_source,external_id,created_at) VALUES ('6','erin','viewer','oidc','sub-1',0)`); err == nil {
		t.Fatal("the same external identity must not map to two users")
	}
}

func TestUsernamesAreUniqueIgnoringCase(t *testing.T) {
	s := open(t)
	if _, err := s.CreateUser(ctx, "x", User{Username: "Alice", PasswordHash: "h", Role: RoleViewer}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "x", User{Username: "aLICE", PasswordHash: "h", Role: RoleViewer}, false); !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v, want ErrExists", err)
	}
	if u, err := s.GetUserByUsername(ctx, "ALICE"); err != nil || u.Username != "Alice" {
		t.Fatalf("lookup = %+v, %v", u, err)
	}
}

func TestSessionsDieWithTheirUser(t *testing.T) {
	s := open(t)
	id, _ := s.CreateUser(ctx, "x", User{Username: "alice", PasswordHash: "h", Role: RoleViewer}, false)
	s.CreateSession(ctx, []byte("hash"), id, "csrf", "", time.Now().Add(time.Hour))
	if _, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, []byte("hash")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if err := s.CreateSession(ctx, []byte("h2"), "ghost", "c", "", time.Now()); err == nil {
		t.Fatal("a session for a nonexistent user must be rejected")
	}
}

// A database created by an older release must upgrade in place, keeping its data.
func TestUpgradeFromSchemaV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(migrations[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO cas (id,name,kind,cert_pem,not_before,not_after,created_at) VALUES ('r','Old Root','root',x'01',0,1,0)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	defer s.Close()
	if ca, err := s.GetCA(ctx, "r"); err != nil || ca.Name != "Old Root" {
		t.Fatalf("data lost in upgrade: %+v, %v", ca, err)
	}
	if _, err := s.CreateUser(ctx, "x", User{Username: "alice", PasswordHash: "h", Role: RoleAdmin}, false); err != nil {
		t.Fatalf("new tables missing after upgrade: %v", err)
	}
}

func TestUpgradeFromSchemaV5KeepsSessionsAndAddsTheProviderHint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v5.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := raw.Exec(migrations[i]); err != nil {
			t.Fatal(err)
		}
	}
	raw.Exec(`PRAGMA user_version = 5`)
	raw.Exec(`INSERT INTO users (id,username,password_hash,role,created_at) VALUES ('u1','ana','h','admin',0)`)
	raw.Exec(`INSERT INTO sessions (token_hash,user_id,csrf,created_at,last_seen,expires_at) VALUES (x'aa','u1','c',0,0,9999999999)`)
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer s.Close()
	old, err := s.GetSession(ctx, []byte{0xaa})
	if err != nil || old.IDPHint != "" {
		t.Fatalf("an existing session must survive, without a hint: %v %+v", err, old)
	}
	if err := s.CreateSession(ctx, []byte("new"), "u1", "c", "a.b.c", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSession(ctx, []byte("new")); got.IDPHint != "a.b.c" {
		t.Fatalf("hint: %q", got.IDPHint)
	}
}
