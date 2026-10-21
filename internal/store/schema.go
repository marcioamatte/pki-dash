package store

// migrations are applied in order; the index+1 is the schema version stored
// in PRAGMA user_version. Never edit a released migration: append a new one.
var migrations = []string{
	// 1: initial schema
	`
CREATE TABLE meta (
	key   TEXT PRIMARY KEY,
	value BLOB NOT NULL
) STRICT;

CREATE TABLE cas (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 200),
	kind       TEXT NOT NULL CHECK (kind IN ('root', 'intermediate')),
	parent_id  TEXT REFERENCES cas(id) ON DELETE RESTRICT,
	cert_pem   BLOB NOT NULL,
	-- Encrypted private key (see internal/vault). NULL once the key has been
	-- exported and removed, which is how a Root goes offline.
	key_blob   BLOB,
	not_before INTEGER NOT NULL,
	not_after  INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	CHECK ((kind = 'root' AND parent_id IS NULL) OR (kind = 'intermediate' AND parent_id IS NOT NULL))
) STRICT;

CREATE TABLE certificates (
	id            TEXT PRIMARY KEY,
	ca_id         TEXT NOT NULL REFERENCES cas(id) ON DELETE RESTRICT,
	serial        TEXT NOT NULL,
	common_name   TEXT NOT NULL,
	sans          TEXT NOT NULL,
	profile       TEXT NOT NULL,
	cert_pem      BLOB NOT NULL,
	not_before    INTEGER NOT NULL,
	not_after     INTEGER NOT NULL,
	key_generated INTEGER NOT NULL CHECK (key_generated IN (0, 1)),
	created_at    INTEGER NOT NULL,
	UNIQUE (ca_id, serial)
) STRICT;
CREATE INDEX certificates_not_after ON certificates(not_after);

-- Append-only, hash-chained audit log. The triggers make UPDATE and DELETE
-- fail; the chain makes edits made around them detectable.
CREATE TABLE audit_log (
	seq    INTEGER PRIMARY KEY,
	ts     INTEGER NOT NULL,
	actor  TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL,
	detail TEXT NOT NULL,
	hash   BLOB NOT NULL
) STRICT;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`,

	// 2: users and sessions
	`
CREATE TABLE users (
	id              TEXT PRIMARY KEY,
	username        TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) BETWEEN 3 AND 64),
	-- PHC-format Argon2id hash. NULL only for externally authenticated users.
	password_hash   TEXT,
	role            TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
	auth_source     TEXT NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc')),
	external_id     TEXT,
	disabled        INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
	failed_attempts INTEGER NOT NULL DEFAULT 0,
	locked_until    INTEGER NOT NULL DEFAULT 0,
	created_at      INTEGER NOT NULL,
	CHECK ((auth_source = 'local' AND password_hash IS NOT NULL) OR auth_source = 'oidc'),
	UNIQUE (auth_source, external_id)
) STRICT;

-- Only the SHA-256 of the session token is stored, so a copy of the database
-- does not yield usable sessions.
CREATE TABLE sessions (
	token_hash BLOB PRIMARY KEY,
	user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf       TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);
`,

	// 3: intermediate CAs waiting for a certificate signed elsewhere
	`
CREATE TABLE pending_cas (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 200),
	parent_id  TEXT NOT NULL REFERENCES cas(id) ON DELETE RESTRICT,
	csr_pem    BLOB NOT NULL,
	-- The intermediate's private key, encrypted like any other (see internal/vault).
	key_blob   BLOB NOT NULL,
	created_at INTEGER NOT NULL
) STRICT;
`,

	// 4: revocation and published CRLs
	`
ALTER TABLE certificates ADD COLUMN revoked_at INTEGER;
-- RFC 5280 reason codes we allow for service certificates (see internal/ca).
ALTER TABLE certificates ADD COLUMN revocation_reason INTEGER NOT NULL DEFAULT 0
	CHECK (revocation_reason IN (0, 1, 3, 4, 5));
CREATE INDEX certificates_revoked ON certificates(ca_id) WHERE revoked_at IS NOT NULL;

-- The latest CRL each CA has published. revoked_count lets us tell, exactly and
-- without comparing clocks, whether a CRL is missing a revocation.
CREATE TABLE crls (
	ca_id         TEXT PRIMARY KEY REFERENCES cas(id) ON DELETE RESTRICT,
	number        INTEGER NOT NULL CHECK (number >= 1),
	generated_at  INTEGER NOT NULL,
	this_update   INTEGER NOT NULL,
	next_update   INTEGER NOT NULL,
	revoked_count INTEGER NOT NULL,
	der           BLOB NOT NULL
) STRICT;
`,

	// 5: revoked intermediates, and the Root's CRL that was signed offline
	`
ALTER TABLE cas ADD COLUMN revoked_at INTEGER;
ALTER TABLE cas ADD COLUMN revocation_reason INTEGER NOT NULL DEFAULT 0
	CHECK (revocation_reason IN (0, 1, 2, 3, 4, 5));

-- A Root never signs here, so its CRL is made elsewhere and imported. It keeps
-- the CRL's own number when it has one (cfssl's does not), and the dates that
-- stop an older list from being put back.
CREATE TABLE imported_crls (
	ca_id         TEXT PRIMARY KEY REFERENCES cas(id) ON DELETE RESTRICT,
	crl_number    INTEGER,
	this_update   INTEGER NOT NULL,
	next_update   INTEGER NOT NULL,
	imported_at   INTEGER NOT NULL,
	revoked_count INTEGER NOT NULL,
	der           BLOB NOT NULL
) STRICT;
`,
}
