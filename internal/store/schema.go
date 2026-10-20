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
}
