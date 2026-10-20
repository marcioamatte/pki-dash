package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrAuditTampered is returned by VerifyAudit when the chain does not check out.
var ErrAuditTampered = errors.New("store: audit log chain is broken")

// AuditEntry is one row of the audit log. Detail must never contain secrets.
type AuditEntry struct {
	Seq    int64
	Time   time.Time
	Actor  string
	Action string
	Target string
	Detail string
	Hash   []byte
}

// entryHash chains an entry to its predecessor. Fields are length-prefixed so
// that moving bytes between fields cannot produce the same hash.
func entryHash(prev []byte, seq, ts int64, actor, action, target, detail string) []byte {
	h := sha256.New()
	h.Write(prev)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(seq))
	h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(ts))
	h.Write(n[:])
	for _, f := range []string{actor, action, target, detail} {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

// appendAudit adds an entry inside the caller's transaction, so an operation
// and its audit record commit or roll back together.
func (s *Store) appendAudit(ctx context.Context, tx *sql.Tx, actor, action, target, detail string) error {
	var seq int64
	var prev []byte
	err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	seq++
	ts := s.now().UnixNano()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_log (seq, ts, actor, action, target, detail, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		seq, ts, actor, action, target, detail, entryHash(prev, seq, ts, actor, action, target, detail))
	return err
}

// Audit returns up to limit entries, newest first.
func (s *Store) Audit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, ts, actor, action, target, detail, hash FROM audit_log ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.Seq, &ts, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.Hash); err != nil {
			return nil, err
		}
		e.Time = time.Unix(0, ts).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAudit recomputes the whole chain. It detects edits, deletions and
// reordering of entries; it cannot detect truncation of the newest entries
// nor a full rewrite by someone who can recompute the hashes.
func (s *Store) VerifyAudit(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, ts, actor, action, target, detail, hash FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var prev []byte
	var want int64 = 1
	for rows.Next() {
		var seq, ts int64
		var actor, action, target, detail string
		var hash []byte
		if err := rows.Scan(&seq, &ts, &actor, &action, &target, &detail, &hash); err != nil {
			return err
		}
		if seq != want {
			return fmt.Errorf("%w: expected entry %d, found %d", ErrAuditTampered, want, seq)
		}
		if !bytes.Equal(hash, entryHash(prev, seq, ts, actor, action, target, detail)) {
			return fmt.Errorf("%w: entry %d does not match its hash", ErrAuditTampered, seq)
		}
		prev, want = hash, want+1
	}
	return rows.Err()
}
