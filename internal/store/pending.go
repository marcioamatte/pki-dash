package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PendingCA is an intermediate CA that has a key and a certificate request but
// no certificate yet: the request was taken to an offline Root to be signed.
type PendingCA struct {
	ID        string
	Name      string
	ParentID  string
	CSRPEM    []byte
	KeyBlob   []byte
	CreatedAt time.Time
}

// CreatePendingCA stores a request. p.ID must be set: the key blob is bound to
// it, so it exists before the insert. The name must not clash with a CA or
// with another pending request.
func (s *Store) CreatePendingCA(ctx context.Context, actor string, p PendingCA) (string, error) {
	if p.ID == "" || p.Name == "" || p.ParentID == "" || len(p.CSRPEM) == 0 || len(p.KeyBlob) == 0 {
		return "", fmt.Errorf("%w: id, name, parent, request and key are required", ErrInvalid)
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM cas WHERE name = ?`, p.Name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrExists
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO pending_cas (id, name, parent_id, csr_pem, key_blob, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			p.ID, p.Name, p.ParentID, p.CSRPEM, p.KeyBlob, s.now().Unix())
		if err != nil {
			if isUnique(err) {
				return ErrExists
			}
			if isForeignKey(err) {
				return fmt.Errorf("%w: unknown parent CA", ErrInvalid)
			}
			return err
		}
		return s.appendAudit(ctx, tx, actor, "ca.request_intermediate", p.ID, p.Name+" parent="+p.ParentID)
	})
	if err != nil {
		return "", err
	}
	return p.ID, nil
}

const pendingColumns = `id, name, parent_id, csr_pem, key_blob, created_at`

func scanPending(r scanner) (PendingCA, error) {
	var p PendingCA
	var created int64
	if err := r.Scan(&p.ID, &p.Name, &p.ParentID, &p.CSRPEM, &p.KeyBlob, &created); err != nil {
		return PendingCA{}, err
	}
	p.CreatedAt = time.Unix(created, 0).UTC()
	return p, nil
}

// GetPendingCA returns one pending request.
func (s *Store) GetPendingCA(ctx context.Context, id string) (PendingCA, error) {
	p, err := scanPending(s.db.QueryRowContext(ctx, `SELECT `+pendingColumns+` FROM pending_cas WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PendingCA{}, ErrNotFound
	}
	return p, err
}

// ListPendingCAs returns pending requests, oldest first.
func (s *Store) ListPendingCAs(ctx context.Context) ([]PendingCA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+pendingColumns+` FROM pending_cas ORDER BY created_at, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingCA
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePendingCA discards a request and its key.
func (s *Store) DeletePendingCA(ctx context.Context, actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM pending_cas WHERE id = ?`, id).Scan(&name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM pending_cas WHERE id = ?`, id); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, "ca.request_cancel", id, name)
	})
}

// CompletePendingCA turns a pending request into a real CA, atomically: the CA
// row appears and the request disappears together. ca.ID must equal the
// request's ID, so the encrypted key (bound to that ID) stays valid as it is.
func (s *Store) CompletePendingCA(ctx context.Context, actor, id string, ca CA) error {
	if ca.ID != id || ca.Kind != KindIntermediate || ca.ParentID == "" || len(ca.CertPEM) == 0 || len(ca.KeyBlob) == 0 {
		return fmt.Errorf("%w: a completed request needs its own ID, a parent, a certificate and its key", ErrInvalid)
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM pending_cas WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO cas (id, name, kind, parent_id, cert_pem, key_blob, not_before, not_after, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ca.ID, ca.Name, ca.Kind, ca.ParentID, ca.CertPEM, ca.KeyBlob,
			ca.NotBefore.Unix(), ca.NotAfter.Unix(), s.now().Unix())
		if err != nil {
			if isUnique(err) {
				return ErrExists
			}
			return err
		}
		return s.appendAudit(ctx, tx, actor, "ca.import_intermediate", id, ca.Name)
	})
}
