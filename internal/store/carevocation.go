package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotIntermediate is returned when something that only applies to an
// intermediate CA is asked of another kind.
var ErrNotIntermediate = errors.New("store: only an intermediate CA can be revoked")

// RevokeCA marks an intermediate revoked, once and for good. A Root cannot be
// revoked this way: nothing above it could sign the statement.
func (s *Store) RevokeCA(ctx context.Context, actor, id string, reason int, at time.Time) (CA, error) {
	var out CA
	err := s.tx(ctx, func(tx *sql.Tx) error {
		cur, err := scanCA(tx.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if cur.Kind != KindIntermediate {
			return ErrNotIntermediate
		}
		if cur.Revoked() {
			return ErrAlreadyRevoked
		}
		if _, err := tx.ExecContext(ctx, `UPDATE cas SET revoked_at = ?, revocation_reason = ? WHERE id = ?`, at.Unix(), reason, id); err != nil {
			if strings.Contains(err.Error(), "CHECK constraint") {
				return fmt.Errorf("%w: revocation reason %d is not allowed", ErrInvalid, reason)
			}
			return err
		}
		if out, err = scanCA(tx.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE id = ?`, id)); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, "ca.revoke", id, fmt.Sprintf("%s reason=%d", out.Name, reason))
	})
	return out, err
}

// Children returns the intermediates signed by a Root, oldest first.
func (s *Store) Children(ctx context.Context, rootID string) ([]CA, error) {
	return listChildren(ctx, s.db, rootID)
}

func listChildren(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, rootID string) ([]CA, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+caColumns+` FROM cas WHERE parent_id = ? ORDER BY created_at, name`, rootID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ImportedCRL is a CRL that someone else signed (the Root's) and we publish.
type ImportedCRL struct {
	CAID         string
	Number       int64 // 0 when the CRL has none
	ThisUpdate   time.Time
	NextUpdate   time.Time
	ImportedAt   time.Time
	RevokedCount int
	DER          []byte
}

// PutImportedCRL stores the Root's CRL. check runs inside the same transaction,
// with what is currently published (nil if nothing) and the Root's
// intermediates, so the decision to accept it and the replacement are one step:
// two imports cannot slip past each other's freshness test.
func (s *Store) PutImportedCRL(ctx context.Context, actor, rootID string, in ImportedCRL,
	check func(prev *ImportedCRL, children []CA) error) (ImportedCRL, error) {
	var out ImportedCRL
	err := s.tx(ctx, func(tx *sql.Tx) error {
		root, err := scanCA(tx.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE id = ?`, rootID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if root.Kind != KindRoot {
			return fmt.Errorf("%w: only a Root's CRL is imported", ErrInvalid)
		}
		prev, err := scanImported(tx.QueryRowContext(ctx, `SELECT `+importedColumns+` FROM imported_crls WHERE ca_id = ?`, rootID))
		var prevPtr *ImportedCRL
		switch {
		case err == nil:
			prevPtr = &prev
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		children, err := listChildren(ctx, tx, rootID)
		if err != nil {
			return err
		}
		if err := check(prevPtr, children); err != nil {
			return err
		}
		in.CAID, in.ImportedAt = rootID, s.now().UTC()
		var number any
		if in.Number > 0 {
			number = in.Number
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO imported_crls (ca_id, crl_number, this_update, next_update, imported_at, revoked_count, der) VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(ca_id) DO UPDATE SET crl_number = excluded.crl_number, this_update = excluded.this_update,
			   next_update = excluded.next_update, imported_at = excluded.imported_at,
			   revoked_count = excluded.revoked_count, der = excluded.der`,
			rootID, number, in.ThisUpdate.Unix(), in.NextUpdate.Unix(), in.ImportedAt.Unix(), in.RevokedCount, in.DER); err != nil {
			return err
		}
		out = in
		return s.appendAudit(ctx, tx, actor, "crl.import", rootID,
			fmt.Sprintf("root=%s number=%d revoked=%d", root.Name, in.Number, in.RevokedCount))
	})
	return out, err
}

const importedColumns = `ca_id, COALESCE(crl_number, 0), this_update, next_update, imported_at, revoked_count, der`

func scanImported(r scanner) (ImportedCRL, error) {
	var c ImportedCRL
	var this, next, at int64
	if err := r.Scan(&c.CAID, &c.Number, &this, &next, &at, &c.RevokedCount, &c.DER); err != nil {
		return ImportedCRL{}, err
	}
	c.ThisUpdate, c.NextUpdate, c.ImportedAt = time.Unix(this, 0).UTC(), time.Unix(next, 0).UTC(), time.Unix(at, 0).UTC()
	return c, nil
}

// GetImportedCRL returns the Root's imported CRL, or ErrNotFound.
func (s *Store) GetImportedCRL(ctx context.Context, rootID string) (ImportedCRL, error) {
	c, err := scanImported(s.db.QueryRowContext(ctx, `SELECT `+importedColumns+` FROM imported_crls WHERE ca_id = ?`, rootID))
	if errors.Is(err, sql.ErrNoRows) {
		return ImportedCRL{}, ErrNotFound
	}
	return c, err
}

// PublishedCRL is whatever list a CA publishes, whoever signed it.
type PublishedCRL struct {
	CAID       string
	DER        []byte
	ModifiedAt time.Time // when it was generated here, or imported
	Imported   bool
}

// GetPublishedCRL returns the list to serve for a CA: the one this service
// signed for an intermediate, or the one imported for a Root.
func (s *Store) GetPublishedCRL(ctx context.Context, caID string) (PublishedCRL, error) {
	if c, err := s.GetCRL(ctx, caID); err == nil {
		return PublishedCRL{CAID: caID, DER: c.DER, ModifiedAt: c.GeneratedAt}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return PublishedCRL{}, err
	}
	c, err := s.GetImportedCRL(ctx, caID)
	if err != nil {
		return PublishedCRL{}, err
	}
	return PublishedCRL{CAID: caID, DER: c.DER, ModifiedAt: c.ImportedAt, Imported: true}, nil
}
