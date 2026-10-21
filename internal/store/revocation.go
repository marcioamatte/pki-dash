package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAlreadyRevoked is returned when revoking a certificate that already is.
var ErrAlreadyRevoked = errors.New("store: certificate already revoked")

// RevokedEntry is a revoked certificate as it goes into a CRL. Serial is hex.
type RevokedEntry struct {
	Serial    string
	RevokedAt time.Time
	Reason    int
}

// RevokeCertificate marks a certificate revoked, once and for good: there is no
// way back, because a CRL entry that clients have cached cannot be taken back.
func (s *Store) RevokeCertificate(ctx context.Context, actor, id string, reason int, at time.Time) (Certificate, error) {
	var out Certificate
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE certificates SET revoked_at = ?, revocation_reason = ? WHERE id = ? AND revoked_at IS NULL`,
			at.Unix(), reason, id)
		if err != nil {
			if strings.Contains(err.Error(), "CHECK constraint") {
				return fmt.Errorf("%w: revocation reason %d is not allowed", ErrInvalid, reason)
			}
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			var exists int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM certificates WHERE id = ?`, id).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				return ErrNotFound
			}
			return ErrAlreadyRevoked
		}
		if out, err = scanCert(tx.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE id = ?`, id)); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, "cert.revoke", id,
			fmt.Sprintf("ca=%s cn=%s serial=%s reason=%d", out.CAID, out.CommonName, out.Serial, reason))
	})
	return out, err
}

func listRevoked(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, caID string) ([]RevokedEntry, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT serial, revoked_at, revocation_reason FROM certificates
		 WHERE ca_id = ? AND revoked_at IS NOT NULL ORDER BY revoked_at, id`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokedEntry
	for rows.Next() {
		var e RevokedEntry
		var at int64
		if err := rows.Scan(&e.Serial, &at, &e.Reason); err != nil {
			return nil, err
		}
		e.RevokedAt = time.Unix(at, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListRevoked returns the revoked certificates of a CA, oldest revocation first.
func (s *Store) ListRevoked(ctx context.Context, caID string) ([]RevokedEntry, error) {
	return listRevoked(ctx, s.db, caID)
}

// CRL is the list a CA has most recently published.
type CRL struct {
	CAID         string
	Number       int64
	GeneratedAt  time.Time
	ThisUpdate   time.Time
	NextUpdate   time.Time
	RevokedCount int
	DER          []byte
}

// PutNextCRL builds and stores a CA's next CRL in one transaction. build gets
// the number to use (one more than the last) and the revoked certificates as
// they are inside that same transaction, so the list can neither skip a
// revocation nor reuse a number, even with concurrent callers.
func (s *Store) PutNextCRL(ctx context.Context, actor, caID string,
	build func(number int64, revoked []RevokedEntry) (der []byte, thisUpdate, nextUpdate time.Time, err error)) (CRL, error) {
	var out CRL
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var prev int64
		err := tx.QueryRowContext(ctx, `SELECT number FROM crls WHERE ca_id = ?`, caID).Scan(&prev)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		revoked, err := listRevoked(ctx, tx, caID)
		if err != nil {
			return err
		}
		der, this, next, err := build(prev+1, revoked)
		if err != nil {
			return err
		}
		out = CRL{CAID: caID, Number: prev + 1, GeneratedAt: s.now().UTC(), ThisUpdate: this, NextUpdate: next, RevokedCount: len(revoked), DER: der}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO crls (ca_id, number, generated_at, this_update, next_update, revoked_count, der) VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(ca_id) DO UPDATE SET number = excluded.number, generated_at = excluded.generated_at,
			   this_update = excluded.this_update, next_update = excluded.next_update,
			   revoked_count = excluded.revoked_count, der = excluded.der`,
			caID, out.Number, out.GeneratedAt.Unix(), this.Unix(), next.Unix(), len(revoked), der)
		if err != nil {
			if isForeignKey(err) {
				return fmt.Errorf("%w: unknown CA", ErrInvalid)
			}
			return err
		}
		return s.appendAudit(ctx, tx, actor, "crl.publish", caID, fmt.Sprintf("number=%d revoked=%d", out.Number, len(revoked)))
	})
	return out, err
}

const crlColumns = `ca_id, number, generated_at, this_update, next_update, revoked_count, der`

func scanCRL(r scanner) (CRL, error) {
	var c CRL
	var gen, this, next int64
	if err := r.Scan(&c.CAID, &c.Number, &gen, &this, &next, &c.RevokedCount, &c.DER); err != nil {
		return CRL{}, err
	}
	c.GeneratedAt, c.ThisUpdate, c.NextUpdate = time.Unix(gen, 0).UTC(), time.Unix(this, 0).UTC(), time.Unix(next, 0).UTC()
	return c, nil
}

// GetCRL returns a CA's latest CRL, or ErrNotFound if it has published none.
func (s *Store) GetCRL(ctx context.Context, caID string) (CRL, error) {
	c, err := scanCRL(s.db.QueryRowContext(ctx, `SELECT `+crlColumns+` FROM crls WHERE ca_id = ?`, caID))
	if errors.Is(err, sql.ErrNoRows) {
		return CRL{}, ErrNotFound
	}
	return c, err
}

// RevokedCount counts a CA's revoked certificates.
func (s *Store) RevokedCount(ctx context.Context, caID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM certificates WHERE ca_id = ? AND revoked_at IS NOT NULL`, caID).Scan(&n)
	return n, err
}
