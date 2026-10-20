// Package store persists pki-dash state in a single SQLite file.
//
// It knows nothing about cryptography: private keys arrive already encrypted
// (see internal/vault) and are stored as opaque blobs. Every mutating method
// writes its audit record in the same transaction as the change itself.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver: no CGO
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrExists   = errors.New("store: already exists")
	ErrInvalid  = errors.New("store: invalid data")
)

// Store is a handle to the database. It is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database at path and applies pending
// migrations. The directory is created 0700 and the file 0600.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Create the file ourselves so it is never world-readable, not even briefly.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()

	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Set("_txlock", "immediate") // take the write lock up front: no read-then-write races
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer at a time; plenty for this workload
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("store: database schema v%d is newer than this build (v%d)", v, len(migrations))
	}
	for i := v; i < len(migrations); i++ {
		err := s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1))
			return err
		})
		if err != nil {
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
	}
	return nil
}

// tx runs f in a transaction, committing only if it returns nil.
func (s *Store) tx(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := f(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// NewID returns a fresh random identifier. Callers that must bind data to a
// CA's ID before inserting it (the encrypted key blob) generate it up front
// and pass it in CA.ID.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system CSPRNG failing is not recoverable
	}
	return hex.EncodeToString(b)
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// ---- vault header ----

// SetVaultHeader stores the vault header. It can only be set once; changing
// the passphrase goes through RewrapKeys.
func (s *Store) SetVaultHeader(ctx context.Context, actor string, header []byte) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES ('vault_header', ?)`, header); err != nil {
			if isUnique(err) {
				return ErrExists
			}
			return err
		}
		return s.appendAudit(ctx, tx, actor, "vault.init", "vault", "")
	})
}

// VaultHeader returns the stored header, or ErrNotFound if the vault has not
// been initialised.
func (s *Store) VaultHeader(ctx context.Context) ([]byte, error) {
	var h []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'vault_header'`).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return h, err
}

// RewrapKeys replaces the vault header and re-encrypts every stored key blob
// with rewrap, all in one transaction: either everything moves to the new
// passphrase or nothing does.
func (s *Store) RewrapKeys(ctx context.Context, actor string, newHeader []byte, rewrap func(id string, blob []byte) ([]byte, error)) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, key_blob FROM cas WHERE key_blob IS NOT NULL`)
		if err != nil {
			return err
		}
		type item struct {
			id   string
			blob []byte
		}
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.blob); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, it := range items {
			nb, err := rewrap(it.id, it.blob)
			if err != nil {
				return fmt.Errorf("rewrap CA %s: %w", it.id, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE cas SET key_blob = ? WHERE id = ?`, nb, it.id); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE meta SET value = ? WHERE key = 'vault_header'`, newHeader)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return s.appendAudit(ctx, tx, actor, "vault.passphrase_changed", "vault", fmt.Sprintf("%d keys rewrapped", len(items)))
	})
}

// ---- CAs ----

// CA kinds.
const (
	KindRoot         = "root"
	KindIntermediate = "intermediate"
)

// CA is a stored certificate authority. KeyBlob is nil when the private key
// is not held by the service (an offline Root, or an imported intermediate).
type CA struct {
	ID        string
	Name      string
	Kind      string
	ParentID  string // empty for a root
	CertPEM   []byte
	KeyBlob   []byte
	NotBefore time.Time
	NotAfter  time.Time
	CreatedAt time.Time
}

// CreateCA stores a CA and returns its ID (ca.ID if set, otherwise a new one).
func (s *Store) CreateCA(ctx context.Context, actor string, ca CA) (string, error) {
	if ca.Name == "" || len(ca.CertPEM) == 0 {
		return "", fmt.Errorf("%w: name and certificate are required", ErrInvalid)
	}
	switch {
	case ca.Kind == KindRoot && ca.ParentID == "":
	case ca.Kind == KindIntermediate && ca.ParentID != "":
	default:
		return "", fmt.Errorf("%w: a root has no parent and an intermediate needs one", ErrInvalid)
	}
	id := ca.ID
	if id == "" {
		id = NewID()
	}
	var parent any
	if ca.ParentID != "" {
		parent = ca.ParentID
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO cas (id, name, kind, parent_id, cert_pem, key_blob, not_before, not_after, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, ca.Name, ca.Kind, parent, ca.CertPEM, ca.KeyBlob,
			ca.NotBefore.Unix(), ca.NotAfter.Unix(), s.now().Unix())
		if err != nil {
			if isUnique(err) {
				return ErrExists
			}
			if strings.Contains(err.Error(), "FOREIGN KEY") {
				return fmt.Errorf("%w: unknown parent CA", ErrInvalid)
			}
			return err
		}
		return s.appendAudit(ctx, tx, actor, "ca.create", id, ca.Kind+" "+ca.Name)
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

const caColumns = `id, name, kind, COALESCE(parent_id, ''), cert_pem, key_blob, not_before, not_after, created_at`

type scanner interface{ Scan(...any) error }

func scanCA(r scanner) (CA, error) {
	var c CA
	var nb, na, cr int64
	if err := r.Scan(&c.ID, &c.Name, &c.Kind, &c.ParentID, &c.CertPEM, &c.KeyBlob, &nb, &na, &cr); err != nil {
		return CA{}, err
	}
	c.NotBefore, c.NotAfter, c.CreatedAt = time.Unix(nb, 0).UTC(), time.Unix(na, 0).UTC(), time.Unix(cr, 0).UTC()
	return c, nil
}

// GetCA returns one CA.
func (s *Store) GetCA(ctx context.Context, id string) (CA, error) {
	c, err := scanCA(s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return CA{}, ErrNotFound
	}
	return c, err
}

// ListCAs returns all CAs ordered by name.
func (s *Store) ListCAs(ctx context.Context) ([]CA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+caColumns+` FROM cas ORDER BY name`)
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

// DropCAKey erases the stored private key of a CA. Callers must have handed
// the key to the operator first: this is how a Root goes offline, and it
// cannot be undone.
func (s *Store) DropCAKey(ctx context.Context, actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE cas SET key_blob = NULL WHERE id = ? AND key_blob IS NOT NULL`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return s.appendAudit(ctx, tx, actor, "ca.drop_key", id, "")
	})
}

// ---- issued certificates ----

// Certificate is an issued service certificate. Private keys are never stored.
type Certificate struct {
	ID           string
	CAID         string
	Serial       string // hex
	CommonName   string
	SANs         []string
	Profile      string
	CertPEM      []byte
	NotBefore    time.Time
	NotAfter     time.Time
	KeyGenerated bool // the key was generated by the service and handed out once
	CreatedAt    time.Time
}

// AddCertificate records an issued certificate and returns its ID.
func (s *Store) AddCertificate(ctx context.Context, actor string, c Certificate) (string, error) {
	if c.CAID == "" || c.Serial == "" || c.CommonName == "" || len(c.CertPEM) == 0 {
		return "", fmt.Errorf("%w: CA, serial, common name and certificate are required", ErrInvalid)
	}
	sans, err := json.Marshal(c.SANs)
	if err != nil {
		return "", err
	}
	id := NewID()
	err = s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO certificates (id, ca_id, serial, common_name, sans, profile, cert_pem, not_before, not_after, key_generated, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, c.CAID, c.Serial, c.CommonName, string(sans), c.Profile, c.CertPEM,
			c.NotBefore.Unix(), c.NotAfter.Unix(), c.KeyGenerated, s.now().Unix())
		if err != nil {
			if isUnique(err) {
				return ErrExists
			}
			if strings.Contains(err.Error(), "FOREIGN KEY") {
				return fmt.Errorf("%w: unknown CA", ErrInvalid)
			}
			return err
		}
		return s.appendAudit(ctx, tx, actor, "cert.issue", id, fmt.Sprintf("ca=%s cn=%s serial=%s", c.CAID, c.CommonName, c.Serial))
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

const certColumns = `id, ca_id, serial, common_name, sans, profile, cert_pem, not_before, not_after, key_generated, created_at`

func scanCert(r scanner) (Certificate, error) {
	var c Certificate
	var sans string
	var nb, na, cr int64
	if err := r.Scan(&c.ID, &c.CAID, &c.Serial, &c.CommonName, &sans, &c.Profile, &c.CertPEM, &nb, &na, &c.KeyGenerated, &cr); err != nil {
		return Certificate{}, err
	}
	if err := json.Unmarshal([]byte(sans), &c.SANs); err != nil {
		return Certificate{}, err
	}
	c.NotBefore, c.NotAfter, c.CreatedAt = time.Unix(nb, 0).UTC(), time.Unix(na, 0).UTC(), time.Unix(cr, 0).UTC()
	return c, nil
}

// GetCertificate returns one certificate.
func (s *Store) GetCertificate(ctx context.Context, id string) (Certificate, error) {
	c, err := scanCert(s.db.QueryRowContext(ctx, `SELECT `+certColumns+` FROM certificates WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	return c, err
}

// ListCertificates returns certificates, soonest-to-expire first. caID may be
// empty for all CAs.
func (s *Store) ListCertificates(ctx context.Context, caID string) ([]Certificate, error) {
	return s.listCerts(ctx, `SELECT `+certColumns+` FROM certificates WHERE (? = '' OR ca_id = ?) ORDER BY not_after`, caID, caID)
}

// ExpiringBefore returns certificates whose validity ends before t, including
// those already expired, soonest first.
func (s *Store) ExpiringBefore(ctx context.Context, t time.Time) ([]Certificate, error) {
	return s.listCerts(ctx, `SELECT `+certColumns+` FROM certificates WHERE not_after < ? ORDER BY not_after`, t.Unix())
}

func (s *Store) listCerts(ctx context.Context, query string, args ...any) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AuditEvent records an event that changes no stored row, such as a key export
// or a login. Detail must never contain secrets.
func (s *Store) AuditEvent(ctx context.Context, actor, action, target, detail string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		return s.appendAudit(ctx, tx, actor, action, target, detail)
	})
}

// SetClock replaces the time source. It exists for tests of time-dependent
// behaviour (lockouts, session expiry) and must not be used in production code.
func (s *Store) SetClock(now func() time.Time) { s.now = now }
