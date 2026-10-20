// Package vault encrypts secrets (CA private keys) at rest.
//
// It uses envelope encryption:
//
//	master passphrase --Argon2id--> KEK (key-encryption key)
//	KEK --AES-256-GCM--> wraps a random DEK (data-encryption key) per secret
//	DEK --AES-256-GCM--> encrypts the secret
//
// Because every secret has its own DEK, changing the passphrase only re-wraps
// the small DEKs; the encrypted secrets themselves are untouched. Each blob
// is bound to its ID through the AEAD associated data, so a database writer
// cannot swap the encrypted key of one CA for another's.
//
// There is no recovery path: a lost passphrase means lost keys.
//
// Go cannot guarantee that secrets are wiped from memory. Lock zeroes the
// KEK on a best-effort basis, which narrows but does not close that window.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// MinPassphraseLen is the minimum passphrase length, in characters.
	MinPassphraseLen = 12

	keyLen   = 32 // AES-256
	saltLen  = 16
	nonceLen = 12
	tagLen   = 16
	version  = 1
)

var (
	ErrWeakPassphrase = errors.New("vault: passphrase too short")
	ErrLocked         = errors.New("vault: locked")
	ErrBadPassphrase  = errors.New("vault: wrong passphrase")
	ErrCorrupt        = errors.New("vault: corrupt or tampered data")
	ErrBadParams      = errors.New("vault: KDF parameters out of the accepted range")
)

// Params are the Argon2id cost parameters. They are stored in the Header so
// they can be raised later without breaking existing vaults.
type Params struct {
	Time    uint32 // passes
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultParams is used for new vaults.
var DefaultParams = Params{Time: 3, Memory: 64 * 1024, Threads: 4}

// Accepted range. The floor prevents a downgrade by someone who can edit the
// stored header (OWASP's minimum Argon2id profile); the ceiling stops that
// same person from making Unlock exhaust the host's memory.
var (
	minParams = Params{Time: 2, Memory: 19 * 1024, Threads: 1}
	maxParams = Params{Time: 10, Memory: 1024 * 1024, Threads: 16}
)

func (p Params) validate() error {
	if p.Time < minParams.Time || p.Memory < minParams.Memory || p.Threads < minParams.Threads ||
		p.Time > maxParams.Time || p.Memory > maxParams.Memory || p.Threads > maxParams.Threads {
		return ErrBadParams
	}
	return nil
}

// Header is the public, non-secret state needed to unlock a vault. Persist
// it with Marshal and restore it with ParseHeader.
type Header struct {
	Params   Params
	Salt     [saltLen]byte
	Verifier []byte // known plaintext sealed under the KEK; proves the passphrase
}

// headerLen is the size of a marshaled header: version, params, salt, verifier.
const headerLen = 1 + 4 + 4 + 1 + saltLen + nonceLen + len(verifierText) + tagLen

const verifierText = "pki-dash vault verifier"

// Marshal encodes the header.
func (h *Header) Marshal() []byte {
	b := make([]byte, 0, headerLen)
	b = append(b, version)
	b = binary.BigEndian.AppendUint32(b, h.Params.Time)
	b = binary.BigEndian.AppendUint32(b, h.Params.Memory)
	b = append(b, h.Params.Threads)
	b = append(b, h.Salt[:]...)
	return append(b, h.Verifier...)
}

// ParseHeader decodes and validates a header produced by Marshal.
func ParseHeader(b []byte) (*Header, error) {
	if len(b) != headerLen || b[0] != version {
		return nil, ErrCorrupt
	}
	h := &Header{Params: Params{
		Time:    binary.BigEndian.Uint32(b[1:5]),
		Memory:  binary.BigEndian.Uint32(b[5:9]),
		Threads: b[9],
	}}
	if err := h.Params.validate(); err != nil {
		return nil, err
	}
	copy(h.Salt[:], b[10:10+saltLen])
	h.Verifier = append([]byte(nil), b[10+saltLen:]...)
	return h, nil
}

// Vault holds the unlocked KEK in memory.
type Vault struct {
	mu  sync.RWMutex
	kek []byte
}

func checkPassphrase(p string) error {
	if utf8.RuneCountInString(p) < MinPassphraseLen {
		return fmt.Errorf("%w: need at least %d characters", ErrWeakPassphrase, MinPassphraseLen)
	}
	return nil
}

func deriveKEK(passphrase string, salt []byte, p Params) []byte {
	return argon2.IDKey([]byte(passphrase), salt, p.Time, p.Memory, p.Threads, keyLen)
}

// Init creates a new vault protected by passphrase.
func Init(passphrase string) (*Header, *Vault, error) {
	return initWith(passphrase, DefaultParams)
}

func initWith(passphrase string, p Params) (*Header, *Vault, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, nil, err
	}
	if err := p.validate(); err != nil {
		return nil, nil, err
	}
	h := &Header{Params: p}
	if _, err := rand.Read(h.Salt[:]); err != nil {
		return nil, nil, err
	}
	kek := deriveKEK(passphrase, h.Salt[:], p)
	v, err := seal(kek, []byte(verifierText), []byte("verifier"))
	if err != nil {
		return nil, nil, err
	}
	h.Verifier = v
	return h, &Vault{kek: kek}, nil
}

// Unlock derives the KEK and checks it against the header's verifier.
func Unlock(h *Header, passphrase string) (*Vault, error) {
	if err := h.Params.validate(); err != nil {
		return nil, err
	}
	kek := deriveKEK(passphrase, h.Salt[:], h.Params)
	pt, err := open(kek, h.Verifier, []byte("verifier"))
	if err != nil || subtle.ConstantTimeCompare(pt, []byte(verifierText)) != 1 {
		zero(kek)
		return nil, ErrBadPassphrase
	}
	return &Vault{kek: kek}, nil
}

// Lock zeroes the KEK. The Vault is unusable afterwards.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	zero(v.kek)
	v.kek = nil
}

// Seal encrypts plaintext under a fresh DEK, bound to id.
//
// Blob layout: version(1) | wrapNonce(12) | wrappedDEK(32+16) | dataNonce(12) | ciphertext+tag.
func (v *Vault) Seal(id string, plaintext []byte) ([]byte, error) {
	kek, err := v.key()
	if err != nil {
		return nil, err
	}
	dek := make([]byte, keyLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer zero(dek)

	wrapped, err := seal(kek, dek, dekAAD(id))
	if err != nil {
		return nil, err
	}
	data, err := seal(dek, plaintext, dataAAD(id))
	if err != nil {
		return nil, err
	}
	return append(append([]byte{version}, wrapped...), data...), nil
}

// Open decrypts a blob produced by Seal for the same id.
func (v *Vault) Open(id string, blob []byte) ([]byte, error) {
	kek, err := v.key()
	if err != nil {
		return nil, err
	}
	wrapped, data, err := split(blob)
	if err != nil {
		return nil, err
	}
	dek, err := open(kek, wrapped, dekAAD(id))
	if err != nil {
		return nil, ErrCorrupt
	}
	defer zero(dek)
	pt, err := open(dek, data, dataAAD(id))
	if err != nil {
		return nil, ErrCorrupt
	}
	return pt, nil
}

// ChangePassphrase returns a new header for newPassphrase together with a
// function that re-wraps a blob from this vault to the new one. Only the
// DEK is re-encrypted; the secret itself is not touched. Callers must apply
// the function to every blob and persist the new header and the new blobs
// atomically, otherwise some secrets stay under the old passphrase.
func (v *Vault) ChangePassphrase(newPassphrase string) (*Header, func(id string, blob []byte) ([]byte, error), error) {
	oldKEK, err := v.key()
	if err != nil {
		return nil, nil, err
	}
	h, nv, err := Init(newPassphrase)
	if err != nil {
		return nil, nil, err
	}
	rewrap := func(id string, blob []byte) ([]byte, error) {
		wrapped, data, err := split(blob)
		if err != nil {
			return nil, err
		}
		dek, err := open(oldKEK, wrapped, dekAAD(id))
		if err != nil {
			return nil, ErrCorrupt
		}
		defer zero(dek)
		newWrapped, err := seal(nv.kek, dek, dekAAD(id))
		if err != nil {
			return nil, err
		}
		return append(append([]byte{version}, newWrapped...), data...), nil
	}
	return h, rewrap, nil
}

func (v *Vault) key() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.kek == nil {
		return nil, ErrLocked
	}
	return append([]byte(nil), v.kek...), nil
}

func dekAAD(id string) []byte  { return []byte("pki-dash/v1/dek|" + id) }
func dataAAD(id string) []byte { return []byte("pki-dash/v1/data|" + id) }

const wrappedLen = nonceLen + keyLen + tagLen

// split separates a blob into its wrapped DEK and its data parts.
func split(blob []byte) (wrapped, data []byte, err error) {
	if len(blob) < 1+wrappedLen+nonceLen+tagLen || blob[0] != version {
		return nil, nil, ErrCorrupt
	}
	return blob[1 : 1+wrappedLen], blob[1+wrappedLen:], nil
}

// seal returns nonce || ciphertext || tag.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen, nonceLen+len(plaintext)+tagLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < nonceLen+tagLen {
		return nil, ErrCorrupt
	}
	return gcm.Open(nil, sealed[:nonceLen], sealed[nonceLen:], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) { clear(b) }
