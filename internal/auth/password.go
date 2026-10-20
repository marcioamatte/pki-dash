package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordParams are the Argon2id cost parameters for user passwords.
type PasswordParams struct {
	Time    uint32 // passes
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultPasswordParams is used for new hashes.
var DefaultPasswordParams = PasswordParams{Time: 3, Memory: 64 * 1024, Threads: 4}

// Accepted range for hashes read back from the database. The floor is the
// OWASP minimum Argon2id profile; the ceiling stops a tampered record from
// making a login attempt exhaust the host's memory.
var (
	minPasswordParams = PasswordParams{Time: 2, Memory: 19 * 1024, Threads: 1}
	maxPasswordParams = PasswordParams{Time: 10, Memory: 256 * 1024, Threads: 16}
)

const (
	saltLen    = 16
	hashLen    = 32
	maxPwBytes = 1024 // hard cap on input, whatever the policy says
)

var errBadHash = errors.New("auth: malformed password hash")

func (p PasswordParams) valid() bool {
	return p.Time >= minPasswordParams.Time && p.Memory >= minPasswordParams.Memory && p.Threads >= minPasswordParams.Threads &&
		p.Time <= maxPasswordParams.Time && p.Memory <= maxPasswordParams.Memory && p.Threads <= maxPasswordParams.Threads
}

// hashPassword returns a PHC-format string:
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func hashPassword(pw string, p PasswordParams) (string, error) {
	if !p.valid() {
		return "", errors.New("auth: password parameters out of the accepted range")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, hashLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(sum)), nil
}

// verifyPassword checks pw against an encoded hash in constant time. needsRehash
// reports a correct password whose hash uses weaker parameters than current.
func verifyPassword(pw, encoded string, current PasswordParams) (ok, needsRehash bool, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return false, false, errBadHash
	}
	var p PasswordParams
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, found := strings.Cut(kv, "=")
		n, perr := strconv.ParseUint(v, 10, 32)
		if !found || perr != nil {
			return false, false, errBadHash
		}
		switch k {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Time = uint32(n)
		case "p":
			if n > 255 {
				return false, false, errBadHash
			}
			p.Threads = uint8(n)
		default:
			return false, false, errBadHash
		}
	}
	if !p.valid() {
		return false, false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(want) < 16 || len(want) > 64 {
		return false, false, errBadHash
	}
	got := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	return true, p.Time < current.Time || p.Memory < current.Memory || p.Threads < current.Threads, nil
}
