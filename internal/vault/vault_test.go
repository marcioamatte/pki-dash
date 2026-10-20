package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const pass = "correct horse battery staple"

// newTest builds a vault at the minimum KDF cost so tests stay fast.
func newTest(t *testing.T) (*Header, *Vault) {
	t.Helper()
	h, v, err := initWith(pass, minParams)
	if err != nil {
		t.Fatal(err)
	}
	return h, v
}

func TestSealOpenRoundTrip(t *testing.T) {
	_, v := newTest(t)
	secret := []byte("-----BEGIN PRIVATE KEY-----\nsuper secret\n-----END PRIVATE KEY-----")
	blob, err := v.Seal("ca-1", secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("super secret")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := v.Open("ca-1", blob)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestSealIsRandomised(t *testing.T) {
	_, v := newTest(t)
	a, _ := v.Seal("id", []byte("same"))
	b, _ := v.Seal("id", []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("sealing twice must not give identical blobs (fresh DEK and nonces)")
	}
}

func TestUnlock(t *testing.T) {
	h, v := newTest(t)
	blob, _ := v.Seal("id", []byte("secret"))

	// Through a marshal round trip, as it would be persisted.
	h2, err := ParseHeader(h.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	v2, err := Unlock(h2, pass)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if got, err := v2.Open("id", blob); err != nil || string(got) != "secret" {
		t.Fatalf("Open after unlock = %q, %v", got, err)
	}
	if _, err := Unlock(h2, "wrong passphrase here"); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: err = %v", err)
	}
}

func TestPassphraseMinimum(t *testing.T) {
	if _, _, err := initWith("short", minParams); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("err = %v, want ErrWeakPassphrase", err)
	}
	// Characters, not bytes: 12 two-byte runes pass, 11 do not.
	if _, _, err := initWith(strings.Repeat("ç", 11), minParams); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("11 runes: err = %v, want ErrWeakPassphrase", err)
	}
	if _, _, err := initWith(strings.Repeat("ç", 12), minParams); err != nil {
		t.Fatalf("12 runes should be accepted: %v", err)
	}
}

func TestBlobBoundToID(t *testing.T) {
	_, v := newTest(t)
	blob, _ := v.Seal("root-ca", []byte("root key"))
	// A database writer swapping blobs between records must be detected.
	if _, err := v.Open("intermediate-ca", blob); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestTamperingIsDetectedInEveryRegion(t *testing.T) {
	_, v := newTest(t)
	blob, _ := v.Seal("id", []byte("secret key material"))
	for i := range blob {
		bad := bytes.Clone(blob)
		bad[i] ^= 0x01
		if _, err := v.Open("id", bad); err == nil {
			t.Fatalf("flipping byte %d went undetected", i)
		}
	}
	for _, n := range []int{0, 1, 10, len(blob) - 1} {
		if _, err := v.Open("id", blob[:n]); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("truncated to %d: err = %v", n, err)
		}
	}
}

func TestWrongVaultCannotOpen(t *testing.T) {
	_, a := newTest(t)
	_, b := newTest(t) // same passphrase, different salt, different KEK
	blob, _ := a.Seal("id", []byte("secret"))
	if _, err := b.Open("id", blob); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

func TestLock(t *testing.T) {
	_, v := newTest(t)
	blob, _ := v.Seal("id", []byte("secret"))
	v.Lock()
	if _, err := v.Open("id", blob); !errors.Is(err, ErrLocked) {
		t.Fatalf("Open: err = %v, want ErrLocked", err)
	}
	if _, err := v.Seal("id", []byte("x")); !errors.Is(err, ErrLocked) {
		t.Fatalf("Seal: err = %v, want ErrLocked", err)
	}
}

func TestChangePassphrase(t *testing.T) {
	_, v := newTest(t)
	blob1, _ := v.Seal("ca-1", []byte("key one"))
	blob2, _ := v.Seal("ca-2", []byte("key two"))

	newPass := "a brand new passphrase!"
	h, rewrap, err := v.ChangePassphrase(newPass)
	if err != nil {
		t.Fatal(err)
	}
	n1, err := rewrap("ca-1", blob1)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := rewrap("ca-2", blob2)
	if err != nil {
		t.Fatal(err)
	}

	// The encrypted payload itself is untouched; only the wrapped DEK changed.
	if !bytes.Equal(n1[1+wrappedLen:], blob1[1+wrappedLen:]) {
		t.Fatal("data part must not change when only the passphrase changes")
	}
	if bytes.Equal(n1[1:1+wrappedLen], blob1[1:1+wrappedLen]) {
		t.Fatal("wrapped DEK must change")
	}

	nv, err := Unlock(h, newPass)
	if err != nil {
		t.Fatal(err)
	}
	for id, c := range map[string][2][]byte{"ca-1": {n1, []byte("key one")}, "ca-2": {n2, []byte("key two")}} {
		if got, err := nv.Open(id, c[0]); err != nil || !bytes.Equal(got, c[1]) {
			t.Fatalf("%s after rotation: %q, %v", id, got, err)
		}
	}
	// The old passphrase no longer unlocks the new header, and the new
	// vault cannot read the old blobs.
	if _, err := Unlock(h, pass); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("old passphrase: err = %v", err)
	}
	if _, err := nv.Open("ca-1", blob1); err == nil {
		t.Fatal("old blob must not open under the new KEK")
	}
	// Rewrapping under the wrong id must fail rather than silently rebind.
	if _, err := rewrap("ca-2", blob1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("rewrap wrong id: err = %v", err)
	}
	if _, _, err := v.ChangePassphrase("short"); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("weak new passphrase: err = %v", err)
	}
}

func TestHeaderValidation(t *testing.T) {
	h, _ := newTest(t)
	good := h.Marshal()

	mutate := func(f func(b []byte)) []byte {
		b := bytes.Clone(good)
		f(b)
		return b
	}
	// An attacker able to edit the stored header must not be able to
	// downgrade the KDF or make Unlock allocate absurd amounts of memory.
	huge := mutate(func(b []byte) { b[5], b[6], b[7], b[8] = 0xff, 0xff, 0xff, 0xff })
	if _, err := ParseHeader(huge); !errors.Is(err, ErrBadParams) {
		t.Fatalf("huge memory: err = %v, want ErrBadParams", err)
	}
	weak := mutate(func(b []byte) { b[1], b[2], b[3], b[4] = 0, 0, 0, 1 })
	if _, err := ParseHeader(weak); !errors.Is(err, ErrBadParams) {
		t.Fatalf("time=1: err = %v, want ErrBadParams", err)
	}
	if _, err := ParseHeader(good[:len(good)-1]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated: err = %v", err)
	}
	if _, err := ParseHeader(mutate(func(b []byte) { b[0] = 9 })); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad version: err = %v", err)
	}

	// A changed salt or verifier means the passphrase can no longer match.
	for _, i := range []int{10, len(good) - 1} {
		bad, err := ParseHeader(mutate(func(b []byte) { b[i] ^= 1 }))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Unlock(bad, pass); !errors.Is(err, ErrBadPassphrase) {
			t.Fatalf("tampered header byte %d: err = %v", i, err)
		}
	}
}

func TestDefaultParamsWithinAcceptedRange(t *testing.T) {
	if err := DefaultParams.validate(); err != nil {
		t.Fatalf("DefaultParams rejected by our own validation: %v", err)
	}
}
