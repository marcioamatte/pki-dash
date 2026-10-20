package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var fast = PasswordParams{Time: 2, Memory: 19 * 1024, Threads: 1}

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := hashPassword("correct horse battery", fast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("not PHC format: %s", h)
	}
	if ok, rehash, err := verifyPassword("correct horse battery", h, fast); !ok || rehash || err != nil {
		t.Fatalf("verify = %v %v %v", ok, rehash, err)
	}
	if ok, _, err := verifyPassword("wrong", h, fast); ok || err != nil {
		t.Fatalf("wrong password: %v %v", ok, err)
	}
	h2, _ := hashPassword("correct horse battery", fast)
	if h == h2 {
		t.Fatal("the same password must hash differently each time (random salt)")
	}
}

func TestNeedsRehash(t *testing.T) {
	h, _ := hashPassword("correct horse battery", fast)
	stronger := PasswordParams{Time: 3, Memory: 32 * 1024, Threads: 1}
	ok, rehash, err := verifyPassword("correct horse battery", h, stronger)
	if !ok || !rehash || err != nil {
		t.Fatalf("verify = %v %v %v", ok, rehash, err)
	}
	// A wrong password must never be reported as needing rehash.
	if _, rehash, _ := verifyPassword("nope", h, stronger); rehash {
		t.Fatal("rehash flagged for a wrong password")
	}
}

// A tampered database record must not be able to make a login expensive or
// weak, nor crash the parser.
func TestHostileHashesAreRejectedCheaply(t *testing.T) {
	good, _ := hashPassword("pw", fast)
	salt := strings.Split(good, "$")[4]
	sum := strings.Split(good, "$")[5]
	cases := map[string]string{
		"huge memory":        "$argon2id$v=19$m=4294967295,t=2,p=1$" + salt + "$" + sum,
		"huge time":          "$argon2id$v=19$m=19456,t=4294967295,p=1$" + salt + "$" + sum,
		"too many lanes":     "$argon2id$v=19$m=19456,t=2,p=255$" + salt + "$" + sum,
		"time below floor":   "$argon2id$v=19$m=19456,t=1,p=1$" + salt + "$" + sum,
		"memory below floor": "$argon2id$v=19$m=8,t=2,p=1$" + salt + "$" + sum,
		"wrong algorithm":    strings.Replace(good, "argon2id", "argon2i", 1),
		"wrong version":      strings.Replace(good, "v=19", "v=16", 1),
		"short salt":         "$argon2id$v=19$m=19456,t=2,p=1$AAAA$" + sum,
		"short hash":         "$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$AAAA",
		"bad base64":         "$argon2id$v=19$m=19456,t=2,p=1$!!!$" + sum,
		"unknown param":      "$argon2id$v=19$m=19456,t=2,p=1,x=1$" + salt + "$" + sum,
		"missing fields":     "$argon2id$v=19$m=19456,t=2,p=1$" + salt,
		"empty":              "",
		"plaintext":          "hunter2",
	}
	for name, enc := range cases {
		start := time.Now()
		ok, _, err := verifyPassword("pw", enc, fast)
		if ok || !errors.Is(err, errBadHash) {
			t.Errorf("%s: ok=%v err=%v, want errBadHash", name, ok, err)
		}
		if time.Since(start) > 200*time.Millisecond {
			t.Errorf("%s: rejection was not cheap", name)
		}
	}
}

func TestHashRefusesOutOfRangeParams(t *testing.T) {
	if _, err := hashPassword("pw", PasswordParams{Time: 1, Memory: 1024, Threads: 1}); err == nil {
		t.Fatal("must refuse parameters below the floor")
	}
}
