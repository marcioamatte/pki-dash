package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writePair makes a certificate and its key in dir and returns their paths.
func writePair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func mustContain(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	for _, p := range parts {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("%q does not mention %q", err, p)
		}
	}
}

func TestLoadTLSKeyPair(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir)
	if _, err := loadTLSKeyPair(cert, key); err != nil {
		t.Fatal(err)
	}

	_, err := loadTLSKeyPair(filepath.Join(dir, "nope.crt"), key)
	mustContain(t, err, "does not exist", "nope.crt")

	garbage := filepath.Join(dir, "garbage.crt")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = loadTLSKeyPair(garbage, key)
	mustContain(t, err, "cannot be used", "PEM")

	// A key from another certificate.
	otherCert, otherKey := writePair(t, t.TempDir())
	_ = otherCert
	_, err = loadTLSKeyPair(cert, otherKey)
	mustContain(t, err, "cannot be used", "belongs to the certificate")
}

func TestLoadTLSKeyPairExplainsAFileTheServiceCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything, so a permission error cannot be provoked")
	}
	dir := t.TempDir()
	cert, key := writePair(t, dir)
	for name, unreadable := range map[string]string{"certificate": cert, "key": key} {
		if err := os.Chmod(unreadable, 0); err != nil {
			t.Fatal(err)
		}
		_, err := loadTLSKeyPair(cert, key)
		mustContain(t, err, "permission denied", "unprivileged user", "pki-dash", "readable by it", unreadable)
		if err := os.Chmod(unreadable, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: ok", name)
	}
}

func TestExplainListenError(t *testing.T) {
	denied := &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EACCES)}
	mustContain(t, explainListenError("172.30.0.147:443", denied), "cannot listen on 172.30.0.147:443", "below 1024", "CAP_NET_BIND_SERVICE", "docs/06-installation.md")
	if e := explainListenError("172.30.0.147:8443", denied); strings.Contains(e.Error(), "CAP_NET_BIND_SERVICE") {
		t.Errorf("a high port must not get the low-port advice: %v", e)
	}
	mustContain(t, explainListenError(":8443", denied), "not allowed to open")

	inUse := &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	mustContain(t, explainListenError("0.0.0.0:8443", inUse), "already listening")

	notMine := &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EADDRNOTAVAIL)}
	mustContain(t, explainListenError("192.0.2.1:8443", notMine), "not assigned to this machine")

	mustContain(t, explainListenError("x:1", os.ErrInvalid), "cannot listen on x:1")
}

func TestListenOnReportsAnAddressInUse(t *testing.T) {
	first, err := listenOn("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, err = listenOn(first.Addr().String())
	mustContain(t, err, "already listening", first.Addr().String())
}

func TestRunStopsEarlyAndClearlyOnAnUnreadableCertificate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	dir := t.TempDir()
	cert, key := writePair(t, dir)
	if err := os.Chmod(cert, 0); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PKI_DASH_TLS_CERT", cert)
	t.Setenv("PKI_DASH_TLS_KEY", key)
	data := filepath.Join(dir, "data")
	err := run(context.Background(), []string{"-data-dir", data, "-listen", "127.0.0.1:0"})
	mustContain(t, err, "cannot read the TLS certificate or key", "readable by it")
	if _, statErr := os.Stat(data); statErr == nil {
		t.Error("the database directory must not have been created: the check comes before anything is opened")
	}
}
