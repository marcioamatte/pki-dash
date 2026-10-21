// Command pki-dash is a web dashboard for managing an internal PKI.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/marcioamatte/pki-dash/internal/api"
	"github.com/marcioamatte/pki-dash/internal/auth"
	"github.com/marcioamatte/pki-dash/internal/service"
	"github.com/marcioamatte/pki-dash/internal/store"
	"github.com/marcioamatte/pki-dash/web"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pki-dash:", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func run(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "healthcheck" {
		return healthcheck(args[1:])
	}
	fs := flag.NewFlagSet("pki-dash", flag.ContinueOnError)
	dataDir := fs.String("data-dir", env("PKI_DASH_DATA_DIR", "./data"), "directory holding the database (env PKI_DASH_DATA_DIR)")
	listen := fs.String("listen", env("PKI_DASH_LISTEN", "127.0.0.1:8443"), "address to listen on (env PKI_DASH_LISTEN)")
	certFile := fs.String("tls-cert", env("PKI_DASH_TLS_CERT", ""), "TLS certificate file (env PKI_DASH_TLS_CERT)")
	keyFile := fs.String("tls-key", env("PKI_DASH_TLS_KEY", ""), "TLS private key file (env PKI_DASH_TLS_KEY)")
	selfSigned := fs.Bool("tls-self-signed", false, "serve TLS with a throwaway self-signed certificate (labs only)")
	pkiListen := fs.String("pki-listen", env("PKI_DASH_PKI_LISTEN", ""), "address of the public, read-only listener that serves CRLs and CA certificates over plain HTTP, e.g. 0.0.0.0:8080 (env PKI_DASH_PKI_LISTEN)")
	publicURL := fs.String("public-url", env("PKI_DASH_PUBLIC_URL", ""), "how clients reach that listener, e.g. http://pki.lab:8080; written into issued certificates (env PKI_DASH_PUBLIC_URL)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	insecure := fs.Bool("insecure-http", false, "serve plain HTTP: development, or behind a TLS-terminating proxy you trust")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("pki-dash", version)
		return nil
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	log.Info("starting", "version", version)

	// Refuse to guess about transport security: the operator must choose.
	modes := 0
	for _, on := range []bool{*certFile != "" || *keyFile != "", *selfSigned, *insecure} {
		if on {
			modes++
		}
	}
	switch {
	case modes != 1:
		return errors.New("choose exactly one of: -tls-cert with -tls-key, -tls-self-signed, or -insecure-http")
	case (*certFile == "") != (*keyFile == ""):
		return errors.New("-tls-cert and -tls-key must be given together")
	}

	base, err := service.NormalizePublicURL(*publicURL)
	if err != nil {
		return err
	}
	if base != "" && *pkiListen == "" {
		return errors.New("-public-url is set but there is no -pki-listen: nothing would serve the CRLs it points to")
	}
	if base == "" && *pkiListen != "" {
		log.Warn("-pki-listen without -public-url: CRLs are served, but issued certificates will not point to them")
	}

	st, err := store.Open(filepath.Join(*dataDir, "pki.db"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	svc := service.New(st, service.Options{PublicURL: base})
	au, err := auth.New(st, auth.Options{})
	if err != nil {
		return err
	}

	var setupToken string
	if need, err := au.NeedsSetup(ctx); err != nil {
		return err
	} else if need {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		setupToken = base64.RawURLEncoding.EncodeToString(b)
		// Printed once to the operator's console and never stored: whoever can
		// read it can reach this process, which is the trust we want.
		log.Warn("first run: complete setup in the web UI or API using this one-time token", "setup_token", setupToken)
	}

	srv := api.New(api.Options{
		Service: svc, Auth: au, Logger: log,
		SecureCookies: !*insecure, SetupToken: setupToken, UI: web.Dist(),
	})
	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	errc := make(chan error, 2)

	go func() { // expired sessions would otherwise pile up
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := au.PurgeExpired(ctx); err != nil {
					log.Error("purge sessions", "err", err)
				}
			}
		}
	}()

	// CRLs must be renewed before they expire. Signing needs the vault open, so
	// while it is locked this does nothing, and the first unlock catches up.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := svc.RefreshCRLs(ctx, "system", false); err != nil && !errors.Is(err, service.ErrLocked) {
					log.Error("refresh CRLs", "err", err)
				}
			}
		}
	}()

	var pubSrv *http.Server
	if *pkiListen != "" {
		pubSrv = &http.Server{
			Addr:              *pkiListen,
			Handler:           srv.PublicHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		go func() {
			log.Info("serving the public PKI listener (plain HTTP, read-only)", "addr", *pkiListen, "public_url", base)
			if err := pubSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	go func() {
		switch {
		case *insecure:
			log.Warn("serving plain HTTP: do not expose this port beyond a trusted network", "addr", *listen)
			errc <- httpSrv.ListenAndServe()
		case *selfSigned:
			cert, fp, err := selfSignedCert()
			if err != nil {
				errc <- err
				return
			}
			httpSrv.TLSConfig.Certificates = []tls.Certificate{cert}
			log.Warn("serving TLS with a throwaway self-signed certificate", "addr", *listen, "sha256", fp)
			errc <- httpSrv.ListenAndServeTLS("", "")
		default:
			log.Info("serving TLS", "addr", *listen)
			errc <- httpSrv.ListenAndServeTLS(*certFile, *keyFile)
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if pubSrv != nil {
		_ = pubSrv.Shutdown(shutdown)
	}
	return httpSrv.Shutdown(shutdown)
}

// selfSignedCert makes an in-memory certificate for localhost and this host.
func selfSignedCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "pki-dash (self-signed)"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

// healthcheck probes the running server and exits non-zero if it is not
// serving. It exists because the container image has no shell and no curl.
func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	listen := fs.String("listen", env("PKI_DASH_LISTEN", "127.0.0.1:8443"), "the server's listen address (env PKI_DASH_LISTEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return probe(*listen)
}

// probe asks the server at addr for its status. A wildcard listen address is
// probed on loopback. Certificate verification is skipped because the target
// is this very process, usually with a throwaway or private-CA certificate:
// the probe checks liveness, not identity.
func probe(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	target := net.JoinHostPort(host, port)
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // see above
		// Never follow redirects: they could point somewhere that is not this process.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		resp, err := client.Get(scheme + "://" + target + "/api/v1/status")
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unhealthy: status %d", resp.StatusCode)
		}
		return nil
	}
	return lastErr
}
