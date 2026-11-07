package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strconv"
	"syscall"
)

// What follows turns the two failures a first install meets most often into
// messages that say what to do: a certificate or key the service cannot read,
// and an address it cannot listen on. Both used to surface as a bare operating
// system error, after the log had already announced "serving".

// loadTLSKeyPair reads the operator's certificate and key at start-up, before
// anything is announced, so a mistake stops the server with an explanation.
func loadTLSKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	switch {
	case err == nil:
		return c, nil
	case errors.Is(err, fs.ErrPermission):
		return tls.Certificate{}, fmt.Errorf("cannot read the TLS certificate or key: %w. "+
			"The server runs as an unprivileged user (pki-dash, when installed from a package) and both files must be readable by it: "+
			"for example chgrp pki-dash on both, chmod 644 on the certificate and chmod 640 on the key (see docs/06-installation.md)", err)
	case errors.Is(err, fs.ErrNotExist):
		return tls.Certificate{}, fmt.Errorf("a TLS file does not exist: %w. Check the paths in the settings (certificate %s, key %s)", err, certFile, keyFile)
	}
	return tls.Certificate{}, fmt.Errorf("the TLS certificate and key cannot be used: %w. "+
		"Both must be PEM files, and the key must be the one that belongs to the certificate", err)
}

// listenOn opens the listening socket itself, so the announcement can wait for
// it to succeed and a failure can be explained.
func listenOn(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, explainListenError(addr, err)
	}
	return ln, nil
}

func explainListenError(addr string, err error) error {
	port := 0
	if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		port, _ = strconv.Atoi(p)
	}
	switch {
	case errors.Is(err, os.ErrPermission) && port > 0 && port < 1024:
		return fmt.Errorf("cannot listen on %s: %w. Ports below 1024 need the capability CAP_NET_BIND_SERVICE, "+
			"which the packaged systemd service does not have: add the drop-in described in docs/06-installation.md, "+
			"or use a port from 1024 up", addr, err)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("cannot listen on %s: %w. The server is not allowed to open that address", addr, err)
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Errorf("cannot listen on %s: %w. Something else is already listening there: choose another address or port, or stop that program", addr, err)
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return fmt.Errorf("cannot listen on %s: %w. That address is not assigned to this machine: check the listen address in the settings", addr, err)
	}
	return fmt.Errorf("cannot listen on %s: %w", addr, err)
}
