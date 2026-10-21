#!/bin/sh
# Runs after the package is installed or upgraded (deb: configure; rpm: 1 or 2).
set -e

# The service account.
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/pki-dash.conf
elif ! getent passwd pki-dash >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /var/lib/pki-dash \
        --shell /usr/sbin/nologin pki-dash
fi

# The settings may name a TLS key: the directory is readable by the service, not by everyone.
if [ -d /etc/pki-dash ]; then
    chgrp pki-dash /etc/pki-dash
    chmod 0750 /etc/pki-dash
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # An upgrade restarts a running service (security fixes must take effect); it never starts a stopped one.
    systemctl try-restart pki-dash.service || true
fi

cat <<'MSG'

pki-dash is installed but not started. Next:
  1. Edit /etc/pki-dash/pki-dash.env and choose how it is served (a TLS certificate, as a rule).
  2. sudo systemctl enable --now pki-dash
  3. sudo journalctl -u pki-dash | grep setup_token      (first run only: the one-time setup token)
Optional sign-in with Keycloak: see /etc/pki-dash/oidc.env.example.
Documentation: /usr/share/doc/pki-dash/

MSG
