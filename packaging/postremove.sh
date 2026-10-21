#!/bin/sh
# Runs after the package is removed. The database is NEVER deleted here: it holds
# your CAs' encrypted keys and the audit log. Remove /var/lib/pki-dash yourself,
# once you are sure you will not need it.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
