#!/bin/sh
# Runs before the package is removed or upgraded (deb: remove|upgrade; rpm: 0|1).
set -e
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl stop pki-dash.service || true
            systemctl disable pki-dash.service || true
        fi
        ;;
esac
