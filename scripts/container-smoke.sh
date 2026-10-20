#!/usr/bin/env bash
# Builds nothing: runs assertions against an already-built image.
#   usage: scripts/container-smoke.sh pki-dash:test
set -euo pipefail
IMG=${1:?usage: container-smoke.sh IMAGE}
NAME=pkid-smoke-$$
VOL=$NAME-data
PORT=${PORT:-18445}
BASE=https://127.0.0.1:$PORT
fail() { echo "FAIL: $*" >&2; docker logs "$NAME" 2>&1 | tail -20 >&2 || true; exit 1; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; docker volume rm -f "$VOL" >/dev/null 2>&1 || true; rm -f "$JAR"; }
JAR=$(mktemp)
trap cleanup EXIT

# --- the image itself ---------------------------------------------------------
user=$(docker image inspect "$IMG" --format '{{.Config.User}}')
[ "$user" = "65532:65532" ] || fail "image must run as 65532:65532, got '$user'"

if docker run --rm --entrypoint /bin/sh "$IMG" -c true >/dev/null 2>&1; then
  fail "the image must not contain a shell"
fi

out=$(docker run --rm "$IMG" 2>&1 || true)
echo "$out" | grep -q "choose exactly one of" || fail "must refuse to start without a TLS choice, got: $out"

# --- run it the way the compose file does -------------------------------------
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" -v "$VOL:/data" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 128 --memory 512m \
  "$IMG" -tls-self-signed >/dev/null

for _ in $(seq 1 60); do
  [ "$(docker inspect "$NAME" --format '{{.State.Health.Status}}')" = healthy ] && break
  sleep 1
done
[ "$(docker inspect "$NAME" --format '{{.State.Health.Status}}')" = healthy ] || fail "container never became healthy"

k() { curl -sk --max-time 20 "$@"; }
J='Content-Type: application/json'

# --- behaviour ----------------------------------------------------------------
headers=$(k -D- -o /dev/null "$BASE/")
echo "$headers" | head -1 | grep -q 200 || fail "UI not served"
echo "$headers" | grep -qi "content-security-policy: default-src 'self'" || fail "UI lacks its CSP"
k "$BASE/api/v1/status" | grep -q '"needs_setup":true' || fail "fresh instance should need setup"

TOK=$(docker logs "$NAME" 2>&1 | grep -o '"setup_token":"[^"]*"' | cut -d'"' -f4)
[ -n "$TOK" ] || fail "no setup token in the logs"
k -X POST "$BASE/api/v1/setup" -H "$J" \
  -d "{\"setup_token\":\"$TOK\",\"username\":\"smoke-admin\",\"password\":\"lantern kettle orchid 123\",\"master_passphrase\":\"granite harbor lantern 789\"}" \
  | grep -q '"vault_initialized":true' || fail "setup failed"
code=$(k -c "$JAR" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/login" -H "$J" \
  -d '{"username":"smoke-admin","password":"lantern kettle orchid 123"}')
[ "$code" = 200 ] || fail "login returned $code"

# State survives a restart, and the vault comes back locked.
docker restart "$NAME" >/dev/null
for _ in $(seq 1 30); do k "$BASE/api/v1/status" | grep -q needs_setup && break; sleep 1; done
status=$(k "$BASE/api/v1/status")
echo "$status" | grep -q '"needs_setup":false' || fail "data lost across restart: $status"
echo "$status" | grep -q '"vault_unlocked":false' || fail "vault must be locked after a restart: $status"

if docker logs "$NAME" 2>&1 | grep -q 'granite harbor\|lantern kettle'; then
  fail "a secret appeared in the container logs"
fi
echo "container smoke test passed"
