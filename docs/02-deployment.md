# Deployment

> Translations: [pt-BR](02-deployment_pt-BR.md)

pki-dash ships as one container: a static binary with the web UI inside, running as an unprivileged user on a read-only filesystem, with one volume for data. It is meant for homelabs and internal networks (see the disclaimer in the README).

## Quick start with Docker Compose

```bash
mkdir certs
cp your-server.crt certs/tls.crt && cp your-server.key certs/tls.key
# The container runs as user 65532, so that user must be able to read the key:
docker run --rm -v "$PWD/certs:/certs" --user 0:0 busybox:stable \
  sh -c 'chown 65532:65532 /certs/tls.key && chmod 400 /certs/tls.key'
docker compose up -d --build
docker compose logs pki-dash | grep setup_token     # first run only
```

If the container restarts in a loop with `permission denied` on the key, that ownership step is the cause. (Compose `secrets:` do not help here: outside Swarm they ignore the requested owner and mode.)

Then open <https://localhost:8443>, enter the setup token, and create the first administrator and the **master passphrase**.

No certificate yet? For a quick try-out, change the `command` in `docker-compose.yml` to `["-tls-self-signed"]`. The server then makes a throwaway certificate and your browser will warn about it. Once you have your own CA here, use it to issue a proper certificate for pki-dash itself.

## How the server is served

The server refuses to start until you choose, explicitly, how it is reached:

| Option | Use |
|---|---|
| `-tls-cert FILE -tls-key FILE` | Your certificate. The normal choice. |
| `-tls-self-signed` | A throwaway certificate, for labs. |
| `-insecure-http` | Plain HTTP, for local development only. Cookies are not marked `Secure` and HSTS is off. |

Terminating TLS in a reverse proxy in front of pki-dash is **not supported yet**: the rate limiter keys on the connecting address, so every user would share the proxy's address, and forwarded headers are deliberately ignored until trusted-proxy support exists. Serve TLS from pki-dash itself.

Environment variables (flags win): `PKI_DASH_DATA_DIR` (default `/data` in the image), `PKI_DASH_LISTEN` (default `0.0.0.0:8443` in the image), `PKI_DASH_TLS_CERT`, `PKI_DASH_TLS_KEY`.

To let people sign in through Keycloak or another OpenID Connect provider, see [Signing in with Keycloak](05-sso-keycloak.md). It adds options of its own (`-external-url`, `-oidc-*`).

## The master passphrase and restarts

CA private keys are encrypted with the master passphrase and are **never** decrypted on disk. After every start, the vault is locked: sign in as an administrator and unlock it from the UI (or `POST /api/v1/vault/unlock`) before issuing certificates. There is no recovery if the passphrase is lost.

## Backups

All state lives in the data volume: the SQLite database (users, CAs, encrypted keys, issued certificates, audit log). Back it up while the container is stopped, so the database and its write-ahead log are consistent:

```bash
docker compose stop pki-dash
docker run --rm -v pki-dash_pki-data:/data -v "$PWD":/backup busybox:stable \
  tar czf /backup/pki-data-$(date +%F).tgz -C /data .
docker compose start pki-dash
```

Keep the backup and the master passphrase **in different places**: together they are everything an attacker needs. The volume name above assumes the default Compose project name; check yours with `docker volume ls`.

## Upgrading

```bash
git pull && docker compose up -d --build
```

The schema migrates in place on start, and the server refuses to open a database written by a newer version than itself.

## What the container does for you

- Runs as `65532:65532`, never root; the image has no shell and no package manager.
- Read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, a PID limit and a memory limit (password hashing uses about 64 MiB per concurrent login, at most 4 at a time).
- The data directory is `0700` and the database file `0600`.
- A health check (`pki-dash healthcheck`) so orchestrators can tell when it is serving.
- Base images are pinned by digest and updated through Dependabot pull requests.

## Limits to know about

- One instance only: no clustering or high availability.
- The login lockout is per account, so someone who knows a username can keep it locked; the per-address rate limit is the mitigation.
- Publish the port on one interface (the Compose file binds to `127.0.0.1`) and reach it over a network you trust.
