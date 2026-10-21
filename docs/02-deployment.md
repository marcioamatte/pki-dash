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
| `-insecure-http` | Plain HTTP: local development, or behind a reverse proxy (see below). On its own, cookies are not marked `Secure` and HSTS is off. |

## Behind a reverse proxy

You can put pki-dash behind a proxy that terminates TLS (nginx, Traefik, Caddy, HAProxy...). Tell pki-dash which proxies to believe:

```bash
pki-dash -insecure-http -listen 172.17.0.1:8080 -trusted-proxies 172.17.0.2
```

`-trusted-proxies` (`PKI_DASH_TRUSTED_PROXIES`) takes addresses and CIDR ranges, separated by commas. What changes:

- **The client's address** is read from `X-Forwarded-For`, but only on connections that come from a listed proxy, and reading from the right: the first address that is not itself a listed proxy. Entries a client put on the left of the header are never used, so nobody can pick the address they are rate-limited and logged under. From any other connection the header is ignored.
- **Sessions are always `Secure`** (with the `__Host-` cookie name and HSTS), because the browser speaks https even though the listener behind the proxy may not. That is why `-insecure-http` is the normal companion of this option here: the plain listener is for the proxy alone, so bind it to an address only the proxy can reach.
- **The cross-origin check** compares the browser's `Origin` with the host the browser used, taken from `X-Forwarded-Host` when it comes from a listed proxy.
- A listed proxy that reports `X-Forwarded-Proto: http` is answered with an explanatory error instead of letting login fail silently.
- A range that would trust every address (`0.0.0.0/0`, `::/0`) is refused at start-up.

The proxy must send `X-Forwarded-For` (appending, not replacing: `$proxy_add_x_forwarded_for` in nginx), `X-Forwarded-Proto` and, if it changes the `Host` header, `X-Forwarded-Host`. This is the nginx configuration it was tested with:

```nginx
server {
    listen 8443 ssl;
    ssl_certificate     /etc/nginx/tls.crt;
    ssl_certificate_key /etc/nginx/tls.key;
    location / {
        proxy_pass http://172.17.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Traefik and Caddy add these headers on their own; check that yours do. For sign-in with Keycloak, `-external-url` is the address of the **proxy**, as the browser sees it.

**List only the proxy itself, not the networks your users sit in.** If a client's own address falls inside a listed range, that client counts as a proxy and its forged headers would be believed. A proxy on the same machine as the browser is the typical way to get this wrong in a test: `127.0.0.1` would then be both.

Environment variables (flags win): `PKI_DASH_DATA_DIR` (default `/data` in the image), `PKI_DASH_LISTEN` (default `0.0.0.0:8443` in the image), `PKI_DASH_TLS_CERT`, `PKI_DASH_TLS_KEY`, `PKI_DASH_TRUSTED_PROXIES`.

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
