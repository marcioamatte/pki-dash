# pki-dash

A web dashboard to create and manage an internal PKI (Root CA, intermediate CAs and service certificates), built on top of Cloudflare's [cfssl](https://github.com/cloudflare/cfssl). Ships as a single container.

> Translations: [pt-BR](README_pt-BR.md)

> **Status: early development. The backend, JSON API and a first web UI (setup, sign-in, vault unlock, creating and listing CAs, issuing and downloading certificates, trust instructions per OS, users and roles, the audit log, taking a Root offline, importing a Root or intermediates signed elsewhere, revoking certificates and intermediates with CRLs, including a Root list signed offline) work. Not ready for real use.**

> **Disclaimer:** pki-dash is meant for internal environments such as homelabs, labs and test machines. It is **not** intended for public PKI or for settings where a CA compromise would have critical impact. It does not replace an HSM, a formal key ceremony or a commercial CA.

## Goals

- Root → intermediate → service certificate hierarchy, with the Root kept offline.
- Friendly UI for issuing certificates and distributing trust to hosts.
- Security first: CA keys encrypted at rest, mandatory authentication, multi-user roles, audit log, optional sign-in with Keycloak/OIDC.

## Running it (development)

```bash
make build                           # builds the web UI (needs Node 20.19+ or 22.12+), then the Go binary into bin/
./bin/pki-dash -tls-self-signed      # or -tls-cert/-tls-key, or -insecure-http for local development
```

Then open <https://localhost:8443>.

Or with Docker (a single container, unprivileged, read-only filesystem): see [Deployment](docs/02-deployment.md).

The server refuses to start unless you choose how it is served. On first run it prints a one-time **setup token** to its log; enter it in the web UI (or send it to `POST /api/v1/setup`) to create the first admin and the master passphrase. After every restart the vault is locked: unlock it from the UI (or `POST /api/v1/vault/unlock`), so CA keys never sit decrypted on disk.

## Documentation

- [Vision and scope](docs/00-vision-and-scope.md)
- [Stack decision](docs/01-stack-decision.md)
- [Deployment (Docker)](docs/02-deployment.md)
- [Keeping the Root offline](docs/03-offline-root.md)
- [Revocation and CRLs](docs/04-revocation.md)
- [Signing in with Keycloak (OIDC)](docs/05-sso-keycloak.md)

## License

[MIT](LICENSE). Bundled third-party software is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), including cfssl (BSD-2-Clause).
