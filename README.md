# pki-dash

A web dashboard to create and manage an internal PKI (Root CA, intermediate CAs and service certificates), built on top of Cloudflare's [cfssl](https://github.com/cloudflare/cfssl). Create a Root and keep it offline, sign intermediates and service certificates, revoke them and publish CRLs, with roles, an audit log and optional sign-in with Keycloak. Installs as a `.deb`/`.rpm` package with a systemd service, as a container image, or as a single binary.

> Translations: [pt-BR](README_pt-BR.md)

> **Status: pre-1.0 (v0.1.0).** Tested end to end against real cfssl, openssl, Keycloak and nginx, including on the author's own infrastructure, but not audited by anyone else. Behaviour may change between versions: read the [release notes](https://github.com/marcioamatte/pki-dash/releases) and back up before upgrading. **There is no warranty and all risk of use is yours: see the notice below.**

> **NO WARRANTY. USE AT YOUR OWN RISK.** pki-dash is provided "as is", without warranty of any kind, express or implied, as the [MIT license](LICENSE) states. **The user is solely responsible for every risk of using it, including misuse and use in unsuitable settings**: the author accepts no liability for any damage, loss, outage, or compromise of keys, certificates or systems that results from it.
>
> It is meant for internal environments such as homelabs, labs and test machines. It is **not** intended for public PKI or for settings where a CA compromise would have critical impact. It does not replace an HSM, a formal key ceremony or a commercial CA.

## Goals

- Root → intermediate → service certificate hierarchy, with the Root kept offline.
- Friendly UI for issuing certificates and distributing trust to hosts.
- Security first: CA keys encrypted at rest, mandatory authentication, multi-user roles, audit log, optional sign-in with Keycloak/OIDC.

## Getting started

Install a release (recommended): a `.deb`/`.rpm` package with a systemd service, a container image, or a bare binary for Linux, macOS and Windows. See [Installing](docs/06-installation.md); Docker details (a single container, unprivileged, read-only filesystem) are in [Deployment](docs/02-deployment.md).

Or build from source:

```bash
make build                           # builds the web UI (needs Node 20.19+ or 22.12+), then the Go binary into bin/
./bin/pki-dash -tls-self-signed      # or -tls-cert/-tls-key, or -insecure-http for local development
```

Then open <https://localhost:8443>.

The server refuses to start unless you choose how it is served. On first run it prints a one-time **setup token** to its log; enter it in the web UI (or send it to `POST /api/v1/setup`) to create the first admin and the master passphrase. After every restart the vault is locked: unlock it from the UI (or `POST /api/v1/vault/unlock`), so CA keys never sit decrypted on disk.

## Documentation

- [Vision and scope](docs/00-vision-and-scope.md)
- [Stack decision](docs/01-stack-decision.md)
- [Deployment (Docker)](docs/02-deployment.md)
- [Keeping the Root offline](docs/03-offline-root.md)
- [Revocation and CRLs](docs/04-revocation.md)
- [Signing in with Keycloak (OIDC)](docs/05-sso-keycloak.md)
- [Installing: packages, image, binaries](docs/06-installation.md)

## Contributing

Bug reports, ideas, documentation and code are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md). For security problems, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Bundled third-party software is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), including cfssl (BSD-2-Clause).
