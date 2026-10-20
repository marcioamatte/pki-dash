# pki-dash

A web dashboard to create and manage an internal PKI (Root CA, intermediate CAs and service certificates), built on top of Cloudflare's [cfssl](https://github.com/cloudflare/cfssl). Ships as a single container.

> Translations: [pt-BR](README_pt-BR.md)

> **Status: early design phase. Nothing is usable yet.**

> **Disclaimer:** pki-dash is meant for internal environments such as homelabs, labs and test machines. It is **not** intended for public PKI or for settings where a CA compromise would have critical impact. It does not replace an HSM, a formal key ceremony or a commercial CA.

## Goals

- Root → intermediate → service certificate hierarchy, with the Root kept offline.
- Friendly UI for issuing certificates and distributing trust to hosts.
- Security first: CA keys encrypted at rest, mandatory authentication, multi-user roles, audit log, OIDC later.

## Documentation

- [Vision and scope](docs/00-vision-and-scope.md)
- [Stack decision](docs/01-stack-decision.md)

## License

[MIT](LICENSE). Bundled third-party software is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), including cfssl (BSD-2-Clause).
