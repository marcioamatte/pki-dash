# pki-dash: Vision and Scope (draft)

> Status: draft. Translations: [pt-BR](00-vision-and-scope_pt-BR.md)

## 1. What it is

A web dashboard to create and manage an internal PKI (Root CA, intermediate CAs and service certificates), using Cloudflare's [cfssl](https://github.com/cloudflare/cfssl) as the cryptographic engine. Shipped as a **single container** (dashboard + cfssl) with one volume for data.

## 2. Target audience and disclaimer

Internal environments: homelabs, labs, test machines and private networks.

**Disclaimer (must appear in the README and in the UI):** pki-dash is not intended for public PKI or for environments where a CA compromise would have critical impact. It does not replace an HSM, a formal key ceremony or a commercial CA.

## 3. MVP use cases

1. Create a Root CA.
2. Create intermediate CAs signed by the Root.
3. Export the Root key and remove it from the service, keeping only the public certificate (the Root goes offline).
4. Import an externally signed intermediate.
5. Issue service certificates from an intermediate:
   - CN, SANs (DNS and IP), validity and profile (server, client, both);
   - from an uploaded CSR (preferred) or with a server-generated key.
6. Download bundles: certificate, key (when generated here) and full chain.
7. Trust distribution: download the Root certificate (PEM/CRT) and show install snippets per OS (Debian/Ubuntu, RHEL, Windows, macOS, Firefox).
8. Inventory: list CAs and certificates with validity and upcoming-expiry alerts.

## 4. Security requirements

Security first is a project principle: when a choice trades security against convenience, security wins.

- **CA private keys encrypted at rest** with a master passphrase set at initialization.
- **Mandatory authentication from day 1.** Local login, admin created on first access.
- **Multi-user with roles** (e.g. admin, operator who issues certificates, viewer). Exact roles TBD.
- **Audit log** of sensitive actions (CA creation, issuance, key export, login).
- **OIDC** (initial target: Keycloak) as an additional login method. Not in the minimal MVP, but the authentication layer must be designed for it from the start.

## 5. Threat model (sketch)

| Threat | Planned mitigation |
|---|---|
| Unauthorized access to the dashboard | Authentication, roles, audit log |
| Theft of the data volume | CA keys encrypted with master passphrase |
| Root compromise | Root removed from the service after signing intermediates |
| Service key intercepted on download | Prefer CSR flow; HTTPS on the dashboard |
| Lost master passphrase | Document that there is no recovery |

To be refined in the next revision.

## 6. Out of scope for the MVP

- Revocation, CRL and OCSP (phase 2; they need a database and a CRL endpoint reachable by clients).
- ACME and automatic renewal.
- HSM / PKCS#11.
- High availability and multiple instances.
- Public PKI use.

## 7. Decisions made

- Open source, intended for publication on GitHub.
- Hierarchy: Root → Intermediates → Service certificates.
- Single container with cfssl embedded.
- Local auth in the MVP, then OIDC/Keycloak; multi-user.
- **Language:** English is the primary language for code, docs and UI. Translations use a `_pt-BR.*` style suffix (e.g. `README_pt-BR.md`); other languages can follow if contributors appear.
- **License:** MIT, kept compatible with cfssl's BSD-2-Clause. See section 9.
- **Backend language:** Go is the preferred direction (not final until the stack review).
- **UX goals:** friendly screens, simple concepts, speed, performance, security and a modern layout. These are goals, not hard constraints on technology.

## 8. Open

- Frontend framework and data storage.
- cfssl integration: internal `cfssl serve` process vs. library use.
- Exact roles and permissions.

## 9. Licensing notes

cfssl is BSD-2-Clause, a permissive license that allows redistribution inside an MIT-licensed project. The conditions to honor:

- Keep cfssl's copyright notice and license text in anything we redistribute (source or binary), e.g. in the container image and in a `THIRD_PARTY_NOTICES` file.
- Do not imply endorsement by Cloudflare or use its name for promotion.
- cfssl and our other dependencies have their own licenses. We will audit them (automated license check in CI) to ensure none conflicts with MIT distribution, and to list them in the notices.

This is a practical summary, not legal advice.
