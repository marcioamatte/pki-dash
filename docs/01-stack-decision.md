# pki-dash: Stack Decision (draft)

> Status: approved by the maintainer on 2026-10-20. Translations: [pt-BR](01-stack-decision_pt-BR.md)

## 1. Verification results

Before choosing, we checked whether cfssl can be used as a **Go library** instead of a child process. A throwaway probe (not part of the repo) cloned cfssl and built a program that:

- generated a Root CA key **in memory** (`ecdsa.GenerateKey`) and created the Root certificate with `initca.NewFromSigner`;
- built a `local.NewSigner(crypto.Signer, cert, ...)` from that in-memory key;
- generated a CSR and signed it as a **CA intermediate** (`signer.Sign`) with a `CAConstraint` profile (path length 0).

Findings:

| Question | Result |
|---|---|
| Can cfssl sign without key files on disk? | **Yes.** `local.NewSigner` accepts any `crypto.Signer`. Keys can be decrypted into memory only when needed, and this also leaves a clean path to PKCS#11/HSM later. |
| Does it build CGO-free? | **Yes.** The probe built with `CGO_ENABLED=0` (~19 MB binary). SQLite/MySQL/Postgres drivers are *not* pulled in unless `certdb` is imported. This allows a static binary and a minimal image. |
| Dependency licenses | The transitive dependencies of the signing path (`x/crypto`, `x/net`, `x/text`, `protobuf`, `zcrypto`, `zlint`, `certificate-transparency-go`, `publicsuffix-go`, `go-toml`, `klog`, `logr`, `sqlx`) are all MIT, BSD or Apache-2.0. None conflict with MIT distribution. Needs a formal CI check later. |
| Project health | Active: last commit on 2026-10-06 (e.g. ML-DSA post-quantum key support, new release targets). It requires a very recent Go toolchain (`go 1.27` in `go.mod`), so we track Go closely. |

Caveats:

- The cfssl library API is **not** a stable public API. We will isolate it behind our own interface (`internal/ca`), and pin an exact cfssl version.
- cfssl logs through its own logger (`[INFO] signed certificate with serial...`). We must redirect/filter it so nothing sensitive leaks into logs, and use our audit log as the source of truth.
- We must verify that the issued certificates are what we expect (extensions, path length, key usages) with our own tests, not trust defaults.

## 2. Decision

| Layer | Choice | Why |
|---|---|---|
| Backend | **Go**, cfssl as an **embedded library** | Single static binary; no child process; no cfssl HTTP API listening, even on loopback; smaller attack surface. |
| Container | `distroless/static` (or `scratch`), non-root, read-only root filesystem, one data volume | Minimal image, no shell, no package manager. |
| Frontend | **Svelte + TypeScript + Tailwind**, built to static assets and embedded in the Go binary (`go:embed`) | Small bundle, fast, modern look; far fewer runtime dependencies than a typical React tree, which matters for npm supply-chain exposure. No Node in production. |
| Storage | **SQLite**, pure-Go driver (`modernc.org/sqlite`) | Single file on the volume, transactional, CGO-free. |
| Secrets at rest | CA keys encrypted at the application layer: master passphrase → Argon2id → AES-256-GCM (envelope encryption: a data key per CA key, wrapped by a key derived from the passphrase) | Does not depend on database-level encryption. Allows passphrase rotation without re-encrypting every key. |
| Auth | Local users with Argon2id password hashes; server-side sessions in cookies (`HttpOnly`, `Secure`, `SameSite=Strict`); CSRF protection; role-based access. OIDC (Keycloak first) via `coreos/go-oidc` later. | Server-side sessions are revocable, unlike long-lived JWTs. |
| Transport | HTTPS only. The dashboard serves TLS itself, and can mint its own certificate from its own CA on first run. | Dogfooding, and no plaintext key downloads. |
| HTTP hardening | Strict CSP (no inline scripts), HSTS, `X-Content-Type-Options`, `Referrer-Policy`, rate limiting and lockout on login, request size limits | Standard baseline for an admin UI. |

## 3. Frontend: why Svelte over React

Both would work. The deciding factors for this project:

- **Supply chain.** Fewer, smaller dependencies means a smaller audit surface for a security-sensitive tool. Svelte compiles away its runtime; a typical React app adds a larger ecosystem of transitive packages.
- **Performance and size.** Smaller bundles and no virtual DOM overhead; helpful for a tool embedded in a binary.
- **Simplicity.** Less boilerplate for forms-heavy screens, which is most of this UI.
- **Trade-off acknowledged:** React has a bigger contributor pool and component ecosystem. If contributor reach later outweighs this, the API-first design (below) lets the frontend be replaced without touching the backend.

## 4. Architecture sketch

```
Browser ──HTTPS──▶ Go binary
                     ├─ embedded static UI (Svelte build)
                     ├─ REST API (JSON, versioned: /api/v1)
                     ├─ auth / sessions / RBAC / audit log
                     ├─ internal/ca  (our interface)
                     │     └─ cfssl library (initca, csr, signer/local)
                     └─ SQLite (users, CA metadata, encrypted keys, issued certs, audit)
```

The API is the contract. The UI is just one client of it, which also makes future CLI or automation use possible.

## 5. Supply-chain and quality baseline

- Pinned dependencies with lockfiles (`go.sum`, `package-lock.json`); `npm ci` only; exact version pins for cfssl.
- CI: `go vet`, tests with race detector, `govulncheck`, `staticcheck`/`golangci-lint`, `npm audit`, license check, container image scan (e.g. Trivy), SBOM generation.
- Reproducible builds and signed release artifacts (e.g. cosign) before the first public release.
- Tests that parse the issued certificates and assert on constraints (CA flag, path length, key usage, SANs, validity), not only that signing "succeeds".
- Security policy (`SECURITY.md`) with a private reporting channel before publishing on GitHub.

## 6. Confirmed decisions

1. Frontend: Svelte.
2. Key algorithms: ECDSA P-384 (Root), P-256 (intermediates and leaves), RSA 3072/4096 optional, Ed25519 off by default.
3. Default validities: Root 10 years, intermediates 2 years (originally 3–5; shortened so a leaked intermediate stops being useful sooner, see [Protecting your PKI](07-security-guidance.md)), leaves ≤ 1 year, with a UI warning above 398 days.
4. Repository: `git@github.com:marcioamatte/pki-dash.git`; Go module path `github.com/marcioamatte/pki-dash`.
