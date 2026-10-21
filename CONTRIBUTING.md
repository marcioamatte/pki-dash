# Contributing to pki-dash

> Translations: [pt-BR](CONTRIBUTING_pt-BR.md)

Thank you for taking the time. pki-dash is a small, volunteer-run project, and bug reports, ideas, documentation fixes, translations and code are all welcome.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

pki-dash manages certificate authorities and private keys, so please read the notice in the [README](README.md) first: it is meant for homelabs and internal environments, and it comes with **no warranty**.

## Report a security problem

**Do not open a public issue.** Use [private vulnerability reporting](https://github.com/marcioamatte/pki-dash/security/advisories/new). Details are in [SECURITY.md](SECURITY.md).

## Report a bug

[Open an issue](https://github.com/marcioamatte/pki-dash/issues/new) and include:

- the version (`pki-dash --version`) and how you installed it (package, container, binary);
- what you did, what you expected and what happened instead;
- the relevant log lines (`journalctl -u pki-dash`, or the container logs). **Remove anything secret first**: tokens, passphrases and private keys never belong in an issue.

## Suggest a change

Open an issue and describe the problem you want to solve before writing a lot of code. A short conversation saves everyone time, and some ideas do not fit the project. These are **out of scope for now**, so please discuss them in an issue first:

- OCSP (the project publishes CRLs only);
- automation for Kubernetes cert-manager, ACME or service tokens (certificates are downloaded and installed by hand);
- importing an intermediate CA together with its private key (the CSR route keeps keys from travelling on purpose);
- anything aimed at public PKI or at settings where a CA compromise would be critical.

## Set up

You need Go (the version in [go.mod](go.mod)), Node.js (20.19+ or 22.12+; CI uses 24) and, for the container and release checks, Docker.

```bash
git clone git@github.com:marcioamatte/pki-dash.git && cd pki-dash
make build                         # builds the web UI, then the Go binary into bin/
./bin/pki-dash -data-dir ./data -tls-self-signed
```

Open <https://localhost:8443>. On first run the log prints a one-time setup token. The binary embeds `web/dist`, so rebuild the UI (`make ui`) after changing the frontend. For quick UI work, run the server in plain-HTTP mode and the Vite dev server next to it, which proxies `/api` to port 8443:

```bash
./bin/pki-dash -data-dir ./data -insecure-http -listen 127.0.0.1:8443
cd web && npm run dev              # then open the address it prints
```

| Command | What it does |
|---|---|
| `make test` | Type-check and test the web UI, `go vet`, and `go test -race` |
| `make check` | `make test`, plus the third-party notices check, `govulncheck` and `npm audit` |
| `make docker` | Build the image and run its smoke test |
| `make snapshot` | Build a whole release (binaries, packages, image) without publishing; needs [GoReleaser](https://goreleaser.com/) |

## Make a change

1. Fork the repository and create a branch from `main`, named for what it does (`feat/...`, `fix/...`, `docs/...`).
2. Keep the change focused: one idea per pull request is easier to review and to revert.
3. Run `make check` before you push. The `go` check in CI must pass, and `main` only changes through pull requests.
4. Open a pull request and say **what** changed, **why**, and **how you verified it**. Link the issue if there is one.
5. A maintainer reviews it. Review is done by volunteers and has no time limit, so a ping after a couple of weeks is fine. The maintainer merges and cuts releases.

Write commit messages in the imperative ("Add X", "Fix Y") and let the body explain *why* when it is not obvious.

### What we look for

- **Tests that prove the behaviour.** New behaviour comes with tests, and the project's habit is to check the important things against the real tools as well (openssl, cfssl, a real Keycloak, a real browser), not only against mocks. Say in the pull request what you tried.
- **Security-sensitive code is careful code.** Never log secrets. Validate input before it reaches a command line, a file name or a recipe the user will paste into a shell. Keep new network access to a minimum and say why it is needed.
- **Dependencies are a decision.** Go modules and npm packages are pinned to exact versions, npm runs with `ignore-scripts`, GitHub Actions are pinned by commit SHA and base images by digest. A new dependency needs a reason, and `./scripts/gen-notices.sh > THIRD_PARTY_NOTICES.md` must be re-run so licences stay accurate. Dependabot proposes updates for what already exists.
- **Go:** `gofmt`, `go vet`, and tests under `-race` all clean. Outside tests, the cfssl library is used only inside `internal/ca`.
- **Web UI:** Svelte 5 (runes), TypeScript and Tailwind. The Content-Security-Policy forbids inline scripts and styles. Every visible string goes in **both** `web/src/lib/messages/en.ts` and `pt-BR.ts` (the types make a missing key a compile error). Check a UI change at phone and desktop widths, in light and dark.
- **Documentation:** English first, with its Brazilian Portuguese twin (`*_pt-BR.md`) kept in step. If you do not write Portuguese, say so in the pull request and a maintainer will translate.

### Using AI tools

This project was itself built in partnership with an AI assistant, so there is no rule against it. The rule is the same as for any code: **you are responsible for what you submit.** Read it, understand it, run it, and say in the pull request that a tool helped.

## Licence

pki-dash is under the [MIT licence](LICENSE). By contributing you agree that your contribution is licensed under it too.
