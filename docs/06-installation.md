# Installing pki-dash

> Translations: [pt-BR](06-installation_pt-BR.md)

Every release publishes the same program in several forms. Pick the one that fits the machine.

| You want | Use | Platforms |
|---|---|---|
| A service on a Debian or Ubuntu server | the `.deb` package | linux amd64, arm64 |
| A service on Fedora, RHEL, Rocky, Alma, openSUSE | the `.rpm` package | linux amd64, arm64 |
| A container | the image `ghcr.io/marcioamatte/pki-dash` | linux amd64, arm64 |
| Anything else, or to try it out | the archive with the bare program | linux, macOS, Windows; amd64, arm64 |

Releases are on the repository's **Releases** page. For a real CA, run pki-dash on a Linux server: it holds the encrypted keys of your CAs, and the packages and the image set up the account, the permissions and the sandbox for that. The macOS and Windows archives run the program, with no service around it, and suit trying it out.

## Verify what you downloaded

Each release carries `checksums.txt` and a signature of it, `checksums.txt.sigstore.json`, made by the release workflow with [Sigstore](https://www.sigstore.dev/) keyless signing: there is no private key anywhere that could leak, and the signature records which workflow in which repository produced it. Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), then, with the files in one folder:

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/marcioamatte/pki-dash/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Replace `v0.1.0` with the version you downloaded. The first command proves the checksums come from this project's release workflow; the second proves your file is the one listed. The `.deb` and `.rpm` packages are not signed with GPG keys of their own: this check is their guarantee. `dnf install ./file.rpm` accepts them as they are; with zypper add `--allow-unsigned-rpm`.

The container image is signed the same way:

```bash
cosign verify ghcr.io/marcioamatte/pki-dash:0.1.0 \
  --certificate-identity "https://github.com/marcioamatte/pki-dash/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each archive has an SBOM (the list of everything inside it, in SPDX) next to it as `*.sbom.json`, and the image carries its own.

## Debian and Ubuntu

```bash
sudo apt install ./pki-dash_0.1.0_amd64.deb      # arm64 on ARM servers
```

## Fedora, RHEL and family

```bash
sudo dnf install ./pki-dash_0.1.0_amd64.rpm      # arm64 on ARM servers
```

## What the packages set up

- The program, `/usr/bin/pki-dash`.
- A **systemd service**, `pki-dash`, running as its own account `pki-dash` (no login, no home), with the sandbox on: it can write only to its data directory, sees no other users' files or devices, has no capabilities and a memory cap.
- **Settings** in `/etc/pki-dash/pki-dash.env`. Your edits are never overwritten by an upgrade.
- **Data** in `/var/lib/pki-dash`, readable by the service only. The database, with the encrypted CA keys, is there.
- An example for signing in with Keycloak, `/etc/pki-dash/oidc.env.example`.
- The documentation in `/usr/share/doc/pki-dash/`.

The service is **installed but not started**: the server refuses to run until you choose how it is served.

### First start

1. Edit `/etc/pki-dash/pki-dash.env` and uncomment **one** of the three ways to serve it:
   - your certificate (`PKI_DASH_TLS_CERT` and `PKI_DASH_TLS_KEY`). The key must be readable by the service: `sudo chgrp pki-dash /etc/pki-dash/tls.key && sudo chmod 640 /etc/pki-dash/tls.key`;
   - `PKI_DASH_TLS_SELF_SIGNED=true`, a throwaway certificate for trying it out (browsers will warn);
   - `PKI_DASH_INSECURE_HTTP=true`, only behind a reverse proxy that terminates TLS (see [Deployment](02-deployment.md)).
2. `sudo systemctl enable --now pki-dash`
3. `sudo journalctl -u pki-dash | grep setup_token`: the one-time token for the first run.
4. Open the address in a browser, enter the token and create the first administrator and the master passphrase.

If you leave step 1 undone, the service stops after a few attempts and the journal says what is missing (`sudo journalctl -u pki-dash`).

### Settings you may want

All in `/etc/pki-dash/pki-dash.env`, then `sudo systemctl restart pki-dash`:

- `PKI_DASH_LISTEN`: the address to listen on (default `127.0.0.1:8443`, only this machine). Use the server's address to let others in. Below port 1024 the service needs a capability: see the comment in the unit file.
- Behind a proxy: `PKI_DASH_TRUSTED_PROXIES`, see [Deployment](02-deployment.md).
- Publishing CRLs: `PKI_DASH_PKI_LISTEN` and `PKI_DASH_PUBLIC_URL`, see [Revocation](04-revocation.md).
- Every other option, and its variable, is in [Deployment](02-deployment.md).

### Signing in with Keycloak (optional)

Nothing to do if you only use local accounts: while `/etc/pki-dash/oidc.env` does not exist, there is no SSO and no button.

```bash
sudo cp /etc/pki-dash/oidc.env.example /etc/pki-dash/oidc.env
sudo $EDITOR /etc/pki-dash/oidc.env                  # issuer, client id, groups
echo 'the-client-secret' | sudo install -m 0640 -o root -g pki-dash /dev/stdin /etc/pki-dash/oidc-secret
sudo systemctl restart pki-dash
```

The file explains each line, and [Signing in with Keycloak](05-sso-keycloak.md) covers what to prepare on the Keycloak side.

### Upgrading

Install the newer package the same way. A running service is restarted, your settings and data stay, and the database is upgraded in place on start. **Back up first** (see [Deployment](02-deployment.md#backups)): the database and your master passphrase are what you cannot recreate.

### Removing

`sudo apt remove pki-dash` (or `purge`, which also deletes the settings) and `sudo dnf remove pki-dash` stop and disable the service. **They never delete `/var/lib/pki-dash` or the `pki-dash` account**: that is your CAs' keys and the audit log. Delete the directory yourself when you are sure you will not need it.

## Container image

```bash
docker run -d --name pki-dash -p 8443:8443 -v pki-data:/data \
  ghcr.io/marcioamatte/pki-dash:0.1.0 -tls-self-signed
```

Replace `-tls-self-signed` with your certificate options ([Deployment](02-deployment.md) has a Compose file with the hardening on). The tags are the exact version (`0.1.0`), the minor line (`0.1`) and `latest`; pin the exact version. While the package is private, sign in to the registry first: `docker login ghcr.io` with a GitHub token that can read packages.

## The bare program

Download the archive for your system, unpack it and run it:

```bash
tar xzf pki-dash_0.1.0_linux_amd64.tar.gz
./pki-dash -data-dir ./data -listen 127.0.0.1:8443 -tls-self-signed
```

On Windows, unzip and run `pki-dash.exe` with the same options. The Linux archive also carries the unit file and the example settings under `packaging/`, for a manual install without the packages: create a `pki-dash` account, copy the files as the packages do and `systemctl enable --now pki-dash`.

## Making a release (maintainers)

1. Everything merged into `main`, CI green. The pipeline runs in CI on every change as **release (snapshot)**, building all of the below without publishing, so it does not fail for the first time on release day.
2. `git tag v0.1.0 && git push origin v0.1.0` (the tag is what a release is; versions follow [semantic versioning](https://semver.org/)).
3. The **Release** workflow re-runs the checks, then builds the binaries, archives, packages and image, makes the SBOMs, signs the checksums and the image, pushes the image to `ghcr.io` and creates the GitHub release with all of it and a changelog.
4. The image package is created **private**. To open it: the repository's *Packages* → `pki-dash` → *Package settings* → *Change visibility*.
5. Try a snapshot locally with `make snapshot` (needs [GoReleaser](https://goreleaser.com/), version in `.github/workflows/release.yml`, and Docker).
