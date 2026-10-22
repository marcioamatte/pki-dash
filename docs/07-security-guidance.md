# Protecting your PKI

> Translations: [pt-BR](07-security-guidance_pt-BR.md)

pki-dash is for homelabs and internal networks, and a private CA is a smaller target than a public one. But a CA is the one component whose failure lets someone impersonate every host you trust, so the habits of larger PKIs are worth the few minutes they cost. This page says which ones matter, and what to do when something goes wrong.

**Everything here is guidance, not a guarantee.** pki-dash comes with no warranty, and all risk of using it is yours (see the [README](../README.md)).

## What a real incident teaches

In October 2026 a public certificate authority had the private keys of several intermediate CAs disclosed as **recoverable from their own certificates**: the keys had been generated incorrectly. A holder of such a key could issue certificates for any host name, and every client that trusted the chain would accept them. Browsers blocked the intermediates within days, but much software that is not a browser never checks revocation, and recovers only when its list of trusted authorities is updated (see [the analysis by Endor Labs](https://www.endorlabs.com/learn/emudhra-intermediate-ca-compromise-the-trust-stores-you-patched-and-the-ones-you-didnt-know-you-had), which is where these facts come from).

Your CA is not that CA, but the same three things decide how bad a leaked intermediate would be for you:

1. **What it was allowed to issue.** Unlimited, it can impersonate anything. Limited to your domains, it can impersonate only those.
2. **How long the key stays useful.** A shorter life ends the exposure sooner, even for clients that never check revocation.
3. **Where your Root is trusted.** You cannot clean up what you did not know you had installed.

## 1. Always limit which names an intermediate may issue for

Give every intermediate a **name constraint**: a critical extension that makes clients reject any certificate it issues for a name outside the domains you list. If its key leaks, the damage is limited to those domains.

- In the signing instructions of the [offline Root workflow](03-offline-root.md#always-limit-which-names-an-intermediate-may-issue-for), list the domains (`lab`, `home.arpa`, your own domain) and use the **openssl** recipe. The screen warns you when the list is empty.
- **cfssl's command line cannot add the extension**, so a constrained intermediate has to be signed with openssl.
- **An intermediate created inside pki-dash, under a Root the service holds, cannot be constrained.** If you want the limit, keep the Root offline and sign with openssl. This is one more reason to do so.
- What it limits: **DNS names**. The recipe does not constrain IP addresses, e-mail addresses or other name types, so a leaked key could still issue a certificate for an IP. Most of what you secure with it is reached by name, but know this limit.
- Clients must enforce it. OpenSSL, Go, Java, the major browsers and most TLS libraries do; some old or embedded software does not. Test yours: `openssl verify` a certificate for a name outside the list and see it fail.
- pki-dash itself refuses to issue for names outside an intermediate's constraints, instead of producing a certificate no client would accept.

## 2. Keep lifetimes short

- **Intermediates: two years by default** (you can change it, never past the Root's own end). A leaked intermediate stays trusted, by clients that do not check revocation, until it expires.
- **Service certificates: as short as you can renew.** A year at most; shorter if you automate renewal.
- The Root can be long (ten years by default), because it is the one thing you keep offline.

## 3. Know where the Root is trusted

Trust is not in one place. The operating system, each browser, each language runtime and every container image can have its **own** list of authorities, and installing the Root in one does not install it in the others. In the dashboard, **Install on hosts** covers the main ones:

| Where | Why it is separate |
|---|---|
| Debian, Ubuntu, RHEL, Fedora, Alpine, macOS, Windows | the system list |
| Firefox | keeps its own list |
| Java | each JDK or JRE has its own `cacerts`, and updates can replace it |
| Node.js | ships its own list and ignores the system one by default |
| Python (`requests`) | uses the `certifi` bundle that comes with it |
| Containers | do not inherit the host's trust; the image needs its own |

Keep a short list of **where you installed your Root**: hosts, images, CI runners, devices. The day you must remove or replace it, that list is the difference between an afternoon and a mystery.

## 4. Revocation is a partial defence

Web browsers mostly do not fetch CRLs for private CAs, and a lot of other software never does. Revocation pays off where something *you control* checks it (see [Revocation](04-revocation.md#who-actually-checks-a-crl)). For everything else, the controls are the ones above: limited names, short lives, and replacing what is compromised.

## 5. Limit who can reach the offline Root, and log every signing

The Root is the most valuable secret in the whole PKI, and the one pki-dash cannot protect for you, because it is **not here**: it lives on a machine or a medium you keep offline. What follows is general good practice that you carry out yourself; pki-dash does not enforce any of it.

- **Keep the circle small.** Everyone who can reach the Root's key *or* its passphrase is one more way for it to leak. In a homelab that may be only you. In a team, name the few people and write the names down, and remove access the day someone leaves.
- **Do not keep the key and its passphrase together.** The key lives on encrypted offline media; the passphrase is stored somewhere else, and a backup of the key never sits next to it.
- **Where there is more than one person, use two steps.** One asks for a signing and another carries it out, or at least wait a day before signing anything unexpected.
- **Keep it offline for real.** A machine or boot medium with no network, used for this and nothing else, and stored locked. Do not sign "just this once" from your everyday laptop.
- **Log every signing.** The dashboard's audit log records what happens *in the dashboard* (importing a signed intermediate, revoking, publishing a CRL). The signing itself happens on the offline machine and leaves no trace there, so keep a short log of your own, in a notebook or a text file kept with the Root:

```
date        : 2026-10-22
who         : who signed / who asked
why         : new intermediate for the lab (replaces "Home Services 2024")
what signed : CN=Home Services 2026, serial, 2 years, path length 0,
              name constraints: lab, home.arpa
checked     : certificate read back with openssl before it left the machine
```

- **Read what you signed before it leaves the Root's machine.** Show it with `openssl x509 -in inter.crt -noout -text` and confirm the subject you expected, path length 0, the name constraints you meant, and a validity that ends before the Root's. When you import it, the dashboard checks the path length, the key usage, the validity and that it matches the request, but it does **not** require name constraints: that part is yours to look at.
- **Test the way back.** Once, restore the Root from its backup on an offline machine, sign a throwaway certificate and delete it, so you know the backup and the passphrase really work. Keep at least two encrypted copies in different places. A Root you cannot restore is not backed up.

## If an intermediate's key leaks

Act in this order. Speed matters more than perfection.

1. **Stop trusting it from now.** In pki-dash, revoke it (reason *CA compromise*) and publish the Root's CRL (see [Revoking an intermediate CA](04-revocation.md#revoking-an-intermediate-ca)). Clients that check CRLs will refuse it.
2. **Destroy its key in pki-dash,** once the revocation is published (**Destroy key**), so a copy cannot leave from there.
3. **Make a new intermediate,** this time with name constraints and a short life, signed by your Root.
4. **Issue the service certificates again from the new intermediate and deploy them.** Old ones keep validating against the old intermediate until it expires.
5. **Remove trust in the old intermediate where clients do not check CRLs.** There is no one way: on Windows, `certutil -addstore Disallowed old-intermediate.crt` as administrator; on macOS, set the certificate to *Never Trust* in Keychain Access; on Linux there is no clean system-wide way to distrust one intermediate while trusting its Root. If you cannot cover every client and the exposure matters, the honest answer is to **replace the Root** and reinstall trust everywhere.
6. **Do not assume you can see what was issued.** The audit log lists what pki-dash issued, not what someone with the stolen key issued elsewhere. Private CAs have no public log. That is why limiting names and lifetimes in advance matters.

If the **Root's** key leaks, nothing short of replacing the Root and reinstalling trust everywhere is enough. Keep it offline, encrypted, and backed up away from its passphrase, as in [section 5](#5-limit-who-can-reach-the-offline-root-and-log-every-signing).

## Keys that come from outside

pki-dash generates its own keys with the operating system's secure random generator. A request signed elsewhere (the CSR route) keeps the intermediate's key inside pki-dash from the start. For public keys that **arrive from elsewhere** (certificate requests, imported certificates), pki-dash checks only that they are big enough. It cannot tell a key made by a broken generator. Make keys with trusted tools, and be wary of devices with poor randomness.

## Running the service

- **Verify what you download** (see [Installing](06-installation.md#verify-what-you-downloaded)) and read the release notes before upgrading. Back up first.
- Bind the listener to one trusted interface; behind a proxy, list **only the proxy** as trusted (see [Deployment](02-deployment.md#behind-a-reverse-proxy)).
- Choose **exactly one** way of serving in the settings. Two at once is as wrong as none, and after fixing the settings run `systemctl reset-failed pki-dash` before restarting (see [Installing](06-installation.md#first-start)).
- Keep the master passphrase and the backups in different places.
