# Revocation and CRLs

> Translations: [pt-BR](04-revocation_pt-BR.md)

You can revoke a service certificate (a leaked key, a decommissioned host), and pki-dash publishes a **CRL** (certificate revocation list) that clients can use to refuse it. OCSP is not implemented yet.

## What it does

- **Revoke** a certificate from the Certificates page (or `POST /api/v1/certificates/{id}/revoke`) with a reason: `key_compromise`, `superseded`, `cessation_of_operation`, `affiliation_changed` or `unspecified`. Admins and operators can revoke.
- Revocation is **final**. There is no "hold" and no way back: once clients have cached a CRL entry it cannot be taken back, so pretending otherwise would only create doubt. To get a working certificate again, issue a new one.
- The **issuing intermediate signs the CRL**, with the key the service already holds. Each CA has its own list.
- A CRL is valid for **7 days** and is reissued **immediately on every revocation**, **every 24 hours**, and **when the vault is unlocked**. The 7-day window means a locked vault over a long weekend does not make clients reject everything.
- The revocation is **recorded at once even if the vault is locked** (a leaked key must stop being valid here immediately). Signing a CRL needs the CA's key, so in that case the CRL is published as soon as you unlock. Until then the dashboard shows the CRL as *behind*, and the API answers `crl_published: false`.

## In the web UI

On the **Certificates** page:

- **Revoke** next to a certificate (admins and operators). You choose a reason and tick that it cannot be undone. If the vault is locked the dialog says the revocation will be recorded now and published on unlock.
- Revoked certificates are struck through with a **Revoked** badge (hover for the date and reason). **Hide revoked certificates** removes them from the list.
- **Revocation lists** shows, for each intermediate, whether its list is *Up to date*, *Behind* (a revocation is recorded but not published, usually because the vault is locked), *Expired* (clients that check will refuse its certificates), *Not published yet*, or *Cannot publish*. **Refresh now** reissues the lists; **Download CRL** gives the PEM. A banner appears for any list that is behind or expired. After you unlock the vault, the page updates itself.

## Publishing: the public listener

Clients fetch CRLs over plain HTTP, and a client that does not yet trust pki-dash's own TLS certificate must still be able to get them. So CRLs are served by a **second, separate listener** that does nothing else:

| URL | What |
|---|---|
| `GET /crl/<ca-id>.crl` | the CA's latest CRL (DER, `application/pkix-crl`) |
| `GET /ca/<ca-id>.crt` | the CA's certificate (DER, `application/pkix-cert`) |

No API, no login, no cookies, no write path: only public data, with `ETag`/`304` support and a per-address rate limit. Everything else on that port is a 404.

Enable it with two settings (flags or environment):

```bash
pki-dash ... -pki-listen 0.0.0.0:8080 -public-url http://pki.lab:8080
# PKI_DASH_PKI_LISTEN / PKI_DASH_PUBLIC_URL
```

`-public-url` is how **your clients** reach that listener, and it is written into every certificate issued afterwards (the *CRL Distribution Points* and *Authority Information Access* extensions). Pick a stable name. With the Docker image, publish port 8080 as well (see the Compose file).

> **Certificates issued before you set `-public-url` carry no address**, so clients have nothing to fetch for them. Reissue them if you need them checked.

## Checking it

```bash
# the certificate says where to look
openssl x509 -in leaf.pem -noout -ext crlDistributionPoints,authorityInfoAccess

# openssl verifies it against the CRL and refuses a revoked certificate:
curl -s http://pki.lab:8080/crl/<ca-id>.crl | openssl crl -inform DER -out crl.pem
openssl verify -CAfile root.pem -untrusted intermediate.pem -crl_check -CRLfile crl.pem leaf.pem
#  -> error 23 at 0 depth lookup: certificate revoked
```

## Who actually checks a CRL

Be realistic about this. **Web browsers mostly do not fetch CRLs for private CAs.** Revocation pays off where something *you control* checks it:

- servers validating **client certificates** (mutual TLS): nginx `ssl_crl`, HAProxy `crl-file`, Envoy, Traefik and similar;
- tools and libraries that you configure to check revocation (`openssl verify -crl_check`, Java, Go with a custom verifier, `curl --crlfile`);
- anything that polls the list itself.

Use it for mTLS and for services you operate. Do not expect it to make a revoked server certificate disappear from every browser.

## Limits

- **No OCSP yet.** CRL only.
- **Intermediate CAs cannot be revoked yet.** That list must be signed by the Root, which stays offline; it comes with the next change.
- A CA can publish a CRL only if its certificate has the **cRLSign** key usage. Intermediates made by pki-dash or by the documented cfssl/openssl recipes have it. If you import one without it, certificates it issues carry no CRL address (a warning says so) and revocations are recorded but cannot be published.
- Clients cache a CRL until it expires or is replaced, so a revocation reaches them after their next refresh, not instantly.
