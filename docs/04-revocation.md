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

## Revoking an intermediate CA

An intermediate is revoked by **its Root**, and the Root stays offline. So this has two halves: the dashboard records the revocation and stops using the CA right away, and **you** bring back a CRL that the Root signed, which the dashboard then publishes in the Root's name.

1. **Revoke** the intermediate (admins only; `POST /api/v1/cas/{id}/revoke`, reasons as for certificates plus `ca_compromise`). From that moment the service **refuses to issue** from it and **signs no more CRLs** with its key. Revoking is final. Certificates it already issued are not listed anywhere until the Root's CRL says the CA itself is revoked, at which point clients reject the whole chain.
2. **Ask what the Root's CRL must contain** (`GET /api/v1/cas/{root}/crl-request`): the revoked intermediates with their serial numbers (hex and decimal), and the number to give the CRL.
3. **On the Root's machine, build a complete CRL** with either tool (both tested):

   **cfssl**: put the decimal serials, one per line, in `serials.txt`:

   ```bash
   cfssl gencrl serials.txt root.pem root-key.pem 15552000 > root-crl.b64     # 15552000 s = 180 days
   ```

   The output is base64 of the DER, which the importer accepts as it is. cfssl writes no CRL number and no reason code, and dates the list to the second.

   **openssl**: it needs a small CA database. One line per revoked intermediate in `index.txt` (tab-separated; serial in upper-case hex with an even number of digits; dates as `YYMMDDHHMMSSZ`), the number in `crlnumber`, and a `ca.cnf`:

   ```ini
   # index.txt  (fields separated by TABs)
   R	351021000000Z	261021025553Z,CACompromise	3BF66B5E5E2E0AD23554366822BEA765B04AA08E	unknown	/CN=Inter A

   # crlnumber
   01

   # ca.cnf
   [ca]
   default_ca = CA_default
   [CA_default]
   database = index.txt
   crlnumber = crlnumber
   certificate = root.pem
   private_key = root-key.pem
   default_md = sha384
   default_crl_days = 180
   ```

   ```bash
   openssl ca -config ca.cnf -gencrl -out root-crl.pem
   ```

   openssl's list carries the CRL number and the reason, so prefer it if you can.
4. **Import it** (`POST /api/v1/cas/{root}/crl/import`, PEM, DER or cfssl's base64). The dashboard serves it at the Root's `/crl/<root-id>.crl`.

### In the web UI

- **Revoke** an intermediate from its row on the Certificate authorities page (admins). Choose a reason (`ca_compromise` is offered here) and acknowledge that it is final. The dialog then offers **Publish the Root's CRL**.
- **Root CRL** on a Root's row (and **Publish Root CRL** in the *Revocation lists* panel) opens a wizard: it lists the revoked intermediates the list must contain, lets you pick the list's validity, and shows the files and the command for **openssl** or **cfssl**, already filled in (the CRL number is the next one). Run them on the Root's machine, then paste or choose the result and **Publish CRL**.
- The *Revocation lists* panel also shows the Root's list: *Up to date*, *Behind* (it does not name every revoked intermediate), *Waiting for the Root's list*, or *Expired*, with a warning. A revoked intermediate shows as *Retired*.
- When you sign a new intermediate, the recipes shown in the dashboard now include the pointer to the Root's CRL, if the server has a public URL (see below).

### What the import checks

It is published in the Root's name, so it is checked first:

- signed by **this Root's key** and issued by its name;
- a **complete** list: delta and partial CRLs are refused;
- current: not expired, not dated in the future;
- **newer than the one already published**, so an old list cannot be put back and quietly un-revoke things. With CRL numbers on both, the number must grow; otherwise (cfssl) its date must be strictly later, which a Root machine with a badly set clock can trip: fix the clock and generate it again;
- **consistent with this dashboard**: it must list every intermediate revoked here, and none that is not (revoke it here first).

A refusal explains why and changes nothing.

### Make the intermediates point at the Root's list

Clients can only check an intermediate if its certificate says where the Root's CRL is. Add that when you **sign** an intermediate (the recipes in [Keeping the Root offline](03-offline-root.md) use the same files):

```json
"crl_url": "http://pki.lab:8080/crl/<root-id>.crl",
"issuer_urls": ["http://pki.lab:8080/ca/<root-id>.crt"],
```
(in the cfssl profile, next to `usages`), or in the openssl extensions file:

```ini
crlDistributionPoints = URI:http://pki.lab:8080/crl/<root-id>.crl
authorityInfoAccess = caIssuers;URI:http://pki.lab:8080/ca/<root-id>.crt
```

`<root-id>` is the Root's id, as in the URLs the dashboard shows. **Intermediates signed before this carry no such address**: clients cannot discover the Root's list for them (re-sign them if you want that).

### The Root's list expires too

Strict clients refuse a chain whose CRL has expired. A Root that is almost never switched on must therefore publish a list with a **long validity** (the commands above use 180 days) and **renew it before it ends**, even when nothing changed. The dashboard shows the Root's list as *Expired* and warns. Publish an empty one as soon as intermediates point at the Root.

## Destroying the key of a revoked intermediate

A revoked intermediate will never sign again, so its private key is only a liability: it is exactly what an attacker would take. Once the revocation is published, destroy the key.

In **Certificate authorities**, a revoked intermediate whose key the dashboard still holds offers **Destroy key**. You type the CA's name and the master passphrase, as for a Root's key, and the key is erased for good: there is no copy and no way back. An admin only.

- **The Root's CRL must be published first.** The dashboard refuses until the Root's CRL that lists this intermediate has been imported (see above): destroying the key before clients can learn of the revocation would leave them trusting a CA that is retired only on your side. The refusal explains this and offers to open the Root CRL steps.
- **Only a revoked intermediate.** A CA in good standing keeps its key; the action is not offered for it, and the server refuses it.
- **What stays:** the CA's certificate, its revocation, and every certificate it issued remain on record and downloadable, and the Root's CRL keeps listing it. What goes is the ability to sign anything with that CA, including a new CRL for its own certificates (it stops being renewed at revocation anyway).
- The audit log records `ca.drop_key` with the number of the Root CRL that allowed it.

A Root's key is a different case: see [Keeping the Root offline](03-offline-root.md).

## Limits

- **No OCSP yet.** CRL only.
- A Root cannot be revoked: nothing above it could sign the statement. To retire one, remove it from the hosts that trust it.
- A CA can publish a CRL only if its certificate has the **cRLSign** key usage. Intermediates made by pki-dash or by the documented cfssl/openssl recipes have it. If you import one without it, certificates it issues carry no CRL address (a warning says so) and revocations are recorded but cannot be published.
- Clients cache a CRL until it expires or is replaced, so a revocation reaches them after their next refresh, not instantly.
