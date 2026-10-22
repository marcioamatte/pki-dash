# Keeping the Root offline

> Translations: [pt-BR](03-offline-root_pt-BR.md)

The Root is the anchor of trust for everything below it, so the safest place for its private key is a machine that is not on a network. pki-dash supports that in two ways, and both end the same way: the service holds the intermediate's key and issues certificates, but never has the Root's.

## Which path?

| Your situation | What to do |
|---|---|
| The Root was made **elsewhere** (cfssl, openssl, another machine) | [Import its public certificate](#a-root-made-elsewhere), then request an intermediate. |
| You created the Root **in pki-dash** | Use **Take offline** on the Root (export the key, then remove it from the service), then request an intermediate. |

## A Root made elsewhere

1. **Import the Root.** Send only the public certificate (`POST /api/v1/cas/import-root`). The service checks that it is self-signed, a CA allowed to have intermediates (path length not 0), uses a strong key, and is currently valid. The private key is never sent and never needed.
2. **Request an intermediate** (`POST /api/v1/cas/{root}/intermediate-requests`). pki-dash generates the intermediate's key and keeps it, encrypted with the master passphrase, and returns a certificate request (CSR). The key never leaves the service.
3. **Sign the CSR on the machine that keeps the Root.** Two ways, both tested:

   **cfssl**, with a profile that makes a CA that can only sign service certificates (`ca-config.json`):

   ```json
   {
     "signing": {
       "profiles": {
         "intermediate": {
           "usages": ["cert sign", "crl sign"],
           "expiry": "17520h",
           "ca_constraint": { "is_ca": true, "max_path_len": 0, "max_path_len_zero": true }
         }
       }
     }
   }
   ```

   ```bash
   cfssl sign -ca root.pem -ca-key root-key.pem -config ca-config.json -profile intermediate inter.csr \
     | cfssljson -bare inter          # writes inter.pem
   ```

   **openssl**, with an extensions file (`inter.ext`):

   ```ini
   basicConstraints = critical, CA:TRUE, pathlen:0
   keyUsage = critical, keyCertSign, cRLSign
   subjectKeyIdentifier = hash
   authorityKeyIdentifier = keyid
   ```

   ```bash
   openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial \
     -days 730 -sha384 -extfile inter.ext -out inter.crt
   ```

   > **Revocation:** if you want clients to be able to check the intermediate against the Root's CRL later, add its address now (`crl_url` and `issuer_urls` in the cfssl profile, or `crlDistributionPoints` and `authorityInfoAccess` in the openssl extensions). See [Revoking an intermediate CA](04-revocation.md#revoking-an-intermediate-ca).

4. **Import the signed certificate** (`POST /api/v1/intermediate-requests/{id}/import`). From then on the intermediate behaves like any other: it issues service certificates, and they verify against the Root you never gave the service.

## In the web UI

Everything above is a screen, so you rarely need the API directly:

1. **Import Root** (on the Certificate authorities page): paste the Root's public certificate or choose its `.crt` / `.pem` file.
2. **New CA**, type *Intermediate*, parent = that Root. A Root whose key is not held by the service is offered as the parent and the form switches to **Create request**. (For a Root whose key *is* held, tick *Sign it elsewhere* to do the same.) You get the CSR to download, and the exact commands for cfssl or openssl, with the validity limited so the intermediate ends before the Root does.
3. Sign it on the Root's machine with those commands.
4. Under **Waiting for a signed certificate**, choose **Import certificate** and paste or choose the signed file. A refusal explains what is wrong (for example "an intermediate must have a path length of 0") and keeps the request, so you can fix the file and retry. **How to sign** reopens the commands; **Cancel request** discards the request and its key.

## What the import checks

A certificate is accepted only if all of this holds, so a mistake (or a tampered file) cannot slip in:

- it is for **the key that made the request**, not some other key;
- it is **signed by the Root** you chose;
- it is a **CA with a path length of 0**: it may sign service certificates and nothing else. A certificate with no `pathlen` (openssl's default when you forget it) is **refused** with an explanation;
- its key usage allows signing certificates;
- it is valid now, and **within the Root's own validity**.

A refused import leaves the request in place, so you can fix the certificate and try again, or cancel the request, which discards its key.

## Always limit which names an intermediate may issue for

**Do this for every intermediate.** If its key ever leaks, an unconstrained intermediate can impersonate any host name; a constrained one can impersonate only your domains. The dashboard warns when the list is empty, and the [security guidance](07-security-guidance.md) explains why this is the single most useful limit you can set.

On the signing instructions you can list **domains** (for example `lab, mattegroup.example`). The openssl recipe then adds a critical `nameConstraints` extension to the intermediate: every client that validates the chain rejects a certificate for any other name, even if the intermediate's key leaks. A domain covers itself and everything below it.

- **Only the openssl recipe can do it.** cfssl's command line has no way to add the extension, so with domains listed the cfssl tab says so instead of showing a recipe that would silently leave them out.
- The service reads the constraints from the imported certificate and **refuses to issue** for names outside them (DNS names and IP ranges), instead of producing a certificate that no client would accept.
- Put the constraints on the intermediate, not the Root, so one intermediate can be limited without touching the others.
- An intermediate **created inside pki-dash** under a Root the service holds **cannot** be constrained (cfssl cannot add the extension). Constraints are one more reason to keep the Root offline.
- Only **DNS names** are limited; IP addresses are not.

## Notes

- The Root's validity must outlast the intermediate's. Choose `-days` / `expiry` accordingly.
- Pending requests keep their keys encrypted like any other, and a change of master passphrase carries them along.
- Every step is in the audit log: `ca.import_root`, `ca.request_intermediate`, `ca.import_intermediate`, `ca.request_cancel`.
