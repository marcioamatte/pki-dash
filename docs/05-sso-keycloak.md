# Signing in with Keycloak (OpenID Connect)

> Translations: [pt-BR](05-sso-keycloak_pt-BR.md)

pki-dash can let people sign in through an identity provider that speaks OpenID Connect. This guide uses **Keycloak**, but any provider that offers the standard authorization-code flow and puts a groups claim in the ID token works the same way.

## What you get

- A **Sign in with Keycloak** button on the login page. Local accounts keep working next to it.
- **Roles come from groups.** You decide which Keycloak group means admin, operator or viewer; the role is recomputed at every sign-in, so the provider stays the source of truth.
- **Nothing is granted by default.** Someone in none of the mapped groups cannot sign in (unless you set a default role) and no account is created for them.
- Accounts are created on first sign-in and appear in **Users** marked as OIDC.

The local administrator you create at first run stays. Keep it: it is how you get in if the provider is down or misconfigured.

## 1. Prepare Keycloak

Steps for the Keycloak 26 admin console. Names may differ slightly in other versions.

1. **Groups.** In your realm go to *Groups* and create `pki-admins`, `pki-operators` and `pki-viewers` (or any names you like; you pass them to pki-dash below).
2. **Client.** *Clients → Create client*:
   - Client type **OpenID Connect**, Client ID `pki-dash`.
   - Capability config: **Client authentication: On**; tick only **Standard flow** (turn off *Direct access grants*).
   - Access settings: *Root URL* `https://pki.lab:8443`, *Valid redirect URIs* exactly `https://pki.lab:8443/api/v1/auth/oidc/callback`, and *Valid post logout redirect URIs* `https://pki.lab:8443/` (this one lets Keycloak send people back after they sign out). Leave *Web origins* empty. Use the address your browsers use to reach pki-dash.
3. **Require PKCE.** In the client, *Advanced → Advanced settings*, set **Proof Key for Code Exchange Code Challenge Method** to `S256` and save. pki-dash always sends PKCE; this makes Keycloak insist on it.
4. **Secret.** *Credentials* tab: copy the **Client secret**.
5. **Groups in the ID token.** *Clients → pki-dash → Client scopes → pki-dash-dedicated → Configure a new mapper → Group Membership*:
   - Name `groups`, Token Claim Name `groups`.
   - **Add to ID token: On**. Add to access token and userinfo can stay off.
   - *Full group path* may be On or Off: pki-dash accepts `/pki-admins` and `pki-admins` alike.
6. **Users.** Put people in the groups: *Users → the user → Groups → Join group*.

## 2. Run pki-dash with it

Put the client secret in a file only the service can read, and pass the settings:

```bash
printf '%s\n' 'the-client-secret' > secrets/oidc-secret && chmod 400 secrets/oidc-secret

pki-dash -tls-cert tls.crt -tls-key tls.key \
  -external-url https://pki.lab:8443 \
  -oidc-issuer https://keycloak.lab/realms/lab \
  -oidc-client-id pki-dash \
  -oidc-client-secret-file secrets/oidc-secret \
  -oidc-name Keycloak \
  -oidc-admin-groups pki-admins \
  -oidc-operator-groups pki-operators \
  -oidc-viewer-groups pki-viewers
```

In the container, mount the secret (and your CA bundle, see below) read-only and pass the same options in the Compose `command`; `docker-compose.yml` has the lines ready to uncomment.

| Option (environment variable) | Meaning |
|---|---|
| `-oidc-issuer` (`PKI_DASH_OIDC_ISSUER`) | The realm's issuer URL, `https://HOST/realms/NAME`. Setting it turns SSO on. |
| `-oidc-client-id` (`PKI_DASH_OIDC_CLIENT_ID`) | The client's ID in the provider. |
| `-oidc-client-secret-file` (`PKI_DASH_OIDC_CLIENT_SECRET_FILE`) | File with the client secret. `PKI_DASH_OIDC_CLIENT_SECRET` also works; there is deliberately no flag with the secret in it, because command lines are visible to other users. No secret at all means a public client (PKCE only). |
| `-external-url` (`PKI_DASH_EXTERNAL_URL`) | How browsers reach pki-dash, just scheme and host, for example `https://pki.lab:8443`. The redirect address is built from it and must match what you registered. |
| `-oidc-name` (`PKI_DASH_OIDC_NAME`) | Label on the button. Default `SSO`. |
| `-oidc-admin-groups`, `-oidc-operator-groups`, `-oidc-viewer-groups` (`PKI_DASH_OIDC_*_GROUPS`) | Comma-separated groups for each role. |
| `-oidc-default-role` (`PKI_DASH_OIDC_DEFAULT_ROLE`) | `viewer` or `operator` for people in none of those groups. Empty (the default) means they cannot sign in. `admin` is refused. |
| `-oidc-groups-claim` (`PKI_DASH_OIDC_GROUPS_CLAIM`) | The ID-token claim that lists groups. Default `groups`. A dotted path reaches inside objects, for example `realm_access.roles`. |
| `-oidc-username-claim` (`PKI_DASH_OIDC_USERNAME_CLAIM`) | The claim used as the account name. Default `preferred_username`. |
| `-oidc-ca-file` (`PKI_DASH_OIDC_CA_FILE`) | PEM file with the CA that signed Keycloak's certificate, when it is a private one. Use it with the Root and intermediate you made here. |

Both the issuer and the external URL must be `https`, except for `localhost` while you try things out. pki-dash refuses to start if SSO is half-configured (for example a client ID but no issuer, or no group mapping at all), rather than run without the sign-in you think you have.

## How roles are decided

- The **highest** role among the person's groups wins: admin over operator over viewer.
- Groups are compared whole, ignoring case and a leading `/`: `pki-admins` does not match `pki-admins-old`.
- The role is recalculated at **every sign-in**. If it changed, the person's other sessions end. If they are no longer in any mapped group, their next sign-in is refused.
- An SSO user's role cannot be edited in **Users** (it would be overwritten at the next sign-in), and they have no password to reset. An administrator can still **disable** them there.
- An account is tied to the provider's stable user id (`sub`) and issuer, never to the name or e-mail. Someone whose Keycloak name equals an existing account's gets a different name (a short suffix is added) and cannot take that account over.
- If the last active administrator is an SSO user and the provider would demote them, the sign-in is refused instead of leaving nobody in charge.

## Things to know

- **Signing out** ends the pki-dash session **and** the one at Keycloak (OpenID Connect RP-initiated logout): the browser makes a short trip to Keycloak and returns to the login page, and the next *Sign in with Keycloak* asks for credentials again. This needs the *post logout redirect URI* of step 2. A session that started before this was available, or a provider without a logout endpoint, only ends the pki-dash session.
- To end the Keycloak session at sign-out, pki-dash keeps the ID token of each SSO session in its database until that session ends, and uses it for nothing else. It is a signed statement of who signed in, not a credential that grants access.
- A pki-dash session lasts at most 12 hours (30 minutes idle) regardless of Keycloak. If you remove someone in Keycloak, they are out at their next sign-in or when the session ends, **not instantly**. To cut them off right away, also **disable** them in *Users*.
- The server fetches Keycloak's configuration the first time someone signs in, and again after a failure, so pki-dash starts even while Keycloak is down. SSO is simply unavailable until it is back; local accounts still work.
- Access to pki-dash is not stronger than your Keycloak: use its MFA and password policies.

## When it does not work

The login page shows a short message; the server log has the detail (`oidc: login refused`), and the audit log records failed sign-ins with the reason.

| Message | Usual cause |
|---|---|
| *Your account is not allowed to use this application* | The person is in none of the mapped groups, or the groups are not in the **ID token**. Check the mapper from step 5 (Add to ID token) and the names you passed. |
| *That sign-in expired or was not started here* | The sign-in took over 10 minutes, was opened in a different browser, or the browser blocked the cookie. Make sure `-external-url` is exactly the address in the browser bar, host included. |
| *The identity provider's answer could not be verified* | Wrong client secret; the redirect URI differs from what Keycloak has; the issuer in the tokens differs from `-oidc-issuer` (Keycloak builds it from the address used to reach it); or the clocks of the two servers are far apart. |
| *The identity provider cannot be reached right now* | pki-dash cannot reach the issuer URL from where it runs (inside a container `localhost` is the container itself), or it does not trust Keycloak's certificate: pass `-oidc-ca-file`. |
| Keycloak shows *Invalid redirect uri* when you sign out | *Valid post logout redirect URIs* in the client is missing or is not `EXTERNAL-URL/`. You are signed out of pki-dash anyway; fix the client to sign out of Keycloak as well. |
| Keycloak shows *Invalid parameter: redirect_uri* | The redirect URI registered in the client is not exactly `EXTERNAL-URL/api/v1/auth/oidc/callback`. |

## What is recorded

`user.login` (detail `oidc`), `user.create` and `user.role_change` (actor `oidc`), and `user.login_failed` with `oidc:` and the reason. The audit log and its hash chain work as for local accounts.
