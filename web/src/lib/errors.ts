import { ApiError } from './api';
import { t } from './i18n.svelte';
import type { MessageKey } from './messages/en';

// Codes with a translated message of their own. Anything else falls back to a
// generic text: server-side wording is English-only and may be technical.
const byCode: Record<string, MessageKey> = {
  invalid_credentials: 'auth.invalid',
  invalid_passphrase: 'vault.invalid',
  bad_setup_token: 'setup.badToken',
  rate_limited: 'common.error.rateLimited',
  forbidden: 'common.error.forbidden',
  network: 'common.error.network',
  vault_locked: 'cas.error.unlock',
  key_offline: 'cas.error.keyOffline',
  already_exists: 'cas.error.exists',
  last_admin: 'users.error.lastAdmin',
  external_user: 'users.error.external',
  revocation_not_published: 'destroy.notPublished',
  not_revoked: 'destroy.notRevoked',
};

/** `overrides` lets a screen give a code its own wording (for example "already exists" for a user). */
/**
 * Server explanations carry Go package prefixes ("ca: certificate violates the CA
 * policy: ..."). The part after them is what a person needs to read.
 */
export function cleanServerMessage(m: string): string {
  const out = m.replace(/^(?:(?:ca|service|store|vault|auth): )?(?:certificate violates the CA policy: |private key does not match certificate: )?/, '');
  return out.charAt(0).toUpperCase() + out.slice(1);
}

export function errorMessage(e: unknown, overrides: Record<string, MessageKey> = {}): string {
  if (e instanceof ApiError) {
    const key = overrides[e.code] ?? byCode[e.code];
    if (key) return t(key);
    // Validation problems are actionable; show the server's explanation.
    if (e.code === 'invalid_input' || e.code === 'bad_request' || e.code === 'policy_violation') return cleanServerMessage(e.message);
  }
  return t('common.error.generic');
}
