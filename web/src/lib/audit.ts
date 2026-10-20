import type { AuditEntry } from './api';

/** Case-insensitive match of every word in `query` against the entry's text fields. */
export function filterAudit(entries: AuditEntry[], query: string): AuditEntry[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return entries;
  return entries.filter((e) => {
    const hay = `${e.actor} ${e.action} ${e.target} ${e.detail}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}

// Actions an administrator should notice at a glance: failed or locked sign-ins,
// anything touching keys or the master passphrase, and changes to who can do what.
const sensitive = new Set([
  'user.login_failed',
  'user.locked',
  'user.password_change_failed',
  'vault.unlock_failed',
  'vault.reauth_failed',
  'vault.passphrase_changed',
  'ca.export_key',
  'ca.drop_key',
  'user.role_change',
  'user.disable',
  'user.password_change',
]);

export function isSensitive(action: string): boolean {
  return sensitive.has(action);
}
