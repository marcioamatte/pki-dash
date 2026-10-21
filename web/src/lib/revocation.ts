import type { Crl } from './api';

// The RFC 5280 reasons the server accepts for a service certificate. They are
// sent by name, so a typo can never turn into a different code.
export const reasons = ['key_compromise', 'superseded', 'cessation_of_operation', 'affiliation_changed', 'unspecified'] as const;
export type Reason = (typeof reasons)[number];

export function isReason(v: string | undefined): v is Reason {
  return !!v && (reasons as readonly string[]).includes(v);
}

export type CrlHealth = 'ok' | 'behind' | 'expired' | 'none' | 'cannot_sign';

/**
 * One word for the state of a CA's revocation list. The order matters: a list
 * that clients will refuse (expired) outranks one that is merely behind, and a
 * CA that cannot publish at all outranks everything.
 */
export function crlHealth(c: Pick<Crl, 'can_sign' | 'published' | 'expired' | 'stale'>): CrlHealth {
  if (!c.can_sign) return 'cannot_sign';
  if (!c.published) return 'none';
  if (c.expired) return 'expired';
  if (c.stale) return 'behind';
  return 'ok';
}

/** Lists that need attention now: ones clients will refuse, and ones missing a revocation. */
export function needsAttention(items: Crl[]): { expired: Crl[]; behind: Crl[] } {
  return {
    expired: items.filter((c) => crlHealth(c) === 'expired'),
    behind: items.filter((c) => crlHealth(c) === 'behind'),
  };
}
