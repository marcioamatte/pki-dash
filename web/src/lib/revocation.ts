import type { Crl } from './api';

// The RFC 5280 reasons the server accepts for a service certificate. They are
// sent by name, so a typo can never turn into a different code.
export const reasons = ['key_compromise', 'superseded', 'cessation_of_operation', 'affiliation_changed', 'unspecified'] as const;
export type Reason = (typeof reasons)[number];

/** A CA can also be revoked because its own key was compromised. */
export const caReasons = ['ca_compromise', ...reasons] as const;
export type CaReason = (typeof caReasons)[number];

export function isReason(v: string | undefined): v is Reason {
  return !!v && (reasons as readonly string[]).includes(v);
}

export type CrlHealth = 'ok' | 'behind' | 'expired' | 'none' | 'cannot_sign' | 'retired' | 'awaiting';

/**
 * One word for the state of a revocation list. The order matters: a CA that was
 * revoked is simply retired, and then a list that clients will refuse (expired)
 * outranks one that is merely behind. A Root's list is made elsewhere, so the
 * question for it is not "can we sign" but "has the list been brought in".
 */
export function crlHealth(
  c: Pick<Crl, 'can_sign' | 'published' | 'expired' | 'stale' | 'external' | 'ca_revoked' | 'revoked'>,
): CrlHealth {
  if (c.ca_revoked) return 'retired';
  if (c.external) {
    if (!c.published) return c.revoked > 0 ? 'awaiting' : 'none';
  } else {
    if (!c.can_sign) return 'cannot_sign';
    if (!c.published) return 'none';
  }
  if (c.expired) return 'expired';
  if (c.stale) return 'behind';
  return 'ok';
}

/** Lists that need attention now: ones clients will refuse, and ones missing a revocation. */
export function needsAttention(items: Crl[]): { expired: Crl[]; behind: Crl[]; awaiting: Crl[] } {
  return {
    expired: items.filter((c) => crlHealth(c) === 'expired'),
    behind: items.filter((c) => crlHealth(c) === 'behind'),
    awaiting: items.filter((c) => crlHealth(c) === 'awaiting'),
  };
}
