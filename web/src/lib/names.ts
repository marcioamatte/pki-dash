/** Splits free text (lines, commas, spaces) into unique, trimmed, non-empty entries. */
export function parseList(text: string): string[] {
  const seen = new Set<string>();
  for (const part of text.split(/[\s,;]+/)) {
    const v = part.trim();
    if (v) seen.add(v);
  }
  return [...seen];
}

const DAY = 24 * 60 * 60 * 1000;

/** Whole days until `iso`, rounded up; negative once expired. */
export function daysLeft(iso: string, now: Date = new Date()): number {
  return Math.ceil((new Date(iso).getTime() - now.getTime()) / DAY);
}

export type Expiry = 'expired' | 'soon' | 'ok';

export const EXPIRING_SOON_DAYS = 30;

export function expiryState(iso: string, now: Date = new Date()): Expiry {
  const d = daysLeft(iso, now);
  if (d <= 0) return 'expired';
  return d <= EXPIRING_SOON_DAYS ? 'soon' : 'ok';
}

/** The longest validity browsers accept for public certificates; we only warn above it. */
export const BROWSER_MAX_DAYS = 398;
