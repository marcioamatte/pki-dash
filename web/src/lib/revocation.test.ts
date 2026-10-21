import { describe, expect, it } from 'vitest';
import type { Crl } from './api';
import { crlHealth, isReason, needsAttention, reasons } from './revocation';

const crl = (o: Partial<Crl> = {}): Crl => ({
  ca_id: 'a', ca_name: 'A', key_held: true, can_sign: true, published: true, number: 3,
  revoked: 0, in_list: 0, stale: false, expired: false, ...o,
});

describe('crlHealth', () => {
  it('is ok for a current list', () => expect(crlHealth(crl())).toBe('ok'));
  it('flags a list that misses a revocation', () => expect(crlHealth(crl({ stale: true, revoked: 2, in_list: 1 }))).toBe('behind'));
  it('flags an expired list, which outranks merely being behind', () => {
    expect(crlHealth(crl({ expired: true }))).toBe('expired');
    expect(crlHealth(crl({ expired: true, stale: true }))).toBe('expired');
  });
  it('says none before anything is published', () => expect(crlHealth(crl({ published: false }))).toBe('none'));
  it('puts a CA that cannot sign above everything else', () => {
    expect(crlHealth(crl({ can_sign: false, published: false }))).toBe('cannot_sign');
    expect(crlHealth(crl({ can_sign: false, expired: true, stale: true }))).toBe('cannot_sign');
  });
});

describe('needsAttention', () => {
  it('separates lists that clients refuse from lists that are behind', () => {
    const a = crl({ ca_id: 'a' });
    const b = crl({ ca_id: 'b', stale: true });
    const c = crl({ ca_id: 'c', expired: true });
    const d = crl({ ca_id: 'd', can_sign: false });
    const r = needsAttention([a, b, c, d]);
    expect(r.expired.map((x) => x.ca_id)).toEqual(['c']);
    expect(r.behind.map((x) => x.ca_id)).toEqual(['b']);
  });
});

describe('reasons', () => {
  it('are exactly the ones the server accepts, and never certificate hold', () => {
    expect([...reasons].sort()).toEqual(['affiliation_changed', 'cessation_of_operation', 'key_compromise', 'superseded', 'unspecified']);
    expect(isReason('certificate_hold')).toBe(false);
    expect(isReason('key_compromise')).toBe(true);
    expect(isReason(undefined)).toBe(false);
  });
});
