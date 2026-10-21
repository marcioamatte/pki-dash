import { describe, expect, it } from 'vitest';
import type { Crl } from './api';
import { caReasons, crlHealth, isReason, needsAttention, reasons } from './revocation';

const crl = (o: Partial<Crl> = {}): Crl => ({
  ca_id: 'a', ca_name: 'A', kind: 'intermediate', external: false, ca_revoked: false, key_held: true, can_sign: true, published: true, number: 3,
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

describe('crlHealth for revoked CAs and for a Root list', () => {
  it('calls a revoked CA retired, whatever else is true of its list', () => {
    expect(crlHealth(crl({ ca_revoked: true, stale: true, expired: true }))).toBe('retired');
  });
  it('waits for the Root list when intermediates are revoked and none is published', () => {
    expect(crlHealth(crl({ kind: 'root', external: true, can_sign: false, published: false, revoked: 2 }))).toBe('awaiting');
    expect(crlHealth(crl({ kind: 'root', external: true, can_sign: false, published: false, revoked: 0 }))).toBe('none');
  });
  it('does not ask a Root whether it can sign: its list comes from elsewhere', () => {
    expect(crlHealth(crl({ kind: 'root', external: true, can_sign: false, published: true }))).toBe('ok');
  });
  it('flags a Root list that is behind or expired like any other', () => {
    expect(crlHealth(crl({ external: true, can_sign: false, stale: true }))).toBe('behind');
    expect(crlHealth(crl({ external: true, can_sign: false, expired: true, stale: true }))).toBe('expired');
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
    expect(r.awaiting).toEqual([]);
  });
});

describe('reasons', () => {
  it('add ca_compromise for a CA, which a service certificate may not use', () => {
    expect(caReasons).toContain('ca_compromise');
    expect(reasons).not.toContain('ca_compromise');
    expect([...caReasons].sort()).toEqual([...reasons, 'ca_compromise'].sort());
  });
  it('are exactly the ones the server accepts, and never certificate hold', () => {
    expect([...reasons].sort()).toEqual(['affiliation_changed', 'cessation_of_operation', 'key_compromise', 'superseded', 'unspecified']);
    expect(isReason('certificate_hold')).toBe(false);
    expect(isReason('key_compromise')).toBe(true);
    expect(isReason(undefined)).toBe(false);
  });
});
