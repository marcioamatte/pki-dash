import { describe, expect, it } from 'vitest';
import type { AuditEntry } from './api';
import { filterAudit, isSensitive } from './audit';

const e = (seq: number, actor: string, action: string, target = '', detail = ''): AuditEntry => ({
  seq,
  time: '2026-10-20T12:00:00Z',
  actor,
  action,
  target,
  detail,
});
const entries = [
  e(1, 'marcio', 'ca.create', 'abc', 'root Lab Root'),
  e(2, 'marcio', 'cert.issue', 'def', 'ca=abc cn=app.lab'),
  e(3, 'mallory', 'user.login_failed', '', 'wrong password'),
];

describe('filterAudit', () => {
  it('returns everything for an empty query', () => {
    expect(filterAudit(entries, '')).toHaveLength(3);
    expect(filterAudit(entries, '   ')).toHaveLength(3);
  });
  it('matches case-insensitively across all fields', () => {
    expect(filterAudit(entries, 'MALLORY').map((x) => x.seq)).toEqual([3]);
    expect(filterAudit(entries, 'app.lab').map((x) => x.seq)).toEqual([2]);
    expect(filterAudit(entries, 'root lab').map((x) => x.seq)).toEqual([1]);
  });
  it('requires every word to match', () => {
    expect(filterAudit(entries, 'marcio issue').map((x) => x.seq)).toEqual([2]);
    expect(filterAudit(entries, 'marcio nothing')).toEqual([]);
  });
});

describe('isSensitive', () => {
  it('flags failures, key handling and permission changes, but not routine actions', () => {
    for (const a of ['user.login_failed', 'user.locked', 'ca.export_key', 'ca.drop_key', 'vault.unlock_failed', 'user.role_change']) {
      expect(isSensitive(a), a).toBe(true);
    }
    for (const a of ['user.login', 'cert.issue', 'ca.create', 'vault.unlock']) expect(isSensitive(a), a).toBe(false);
  });
});
