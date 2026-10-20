import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError, setCsrf, setUnauthorizedHandler } from './api';
import { cleanServerMessage, errorMessage } from './errors';
import { detectLocale, interpolate, setLocale } from './i18n.svelte';
import { en } from './messages/en';
import { ptBR } from './messages/pt-BR';

describe('i18n', () => {
  it('interpolates placeholders as plain text and leaves unknown ones alone', () => {
    expect(interpolate('Hello {name}!', { name: 'Ana' })).toBe('Hello Ana!');
    expect(interpolate('{a} {b}', { a: 1 })).toBe('1 {b}');
    expect(interpolate('<b>{x}</b>', { x: '<script>' })).toBe('<b><script></b>'); // text only: rendering never uses innerHTML
    expect(interpolate('no params')).toBe('no params');
  });

  it('detects the locale: saved choice, then browser language, then English', () => {
    expect(detectLocale('en-US', 'pt-BR')).toBe('pt-BR');
    expect(detectLocale('pt-BR', null)).toBe('pt-BR');
    expect(detectLocale('pt-PT', null)).toBe('pt-BR');
    expect(detectLocale('fr-FR', null)).toBe('en');
    expect(detectLocale(undefined, null)).toBe('en');
    expect(detectLocale('pt-BR', 'xx')).toBe('pt-BR'); // a corrupt saved value is ignored
  });

  it('keeps the translations in step with English', () => {
    expect(Object.keys(ptBR).sort()).toEqual(Object.keys(en).sort());
    const placeholders = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join();
    for (const k of Object.keys(en) as (keyof typeof en)[]) {
      expect(ptBR[k], k).not.toBe('');
      expect(placeholders(ptBR[k]), `placeholders of ${k}`).toBe(placeholders(en[k]));
    }
  });
});

describe('api client', () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    setCsrf('tok123');
    setUnauthorizedHandler(() => {});
  });
  afterEach(() => {
    fetchMock.mockReset();
    vi.unstubAllGlobals();
  });
  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

  it('sends the CSRF token on state-changing requests only, and never leaves the origin', async () => {
    fetchMock.mockResolvedValue(json(200, []));
    await api.listCAs();
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/v1/cas');
    expect(fetchMock.mock.calls[0]![1].headers['X-CSRF-Token']).toBeUndefined();

    fetchMock.mockResolvedValue(json(201, {}));
    await api.createCA({ kind: 'root', name: 'R', validity_days: 30, key_algo: 'ecdsa-p384' });
    const init = fetchMock.mock.calls[1]![1];
    expect(init.headers['X-CSRF-Token']).toBe('tok123');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.credentials).toBe('same-origin');
    expect(JSON.parse(init.body).name).toBe('R');
  });

  it('treats 204 as success without a body', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(api.logout()).resolves.toBeUndefined();
  });

  it('turns API errors into ApiError with the server code', async () => {
    fetchMock.mockResolvedValue(json(409, { error: { code: 'vault_locked', message: 'locked' } }));
    const err = await api.listCAs().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 409, code: 'vault_locked' });
  });

  it('survives non-JSON error bodies and network failures', async () => {
    fetchMock.mockResolvedValue(new Response('<html>bad gateway</html>', { status: 502 }));
    expect(await api.listCAs().catch((e) => e)).toMatchObject({ status: 502, code: 'unknown' });
    fetchMock.mockRejectedValue(new TypeError('failed to fetch'));
    expect(await api.listCAs().catch((e) => e)).toMatchObject({ status: 0, code: 'network' });
  });

  it('calls the unauthorized handler only when the session has ended', async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetchMock.mockResolvedValue(json(401, { error: { code: 'invalid_credentials', message: 'x' } }));
    await api.login('a', 'b').catch(() => {});
    expect(handler).not.toHaveBeenCalled(); // a failed login is not an expired session
    fetchMock.mockResolvedValue(json(401, { error: { code: 'unauthenticated', message: 'x' } }));
    await api.listCAs().catch(() => {});
    expect(handler).toHaveBeenCalledOnce();
  });
});

describe('cleanServerMessage', () => {
  it('drops Go package prefixes and keeps the useful explanation', () => {
    expect(cleanServerMessage('ca: certificate violates the CA policy: not signed by the chosen Root')).toBe('Not signed by the chosen Root');
    expect(cleanServerMessage('ca: private key does not match certificate: the certificate is not for the key that made the request')).toBe(
      'The certificate is not for the key that made the request',
    );
    expect(cleanServerMessage('ca: invalid request: common name is required')).toBe('Invalid request: common name is required');
    expect(cleanServerMessage('plain text')).toBe('Plain text');
  });
});

describe('errorMessage', () => {
  beforeEach(() => setLocale('en')); // do not depend on the machine's language
  it('uses translated texts for known codes', () => {
    expect(errorMessage(new ApiError(401, 'invalid_credentials', 'x'))).toBe(en['auth.invalid']);
    expect(errorMessage(new ApiError(0, 'network', 'x'))).toBe(en['common.error.network']);
    expect(errorMessage(new ApiError(429, 'rate_limited', 'x'))).toBe(en['common.error.rateLimited']);
  });

  it('shows validation explanations but hides everything else behind a generic message', () => {
    expect(errorMessage(new ApiError(400, 'invalid_input', 'common name is required'))).toBe('Common name is required');
    expect(errorMessage(new ApiError(500, 'internal', 'pq: connection refused at 10.0.0.1'))).toBe(en['common.error.generic']);
    expect(errorMessage(new Error('boom'))).toBe(en['common.error.generic']);
  });
});
