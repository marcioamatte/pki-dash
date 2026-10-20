// Thin client for the pki-dash JSON API. It never stores credentials: the
// session lives in an HttpOnly cookie the browser manages, and the only secret
// held here is the per-session CSRF token, in memory.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken = '';
let onUnauthorized: () => void = () => {};

export function setCsrf(token: string): void {
  csrfToken = token;
}

/** Called when an authenticated request comes back 401 (the session ended). */
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

const base = '/api/v1';

async function call<T>(method: string, path: string, body: unknown, as: 'json' | 'text'): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken;

  let res: Response;
  try {
    res = await fetch(base + path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'network', 'network error');
  }

  if (res.status === 204) return undefined as T;
  if (res.ok && as === 'text') return (await res.text()) as T;

  let data: unknown;
  try {
    data = await res.json();
  } catch {
    data = undefined;
  }
  if (!res.ok) {
    const e = (data as { error?: { code?: string; message?: string } } | undefined)?.error;
    if (res.status === 401 && e?.code === 'unauthenticated') onUnauthorized();
    throw new ApiError(res.status, e?.code ?? 'unknown', e?.message ?? res.statusText);
  }
  return data as T;
}

const request = <T>(method: string, path: string, body?: unknown) => call<T>(method, path, body, 'json');
const requestText = (method: string, path: string, body?: unknown) => call<string>(method, path, body, 'text');

// ---- types ----

export type Role = 'admin' | 'operator' | 'viewer';
export interface Status {
  needs_setup: boolean;
  vault_initialized: boolean;
  vault_unlocked: boolean;
}
export interface SessionInfo {
  username: string;
  role: Role;
  csrf_token: string;
  expires_at: string;
}
export interface CA {
  id: string;
  name: string;
  kind: 'root' | 'intermediate';
  parent_id?: string;
  not_before: string;
  not_after: string;
  created_at: string;
  key_held: boolean;
}
export type Profile = 'server' | 'client' | 'both';
export interface Cert {
  id: string;
  ca_id: string;
  serial: string;
  common_name: string;
  sans: string[];
  profile: Profile;
  not_before: string;
  not_after: string;
  key_generated: boolean;
  created_at: string;
}
export interface NewCert {
  common_name: string;
  dns_names: string[];
  ip_addresses: string[];
  profile: Profile;
  validity_days: number;
  key_algo?: KeyAlgo;
  csr_pem?: string;
}
export interface Issued {
  id: string;
  certificate_pem: string;
  private_key_pem?: string;
  chain_pem: string;
}
export interface User {
  id: string;
  username: string;
  role: Role;
  auth_source: 'local' | 'oidc';
  disabled: boolean;
  created_at: string;
}
export interface AuditEntry {
  seq: number;
  time: string;
  actor: string;
  action: string;
  target: string;
  detail: string;
}
export interface PendingCA {
  id: string;
  name: string;
  parent_id: string;
  created_at: string;
}
export interface RequestCreated extends PendingCA {
  csr_pem: string;
}
export type KeyAlgo = 'ecdsa-p256' | 'ecdsa-p384' | 'rsa-3072' | 'rsa-4096';
export interface NewCA {
  kind: 'root' | 'intermediate';
  parent_id?: string;
  name: string;
  organization?: string;
  validity_days: number;
  key_algo: KeyAlgo;
}

// ---- endpoints ----

export const api = {
  status: () => request<Status>('GET', '/status'),
  setup: (b: { setup_token: string; username: string; password: string; master_passphrase: string }) =>
    request<{ username: string }>('POST', '/setup', b),
  login: (username: string, password: string) =>
    request<SessionInfo>('POST', '/login', { username, password }),
  logout: () => request<void>('POST', '/logout'),
  me: () => request<SessionInfo>('GET', '/me'),

  initVault: (master_passphrase: string) => request<void>('POST', '/vault/init', { master_passphrase }),
  unlockVault: (master_passphrase: string) => request<void>('POST', '/vault/unlock', { master_passphrase }),

  listCAs: () => request<CA[]>('GET', '/cas'),
  createCA: (b: NewCA) => request<CA>('POST', '/cas', b),

  listUsers: () => request<User[]>('GET', '/users'),
  createUser: (b: { username: string; password: string; role: Role }) => request<{ id: string }>('POST', '/users', b),
  patchUser: (id: string, b: { role?: Role; disabled?: boolean }) =>
    request<void>('PATCH', `/users/${encodeURIComponent(id)}`, b),
  resetPassword: (id: string, new_password: string) =>
    request<void>('POST', `/users/${encodeURIComponent(id)}/password`, { new_password }),
  changeOwnPassword: (current_password: string, new_password: string) =>
    request<void>('POST', '/me/password', { current_password, new_password }),

  audit: (limit: number) => request<AuditEntry[]>('GET', `/audit?limit=${limit}`),
  auditVerify: () => request<{ ok: boolean; message?: string }>('GET', '/audit/verify'),

  /** The Root's private key as PEM text. The most sensitive response this API has. */
  exportKey: (id: string, master_passphrase: string) =>
    requestText('POST', `/cas/${encodeURIComponent(id)}/export-key`, { master_passphrase }),
  removeKey: (id: string, master_passphrase: string, confirm_name: string) =>
    request<void>('POST', `/cas/${encodeURIComponent(id)}/remove-key`, { master_passphrase, confirm_name }),

  importRoot: (name: string, certificate_pem: string) =>
    request<CA>('POST', '/cas/import-root', { name, certificate_pem }),
  requestIntermediate: (parentId: string, b: { name: string; organization?: string; key_algo: KeyAlgo }) =>
    request<RequestCreated>('POST', `/cas/${encodeURIComponent(parentId)}/intermediate-requests`, b),
  listRequests: () => request<PendingCA[]>('GET', '/intermediate-requests'),
  importIntermediate: (id: string, certificate_pem: string) =>
    request<CA>('POST', `/intermediate-requests/${encodeURIComponent(id)}/import`, { certificate_pem }),
  cancelRequest: (id: string) => request<void>('DELETE', `/intermediate-requests/${encodeURIComponent(id)}`),

  listCerts: (caId?: string) => request<Cert[]>('GET', '/certificates' + (caId ? `?ca_id=${encodeURIComponent(caId)}` : '')),
  issueCert: (caId: string, b: NewCert) => request<Issued>('POST', `/cas/${encodeURIComponent(caId)}/certificates`, b),
};

export const downloadURL = {
  requestCSR: (id: string) => `${base}/intermediate-requests/${encodeURIComponent(id)}/csr`,
  certPEM: (id: string) => `${base}/certificates/${encodeURIComponent(id)}/pem`,
  certFullchain: (id: string) => `${base}/certificates/${encodeURIComponent(id)}/fullchain`,
  caCert: (id: string) => `${base}/cas/${encodeURIComponent(id)}/cert`,
  caChain: (id: string) => `${base}/cas/${encodeURIComponent(id)}/chain`,
};
