import { api, ApiError, setCsrf, setUnauthorizedHandler, type Role, type Status } from './api';

export type Phase = 'loading' | 'setup' | 'login' | 'ready' | 'error';

interface State {
  phase: Phase;
  username: string;
  role: Role | null;
  vault: { initialized: boolean; unlocked: boolean };
  /** Where clients reach the public listener (CRLs, CA certificates); empty when not configured. */
  publicUrl: string;
  /** The identity provider's button label, or empty when only local sign-in exists. */
  ssoName: string;
}

export const session: State = $state({
  phase: 'loading',
  username: '',
  role: null,
  vault: { initialized: false, unlocked: false },
  publicUrl: '',
  ssoName: '',
});

function applyVault(s: Status) {
  session.vault.initialized = s.vault_initialized;
  session.vault.unlocked = s.vault_unlocked;
}

function signedOut() {
  setCsrf('');
  session.username = '';
  session.role = null;
}

/** Works out where the user stands: first run, signed out, or signed in. */
export async function refresh(): Promise<void> {
  try {
    const st = await api.status();
    applyVault(st);
    session.ssoName = st.oidc?.name ?? '';
    if (st.needs_setup) {
      signedOut();
      session.phase = 'setup';
      return;
    }
    try {
      const me = await api.me();
      setCsrf(me.csrf_token);
      session.username = me.username;
      session.role = me.role;
      session.phase = 'ready';
      loadConfig();
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 401)) throw e;
      signedOut();
      session.phase = 'login';
    }
  } catch {
    session.phase = 'error';
  }
}

export async function signIn(username: string, password: string): Promise<void> {
  const s = await api.login(username, password);
  setCsrf(s.csrf_token);
  session.username = s.username;
  session.role = s.role;
  applyVault(await api.status());
  session.phase = 'ready';
  loadConfig();
}

/** Best effort: without it the signing recipes simply carry no CRL pointers. */
function loadConfig() {
  api.config().then((c) => (session.publicUrl = c.public_url)).catch(() => (session.publicUrl = ''));
}

export async function signOut(): Promise<void> {
  let next: string | undefined;
  try {
    next = (await api.logout())?.logout_url;
  } finally {
    signedOut();
    session.phase = 'login';
  }
  // For an SSO session, go through the provider's logout so its own session ends
  // too; otherwise "Sign in" would walk straight back in. It returns here after.
  if (next && /^https?:\/\//.test(next)) location.assign(next);
}

export async function reloadVault(): Promise<void> {
  applyVault(await api.status());
}

export const isAdmin = () => session.role === 'admin';
/** Admins and operators can issue certificates; viewers cannot. */
export const canIssue = () => session.role === 'admin' || session.role === 'operator';
/** The same people who can issue can revoke: the server decides, this only hides the buttons. */
export const canRevoke = canIssue;

// An expired session (401 from any call) sends the user back to the login screen.
setUnauthorizedHandler(() => {
  if (session.phase === 'ready') {
    signedOut();
    session.phase = 'login';
  }
});
