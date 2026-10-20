import { api, ApiError, setCsrf, setUnauthorizedHandler, type Role, type Status } from './api';

export type Phase = 'loading' | 'setup' | 'login' | 'ready' | 'error';

interface State {
  phase: Phase;
  username: string;
  role: Role | null;
  vault: { initialized: boolean; unlocked: boolean };
}

export const session: State = $state({
  phase: 'loading',
  username: '',
  role: null,
  vault: { initialized: false, unlocked: false },
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
}

export async function signOut(): Promise<void> {
  try {
    await api.logout();
  } finally {
    signedOut();
    session.phase = 'login';
  }
}

export async function reloadVault(): Promise<void> {
  applyVault(await api.status());
}

export const isAdmin = () => session.role === 'admin';

// An expired session (401 from any call) sends the user back to the login screen.
setUnauthorizedHandler(() => {
  if (session.phase === 'ready') {
    signedOut();
    session.phase = 'login';
  }
});
