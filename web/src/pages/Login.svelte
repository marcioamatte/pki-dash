<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Field from '../components/Field.svelte';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import type { MessageKey } from '../lib/messages/en';
  import { session, signIn } from '../lib/session.svelte';

  let username = $state('');
  let password = $state('');
  let busy = $state(false);
  let error = $state('');

  // The server sends people back from the identity provider with a fixed code.
  // Only codes we know become text; anything else is ignored.
  const ssoErrors: Record<string, MessageKey> = {
    no_access: 'auth.sso.error.no_access',
    denied: 'auth.sso.error.denied',
    state: 'auth.sso.error.state',
    token: 'auth.sso.error.token',
    unavailable: 'auth.sso.error.unavailable',
    busy: 'auth.sso.error.busy',
    failed: 'auth.sso.error.failed',
  };
  const ssoCode = new URLSearchParams(location.search).get('sso_error') ?? '';
  if (ssoCode) {
    error = t(ssoErrors[ssoCode] ?? 'auth.sso.error.failed');
    history.replaceState(null, '', location.pathname + location.hash); // so a reload does not show it again
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await signIn(username, password);
    } catch (err) {
      error = errorMessage(err);
      password = '';
    } finally {
      busy = false;
    }
  }
</script>

<div class="mx-auto mt-8 max-w-sm">
  <form class="card flex flex-col gap-4" onsubmit={submit}>
    <h1 class="text-xl font-semibold">{t('auth.login.title')}</h1>
    {#if session.ssoName}
      <!-- A plain link: the whole sign-in is a redirect dance the server runs. -->
      <a class="btn-primary text-center" href="/api/v1/auth/oidc/login">{t('auth.sso.signInWith', { name: session.ssoName })}</a>
      <p class="text-center text-sm text-slate-500">{t('auth.sso.or')}</p>
    {/if}
    <Field id="username" label={t('auth.username')} bind:value={username} autocomplete="username" />
    <Field id="password" type="password" label={t('auth.password')} bind:value={password} autocomplete="current-password" />
    {#if error}<Alert>{error}</Alert>{/if}
    <button class="btn-primary" disabled={busy}>{t('auth.signIn')}</button>
  </form>
</div>
