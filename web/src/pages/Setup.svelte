<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Field from '../components/Field.svelte';
  import { api } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { signIn } from '../lib/session.svelte';

  let token = $state('');
  let username = $state('');
  let password = $state('');
  let password2 = $state('');
  let passphrase = $state('');
  let passphrase2 = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (password !== password2 || passphrase !== passphrase2) {
      error = t('setup.mismatch');
      return;
    }
    busy = true;
    try {
      await api.setup({ setup_token: token.trim(), username: username.trim(), password, master_passphrase: passphrase });
      await signIn(username.trim(), password);
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="mx-auto max-w-lg">
  <form class="card flex flex-col gap-4" onsubmit={submit}>
    <div>
      <h1 class="text-xl font-semibold">{t('setup.title')}</h1>
      <p class="mt-1 text-sm text-slate-600 dark:text-slate-400">{t('setup.intro')}</p>
    </div>

    <Field id="token" label={t('setup.token')} hint={t('setup.tokenHelp')} bind:value={token} />
    <Field id="admin-user" label={t('setup.username')} bind:value={username} autocomplete="username" />
    <Field id="admin-pass" type="password" label={t('setup.password')} hint={t('setup.passwordHelp')} bind:value={password} autocomplete="new-password" minlength={12} />
    <Field id="admin-pass2" type="password" label={t('setup.passwordConfirm')} bind:value={password2} autocomplete="new-password" minlength={12} />

    <hr class="border-slate-200 dark:border-slate-800" />

    <Alert kind="warning">{t('setup.passphraseWarning')}</Alert>
    <Field id="master" type="password" label={t('setup.passphrase')} hint={t('setup.passphraseHelp')} bind:value={passphrase} autocomplete="off" minlength={12} />
    <Field id="master2" type="password" label={t('setup.passphraseConfirm')} bind:value={passphrase2} autocomplete="off" minlength={12} />

    {#if error}<Alert>{error}</Alert>{/if}
    <button class="btn-primary" disabled={busy}>{t('setup.submit')}</button>
  </form>
</div>
