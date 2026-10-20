<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Field from '../components/Field.svelte';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { signIn } from '../lib/session.svelte';

  let username = $state('');
  let password = $state('');
  let busy = $state(false);
  let error = $state('');

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
    <Field id="username" label={t('auth.username')} bind:value={username} autocomplete="username" />
    <Field id="password" type="password" label={t('auth.password')} bind:value={password} autocomplete="current-password" />
    {#if error}<Alert>{error}</Alert>{/if}
    <button class="btn-primary" disabled={busy}>{t('auth.signIn')}</button>
  </form>
</div>
