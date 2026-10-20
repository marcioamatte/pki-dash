<script lang="ts">
  import { api } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { isAdmin, reloadVault, session } from '../lib/session.svelte';
  import Alert from './Alert.svelte';
  import Field from './Field.svelte';

  let passphrase = $state('');
  let busy = $state(false);
  let error = $state('');

  const uninitialised = $derived(!session.vault.initialized);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      if (uninitialised) await api.initVault(passphrase);
      else await api.unlockVault(passphrase);
      passphrase = ''; // do not keep the secret around longer than needed
      await reloadVault();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="card mb-6 border-amber-300 dark:border-amber-900">
  <h2 class="text-base font-semibold">
    {uninitialised ? t('vault.uninit.title') : t('vault.locked.title')}
  </h2>
  {#if isAdmin()}
    <p class="mt-1 text-sm text-slate-600 dark:text-slate-400">
      {uninitialised ? t('vault.uninit.admin') : t('vault.locked.admin')}
    </p>
    <form class="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end" onsubmit={submit}>
      <div class="flex-1">
        <Field id="vault-pass" type="password" label={t('vault.passphrase')} bind:value={passphrase} autocomplete="off" minlength={12} />
      </div>
      <button class="btn-primary" disabled={busy}>
        {uninitialised ? t('vault.init') : t('vault.unlock')}
      </button>
    </form>
    {#if error}<div class="mt-3"><Alert>{error}</Alert></div>{/if}
  {:else}
    <p class="mt-1 text-sm text-slate-600 dark:text-slate-400">
      {uninitialised ? t('vault.uninit.other') : t('vault.locked.other')}
    </p>
  {/if}
</div>
