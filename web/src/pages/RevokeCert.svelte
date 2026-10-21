<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import { api, type Cert } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { reasons } from '../lib/revocation';
  import { session } from '../lib/session.svelte';

  let { cert, canPublish, onRevoked, onClose }: { cert: Cert; canPublish: boolean; onRevoked: () => void; onClose: () => void } = $props();

  let reason = $state('');
  let understood = $state(false);
  let busy = $state(false);
  let error = $state('');
  let outcome = $state<'' | 'published' | 'pending' | 'cannot'>('');

  const locked = $derived(!session.vault.unlocked);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      const res = await api.revokeCert(cert.id, reason);
      outcome = res.crl_published ? 'published' : canPublish ? 'pending' : 'cannot';
      onRevoked(); // refresh the list behind the dialog; stay open to say what happened
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('revoke.title', { name: cert.common_name })} {onClose}>
  {#if outcome}
    <Alert kind={outcome === 'published' ? 'info' : 'warning'}>
      {t(outcome === 'published' ? 'revoke.done.published' : outcome === 'pending' ? 'revoke.done.pending' : 'revoke.done.cannot')}
    </Alert>
    <div class="flex justify-end">
      <button type="button" class="btn-primary" onclick={onClose}>{t('common.done')}</button>
    </div>
  {:else}
    <form class="flex flex-col gap-4" onsubmit={submit}>
      <p class="text-sm text-slate-600 dark:text-slate-400">{t('revoke.intro')}</p>
      {#if locked}<Alert kind="warning">{t('revoke.lockedNote')}</Alert>{/if}

      <div>
        <label class="label" for="rv-reason">{t('revoke.reason')}</label>
        <select id="rv-reason" class="input" required bind:value={reason}>
          <option value="" disabled>{t('revoke.reasonPlaceholder')}</option>
          {#each reasons as r (r)}<option value={r}>{t(`reason.${r}`)}</option>{/each}
        </select>
      </div>

      <label class="flex items-start gap-2 text-sm">
        <input type="checkbox" class="mt-1" bind:checked={understood} />
        {t('revoke.confirm')}
      </label>

      {#if error}<Alert>{error}</Alert>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
        <button class="btn bg-red-700 text-white hover:bg-red-800" disabled={busy || !reason || !understood}>{t('revoke.submit')}</button>
      </div>
    </form>
  {/if}
</Dialog>
