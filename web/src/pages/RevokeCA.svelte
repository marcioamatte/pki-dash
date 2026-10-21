<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import { api, type CA } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { caReasons } from '../lib/revocation';

  let { ca, onRevoked, onPublish, onClose }: { ca: CA; onRevoked: () => void; onPublish: (rootId: string) => void; onClose: () => void } = $props();

  let reason = $state('');
  let understood = $state(false);
  let busy = $state(false);
  let error = $state('');
  let rootId = $state('');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      rootId = (await api.revokeCA(ca.id, reason)).root_id;
      onRevoked();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('revokeCa.title', { name: ca.name })} {onClose}>
  {#if rootId}
    <Alert kind="info">{t('revokeCa.done')}</Alert>
    <p class="text-sm">{t('revokeCa.next')}</p>
    <div class="flex justify-end gap-2">
      <button type="button" class="btn-secondary" onclick={onClose}>{t('common.close')}</button>
      <button type="button" class="btn-primary" onclick={() => onPublish(rootId)}>{t('revokeCa.publishNow')}</button>
    </div>
  {:else}
    <form class="flex flex-col gap-4" onsubmit={submit}>
      <p class="text-sm text-slate-600 dark:text-slate-400">{t('revokeCa.intro')}</p>
      <Alert kind="warning">{t('revokeCa.warn')}</Alert>
      <div>
        <label class="label" for="rca-reason">{t('revoke.reason')}</label>
        <select id="rca-reason" class="input" required bind:value={reason}>
          <option value="" disabled>{t('revoke.reasonPlaceholder')}</option>
          {#each caReasons as r (r)}<option value={r}>{t(`reason.${r}`)}</option>{/each}
        </select>
      </div>
      <label class="flex items-start gap-2 text-sm">
        <input type="checkbox" class="mt-1" bind:checked={understood} />
        {t('revokeCa.confirm')}
      </label>
      {#if error}<Alert>{error}</Alert>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
        <button class="btn bg-red-700 text-white hover:bg-red-800" disabled={busy || !reason || !understood}>{t('revokeCa.submit')}</button>
      </div>
    </form>
  {/if}
</Dialog>
