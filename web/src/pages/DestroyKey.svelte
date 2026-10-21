<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import { api, ApiError, type CA } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';

  // Destroys the private key of a revoked intermediate. Irreversible, so the
  // name is typed and the master passphrase asked for, as for a Root's key.
  let { ca, onDestroyed, onPublish, onClose }: { ca: CA; onDestroyed: () => void; onPublish: (rootId: string) => void; onClose: () => void } = $props();

  let confirmName = $state('');
  let pass = $state('');
  let busy = $state(false);
  let error = $state('');
  let notPublished = $state(false);
  let done = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    notPublished = false;
    try {
      await api.removeKey(ca.id, pass, confirmName);
      pass = '';
      done = true;
      onDestroyed();
    } catch (err) {
      notPublished = err instanceof ApiError && err.code === 'revocation_not_published';
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('destroy.title', { name: ca.name })} {onClose}>
  {#if done}
    <Alert kind="info">{t('destroy.done', { name: ca.name })}</Alert>
    <div class="flex justify-end">
      <button type="button" class="btn-primary" onclick={onClose}>{t('common.done')}</button>
    </div>
  {:else}
    <form class="flex flex-col gap-4" onsubmit={submit}>
      <p class="text-sm text-slate-600 dark:text-slate-400">{t('destroy.intro')}</p>
      <Alert kind="warning">{t('destroy.warn')}</Alert>
      <Field id="destroy-name" label={t('offline.remove.confirmName', { name: ca.name })} bind:value={confirmName} autocomplete="off" />
      <Field id="destroy-pass" type="password" label={t('vault.passphrase')} bind:value={pass} autocomplete="off" />
      {#if error}<Alert>{error}</Alert>{/if}
      <div class="flex flex-wrap justify-end gap-2">
        <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
        {#if notPublished && ca.parent_id}
          <button type="button" class="btn-secondary" onclick={() => onPublish(ca.parent_id!)}>{t('destroy.publishNow')}</button>
        {/if}
        <button class="btn bg-red-700 text-white hover:bg-red-800" disabled={busy || confirmName !== ca.name || !pass}>{t('destroy.submit')}</button>
      </div>
    </form>
  {/if}
</Dialog>
