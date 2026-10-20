<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import PemInput from '../components/PemInput.svelte';
  import { api, type PendingCA } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';

  let { request, onImported, onClose }: { request: PendingCA; onImported: () => void; onClose: () => void } = $props();

  let cert = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await api.importIntermediate(request.id, cert);
      onImported();
    } catch (err) {
      // A refusal explains itself ("not signed by the chosen Root", "path length"...)
      // and leaves the request in place, so the user can fix the file and retry.
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('pending.import.title', { name: request.name })} {onClose} wide>
  <form class="flex flex-col gap-4" onsubmit={submit}>
    <PemInput id="ic-cert" label={t('pending.import.cert')} hint={t('pending.import.hint')} bind:value={cert} />
    {#if error}<Alert>{error}</Alert>{/if}
    <div class="flex justify-end gap-2">
      <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
      <button class="btn-primary" disabled={busy}>{t('pending.import.submit')}</button>
    </div>
  </form>
</Dialog>
