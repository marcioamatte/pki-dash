<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import PemInput from '../components/PemInput.svelte';
  import { api } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';

  let { onImported, onClose }: { onImported: () => void; onClose: () => void } = $props();

  let name = $state('');
  let cert = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await api.importRoot(name.trim(), cert);
      onImported();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('import.root.title')} {onClose} wide>
  <p class="text-sm text-slate-600 dark:text-slate-400">{t('import.root.intro')}</p>
  <form class="flex flex-col gap-4" onsubmit={submit}>
    <Field id="ir-name" label={t('import.root.name')} bind:value={name} />
    <PemInput id="ir-cert" label={t('import.root.cert')} hint={t('import.root.certHint')} bind:value={cert} />
    {#if error}<Alert>{error}</Alert>{/if}
    <div class="flex justify-end gap-2">
      <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
      <button class="btn-primary" disabled={busy}>{t('import.root.submit')}</button>
    </div>
  </form>
</Dialog>
