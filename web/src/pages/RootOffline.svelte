<script lang="ts">
  import { onDestroy } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import { api, type CA } from '../lib/api';
  import { textDownload, type TextDownload } from '../lib/download';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { fileName } from '../lib/trust';

  // A guided way to take a Root offline: save its key, confirm, then make the
  // service forget it. Each step is its own screen so nothing happens by accident.
  let {
    ca,
    hasIntermediates,
    onChanged,
    onClose,
  }: { ca: CA; hasIntermediates: boolean; onChanged: () => void; onClose: () => void } = $props();

  type Step = 'intro' | 'export' | 'exported' | 'remove' | 'done';
  let step = $state<Step>('intro');
  let pass = $state('');
  let confirmName = $state('');
  let saved = $state(false);
  let keyFile = $state<TextDownload | null>(null);
  let kept = $state(false);
  let busy = $state(false);
  let error = $state('');

  // The key must not outlive this window: revoke the object URL that holds it.
  onDestroy(() => keyFile?.revoke());

  async function doExport(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      keyFile = textDownload(await api.exportKey(ca.id, pass)); // the text itself is not kept in a variable
      pass = '';
      step = 'exported';
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }

  async function doRemove(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      await api.removeKey(ca.id, pass, confirmName);
      pass = '';
      step = 'done';
      onChanged();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }

  function finishKeeping() {
    kept = true;
    step = 'done';
  }
</script>

<Dialog title={t('offline.title', { name: ca.name })} {onClose} wide>
  {#if step === 'intro'}
    <div class="flex flex-col gap-3 text-sm">
      <p>{t('offline.intro1')}</p>
      <p>{t('offline.intro2')}</p>
      <Alert kind="warning">{t('offline.intro3')}</Alert>
      {#if !hasIntermediates}<Alert>{t('offline.needIntermediate')}</Alert>{/if}
    </div>
    <div class="flex justify-end gap-2">
      <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
      <button type="button" class="btn-primary" disabled={!hasIntermediates} onclick={() => (step = 'export')}>{t('offline.continue')}</button>
    </div>
  {:else if step === 'export'}
    <h3 class="text-sm font-semibold">{t('offline.step1')}</h3>
    <form class="flex flex-col gap-4" onsubmit={doExport}>
      <Field id="off-pass" type="password" label={t('vault.passphrase')} hint={t('offline.export.help')} bind:value={pass} autocomplete="off" />
      {#if error}<Alert>{error}</Alert>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
        <button class="btn-primary" disabled={busy}>{t('offline.export')}</button>
      </div>
    </form>
  {:else if step === 'exported' && keyFile}
    <h3 class="text-sm font-semibold">{t('offline.step2')}</h3>
    <Alert kind="warning">{t('offline.exported.warning')}</Alert>
    <div>
      <a class="btn-primary" href={keyFile.url} download={fileName.caKey(ca.name)}>
        {t('offline.downloadKey', { file: fileName.caKey(ca.name) })}
      </a>
    </div>
    <label class="flex items-start gap-2 text-sm">
      <input type="checkbox" class="mt-1" bind:checked={saved} />
      {t('offline.saved')}
    </label>
    <div class="flex flex-wrap justify-end gap-2">
      <button type="button" class="btn-secondary" onclick={finishKeeping}>{t('offline.keepKey')}</button>
      <button type="button" class="btn-primary" disabled={!saved} onclick={() => { step = 'remove'; error = ''; }}>{t('offline.toRemove')}</button>
    </div>
  {:else if step === 'remove'}
    <h3 class="text-sm font-semibold">{t('offline.step3')}</h3>
    <Alert kind="warning">{t('offline.intro3')}</Alert>
    <form class="flex flex-col gap-4" onsubmit={doRemove}>
      <p class="text-sm">{t('offline.remove.help')}</p>
      <Field id="off-name" label={t('offline.remove.confirmName', { name: ca.name })} bind:value={confirmName} autocomplete="off" />
      <Field id="off-pass2" type="password" label={t('vault.passphrase')} bind:value={pass} autocomplete="off" />
      {#if error}<Alert>{error}</Alert>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
        <button class="btn bg-red-700 text-white hover:bg-red-800" disabled={busy || confirmName !== ca.name}>{t('offline.remove.submit')}</button>
      </div>
    </form>
  {:else}
    <h3 class="text-base font-semibold">{kept ? t('offline.done.kept') : t('offline.done.title')}</h3>
    {#if !kept}<p class="text-sm">{t('offline.done.text', { name: ca.name })}</p>{/if}
    <div class="flex justify-end">
      <button type="button" class="btn-primary" onclick={onClose}>{t('common.done')}</button>
    </div>
  {/if}
</Dialog>
