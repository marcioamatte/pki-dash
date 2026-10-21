<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import SignGuide from '../components/SignGuide.svelte';
  import { api, type CA, type KeyAlgo, type RequestCreated } from '../lib/api';
  import { textDownload, type TextDownload } from '../lib/download';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { csrFileName } from '../lib/signing';

  let {
    roots,
    onCreated,
    onChanged,
    onClose,
  }: { roots: CA[]; onCreated: () => void; onChanged: () => void; onClose: () => void } = $props();

  // The dialog is created when opened, so the initial snapshot of roots is what we want.
  let kind = $state<'root' | 'intermediate'>(untrack(() => (roots.length === 0 ? 'root' : 'intermediate')));
  let parentId = $state(untrack(() => (roots.find((r) => r.key_held) ?? roots[0])?.id ?? ''));
  let viaRequest = $state(false);
  let name = $state('');
  let organization = $state('');
  let years = $state('');
  let algo = $state<KeyAlgo>('ecdsa-p256');
  let busy = $state(false);
  let error = $state('');

  let requested = $state<RequestCreated | null>(null);
  let csrFile = $state<TextDownload | null>(null);
  onDestroy(() => csrFile?.revoke());

  const algos: KeyAlgo[] = ['ecdsa-p384', 'ecdsa-p256', 'rsa-3072', 'rsa-4096'];
  const defaultYears = { root: '10', intermediate: '5' };

  const parent = $derived(roots.find((r) => r.id === parentId));
  // A Root whose key is not here can only get its intermediates signed elsewhere;
  // a Root whose key is here can do either, at the user's choice.
  const offlineOnly = $derived(kind === 'intermediate' && !!parent && !parent.key_held);
  const requestMode = $derived(kind === 'intermediate' && !!parent && (offlineOnly || viaRequest));

  // Sensible defaults follow the type, until the user edits them.
  $effect(() => {
    algo = kind === 'root' ? 'ecdsa-p384' : 'ecdsa-p256';
    years = defaultYears[kind];
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      if (requestMode) {
        const res = await api.requestIntermediate(parentId, {
          name: name.trim(),
          organization: organization.trim() || undefined,
          key_algo: algo,
        });
        csrFile = textDownload(res.csr_pem);
        requested = res;
        onChanged(); // refresh the list behind the dialog, but stay open to show the request
        return;
      }
      const n = Number(years);
      if (!Number.isInteger(n) || n < 1 || n > 20) {
        error = t('common.error.generic');
        return;
      }
      await api.createCA({
        kind,
        parent_id: kind === 'intermediate' ? parentId : undefined,
        name: name.trim(),
        organization: organization.trim() || undefined,
        validity_days: n * 365,
        key_algo: algo,
      });
      onCreated();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

{#if requested && csrFile}
  <Dialog title={t('request.done.title')} {onClose} wide>
    <Alert kind="info">{t('request.done.next')}</Alert>
    <div>
      <a class="btn-primary" href={csrFile.url} download={csrFileName(requested.name)}>
        {t('request.done.download', { file: csrFileName(requested.name) })}
      </a>
    </div>
    <div>
      <h3 class="mb-1 text-sm font-semibold">{t('request.done.csr')}</h3>
      <CodeBlock code={requested.csr_pem} />
    </div>
    <h3 class="text-sm font-semibold">{t('sign.title')}</h3>
    <SignGuide requestName={requested.name} rootNotAfter={parent?.not_after ?? ''} rootId={requested.parent_id} />
    <div class="flex justify-end">
      <button type="button" class="btn-primary" onclick={onClose}>{t('request.done.close')}</button>
    </div>
  </Dialog>
{:else}
  <Dialog title={requestMode ? t('request.title') : t('cas.form.title')} {onClose}>
    <form class="flex flex-col gap-4" onsubmit={submit}>
      <div>
        <label class="label" for="ca-kind">{t('cas.form.kind')}</label>
        <select id="ca-kind" class="input" bind:value={kind}>
          <option value="root">{t('cas.kind.root')}</option>
          <option value="intermediate" disabled={roots.length === 0}>{t('cas.kind.intermediate')}</option>
        </select>
        {#if kind === 'root'}
          <p class="hint">{t('cas.form.rootHint')}</p>
        {/if}
      </div>

      {#if kind === 'intermediate'}
        <div>
          <label class="label" for="ca-parent">{t('cas.form.parent')}</label>
          <select id="ca-parent" class="input" required bind:value={parentId}>
            <option value="" disabled>{t('cas.form.parentPlaceholder')}</option>
            {#each roots as r (r.id)}
              <option value={r.id}>{r.name}{r.key_held ? '' : ` — ${t('cas.keyOffline')}`}</option>
            {/each}
          </select>
        </div>

        {#if offlineOnly}
          <Alert kind="info">{t('request.offlineForced')}</Alert>
        {:else if parent}
          <label class="flex items-start gap-2 text-sm">
            <input type="checkbox" class="mt-1" bind:checked={viaRequest} />
            {t('request.mode.offline')}
          </label>
        {/if}
        {#if requestMode}<p class="hint">{t('request.hint')}</p>{/if}
      {/if}

      <Field id="ca-name" label={t('cas.form.name')} bind:value={name} />
      <Field id="ca-org" label={t('cas.form.organization')} bind:value={organization} required={false} />
      {#if !requestMode}
        <Field id="ca-years" type="number" label={t('cas.form.validity')} bind:value={years} />
      {/if}

      <div>
        <label class="label" for="ca-algo">{t('cas.form.keyAlgo')}</label>
        <select id="ca-algo" class="input" bind:value={algo}>
          {#each algos as a (a)}
            <option value={a}>{t(`cas.form.algo.${a}`)}</option>
          {/each}
        </select>
      </div>

      {#if error}<Alert>{error}</Alert>{/if}

      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
        <button class="btn-primary" disabled={busy}>{requestMode ? t('request.submit') : t('common.create')}</button>
      </div>
    </form>
  </Dialog>
{/if}
