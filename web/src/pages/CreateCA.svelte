<script lang="ts">
  import { untrack } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import { api, type CA, type KeyAlgo } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';

  let { roots, onCreated, onClose }: { roots: CA[]; onCreated: () => void; onClose: () => void } = $props();

  // The dialog is created when opened, so the initial snapshot of roots is what we want.
  let kind = $state<'root' | 'intermediate'>(untrack(() => (roots.length === 0 ? 'root' : 'intermediate')));
  let parentId = $state(untrack(() => roots.find((r) => r.key_held)?.id ?? ''));
  let name = $state('');
  let organization = $state('');
  let years = $state('');
  let algo = $state<KeyAlgo>('ecdsa-p256');
  let busy = $state(false);
  let error = $state('');

  const algos: KeyAlgo[] = ['ecdsa-p384', 'ecdsa-p256', 'rsa-3072', 'rsa-4096'];
  const defaultYears = { root: '10', intermediate: '5' };

  // Sensible defaults follow the type, until the user edits them.
  $effect(() => {
    algo = kind === 'root' ? 'ecdsa-p384' : 'ecdsa-p256';
    years = defaultYears[kind];
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    const n = Number(years);
    if (!Number.isInteger(n) || n < 1 || n > 20) {
      error = t('common.error.generic');
      return;
    }
    busy = true;
    try {
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

<Dialog title={t('cas.form.title')} {onClose}>
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
            <option value={r.id} disabled={!r.key_held}>
              {r.name}{r.key_held ? '' : ` — ${t('cas.keyOffline')}`}
            </option>
          {/each}
        </select>
      </div>
    {/if}

    <Field id="ca-name" label={t('cas.form.name')} bind:value={name} />
    <Field id="ca-org" label={t('cas.form.organization')} bind:value={organization} required={false} />
    <Field id="ca-years" type="number" label={t('cas.form.validity')} bind:value={years} />

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
      <button class="btn-primary" disabled={busy}>{t('common.create')}</button>
    </div>
  </form>
</Dialog>
