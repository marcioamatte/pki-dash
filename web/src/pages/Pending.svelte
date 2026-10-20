<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import SignGuide from '../components/SignGuide.svelte';
  import { api, downloadURL, type CA, type PendingCA } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { formatDate, t } from '../lib/i18n.svelte';
  import { csrFileName } from '../lib/signing';
  import ImportCert from './ImportCert.svelte';

  // Intermediates that have a key here and are waiting for the Root to sign them.
  let { pending, cas, onChanged }: { pending: PendingCA[]; cas: CA[]; onChanged: () => void } = $props();

  let guiding = $state<PendingCA | null>(null);
  let importing = $state<PendingCA | null>(null);
  let confirming = $state('');
  let error = $state('');

  const root = (id: string) => cas.find((c) => c.id === id);

  async function cancel(p: PendingCA) {
    error = '';
    try {
      await api.cancelRequest(p.id);
      confirming = '';
      onChanged();
    } catch (e) {
      error = errorMessage(e);
    }
  }
</script>

<section class="mt-10">
  <h2 class="text-lg font-semibold">{t('pending.title')}</h2>
  <p class="mt-1 mb-4 text-sm text-slate-600 dark:text-slate-400">{t('pending.subtitle')}</p>
  {#if error}<div class="mb-3"><Alert>{error}</Alert></div>{/if}

  <div class="card overflow-x-auto p-0">
    <table class="w-full text-left text-sm whitespace-nowrap">
      <thead class="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
        <tr>
          <th class="px-4 py-3 font-medium">{t('pending.col.name')}</th>
          <th class="px-4 py-3 font-medium">{t('pending.col.root')}</th>
          <th class="px-4 py-3 font-medium">{t('pending.col.created')}</th>
          <th class="px-4 py-3 font-medium"></th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each pending as p (p.id)}
          <tr>
            <td class="px-4 py-3 font-medium">{p.name}</td>
            <td class="px-4 py-3">{root(p.parent_id)?.name ?? '—'}</td>
            <td class="px-4 py-3">{formatDate(p.created_at)}</td>
            <td class="px-4 py-3">
              {#if confirming === p.id}
                <span class="mr-2 text-slate-600 dark:text-slate-400">{t('pending.cancel.confirm')}</span>
                <button type="button" class="font-medium text-red-700 hover:underline dark:text-red-400" onclick={() => cancel(p)}>{t('pending.cancel')}</button>
                <span class="text-slate-300 dark:text-slate-700"> · </span>
                <button type="button" class="text-teal-700 hover:underline dark:text-teal-400" onclick={() => (confirming = '')}>{t('common.close')}</button>
              {:else}
                <a class="text-teal-700 hover:underline dark:text-teal-400" href={downloadURL.requestCSR(p.id)} download={csrFileName(p.name)}>{t('pending.csr')}</a>
                <span class="text-slate-300 dark:text-slate-700"> · </span>
                <button type="button" class="text-teal-700 hover:underline dark:text-teal-400" onclick={() => (guiding = p)}>{t('pending.how')}</button>
                <span class="text-slate-300 dark:text-slate-700"> · </span>
                <button type="button" class="font-medium text-teal-700 hover:underline dark:text-teal-400" onclick={() => (importing = p)}>{t('pending.import')}</button>
                <span class="text-slate-300 dark:text-slate-700"> · </span>
                <button type="button" class="text-slate-500 hover:underline dark:text-slate-400" onclick={() => (confirming = p.id)}>{t('pending.cancel')}</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

{#if guiding}
  {@const g = guiding}
  <Dialog title={t('sign.title')} onClose={() => (guiding = null)} wide>
    <SignGuide requestName={g.name} rootNotAfter={root(g.parent_id)?.not_after ?? ''} />
    <div class="flex justify-end">
      <button type="button" class="btn-secondary" onclick={() => (guiding = null)}>{t('common.close')}</button>
    </div>
  </Dialog>
{/if}

{#if importing}
  <ImportCert request={importing} onImported={() => { importing = null; onChanged(); }} onClose={() => (importing = null)} />
{/if}
