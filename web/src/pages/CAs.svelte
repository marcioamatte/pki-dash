<script lang="ts">
  import { onMount } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import VaultGate from '../components/VaultGate.svelte';
  import { api, downloadURL, type CA, type PendingCA } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { formatDate, t } from '../lib/i18n.svelte';
  import { isAdmin, session } from '../lib/session.svelte';
  import CreateCA from './CreateCA.svelte';
  import ImportRoot from './ImportRoot.svelte';
  import Pending from './Pending.svelte';
  import RootOffline from './RootOffline.svelte';
  import TrustDialog from './TrustDialog.svelte';

  let cas = $state<CA[] | null>(null);
  let pending = $state<PendingCA[]>([]);
  let importingRoot = $state(false);
  let error = $state('');
  let creating = $state(false);
  let trusting = $state<CA | null>(null);
  let offline = $state<CA | null>(null);

  async function load() {
    try {
      cas = await api.listCAs();
      // Pending requests are an admin matter: others are not even asked.
      pending = isAdmin() ? await api.listRequests() : [];
      error = '';
    } catch (e) {
      error = errorMessage(e);
    }
  }
  onMount(load);

  const roots = $derived((cas ?? []).filter((c) => c.kind === 'root'));
  // Roots first, each followed by the intermediates it signed.
  const rows = $derived(
    roots.flatMap((r) => [r, ...(cas ?? []).filter((c) => c.parent_id === r.id)]),
  );
  const vaultReady = $derived(session.vault.initialized && session.vault.unlocked);

  const expired = (c: CA) => new Date(c.not_after).getTime() < Date.now();

  function created() {
    creating = false;
    load();
  }
</script>

{#if !vaultReady}<VaultGate />{/if}

<div class="mb-6 flex flex-wrap items-start justify-between gap-4">
  <div>
    <h1 class="text-2xl font-semibold">{t('cas.title')}</h1>
    <p class="mt-1 text-sm text-slate-600 dark:text-slate-400">{t('cas.subtitle')}</p>
  </div>
  {#if isAdmin()}
    <div class="flex shrink-0 gap-2">
      <button class="btn-secondary" onclick={() => (importingRoot = true)}>{t('import.root.button')}</button>
      <button class="btn-primary" disabled={!vaultReady} onclick={() => (creating = true)}>
        {t('cas.create')}
      </button>
    </div>
  {/if}
</div>

{#if error}
  <Alert>{error}</Alert>
{:else if cas === null}
  <p class="text-sm text-slate-500">{t('common.loading')}</p>
{:else if rows.length === 0}
  <div class="card text-center text-sm text-slate-600 dark:text-slate-400">{t('cas.empty')}</div>
{:else}
  <div class="card overflow-x-auto p-0">
    <table class="w-full text-left text-sm whitespace-nowrap">
      <thead class="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
        <tr>
          <th class="px-4 py-3 font-medium">{t('cas.col.name')}</th>
          <th class="px-4 py-3 font-medium">{t('cas.col.type')}</th>
          <th class="px-4 py-3 font-medium">{t('cas.col.validity')}</th>
          <th class="px-4 py-3 font-medium">{t('cas.col.status')}</th>
          <th class="px-4 py-3 font-medium">{t('cas.col.download')}</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each rows as ca (ca.id)}
          <tr>
            <td class="px-4 py-3 font-medium">
              <span class={ca.kind === 'intermediate' ? 'ml-5 inline-block' : ''}>{ca.name}</span>
            </td>
            <td class="px-4 py-3">
              <span
                class="badge {ca.kind === 'root'
                  ? 'bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-200'
                  : 'bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200'}"
              >
                {t(`cas.kind.${ca.kind}`)}
              </span>
            </td>
            <td class="px-4 py-3">
              {formatDate(ca.not_after)}
              {#if expired(ca)}
                <span class="badge ml-1 bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200">{t('cas.expired')}</span>
              {/if}
            </td>
            <td class="px-4 py-3">
              <span class="badge {ca.key_held ? 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300' : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200'}">
                {ca.key_held ? t('cas.keyHeld') : t('cas.keyOffline')}
              </span>
            </td>
            <td class="px-4 py-3">
              <a class="text-teal-700 hover:underline dark:text-teal-400" href={downloadURL.caCert(ca.id)} download>{t('cas.download.cert')}</a>
              {#if ca.kind === 'intermediate'}
                <span class="text-slate-300 dark:text-slate-700"> · </span>
                <a class="text-teal-700 hover:underline dark:text-teal-400" href={downloadURL.caChain(ca.id)} download>{t('cas.download.chain')}</a>
              {:else}
                <span class="text-slate-300 dark:text-slate-700"> · </span>
                <button type="button" class="text-teal-700 hover:underline dark:text-teal-400" onclick={() => (trusting = ca)}>{t('trust.button')}</button>
                {#if isAdmin() && ca.key_held}
                  <span class="text-slate-300 dark:text-slate-700"> · </span>
                  <button type="button" class="text-teal-700 hover:underline dark:text-teal-400" onclick={() => (offline = ca)}>{t('offline.button')}</button>
                {/if}
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if isAdmin() && pending.length > 0}
  <Pending {pending} cas={cas ?? []} onChanged={load} />
{/if}

{#if importingRoot}
  <ImportRoot onImported={() => { importingRoot = false; load(); }} onClose={() => (importingRoot = false)} />
{/if}

{#if offline}
  <RootOffline
    ca={offline}
    hasIntermediates={(cas ?? []).some((c) => c.parent_id === offline?.id)}
    onChanged={load}
    onClose={() => (offline = null)}
  />
{/if}

{#if trusting}
  <TrustDialog ca={trusting} onClose={() => (trusting = null)} />
{/if}

{#if creating}
  <CreateCA {roots} onCreated={created} onChanged={load} onClose={() => (creating = false)} />
{/if}
