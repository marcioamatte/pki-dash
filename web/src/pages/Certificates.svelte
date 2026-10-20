<script lang="ts">
  import { onMount } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import VaultGate from '../components/VaultGate.svelte';
  import { api, downloadURL, type CA, type Cert } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { formatDate, t } from '../lib/i18n.svelte';
  import { daysLeft, expiryState } from '../lib/names';
  import { canIssue, session } from '../lib/session.svelte';
  import IssueCert from './IssueCert.svelte';

  let certs = $state<Cert[] | null>(null);
  let cas = $state<CA[]>([]);
  let filter = $state('');
  let error = $state('');
  let issuing = $state(false);

  async function load() {
    try {
      [certs, cas] = await Promise.all([api.listCerts(filter || undefined), api.listCAs()]);
      error = '';
    } catch (e) {
      error = errorMessage(e);
    }
  }
  onMount(load);

  const issuerName = (id: string) => cas.find((c) => c.id === id)?.name ?? '—';
  const issuers = $derived(cas.filter((c) => c.kind === 'intermediate' && c.key_held));
  const intermediates = $derived(cas.filter((c) => c.kind === 'intermediate'));
  const vaultReady = $derived(session.vault.initialized && session.vault.unlocked);
</script>

{#if !vaultReady}<VaultGate />{/if}

<div class="mb-6 flex flex-wrap items-start justify-between gap-4">
  <div>
    <h1 class="text-2xl font-semibold">{t('certs.title')}</h1>
    <p class="mt-1 text-sm text-slate-600 dark:text-slate-400">{t('certs.subtitle')}</p>
  </div>
  {#if canIssue()}
    <button class="btn-primary shrink-0" disabled={!vaultReady} onclick={() => (issuing = true)}>
      {t('certs.issue')}
    </button>
  {/if}
</div>

{#if intermediates.length > 1}
  <div class="mb-4 max-w-xs">
    <label class="label" for="filter">{t('certs.filter')}</label>
    <select id="filter" class="input" bind:value={filter} onchange={load}>
      <option value="">{t('certs.filter.all')}</option>
      {#each intermediates as c (c.id)}<option value={c.id}>{c.name}</option>{/each}
    </select>
  </div>
{/if}

{#if error}
  <Alert>{error}</Alert>
{:else if certs === null}
  <p class="text-sm text-slate-500">{t('common.loading')}</p>
{:else if certs.length === 0}
  <div class="card text-center text-sm text-slate-600 dark:text-slate-400">{t('certs.empty')}</div>
{:else}
  <div class="card overflow-x-auto p-0">
    <table class="w-full text-left text-sm whitespace-nowrap">
      <thead class="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
        <tr>
          <th class="px-4 py-3 font-medium">{t('certs.col.name')}</th>
          <th class="px-4 py-3 font-medium">{t('certs.col.issuer')}</th>
          <th class="px-4 py-3 font-medium">{t('certs.col.profile')}</th>
          <th class="px-4 py-3 font-medium">{t('certs.col.validity')}</th>
          <th class="px-4 py-3 font-medium">{t('certs.col.download')}</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each certs as c (c.id)}
          {@const state = expiryState(c.not_after)}
          <tr>
            <td class="px-4 py-3">
              <div class="font-medium">{c.common_name}</div>
              <div class="max-w-xs truncate text-xs text-slate-500 dark:text-slate-400" title={c.sans.join(', ')}>{c.sans.join(', ')}</div>
            </td>
            <td class="px-4 py-3">{issuerName(c.ca_id)}</td>
            <td class="px-4 py-3">{t(`profile.${c.profile}`)}</td>
            <td class="px-4 py-3">
              {formatDate(c.not_after)}
              {#if state === 'expired'}
                <span class="badge ml-1 bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200">{t('certs.expired')}</span>
              {:else if state === 'soon'}
                <span class="badge ml-1 bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200">{t('certs.expiresIn', { days: daysLeft(c.not_after) })}</span>
              {/if}
            </td>
            <td class="px-4 py-3">
              <a class="text-teal-700 hover:underline dark:text-teal-400" href={downloadURL.certPEM(c.id)} download>{t('certs.download.cert')}</a>
              <span class="text-slate-300 dark:text-slate-700"> · </span>
              <a class="text-teal-700 hover:underline dark:text-teal-400" href={downloadURL.certFullchain(c.id)} download>{t('certs.download.fullchain')}</a>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if issuing}
  <IssueCert {issuers} onIssued={load} onClose={() => (issuing = false)} />
{/if}
