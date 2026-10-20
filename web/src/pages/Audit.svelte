<script lang="ts">
  import { onMount } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import { api, type AuditEntry } from '../lib/api';
  import { filterAudit, isSensitive } from '../lib/audit';
  import { errorMessage } from '../lib/errors';
  import { formatDateTime, t } from '../lib/i18n.svelte';

  let entries = $state<AuditEntry[] | null>(null);
  let limit = $state(100);
  let query = $state('');
  let error = $state('');
  let verdict = $state<'' | 'ok' | 'bad'>('');
  let verifying = $state(false);

  async function load() {
    try {
      entries = await api.audit(limit);
      error = '';
    } catch (e) {
      error = errorMessage(e);
    }
  }
  onMount(load);

  async function verify() {
    verifying = true;
    verdict = '';
    try {
      verdict = (await api.auditVerify()).ok ? 'ok' : 'bad';
    } catch (e) {
      error = errorMessage(e);
    } finally {
      verifying = false;
    }
  }

  const shown = $derived(filterAudit(entries ?? [], query));
</script>

<div class="mb-6 flex flex-wrap items-start justify-between gap-4">
  <div>
    <h1 class="text-2xl font-semibold">{t('audit.title')}</h1>
    <p class="mt-1 text-sm text-slate-600 dark:text-slate-400">{t('audit.subtitle')}</p>
  </div>
  <button class="btn-secondary shrink-0" disabled={verifying} onclick={verify}>{t('audit.verify')}</button>
</div>

{#if verdict === 'ok'}
  <div class="mb-4"><Alert kind="info">{t('audit.verify.ok')}</Alert></div>
{:else if verdict === 'bad'}
  <div class="mb-4"><Alert>{t('audit.verify.bad')}</Alert></div>
{/if}
{#if error}<div class="mb-4"><Alert>{error}</Alert></div>{/if}

<div class="mb-4 flex flex-wrap items-end gap-3">
  <div class="min-w-48 flex-1">
    <label class="label" for="audit-q">{t('audit.filter')}</label>
    <input id="audit-q" class="input" type="search" placeholder={t('audit.filterPlaceholder')} bind:value={query} autocomplete="off" />
  </div>
  <div>
    <label class="label" for="audit-limit">{t('audit.limit')}</label>
    <select id="audit-limit" class="input" bind:value={limit} onchange={load}>
      <option value={50}>50</option>
      <option value={100}>100</option>
      <option value={500}>500</option>
      <option value={1000}>1000</option>
    </select>
  </div>
  <button class="btn-secondary" onclick={load}>{t('audit.refresh')}</button>
</div>

{#if entries === null}
  <p class="text-sm text-slate-500">{t('common.loading')}</p>
{:else if shown.length === 0}
  <div class="card text-center text-sm text-slate-600 dark:text-slate-400">{t('audit.empty')}</div>
{:else}
  <div class="card overflow-x-auto p-0">
    <table class="w-full text-left text-sm">
      <thead class="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
        <tr>
          <th class="px-4 py-3 font-medium whitespace-nowrap">{t('audit.col.time')}</th>
          <th class="px-4 py-3 font-medium">{t('audit.col.actor')}</th>
          <th class="px-4 py-3 font-medium">{t('audit.col.action')}</th>
          <th class="px-4 py-3 font-medium">{t('audit.col.target')}</th>
          <th class="px-4 py-3 font-medium">{t('audit.col.detail')}</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each shown as e (e.seq)}
          <tr>
            <td class="px-4 py-2 whitespace-nowrap text-slate-600 dark:text-slate-400">{formatDateTime(e.time)}</td>
            <td class="px-4 py-2 whitespace-nowrap">{e.actor}</td>
            <td class="px-4 py-2 whitespace-nowrap">
              <span class="badge font-mono {isSensitive(e.action) ? 'bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200' : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'}">{e.action}</span>
            </td>
            <td class="max-w-40 truncate px-4 py-2 font-mono text-xs" title={e.target}>{e.target}</td>
            <td class="px-4 py-2 break-words">{e.detail}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
