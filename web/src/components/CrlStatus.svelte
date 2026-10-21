<script lang="ts">
  import { api, downloadURL, type Crl } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { formatDateTime, t } from '../lib/i18n.svelte';
  import { crlHealth, needsAttention, type CrlHealth } from '../lib/revocation';
  import Alert from './Alert.svelte';

  let {
    items,
    canManage,
    vaultReady,
    onChanged,
    onPublishRoot,
  }: { items: Crl[]; canManage: boolean; vaultReady: boolean; onChanged: () => void; onPublishRoot: (rootId: string) => void } = $props();

  let busy = $state(false);
  let error = $state('');
  let renewed = $state(false);

  const attention = $derived(needsAttention(items));

  const style: Record<CrlHealth, string> = {
    ok: 'bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-200',
    behind: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200',
    expired: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200',
    none: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
    cannot_sign: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200',
    retired: 'bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
    awaiting: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200',
  };
  const hasOwn = $derived(items.some((c) => !c.external && !c.ca_revoked));

  async function refresh() {
    busy = true;
    error = '';
    renewed = false;
    try {
      await api.refreshCrls();
      renewed = true;
      onChanged();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

{#each attention.expired as c (c.ca_id)}
  <div class="mb-3"><Alert>{t(c.external ? 'crl.alert.rootExpired' : 'crl.alert.expired', { name: c.ca_name })}</Alert></div>
{/each}
{#each attention.behind as c (c.ca_id)}
  <div class="mb-3"><Alert kind="warning">{t(c.external ? 'crl.alert.rootBehind' : 'crl.alert.behind', { name: c.ca_name })}</Alert></div>
{/each}
{#each attention.awaiting as c (c.ca_id)}
  <div class="mb-3"><Alert kind="warning">{t('crl.alert.rootAwaiting', { name: c.ca_name })}</Alert></div>
{/each}

<section class="card mb-6 p-0">
  <div class="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200 p-4 dark:border-slate-800">
    <div>
      <h2 class="text-base font-semibold">{t('crl.title')}</h2>
      <p class="mt-0.5 text-sm text-slate-600 dark:text-slate-400">{t('crl.subtitle')}</p>
    </div>
    {#if canManage && hasOwn}
      <button class="btn-secondary" disabled={busy || !vaultReady} onclick={refresh}>{t('crl.refresh')}</button>
    {/if}
  </div>
  {#if error}<div class="p-4 pb-0"><Alert>{error}</Alert></div>{/if}
  {#if renewed}<div class="p-4 pb-0"><Alert kind="info">{t('crl.refreshed')}</Alert></div>{/if}

  <div class="overflow-x-auto">
    <table class="w-full text-left text-sm whitespace-nowrap">
      <thead class="text-xs text-slate-500 uppercase dark:text-slate-400">
        <tr>
          <th class="px-4 py-3 font-medium">{t('crl.col.ca')}</th>
          <th class="px-4 py-3 font-medium">{t('crl.col.status')}</th>
          <th class="px-4 py-3 font-medium">{t('crl.col.list')}</th>
          <th class="px-4 py-3 font-medium">{t('crl.col.validUntil')}</th>
          <th class="px-4 py-3 font-medium">{t('crl.col.revoked')}</th>
          <th class="px-4 py-3 font-medium"></th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each items as c (c.ca_id)}
          {@const h = crlHealth(c)}
          <tr>
            <td class="px-4 py-3 font-medium">
              {c.ca_name}
              {#if c.external}<div class="text-xs font-normal text-slate-500 dark:text-slate-400">{t('crl.kind.root')}</div>{/if}
            </td>
            <td class="px-4 py-3">
              <span
                class="badge {style[h]}"
                title={h === 'cannot_sign' ? t('crl.hint.cannot_sign') : h === 'retired' ? t('crl.hint.retired') : undefined}
              >{t(`crl.health.${h}`)}</span>
            </td>
            <td class="px-4 py-3">{c.published && c.number ? t('crl.number', { n: c.number }) : '—'}</td>
            <td class="px-4 py-3">{c.next_update ? formatDateTime(c.next_update) : '—'}</td>
            <td class="px-4 py-3">{t('crl.revokedCount', { revoked: c.revoked, inList: c.in_list })}</td>
            <td class="px-4 py-3">
              {#if c.published}
                <a class="text-teal-700 hover:underline dark:text-teal-400" href={downloadURL.crl(c.ca_id)} download>{t('crl.download')}</a>
              {/if}
              {#if c.external && canManage}
                {#if c.published}<span class="text-slate-300 dark:text-slate-700"> · </span>{/if}
                <button type="button" class="font-medium text-teal-700 hover:underline dark:text-teal-400" onclick={() => onPublishRoot(c.ca_id)}>{t('crl.publishRoot')}</button>
              {/if}
            </td>
          </tr>
          {#if h === 'cannot_sign'}
            <tr><td colspan="6" class="px-4 pb-3 text-xs text-red-700 dark:text-red-300">{t('crl.hint.cannot_sign')}</td></tr>
          {/if}
        {/each}
      </tbody>
    </table>
  </div>
</section>
