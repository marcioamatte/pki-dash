<script lang="ts">
  import { onMount } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import CrlStatus from '../components/CrlStatus.svelte';
  import VaultGate from '../components/VaultGate.svelte';
  import { api, downloadURL, type CA, type Cert, type Crl } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { formatDate, t } from '../lib/i18n.svelte';
  import { daysLeft, expiryState } from '../lib/names';
  import { isReason } from '../lib/revocation';
  import { canIssue, canRevoke, session } from '../lib/session.svelte';
  import IssueCert from './IssueCert.svelte';
  import RevokeCert from './RevokeCert.svelte';
  import RootCrlWizard from './RootCrlWizard.svelte';

  let certs = $state<Cert[] | null>(null);
  let cas = $state<CA[]>([]);
  let filter = $state('');
  let error = $state('');
  let issuing = $state(false);
  let crls = $state<Crl[]>([]);
  let revoking = $state<Cert | null>(null);
  let rootCrl = $state<CA | null>(null);
  let hideRevoked = $state(false);

  async function load() {
    try {
      [certs, cas, crls] = await Promise.all([api.listCerts(filter || undefined), api.listCAs(), api.crlStatus()]);
      error = '';
    } catch (e) {
      error = errorMessage(e);
    }
  }
  onMount(load);

  // Unlocking the vault makes the server publish any pending revocations, so
  // what is on screen is out of date the moment the vault changes state.
  let lastReady: boolean | null = null;
  $effect(() => {
    const ready = session.vault.initialized && session.vault.unlocked;
    if (lastReady !== null && ready !== lastReady) load();
    lastReady = ready;
  });

  const issuerName = (id: string) => cas.find((c) => c.id === id)?.name ?? '—';
  const issuers = $derived(cas.filter((c) => c.kind === 'intermediate' && c.key_held));
  const intermediates = $derived(cas.filter((c) => c.kind === 'intermediate'));
  const vaultReady = $derived(session.vault.initialized && session.vault.unlocked);
  const shown = $derived((certs ?? []).filter((c) => !(hideRevoked && c.revoked)));
  const reasonLabel = (r?: string) => (isReason(r) ? t(`reason.${r}`) : '');
  const canPublish = (c: Cert) => crls.find((x) => x.ca_id === c.ca_id)?.can_sign ?? true;
</script>

<PageHeader title={t('certs.title')} subtitle={t('certs.subtitle')}>
  {#snippet actions()}
    {#if canIssue()}
      <button class="btn-primary shrink-0" disabled={!vaultReady} onclick={() => (issuing = true)}>
        {t('certs.issue')}
      </button>
    {/if}
  {/snippet}
</PageHeader>

<div class="page">
{#if !vaultReady}<VaultGate />{/if}

{#if crls.length > 0}
  <CrlStatus
    items={crls}
    canManage={canRevoke()}
    {vaultReady}
    onChanged={load}
    onPublishRoot={(id) => (rootCrl = cas.find((c) => c.id === id) ?? null)}
  />
{/if}

<div class="mb-4 flex flex-wrap items-end gap-4">
{#if intermediates.length > 1}
  <div class="max-w-xs">
    <label class="label" for="filter">{t('certs.filter')}</label>
    <select id="filter" class="input" bind:value={filter} onchange={load}>
      <option value="">{t('certs.filter.all')}</option>
      {#each intermediates as c (c.id)}<option value={c.id}>{c.name}</option>{/each}
    </select>
  </div>
{/if}
  <label class="flex items-center gap-2 pb-2 text-sm">
    <input type="checkbox" bind:checked={hideRevoked} />
    {t('certs.hideRevoked')}
  </label>
</div>

{#if error}
  <Alert>{error}</Alert>
{:else if certs === null}
  <p class="text-sm text-slate-500">{t('common.loading')}</p>
{:else if certs.length === 0}
  <div class="card text-center text-sm text-slate-600 dark:text-slate-400">{t('certs.empty')}</div>
{:else}
  <div class="card overflow-x-auto p-0">
    <table class="data-table table-stack">
      <thead>
        <tr>
          <th class="px-4 py-3 font-semibold">{t('certs.col.name')}</th>
          <th class="px-4 py-3 font-semibold">{t('certs.col.issuer')}</th>
          <th class="px-4 py-3 font-semibold">{t('certs.col.profile')}</th>
          <th class="px-4 py-3 font-semibold">{t('certs.col.validity')}</th>
          <th class="px-4 py-3 font-semibold">{t('certs.col.download')}</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each shown as c (c.id)}
          {@const state = expiryState(c.not_after)}
          <tr class={c.revoked ? 'opacity-70' : ''}>
            <td class="px-4 py-3" data-label={t('certs.col.name')}>
              <div class="font-semibold {c.revoked ? 'line-through' : ''}">
                {c.common_name}
                {#if c.revoked}
                  <span
                    class="badge ml-1 bg-red-100 text-red-800 no-underline dark:bg-red-950 dark:text-red-200"
                    title={t('certs.revokedOn', { date: formatDate(c.revoked_at ?? ''), reason: reasonLabel(c.revocation_reason) })}
                  >{t('certs.revoked')}</span>
                {/if}
              </div>
              <div class="max-w-xs truncate text-xs text-slate-500 dark:text-slate-400" title={c.sans.join(', ')}>{c.sans.join(', ')}</div>
            </td>
            <td class="px-4 py-3" data-label={t('certs.col.issuer')}>{issuerName(c.ca_id)}</td>
            <td class="px-4 py-3" data-label={t('certs.col.profile')}>{t(`profile.${c.profile}`)}</td>
            <td class="px-4 py-3" data-label={t('certs.col.validity')}>
              {formatDate(c.not_after)}
              {#if state === 'expired'}
                <span class="badge ml-1 bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200">{t('certs.expired')}</span>
              {:else if state === 'soon'}
                <span class="badge ml-1 bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200">{t('certs.expiresIn', { days: daysLeft(c.not_after) })}</span>
              {/if}
            </td>
            <td class="px-4 py-3" data-label={t('certs.col.download')}>
              <a class="text-brand-600 hover:underline dark:text-brand-400" href={downloadURL.certPEM(c.id)} download>{t('certs.download.cert')}</a>
              <span class="text-slate-300 dark:text-slate-700"> · </span>
              <a class="text-brand-600 hover:underline dark:text-brand-400" href={downloadURL.certFullchain(c.id)} download>{t('certs.download.fullchain')}</a>
              {#if canRevoke() && !c.revoked}
                <span class="text-slate-300 dark:text-slate-700"> · </span>
                <button type="button" class="text-red-700 hover:underline dark:text-red-400" onclick={() => (revoking = c)}>{t('revoke.button')}</button>
              {/if}
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

{#if revoking}
  <RevokeCert cert={revoking} canPublish={canPublish(revoking)} onRevoked={load} onClose={() => (revoking = null)} />
{/if}

{#if rootCrl}
  <RootCrlWizard root={rootCrl} onChanged={load} onClose={() => (rootCrl = null)} />
{/if}
</div>
