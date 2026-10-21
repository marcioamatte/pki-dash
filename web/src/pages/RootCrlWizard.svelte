<script lang="ts">
  import { onMount } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import Dialog from '../components/Dialog.svelte';
  import PemInput from '../components/PemInput.svelte';
  import { api, type CA, type RootCrlRequest } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { formatDate, t } from '../lib/i18n.svelte';
  import { cfsslCrl, clampDays, crlTools, DEFAULT_CRL_DAYS, opensslCrl, type CrlTool } from '../lib/rootcrl';

  let { root, onChanged, onClose }: { root: CA; onChanged: () => void; onClose: () => void } = $props();

  let req = $state<RootCrlRequest | null>(null);
  let tool = $state<CrlTool>('openssl');
  let days = $state(String(DEFAULT_CRL_DAYS));
  let crl = $state('');
  let busy = $state(false);
  let error = $state('');
  let loadError = $state('');
  let published = $state('');

  async function load() {
    try {
      req = await api.rootCrlRequest(root.id);
      loadError = '';
    } catch (e) {
      loadError = errorMessage(e);
    }
  }
  onMount(load);

  const entries = $derived(req?.entries ?? []);
  const recipe = $derived(
    tool === 'cfssl' ? cfsslCrl(entries, Number(days)) : opensslCrl(entries, req?.next_number ?? 1, Number(days)),
  );

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    published = '';
    try {
      const r = await api.importRootCrl(root.id, crl);
      published = r.number > 0
        ? t('rootcrl.published', { n: r.number, date: formatDate(r.next_update), count: r.revoked })
        : t('rootcrl.publishedNoNumber', { date: formatDate(r.next_update), count: r.revoked });
      crl = '';
      onChanged();
      await load(); // the next number moves on
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('rootcrl.title', { name: root.name })} {onClose} wide>
  <p class="text-sm text-slate-600 dark:text-slate-400">{t('rootcrl.intro')}</p>
  {#if loadError}<Alert>{t('rootcrl.loadError')} {loadError}</Alert>{/if}

  {#if req}
    {#if req.published}
      <p class="text-sm text-slate-600 dark:text-slate-400">{t('rootcrl.last', { date: formatDate(req.published.next_update) })}</p>
    {/if}

    <h3 class="text-sm font-semibold">{t('rootcrl.entries')}</h3>
    {#if entries.length === 0}
      <Alert kind="info">{t('rootcrl.none')}</Alert>
    {:else}
      <div class="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
        <table class="w-full text-left text-sm whitespace-nowrap">
          <thead class="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
            <tr>
              <th class="px-3 py-2 font-medium">{t('rootcrl.col.name')}</th>
              <th class="px-3 py-2 font-medium">{t('rootcrl.col.serial')}</th>
              <th class="px-3 py-2 font-medium">{t('rootcrl.col.reason')}</th>
              <th class="px-3 py-2 font-medium">{t('rootcrl.col.date')}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
            {#each entries as e (e.ca_id)}
              <tr>
                <td class="px-3 py-2 font-medium">{e.ca_name}</td>
                <td class="px-3 py-2 font-mono text-xs" title={e.serial_hex}>{e.serial_hex.slice(0, 16)}…</td>
                <td class="px-3 py-2">{t(`reason.${e.reason}` as 'reason.superseded')}</td>
                <td class="px-3 py-2">{formatDate(e.revoked_at)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    <div class="max-w-48">
      <label class="label" for="rc-days">{t('rootcrl.days')}</label>
      <input id="rc-days" class="input" type="number" min="7" max="730" bind:value={days} onblur={() => (days = String(clampDays(Number(days))))} aria-describedby="rc-days-hint" />
    </div>
    <p class="hint !mt-0" id="rc-days-hint">{t('rootcrl.daysHint')}</p>

    <div role="tablist" class="flex gap-1 border-b border-slate-200 dark:border-slate-800">
      {#each crlTools as tl (tl)}
        <button
          role="tab"
          type="button"
          aria-selected={tool === tl}
          class="-mb-px border-b-2 px-3 py-2 text-sm {tool === tl
            ? 'border-teal-600 font-medium text-teal-700 dark:text-teal-400'
            : 'border-transparent text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'}"
          onclick={() => (tool = tl)}
        >
          {tl}
        </button>
      {/each}
    </div>

    <div class="flex flex-col gap-3 text-sm" role="tabpanel">
      <p>{t('rootcrl.files')}</p>
      {#each recipe.files as f (f.name)}
        <div>
          <p class="mb-1 font-mono text-xs text-slate-500">{f.name}</p>
          {#if f.content}<CodeBlock code={f.content} />{:else}<p class="hint !mt-0">({t('rootcrl.none')})</p>{/if}
        </div>
      {/each}
      <p>{t('rootcrl.run')}</p>
      <CodeBlock code={recipe.command} />
      <p class="font-medium">{t('rootcrl.result', { file: recipe.resultFile })}</p>
      {#if tool === 'cfssl'}<p class="hint !mt-0">{t('rootcrl.prefer')}</p>{/if}
    </div>

    <hr class="border-slate-200 dark:border-slate-800" />
    <form class="flex flex-col gap-4" onsubmit={submit}>
      <h3 class="text-sm font-semibold">{t('rootcrl.import')}</h3>
      <PemInput id="rc-crl" label={t('rootcrl.importCert')} hint={t('rootcrl.importHint')} bind:value={crl} />
      {#if error}<Alert>{error}</Alert>{/if}
      {#if published}<Alert kind="info">{published}</Alert>{/if}
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" onclick={onClose}>{t('common.close')}</button>
        <button class="btn-primary" disabled={busy}>{t('rootcrl.submit')}</button>
      </div>
    </form>
  {:else if !loadError}
    <p class="text-sm text-slate-500">{t('common.loading')}</p>
  {/if}
</Dialog>
