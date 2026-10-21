<script lang="ts">
  import { untrack } from 'svelte';
  import { t } from '../lib/i18n.svelte';
  import { session } from '../lib/session.svelte';
  import { maxSigningDays, parseDomains, rootPointers, signers, signingGuide, type Signer } from '../lib/signing';
  import CodeBlock from './CodeBlock.svelte';

  let { requestName, rootNotAfter, rootId }: { requestName: string; rootNotAfter: string; rootId: string } = $props();

  let signer = $state<Signer>('cfssl');
  const limit = untrack(() => maxSigningDays(rootNotAfter));
  let days = $state(String(limit));
  const pointers = $derived(rootPointers(session.publicUrl, rootId));
  let domainText = $state('');
  const parsed = $derived(parseDomains(domainText));
  const guide = $derived(signingGuide(signer, requestName, Number(days), pointers, parsed.invalid.length ? [] : parsed.domains));
</script>

<div class="flex flex-col gap-3 text-sm">
  <p class="text-slate-600 dark:text-slate-400">{t('sign.intro')}</p>

  <div role="tablist" class="flex gap-1 border-b border-slate-200 dark:border-slate-800">
    {#each signers as s (s)}
      <button
        role="tab"
        type="button"
        aria-selected={signer === s}
        class="-mb-px border-b-2 px-3 py-2 text-sm {signer === s
          ? 'border-brand-500 font-semibold text-brand-600 dark:text-brand-400'
          : 'border-transparent text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'}"
        onclick={() => (signer = s)}
      >
        {s}
      </button>
    {/each}
  </div>

  <div class="max-w-48">
    <label class="label" for="sign-days">{t('sign.days')}</label>
    <input id="sign-days" class="input" type="number" min="1" max={limit} bind:value={days} aria-describedby="sign-days-hint" />
    <p class="hint" id="sign-days-hint">{t('sign.daysHint')}</p>
  </div>

  <div>
    <label class="label" for="sign-domains">{t('sign.domains')}</label>
    <textarea id="sign-domains" class="input font-mono" rows="2" placeholder="lab, mattegroup.example" bind:value={domainText} aria-describedby="sign-domains-hint"></textarea>
    <p class="hint" id="sign-domains-hint">{t('sign.domainsHint')}</p>
    {#if parsed.invalid.length}
      <p class="mt-1 text-sm text-red-700 dark:text-red-400" role="alert">{t('sign.domainsInvalid', { list: parsed.invalid.join(', ') })}</p>
    {/if}
  </div>

  <div class="flex flex-col gap-3" role="tabpanel">
    {#if guide.unsupported}
      <p role="alert" class="rounded-md border border-amber-300 bg-amber-50 p-3 text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200">
        {t('sign.cfsslNoConstraints')}
      </p>
    {:else}
    <p class="hint !mt-0">{pointers ? t('sign.pointers') : t('sign.noPointers')}</p>
    <p>{t('sign.files')}</p>
    {#each guide.files as f (f.name)}
      <div>
        <p class="mb-1 font-mono text-xs text-slate-500">{f.name}</p>
        <CodeBlock code={f.content} />
      </div>
    {/each}
    <p>{t('sign.run')}</p>
    <CodeBlock code={guide.command} />
    <p class="hint">{t('sign.rootFiles')}</p>
    <p class="font-semibold">{t('sign.result', { file: guide.resultFile })}</p>
    {/if}
  </div>
</div>
