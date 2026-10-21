<script lang="ts">
  import { untrack } from 'svelte';
  import { t } from '../lib/i18n.svelte';
  import { session } from '../lib/session.svelte';
  import { maxSigningDays, rootPointers, signers, signingGuide, type Signer } from '../lib/signing';
  import CodeBlock from './CodeBlock.svelte';

  let { requestName, rootNotAfter, rootId }: { requestName: string; rootNotAfter: string; rootId: string } = $props();

  let signer = $state<Signer>('cfssl');
  const limit = untrack(() => maxSigningDays(rootNotAfter));
  let days = $state(String(limit));
  const pointers = $derived(rootPointers(session.publicUrl, rootId));
  const guide = $derived(signingGuide(signer, requestName, Number(days), pointers));
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
          ? 'border-teal-600 font-medium text-teal-700 dark:text-teal-400'
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

  <div class="flex flex-col gap-3" role="tabpanel">
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
    <p class="font-medium">{t('sign.result', { file: guide.resultFile })}</p>
  </div>
</div>
