<script lang="ts">
  import CodeBlock from '../components/CodeBlock.svelte';
  import Dialog from '../components/Dialog.svelte';
  import { downloadURL, type CA } from '../lib/api';
  import { t } from '../lib/i18n.svelte';
  import { fileName, operatingSystems, trustCommands, type OS } from '../lib/trust';

  let { ca, onClose }: { ca: CA; onClose: () => void } = $props();

  let os = $state<OS>('debian');
  const file = $derived(fileName.caCert(ca.name));
  const commands = $derived(trustCommands(os, ca.name));
</script>

<Dialog title={t('trust.title', { name: ca.name })} {onClose} wide>
  <p class="text-sm text-slate-600 dark:text-slate-400">{t('trust.intro')}</p>

  <div>
    <a class="btn-primary" href={downloadURL.caCert(ca.id)} download={file}>
      {t('trust.download', { file })}
    </a>
  </div>

  <div role="tablist" class="flex flex-wrap gap-1 border-b border-slate-200 dark:border-slate-800">
    {#each operatingSystems as o (o)}
      <button
        role="tab"
        type="button"
        aria-selected={os === o}
        class="-mb-px rounded-t-sm border-b-2 px-3 py-2 text-sm {os === o
          ? 'border-brand-500 font-semibold text-brand-600 dark:text-brand-400'
          : 'border-transparent text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'}"
        onclick={() => (os = o)}
      >
        {t(`trust.os.${o}`)}
      </button>
    {/each}
  </div>

  <div role="tabpanel" class="flex flex-col gap-3 text-sm">
    {#if commands !== null}
      <p>{t('trust.save', { file })}</p>
      <CodeBlock code={commands} />
      {#if os === 'macos'}<p class="hint">{t('trust.note.macos')}</p>{/if}
      {#if os === 'windows'}<p class="hint">{t('trust.note.windows')}</p>{/if}
    {:else}
      <p>{t('trust.firefox.intro')}</p>
      <ol class="list-decimal space-y-1 pl-5">
        <li>{t('trust.firefox.s1')}</li>
        <li>{t('trust.firefox.s2')}</li>
        <li>{t('trust.firefox.s3')}</li>
      </ol>
      <p class="hint">{t('trust.firefox.alt')}</p>
    {/if}
  </div>

  <div class="flex justify-end">
    <button type="button" class="btn-secondary" onclick={onClose}>{t('common.close')}</button>
  </div>
</Dialog>
