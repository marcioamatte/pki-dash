<script lang="ts">
  import { t } from '../lib/i18n.svelte';

  let { code }: { code: string } = $props();
  let copied = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch {
      /* clipboard blocked: the text is still selectable */
    }
  }
</script>

<div class="relative">
  <pre class="overflow-x-auto rounded-sm border border-slate-200 bg-slate-50 p-3 pr-20 text-xs leading-relaxed dark:border-slate-800 dark:bg-slate-950"><code>{code}</code></pre>
  <button type="button" class="btn-secondary absolute top-2 right-2 !px-2 !py-1 text-xs" onclick={copy}>
    {copied ? t('common.copied') : t('common.copy')}
  </button>
</div>
