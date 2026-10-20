<script lang="ts">
  import { t } from '../lib/i18n.svelte';

  // A certificate can be pasted or loaded from a file. Either way it ends up in
  // the text box, so what is submitted is always what the user can see.
  let {
    id,
    label,
    hint = '',
    value = $bindable(''),
  }: { id: string; label: string; hint?: string; value?: string } = $props();

  const MAX_BYTES = 64 * 1024; // a certificate is a couple of KiB
  let tooBig = $state(false);

  async function load(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    tooBig = false;
    if (!file) return;
    if (file.size > MAX_BYTES) {
      tooBig = true;
    } else {
      value = await file.text();
    }
    input.value = ''; // allow choosing the same file again
  }
</script>

<div>
  <label class="label" for={id}>{label}</label>
  <textarea
    {id}
    class="input min-h-36 font-mono text-xs"
    spellcheck="false"
    required
    placeholder="-----BEGIN CERTIFICATE-----"
    aria-describedby={hint ? `${id}-hint` : undefined}
    bind:value
  ></textarea>
  <div class="mt-2 flex flex-wrap items-center gap-3">
    <label class="btn-secondary cursor-pointer !px-3 !py-1.5 text-xs">
      {t('import.root.file')}
      <input id="{id}-file" type="file" class="sr-only" accept=".crt,.pem,.cer,.txt,text/plain,application/x-pem-file" onchange={load} />
    </label>
    {#if hint}<span class="hint !mt-0" id="{id}-hint">{hint}</span>{/if}
  </div>
  {#if tooBig}<p class="mt-1 text-xs text-red-600 dark:text-red-400" role="alert">{t('import.fileTooBig')}</p>{/if}
</div>
