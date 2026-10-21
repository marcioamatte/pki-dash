<script lang="ts">
  import { getLocale, locales, setLocale, t, type Locale } from '../lib/i18n.svelte';

  // `onDark` styles it for the navy header and the sign-in screens.
  let { onDark = false }: { onDark?: boolean } = $props();

  function change(e: Event) {
    setLocale((e.currentTarget as HTMLSelectElement).value as Locale);
  }
</script>

<label class="sr-only" for="lang">{t('lang.label')}</label>
<select
  id="lang"
  class="rounded-sm border px-2 py-1 text-sm {onDark
    ? 'border-white/30 bg-white/10 text-white [&>option]:text-slate-900'
    : 'border-slate-300 bg-white dark:border-slate-700 dark:bg-slate-900'}"
  value={getLocale()}
  onchange={change}
>
  {#each locales as l (l.code)}
    <option value={l.code}>{l.label}</option>
  {/each}
</select>
