<script lang="ts">
  import { getLocale, locales, setLocale, t, type Locale } from '../lib/i18n.svelte';

  function change(e: Event) {
    setLocale((e.currentTarget as HTMLSelectElement).value as Locale);
  }
</script>

<label class="sr-only" for="lang">{t('lang.label')}</label>
<select
  id="lang"
  class="rounded-lg border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
  value={getLocale()}
  onchange={change}
>
  {#each locales as l (l.code)}
    <option value={l.code}>{l.label}</option>
  {/each}
</select>
