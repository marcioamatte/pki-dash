<script lang="ts">
  import type { Snippet } from 'svelte';
  import { t } from '../lib/i18n.svelte';
  import { session, signOut } from '../lib/session.svelte';
  import LanguageSwitcher from './LanguageSwitcher.svelte';

  let { children }: { children: Snippet } = $props();
</script>

<div class="flex min-h-screen flex-col">
  <header class="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
    <div class="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 py-3">
      <div class="flex items-center gap-3">
        <img src="/favicon.svg" alt="" class="h-7 w-7" />
        <span class="text-lg font-semibold whitespace-nowrap">{t('app.name')}</span>
      </div>
      <div class="flex items-center gap-3">
        <LanguageSwitcher />
        {#if session.phase === 'ready' && session.role}
          <span class="hidden text-sm text-slate-600 sm:inline dark:text-slate-400">
            {session.username}
            <span class="badge ml-1 bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {t(`role.${session.role}`)}
            </span>
          </span>
          <button class="btn-secondary whitespace-nowrap" onclick={signOut}>{t('auth.signOut')}</button>
        {/if}
      </div>
    </div>
  </header>

  <main class="mx-auto w-full max-w-5xl flex-1 px-4 py-8">
    {@render children()}
  </main>

  <footer class="border-t border-slate-200 px-4 py-4 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
    {t('app.disclaimer')}
  </footer>
</div>
