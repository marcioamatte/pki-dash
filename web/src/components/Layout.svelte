<script lang="ts">
  import type { Snippet } from 'svelte';
  import { t } from '../lib/i18n.svelte';
  import { router } from '../lib/router.svelte';
  import { isAdmin, session, signOut } from '../lib/session.svelte';
  import ChangePassword from '../pages/ChangePassword.svelte';
  import LanguageSwitcher from './LanguageSwitcher.svelte';

  let { children }: { children: Snippet } = $props();
  let account = $state(false);

  const navItems = $derived(
    [
      ['/cas', 'nav.cas'],
      ['/certs', 'nav.certs'],
      ...(isAdmin() ? ([['/users', 'nav.users'], ['/audit', 'nav.audit']] as const) : []),
    ] as const,
  );
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
          <button
            type="button"
            class="hidden rounded-lg px-2 py-1 text-sm text-slate-600 hover:bg-slate-100 sm:inline dark:text-slate-400 dark:hover:bg-slate-800"
            title={t('account.changePassword')}
            onclick={() => (account = true)}
          >
            {session.username}
            <span class="badge ml-1 bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {t(`role.${session.role}`)}
            </span>
          </button>
          <button class="btn-secondary whitespace-nowrap" onclick={signOut}>{t('auth.signOut')}</button>
        {/if}
      </div>
    </div>
    {#if session.phase === 'ready'}
      <nav class="mx-auto flex max-w-5xl gap-1 px-4" aria-label="Main">
        {#each navItems as [path, label] (path)}
          <a
            href={`#${path}`}
            aria-current={router.path === path ? 'page' : undefined}
            class="-mb-px border-b-2 px-3 py-2 text-sm whitespace-nowrap {router.path === path
              ? 'border-teal-600 font-medium text-teal-700 dark:text-teal-400'
              : 'border-transparent text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'}"
          >
            {t(label)}
          </a>
        {/each}
      </nav>
    {/if}
  </header>

  <main class="mx-auto w-full max-w-5xl flex-1 px-4 py-8">
    {@render children()}
  </main>

  {#if account}<ChangePassword onClose={() => (account = false)} />{/if}

  <footer class="border-t border-slate-200 px-4 py-4 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
    {t('app.disclaimer')}
  </footer>
</div>
