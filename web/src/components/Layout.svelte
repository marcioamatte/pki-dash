<script lang="ts">
  import type { Snippet } from 'svelte';
  import { t } from '../lib/i18n.svelte';
  import { router } from '../lib/router.svelte';
  import { isAdmin, session, signOut } from '../lib/session.svelte';
  import ChangePassword from '../pages/ChangePassword.svelte';
  import LanguageSwitcher from './LanguageSwitcher.svelte';

  let { children }: { children: Snippet } = $props();
  let account = $state(false);

  // Before signing in (and while loading) there is no navigation: just the blue screen.
  const signedIn = $derived(session.phase === 'ready');

  const navItems = $derived(
    [
      ['/cas', 'nav.cas'],
      ['/certs', 'nav.certs'],
      ...(isAdmin() ? ([['/users', 'nav.users'], ['/audit', 'nav.audit']] as const) : []),
    ] as const,
  );
</script>

<a
  href="#content"
  class="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-white focus:px-3 focus:py-2 focus:text-brand-700"
  onclick={(e) => {
    e.preventDefault();
    document.getElementById('content')?.focus();
  }}
>
  {t('common.skipToContent')}
</a>

{#if signedIn}
  <div class="flex min-h-screen flex-col">
    <header class="bg-brand-900 text-white">
      <div class="flex flex-wrap items-center gap-x-8 gap-y-1 px-4 pt-2 sm:px-6 lg:px-8">
        <div class="flex items-center gap-3 py-1">
          <img src="/favicon.svg" alt="" class="h-8 w-8" />
          <span class="text-xl font-bold whitespace-nowrap">{t('app.name')}</span>
        </div>

        <nav class="order-last -mx-4 flex w-[calc(100%+2rem)] overflow-x-auto px-4 sm:order-none sm:mx-0 sm:w-auto sm:flex-1 sm:overflow-visible sm:px-0" aria-label="Main">
          {#each navItems as [path, label] (path)}
            <a
              href={`#${path}`}
              aria-current={router.path === path ? 'page' : undefined}
              class="border-b-4 px-4 py-3 text-base whitespace-nowrap {router.path === path
                ? 'border-brand-400 font-bold text-white'
                : 'border-transparent text-white/75 hover:bg-white/10 hover:text-white'}"
            >
              {t(label)}
            </a>
          {/each}
        </nav>

        <div class="ml-auto flex items-center gap-3 py-1">
          <LanguageSwitcher onDark />
          {#if session.role}
            <button
              type="button"
              class="hidden items-center gap-2 rounded-sm px-2 py-1 text-sm hover:bg-white/10 sm:flex"
              title={t('account.changePassword')}
              onclick={() => (account = true)}
            >
              {session.username}
              <span class="badge bg-white/15 text-white">{t(`role.${session.role}`)}</span>
            </button>
            <button class="btn-ghost whitespace-nowrap" onclick={signOut}>{t('auth.signOut')}</button>
          {/if}
        </div>
      </div>
    </header>

    <main id="content" tabindex="-1" class="w-full flex-1 focus:outline-none">
      {@render children()}
    </main>

    <footer class="border-t border-slate-200 bg-white px-4 py-3 text-center text-xs text-slate-500 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400">
      {t('app.disclaimer')}
    </footer>
  </div>
  {#if account}<ChangePassword onClose={() => (account = false)} />{/if}
{:else}
  <div class="flex min-h-screen flex-col bg-linear-to-b from-brand-600 to-brand-900 text-white">
    <div class="flex justify-end px-4 pt-4 sm:px-6"><LanguageSwitcher onDark /></div>
    <main id="content" tabindex="-1" class="flex flex-1 flex-col items-center justify-center px-4 py-8 focus:outline-none">
      <div class="mb-6 flex items-center gap-3">
        <img src="/favicon.svg" alt="" class="h-10 w-10" />
        <span class="text-3xl font-bold">{t('app.name')}</span>
      </div>
      <div class="w-full max-w-lg text-slate-900 dark:text-slate-100">
        {@render children()}
      </div>
    </main>
    <footer class="px-4 py-4 text-center text-xs text-white/75">{t('app.disclaimer')}</footer>
  </div>
{/if}
