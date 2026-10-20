<script lang="ts">
  import { onMount } from 'svelte';
  import Layout from './components/Layout.svelte';
  import { t } from './lib/i18n.svelte';
  import { isAdmin, refresh, session } from './lib/session.svelte';
  import { adminRoutes, router } from './lib/router.svelte';
  import CAs from './pages/CAs.svelte';
  import Audit from './pages/Audit.svelte';
  import Certificates from './pages/Certificates.svelte';
  import Users from './pages/Users.svelte';
  import Login from './pages/Login.svelte';
  import Setup from './pages/Setup.svelte';
  import Alert from './components/Alert.svelte';

  onMount(refresh);

  // Non-admins never see admin screens, even by typing the URL (the API refuses them too).
  const route = $derived(adminRoutes.includes(router.path) && !isAdmin() ? '/cas' : router.path);
</script>

<Layout>
  {#if session.phase === 'loading'}
    <p class="text-sm text-slate-500">{t('common.loading')}</p>
  {:else if session.phase === 'error'}
    <Alert>{t('common.error.network')}</Alert>
  {:else if session.phase === 'setup'}
    <Setup />
  {:else if session.phase === 'login'}
    <Login />
  {:else if route === '/certs'}
    <Certificates />
  {:else if route === '/users'}
    <Users />
  {:else if route === '/audit'}
    <Audit />
  {:else}
    <CAs />
  {/if}
</Layout>
