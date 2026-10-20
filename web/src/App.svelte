<script lang="ts">
  import { onMount } from 'svelte';
  import Layout from './components/Layout.svelte';
  import { t } from './lib/i18n.svelte';
  import { refresh, session } from './lib/session.svelte';
  import { router } from './lib/router.svelte';
  import CAs from './pages/CAs.svelte';
  import Certificates from './pages/Certificates.svelte';
  import Login from './pages/Login.svelte';
  import Setup from './pages/Setup.svelte';
  import Alert from './components/Alert.svelte';

  onMount(refresh);
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
  {:else if router.path === '/certs'}
    <Certificates />
  {:else}
    <CAs />
  {/if}
</Layout>
