<script lang="ts">
  import { onMount } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import { api, type Role, type User } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { formatDate, t } from '../lib/i18n.svelte';
  import { session } from '../lib/session.svelte';
  import CreateUser from './CreateUser.svelte';
  import ResetPassword from './ResetPassword.svelte';

  let users = $state<User[] | null>(null);
  let error = $state('');
  let creating = $state(false);
  let resetting = $state<User | null>(null);
  const roles: Role[] = ['viewer', 'operator', 'admin'];

  async function load() {
    try {
      users = await api.listUsers();
    } catch (e) {
      error = errorMessage(e);
    }
  }
  onMount(load);

  // Run a change, show any refusal (for example "last admin"), and refresh either way.
  async function change(fn: () => Promise<unknown>) {
    error = '';
    try {
      await fn();
    } catch (e) {
      error = errorMessage(e);
    }
    await load();
  }

  const isMe = (u: User) => u.username.toLowerCase() === session.username.toLowerCase();
</script>

<PageHeader title={t('users.title')} subtitle={t('users.subtitle')}>
  {#snippet actions()}
    <button class="btn-primary shrink-0" onclick={() => (creating = true)}>{t('users.create')}</button>
  {/snippet}
</PageHeader>

<div class="page">
{#if error}<div class="mb-4"><Alert>{error}</Alert></div>{/if}

{#if users === null}
  <p class="text-sm text-slate-500">{t('common.loading')}</p>
{:else}
  <div class="card overflow-x-auto p-0">
    <table class="data-table table-stack">
      <thead>
        <tr>
          <th class="px-4 py-3 font-semibold">{t('users.col.username')}</th>
          <th class="px-4 py-3 font-semibold">{t('users.col.role')}</th>
          <th class="px-4 py-3 font-semibold">{t('users.col.source')}</th>
          <th class="px-4 py-3 font-semibold">{t('users.col.status')}</th>
          <th class="px-4 py-3 font-semibold">{t('users.col.created')}</th>
          <th class="px-4 py-3 font-semibold">{t('users.col.actions')}</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
        {#each users as u (u.id)}
          {@const me = isMe(u)}
          <tr>
            <td class="px-4 py-3 font-semibold" data-label={t('users.col.username')}>
              {u.username}
              {#if me}<span class="badge ml-1 bg-brand-100 text-brand-700 dark:bg-brand-950 dark:text-brand-200">{t('users.you')}</span>{/if}
            </td>
            <td class="px-4 py-3" data-label={t('users.col.role')}>
              <label class="sr-only" for="role-{u.id}">{t('users.col.role')}</label>
              <select
                id="role-{u.id}"
                class="rounded-sm border border-slate-300 bg-white px-2 py-1 text-sm disabled:opacity-60 dark:border-slate-700 dark:bg-slate-900"
                value={u.role}
                disabled={me || u.auth_source !== 'local'}
                title={me ? t('users.selfHint') : u.auth_source !== 'local' ? t('users.ssoRoleHint') : undefined}
                onchange={(e) => change(() => api.patchUser(u.id, { role: e.currentTarget.value as Role }))}
              >
                {#each roles as r (r)}<option value={r}>{t(`role.${r}`)}</option>{/each}
              </select>
            </td>
            <td class="px-4 py-3" data-label={t('users.col.source')}>{t(`users.source.${u.auth_source}`)}</td>
            <td class="px-4 py-3" data-label={t('users.col.status')}>
              <span class="badge {u.disabled ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200' : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'}">
                {u.disabled ? t('users.disabled') : t('users.active')}
              </span>
            </td>
            <td class="px-4 py-3" data-label={t('users.col.created')}>{formatDate(u.created_at)}</td>
            <td class="px-4 py-3" data-label={t('users.col.actions')}>
              <button type="button" class="text-brand-600 hover:underline disabled:no-underline disabled:opacity-50 dark:text-brand-400"
                disabled={me} title={me ? t('users.selfHint') : undefined}
                onclick={() => change(() => api.patchUser(u.id, { disabled: !u.disabled }))}>
                {u.disabled ? t('users.enable') : t('users.disable')}
              </button>
              {#if u.auth_source === 'local'}
                <span class="text-slate-300 dark:text-slate-700"> · </span>
                <button type="button" class="text-brand-600 hover:underline dark:text-brand-400" onclick={() => (resetting = u)}>{t('users.resetPassword')}</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if creating}
  <CreateUser onCreated={() => { creating = false; load(); }} onClose={() => (creating = false)} />
{/if}
{#if resetting}
  <ResetPassword user={resetting} onDone={() => (resetting = null)} onClose={() => (resetting = null)} />
{/if}
</div>
