<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import { api, type Role } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';

  let { onCreated, onClose }: { onCreated: () => void; onClose: () => void } = $props();

  let username = $state('');
  let password = $state('');
  let role = $state<Role>('viewer');
  let busy = $state(false);
  let error = $state('');
  const roles: Role[] = ['viewer', 'operator', 'admin'];

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await api.createUser({ username: username.trim(), password, role });
      password = '';
      onCreated();
    } catch (err) {
      error = errorMessage(err, { already_exists: 'users.error.exists' });
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('users.form.title')} {onClose}>
  <form class="flex flex-col gap-4" onsubmit={submit}>
    <Field id="nu-name" label={t('users.form.username')} hint={t('users.form.usernameHelp')} bind:value={username} autocomplete="off" />
    <Field id="nu-pass" type="password" label={t('users.form.password')} hint={t('users.form.passwordHelp')} bind:value={password} autocomplete="new-password" minlength={12} />
    <div>
      <label class="label" for="nu-role">{t('users.form.role')}</label>
      <select id="nu-role" class="input" bind:value={role} aria-describedby="nu-role-help">
        {#each roles as r (r)}<option value={r}>{t(`role.${r}`)}</option>{/each}
      </select>
      <p class="hint" id="nu-role-help">{t(`users.roleHelp.${role}`)}</p>
    </div>
    {#if error}<Alert>{error}</Alert>{/if}
    <div class="flex justify-end gap-2">
      <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
      <button class="btn-primary" disabled={busy}>{t('common.create')}</button>
    </div>
  </form>
</Dialog>
