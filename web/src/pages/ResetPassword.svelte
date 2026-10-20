<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import { api, type User } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';

  let { user, onDone, onClose }: { user: User; onDone: () => void; onClose: () => void } = $props();

  let password = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await api.resetPassword(user.id, password);
      password = '';
      onDone();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('users.reset.title', { name: user.username })} {onClose}>
  <form class="flex flex-col gap-4" onsubmit={submit}>
    <Field id="rp-pass" type="password" label={t('users.reset.new')} hint={t('users.reset.help')} bind:value={password} autocomplete="new-password" minlength={12} />
    {#if error}<Alert>{error}</Alert>{/if}
    <div class="flex justify-end gap-2">
      <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
      <button class="btn-primary" disabled={busy}>{t('users.reset.submit')}</button>
    </div>
  </form>
</Dialog>
