<script lang="ts">
  import Alert from '../components/Alert.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import { api } from '../lib/api';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { refresh } from '../lib/session.svelte';

  let { onClose }: { onClose: () => void } = $props();

  let current = $state('');
  let next = $state('');
  let again = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (next !== again) {
      error = t('setup.mismatch');
      return;
    }
    busy = true;
    try {
      await api.changeOwnPassword(current, next);
      current = next = again = '';
      onClose(); // do not leave the dialog open over the sign-in screen
      // The server ended every session, ours included: this lands on the sign-in screen.
      await refresh();
    } catch (err) {
      error = errorMessage(err);
      busy = false;
      current = ''; // the old secret is spent, but keep what the user typed for the new one
    }
  }
</script>

<Dialog title={t('account.title')} {onClose}>
  <form class="flex flex-col gap-4" onsubmit={submit}>
    <Field id="cp-current" type="password" label={t('account.current')} bind:value={current} autocomplete="current-password" />
    <Field id="cp-new" type="password" label={t('account.new')} hint={t('account.hint')} bind:value={next} autocomplete="new-password" minlength={12} />
    <Field id="cp-again" type="password" label={t('account.confirm')} bind:value={again} autocomplete="new-password" minlength={12} />
    {#if error}<Alert>{error}</Alert>{/if}
    <div class="flex justify-end gap-2">
      <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
      <button class="btn-primary" disabled={busy}>{t('account.changePassword')}</button>
    </div>
  </form>
</Dialog>
