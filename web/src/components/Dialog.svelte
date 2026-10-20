<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    title,
    onClose,
    wide = false,
    children,
  }: { title: string; onClose: () => void; wide?: boolean; children: Snippet } = $props();

  let dialog: HTMLDialogElement;

  // A native modal <dialog> gives focus trapping, Escape and a backdrop for free.
  $effect(() => {
    dialog.showModal();
  });
</script>

<dialog
  bind:this={dialog}
  onclose={onClose}
  aria-labelledby="dialog-title"
  class="m-auto max-h-[92vh] w-full overflow-y-auto rounded-xl border border-slate-200 bg-white p-0 text-slate-900 shadow-xl backdrop:bg-slate-900/50 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 {wide ? 'max-w-3xl' : 'max-w-lg'}"
>
  <div class="flex flex-col gap-4 p-6">
    <h2 id="dialog-title" class="text-lg font-semibold">{title}</h2>
    {@render children()}
  </div>
</dialog>
