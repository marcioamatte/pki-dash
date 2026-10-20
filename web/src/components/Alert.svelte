<script lang="ts">
  import type { Snippet } from 'svelte';

  let { kind = 'error', children }: { kind?: 'error' | 'warning' | 'info'; children: Snippet } = $props();

  const styles = {
    error: 'border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-100',
    warning: 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-100',
    info: 'border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-900 dark:bg-sky-950 dark:text-sky-100',
  };
</script>

<div
  class="rounded-lg border px-4 py-3 text-sm {styles[kind]}"
  role={kind === 'error' ? 'alert' : 'status'}
>
  {@render children()}
</div>
