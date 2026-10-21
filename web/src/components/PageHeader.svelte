<script lang="ts">
  import type { Snippet } from 'svelte';

  // The band under the navigation: what this page is, and what you can do here.
  let { title, subtitle = '', actions }: { title: string; subtitle?: string; actions?: Snippet } = $props();
</script>

<div class="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
  <div class="flex flex-wrap items-start justify-between gap-4 px-4 py-5 sm:px-6 lg:px-8">
    <div class="min-w-0">
      <h1 class="text-2xl font-bold tracking-tight">{title}</h1>
      {#if subtitle}<p class="mt-1 max-w-3xl text-sm text-slate-600 dark:text-slate-400">{subtitle}</p>{/if}
    </div>
    {#if actions}<div class="flex shrink-0 flex-wrap gap-2">{@render actions()}</div>{/if}
  </div>
</div>
