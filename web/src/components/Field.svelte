<script lang="ts">
  let {
    id,
    label,
    value = $bindable(''),
    type = 'text',
    hint = '',
    autocomplete = 'off',
    required = true,
    minlength,
  }: {
    id: string;
    label: string;
    value?: string;
    type?: 'text' | 'password' | 'number';
    hint?: string;
    autocomplete?: AutoFill;
    required?: boolean;
    minlength?: number;
  } = $props();
</script>

<div>
  <label class="label" for={id}>{label}</label>
  <input
    class="input"
    {id}
    {type}
    {required}
    {minlength}
    {autocomplete}
    spellcheck="false"
    autocapitalize="off"
    aria-describedby={hint ? `${id}-hint` : undefined}
    bind:value
  />
  {#if hint}<p class="hint" id="{id}-hint">{hint}</p>{/if}
</div>
