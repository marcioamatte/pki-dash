<script lang="ts">
  import { onDestroy } from 'svelte';
  import { untrack } from 'svelte';
  import Alert from '../components/Alert.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Field from '../components/Field.svelte';
  import { api, type CA, type Issued, type KeyAlgo, type Profile } from '../lib/api';
  import { textDownload, type TextDownload } from '../lib/download';
  import { errorMessage } from '../lib/errors';
  import { t } from '../lib/i18n.svelte';
  import { BROWSER_MAX_DAYS, parseList } from '../lib/names';
  import { fileName } from '../lib/trust';

  // Only intermediates whose key the service holds can sign.
  let { issuers, onIssued, onClose }: { issuers: CA[]; onIssued: () => void; onClose: () => void } = $props();

  let caId = $state(untrack(() => issuers[0]?.id ?? ''));
  let cn = $state('');
  let dns = $state('');
  let ips = $state('');
  let profile = $state<Profile>('server');
  let days = $state('365');
  let algo = $state<KeyAlgo>('ecdsa-p256');
  let useCsr = $state(false);
  let csr = $state('');
  let busy = $state(false);
  let error = $state('');

  let issued = $state<Issued | null>(null);
  let downloads = $state<{ cert: TextDownload; key?: TextDownload; chain: TextDownload } | null>(null);
  let showKey = $state(false);
  let name = $state('');

  const algos: KeyAlgo[] = ['ecdsa-p256', 'ecdsa-p384', 'rsa-3072', 'rsa-4096'];
  const profiles: Profile[] = ['server', 'client', 'both'];
  const longValidity = $derived(Number(days) > BROWSER_MAX_DAYS);

  // Fill the DNS list from the common name until the user edits it themselves.
  let dnsTouched = false;
  $effect(() => {
    if (!dnsTouched) dns = cn;
  });

  function revokeAll() {
    downloads?.cert.revoke();
    downloads?.key?.revoke();
    downloads?.chain.revoke();
    downloads = null;
  }
  // The private key must not outlive this window.
  onDestroy(() => {
    revokeAll();
    issued = null;
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    const dnsNames = parseList(dns);
    const ipList = parseList(ips);
    if (dnsNames.length + ipList.length === 0) {
      error = t('issue.needName');
      return;
    }
    const n = Number(days);
    if (!Number.isInteger(n) || n < 1) {
      error = t('common.error.generic');
      return;
    }
    busy = true;
    try {
      const res = await api.issueCert(caId, {
        common_name: cn.trim(),
        dns_names: dnsNames,
        ip_addresses: ipList,
        profile,
        validity_days: n,
        key_algo: useCsr ? undefined : algo,
        csr_pem: useCsr ? csr : undefined,
      });
      name = cn.trim();
      downloads = {
        cert: textDownload(res.certificate_pem),
        key: res.private_key_pem ? textDownload(res.private_key_pem) : undefined,
        chain: textDownload(res.certificate_pem + res.chain_pem),
      };
      issued = res;
      csr = '';
      onIssued();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

{#if issued && downloads}
  <Dialog title={t('issue.done.title')} {onClose} wide>
    {#if issued.private_key_pem}
      <Alert kind="warning">{t('issue.done.keyOnce')}</Alert>
    {:else}
      <Alert kind="info">{t('issue.done.noKey')}</Alert>
    {/if}

    <div class="grid gap-3 sm:grid-cols-3">
      <a class="btn-secondary" href={downloads.cert.url} download={fileName.leafCert(name)}>
        {t('issue.done.download')}: {t('issue.done.certificate')}
      </a>
      {#if downloads.key}
        <a class="btn-primary" href={downloads.key.url} download={fileName.leafKey(name)}>
          {t('issue.done.download')}: {t('issue.done.privateKey')}
        </a>
      {/if}
      <a class="btn-secondary" href={downloads.chain.url} download={fileName.leafChain(name)}>
        {t('issue.done.download')}: {t('issue.done.fullchain')}
      </a>
    </div>
    <p class="hint">{t('issue.done.servers')}</p>

    <div>
      <h3 class="mb-1 text-sm font-medium">{t('issue.done.certificate')}</h3>
      <CodeBlock code={issued.certificate_pem} />
    </div>

    {#if issued.private_key_pem}
      <div>
        <div class="mb-1 flex items-center justify-between">
          <h3 class="text-sm font-medium">{t('issue.done.privateKey')}</h3>
          <button type="button" class="text-sm text-teal-700 hover:underline dark:text-teal-400" onclick={() => (showKey = !showKey)}>
            {showKey ? t('issue.done.hide') : t('issue.done.show')}
          </button>
        </div>
        {#if showKey}<CodeBlock code={issued.private_key_pem} />{/if}
      </div>
    {/if}

    <div class="flex justify-end">
      <button type="button" class="btn-primary" onclick={onClose}>{t('common.done')}</button>
    </div>
  </Dialog>
{:else}
  <Dialog title={t('issue.title')} {onClose} wide>
    {#if issuers.length === 0}
      <Alert kind="warning">{t('issue.noIssuer')}</Alert>
      <div class="flex justify-end">
        <button type="button" class="btn-secondary" onclick={onClose}>{t('common.close')}</button>
      </div>
    {:else}
      <form class="flex flex-col gap-4" onsubmit={submit}>
        <div>
          <label class="label" for="issue-ca">{t('issue.issuer')}</label>
          <select id="issue-ca" class="input" required bind:value={caId}>
            <option value="" disabled>{t('issue.issuerPlaceholder')}</option>
            {#each issuers as c (c.id)}<option value={c.id}>{c.name}</option>{/each}
          </select>
        </div>

        <Field id="issue-cn" label={t('issue.cn')} hint={t('issue.cnHint')} bind:value={cn} />

        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="label" for="issue-dns">{t('issue.dns')}</label>
            <textarea id="issue-dns" class="input min-h-24 font-mono" spellcheck="false" bind:value={dns} oninput={() => (dnsTouched = true)} aria-describedby="issue-dns-hint"></textarea>
            <p class="hint" id="issue-dns-hint">{t('issue.dnsHint')}</p>
          </div>
          <div>
            <label class="label" for="issue-ips">{t('issue.ips')}</label>
            <textarea id="issue-ips" class="input min-h-24 font-mono" spellcheck="false" bind:value={ips} aria-describedby="issue-ips-hint"></textarea>
            <p class="hint" id="issue-ips-hint">{t('issue.ipsHint')}</p>
          </div>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="label" for="issue-profile">{t('issue.profile')}</label>
            <select id="issue-profile" class="input" bind:value={profile}>
              {#each profiles as p (p)}<option value={p}>{t(`profile.${p}`)}</option>{/each}
            </select>
          </div>
          <Field id="issue-days" type="number" label={t('issue.validity')} bind:value={days} />
        </div>
        {#if longValidity}
          <Alert kind="warning">{t('issue.validityWarn', { max: BROWSER_MAX_DAYS })}</Alert>
        {/if}

        <label class="flex items-center gap-2 text-sm">
          <input type="checkbox" bind:checked={useCsr} />
          {t('issue.useCsr')}
        </label>

        {#if useCsr}
          <div>
            <label class="label" for="issue-csr">{t('issue.csr')}</label>
            <textarea id="issue-csr" class="input min-h-32 font-mono text-xs" spellcheck="false" required bind:value={csr} aria-describedby="issue-csr-hint"></textarea>
            <p class="hint" id="issue-csr-hint">{t('issue.csrHint')}</p>
          </div>
        {:else}
          <div>
            <label class="label" for="issue-algo">{t('issue.keyAlgo')}</label>
            <select id="issue-algo" class="input" bind:value={algo}>
              {#each algos as a (a)}<option value={a}>{t(`cas.form.algo.${a}`)}</option>{/each}
            </select>
          </div>
        {/if}

        {#if error}<Alert>{error}</Alert>{/if}

        <div class="flex justify-end gap-2">
          <button type="button" class="btn-secondary" onclick={onClose}>{t('common.cancel')}</button>
          <button class="btn-primary" disabled={busy}>{t('issue.submit')}</button>
        </div>
      </form>
    {/if}
  </Dialog>
{/if}
