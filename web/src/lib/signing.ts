// What to run, on the machine that keeps the Root, to sign an intermediate's
// request. Both recipes are the ones tested against real cfssl and openssl (see
// docs/03-offline-root.md). Request names go into commands, so they pass
// through safeStem: only [a-z0-9._-] can reach a shell.
import { safeStem } from './trust';

export type Signer = 'cfssl' | 'openssl';
export const signers: Signer[] = ['cfssl', 'openssl'];

export interface SigningGuide {
  /** Files to create first (name and content). */
  files: { name: string; content: string }[];
  /** The command that signs the request. */
  command: string;
  /** The file the command produces: this is what gets imported. */
  resultFile: string;
  /** True when this signer cannot apply the requested name constraints: do not show its recipe. */
  unsupported?: boolean;
}

const DOMAIN = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Parses a list of domains (one per line or separated by commas/spaces) that an
 * intermediate may issue for. A permitted domain covers itself and everything
 * below it, so a leading "*." or "." is dropped. Anything that is not a plain
 * DNS name is reported in `invalid` and never reaches a recipe.
 */
export function parseDomains(text: string): { domains: string[]; invalid: string[] } {
  const domains: string[] = [];
  const invalid: string[] = [];
  for (const raw of text.split(/[\s,;]+/)) {
    if (!raw) continue;
    const d = raw.toLowerCase().replace(/^(\*\.|\.)/, '');
    if (d.length > 253 || !DOMAIN.test(d)) invalid.push(raw);
    else if (!domains.includes(d)) domains.push(d);
  }
  return { domains, invalid };
}

const DAY = 24 * 60 * 60 * 1000;
export const DEFAULT_SIGNING_DAYS = 1825; // five years

/**
 * How many days an intermediate may be valid for: the default, but never past
 * the Root's own end (a day short, so the dates cannot touch).
 */
export function maxSigningDays(rootNotAfter: string, now: Date = new Date(), wanted = DEFAULT_SIGNING_DAYS): number {
  const left = Math.floor((new Date(rootNotAfter).getTime() - now.getTime()) / DAY) - 1;
  if (!Number.isFinite(left)) return wanted;
  return Math.max(1, Math.min(wanted, left));
}

/** Where clients find the Root's CRL and certificate, written into an intermediate when it is signed. */
export interface Pointers {
  crl: string;
  issuer: string;
}

/**
 * The pointers for a Root, or undefined when there is no public address to point
 * at. They end up inside a signing recipe, so they are only built from a plain
 * http(s) base URL and a hex id: anything else is dropped rather than escaped.
 */
export function rootPointers(publicUrl: string | undefined, rootId: string): Pointers | undefined {
  const base = (publicUrl ?? '').replace(/\/+$/, '');
  if (!/^https?:\/\/[A-Za-z0-9._:\[\]-]+(?::\d+)?$/.test(base) || !/^[0-9a-f]{32}$/.test(rootId)) return undefined;
  return { crl: `${base}/crl/${rootId}.crl`, issuer: `${base}/ca/${rootId}.crt` };
}

export function csrFileName(name: string): string {
  return `${safeStem(name)}.csr`;
}

export function signingGuide(signer: Signer, requestName: string, days: number = DEFAULT_SIGNING_DAYS, pointers?: Pointers, domains: string[] = []): SigningGuide {
  const permitted = domains.filter((d) => DOMAIN.test(d));
  const d = Number.isInteger(days) && days >= 1 ? days : DEFAULT_SIGNING_DAYS;
  const stem = safeStem(requestName);
  if (signer === 'cfssl') {
    // cfssl's command line has no way to put a nameConstraints extension in a certificate.
    if (permitted.length > 0) return { files: [], command: '', resultFile: `${stem}.pem`, unsupported: true };
    const config = {
      signing: {
        profiles: {
          intermediate: {
            usages: ['cert sign', 'crl sign'],
            expiry: `${d * 24}h`,
            ...(pointers ? { crl_url: pointers.crl, issuer_urls: [pointers.issuer] } : {}),
            ca_constraint: { is_ca: true, max_path_len: 0, max_path_len_zero: true },
          },
        },
      },
    };
    return {
      files: [{ name: 'ca-config.json', content: JSON.stringify(config, null, 2) }],
      command:
        `cfssl sign -ca root.pem -ca-key root-key.pem -config ca-config.json -profile intermediate ${stem}.csr \\\n` +
        `  | cfssljson -bare ${stem}`,
      resultFile: `${stem}.pem`,
    };
  }
  return {
    files: [
      {
        name: 'inter.ext',
        content:
          'basicConstraints = critical, CA:TRUE, pathlen:0\n' +
          'keyUsage = critical, keyCertSign, cRLSign\n' +
          'subjectKeyIdentifier = hash\n' +
          'authorityKeyIdentifier = keyid' +
          (permitted.length ? `\nnameConstraints = critical, ${permitted.map((d) => `permitted;DNS:${d}`).join(', ')}` : '') +
          (pointers ? `\ncrlDistributionPoints = URI:${pointers.crl}\nauthorityInfoAccess = caIssuers;URI:${pointers.issuer}` : ''),
      },
    ],
    command:
      `openssl x509 -req -in ${stem}.csr -CA root.crt -CAkey root.key -CAcreateserial \\\n` +
      `  -days ${d} -sha384 -extfile inter.ext -out ${stem}.crt`,
    resultFile: `${stem}.crt`,
  };
}
