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

export function signingGuide(signer: Signer, requestName: string, days: number = DEFAULT_SIGNING_DAYS, pointers?: Pointers): SigningGuide {
  const d = Number.isInteger(days) && days >= 1 ? days : DEFAULT_SIGNING_DAYS;
  const stem = safeStem(requestName);
  if (signer === 'cfssl') {
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
          (pointers ? `\ncrlDistributionPoints = URI:${pointers.crl}\nauthorityInfoAccess = caIssuers;URI:${pointers.issuer}` : ''),
      },
    ],
    command:
      `openssl x509 -req -in ${stem}.csr -CA root.crt -CAkey root.key -CAcreateserial \\\n` +
      `  -days ${d} -sha384 -extfile inter.ext -out ${stem}.crt`,
    resultFile: `${stem}.crt`,
  };
}
