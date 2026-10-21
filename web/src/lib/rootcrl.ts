// What to run, on the machine that keeps the Root, to make the Root's CRL after
// an intermediate was revoked. Both recipes are the ones tested against real
// cfssl and openssl (docs/04-revocation.md). The files are data, not commands,
// but names still go through a strict filter so a name cannot break the line
// format of index.txt (TAB separated, one entry per line).

export interface RootCrlEntry {
  ca_id: string;
  ca_name: string;
  serial_hex: string;
  serial_dec: string;
  revoked_at: string;
  reason: string;
}

export type CrlTool = 'cfssl' | 'openssl';
export const crlTools: CrlTool[] = ['cfssl', 'openssl'];

export interface CrlRecipe {
  files: { name: string; content: string }[];
  command: string;
  /** What the command produces: this is what gets imported. */
  resultFile: string;
}

export const DEFAULT_CRL_DAYS = 180; // a Root is rarely powered on: give its list room
export const MIN_CRL_DAYS = 7;
export const MAX_CRL_DAYS = 730;

export function clampDays(n: number): number {
  return Number.isInteger(n) ? Math.min(MAX_CRL_DAYS, Math.max(MIN_CRL_DAYS, n)) : DEFAULT_CRL_DAYS;
}

/** Keeps only characters that cannot disturb a TAB-separated line or a /CN= subject. */
export function safeSubject(name: string): string {
  const s = name.replace(/[^A-Za-z0-9 ._-]+/g, '_').replace(/\s+/g, ' ').trim();
  return s || 'CA';
}

// openssl's index.txt names the reasons its own way.
const opensslReason: Record<string, string> = {
  key_compromise: 'keyCompromise',
  ca_compromise: 'CACompromise',
  affiliation_changed: 'affiliationChanged',
  superseded: 'superseded',
  cessation_of_operation: 'cessationOfOperation',
  unspecified: 'unspecified',
};

/** YYMMDDHHMMSSZ, UTC, as openssl's database wants it. */
export function opensslTime(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

/** Upper-case hex with an even number of digits, which is what the database requires. */
export function evenHex(hex: string): string {
  const h = hex.toUpperCase().replace(/[^0-9A-F]/g, '');
  return h.length % 2 ? `0${h}` : h;
}

export function cfsslCrl(entries: RootCrlEntry[], days: number = DEFAULT_CRL_DAYS): CrlRecipe {
  const d = clampDays(days);
  return {
    // cfssl wants decimal serials, one per line. An empty file makes an empty (valid) list.
    files: [{ name: 'serials.txt', content: entries.map((e) => e.serial_dec.replace(/[^0-9]/g, '')).join('\n') + (entries.length ? '\n' : '') }],
    command: `cfssl gencrl serials.txt root.pem root-key.pem ${d * 86400} > root-crl.b64`,
    resultFile: 'root-crl.b64',
  };
}

export function opensslCrl(entries: RootCrlEntry[], number: number, days: number = DEFAULT_CRL_DAYS, now: Date = new Date()): CrlRecipe {
  const d = clampDays(days);
  const expires = opensslTime(new Date(now.getTime() + 20 * 365 * 86400_000)); // long after any intermediate's own end
  const lines = entries.map((e) => {
    const when = opensslTime(new Date(e.revoked_at));
    const reason = opensslReason[e.reason] ?? 'unspecified';
    return ['R', expires, `${when},${reason}`, evenHex(e.serial_hex), 'unknown', `/CN=${safeSubject(e.ca_name)}`].join('\t');
  });
  const n = Math.max(1, Math.floor(number));
  return {
    files: [
      { name: 'index.txt', content: lines.join('\n') + (lines.length ? '\n' : '') },
      { name: 'crlnumber', content: evenHex(n.toString(16)) + '\n' },
      {
        name: 'ca.cnf',
        content:
          '[ca]\ndefault_ca = CA_default\n\n[CA_default]\n' +
          'database = index.txt\ncrlnumber = crlnumber\ncertificate = root.pem\nprivate_key = root-key.pem\n' +
          `default_md = sha384\ndefault_crl_days = ${d}\n`,
      },
    ],
    command: 'openssl ca -config ca.cnf -gencrl -out root-crl.pem',
    resultFile: 'root-crl.pem',
  };
}
