import { describe, expect, it } from 'vitest';
import { cfsslCrl, clampDays, DEFAULT_CRL_DAYS, evenHex, opensslCrl, opensslTime, safeSubject, type RootCrlEntry } from './rootcrl';
import { rootPointers, signingGuide } from './signing';

const entry = (o: Partial<RootCrlEntry> = {}): RootCrlEntry => ({
  ca_id: 'a'.repeat(32), ca_name: 'Inter A', serial_hex: '3bf66b5e5e2e0ad23554366822bea765b04aa08e',
  serial_dec: '339425791923842345234234', revoked_at: '2026-10-21T02:55:53Z', reason: 'ca_compromise', ...o,
});

describe('cfsslCrl', () => {
  it('lists decimal serials, one per line, and asks for the validity in seconds', () => {
    const r = cfsslCrl([entry(), entry({ serial_dec: '42' })], 180);
    expect(r.files).toEqual([{ name: 'serials.txt', content: '339425791923842345234234\n42\n' }]);
    expect(r.command).toBe('cfssl gencrl serials.txt root.pem root-key.pem 15552000 > root-crl.b64');
    expect(r.resultFile).toBe('root-crl.b64');
  });
  it('makes an empty file for an empty list, which is a valid thing to publish', () => {
    expect(cfsslCrl([]).files[0]!.content).toBe('');
  });
  it('only ever writes digits into the serial file', () => {
    expect(cfsslCrl([entry({ serial_dec: '12; rm -rf /\n34' })]).files[0]!.content).toBe('1234\n');
  });
});

describe('opensslCrl', () => {
  const now = new Date('2026-10-21T10:00:00Z');
  const r = opensslCrl([entry()], 7, 90, now);
  const index = r.files.find((f) => f.name === 'index.txt')!.content;

  it('writes index.txt as openssl expects: TAB separated, even upper-case hex, reason named its way', () => {
    const cols = index.trimEnd().split('\t');
    expect(cols).toHaveLength(6);
    expect(cols[0]).toBe('R');
    expect(cols[1]).toMatch(/^\d{12}Z$/);
    expect(cols[2]).toBe('261021025553Z,CACompromise');
    expect(cols[3]).toBe('3BF66B5E5E2E0AD23554366822BEA765B04AA08E');
    expect(cols[4]).toBe('unknown');
    expect(cols[5]).toBe('/CN=Inter A');
  });
  it('writes the CRL number in hex and a config pointing at the files', () => {
    expect(r.files.find((f) => f.name === 'crlnumber')!.content).toBe('07\n');
    const cnf = r.files.find((f) => f.name === 'ca.cnf')!.content;
    expect(cnf).toContain('database = index.txt');
    expect(cnf).toContain('crlnumber = crlnumber');
    expect(cnf).toContain('default_crl_days = 90');
    expect(r.command).toBe('openssl ca -config ca.cnf -gencrl -out root-crl.pem');
    expect(r.resultFile).toBe('root-crl.pem');
  });
  it('numbers large values correctly', () => {
    expect(opensslCrl([], 255, 90, now).files.find((f) => f.name === 'crlnumber')!.content).toBe('FF\n');
    expect(opensslCrl([], 256, 90, now).files.find((f) => f.name === 'crlnumber')!.content).toBe('0100\n');
  });
  it('cannot be made to break the line format through a CA name', () => {
    const nasty = opensslCrl([entry({ ca_name: 'x\tR\tfake\n/CN=evil' })], 1, 90, now).files[0]!.content;
    expect(nasty.trimEnd().split('\n')).toHaveLength(1);
    expect(nasty.trimEnd().split('\t')).toHaveLength(6);
  });
  it('maps every reason to a name openssl knows', () => {
    for (const reason of ['key_compromise', 'ca_compromise', 'affiliation_changed', 'superseded', 'cessation_of_operation', 'unspecified']) {
      const col = opensslCrl([entry({ reason })], 1, 90, now).files[0]!.content.split('\t')[2]!;
      expect(col).toMatch(/^\d{12}Z,[A-Za-z]+$/);
    }
    expect(opensslCrl([entry({ reason: 'made-up' })], 1, 90, now).files[0]!.content).toContain(',unspecified');
  });
});

describe('helpers', () => {
  it('formats times for openssl in UTC', () => expect(opensslTime(new Date('2026-01-02T03:04:05Z'))).toBe('260102030405Z'));
  it('pads hex to an even length', () => {
    expect(evenHex('abc')).toBe('0ABC');
    expect(evenHex('0a')).toBe('0A');
    expect(evenHex('xyz-12')).toBe('12');
  });
  it('keeps subjects to harmless characters', () => {
    expect(safeSubject('Grupo Matté CA')).toBe('Grupo Matt_ CA');
    expect(safeSubject('')).toBe('CA');
    expect(safeSubject('a/b\\c')).toBe('a_b_c');
  });
  it('keeps the validity within sane bounds', () => {
    expect(clampDays(1)).toBe(7);
    expect(clampDays(100000)).toBe(730);
    expect(clampDays(90)).toBe(90);
    expect(clampDays(NaN)).toBe(DEFAULT_CRL_DAYS);
    expect(clampDays(1.5)).toBe(DEFAULT_CRL_DAYS);
  });
});

describe('the Root pointers in signing recipes', () => {
  const id = 'a'.repeat(32);
  it('are built from a plain public URL and the Root id', () => {
    expect(rootPointers('http://pki.lab:8080', id)).toEqual({ crl: `http://pki.lab:8080/crl/${id}.crl`, issuer: `http://pki.lab:8080/ca/${id}.crt` });
    expect(rootPointers('https://pki.example.com/', id)?.crl).toBe(`https://pki.example.com/crl/${id}.crl`);
  });
  it('are dropped, not escaped, when anything looks wrong', () => {
    for (const bad of [undefined, '', 'pki.lab', 'ftp://pki.lab', 'http://pki.lab/x y', 'http://a"b', "http://a'b", 'http://a;b', 'http://pki.lab\nfoo', 'javascript:alert(1)']) {
      expect(rootPointers(bad, id), String(bad)).toBeUndefined();
    }
    expect(rootPointers('http://pki.lab', 'not-an-id')).toBeUndefined();
    expect(rootPointers('http://pki.lab', id + '"; rm -rf /')).toBeUndefined();
  });
  it('end up in the cfssl profile', () => {
    const p = rootPointers('http://pki.lab:8080', id);
    const cfg = JSON.parse(signingGuide('cfssl', 'x', 365, p).files[0]!.content);
    expect(cfg.signing.profiles.intermediate.crl_url).toBe(`http://pki.lab:8080/crl/${id}.crl`);
    expect(cfg.signing.profiles.intermediate.issuer_urls).toEqual([`http://pki.lab:8080/ca/${id}.crt`]);
    expect(cfg.signing.profiles.intermediate.ca_constraint).toEqual({ is_ca: true, max_path_len: 0, max_path_len_zero: true });
  });
  it('end up in the openssl extensions', () => {
    const ext = signingGuide('openssl', 'x', 365, rootPointers('http://pki.lab:8080', id)).files[0]!.content;
    expect(ext).toContain(`crlDistributionPoints = URI:http://pki.lab:8080/crl/${id}.crl`);
    expect(ext).toContain(`authorityInfoAccess = caIssuers;URI:http://pki.lab:8080/ca/${id}.crt`);
    expect(ext).toContain('pathlen:0');
  });
  it('are absent when there is no public URL, leaving the earlier recipes unchanged', () => {
    const plain = signingGuide('openssl', 'x', 365).files[0]!.content;
    expect(plain).not.toContain('crlDistributionPoints');
    expect(JSON.parse(signingGuide('cfssl', 'x', 365).files[0]!.content).signing.profiles.intermediate.crl_url).toBeUndefined();
  });
});
