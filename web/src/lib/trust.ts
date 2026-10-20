// Instructions for making hosts trust a Root CA. Commands embed a file name
// derived from the CA's name, so that name is reduced to a strict safe subset:
// no spaces, quotes or shell metacharacters can reach a command line.

export type OS = 'debian' | 'rhel' | 'macos' | 'windows' | 'firefox';
export const operatingSystems: OS[] = ['debian', 'rhel', 'macos', 'windows', 'firefox'];

/** A lowercase file stem made only of [a-z0-9._-], never empty and never starting with a dot or dash. */
export function safeStem(name: string): string {
  const s = name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '') // drop accents: "Autoridade Café" -> "Autoridade Cafe"
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, '')
    .replace(/-{2,}/g, '-');
  return s || 'ca';
}

/** Shell/PowerShell commands for an OS, or null when the OS needs a walkthrough (Firefox). */
export function trustCommands(os: OS, caName: string): string | null {
  const f = `${safeStem(caName)}.crt`;
  switch (os) {
    case 'debian':
      return `sudo cp ${f} /usr/local/share/ca-certificates/${f}\nsudo update-ca-certificates`;
    case 'rhel':
      return `sudo cp ${f} /etc/pki/ca-trust/source/anchors/${f}\nsudo update-ca-trust`;
    case 'macos':
      return `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${f}`;
    case 'windows':
      return `Import-Certificate -FilePath .\\${f} -CertStoreLocation Cert:\\LocalMachine\\Root`;
    case 'firefox':
      return null;
  }
}

export const fileName = {
  caCert: (name: string) => `${safeStem(name)}.crt`,
  caKey: (name: string) => `${safeStem(name)}.key`,
  leafCert: (cn: string) => `${safeStem(cn.replace(/^\*\./, 'wildcard.'))}.crt`,
  leafKey: (cn: string) => `${safeStem(cn.replace(/^\*\./, 'wildcard.'))}.key`,
  leafChain: (cn: string) => `${safeStem(cn.replace(/^\*\./, 'wildcard.'))}-fullchain.pem`,
};
