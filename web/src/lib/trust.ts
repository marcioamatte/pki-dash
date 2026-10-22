// Instructions for making hosts trust a Root CA. Commands embed a file name
// derived from the CA's name, so that name is reduced to a strict safe subset:
// no spaces, quotes or shell metacharacters can reach a command line.

// Trust is not one list. The system, the browsers, the language runtimes and every
// container image can each keep their own, which is why this is more than "OS".
export type OS = 'debian' | 'rhel' | 'alpine' | 'macos' | 'windows' | 'firefox' | 'java' | 'node' | 'python' | 'containers';
export const operatingSystems: OS[] = ['debian', 'rhel', 'alpine', 'macos', 'windows', 'firefox', 'java', 'node', 'python', 'containers'];

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
    case 'alpine':
      return `apk add --no-cache ca-certificates\ncp ${f} /usr/local/share/ca-certificates/${f}\nupdate-ca-certificates`;
    case 'java':
      return `keytool -importcert -cacerts -alias ${safeStem(caName)} -file ${f} -storepass changeit -noprompt`;
    case 'node':
      return `export NODE_EXTRA_CA_CERTS="$PWD/${f}"`;
    case 'python':
      return `cat "$(python3 -m certifi)" ${f} > ca-bundle.pem\nexport REQUESTS_CA_BUNDLE="$PWD/ca-bundle.pem"`;
    case 'containers':
      return `RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*\nCOPY ${f} /usr/local/share/ca-certificates/${f}\nRUN update-ca-certificates`;
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
