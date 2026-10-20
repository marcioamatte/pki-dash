import { describe, expect, it } from 'vitest';
import { textDownload } from './download';

describe('textDownload', () => {
  it('serves exactly the given text and can be revoked', async () => {
    const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';
    const d = textDownload(pem);
    expect(d.url.startsWith('blob:')).toBe(true);
    expect(await (await fetch(d.url)).text()).toBe(pem);
    d.revoke();
    await expect(fetch(d.url)).rejects.toThrow();
  });
});
