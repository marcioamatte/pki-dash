/** A downloadable text file backed by an object URL. Call revoke() when done. */
export interface TextDownload {
  url: string;
  revoke: () => void;
}

export function textDownload(text: string): TextDownload {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }));
  return { url, revoke: () => URL.revokeObjectURL(url) };
}
