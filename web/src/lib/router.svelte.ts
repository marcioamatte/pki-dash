// A tiny hash router: the server only ever has to serve index.html at "/".
export type Route = '/cas' | '/certs';
const known: Route[] = ['/cas', '/certs'];

function parse(hash: string): Route {
  const p = hash.replace(/^#/, '');
  return (known as string[]).includes(p) ? (p as Route) : '/cas';
}

export const router = $state({ path: parse(typeof location === 'undefined' ? '' : location.hash) });

if (typeof window !== 'undefined') {
  window.addEventListener('hashchange', () => {
    router.path = parse(location.hash);
  });
}
