// GET /api/sejm-sittings — Sejm sittings for the public calendar, fetched at
// the edge so the office server never needs egress to api.sejm.gov.pl.
// Port of legatto-app api/sejm-sittings.ts with the Cache API instead of the
// Vercel CDN: the full upstream answer is ~1 MB, the response a few KB.

const SEJM_API = 'https://api.sejm.gov.pl/sejm';
const TIMEOUT_MS = 10_000;
export const SEJM_PATH = '/api/sejm-sittings';
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const CACHE_CONTROL = 'public, max-age=3600, s-maxage=21600, stale-while-revalidate=86400';

interface SejmTerm {
  num: number;
  current: boolean;
}

interface SejmProceeding {
  number: number;
  dates: string[];
  current: boolean;
}

async function getJson<T>(url: string, signal: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal, headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`Sejm API ${res.status}`);
  return (await res.json()) as T;
}

async function fetchSittings(): Promise<Response> {
  const signal = AbortSignal.timeout(TIMEOUT_MS);
  const terms = await getJson<SejmTerm[]>(`${SEJM_API}/term`, signal);
  const term = Array.isArray(terms) ? terms.find((t) => t.current) : undefined;
  // The term number goes into the URL path: small integers only.
  if (!term || !Number.isInteger(term.num) || term.num < 1 || term.num > 99) throw new Error('Sejm API: no current term');
  const proceedings = await getJson<SejmProceeding[]>(`${SEJM_API}/term${term.num}/proceedings`, signal);
  if (!Array.isArray(proceedings)) throw new Error('Sejm API: invalid proceedings');
  const sittings = proceedings
    .filter((p) => Array.isArray(p.dates) && Number.isInteger(p.number))
    .map((p) => ({
      number: p.number,
      dates: p.dates.filter((d) => typeof d === 'string' && DATE_RE.test(d)).sort(),
      current: p.current === true,
    }))
    .filter((s) => s.dates.length > 0);
  return new Response(JSON.stringify({ sittings }), {
    status: 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': CACHE_CONTROL },
  });
}

export async function handleSejmSittings(request: Request, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'method_not_allowed' }), {
      status: 405,
      headers: { Allow: 'GET', 'Content-Type': 'application/json' },
    });
  }
  const url = new URL(request.url);
  // No parameters: any query string would bypass the cache, so redirect it.
  if (url.search !== '') {
    return new Response(null, {
      status: 308,
      headers: { Location: SEJM_PATH, 'Cache-Control': 'public, max-age=86400' },
    });
  }
  const cache = caches.default;
  const cacheKey = new Request(`${url.origin}${SEJM_PATH}`, { method: 'GET' });
  const hit = await cache.match(cacheKey);
  if (hit) return hit;
  try {
    const fresh = await fetchSittings();
    ctx.waitUntil(cache.put(cacheKey, fresh.clone()));
    return fresh;
  } catch {
    return new Response(JSON.stringify({ error: 'sejm_unavailable' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }
}
