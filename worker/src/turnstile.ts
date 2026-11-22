// Turnstile server-side validation (siteverify). A token is single-use and
// valid for 300 s; the Worker additionally requires the configured hostname
// and action, so dummy test keys (hostname example.com, no action) can never
// pass a production Worker.

export const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export type TurnstileResult =
  | { ok: true; challengeTs: string | null }
  | { ok: false; reason: 'rejected' | 'hostname' | 'action' | 'unavailable' };

interface SiteverifyResponse {
  success?: unknown;
  hostname?: unknown;
  action?: unknown;
  challenge_ts?: unknown;
}

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

export async function verifyTurnstile(
  token: string,
  remoteIp: string | null,
  secret: string,
  hostnames: string[],
  action: string,
): Promise<TurnstileResult> {
  const form = new URLSearchParams();
  form.set('secret', secret);
  form.set('response', token);
  if (remoteIp) form.set('remoteip', remoteIp);
  form.set('idempotency_key', crypto.randomUUID());
  let body: SiteverifyResponse;
  try {
    const res = await fetch(SITEVERIFY_URL, {
      method: 'POST',
      body: form,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return { ok: false, reason: 'unavailable' };
    body = (await res.json()) as SiteverifyResponse;
  } catch {
    return { ok: false, reason: 'unavailable' };
  }
  if (body.success !== true) return { ok: false, reason: 'rejected' };
  if (typeof body.hostname !== 'string' || !hostnames.includes(body.hostname)) return { ok: false, reason: 'hostname' };
  if (body.action !== action) return { ok: false, reason: 'action' };
  const challengeTs = typeof body.challenge_ts === 'string' && ISO_RE.test(body.challenge_ts) ? body.challenge_ts : null;
  return { ok: true, challengeTs };
}
