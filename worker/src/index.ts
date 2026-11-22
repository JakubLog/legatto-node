// legatto-forms: Cloudflare Worker on https://<site>/api/* (office CF account).
//
// D15(b): the browser seals the form with the office X25519 key; the Worker
// never sees the form plaintext. It checks size, key id, origin, Turnstile and
// rate limits, seals its own metadata (IP hash, User-Agent), signs the
// fixed-size envelope with its Ed25519 key and enqueues it. The Worker has no
// API token: it can only produce to the queue, it cannot read or ack it.
// Nothing about a request is logged (observability and logpush are off).
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { rateLimitBucket, sanitizeUserAgent } from './client';
import { type Config, ConfigError, type Env, loadConfig } from './config';
import { concatBytes, ed25519Verify, fromBase64, toHex } from './crypto';
import { FORM_CT_SIZE, KIND_SELFTEST, KIND_SUBMISSION, type Meta, buildEnvelope } from './envelope';
import { SEJM_PATH, handleSejmSittings } from './sejm';
import { verifyTurnstile } from './turnstile';

export type { Env } from './config';

/** Body cap for /api/submit and /api/selftest (base64 of 24 624 B is 32 832 B). */
export const MAX_BODY_BYTES = 40_960;
export const SELFTEST_MAX_SKEW_MS = 120_000;
export const SELFTEST_SIGNATURE_DOMAIN = new TextEncoder().encode('legatto-selftest-v1\0');
const FORM_CT_B64_LENGTH = Math.ceil(FORM_CT_SIZE / 3) * 4;

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const KID_RE = /^[0-9a-f]{16}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extra,
    },
  });
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

/** Reads at most MAX_BODY_BYTES; larger bodies (declared or streamed) are 413. */
async function readBody(request: Request): Promise<Uint8Array> {
  const declared = request.headers.get('Content-Length');
  if (declared !== null && Number(declared) > MAX_BODY_BYTES) throw new HttpError(413, 'too_large');
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new HttpError(413, 'too_large');
    }
    chunks.push(value);
  }
  return concatBytes(...chunks);
}

function parseObject(raw: Uint8Array, keys: readonly string[]): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(raw));
  } catch {
    throw new HttpError(400, 'bad_request');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new HttpError(400, 'bad_request');
  const record = parsed as Record<string, unknown>;
  const present = Object.keys(record);
  if (present.length !== keys.length || !keys.every((k) => present.includes(k))) throw new HttpError(400, 'bad_request');
  if (record.v !== 1) throw new HttpError(400, 'bad_request');
  return record;
}

function requireString(value: unknown, max: number): string {
  if (typeof value !== 'string' || value.length > max) throw new HttpError(400, 'bad_request');
  return value;
}

/** Decodes the browser/server ciphertext; only the exact sealed-form size is accepted. */
function decodeFormCt(value: unknown): Uint8Array {
  const text = requireString(value, FORM_CT_B64_LENGTH);
  if (text.length !== FORM_CT_B64_LENGTH) throw new HttpError(400, 'bad_request');
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(text);
  } catch {
    throw new HttpError(400, 'bad_request');
  }
  if (bytes.length !== FORM_CT_SIZE) throw new HttpError(400, 'bad_request');
  return bytes;
}

function checkKid(value: unknown, config: Config): void {
  const kid = requireString(value, 16);
  if (!KID_RE.test(kid)) throw new HttpError(400, 'bad_request');
  if (kid !== config.officeKidHex) throw new HttpError(409, 'stale_key');
}

async function enqueue(env: Env, config: Config, kind: typeof KIND_SUBMISSION | typeof KIND_SELFTEST, meta: Meta, formCt: Uint8Array): Promise<Response> {
  const envelope = buildEnvelope({
    kind,
    officePublic: config.officePublic,
    officeKid: config.officeKid,
    signerSeed: config.signerSeed,
    signerKid: config.signerKid,
    receivedAtMs: Date.now(),
    meta,
    formCt,
  });
  try {
    await env.FORMS.send(envelope, { contentType: 'bytes' });
  } catch {
    throw new HttpError(503, 'unavailable');
  }
  return json(202, { ref: toHex(sha256(formCt)).slice(0, 8) });
}

async function handleSubmit(request: Request, env: Env, config: Config): Promise<Response> {
  if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' }, { Allow: 'POST' });
  if (request.headers.get('Origin') !== config.siteOrigin) throw new HttpError(403, 'origin');
  const contentType = request.headers.get('Content-Type') ?? '';
  if (!/^application\/json(\s*;|$)/i.test(contentType)) throw new HttpError(415, 'unsupported_media_type');

  const clientIp = request.headers.get('CF-Connecting-IP');
  const bucket = rateLimitBucket(clientIp ?? 'unknown');
  const ipHash = toHex(hmac(sha256, config.ipHashKey, new TextEncoder().encode(bucket)));
  if (!(await env.RL_IP.limit({ key: ipHash })).success) throw new HttpError(429, 'rate_limited');

  const body = parseObject(await readBody(request), ['v', 'kid', 'ct', 'turnstile', 'hp']);
  const honeypot = requireString(body.hp, 1024);
  if (honeypot !== '') {
    // Bots get the same answer as people; nothing is enqueued.
    return json(202, { ref: toHex(crypto.getRandomValues(new Uint8Array(4))) });
  }
  checkKid(body.kid, config);
  const formCt = decodeFormCt(body.ct);
  const token = requireString(body.turnstile, 2048);
  if (token === '') throw new HttpError(403, 'turnstile');

  const verdict = await verifyTurnstile(token, clientIp, config.turnstileSecret, config.turnstileHostnames, config.turnstileAction);
  if (!verdict.ok) throw new HttpError(verdict.reason === 'unavailable' ? 503 : 403, verdict.reason === 'unavailable' ? 'unavailable' : 'turnstile');
  if (!(await env.RL_GLOBAL.limit({ key: 'global' })).success) throw new HttpError(429, 'rate_limited');

  const meta: Meta = {
    v: 1,
    ip_hash: ipHash,
    ua: sanitizeUserAgent(request.headers.get('User-Agent')),
    turnstile_ts: verdict.challengeTs,
    release: config.release,
  };
  return enqueue(env, config, KIND_SUBMISSION, meta, formCt);
}

/**
 * POST /api/selftest — the office server (legatto-intake selftest) proves the
 * whole path (Worker -> queue -> intake) without Turnstile. Authenticated by
 * the office self-test Ed25519 key; replays are bounded by the ±120 s window,
 * the rate limit and envelope de-duplication in intake.
 */
async function handleSelftest(request: Request, env: Env, config: Config): Promise<Response> {
  if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' }, { Allow: 'POST' });
  if (!(await env.RL_SELFTEST.limit({ key: 'selftest' })).success) throw new HttpError(429, 'rate_limited');
  const body = parseObject(await readBody(request), ['v', 'kid', 'ct', 'ts', 'nonce', 'sig']);
  checkKid(body.kid, config);
  const formCt = decodeFormCt(body.ct);
  const ts = requireString(body.ts, 40);
  const nonce = requireString(body.nonce, 32);
  if (!ISO_RE.test(ts) || !NONCE_RE.test(nonce)) throw new HttpError(400, 'bad_request');
  const sentAt = Date.parse(ts);
  if (!Number.isFinite(sentAt) || Math.abs(Date.now() - sentAt) > SELFTEST_MAX_SKEW_MS) throw new HttpError(403, 'selftest_auth');
  let signature: Uint8Array;
  try {
    signature = fromBase64(requireString(body.sig, 100));
  } catch {
    throw new HttpError(400, 'bad_request');
  }
  const encoder = new TextEncoder();
  const signed = concatBytes(SELFTEST_SIGNATURE_DOMAIN, encoder.encode(ts), new Uint8Array([0]), encoder.encode(nonce), new Uint8Array([0]), sha256(formCt));
  if (signature.length !== 64 || !ed25519Verify(signature, signed, config.selftestPublic)) throw new HttpError(403, 'selftest_auth');

  const meta: Meta = { v: 1, ip_hash: '0'.repeat(64), ua: 'selftest', turnstile_ts: null, release: config.release };
  return enqueue(env, config, KIND_SELFTEST, meta, formCt);
}

function handleHealth(request: Request, config: Config): Response {
  if (request.method !== 'GET') return json(405, { error: 'method_not_allowed' }, { Allow: 'GET' });
  return json(200, {
    v: 1,
    release: config.release,
    office_kid: config.officeKidHex,
    signer_kid: config.signerKidHex,
    selftest_kid: config.selftestKidHex,
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === SEJM_PATH) return handleSejmSittings(request, ctx);
    let config: Config;
    try {
      config = loadConfig(env);
    } catch (err) {
      if (err instanceof ConfigError) return json(503, { error: 'misconfigured' });
      throw err;
    }
    try {
      switch (pathname) {
        case '/api/submit':
          return await handleSubmit(request, env, config);
        case '/api/selftest':
          return await handleSelftest(request, env, config);
        case '/api/health':
          return handleHealth(request, config);
        default:
          return json(404, { error: 'not_found' });
      }
    } catch (err) {
      if (err instanceof HttpError) return json(err.status, { error: err.code });
      return json(500, { error: 'internal' });
    }
  },
} satisfies ExportedHandler<Env>;
