import { env } from 'cloudflare:workers';
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { vi } from 'vitest';
import worker, { type Env } from '../../src/index';
import { concatBytes, fromBase64, sealBox, toBase64 } from '../../src/crypto';
import { FORM_PLAINTEXT_SIZE, pad } from '../../src/envelope';

export interface TestEnv extends Env {
  TEST_OFFICE_SECRET: string;
  TEST_SELFTEST_SEED: string;
}

export const baseEnv = env as unknown as TestEnv; // bindings from vitest.config.ts
export const officePublic = fromBase64(baseEnv.OFFICE_X25519_PUB);
export const officeSecret = fromBase64(baseEnv.TEST_OFFICE_SECRET);
export const selftestSeed = fromBase64(baseEnv.TEST_SELFTEST_SEED);
export const signerPublic = ed25519.getPublicKey(fromBase64(baseEnv.SIGNING_KEY));
export const SITE = 'https://posel-test.pl';

export const FORM = {
  v: 1,
  id: '6f1c2b0e-8a4d-4d2a-9b55-0c4a7d7b9e01',
  ts: '2026-11-21T12:00:00.000Z',
  kind: 'submission',
  site: 'posel-test.pl',
  form: {
    reporter_name: 'Jan Testowy',
    reporter_email: 'jan@example.org',
    reporter_phone: null,
    powiat_id: 1,
    gmina_id: null,
    category_id: 3,
    title: 'Dziura w drodze',
    description: 'Na ulicy Długiej od miesiąca jest dziura, której nikt nie łata.',
    rodo_consent: true,
    consent_newsletter: false,
    consent_contacts_db: false,
  },
};

export function sealedForm(plaintext: unknown = FORM): Uint8Array {
  return sealBox(pad(JSON.stringify(plaintext), FORM_PLAINTEXT_SIZE), officePublic);
}

export interface Sent {
  body: Uint8Array;
  contentType: string | undefined;
}

export function fakeEnv(overrides: Partial<Record<'ip' | 'global' | 'selftest' | 'queueFails', boolean>> = {}): { env: TestEnv; sent: Sent[]; limits: string[] } {
  const sent: Sent[] = [];
  const limits: string[] = [];
  const limiter = (name: string, ok: boolean): RateLimit => ({
    async limit({ key }) {
      limits.push(`${name}:${key}`);
      return { success: ok };
    },
  });
  const queue = {
    async send(body: unknown, options?: { contentType?: string }) {
      if (overrides.queueFails) throw new Error('queue down');
      sent.push({ body: new Uint8Array(body as ArrayBufferLike), contentType: options?.contentType });
    },
    async sendBatch() {
      throw new Error('not used');
    },
  } as unknown as Queue; // only send() is used by the Worker
  return {
    env: {
      ...baseEnv,
      FORMS: queue,
      RL_IP: limiter('ip', overrides.ip ?? true),
      RL_GLOBAL: limiter('global', overrides.global ?? true),
      RL_SELFTEST: limiter('selftest', overrides.selftest ?? true),
    },
    sent,
    limits,
  };
}

export interface SiteverifyCall {
  secret: string;
  response: string;
  remoteip: string | null;
  idempotency_key: string | null;
}

/**
 * Stubs global fetch with a siteverify emulator. Dummy secret keys behave as
 * documented by Cloudflare (1x… passes with hostname example.com and no action,
 * 2x… fails, 3x… "timeout-or-duplicate"); any other secret returns `real`.
 */
export function stubSiteverify(real: Record<string, unknown> | 'error' = { success: true, hostname: 'posel-test.pl', action: 'submit_case', challenge_ts: '2026-11-21T11:59:58.000Z' }): SiteverifyCall[] {
  const calls: SiteverifyCall[] = [];
  vi.stubGlobal('fetch', async (input: RequestInfo, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.url;
    if (url !== 'https://challenges.cloudflare.com/turnstile/v0/siteverify') throw new Error(`unexpected fetch ${url}`);
    const form = new URLSearchParams(String(init?.body ?? ''));
    const call: SiteverifyCall = {
      secret: form.get('secret') ?? '',
      response: form.get('response') ?? '',
      remoteip: form.get('remoteip'),
      idempotency_key: form.get('idempotency_key'),
    };
    calls.push(call);
    if (real === 'error') return new Response('upstream error', { status: 500 });
    let body: Record<string, unknown>;
    if (call.secret.startsWith('1x0000')) {
      body = call.response === 'XXXX.DUMMY.TOKEN.XXXX'
        ? { success: true, challenge_ts: '2022-02-28T15:14:30.096Z', hostname: 'example.com', 'error-codes': [] }
        : { success: false, 'error-codes': ['invalid-input-response'] };
    } else if (call.secret.startsWith('2x0000')) body = { success: false, 'error-codes': ['invalid-input-response'] };
    else if (call.secret.startsWith('3x0000')) body = { success: false, 'error-codes': ['timeout-or-duplicate'] };
    else body = real;
    return Response.json(body);
  });
  return calls;
}

export async function call(testEnv: TestEnv, path: string, init: RequestInit & { headers?: Record<string, string> } = {}): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${SITE}${path}`, init), testEnv, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

export function submitInit(body: unknown, headers: Record<string, string> = {}): RequestInit & { headers: Record<string, string> } {
  return {
    method: 'POST',
    headers: {
      Origin: SITE,
      'Content-Type': 'application/json',
      'CF-Connecting-IP': '203.0.113.77',
      'User-Agent': 'Mozilla/5.0 (Test)',
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

export function submitBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 1, kid: baseEnv.OFFICE_KID, ct: toBase64(sealedForm()), turnstile: 'token-from-widget', hp: '', ...overrides };
}

export function selftestBody(ts = new Date().toISOString(), seed = selftestSeed, ct = sealedForm({ v: 1, kind: 'selftest', form: null, marker: 'a'.repeat(32), mode: 'ping' })): Record<string, unknown> {
  const nonce = '0123456789abcdef0123456789abcdef';
  const enc = new TextEncoder();
  const signed = concatBytes(enc.encode('legatto-selftest-v1\0'), enc.encode(ts), new Uint8Array([0]), enc.encode(nonce), new Uint8Array([0]), sha256(ct));
  return { v: 1, kid: baseEnv.OFFICE_KID, ct: toBase64(ct), ts, nonce, sig: toBase64(ed25519.sign(signed, seed)) };
}
