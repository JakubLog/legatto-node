import { exports } from 'cloudflare:workers';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { concatBytes, fromBase64, keyId, openBox, toBase64, toHex } from '../../src/crypto';
import {
  ENVELOPE_SIZE,
  FORM_CT_SIZE,
  HEADER_SIZE,
  KIND_SELFTEST,
  KIND_SUBMISSION,
  META_CT_SIZE,
  SIGNATURE_DOMAIN,
  SIGNED_HEADER_SIZE,
} from '../../src/envelope';
import {
  FORM,
  baseEnv,
  call,
  fakeEnv,
  officeSecret,
  sealedForm,
  selftestBody,
  signerPublic,
  stubSiteverify,
  submitBody,
  submitInit,
} from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
});

function unpad(plain: Uint8Array): unknown {
  const len = new DataView(plain.buffer, plain.byteOffset).getUint32(0, false);
  expect(plain.subarray(4 + len).every((b) => b === 0)).toBe(true);
  return JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + len)));
}

/** Parses and fully checks an envelope; returns decrypted parts. */
function openEnvelope(envelope: Uint8Array): { kind: number; receivedAt: bigint; meta: Record<string, unknown>; form: unknown; formCt: Uint8Array } {
  expect(envelope.length).toBe(ENVELOPE_SIZE);
  expect(new TextDecoder().decode(envelope.subarray(0, 4))).toBe('LGF1');
  expect(envelope[4]).toBe(1);
  expect(toHex(envelope.subarray(6, 14))).toBe(baseEnv.OFFICE_KID);
  expect(toHex(envelope.subarray(14, 22))).toBe(toHex(keyId(signerPublic)));
  const receivedAt = new DataView(envelope.buffer, envelope.byteOffset).getBigUint64(22, false);
  const sig = envelope.subarray(SIGNED_HEADER_SIZE, HEADER_SIZE);
  const metaCt = envelope.subarray(HEADER_SIZE, HEADER_SIZE + META_CT_SIZE);
  const formCt = envelope.subarray(HEADER_SIZE + META_CT_SIZE);
  expect(formCt.length).toBe(FORM_CT_SIZE);
  const signed = concatBytes(SIGNATURE_DOMAIN, envelope.subarray(0, SIGNED_HEADER_SIZE), metaCt, formCt);
  expect(ed25519.verify(sig, signed, signerPublic)).toBe(true);
  return {
    kind: envelope[5],
    receivedAt,
    meta: unpad(openBox(metaCt, officeSecret)) as Record<string, unknown>,
    form: unpad(openBox(formCt, officeSecret)),
    formCt,
  };
}

describe('GET /api/health', () => {
  it('reports release and key ids, no secrets', async () => {
    const { env } = fakeEnv();
    const res = await call(env, '/api/health');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({
      v: 1,
      release: '1.2.3',
      office_kid: baseEnv.OFFICE_KID,
      signer_kid: toHex(keyId(signerPublic)),
      selftest_kid: toHex(keyId(fromBase64(baseEnv.SELFTEST_ED25519_PUB))),
    });
    expect(JSON.stringify(body)).not.toContain(baseEnv.SIGNING_KEY);
  });

  it('answers 503 when the Worker is misconfigured', async () => {
    const { env } = fakeEnv();
    const res = await call({ ...env, OFFICE_KID: '0000000000000000' }, '/api/health');
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: 'misconfigured' });
  });
});

describe('POST /api/submit', () => {
  it('signs and enqueues a fixed-size envelope; the browser ciphertext passes through untouched', async () => {
    const { env, sent, limits } = fakeEnv();
    const calls = stubSiteverify();
    const body = submitBody();
    const res = await call(env, '/api/submit', submitInit(body));
    expect(res.status).toBe(202);
    const ct = fromBase64(body.ct as string);
    expect(await res.json()).toEqual({ ref: toHex(sha256(ct)).slice(0, 8) });

    expect(sent).toHaveLength(1);
    expect(sent[0].contentType).toBe('bytes');
    const opened = openEnvelope(sent[0].body);
    expect(opened.kind).toBe(KIND_SUBMISSION);
    expect(Number(opened.receivedAt)).toBeGreaterThan(Date.parse('2026-01-01T00:00:00Z'));
    expect(toHex(opened.formCt)).toBe(toHex(ct));
    expect(opened.form).toEqual(FORM);

    const expectedHash = toHex(hmac(sha256, fromBase64(baseEnv.IP_HASH_KEY), new TextEncoder().encode('203.0.113.77')));
    expect(opened.meta).toEqual({
      v: 1,
      ip_hash: expectedHash,
      ua: 'Mozilla/5.0 (Test)',
      turnstile_ts: '2026-11-21T11:59:58.000Z',
      release: '1.2.3',
    });
    // The raw client IP never reaches the queue (not even inside the sealed meta).
    expect(new TextDecoder('latin1').decode(sent[0].body)).not.toContain('203.0.113.77');
    expect(JSON.stringify(opened.meta)).not.toContain('203.0.113.77');

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ secret: baseEnv.TURNSTILE_SECRET, response: 'token-from-widget', remoteip: '203.0.113.77' });
    expect(calls[0].idempotency_key).toMatch(/^[0-9a-f-]{36}$/);
    expect(limits).toEqual([`ip:${expectedHash}`, 'global:global']);
  });

  it('collapses IPv6 clients to their /64 for the IP hash', async () => {
    const { env, sent } = fakeEnv();
    stubSiteverify();
    const res = await call(env, '/api/submit', submitInit(submitBody(), { 'CF-Connecting-IP': '2001:db8:1:2:aaaa::1' }));
    expect(res.status).toBe(202);
    const expected = toHex(hmac(sha256, fromBase64(baseEnv.IP_HASH_KEY), new TextEncoder().encode('2001:0db8:0001:0002::/64')));
    expect(openEnvelope(sent[0].body).meta.ip_hash).toBe(expected);
  });

  describe('envelope size (fixed-size sealed form)', () => {
    for (const size of [FORM_CT_SIZE - 1, FORM_CT_SIZE + 1, FORM_CT_SIZE - 48, 0]) {
      it(`rejects a ${size}-byte ciphertext without enqueueing`, async () => {
        const { env, sent } = fakeEnv();
        const calls = stubSiteverify();
        const ct = new Uint8Array(size);
        const res = await call(env, '/api/submit', submitInit(submitBody({ ct: toBase64(ct) })));
        expect(res.status).toBe(400);
        expect(sent).toHaveLength(0);
        expect(calls).toHaveLength(0);
      });
    }

    it('rejects non-canonical base64 of the right length', async () => {
      const { env, sent } = fakeEnv();
      stubSiteverify();
      const good = toBase64(sealedForm());
      const res = await call(env, '/api/submit', submitInit(submitBody({ ct: `${good.slice(0, -4)}!!!=` })));
      expect(res.status).toBe(400);
      expect(sent).toHaveLength(0);
    });

    it('rejects bodies over 40 KiB by Content-Length and by streamed size', async () => {
      const { env, sent } = fakeEnv();
      stubSiteverify();
      const big = JSON.stringify(submitBody({ hp: 'x'.repeat(50_000) }));
      const declared = await call(env, '/api/submit', submitInit(big));
      expect(declared.status).toBe(413);
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(big));
          controller.close();
        },
      });
      const init = submitInit('');
      const streamed = await call(env, '/api/submit', { ...init, body: stream, duplex: 'half' } as RequestInit & { headers: Record<string, string> });
      expect(streamed.status).toBe(413);
      expect(sent).toHaveLength(0);
    });
  });

  it('rejects unknown or missing fields', async () => {
    const { env, sent } = fakeEnv();
    stubSiteverify();
    const extra = await call(env, '/api/submit', submitInit({ ...submitBody(), title: 'plaintext leak' }));
    expect(extra.status).toBe(400);
    const { hp: _hp, ...missing } = submitBody();
    expect((await call(env, '/api/submit', submitInit(missing))).status).toBe(400);
    expect((await call(env, '/api/submit', submitInit(submitBody({ v: 2 })))).status).toBe(400);
    expect((await call(env, '/api/submit', submitInit('not json'))).status).toBe(400);
    expect(sent).toHaveLength(0);
  });

  it('answers 409 stale_key when the browser used another office key', async () => {
    const { env, sent } = fakeEnv();
    stubSiteverify();
    const res = await call(env, '/api/submit', submitInit(submitBody({ kid: 'ffffffffffffffff' })));
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: 'stale_key' });
    expect(sent).toHaveLength(0);
  });

  it('requires the site Origin and a JSON content type', async () => {
    const { env, sent } = fakeEnv();
    stubSiteverify();
    expect((await call(env, '/api/submit', submitInit(submitBody(), { Origin: 'https://evil.example' }))).status).toBe(403);
    expect((await call(env, '/api/submit', submitInit(submitBody(), { 'Content-Type': 'text/plain' }))).status).toBe(415);
    expect((await call(env, '/api/submit', { method: 'GET' })).status).toBe(405);
    expect(sent).toHaveLength(0);
  });

  it('answers a filled honeypot with a fake 202 and enqueues nothing', async () => {
    const { env, sent } = fakeEnv();
    const calls = stubSiteverify();
    const res = await call(env, '/api/submit', submitInit(submitBody({ hp: 'http://spam.example' })));
    expect(res.status).toBe(202);
    expect((await res.json()) as { ref: string }).toMatchObject({ ref: expect.stringMatching(/^[0-9a-f]{8}$/) });
    expect(sent).toHaveLength(0);
    expect(calls).toHaveLength(0);
  });

  describe('Turnstile with Cloudflare test keys', () => {
    it('never accepts the always-pass dummy key: hostname example.com and no action', async () => {
      const { env, sent } = fakeEnv();
      const calls = stubSiteverify();
      const testEnv = { ...env, TURNSTILE_SECRET: '1x0000000000000000000000000000000AA' };
      const res = await call(testEnv, '/api/submit', submitInit(submitBody({ turnstile: 'XXXX.DUMMY.TOKEN.XXXX' })));
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: 'turnstile' });
      expect(calls[0].secret).toBe('1x0000000000000000000000000000000AA');
      // Even with example.com allowed, the missing action keeps it closed.
      const permissive = { ...testEnv, TURNSTILE_HOSTNAMES: 'posel-test.pl,example.com' };
      expect((await call(permissive, '/api/submit', submitInit(submitBody({ turnstile: 'XXXX.DUMMY.TOKEN.XXXX' })))).status).toBe(403);
      expect(sent).toHaveLength(0);
    });

    it('rejects the always-fail and already-spent dummy keys', async () => {
      const { env, sent } = fakeEnv();
      stubSiteverify();
      for (const secret of ['2x0000000000000000000000000000000AA', '3x0000000000000000000000000000000AA']) {
        const res = await call({ ...env, TURNSTILE_SECRET: secret }, '/api/submit', submitInit(submitBody({ turnstile: 'XXXX.DUMMY.TOKEN.XXXX' })));
        expect(res.status).toBe(403);
      }
      expect(sent).toHaveLength(0);
    });

    it('rejects a wrong hostname or action and an empty token', async () => {
      const { env, sent } = fakeEnv();
      stubSiteverify({ success: true, hostname: 'other.pl', action: 'submit_case' });
      expect((await call(env, '/api/submit', submitInit(submitBody()))).status).toBe(403);
      stubSiteverify({ success: true, hostname: 'posel-test.pl', action: 'login' });
      expect((await call(env, '/api/submit', submitInit(submitBody()))).status).toBe(403);
      const calls = stubSiteverify();
      expect((await call(env, '/api/submit', submitInit(submitBody({ turnstile: '' })))).status).toBe(403);
      expect(calls).toHaveLength(0);
      expect(sent).toHaveLength(0);
    });

    it('answers 503 when siteverify is unavailable', async () => {
      const { env, sent } = fakeEnv();
      stubSiteverify('error');
      expect((await call(env, '/api/submit', submitInit(submitBody()))).status).toBe(503);
      expect(sent).toHaveLength(0);
    });
  });

  describe('rate limits', () => {
    it('per-IP limit answers 429 before Turnstile is consumed', async () => {
      const { env, sent } = fakeEnv({ ip: false });
      const calls = stubSiteverify();
      const res = await call(env, '/api/submit', submitInit(submitBody()));
      expect(res.status).toBe(429);
      expect(calls).toHaveLength(0);
      expect(sent).toHaveLength(0);
    });

    it('global limit answers 429 after Turnstile', async () => {
      const { env, sent } = fakeEnv({ global: false });
      stubSiteverify();
      expect((await call(env, '/api/submit', submitInit(submitBody()))).status).toBe(429);
      expect(sent).toHaveLength(0);
    });
  });

  it('answers 503 when the queue rejects the message', async () => {
    const { env } = fakeEnv({ queueFails: true });
    stubSiteverify();
    expect((await call(env, '/api/submit', submitInit(submitBody()))).status).toBe(503);
  });
});

describe('POST /api/selftest', () => {
  it('accepts a request signed with the office self-test key and enqueues a selftest envelope', async () => {
    const { env, sent } = fakeEnv();
    const calls = stubSiteverify();
    const body = selftestBody();
    const res = await call(env, '/api/selftest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    expect(res.status).toBe(202);
    expect(calls).toHaveLength(0);
    const opened = openEnvelope(sent[0].body);
    expect(opened.kind).toBe(KIND_SELFTEST);
    expect(opened.meta).toEqual({ v: 1, ip_hash: '0'.repeat(64), ua: 'selftest', turnstile_ts: null, release: '1.2.3' });
    expect(opened.form).toMatchObject({ kind: 'selftest', marker: 'a'.repeat(32) });
  });

  it('rejects a foreign key, a tampered ciphertext and a stale timestamp', async () => {
    const { env, sent } = fakeEnv();
    const post = (body: Record<string, unknown>) =>
      call(env, '/api/selftest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    expect((await post(selftestBody(undefined, ed25519.utils.randomSecretKey()))).status).toBe(403);
    const tampered = selftestBody();
    tampered.ct = toBase64(sealedForm());
    expect((await post(tampered)).status).toBe(403);
    expect((await post(selftestBody(new Date(Date.now() - 5 * 60_000).toISOString()))).status).toBe(403);
    expect((await post({ ...selftestBody(), extra: 1 })).status).toBe(400);
    expect(sent).toHaveLength(0);
  });

  it('is rate limited', async () => {
    const { env, sent } = fakeEnv({ selftest: false });
    const res = await call(env, '/api/selftest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(selftestBody()) });
    expect(res.status).toBe(429);
    expect(sent).toHaveLength(0);
  });
});

describe('integration with real Miniflare bindings (queue producer, rate limiters)', () => {
  it('health and selftest run end to end through the deployed handler', async () => {
    const health = await exports.default.fetch('https://posel-test.pl/api/health');
    expect(health.status).toBe(200);
    const res = await exports.default.fetch('https://posel-test.pl/api/selftest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(selftestBody()),
    });
    expect(res.status).toBe(202);
    const notFound = await exports.default.fetch('https://posel-test.pl/api/other');
    expect(notFound.status).toBe(404);
  });
});
