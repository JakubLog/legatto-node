import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { defineConfig } from 'vitest/config';

// Deterministic test-only keys (never used outside tests).
const officeSecret = sha256(new TextEncoder().encode('legatto-test office x25519'));
const selftestSeed = sha256(new TextEncoder().encode('legatto-test selftest ed25519'));
const signingSeed = sha256(new TextEncoder().encode('legatto-test worker ed25519'));
const ipHashKey = sha256(new TextEncoder().encode('legatto-test ip hash key'));
const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
const officePublic = x25519.getPublicKey(officeSecret);

const bindings = {
  OFFICE_X25519_PUB: b64(officePublic),
  OFFICE_KID: Buffer.from(sha256(officePublic).subarray(0, 8)).toString('hex'),
  SELFTEST_ED25519_PUB: b64(ed25519.getPublicKey(selftestSeed)),
  SITE_ORIGIN: 'https://posel-test.pl',
  TURNSTILE_HOSTNAMES: 'posel-test.pl',
  TURNSTILE_ACTION: 'submit_case',
  RELEASE: '1.2.3',
  TURNSTILE_SECRET: '0x4AAAAAAA-test-secret',
  IP_HASH_KEY: b64(ipHashKey),
  SIGNING_KEY: b64(signingSeed),
  // Test-only: private halves the tests need to open/verify envelopes.
  TEST_OFFICE_SECRET: b64(officeSecret),
  TEST_SELFTEST_SEED: b64(selftestSeed),
};

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [
          cloudflareTest({
            wrangler: { configPath: './test/worker/wrangler.test.jsonc' },
            miniflare: { bindings },
          }),
        ],
        test: { name: 'worker', include: ['test/worker/**/*.test.ts'] },
      },
      {
        test: { name: 'tools', include: ['test/tools/**/*.test.ts'], environment: 'node', testTimeout: 30_000 },
      },
    ],
  },
});
