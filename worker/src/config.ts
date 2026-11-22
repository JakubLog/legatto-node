import { ed25519 } from '@noble/curves/ed25519.js';
import { fromBase64, keyId, toHex } from './crypto';

/** Bindings, vars and secrets of the legatto-forms Worker (set by legatto-worker-deploy). */
export interface Env {
  FORMS: Queue;
  RL_IP: RateLimit;
  RL_GLOBAL: RateLimit;
  RL_SELFTEST: RateLimit;
  // vars (plain_text)
  OFFICE_X25519_PUB: string;
  OFFICE_KID: string;
  SELFTEST_ED25519_PUB: string;
  SITE_ORIGIN: string;
  TURNSTILE_HOSTNAMES: string;
  TURNSTILE_ACTION: string;
  RELEASE: string;
  // secrets (secret_text)
  TURNSTILE_SECRET: string;
  IP_HASH_KEY: string;
  SIGNING_KEY: string;
}

export interface Config {
  officePublic: Uint8Array;
  officeKid: Uint8Array;
  officeKidHex: string;
  selftestPublic: Uint8Array;
  selftestKidHex: string;
  signerSeed: Uint8Array;
  signerKid: Uint8Array;
  signerKidHex: string;
  siteOrigin: string;
  turnstileHostnames: string[];
  turnstileAction: string;
  turnstileSecret: string;
  ipHashKey: Uint8Array;
  release: string;
}

export class ConfigError extends Error {}

const ORIGIN_RE = /^https:\/\/[a-z0-9.-]+$/;
const HOST_RE = /^[a-z0-9.-]+$/;
const RELEASE_RE = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/;

function decodeKey(name: string, value: string | undefined, size: number): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(value ?? '');
  } catch {
    throw new ConfigError(`${name} is not base64`);
  }
  if (bytes.length !== size) throw new ConfigError(`${name} must be ${size} bytes`);
  return bytes;
}

let cached: { env: Env; config: Config } | undefined;

/** Validates the Worker environment once per isolate; throws ConfigError when incomplete. */
export function loadConfig(env: Env): Config {
  if (cached && cached.env === env) return cached.config;
  const officePublic = decodeKey('OFFICE_X25519_PUB', env.OFFICE_X25519_PUB, 32);
  const officeKid = keyId(officePublic);
  if (toHex(officeKid) !== env.OFFICE_KID) throw new ConfigError('OFFICE_KID does not match OFFICE_X25519_PUB');
  const selftestPublic = decodeKey('SELFTEST_ED25519_PUB', env.SELFTEST_ED25519_PUB, 32);
  const signerSeed = decodeKey('SIGNING_KEY', env.SIGNING_KEY, 32);
  const signerKid = keyId(ed25519.getPublicKey(signerSeed));
  const ipHashKey = decodeKey('IP_HASH_KEY', env.IP_HASH_KEY, 32);
  if (!ORIGIN_RE.test(env.SITE_ORIGIN ?? '')) throw new ConfigError('SITE_ORIGIN must be https://<host>');
  const turnstileHostnames = (env.TURNSTILE_HOSTNAMES ?? '').split(',').map((h) => h.trim()).filter(Boolean);
  if (turnstileHostnames.length === 0 || !turnstileHostnames.every((h) => HOST_RE.test(h))) {
    throw new ConfigError('TURNSTILE_HOSTNAMES must list host names');
  }
  if (!/^[a-z0-9_-]{1,32}$/.test(env.TURNSTILE_ACTION ?? '')) throw new ConfigError('TURNSTILE_ACTION is invalid');
  if (!env.TURNSTILE_SECRET) throw new ConfigError('TURNSTILE_SECRET is missing');
  if (!RELEASE_RE.test(env.RELEASE ?? '')) throw new ConfigError('RELEASE is not a version');
  const config: Config = {
    officePublic,
    officeKid,
    officeKidHex: env.OFFICE_KID,
    selftestPublic,
    selftestKidHex: toHex(keyId(selftestPublic)),
    signerSeed,
    signerKid,
    signerKidHex: toHex(signerKid),
    siteOrigin: env.SITE_ORIGIN,
    turnstileHostnames,
    turnstileAction: env.TURNSTILE_ACTION,
    turnstileSecret: env.TURNSTILE_SECRET,
    ipHashKey,
    release: env.RELEASE,
  };
  cached = { env, config };
  return config;
}
