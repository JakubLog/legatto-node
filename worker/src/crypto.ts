// Cryptographic primitives shared by the Worker and the server-side tools.
//
// sealBox/openBox implement libsodium crypto_box_seal / crypto_box_seal_open:
//   epk, esk = X25519 keypair (ephemeral)
//   nonce    = BLAKE2b-192(epk || recipient_pk)
//   k        = HSalsa20(X25519(esk, recipient_pk), 0^16)        (crypto_box_beforenm)
//   output   = epk || XSalsa20-Poly1305(k, nonce, m)            (tag first, 48 B overhead)
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hsalsa, secretbox } from '@noble/ciphers/salsa.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const SEAL_OVERHEAD = 48;

// "expand 32-byte k" as little-endian words.
const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function u8ToU32le(bytes: Uint8Array): Uint32Array {
  const out = new Uint32Array(bytes.length / 4);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < out.length; i++) out[i] = view.getUint32(i * 4, true);
  return out;
}

function u32leToU8(words: Uint32Array): Uint8Array {
  const out = new Uint8Array(words.length * 4);
  const view = new DataView(out.buffer);
  for (let i = 0; i < words.length; i++) view.setUint32(i * 4, words[i], true);
  return out;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function boxBeforenm(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(secretKey, publicKey);
  const out = new Uint32Array(8);
  hsalsa(SIGMA, u8ToU32le(shared), new Uint32Array(4), out);
  return u32leToU8(out);
}

function sealNonce(ephemeralPublic: Uint8Array, recipientPublic: Uint8Array): Uint8Array {
  return blake2b(concatBytes(ephemeralPublic, recipientPublic), { dkLen: 24 });
}

export function sealBox(message: Uint8Array, recipientPublic: Uint8Array): Uint8Array {
  if (recipientPublic.length !== 32) throw new Error('recipient public key must be 32 bytes');
  const esk = x25519.utils.randomSecretKey();
  const epk = x25519.getPublicKey(esk);
  const key = boxBeforenm(recipientPublic, esk);
  const boxed = secretbox(key, sealNonce(epk, recipientPublic)).seal(message);
  esk.fill(0);
  key.fill(0);
  return concatBytes(epk, boxed);
}

export function openBox(sealed: Uint8Array, recipientSecret: Uint8Array): Uint8Array {
  if (sealed.length < SEAL_OVERHEAD) throw new Error('sealed box too short');
  const recipientPublic = x25519.getPublicKey(recipientSecret);
  const epk = sealed.subarray(0, 32);
  const key = boxBeforenm(epk, recipientSecret);
  try {
    return secretbox(key, sealNonce(epk, recipientPublic)).open(sealed.subarray(32));
  } finally {
    key.fill(0);
  }
}

export function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/** Key identifier: first 8 bytes of SHA-256 over the raw 32-byte public key. */
export function keyId(publicKey: Uint8Array): Uint8Array {
  return sha256(publicKey).subarray(0, 8);
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(text: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(text)) throw new Error('invalid hex');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Strict standard base64 (RFC 4648 §4, padded); throws on anything else. */
export function fromBase64(text: string): Uint8Array {
  if (!B64_RE.test(text)) throw new Error('invalid base64');
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

/** Constant-time comparison of equal-length byte strings. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
