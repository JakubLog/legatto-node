// Envelope v1 ("LGF1") written by the Worker into the Cloudflare queue.
// Format owner: legatto-app packages/public-submission (interface agreed with
// the publicsite lane); the intake gate (legatto-intake, Python) and the app
// intake process parse exactly this layout.
//
//   offset size  field
//   0      4     magic "LGF1"
//   4      1     version = 1
//   5      1     kind (1 submission, 2 selftest)
//   6      8     office_kid  = sha256(office_x25519_pub)[0..8]
//   14     8     signer_kid  = sha256(worker_ed25519_pub)[0..8]
//   22     8     received_at = u64be milliseconds since epoch (Worker clock)
//   30     64    sig = Ed25519(SIGNING_KEY, "legatto-forms-v1\0" || bytes[0..30] || meta_ct || ct)
//   94     560   meta_ct = crypto_box_seal(pad(meta JSON, 512), office_x25519_pub)
//   654    24624 ct = crypto_box_seal(pad(form JSON, 24576), office_x25519_pub)  (sealed in the browser, D15b)
//
// pad(json, n) = u32be(len(utf8(json))) || utf8(json) || 0x00 ... up to n bytes.
import { ed25519 } from '@noble/curves/ed25519.js';
import { SEAL_OVERHEAD, concatBytes, sealBox } from './crypto';

export const MAGIC = new Uint8Array([0x4c, 0x47, 0x46, 0x31]); // "LGF1"
export const VERSION = 1;
export const KIND_SUBMISSION = 1;
export const KIND_SELFTEST = 2;
export const FORM_PLAINTEXT_SIZE = 24576;
export const FORM_CT_SIZE = FORM_PLAINTEXT_SIZE + SEAL_OVERHEAD; // 24624
export const META_PLAINTEXT_SIZE = 512;
export const META_CT_SIZE = META_PLAINTEXT_SIZE + SEAL_OVERHEAD; // 560
export const HEADER_SIZE = 94;
export const SIGNED_HEADER_SIZE = 30;
export const ENVELOPE_SIZE = HEADER_SIZE + META_CT_SIZE + FORM_CT_SIZE; // 25278
export const SIGNATURE_DOMAIN = new TextEncoder().encode('legatto-forms-v1\0');

export interface Meta {
  v: 1;
  ip_hash: string;
  ua: string;
  turnstile_ts: string | null;
  release: string;
}

/** u32be length prefix, UTF-8 JSON, zero fill to exactly `size` bytes. */
export function pad(json: string, size: number): Uint8Array {
  const body = new TextEncoder().encode(json);
  if (body.length + 4 > size) throw new Error(`plaintext ${body.length} B does not fit ${size} B`);
  const out = new Uint8Array(size);
  new DataView(out.buffer).setUint32(0, body.length, false);
  out.set(body, 4);
  return out;
}

export interface EnvelopeInput {
  kind: typeof KIND_SUBMISSION | typeof KIND_SELFTEST;
  officePublic: Uint8Array;
  officeKid: Uint8Array;
  signerSeed: Uint8Array;
  signerKid: Uint8Array;
  receivedAtMs: number;
  meta: Meta;
  formCt: Uint8Array;
}

export function buildEnvelope(input: EnvelopeInput): Uint8Array {
  if (input.formCt.length !== FORM_CT_SIZE) throw new Error('form ciphertext has the wrong size');
  if (input.officeKid.length !== 8 || input.signerKid.length !== 8) throw new Error('key ids must be 8 bytes');
  const header = new Uint8Array(SIGNED_HEADER_SIZE);
  header.set(MAGIC, 0);
  header[4] = VERSION;
  header[5] = input.kind;
  header.set(input.officeKid, 6);
  header.set(input.signerKid, 14);
  new DataView(header.buffer).setBigUint64(22, BigInt(input.receivedAtMs), false);
  const metaCt = sealBox(pad(JSON.stringify(input.meta), META_PLAINTEXT_SIZE), input.officePublic);
  const signature = ed25519.sign(concatBytes(SIGNATURE_DOMAIN, header, metaCt, input.formCt), input.signerSeed);
  const envelope = concatBytes(header, signature, metaCt, input.formCt);
  if (envelope.length !== ENVELOPE_SIZE) throw new Error('envelope size mismatch');
  return envelope;
}
