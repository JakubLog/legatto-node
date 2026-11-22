// Interop vectors: envelopes produced by the Worker's own code (src/envelope.ts)
// for the Python intake gate (tests/publicsite) and the app processor.
// Written to $LEGATTO_VECTOR_OUT when set.
import { writeFileSync } from 'node:fs';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import { keyId, openBox, sealBox, toBase64, toHex } from '../../src/crypto';
import { ENVELOPE_SIZE, FORM_PLAINTEXT_SIZE, KIND_SELFTEST, KIND_SUBMISSION, buildEnvelope, pad } from '../../src/envelope';

const enc = new TextEncoder();
const officeSecret = sha256(enc.encode('vector office x25519'));
const officePublic = x25519.getPublicKey(officeSecret);
const signerSeed = sha256(enc.encode('vector worker ed25519'));
const signerPublic = ed25519.getPublicKey(signerSeed);

function vector(kind: typeof KIND_SUBMISSION | typeof KIND_SELFTEST, form: unknown) {
  const formCt = sealBox(pad(JSON.stringify(form), FORM_PLAINTEXT_SIZE), officePublic);
  const meta = { v: 1 as const, ip_hash: 'ab'.repeat(32), ua: 'vector', turnstile_ts: null, release: '1.0.0' };
  const envelope = buildEnvelope({
    kind,
    officePublic,
    officeKid: keyId(officePublic),
    signerSeed,
    signerKid: keyId(signerPublic),
    receivedAtMs: Date.now(),
    meta,
    formCt,
  });
  return { kind, form, meta, envelope_b64: toBase64(envelope), sha256: toHex(sha256(envelope)) };
}

describe('envelope interop vectors', () => {
  it('builds openable envelopes and exports them', () => {
    const vectors = {
      office_x25519_secret: toBase64(officeSecret),
      office_x25519_pub: toBase64(officePublic),
      office_kid: toHex(keyId(officePublic)),
      signer_ed25519_pub: toBase64(signerPublic),
      signer_kid: toHex(keyId(signerPublic)),
      envelopes: [
        vector(KIND_SUBMISSION, { v: 1, kind: 'submission', form: { title: 'Wektor', description: 'Zażółć gęślą jaźń' } }),
        vector(KIND_SELFTEST, { v: 1, kind: 'selftest', form: null, marker: 'c'.repeat(32), mode: 'ping' }),
      ],
    };
    for (const v of vectors.envelopes) {
      const bytes = Buffer.from(v.envelope_b64, 'base64');
      expect(bytes.length).toBe(ENVELOPE_SIZE);
      const plain = openBox(bytes.subarray(654), officeSecret);
      const len = Buffer.from(plain).readUInt32BE(0);
      expect(JSON.parse(Buffer.from(plain.subarray(4, 4 + len)).toString('utf8'))).toEqual(v.form);
    }
    const out = process.env.LEGATTO_VECTOR_OUT;
    if (out) writeFileSync(out, `${JSON.stringify(vectors, null, 1)}\n`);
  });
});
