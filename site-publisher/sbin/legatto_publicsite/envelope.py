"""Outer check of envelope v1 ("LGF1") before anything reaches the process
that holds the office X25519 key (R9 defence in depth).

Layout (worker/src/envelope.ts, agreed with legatto-app public-submission):
  0 magic "LGF1" | 4 version=1 | 5 kind (1 submission, 2 selftest)
  6 office_kid[8] | 14 signer_kid[8] | 22 received_at u64be ms
  30 sig[64] = Ed25519("legatto-forms-v1\\0" || bytes[0:30] || meta_ct || ct)
  94 meta_ct[560] | 654 ct[24624]           total 25 278 bytes

The gate never decrypts. It needs only public keys: the office key ids that
the processor can open and the Worker signing keys in signers.d.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from pathlib import Path

from . import ed25519

MAGIC = b"LGF1"
VERSION = 1
KINDS = {1: "submission", 2: "selftest"}
SIGNED_HEADER_SIZE = 30
HEADER_SIZE = 94
META_CT_SIZE = 560
FORM_CT_SIZE = 24624
ENVELOPE_SIZE = HEADER_SIZE + META_CT_SIZE + FORM_CT_SIZE
SIGNATURE_DOMAIN = b"legatto-forms-v1\x00"
MAX_AGE_MS = 16 * 24 * 3600 * 1000
MAX_FUTURE_MS = 10 * 60 * 1000


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str  # "ok" or a quarantine reason shared with the app processor
    kind: str | None = None
    digest: str | None = None  # sha256 of the whole envelope (replay ledger key)
    received_at_ms: int | None = None


def load_signers(directory: Path) -> dict[bytes, bytes]:
    """signers.d/*.pub: base64 of the raw 32-byte Worker Ed25519 key -> {kid: pub}."""
    signers: dict[bytes, bytes] = {}
    if not directory.is_dir():
        return signers
    for entry in sorted(directory.glob("*.pub")):
        try:
            pub = base64.b64decode(entry.read_text(encoding="ascii").strip(), validate=True)
        except (binascii.Error, UnicodeDecodeError):
            continue
        if len(pub) == 32:
            signers[ed25519.key_id(pub)] = pub
    return signers


def check(body: bytes, office_kids: set[bytes], signers: dict[bytes, bytes], now_ms: int) -> Verdict:
    digest = hashlib.sha256(body).hexdigest()
    if len(body) != ENVELOPE_SIZE:
        return Verdict(False, "bad_size", digest=digest)
    if body[0:4] != MAGIC:
        return Verdict(False, "bad_magic", digest=digest)
    if body[4] != VERSION or body[5] not in KINDS:
        return Verdict(False, "bad_magic", digest=digest)
    kind = KINDS[body[5]]
    received_at = int.from_bytes(body[22:30], "big")
    signer = signers.get(body[14:22])
    if signer is None:
        return Verdict(False, "unknown_signer", kind, digest, received_at)
    signed = SIGNATURE_DOMAIN + body[0:SIGNED_HEADER_SIZE] + body[HEADER_SIZE:]
    if not ed25519.verify(signer, signed, body[SIGNED_HEADER_SIZE:HEADER_SIZE]):
        return Verdict(False, "bad_signature", kind, digest, received_at)
    if body[6:14] not in office_kids:
        return Verdict(False, "unknown_office_kid", kind, digest, received_at)
    if received_at < now_ms - MAX_AGE_MS or received_at > now_ms + MAX_FUTURE_MS:
        return Verdict(False, "expired", kind, digest, received_at)
    return Verdict(True, "ok", kind, digest, received_at)
