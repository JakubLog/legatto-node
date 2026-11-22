"""TOTP (RFC 4226 / RFC 6238), scrypt password hashes, ULIDs and random secrets.

Standard library only (CONTRACT §1 pkt 5). Every comparison of a secret value
goes through hmac.compare_digest.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import string
import time
import urllib.parse

# --- TOTP ---------------------------------------------------------------------
TOTP_DIGITS = 6
TOTP_STEP = 30
TOTP_WINDOW = 1  # accept codes from step-1 .. step+1
TOTP_SECRET_BYTES = 20  # 160 bits, RFC 4226 recommendation


def hotp(key: bytes, counter: int, digits: int = TOTP_DIGITS, digest: str = "sha1") -> str:
    """RFC 4226 HOTP value for `counter` (dynamic truncation, zero padded)."""
    mac = hmac.new(key, counter.to_bytes(8, "big"), digest).digest()
    offset = mac[-1] & 0x0F
    value = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def totp_step(now: float, step: int = TOTP_STEP) -> int:
    return int(now) // step


def totp(key: bytes, now: float, digits: int = TOTP_DIGITS, digest: str = "sha1", step: int = TOTP_STEP) -> str:
    """RFC 6238 TOTP value at unix time `now`."""
    return hotp(key, totp_step(now, step), digits, digest)


def totp_match(key: bytes, code: str, now: float, window: int = TOTP_WINDOW) -> int | None:
    """Return the time step whose code equals `code`, or None.

    All candidate steps are compared (no early exit) so the running time does
    not reveal which step matched.
    """
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{%d}" % TOTP_DIGITS, code):
        return None
    current = totp_step(now)
    matched = None
    for candidate in range(current - window, current + window + 1):
        if hmac.compare_digest(hotp(key, candidate).encode(), code.encode()) and matched is None:
            matched = candidate
    return matched


def new_totp_secret() -> str:
    """Random TOTP seed as unpadded RFC 4648 base32 (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")


def decode_totp_secret(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z2-7]{16,128}", cleaned):
        raise ValueError("invalid base32 TOTP secret")
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def otpauth_uri(secret: str, login: str, issuer: str) -> str:
    """Key URI understood by authenticator apps (Google Authenticator format)."""
    label = urllib.parse.quote(f"{issuer}:{login}", safe="")
    query = urllib.parse.urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": TOTP_DIGITS, "period": TOTP_STEP},
        quote_via=urllib.parse.quote,
    )
    return f"otpauth://totp/{label}?{query}"


# --- scrypt password hashes -----------------------------------------------------
# Format: scrypt$<n>$<r>$<p>$<salt_b64>$<hash_b64> (standard base64 with padding).
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
SCRYPT_DKLEN = 64
SCRYPT_N_MAX = 2 ** 20  # refuse hashes that would make verification a DoS
SCRYPT_MAXMEM = 1024 * 1024 * 1024 + 64 * 1024 * 1024
_SCRYPT_RE = re.compile(r"scrypt\$([0-9]{1,8})\$([0-9]{1,2})\$([0-9]{1,2})\$([A-Za-z0-9+/=]{4,128})\$([A-Za-z0-9+/=]{4,256})")


class WeakHash(ValueError):
    """The hash string is well formed but weaker than the contract minimum."""


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def scrypt_hash(password: str, *, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P,
                salt: bytes | None = None) -> str:
    salt = salt if salt is not None else secrets.token_bytes(SCRYPT_SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=SCRYPT_DKLEN,
                            maxmem=SCRYPT_MAXMEM)
    return "scrypt${}${}${}${}${}".format(n, r, p, base64.b64encode(salt).decode("ascii"),
                                         base64.b64encode(digest).decode("ascii"))


def parse_scrypt(value: str) -> tuple[int, int, int, bytes, bytes]:
    """Parse and check a hash string against the contract minimum.

    Raises ValueError for malformed strings and WeakHash for parameters below
    n >= 2^15, r = 8, p = 1, salt >= 16 B, hash = 64 B (CONTRACT §4.3).
    """
    if not isinstance(value, str):
        raise ValueError("scrypt hash must be a string")
    match = _SCRYPT_RE.fullmatch(value)
    if not match:
        raise ValueError("malformed scrypt hash")
    n, r, p = int(match.group(1)), int(match.group(2)), int(match.group(3))
    try:
        salt = _b64decode(match.group(4))
        digest = _b64decode(match.group(5))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("malformed base64 in scrypt hash") from exc
    if n < 2 or n & (n - 1):
        raise ValueError("scrypt n must be a power of two")
    if n > SCRYPT_N_MAX:
        raise ValueError("scrypt n too large")
    if n < SCRYPT_N or r != SCRYPT_R or p != SCRYPT_P or len(salt) < SCRYPT_SALT_BYTES or len(digest) != SCRYPT_DKLEN:
        raise WeakHash("scrypt parameters below the contract minimum")
    return n, r, p, salt, digest


def scrypt_verify(password: str, stored: str) -> bool:
    """Constant-time check of `password` against a stored hash string."""
    try:
        n, r, p, salt, expected = parse_scrypt(stored)
    except ValueError:
        return False
    candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected),
                               maxmem=SCRYPT_MAXMEM)
    return hmac.compare_digest(candidate, expected)


# A hash of a random password, verified when the login does not exist so that
# unknown and known logins cost the same scrypt work.
_DUMMY_HASH: list[str] = []


def dummy_hash() -> str:
    if not _DUMMY_HASH:
        _DUMMY_HASH.append(scrypt_hash(secrets.token_urlsafe(24)))
    return _DUMMY_HASH[0]


# --- ULID -------------------------------------------------------------------------
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ULID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")


def new_ulid(now: float | None = None) -> str:
    millis = int((time.time() if now is None else now) * 1000)
    value = (millis << 80) | int.from_bytes(secrets.token_bytes(10), "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def is_ulid(value: object) -> bool:
    return isinstance(value, str) and ULID_RE.fullmatch(value) is not None


# --- Random secrets for people -----------------------------------------------------
# Lower-case letters and digits without the look-alikes 0/o/1/l/i.
_READABLE = "".join(c for c in string.ascii_lowercase + string.digits if c not in "0o1li")


def new_password(groups: int = 5, size: int = 5) -> str:
    """Readable random password: 5 groups of 5 characters (about 124 bits)."""
    return "-".join("".join(secrets.choice(_READABLE) for _ in range(size)) for _ in range(groups))


def new_setup_code() -> str:
    """One-time setup code, 4 groups of 4 Crockford base32 chars (80 bits)."""
    raw = "".join(secrets.choice(_CROCKFORD) for _ in range(16))
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def normalize_setup_code(value: str) -> str:
    """Accept lower case, spaces and the usual Crockford look-alikes."""
    cleaned = value.upper().replace(" ", "").replace("-", "")
    cleaned = cleaned.replace("O", "0").replace("I", "1").replace("L", "1")
    return "-".join(cleaned[i:i + 4] for i in range(0, len(cleaned), 4))
