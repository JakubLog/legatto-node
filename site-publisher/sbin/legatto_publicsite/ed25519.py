"""Ed25519 (RFC 8032, PureEdDSA) and X25519 public keys, Python stdlib only.

Used on the office server for:
  * verifying the Worker signature on every queued envelope (intake gate),
  * generating the Worker signing key and the self-test key (cf_bootstrap).

Verification follows RFC 8032 section 5.1.7 with the strict checks of
section 5.1.7 step 1 (canonical S < L, canonical point encodings). Timing is
not constant; only public data (signatures, public keys) and freshly
generated keys are processed here, never a long-lived secret under attacker
influence.
"""

from __future__ import annotations

import hashlib
import os

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# Extended homogeneous coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z.
_GY = 4 * pow(5, P - 2, P) % P


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GX = _recover_x(_GY, 0)
assert _GX is not None
G = (_GX, _GY, 1, _GX * _GY % P)
IDENTITY = (0, 1, 1, 0)


def _add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    d = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> bool:
    return (p1[0] * p2[2] - p2[0] * p1[2]) % P == 0 and (p1[1] * p2[2] - p2[1] * p1[2]) % P == 0


def _compress(point: tuple[int, int, int, int]) -> bytes:
    zinv = pow(point[2], P - 2, P)
    x = point[0] * zinv % P
    y = point[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _sha512_int(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed: bytes) -> bytes:
    scalar, _prefix = _expand_seed(seed)
    return _compress(_mul(scalar, G))


def sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _expand_seed(seed)
    pub = _compress(_mul(scalar, G))
    r = _sha512_int(prefix, message) % L
    big_r = _compress(_mul(r, G))
    k = _sha512_int(big_r, pub, message) % L
    s = (r + k * scalar) % L
    return big_r + int.to_bytes(s, 32, "little")


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    if len(pub) != 32 or len(signature) != 64:
        return False
    point_a = _decompress(pub)
    point_r = _decompress(signature[:32])
    if point_a is None or point_r is None:
        return False
    # Canonical encodings only (reject y >= p re-encodings).
    if _compress(point_a) != pub or _compress(point_r) != signature[:32]:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = _sha512_int(signature[:32], pub, message) % L
    return _equal(_mul(s, G), _add(point_r, _mul(k, point_a)))


def generate_seed() -> bytes:
    return os.urandom(32)


# --- X25519 (RFC 7748) ----------------------------------------------------------

_A24 = 121665


def x25519(scalar: bytes, u_bytes: bytes) -> bytes:
    if len(scalar) != 32 or len(u_bytes) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (k_int >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + _A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return int.to_bytes(x2 * pow(z2, P - 2, P) % P, 32, "little")


def x25519_public_key(secret: bytes) -> bytes:
    return x25519(secret, int.to_bytes(9, 32, "little"))


def key_id(public: bytes) -> bytes:
    """Key identifier shared with the Worker and the app: sha256(pub)[0:8]."""
    return hashlib.sha256(public).digest()[:8]
