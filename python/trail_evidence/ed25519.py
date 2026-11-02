"""Ed25519 (RFC 8032) in pure Python, for verification in tools and tests.

This is a straightforward implementation with extended twisted Edwards
coordinates. It is deterministic and correct against the RFC 8032 vectors,
but it is neither fast nor constant-time. Do not use it to sign in
production; verification of untrusted journals is its intended job.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple  # (X, Y, Z, T) extended coordinates


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _add(p: Point, q: Point) -> Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, p: Point) -> Point:
    q: Point = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _decompress(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _compress(p: Point) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _equal(p: Point, q: Point) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


_BY = 4 * _inv(5) % P
_BX = pow((_BY * _BY - 1) * _inv(D * _BY * _BY + 1) % P, (P + 3) // 8, P)
if (_BX * _BX - (_BY * _BY - 1) * _inv(D * _BY * _BY + 1)) % P:
    _BX = _BX * SQRT_M1 % P
if _BX & 1:
    _BX = P - _BX
B: Point = (_BX, _BY, 1, _BX * _BY % P)


def _clamp(h: bytes) -> int:
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def public_key(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a = _clamp(hashlib.sha512(seed).digest())
    return _compress(_mul(a, B))


def sign(seed: bytes, message: bytes) -> bytes:
    """Return the 64-byte signature of message under seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h)
    prefix = h[32:]
    pub = _compress(_mul(a, B))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    big_r = _compress(_mul(r, B))
    k = int.from_bytes(hashlib.sha512(big_r + pub + message).digest(), "little") % L
    s = (r + k * a) % L
    return big_r + s.to_bytes(32, "little")


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    """Return True when signature is valid for message under pub."""
    if len(pub) != 32 or len(signature) != 64:
        return False
    a = _decompress(pub)
    r = _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + pub + message).digest(), "little") % L
    return _equal(_mul(s, B), _add(r, _mul(k, a)))
