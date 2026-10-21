#!/usr/bin/env python3
"""Write the small-multiples tables behind `certinfo.ec_small_scalar`.

For each of P-256, P-384, and P-521, computes [k]G for k in 1..=4096 and
writes one 10-byte entry per multiple: the low 8 bytes of the affine x
coordinate, then k, both big-endian, sorted by those 8 bytes. The Rust code
binary-searches these files, so checking a key against the first 4096
multiples is a lookup rather than 4096 point additions.

The arithmetic here is deliberately separate from the Rust crate's (affine
coordinates, Python integers, curve constants typed from FIPS 186-4 D.1.2).
The Rust test `every_small_multiple_of_the_generator_is_found` recomputes
every entry with the crate's own arithmetic, so the two have to agree.

Run it from the repo root after changing `TABLE_LEN`:

    uv run python scripts/generate_small_multiples.py
"""

from __future__ import annotations

from pathlib import Path

TABLE_LEN = 4096
OUT = (
    Path(__file__).resolve().parent.parent
    / "rust_certinfo/src/crypto/ecdsa/small_multiples"
)

# (name, p, gx, gy). All three curves have a = -3; b is not needed to add points.
CURVES = [
    (
        "p256",
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    ),
    (
        "p384",
        int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
            "FFFFFFFF0000000000000000FFFFFFFF",
            16,
        ),
        int(
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
            "5502F25DBF55296C3A545E3872760AB7",
            16,
        ),
        int(
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
            "0A60B1CE1D7E819D7A431D7C90EA0E5F",
            16,
        ),
    ),
    (
        "p521",
        (1 << 521) - 1,
        int(
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
            "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5"
            "BD66",
            16,
        ),
        int(
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
            "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD1"
            "6650",
            16,
        ),
    ),
]


def add(p: int, a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    """Affine point addition on y^2 = x^3 - 3x + b (never the point at infinity here)."""
    (x1, y1), (x2, y2) = a, b
    if a == b:
        slope = (3 * x1 * x1 - 3) * pow(2 * y1, -1, p) % p
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (slope * slope - x1 - x2) % p
    return x3, (slope * (x1 - x3) - y1) % p


def table(p: int, g: tuple[int, int]) -> bytes:
    entries = []
    point = g
    for k in range(1, TABLE_LEN + 1):
        entries.append(((point[0] & (2**64 - 1)).to_bytes(8, "big"), k))
        point = add(p, point, g)
    entries.sort()
    if any(a[0] == b[0] for a, b in zip(entries, entries[1:])):
        raise SystemExit("two multiples share their low 8 bytes; widen the entry")
    return b"".join(prefix + k.to_bytes(2, "big") for prefix, k in entries)


def main() -> None:
    for name, p, gx, gy in CURVES:
        path = OUT / f"{name}.bin"
        path.write_bytes(table(p, (gx, gy)))
        print(f"wrote {path.relative_to(OUT.parents[4])} ({TABLE_LEN} entries)")


if __name__ == "__main__":
    main()
