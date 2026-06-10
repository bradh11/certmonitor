#!/usr/bin/env python3
"""Regenerate the ML-KEM-768 KAT encapsulation-key fixture used by the
TLS post-quantum probe (``rust_certinfo/src/tls/mlkem768_kat_ek.bin``).

The probe sends this public key as the ML-KEM half of its
X25519MLKEM768 key_share. It must be a *valid* FIPS 203 encapsulation
key (servers modulus-check it before replying), but it is opaque lattice
key material with no human-readable source form — so rather than hand-
maintain 1184 bytes of hex, we pin a published NIST known-answer-test
vector and embed it via ``include_bytes!``.

This script makes that provenance executable: it fetches the NIST ACVP
ML-KEM-keyGen-FIPS203 vectors, extracts the ML-KEM-768 ``ek`` from the
chosen test case, validates it (length + FIPS 203 coefficient bound),
and writes the binary fixture. It is a manual maintenance tool — NOT run
by the build or CI.

Usage:
    python scripts/fetch_mlkem_kat.py            # verify current fixture
    python scripts/fetch_mlkem_kat.py --write    # overwrite the fixture

Requires network access to raw.githubusercontent.com.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

# NIST ACVP-Server (https://github.com/usnistgov/ACVP-Server) keyGen vectors.
ACVP_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/"
    "gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json"
)
PARAMETER_SET = "ML-KEM-768"
TC_ID = 26  # The specific known-answer test case pinned by the fixture.
EK_LEN = 1184  # ML-KEM-768 encapsulation key length (FIPS 203 Table 2).

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "rust_certinfo"
    / "src"
    / "tls"
    / "mlkem768_kat_ek.bin"
)


def fetch_ek() -> bytes:
    """Fetch the ACVP vectors and return the pinned ML-KEM-768 ek bytes."""
    req = urllib.request.Request(ACVP_URL, headers={"User-Agent": "certmonitor-fetch"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (trusted URL)
        data = json.load(resp)

    for group in data["testGroups"]:
        if group.get("parameterSet") != PARAMETER_SET:
            continue
        for test in group["tests"]:
            if test["tcId"] == TC_ID:
                return bytes.fromhex(test["ek"])
    raise SystemExit(f"tcId {TC_ID} not found for {PARAMETER_SET} in ACVP vectors")


def validate(ek: bytes) -> None:
    """Length + FIPS 203 coefficient-bound check (mirrors the Rust test)."""
    if len(ek) != EK_LEN:
        raise SystemExit(f"ek length {len(ek)} != {EK_LEN}")
    body = ek[:1152]  # 3 packed polynomials; last 32 bytes are rho.
    coeffs: list[int] = []
    for i in range(0, len(body), 3):
        x = body[i] | (body[i + 1] << 8) | (body[i + 2] << 16)
        coeffs.append(x & 0xFFF)
        coeffs.append((x >> 12) & 0xFFF)
    if len(coeffs) != 768 or any(c >= 3329 for c in coeffs):
        raise SystemExit("ek failed the FIPS 203 coefficient bound (q = 3329)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--write",
        action="store_true",
        help="overwrite the fixture (default: verify it matches ACVP)",
    )
    args = ap.parse_args()

    ek = fetch_ek()
    validate(ek)

    if args.write:
        FIXTURE.write_bytes(ek)
        print(f"wrote {FIXTURE} ({len(ek)} bytes)")
        return 0

    current = FIXTURE.read_bytes() if FIXTURE.exists() else b""
    if current == ek:
        print(f"OK: {FIXTURE.name} matches ACVP {PARAMETER_SET} tcId {TC_ID}")
        return 0
    print(f"MISMATCH: {FIXTURE.name} differs from ACVP — run with --write to update")
    return 1


if __name__ == "__main__":
    sys.exit(main())
