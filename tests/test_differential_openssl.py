"""Differential check of the in-house signature verifier against OpenSSL.

OpenSSL signs random messages with fresh keys; CertMonitor must accept
every one. Then each signature or message is damaged in a random way, and
CertMonitor must reject it, and must never accept an input that OpenSSL
rejects. CertMonitor may be stricter: OpenSSL's CLI tolerates a trailing
byte on an RSA signature, which RFC 8017 says to refuse, so the check is
one-sided on purpose. Random inputs are evidence the fixed vectors cannot
give on their own.

The run takes well under a minute, so it is part of the normal suite. Set
`CERTMONITOR_DIFFERENTIAL_SEED` to replay a run, and the `_KEYS` and
`_MESSAGES` variables to make it longer (`make differential`).
"""

from __future__ import annotations

import hashlib
import os
import random
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from certmonitor import certinfo

pytestmark = pytest.mark.differential

KEYS_PER_TYPE = int(os.environ.get("CERTMONITOR_DIFFERENTIAL_KEYS", "4"))
MESSAGES_PER_KEY = int(os.environ.get("CERTMONITOR_DIFFERENTIAL_MESSAGES", "8"))
WRONG_HASH = {"sha256": "sha384", "sha384": "sha512", "sha512": "sha256"}
SCHEMES = {
    "rsa2048-sha256": (
        ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "sha256",
        "1.2.840.113549.1.1.11",
    ),
    "rsa2048-sha512": (
        ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "sha512",
        "1.2.840.113549.1.1.13",
    ),
    "rsa3072-sha384": (
        ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
        "sha384",
        "1.2.840.113549.1.1.12",
    ),
    "p256-sha256": (
        ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        "sha256",
        "1.2.840.10045.4.3.2",
    ),
    "p256-sha512": (
        ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        "sha512",
        "1.2.840.10045.4.3.4",
    ),
    "p384-sha384": (
        ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
        "sha384",
        "1.2.840.10045.4.3.3",
    ),
}


@pytest.fixture(scope="module")
def openssl():
    path = shutil.which("openssl")
    if path is None:
        pytest.skip("OpenSSL CLI required")
    return path


@pytest.fixture(scope="module")
def rng():
    seed = int(os.environ.get("CERTMONITOR_DIFFERENTIAL_SEED", str(int(time.time()))))
    print(f"\nCERTMONITOR_DIFFERENTIAL_SEED={seed}")
    return random.Random(seed), seed


class Signer:
    """One OpenSSL key pair and the commands to sign and verify with it."""

    def __init__(
        self, openssl: str, directory: Path, genpkey: list[str], hash_name: str
    ):
        self.openssl = openssl
        self.directory = directory
        self.hash_name = hash_name
        directory.mkdir(parents=True, exist_ok=True)
        self.key = directory / "key.pem"
        self.spki_path = directory / "spki.der"
        self._run("genpkey", *genpkey, "-out", str(self.key))
        self._run(
            "pkey",
            "-in",
            str(self.key),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(self.spki_path),
        )
        self.spki = self.spki_path.read_bytes()

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([self.openssl, *args], check=True, capture_output=True)

    def sign(self, message: bytes) -> bytes:
        msg = self.directory / "msg"
        sig = self.directory / "sig"
        msg.write_bytes(message)
        self._run(
            "dgst",
            f"-{self.hash_name}",
            "-sign",
            str(self.key),
            "-out",
            str(sig),
            str(msg),
        )
        return sig.read_bytes()

    def openssl_verifies(self, message: bytes, signature: bytes) -> bool:
        msg = self.directory / "vmsg"
        sig = self.directory / "vsig"
        msg.write_bytes(message)
        sig.write_bytes(signature)
        done = subprocess.run(
            [
                self.openssl,
                "dgst",
                f"-{self.hash_name}",
                "-verify",
                str(self.spki_path),
                "-signature",
                str(sig),
                str(msg),
            ],
            capture_output=True,
        )
        return done.returncode == 0


def ours_verifies(
    algorithm: str, hash_name: str, message: bytes, signature: bytes, spki: bytes
) -> bool:
    digest = hashlib.new(hash_name, message).digest()
    try:
        return certinfo.verify_signature(algorithm, digest, signature, spki)
    except ValueError:
        return False


def swap_ecdsa_integers(signature: bytes) -> bytes | None:
    """Swap r and s inside a DER ECDSA signature, or `None` if it is not one."""
    if len(signature) < 8 or signature[0] != 0x30 or signature[2] != 0x02:
        return None
    r_len = signature[3]
    r = signature[2 : 4 + r_len]
    s = signature[4 + r_len :]
    if not s or s[0] != 0x02:
        return None
    return signature[:2] + s + r


def damage(
    random_: random.Random, signature: bytes, message: bytes
) -> tuple[str, bytes, bytes]:
    """One random mutation of the signature or the message."""
    choice = random_.randrange(6)
    if choice == 4:
        swapped = swap_ecdsa_integers(signature)
        if swapped is not None and swapped != signature:
            return "swap r and s", swapped, message
        choice = 0
    if choice == 5 and len(signature) > 2:
        # Zero the low bits of every byte: a structurally plausible signature
        # that is arithmetically unrelated to the message.
        return "zero the low bits", bytes(b & 0xF0 for b in signature), message
    if choice == 0 and signature:
        index = random_.randrange(len(signature))
        flipped = bytearray(signature)
        flipped[index] ^= 1 << random_.randrange(8)
        return f"flip signature bit at {index}", bytes(flipped), message
    if choice == 1 and len(signature) > 1:
        cut = random_.randrange(1, len(signature))
        return f"truncate signature to {cut} bytes", signature[:cut], message
    if choice == 2:
        return (
            "append a byte to the signature",
            signature + bytes([random_.randrange(256)]),
            message,
        )
    if message:
        index = random_.randrange(len(message))
        flipped = bytearray(message)
        flipped[index] ^= 1 << random_.randrange(8)
        return f"flip message bit at {index}", signature, bytes(flipped)
    return "replace empty message", signature, b"x"


@pytest.mark.parametrize("scheme", sorted(SCHEMES))
def test_openssl_and_certmonitor_agree(openssl, rng, tmp_path, scheme):
    random_, seed = rng
    genpkey, hash_name, algorithm = SCHEMES[scheme]
    for key_index in range(KEYS_PER_TYPE):
        signer = Signer(openssl, tmp_path / f"{scheme}-{key_index}", genpkey, hash_name)
        for _ in range(MESSAGES_PER_KEY):
            message = random_.randbytes(random_.randrange(0, 300))
            signature = signer.sign(message)
            context = f"seed={seed} scheme={scheme} key={key_index}"
            assert ours_verifies(
                algorithm, hash_name, message, signature, signer.spki
            ), f"{context}: rejected a signature OpenSSL produced"
            # The right signature checked under the wrong hash must fail too.
            wrong = WRONG_HASH[hash_name]
            family = algorithm.rsplit(".", 1)[0]
            wrong_algorithm = next(
                oid
                for _, (_, h, oid) in SCHEMES.items()
                if h == wrong and oid.rsplit(".", 1)[0] == family
            )
            assert not ours_verifies(
                wrong_algorithm, wrong, message, signature, signer.spki
            ), f"{context}: accepted a signature under the wrong hash algorithm"
            what, bad_signature, bad_message = damage(random_, signature, message)
            mine = ours_verifies(
                algorithm, hash_name, bad_message, bad_signature, signer.spki
            )
            assert mine is False, f"{context}: accepted a damaged input after '{what}'"
            theirs = signer.openssl_verifies(bad_message, bad_signature)
            assert not (mine and not theirs), (
                f"{context}: accepted an input OpenSSL rejects after '{what}'"
            )
