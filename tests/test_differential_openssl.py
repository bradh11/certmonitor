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

from certmonitor import certinfo, signatures
from tests.support import pss_params

pytestmark = pytest.mark.differential

KEYS_PER_TYPE = int(os.environ.get("CERTMONITOR_DIFFERENTIAL_KEYS", "4"))
MESSAGES_PER_KEY = int(os.environ.get("CERTMONITOR_DIFFERENTIAL_MESSAGES", "8"))
WRONG_HASH = {"sha256": "sha384", "sha384": "sha512", "sha512": "sha256"}
# (genpkey options, hash name, algorithm OID, extra -sigopt/-verify options).
# A `None` hash name means PureEdDSA, which hashes the whole message itself
# (RFC 8032 §4) and so is signed and verified raw rather than over a digest.
SCHEMES = {
    "rsa2048-sha256": (
        ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "sha256",
        "1.2.840.113549.1.1.11",
        [],
    ),
    "rsa2048-sha512": (
        ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "sha512",
        "1.2.840.113549.1.1.13",
        [],
    ),
    "rsa3072-sha384": (
        ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
        "sha384",
        "1.2.840.113549.1.1.12",
        [],
    ),
    "p256-sha256": (
        ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        "sha256",
        "1.2.840.10045.4.3.2",
        [],
    ),
    "p256-sha512": (
        ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        "sha512",
        "1.2.840.10045.4.3.4",
        [],
    ),
    "p384-sha384": (
        ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
        "sha384",
        "1.2.840.10045.4.3.3",
        [],
    ),
    "p521-sha512": (
        ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"],
        "sha512",
        "1.2.840.10045.4.3.4",
        [],
    ),
    "rsa2048-pss-sha256": (
        ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "sha256",
        "1.2.840.113549.1.1.10",
        ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest"],
    ),
    "ed25519": (["-algorithm", "ED25519"], None, "1.3.101.112", []),
    "ed448": (["-algorithm", "ED448"], None, "1.3.101.113", []),
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
        self,
        openssl: str,
        directory: Path,
        genpkey: list[str],
        hash_name: str | None,
        sign_options: list[str] | None = None,
    ):
        self.openssl = openssl
        self.directory = directory
        self.hash_name = hash_name
        # `dgst` cannot sign or verify with an Edwards key at all, so raw
        # schemes go through `pkeyutl -rawin`, which hands the whole
        # message to the algorithm instead of a digest.
        self.raw = hash_name is None
        self.sign_options = sign_options or []
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
        if self.raw:
            self._run(
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(self.key),
                "-in",
                str(msg),
                "-out",
                str(sig),
            )
        else:
            self._run(
                "dgst",
                f"-{self.hash_name}",
                "-sign",
                str(self.key),
                *self.sign_options,
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
        if self.raw:
            command = [
                self.openssl,
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(self.spki_path),
                "-keyform",
                "DER",
                "-in",
                str(msg),
                "-sigfile",
                str(sig),
            ]
        else:
            command = [
                self.openssl,
                "dgst",
                f"-{self.hash_name}",
                "-verify",
                str(self.spki_path),
                *self.sign_options,
                "-signature",
                str(sig),
                str(msg),
            ]
        done = subprocess.run(command, capture_output=True)
        return done.returncode == 0


def ours_verifies(
    algorithm: str, hash_name: str | None, message: bytes, signature: bytes, spki: bytes
) -> bool:
    if algorithm in (signatures.ED25519, signatures.ED448):
        outcome, _ = signatures.verify(spki, algorithm, None, message, signature)
        return outcome == signatures.VERIFIED
    if algorithm == signatures.RSASSA_PSS:
        params = pss_params(hash_name, hash_name, hashlib.new(hash_name).digest_size)
        outcome, _ = signatures.verify(spki, algorithm, params, message, signature)
        return outcome == signatures.VERIFIED
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
    genpkey, hash_name, algorithm, sign_options = SCHEMES[scheme]
    for key_index in range(KEYS_PER_TYPE):
        signer = Signer(
            openssl,
            tmp_path / f"{scheme}-{key_index}",
            genpkey,
            hash_name,
            sign_options,
        )
        for _ in range(MESSAGES_PER_KEY):
            # `pkeyutl -rawin` refuses a zero-length input file, so raw
            # schemes get at least one message byte.
            message = random_.randbytes(random_.randrange(int(signer.raw), 300))
            signature = signer.sign(message)
            context = f"seed={seed} scheme={scheme} key={key_index}"
            assert ours_verifies(
                algorithm, hash_name, message, signature, signer.spki
            ), f"{context}: rejected a signature OpenSSL produced"
            # The right signature checked under the wrong hash must fail too.
            # RSASSA-PSS keeps one OID across hashes, so the wrong-hash check
            # only needs to change `hash_name`; PKCS#1 v1.5 and ECDSA each
            # have a distinct OID per hash, so the matching OID is looked up.
            # PureEdDSA fixes its hash in RFC 8032, so there is none to get
            # wrong and nothing to check.
            if hash_name is not None:
                wrong = WRONG_HASH[hash_name]
                if algorithm == signatures.RSASSA_PSS:
                    wrong_algorithm = algorithm
                else:
                    family = algorithm.rsplit(".", 1)[0]
                    wrong_algorithm = next(
                        oid
                        for _, (_, h, oid, _) in SCHEMES.items()
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
