# validators/weak_keys.py

from functools import lru_cache
from math import isqrt
from typing import Any

from certmonitor import certinfo

from ._utils import format_dn
from .base import BaseCertValidator
from .results import ValidationResult


class WeakKeysResult(ValidationResult, total=False):
    """Result shape for `WeakKeysValidator` (envelope + data)."""

    certs_checked: int
    findings: list[dict[str, Any]]


EC_SMALL_SCALAR = "ec_small_scalar"
RSA_CLOSE_PRIMES = "rsa_close_primes"
RSA_ROCA = "rsa_roca"
CHECKS: tuple[str, ...] = (EC_SMALL_SCALAR, RSA_CLOSE_PRIMES, RSA_ROCA)

_DETAILS = {
    EC_SMALL_SCALAR: (
        "The EC private key is a small integer, so anyone can find it by "
        "counting from the public key."
    ),
    RSA_CLOSE_PRIMES: (
        "The RSA primes are so close together that Fermat's method factors "
        "the modulus (the CVE-2022-26320 pattern)."
    ),
    RSA_ROCA: (
        "The RSA key has the structure of Infineon RSALib keys (ROCA, "
        "CVE-2017-15361), which can be factored."
    ),
}

_EC_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})
MAX_EC_SCALAR_BOUND = 1 << 24

# Keys from the vulnerable generators factor within a handful of rounds;
# a hundred costs well under a millisecond on a 4096-bit modulus.
_FERMAT_ROUNDS = 100

# The ROCA fingerprint (Nemec et al., CCS 2017): an RSALib prime is
# k * M + (65537^a mod M), so modulo each small prime r dividing M, the
# modulus lies in the subgroup 65537 generates. These are the primes the
# reference detector (`roca-detect`) tests.
_ROCA_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167,
)  # fmt: skip
_ROCA_RESIDUES = tuple(
    frozenset(pow(65537, k, r) for k in range(r)) for r in _ROCA_PRIMES
)


def _fermat_factor(modulus: int) -> tuple[int, int] | None:
    a = isqrt(modulus)
    if a * a < modulus:
        a += 1
    for _ in range(_FERMAT_ROUNDS):
        b_squared = a * a - modulus
        b = isqrt(b_squared)
        if b * b == b_squared:
            return a - b, a + b
        a += 1
    return None


def _has_roca_fingerprint(modulus: int) -> bool:
    return all(
        modulus % r in residues for r, residues in zip(_ROCA_PRIMES, _ROCA_RESIDUES)
    )


# The same intermediates turn up behind many hosts, so a `scan_hosts` run
# checks each distinct key once.
@lru_cache(maxsize=1024)
def _key_weaknesses(
    spki: bytes, checks: frozenset[str], ec_scalar_bound: int
) -> tuple[tuple[str, tuple[tuple[str, int], ...]], ...]:
    """`(check, evidence)` pairs for every weakness found in one key."""
    info = certinfo.parse_spki(spki)  # type: ignore[attr-defined]
    found: list[tuple[str, tuple[tuple[str, int], ...]]] = []
    if EC_SMALL_SCALAR in checks and info.get("curve") in _EC_CURVES:
        try:
            scalar = certinfo.ec_small_scalar(spki, ec_scalar_bound)  # type: ignore[attr-defined]
        except ValueError:
            # A point encoding the search cannot decode, such as a
            # compressed point: not a finding either way.
            scalar = None
        if scalar is not None:
            found.append((EC_SMALL_SCALAR, (("private_scalar", scalar),)))
    modulus_bytes = info.get("rsa_modulus")
    if modulus_bytes is not None:
        modulus = int.from_bytes(modulus_bytes, "big")
        if RSA_CLOSE_PRIMES in checks:
            factors = _fermat_factor(modulus)
            if factors is not None:
                found.append((RSA_CLOSE_PRIMES, (("p", factors[0]), ("q", factors[1]))))
        if RSA_ROCA in checks and _has_roca_fingerprint(modulus):
            found.append((RSA_ROCA, ()))
    return tuple(found)


class WeakKeysValidator(BaseCertValidator):
    """
    A validator for public keys whose private half anyone can recover.

    Checks the leaf **and every certificate in the chain**, since a weak CA
    key compromises every certificate under it. Three recognizable
    weaknesses are looked for:

    - **`ec_small_scalar`**: a P-256, P-384, or P-521 private key that is a
      small integer (or `n` minus one), found by counting up from the
      public key. The eMudhra intermediates revoked in October 2026 had
      P-384 private keys below 256.
    - **`rsa_close_primes`**: RSA primes close enough together that Fermat's
      method factors the modulus within a hundred rounds (CVE-2022-26320).
    - **`rsa_roca`**: the Infineon RSALib key structure (ROCA,
      CVE-2017-15361).

    Passing proves nothing about how well a key was generated; it only
    means none of these patterns is present. Key types without a check
    (EdDSA, post-quantum, other curves) pass. Each distinct key is analyzed
    once per process.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "weak_keys"

    def validate(
        self,
        cert: dict[str, Any],
        host: str,
        port: int,
        *,
        ec_scalar_bound: int = 4096,
        checks: list[str] | None = None,
        show_evidence: bool = False,
    ) -> WeakKeysResult:
        """
        Check every key in the certificate chain for recoverable private keys.

        Args:
            cert: The cert data dict built by `CertMonitor._fetch_raw_cert`,
                with the served chain in `chain_der` and the leaf in `der`.
                When the chain is unavailable, only the leaf is checked and
                a warning says so.
            host: The hostname (unused; accepted for dispatcher compatibility).
            port: The port (unused; accepted for dispatcher compatibility).
            ec_scalar_bound: How far to look for a small EC private key,
                up to 2**24. The first 4096 come from a precomputed table,
                so the default costs microseconds per EC key; each step past
                that is one point addition (about 8 microseconds on P-384).
                The largest eMudhra scalar was 237.
            checks: Which weaknesses to look for, from `ec_small_scalar`,
                `rsa_close_primes`, and `rsa_roca`. `None` means all of them.
            show_evidence: Include the recovered secret in each finding: the
                EC private scalar, or the RSA primes. Off by default, since
                a recovered key is a working private key and results end up
                in logs and dashboards. A ROCA finding never has evidence,
                because factoring the key is far more work than spotting it.

        Returns:
            dict: `certs_checked` and one entry in `findings` per weakness,
                each with the certificate's `position` (0 is the leaf),
                `role`, `subject`, the `check` that fired, and a `detail`
                sentence.

        Raises:
            ValueError: An unknown name in `checks`, or `ec_scalar_bound`
                outside 0 to 2**24.

        Examples:
            Example output (failure):
                The chain served by the eMudhra incident's test host
                `dv-g3b-emudhra.we-have-a-problem.com`: the leaf's key is
                fine, but the intermediate's private key is the number 156.
                Pass `show_evidence=True` to add
                `"evidence": {"private_scalar": 156}` to the finding.

                ```json
                {
                    "is_valid": false,
                    "reason": "The certificate at position 1 (EM DV TLS CA - G3B (eMudhra BV)) has a private key anyone can recover from its public key (ec_small_scalar).",
                    "certs_checked": 3,
                    "findings": [
                        {
                            "position": 1,
                            "role": "intermediate",
                            "subject": {
                                "commonName": "EM DV TLS CA - G3B",
                                "organizationName": "eMudhra BV",
                                "countryName": "NL"
                            },
                            "check": "ec_small_scalar",
                            "detail": "The EC private key is a small integer, so anyone can find it by counting from the public key."
                        }
                    ]
                }
                ```

            Example output (success):
                ```json
                {
                    "is_valid": true,
                    "certs_checked": 3,
                    "findings": []
                }
                ```
        """
        selected = frozenset(CHECKS if checks is None else checks)
        unknown = sorted(selected.difference(CHECKS))
        if unknown:
            raise ValueError(
                f"unknown check(s) {', '.join(unknown)}; choose from {', '.join(CHECKS)}"
            )
        if not 0 <= ec_scalar_bound <= MAX_EC_SCALAR_BOUND:
            raise ValueError(
                f"ec_scalar_bound must be between 0 and {MAX_EC_SCALAR_BOUND}"
            )

        warnings: list[str] = []
        chain = cert.get("chain_der")
        if not chain:
            leaf = cert.get("der")
            if not leaf:
                return {
                    "is_valid": False,
                    "reason": "No certificate data is available to check.",
                    "certs_checked": 0,
                    "findings": [],
                }
            chain = [leaf]
            warnings.append(
                "The certificate chain was not available, so only the leaf was checked."
            )

        findings: list[dict[str, Any]] = []
        certs_checked = 0
        for position, der in enumerate(chain):
            try:
                parts = certinfo.certificate_signature_parts(der)  # type: ignore[attr-defined]
            except ValueError:
                warnings.append(
                    f"The certificate at position {position} could not be parsed, "
                    "so its key was not checked."
                )
                continue
            certs_checked += 1
            if position == 0:
                role = "leaf"
            elif parts["subject_der"] == parts["issuer_der"]:
                role = "root"
            else:
                role = "intermediate"
            for check, evidence in _key_weaknesses(
                parts["spki"], selected, ec_scalar_bound
            ):
                finding: dict[str, Any] = {
                    "position": position,
                    "role": role,
                    "subject": parts["subject"],
                    "check": check,
                    "detail": _DETAILS[check],
                }
                if show_evidence and evidence:
                    finding["evidence"] = dict(evidence)
                findings.append(finding)

        result: WeakKeysResult = {
            "is_valid": not findings,
            "certs_checked": certs_checked,
            "findings": findings,
        }
        if findings:
            first = findings[0]
            reason = (
                f"The certificate at position {first['position']} "
                f"({format_dn(first['subject'])}) has a private key anyone can "
                f"recover from its public key ({first['check']})."
            )
            if len(findings) > 1:
                reason += f" {len(findings)} findings in total."
            result["reason"] = reason
        if warnings:
            result["warnings"] = warnings
        return result
