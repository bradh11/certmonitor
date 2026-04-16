# validators/chain.py

import datetime
from typing import Any, Dict, List, Optional

from .base import BaseCertValidator

# Signature algorithm OIDs treated as weak by default. Override per-call via
# the ``weak_signature_algorithms`` user arg.
_DEFAULT_WEAK_SIG_OIDS: frozenset = frozenset(
    {
        "1.2.840.113549.1.1.5",  # sha1WithRSAEncryption
        "1.2.840.113549.1.1.4",  # md5WithRSAEncryption
        "1.2.840.113549.1.1.2",  # md2WithRSAEncryption
        "1.2.840.10045.4.1",  # ecdsa-with-SHA1
        "1.2.840.10040.4.3",  # dsa-with-sha1
    }
)


def _format_dn(fields: Dict[str, Any]) -> str:
    cn = fields.get("commonName")
    o = fields.get("organizationName")
    if cn and o:
        return f"{cn} ({o})"
    return cn or o or "Unknown"


def _iso(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()


class ChainValidator(BaseCertValidator):
    """
    Validator for the structural integrity of the TLS certificate chain.

    This validator inspects the chain the server presented during the TLS
    handshake (leaf through root) and checks for the problems operators
    actually hit in production: missing intermediates, out-of-order chains,
    expired members, weak signature algorithms, and non-CA intermediates.
    It does **not** perform cryptographic signature verification — that is
    intentionally left to Phase 2 to keep the Rust dependency footprint at
    ``pyo3 + x509-parser``.

    The validator ships **disabled by default**. Opt in via:

        CertMonitor("example.com",
                    enabled_validators=["expiration", "hostname",
                                        "root_certificate", "chain"])

    or by setting ``ENABLED_VALIDATORS`` in the environment.

    Chain retrieval requires Python 3.10 or newer. On 3.8/3.9 this validator
    reports a clear error rather than silently degrading.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "chain"

    def validate(
        self,
        cert: Dict[str, Any],
        host: str,
        port: int,
        *,
        min_chain_length: int = 2,
        require_root_in_chain: bool = False,
        allow_self_signed_leaf: bool = False,
        weak_signature_algorithms: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Validate the certificate chain fetched alongside the leaf cert.

        Args:
            cert: The cert data dict built by ``CertMonitor._fetch_raw_cert``.
                Expected to contain ``chain_analysis`` (populated by the Rust
                ``certinfo.analyze_chain`` call) and/or ``chain_error``.
            host: The hostname (unused; accepted for dispatcher compatibility).
            port: The port (unused; accepted for dispatcher compatibility).
            min_chain_length: Minimum acceptable chain length. Default ``2``
                rejects servers that only send the leaf.
            require_root_in_chain: If ``True``, the chain must terminate in a
                self-signed root. Most well-configured public TLS servers do
                **not** include the root (browsers supply it from the trust
                store), so this defaults to ``False`` and only emits a
                warning.
            allow_self_signed_leaf: If ``True``, a self-signed leaf (chain
                length 1, subject == issuer) is accepted. Useful for internal
                services; default ``False``.
            weak_signature_algorithms: Override the default set of weak
                signature algorithm OIDs. Pass an empty list to disable the
                weak-signature warning entirely.

        Returns:
            dict: A structured report with per-cert details and a summary.
                The shape is stable and documented in
                ``docs/validators/chain.md``.
        """
        warnings: List[str] = []

        chain_error = cert.get("chain_error")
        if chain_error:
            return {
                "is_valid": False,
                "reason": chain_error,
                "chain_length": 0,
                "chain_ordered": False,
                "terminates_in_self_signed": False,
                "certs": [],
                "warnings": [chain_error],
            }

        analysis = cert.get("chain_analysis")
        if analysis is None:
            reason = (
                "Certificate chain was not fetched. This typically means the "
                "Python interpreter is older than 3.10 or the SSL handler did "
                "not populate the chain."
            )
            return {
                "is_valid": False,
                "reason": reason,
                "chain_length": 0,
                "chain_ordered": False,
                "terminates_in_self_signed": False,
                "certs": [],
                "warnings": [reason],
            }

        if isinstance(analysis, dict) and "error" in analysis:
            return {
                "is_valid": False,
                "reason": analysis["error"],
                "chain_length": 0,
                "chain_ordered": False,
                "terminates_in_self_signed": False,
                "certs": [],
                "warnings": [analysis["error"]],
            }

        weak_oids = (
            frozenset(weak_signature_algorithms)
            if weak_signature_algorithms is not None
            else _DEFAULT_WEAK_SIG_OIDS
        )

        chain_length: int = analysis["chain_length"]
        chain_ordered: bool = analysis["ordered"]
        terminates_in_self_signed: bool = analysis["terminates_in_self_signed"]
        raw_certs: List[Dict[str, Any]] = list(analysis.get("certs", []))

        now = datetime.datetime.now(datetime.timezone.utc)
        any_expired = False
        any_not_yet_valid = False

        cert_reports: List[Dict[str, Any]] = []
        for idx, raw in enumerate(raw_certs):
            cert_warnings: List[str] = []

            not_before_ts = raw["not_before_unix"]
            not_after_ts = raw["not_after_unix"]
            not_before = datetime.datetime.fromtimestamp(
                not_before_ts, tz=datetime.timezone.utc
            )
            not_after = datetime.datetime.fromtimestamp(
                not_after_ts, tz=datetime.timezone.utc
            )
            days_to_expiry = (not_after - now).days

            if now > not_after:
                any_expired = True
                cert_warnings.append(
                    f"Certificate at position {idx} is expired "
                    f"({abs(days_to_expiry)} days ago)."
                )
            elif now < not_before:
                any_not_yet_valid = True
                cert_warnings.append(
                    f"Certificate at position {idx} is not yet valid "
                    f"(notBefore={not_before.isoformat()})."
                )

            sig_oid = raw.get("signature_algorithm_oid", "")
            if sig_oid in weak_oids:
                cert_warnings.append(
                    f"Certificate at position {idx} uses a weak signature "
                    f"algorithm ({sig_oid})."
                )

            # A cert is only labeled "root" when it is actually self-signed.
            # Servers often send a cross-signed version of a root (e.g.
            # SSL.com's ECC root cross-signed by Comodo's AAA root) as the
            # last cert in the chain. The last cert in those chains is
            # structurally an intermediate, not a root — its trust anchor
            # (the signer) lives in the client's trust store.
            if idx == 0:
                role = "leaf"
            elif raw.get("is_self_signed", False):
                role = "root"
            else:
                role = "intermediate"

            if role in ("intermediate", "root") and not raw.get("is_ca"):
                cert_warnings.append(
                    f"Certificate at position {idx} ({role}) is not marked "
                    "as a CA (BasicConstraints.cA is false)."
                )

            cert_reports.append(
                {
                    "position": idx,
                    "role": role,
                    "subject": raw.get("subject", {}),
                    "issuer": raw.get("issuer", {}),
                    "not_before": _iso(not_before_ts),
                    "not_after": _iso(not_after_ts),
                    "days_to_expiry": days_to_expiry,
                    "is_ca": raw.get("is_ca", False),
                    "is_self_signed": raw.get("is_self_signed", False),
                    "signature_algorithm_oid": sig_oid,
                    "subject_key_identifier": raw.get("subject_key_identifier"),
                    "authority_key_identifier": raw.get("authority_key_identifier"),
                    "public_key_info": raw.get("public_key_info", {}),
                    "warnings": cert_warnings,
                }
            )

        # Chain-level warnings and pass/fail logic.
        if chain_length < min_chain_length:
            warnings.append(
                f"Chain length {chain_length} is below the required minimum "
                f"of {min_chain_length}. The server likely failed to send "
                "one or more intermediate certificates."
            )

        if not chain_ordered:
            warnings.append(
                "Chain is not ordered correctly: the subject of each parent "
                "does not match the issuer of its child."
            )

        if any_expired:
            warnings.append("One or more certificates in the chain are expired.")

        if any_not_yet_valid:
            warnings.append("One or more certificates in the chain are not yet valid.")

        leaf_self_signed = (
            chain_length >= 1
            and raw_certs
            and raw_certs[0].get("is_self_signed", False)
        )
        if leaf_self_signed and not allow_self_signed_leaf:
            leaf_dn = _format_dn(raw_certs[0].get("subject", {}))
            warnings.append(
                f"Leaf certificate is self-signed ({leaf_dn}). "
                "Pass allow_self_signed_leaf=True to accept this."
            )

        if not terminates_in_self_signed:
            chain_warning = (
                "Chain does not terminate in a self-signed root certificate. "
                "The last cert is either a cross-signed intermediate (legitimate "
                "— the real root lives in the client's trust store) or the "
                "server is not sending the root at all (also common — browsers "
                "supply the root from their trust store)."
            )
            if require_root_in_chain:
                warnings.append(
                    chain_warning + " (require_root_in_chain=True rejects this.)"
                )
            else:
                warnings.append(chain_warning)

        # Pass-through per-cert warnings at the top level so a single
        # ``warnings`` list gives operators everything.
        for cert_report in cert_reports:
            warnings.extend(cert_report["warnings"])

        is_valid = (
            chain_length >= min_chain_length
            and chain_ordered
            and not any_expired
            and not any_not_yet_valid
            and (not leaf_self_signed or allow_self_signed_leaf)
            and (terminates_in_self_signed or not require_root_in_chain)
        )

        result: Dict[str, Any] = {
            "is_valid": is_valid,
            "chain_length": chain_length,
            "chain_ordered": chain_ordered,
            "terminates_in_self_signed": terminates_in_self_signed,
            "certs": cert_reports,
            "warnings": warnings,
        }
        if not is_valid:
            result["reason"] = warnings[0] if warnings else "Chain validation failed."
        return result
