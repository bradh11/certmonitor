# validators/pq_chain.py

from typing import Any, ClassVar

from certmonitor import certinfo

from .base import BaseCertValidator
from .results import ValidationResult

# Post-quantum algorithm identities, sourced from the Rust registry
# (rust_certinfo/src/pq_algorithms.rs) so Python never carries its own
# copy of the table. Keys (SPKI) are matched by name; certificate
# signature algorithms are matched by dotted OID.
_PQ_KEY_NAMES: frozenset[str] = frozenset(
    alg["name"]
    for alg in certinfo.pq_algorithms()  # type: ignore[attr-defined]
)
_PQ_SIG_OIDS: frozenset[str] = frozenset(
    alg["dotted"]
    for alg in certinfo.pq_algorithms()  # type: ignore[attr-defined]
)


class PqChainResult(ValidationResult, total=False):
    """Result shape for :class:`PqChainValidator` (envelope + data)."""

    chain_length: int
    certs: list[dict[str, Any]]
    summary: dict[str, bool | None]


class PqChainValidator(BaseCertValidator):
    """Report the post-quantum posture of every certificate in the chain.

    During the staged PQ migration, the leaf, intermediates, and root
    rotate independently — a post-quantum leaf will routinely chain up to
    classical intermediates and roots for years. This validator walks the
    chain the server presented and reports, per certificate, whether the
    public key and the signature use post-quantum algorithms, plus a
    role-level summary.

    A certificate counts as PQ when **either** its key algorithm or its
    signature algorithm is post-quantum (standalone or composite) — both
    are meaningful migration signals, and the signature is the issuing
    CA's choice rather than the operator's.

    By default ``is_valid`` is ``True`` when the **leaf certificate's key
    is post-quantum** — the part the operator controls. Pass
    ``require_full_chain=True`` to demand that every certificate in the
    chain is PQ.

    Note: chains that terminate at public trust anchors will report a
    classical root for the foreseeable future. **This is expected, not a
    bug** — root CAs migrate last.

    Opt-in: registered in ``VALIDATORS`` but not in
    ``DEFAULT_VALIDATORS``. Chain retrieval requires Python 3.10+ (same
    constraint as the ``chain`` validator); on older interpreters this
    validator reports a structured error.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "pq_chain"
    requires: ClassVar = ("cert_data",)

    def validate(
        self,
        cert: dict[str, Any],
        host: str,
        port: int,
        *,
        require_full_chain: bool = False,
    ) -> PqChainResult:
        """Walk the presented chain and report per-certificate PQ posture.

        Args:
            cert: The cert data dict built by ``CertMonitor``; expected to
                contain ``chain_analysis`` (and/or ``chain_error``).
            host: The hostname (unused; dispatcher compatibility).
            port: The port (unused; dispatcher compatibility).
            require_full_chain: When ``True``, ``is_valid`` requires every
                certificate in the chain to be post-quantum. Default
                ``False``: the leaf's key decides.

        Returns:
            dict: ``{chain_length, certs, summary, is_valid}`` where each
            entry is ``{position, role, subject, key_algorithm, key_is_pq,
            signature_algorithm_oid, signature_is_pq, is_pq}`` and the
            summary is ``{leaf_pq, intermediate_pq, root_pq}``
            (``None`` when the chain has no certificate in that role).

        Examples:
            Example output (post-quantum leaf on a classical chain):
                ```json
                {
                    "chain_length": 3,
                    "certs": [
                        {"position": 0, "role": "leaf", "key_algorithm": "ml-dsa-65", "key_is_pq": true, "is_pq": true},
                        {"position": 1, "role": "intermediate", "key_algorithm": "rsaEncryption", "key_is_pq": false, "is_pq": false},
                        {"position": 2, "role": "root", "key_algorithm": "rsaEncryption", "key_is_pq": false, "is_pq": false}
                    ],
                    "summary": {"leaf_pq": true, "intermediate_pq": false, "root_pq": false},
                    "is_valid": true
                }
                ```
                (Per-cert fields abbreviated; each entry also carries
                ``subject``, ``signature_algorithm_oid``, and
                ``signature_is_pq``.)
        """
        chain_error = cert.get("chain_error")
        if chain_error:
            return self._error_result(chain_error)

        analysis = cert.get("chain_analysis")
        if analysis is None:
            return self._error_result(
                "Certificate chain was not fetched. This typically means the "
                "Python interpreter is older than 3.10 or the SSL handler did "
                "not populate the chain."
            )
        if isinstance(analysis, dict) and "error" in analysis:
            return self._error_result(analysis["error"])

        raw_certs: list[dict[str, Any]] = list(analysis.get("certs", []))
        if not raw_certs:
            return self._error_result("Certificate chain is empty.")

        certs: list[dict[str, Any]] = []
        for idx, raw in enumerate(raw_certs):
            key_algorithm = raw.get("public_key_info", {}).get("algorithm", "unknown")
            sig_oid = raw.get("signature_algorithm_oid", "")
            key_is_pq = key_algorithm in _PQ_KEY_NAMES
            signature_is_pq = sig_oid in _PQ_SIG_OIDS

            if idx == 0:
                role = "leaf"
            elif raw.get("is_self_signed", False):
                role = "root"
            else:
                role = "intermediate"

            certs.append(
                {
                    "position": idx,
                    "role": role,
                    "subject": raw.get("subject", {}),
                    "key_algorithm": key_algorithm,
                    "key_is_pq": key_is_pq,
                    "signature_algorithm_oid": sig_oid,
                    "signature_is_pq": signature_is_pq,
                    "is_pq": key_is_pq or signature_is_pq,
                }
            )

        summary = {
            "leaf_pq": certs[0]["key_is_pq"],
            "intermediate_pq": self._role_all_pq(certs, "intermediate"),
            "root_pq": self._role_all_pq(certs, "root"),
        }

        if require_full_chain:
            is_valid = all(entry["is_pq"] for entry in certs)
        else:
            is_valid = bool(summary["leaf_pq"])

        result: PqChainResult = {
            "chain_length": len(certs),
            "certs": certs,
            "summary": summary,
            "is_valid": is_valid,
        }
        if not is_valid:
            result["reason"] = (
                "Not every certificate in the chain uses a post-quantum algorithm."
                if require_full_chain
                else f"Leaf key algorithm ({certs[0]['key_algorithm']}) is not post-quantum."
            )
        return result

    @staticmethod
    def _role_all_pq(certs: list[dict[str, Any]], role: str) -> bool | None:
        """True/False when every cert of ``role`` is PQ; None when absent."""
        of_role = [entry for entry in certs if entry["role"] == role]
        if not of_role:
            return None
        return all(entry["is_pq"] for entry in of_role)

    @staticmethod
    def _error_result(reason: str) -> PqChainResult:
        return {
            "is_valid": False,
            "reason": reason,
            "chain_length": 0,
            "certs": [],
            "summary": {"leaf_pq": False, "intermediate_pq": None, "root_pq": None},
        }
