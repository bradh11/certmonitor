# validators/pq_signature.py

from typing import Any, ClassVar

from certmonitor import certinfo

from .base import BaseCertValidator
from .results import ValidationResult

# Post-quantum algorithm identities, sourced from the Rust registry
# (rust_certinfo/src/pq_algorithms.rs) so Python never carries its own
# copy of the table. Keys (SPKI) are matched by name; certificate
# signature algorithms are matched by dotted OID. Composite entries are
# tracked separately so the validator can report hybrid composites.
_PQ_KEY_NAMES: frozenset[str] = frozenset(
    alg["name"]
    for alg in certinfo.pq_algorithms()  # type: ignore[attr-defined]
)
_PQ_SIG_OIDS: frozenset[str] = frozenset(
    alg["dotted"]
    for alg in certinfo.pq_algorithms()  # type: ignore[attr-defined]
)
_COMPOSITE_KEY_NAMES: frozenset[str] = frozenset(
    alg["name"]
    for alg in certinfo.pq_algorithms()  # type: ignore[attr-defined]
    if alg["composite"]
)
_COMPOSITE_SIG_OIDS: frozenset[str] = frozenset(
    alg["dotted"]
    for alg in certinfo.pq_algorithms()  # type: ignore[attr-defined]
    if alg["composite"]
)


class PqSignatureResult(ValidationResult, total=False):
    """Result shape for :class:`PqSignatureValidator` (envelope + data)."""

    key_algorithm: str
    key_is_pq: bool
    signature_algorithm_oid: str
    signature_is_pq: bool
    is_hybrid_composite: bool
    is_pq: bool


class PqSignatureValidator(BaseCertValidator):
    """Report the post-quantum posture of the leaf certificate.

    Judges the certificate the server presented for itself: whether its
    public key algorithm and its signature algorithm are post-quantum
    (standalone ML-DSA/SLH-DSA or a hybrid composite). The key and the
    signature are reported separately because they migrate separately —
    the key is the operator's choice, while the signature is applied by
    the issuing CA.

    By default ``is_valid`` is ``True`` when the **leaf key is
    post-quantum** — the part the operator controls — matching the
    ``pq_chain`` default so a PQ-keyed, classically-signed certificate
    (the realistic migration shape) gets one consistent verdict. Pass
    ``require_pq_signature=True`` to additionally demand a post-quantum
    signature from the CA.

    Works on every supported interpreter: the leaf data comes from the
    chain analysis when available, with a leaf-only fallback otherwise.

    Opt-in: registered in ``VALIDATORS`` but not in
    ``DEFAULT_VALIDATORS``.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "pq_signature"
    requires: ClassVar = ("cert_data",)

    def validate(
        self,
        cert: dict[str, Any],
        host: str,
        port: int,
        *,
        require_pq_signature: bool = False,
    ) -> PqSignatureResult:
        """Judge the leaf certificate's post-quantum posture.

        Args:
            cert: The cert data dict built by ``CertMonitor``; the leaf is
                read from ``chain_analysis`` or the ``leaf_analysis``
                fallback.
            host: The hostname (unused; dispatcher compatibility).
            port: The port (unused; dispatcher compatibility).
            require_pq_signature: When ``True``, ``is_valid`` additionally
                requires the CA's signature algorithm to be post-quantum.
                Default ``False``: the leaf key decides.

        Returns:
            dict: ``{key_algorithm, key_is_pq, signature_algorithm_oid,
            signature_is_pq, is_hybrid_composite, is_pq, is_valid}`` —
            per-cert field names match ``pq_chain``. ``is_pq`` is true
            when either the key or the signature is post-quantum;
            ``is_hybrid_composite`` is true when either uses a composite
            (PQ + classical) algorithm.

        Examples:
            Example output (post-quantum leaf, classically signed — the
            realistic migration shape):
                ```json
                {
                    "key_algorithm": "ml-dsa-65",
                    "key_is_pq": true,
                    "signature_algorithm_oid": "1.2.840.113549.1.1.11",
                    "signature_is_pq": false,
                    "is_hybrid_composite": false,
                    "is_pq": true,
                    "is_valid": true
                }
                ```

            Example output (classical leaf):
                ```json
                {
                    "key_algorithm": "rsaEncryption",
                    "key_is_pq": false,
                    "signature_algorithm_oid": "1.2.840.113549.1.1.11",
                    "signature_is_pq": false,
                    "is_hybrid_composite": false,
                    "is_pq": false,
                    "is_valid": false,
                    "reason": "Leaf key algorithm (rsaEncryption) is not post-quantum."
                }
                ```
        """
        leaf = self._leaf(cert)
        if leaf is None:
            return {
                "is_valid": False,
                "reason": (
                    "Leaf certificate could not be analyzed: no chain or "
                    "leaf analysis is available."
                ),
            }

        key_algorithm = leaf.get("public_key_info", {}).get("algorithm", "unknown")
        sig_oid = leaf.get("signature_algorithm_oid", "")
        key_is_pq = key_algorithm in _PQ_KEY_NAMES
        signature_is_pq = sig_oid in _PQ_SIG_OIDS
        is_hybrid_composite = (
            key_algorithm in _COMPOSITE_KEY_NAMES or sig_oid in _COMPOSITE_SIG_OIDS
        )

        is_valid = key_is_pq and (signature_is_pq or not require_pq_signature)

        result: PqSignatureResult = {
            "key_algorithm": key_algorithm,
            "key_is_pq": key_is_pq,
            "signature_algorithm_oid": sig_oid,
            "signature_is_pq": signature_is_pq,
            "is_hybrid_composite": is_hybrid_composite,
            "is_pq": key_is_pq or signature_is_pq,
            "is_valid": is_valid,
        }
        if not is_valid:
            if not key_is_pq:
                result["reason"] = (
                    f"Leaf key algorithm ({key_algorithm}) is not post-quantum."
                )
            else:
                result["reason"] = (
                    f"Leaf signature algorithm ({sig_oid}) is not post-quantum "
                    "(required by require_pq_signature)."
                )
        return result

    @staticmethod
    def _leaf(cert: dict[str, Any]) -> dict[str, Any] | None:
        """The leaf cert dict from chain_analysis, else leaf_analysis."""
        for source in ("chain_analysis", "leaf_analysis"):
            analysis = cert.get(source)
            if (
                isinstance(analysis, dict)
                and "error" not in analysis
                and analysis.get("certs")
            ):
                return analysis["certs"][0]  # type: ignore[no-any-return]
        return None
