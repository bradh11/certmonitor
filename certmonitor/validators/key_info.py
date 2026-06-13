# validators/key_info.py

from typing import Any, Dict, FrozenSet, Optional

from certmonitor import certinfo

from .base import BaseCertValidator

# Post-quantum algorithm names, sourced from the Rust registry
# (rust_certinfo/src/pq_algorithms.rs) via certinfo.pq_algorithms() so
# Python never carries its own copy of the table — a new algorithm added
# there is recognized here automatically.
_PQ_ALGORITHM_NAMES: FrozenSet[str] = frozenset(
    alg["name"]
    for alg in certinfo.pq_algorithms()  # type: ignore[attr-defined]
)


class KeyInfoValidator(BaseCertValidator):
    """
    A validator for checking the public key of an SSL certificate.

    Judges key strength per algorithm family:

    - **RSA**: modulus must be at least 2048 bits.
    - **EC**: curve must be one of secp256r1 / secp384r1 / secp521r1
      (the parser reports the curve by short name; unrecognized curves
      come through as an OID dotted string and are treated as not strong).
    - **Post-quantum** (ML-DSA, SLH-DSA, and hybrid composite ML-DSA):
      always strong — PQ strength is judged by algorithm identity, since
      the FIPS 204/205 parameter sets have no weak sizes or curves. The
      recognized set comes from the Rust registry exposed via
      ``certinfo.pq_algorithms()``.

    Unrecognized algorithms return ``is_valid: None`` ("can't judge"),
    never ``False``.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "key_info"

    def validate(self, cert: Dict[str, Any], host: str, port: int) -> Dict[str, Any]:
        """
        Validates the key information of the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).

        Returns:
            dict: A dictionary containing the validation results, including key type, key size,
                  whether the key is considered strong enough (see the class docstring for the
                  per-family rules, including post-quantum algorithms), and curve information
                  if applicable.

        Examples:
            Example output (success):
                This example shows a certificate with a strong RSA 2048-bit key, so validation passes and no warnings are present.

                ```json
                {
                    "key_type": "rsaEncryption",
                    "key_size": 2048,
                    "is_valid": true,
                    "curve": null
                }
                ```

            Example output (post-quantum key):
                This example shows a certificate with an ML-DSA-65 (FIPS 204) key. Post-quantum
                keys are valid by algorithm identity; ``key_size`` reports the subjectPublicKey
                bit length and is informational only.

                ```json
                {
                    "key_type": "ml-dsa-65",
                    "key_size": 15616,
                    "is_valid": true
                }
                ```

            Example output (failure):
                This example shows a certificate with a weak 512-bit key, so validation fails and a warning is included.

                ```json
                {
                    "key_type": "rsaEncryption",
                    "key_size": 512,
                    "is_valid": false,
                    "curve": null,
                    "warnings": [
                        "Key size 512 is considered weak."
                    ]
                }
                ```
        """
        public_key_info = cert.get("public_key_info", {})
        if not public_key_info:
            return {
                "error": "Unable to extract public key information",
                "is_valid": False,
            }

        key_type = public_key_info.get("algorithm", "Unknown")
        key_size = public_key_info.get("size")
        curve = public_key_info.get("curve")

        result = {
            "key_type": key_type,
            "key_size": key_size,
            "is_valid": self._is_key_strong_enough(key_type, key_size, curve),
        }

        if curve:
            result["curve"] = curve

        return result

    def _is_key_strong_enough(
        self, key_type: str, key_size: Optional[int], curve: Optional[str]
    ) -> Optional[bool]:
        """
        Checks if the key is strong enough based on its type, size, and curve.

        Post-quantum algorithms (any name in the Rust registry exposed by
        ``certinfo.pq_algorithms()``) are always strong; RSA requires a
        modulus of at least 2048 bits; EC requires a strong named curve.

        Args:
            key_type (str): The key algorithm name (e.g. ``"rsaEncryption"``,
                ``"ecPublicKey"``, ``"ml-dsa-65"``).
            key_size (int): The size of the key. Ignored for PQ algorithms.
            curve (str): The curve of the key (EC only).

        Returns:
            bool: True if the key is considered strong enough, False if not.
            None when the key type is unrecognized or required details are
            missing.
        """
        if key_type in _PQ_ALGORITHM_NAMES:
            # Post-quantum strength is judged by algorithm identity: the
            # FIPS 204/205 parameter sets and the composite variants have
            # no weak sizes or curves to check.
            return True
        if "rsaEncryption" in key_type:
            if key_size is None:
                return None
            return key_size >= 2048
        elif "ecPublicKey" in key_type:
            strong_curves = ["secp256r1", "secp384r1", "secp521r1"]
            if curve is None:
                return None
            return curve in strong_curves
        return None
