# validators/weak_cipher.py

from typing import Any, Dict, FrozenSet, List, Optional

from .base import BaseCipherValidator
from .results import ValidationResult

# Default allowed cipher suites, following Mozilla's "Intermediate" TLS
# configuration. Includes the TLS 1.3 suites (IANA names) and the TLS 1.2
# ECDHE/DHE AEAD suites (OpenSSL-style names). Override per call with the
# ``allowed_cipher_suites`` user arg.
_DEFAULT_ALLOWED_CIPHER_SUITES: FrozenSet[str] = frozenset(
    {
        # TLS 1.3 (IANA names, as reported by Python's ssl module).
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        # TLS 1.2 ECDHE (OpenSSL-style names).
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        # TLS 1.2 DHE.
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-CHACHA20-POLY1305",
    }
)


class WeakCipherResult(ValidationResult, total=False):
    """Result shape for :class:`WeakCipherValidator` (envelope + data)."""

    cipher_suite: Optional[str]


class WeakCipherValidator(BaseCipherValidator):
    """
    Validates that the negotiated cipher suite is in the allowed list.

    The default allowed set follows Mozilla's "Intermediate" configuration.
    Override it per call with the ``allowed_cipher_suites`` argument.
    """

    name: str = "weak_cipher"

    def validate(
        self,
        cipher_info: Dict[str, Any],
        host: str,
        port: int,
        *,
        allowed_cipher_suites: Optional[List[str]] = None,
    ) -> WeakCipherResult:
        """
        Validates that the negotiated cipher suite is in the allowed list.

        Args:
            cipher_info (dict): The cipher information.
            host (str): The hostname.
            port (int): The port number.
            allowed_cipher_suites (list, optional): Override the default
                allowed cipher suites. When ``None`` (the default), the
                Mozilla "Intermediate" set is used.

        Returns:
            dict: A dictionary containing the validation results, including whether the cipher suite is allowed.

        Examples:
            Example output (success):
                This example shows a connection using a strong cipher suite, so validation passes.

                ```json
                {
                    "is_valid": true,
                    "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256"
                }
                ```

            Example output (failure):
                This example shows a connection using a weak cipher suite, so validation fails.

                ```json
                {
                    "is_valid": false,
                    "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5",
                    "reason": "Cipher suite TLS_RSA_WITH_RC4_128_MD5 is not allowed. Please update your allowed cipher suites or negotiate a supported cipher."
                }
                ```
        """
        allowed: FrozenSet[str] = (
            frozenset(allowed_cipher_suites)
            if allowed_cipher_suites is not None
            else _DEFAULT_ALLOWED_CIPHER_SUITES
        )

        cipher_suite = cipher_info.get("cipher_suite", {})
        cipher_name = cipher_suite.get("name")

        result: WeakCipherResult = {
            "is_valid": True,
            "cipher_suite": cipher_name,
        }

        if cipher_name not in allowed:
            result["is_valid"] = False
            result["reason"] = (
                f"Cipher suite {cipher_name} is not allowed. "
                "Please update your allowed cipher suites or negotiate a supported cipher."
            )

        return result
