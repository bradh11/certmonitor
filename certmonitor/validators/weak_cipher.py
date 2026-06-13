# validators/weak_cipher.py

from typing import Any, Dict, Optional

from ..cipher_algorithms import ALLOWED_CIPHER_SUITES
from .base import BaseCipherValidator
from .results import ValidationResult


class WeakCipherResult(ValidationResult, total=False):
    """Result shape for :class:`WeakCipherValidator` (envelope + data)."""

    cipher_suite: Optional[str]


class WeakCipherValidator(BaseCipherValidator):
    """
    Validates that the negotiated cipher suite is in the allowed list.
    """

    name: str = "weak_cipher"

    def validate(
        self, cipher_info: Dict[str, Any], host: str, port: int
    ) -> WeakCipherResult:
        """
        Validates that the negotiated cipher suite is in the allowed list.

        Args:
            cipher_info (dict): The cipher information.
            host (str): The hostname.
            port (int): The port number.

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
        cipher_suite = cipher_info.get("cipher_suite", {})
        cipher_name = cipher_suite.get("name")

        result: WeakCipherResult = {
            "is_valid": True,
            "cipher_suite": cipher_name,
        }

        if cipher_name not in ALLOWED_CIPHER_SUITES:
            result["is_valid"] = False
            result["reason"] = (
                f"Cipher suite {cipher_name} is not allowed. "
                "Please update your allowed cipher suites or negotiate a supported cipher."
            )

        return result
