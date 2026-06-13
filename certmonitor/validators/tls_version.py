# validators/tls_version.py

from typing import Any, Dict, Optional

from ..cipher_algorithms import ALLOWED_TLS_VERSIONS
from .base import BaseCipherValidator
from .results import ValidationResult


class TLSVersionResult(ValidationResult, total=False):
    """Result shape for :class:`TLSVersionValidator` (envelope + data)."""

    protocol_version: Optional[str]


class TLSVersionValidator(BaseCipherValidator):
    """
    Checks if the negotiated TLS version is in the allowed list.
    """

    name: str = "tls_version"

    def validate(
        self, cipher_info: Dict[str, Any], host: str, port: int
    ) -> TLSVersionResult:
        """
        Validates the TLS protocol version used by the connection.

        Args:
            cipher_info (dict): The cipher information for the connection.
            host (str): The hostname.
            port (int): The port number.

        Returns:
            dict: A dictionary containing the validation results, including whether the TLS version is acceptable,
                  the protocol version, and any warnings.

        Examples:
            Example output (success):
                This example shows a connection using TLSv1.3, which is considered secure, so validation passes and no warnings are present.

                ```json
                {
                    "is_valid": true,
                    "protocol_version": "TLSv1.3",
                    "warnings": []
                }
                ```

            Example output (failure):
                This example shows a connection using TLSv1.0, which is considered insecure, so validation fails and a warning is included.

                ```json
                {
                    "is_valid": false,
                    "protocol_version": "TLSv1.0",
                    "warnings": [
                        "TLS version TLSv1.0 is considered insecure."
                    ]
                }
                ```
        """
        protocol_version = cipher_info.get("protocol_version")
        result: TLSVersionResult = {
            "is_valid": True,
            "protocol_version": protocol_version,
        }

        if protocol_version not in ALLOWED_TLS_VERSIONS:
            result["is_valid"] = False
            result["reason"] = (
                f"TLS version {protocol_version} is not allowed. "
                "Update your allowed TLS versions or negotiate a supported version."
            )

        return result
