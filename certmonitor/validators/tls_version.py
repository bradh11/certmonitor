# validators/tls_version.py

from typing import Any, Dict, FrozenSet, List, Optional

from .base import BaseCipherValidator
from .results import ValidationResult

# Default acceptable TLS versions. TLS 1.1 and older are deprecated.
# Override per call with the ``allowed_tls_versions`` user arg.
_DEFAULT_ALLOWED_TLS_VERSIONS: FrozenSet[str] = frozenset({"TLSv1.2", "TLSv1.3"})


class TLSVersionResult(ValidationResult, total=False):
    """Result shape for :class:`TLSVersionValidator` (envelope + data)."""

    protocol_version: Optional[str]


class TLSVersionValidator(BaseCipherValidator):
    """
    Checks if the negotiated TLS version is in the allowed list.

    The default allowed set is TLS 1.2 and TLS 1.3. Override it per call
    with the ``allowed_tls_versions`` argument.
    """

    name: str = "tls_version"

    def validate(
        self,
        cipher_info: Dict[str, Any],
        host: str,
        port: int,
        *,
        allowed_tls_versions: Optional[List[str]] = None,
    ) -> TLSVersionResult:
        """
        Validates the TLS protocol version used by the connection.

        Args:
            cipher_info (dict): The cipher information for the connection.
            host (str): The hostname.
            port (int): The port number.
            allowed_tls_versions (list, optional): Override the default
                acceptable TLS versions. When ``None`` (the default),
                ``{"TLSv1.2", "TLSv1.3"}`` is used.

        Returns:
            dict: A dictionary containing the validation result and the
                  negotiated protocol version. A ``reason`` is added when
                  the version is not allowed.

        Examples:
            Example output (success):
                This example shows a connection using TLSv1.3, which is considered secure, so validation passes.

                ```json
                {
                    "is_valid": true,
                    "protocol_version": "TLSv1.3"
                }
                ```

            Example output (failure):
                This example shows a connection using TLSv1.0, which is considered insecure, so validation fails with a reason.

                ```json
                {
                    "is_valid": false,
                    "protocol_version": "TLSv1.0",
                    "reason": "TLS version TLSv1.0 is not allowed. Update your allowed TLS versions or negotiate a supported version."
                }
                ```
        """
        allowed: FrozenSet[str] = (
            frozenset(allowed_tls_versions)
            if allowed_tls_versions is not None
            else _DEFAULT_ALLOWED_TLS_VERSIONS
        )

        protocol_version = cipher_info.get("protocol_version")
        result: TLSVersionResult = {
            "is_valid": True,
            "protocol_version": protocol_version,
        }

        if protocol_version not in allowed:
            result["is_valid"] = False
            result["reason"] = (
                f"TLS version {protocol_version} is not allowed. "
                "Update your allowed TLS versions or negotiate a supported version."
            )

        return result
