from typing import Any

from ..utils.identity import match_identity, normalize_sans
from .base import BaseCertValidator
from .results import ValidationResult


class SubjectAltNamesResult(ValidationResult, total=False):
    """Result shape for `SubjectAltNamesValidator` (envelope + data).

    With `alternate_names`, the top-level `is_valid` requires every requested
    name to match and the per-name outcomes live in `contains_alternate`.
    Without them, `is_valid` reflects the primary host, whose outcome is
    always reported in `contains_host`.
    """

    sans: dict[str, list[str]] | None
    count: int
    contains_host: dict[str, Any]
    contains_alternate: dict[str, Any]


class SubjectAltNamesValidator(BaseCertValidator):
    """A validator for checking the Subject Alternative Names (SANs) in an SSL certificate.

    This validator checks explicitly requested alternate names against both DNS and IP Address SANs.
    Without alternate names it checks the primary host instead, so enabling it by name alone still
    produces a meaningful verdict.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "subject_alt_names"

    def validate(
        self,
        cert: dict[str, Any],
        host: str,
        port: int,
        *,
        alternate_names: list[str] | None = None,
    ) -> SubjectAltNamesResult:
        """
        Validates the SANs in the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The primary host. Always reported in `contains_host`; it decides
                `is_valid` only when no alternate names are requested.
            port (int): The port number.
            alternate_names (list, optional): Alternate names to validate against the SANs.
                A list or tuple of non-empty strings. When given, every requested name must
                match for `is_valid` to be true. Defaults to `None`, which checks the primary host.

        Returns:
            dict: A dictionary containing the validation results, including whether the SANs are valid,
                  the SANs themselves, the count of SANs, and any warnings or reasons for validation failure.

        Examples:
            Example output (success):
                This example shows a certificate where an alternate name is present in the DNS SANs, so validation passes.

                ```json
                {
                    "is_valid": true,
                    "sans": {
                        "DNS": [
                            "example.com",
                            "www.example.com"
                        ],
                        "IP Address": []
                    },
                    "count": 2,
                    "contains_host": {
                        "name": "example.com",
                        "is_valid": true,
                        "reason": "Exact match for example.com found in DNS SANs"
                    },
                    "contains_alternate": {
                        "www.example.com": {
                            "name": "www.example.com",
                            "is_valid": true,
                            "reason": "Exact match for www.example.com found in DNS SANs"
                        }
                    },
                    "warnings": []
                }
                ```

            Example output (failure):
                This example shows a certificate where the alternate name is absent from the DNS SANs, so validation fails and a warning is included.

                ```json
                {
                    "is_valid": false,
                    "reason": "One or more required alternate names are absent from the SANs.",
                    "sans": {
                        "DNS": [
                            "demo.nautobot.com"
                        ],
                        "IP Address": []
                    },
                    "count": 1,
                    "contains_host": {
                        "name": "demo.nautobot.com",
                        "is_valid": true,
                        "reason": "Exact match for demo.nautobot.com found in DNS SANs"
                    },
                    "contains_alternate": {
                        "example.com": {
                            "name": "example.com",
                            "is_valid": false,
                            "reason": "No match found for example.com in DNS SANs: ['demo.nautobot.com']"
                        }
                    },
                    "warnings": [
                        "Alternate name example.com: No match found for example.com in DNS SANs: ['demo.nautobot.com']"
                    ]
                }
                ```
        """
        normalized = normalize_sans(cert.get("cert_info", {}).get("subjectAltName"))
        sans = {kind: normalized[kind] for kind in ("DNS", "IP Address")}
        primary = match_identity(host, sans)
        result: SubjectAltNamesResult = {
            "is_valid": False,
            "sans": sans if "subjectAltName" in cert.get("cert_info", {}) else None,
            "count": sum(len(names) for names in sans.values()),
            "contains_host": {
                "name": host,
                "is_valid": primary.is_valid,
                "reason": primary.reason,
            },
            "contains_alternate": {},
            "warnings": [],
        }
        if result["count"] > 100:
            result["warnings"].append(
                f"Certificate contains an unusually high number of SANs ({result['count']})"
            )
        if not alternate_names:
            if not host:
                result["status"] = "unsupported"
                result["reason"] = (
                    "No names to check: pass alternate_names, or load the certificate "
                    "with a host."
                )
                return result
            result["is_valid"] = primary.is_valid
            if not primary.is_valid:
                result["reason"] = (
                    f"The hostname/IP {host} is not included in the SANs: {primary.reason}"
                )
            return result
        if not isinstance(alternate_names, (list, tuple)) or not all(
            isinstance(name, str) and name for name in alternate_names
        ):
            raise ValueError("alternate_names must be a list of non-empty strings")
        for name in alternate_names:
            match = match_identity(name, sans)
            result["contains_alternate"][name] = {
                "name": name,
                "is_valid": match.is_valid,
                "reason": match.reason,
            }
            if not match.is_valid:
                result["warnings"].append(f"Alternate name {name}: {match.reason}")
        result["is_valid"] = all(
            item["is_valid"] for item in result["contains_alternate"].values()
        )
        if not result["is_valid"]:
            result["reason"] = (
                "One or more required alternate names are absent from the SANs."
            )
        return result
