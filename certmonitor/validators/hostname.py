from typing import Any

from ..utils.identity import dns_match, match_identity, normalize_sans
from .base import BaseCertValidator
from .results import ValidationResult


class HostnameResult(ValidationResult, total=False):
    """Result shape for `HostnameValidator` (envelope + data)."""

    matched_name: str
    alt_names: list[str]
    common_name: str | None
    common_name_matches: bool
    identity_source: str


class HostnameValidator(BaseCertValidator):
    """
    A validator for checking the hostname in an SSL certificate.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "hostname"

    def validate(
        self,
        cert: dict[str, Any],
        host: str,
        port: int,
        *,
        expected_identity: str | None = None,
    ) -> HostnameResult:
        """
        Validates the hostname against the Subject Alternative Names (SANs) in the provided SSL certificate.

        Common Name is also reported in `common_name` and `common_name_matches`
        for inspection. It never overrides the SAN-based `is_valid` result.
        DNS matching is case-insensitive, and IP identities match IP Address SANs.
        `matched_name` is the SAN entry that matched: the exact name, the
        wildcard pattern, or the IP address.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname to validate.
            port (int): The port number.
            expected_identity (str, optional): A DNS name or IP address to check instead
                of `host`. Use it when the monitor connects by one name or address but
                the certificate must be valid for another. Defaults to `None`.

        Returns:
            dict: A dictionary containing the validation results, including whether the hostname is valid,
                  the reason for validation failure, and the alternative names (SANs) in the certificate.

        Examples:
            Example output (success):
                This example shows a certificate where the hostname matches one of the DNS SANs, so validation passes and the matched name is shown.

                {
                    "is_valid": true,
                    "matched_name": "example.com",
                    "alt_names": [
                        "example.com",
                        "www.example.com"
                    ]
                }

            Example output (failure):
                This example shows a certificate where the hostname does not match any DNS SAN, so validation fails and a reason is provided.

                {
                    "is_valid": false,
                    "reason": "Hostname test.example.com doesn't match any of the certificate's subject alternative names",
                    "alt_names": [
                        "example.com",
                        "www.example.com"
                    ]
                }
        """
        host = expected_identity or host
        info = cert.get("cert_info", {})
        sans = normalize_sans(info.get("subjectAltName"))
        match = match_identity(host, sans)
        subject = info.get("subject", {})
        if not isinstance(subject, dict):
            subject = dict(pair for rdn in subject for pair in rdn)
        common_name = subject.get("commonName")
        if not isinstance(common_name, str):
            common_name = None
        result: HostnameResult = {
            "is_valid": match.is_valid,
            "alt_names": sans["DNS"] + sans["IP Address"],
            "identity_source": "subjectAltName",
            "common_name": common_name,
            "common_name_matches": common_name is not None
            and dns_match(host, common_name),
        }
        if match.is_valid:
            result["matched_name"] = match.matched_name or host
            return result

        if "subjectAltName" not in info:
            reason = "Certificate does not contain a Subject Alternative Name extension"
        elif match.kind == "dns":
            reason = (
                f"Hostname {host} doesn't match any of the certificate's subject alternative names"
                if sans["DNS"]
                else "Certificate does not contain any DNS SANs"
            )
        else:
            reason = match.reason
        result["reason"] = reason
        return result
