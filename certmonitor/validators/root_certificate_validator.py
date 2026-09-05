from typing import Any, ClassVar, cast
from .base import BaseCertValidator
from .results import ValidationResult


class RootCertificateResult(ValidationResult, total=False):
    """Result shape for `RootCertificateValidator` (envelope + data)."""

    issuer: dict[str, Any]
    trust_verified: bool
    revocation_status: str


class RootCertificateValidator(BaseCertValidator):
    """
    A validator for checking if the SSL certificate is issued by a trusted root CA.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "root_certificate"
    requires: ClassVar[tuple[str, ...]] = ("verified_trust",)

    def validate(
        self, cert: dict[str, Any], host: str, port: int
    ) -> RootCertificateResult:
        """
        Validates if the SSL certificate is issued by a trusted root CA.

        This reports the dispatcher's separate, cryptographically verified TLS
        handshake against the system or configured CA store. The verified leaf
        must match the collected snapshot. Metadata alone cannot establish trust;
        a direct call without verification evidence reports TrustNotVerified.
        Revocation is not checked.

        Args:
            cert (dict): Verified-trust evidence from the dispatcher, including the issuer.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).

        Returns:
            dict: A dictionary containing the validation results, including whether the certificate is valid,
                  and any warnings or reasons for validation failure.

        Examples:
            Example output (success):
                This example shows a certificate that is signed by a trusted root CA, so validation passes and no warnings are present.

                {
                  "is_valid": true,
                  "issuer": {
                    "commonName": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                    "organizationName": "DigiCert Inc"
                  },
                  "warnings": []
                }

            Example output (failure):
                This example shows a certificate that is not signed by a trusted root CA, so validation fails and a verification reason is included.

                {
                  "is_valid": false,
                  "issuer": {
                    "commonName": "Unknown",
                    "organizationName": "Unknown"
                  },
                  "warnings": [],
                  "status": "fail",
                  "trust_verified": false,
                  "verify_code": 18,
                  "reason": "certificate verify failed: self-signed certificate"
                }
        """
        if "is_valid" in cert and "status" in cert:
            result = cast(RootCertificateResult, dict(cert))
            result.setdefault("issuer", {})
            result.setdefault("warnings", [])
            return result
        return {
            "is_valid": False,
            "issuer": cert.get("cert_info", {}).get("issuer", {}),
            "warnings": [],
            "status": "error",
            "error": "TrustNotVerified",
            "reason": "Certificate metadata alone cannot establish trust.",
        }
