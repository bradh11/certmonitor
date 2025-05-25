# validators/root_certificate_validator.py

from .base import BaseCertValidator


class RootCertificateValidator(BaseCertValidator):
    """
    A validator for checking if the SSL certificate is issued by a trusted root CA.

    Attributes:
        name (str): The name of the validator.
    """

    name = "root_certificate"

    def validate(self, cert, host, port) -> dict:
        """
        Validates if the SSL certificate is issued by a trusted root CA.

        Args:
            cert (dict): The SSL certificate.
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
                This example shows a certificate that is not signed by a trusted root CA, so validation fails and warnings are included.

                {
                  "is_valid": false,
                  "issuer": {
                    "commonName": "Unknown",
                    "organizationName": "Unknown"
                  },
                  "warnings": [
                    "Certificate does not provide OCSP information.",
                    "Certificate does not provide caIssuers information.",
                    "Certificate is self-signed.",
                    "The certificate is issued by an untrusted root CA: Unknown (Unknown)"
                  ]
                }
        """
        cert_info = cert.get("cert_info", {})
        issuer = cert_info.get("issuer", {})
        subject = cert_info.get("subject", {})
        common_name = issuer.get("commonName", "Unknown")
        organization_name = issuer.get("organizationName", "Unknown")

        # Check for presence of OCSP and caIssuers fields
        has_ocsp = bool(cert_info.get("OCSP"))
        has_ca_issuers = bool(cert_info.get("caIssuers"))

        # Check if the certificate is self-signed
        is_self_signed = issuer == subject and issuer != {}

        # Heuristic check: If the issuer's common name or organization name contains 'Untrusted', flag it
        is_trusted = (
            (has_ocsp and has_ca_issuers)
            and not is_self_signed
            and (
                "untrusted" not in common_name.lower()
                and "untrusted" not in organization_name.lower()
            )
        )

        warnings = []
        if not has_ocsp:
            warnings.append("Certificate does not provide OCSP information.")
        if not has_ca_issuers:
            warnings.append("Certificate does not provide caIssuers information.")
        if is_self_signed:
            warnings.append("Certificate is self-signed.")
        if not is_trusted:
            warnings.append(
                f"The certificate is issued by an untrusted root CA: {organization_name} ({common_name})"
            )

        return {
            "is_valid": is_trusted,
            "issuer": issuer,
            "warnings": warnings,
        }
