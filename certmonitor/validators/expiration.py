# validators/expiration.py

import datetime
from typing import Any, Dict

from .base import BaseCertValidator


class ExpirationValidator(BaseCertValidator):
    """
    A validator for checking the expiration date of an SSL certificate.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "expiration"

    def validate(self, cert: Dict[str, Any], host: str, port: int) -> Dict[str, Any]:
        """
        Validates the expiration date of the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).

        Returns:
            dict: A dictionary containing the validation results, including whether the certificate is valid,
                  the number of days until expiry, the expiration date, and any warnings.

        Examples:
            Example output (success):
                This example shows a certificate that is valid and has 120 days until expiration, so no warnings are present.

                ```json
                {
                    "is_valid": true,
                    "days_to_expiry": 120,
                    "expires_on": "2025-09-01T23:59:59",
                    "warnings": []
                }
                ```

            Example output (failure):
                This example shows a certificate that expired 10 days ago, so validation fails and a warning is included.

                ```json
                {
                    "is_valid": false,
                    "days_to_expiry": -10,
                    "expires_on": "2025-04-30T23:59:59",
                    "warnings": [
                        "Certificate is expired and has been expired for (-10 days)"
                    ]
                }
                ```
        """
        now = datetime.datetime.now(datetime.UTC)
        not_after = datetime.datetime.strptime(
            cert["cert_info"]["notAfter"], "%b %d %H:%M:%S %Y GMT"
        ).replace(tzinfo=datetime.UTC)

        is_valid = now < not_after
        days_to_expiry = (not_after - now).days

        warnings = []
        if days_to_expiry < 0:
            warnings.append(
                f"Certificate is expired and has been expired for ({days_to_expiry} days)"
            )
        if days_to_expiry < 7 and days_to_expiry > 0:
            warnings.append(
                f"Certificate is expiring in less than 1 week ({days_to_expiry} days)"
            )
        if days_to_expiry > 398:
            warnings.append(
                f"Certificate is valid for more than industry standard ({days_to_expiry}/398 days)"
            )

        return {
            "is_valid": is_valid,
            "days_to_expiry": days_to_expiry,
            "expires_on": not_after.isoformat(),
            "warnings": warnings,
        }
