# validators/sensitive_date.py

"""
Module for validating SSL certificates against specified sensitive dates.
"""

from datetime import datetime, date
from typing import Any, Dict, List, NamedTuple, Optional

from .base import BaseCertValidator


class SensitiveDate(NamedTuple):
    """
    Represents a date associated with a named sensitive event.

    Attributes:
        name (str): A descriptive name for the sensitive date (e.g. "Busy Sunday").
        date (date): The calendar date of the event, stored as a datetime.date object.
    """

    name: str
    date: date


class SensitiveDateValidator(BaseCertValidator):
    """
    A validator for checking if an SSL certificate expires on a sensitive/special date.


    Attributes:
        name (str): The name of the validator.
    """

    name = "sensitive_date"

    def validate(
        self,
        cert: Dict[str, Any],
        host: str,
        port: int,
        *,
        dates: Optional[List[SensitiveDate]] = None,
    ) -> Dict[str, Any]:
        """
        Validates the sensitivity of the expiry date of the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).
            dates (list, optional): A list of ``SensitiveDate`` objects to check
                against the certificate's expiration date. Defaults to ``None``
                (no sensitive-date matching, only weekend/leap-day checks).

        Returns:
            dict: A dictionary containing the validation results, including whether the certificate
                expires on a weekend, a leap day, or on any of the passed-in dates.

        Examples:
            Example output (success):

                ```json
                {
                    "is_valid": true,
                    "leapday_expiry": false,
                    "weekend_expiry": false,
                    "warnings": []
                }
                ```

            Example output (failure):

                ```json
                {
                    "is_valid": false,
                    "leapday_expiry": false,
                    "weekend_expiry": true,
                    "warnings": [
                        'Certificate is due to expire on sensitive date "Busy Sunday" (2025-11-16)'
                    ]
                }
                ```
        """
        sensitive_dates: List[SensitiveDate] = list(dates) if dates else []

        for sd in sensitive_dates:
            if not isinstance(sd, SensitiveDate):
                raise TypeError(
                    f"Expected SensitiveDate, got {type(sd).__name__}: {sd!r}"
                )

        not_after = datetime.strptime(
            cert["cert_info"]["notAfter"], "%b %d %H:%M:%S %Y GMT"
        )

        leapday_expiry = not_after.month == 2 and not_after.day == 29
        weekend_expiry = not_after.weekday() in (5, 6)

        warnings = []
        for sensitive_date in sensitive_dates:
            if not_after.date() == sensitive_date.date:
                warnings.append(
                    f'Certificate is due to expire on sensitive date "{sensitive_date.name}"'
                    f" ({sensitive_date.date.isoformat()})"
                )

        is_valid = not (leapday_expiry or warnings or weekend_expiry)

        return {
            "is_valid": is_valid,
            "leapday_expiry": leapday_expiry,
            "weekend_expiry": weekend_expiry,
            "warnings": warnings,
        }
