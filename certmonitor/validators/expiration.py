# validators/expiration.py

import datetime
from typing import Any, cast

from ._utils import parse_not_after, parse_not_before
from .base import BaseCertValidator
from .results import ValidationResult

# CA/Browser Forum maximum validity for publicly trusted TLS certificates,
# keyed on the certificate's issue date. Ballot SC-081 (2025) set the 200,
# 100, and 47 day steps; 398 came from the 2020 baseline and 825 from 2018.
PUBLIC_TLS_LIFETIME_SCHEDULE: tuple[tuple[datetime.date, int], ...] = (
    (datetime.date(2029, 3, 15), 47),
    (datetime.date(2027, 3, 15), 100),
    (datetime.date(2026, 3, 15), 200),
    (datetime.date(2020, 9, 1), 398),
    (datetime.date(2018, 3, 1), 825),
)
PUBLIC_TLS_POLICY = "public"


def public_tls_lifetime_limit(issued: datetime.date) -> int:
    """Return the public TLS validity limit in days for a certificate issued on `issued`."""
    for start, limit in PUBLIC_TLS_LIFETIME_SCHEDULE:
        if issued >= start:
            return limit
    return 1187  # 39 months, the limit before March 2018


class ExpirationResult(ValidationResult, total=False):
    """Result shape for `ExpirationValidator` (envelope + data)."""

    days_to_expiry: int
    expires_on: str
    lifetime_days: int
    lifetime_limit_days: int


class ExpirationValidator(BaseCertValidator):
    """
    A validator for checking the expiration date of an SSL certificate.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "expiration"

    def validate(
        self,
        cert: dict[str, Any],
        host: str,
        port: int,
        *,
        warning_days: float = 7,
        critical_days: float = 1,
        max_lifetime_days: float | str | None = PUBLIC_TLS_POLICY,
    ) -> ExpirationResult:
        """
        Validates the validity window of the provided SSL certificate and its total lifetime.

        The certificate fails when it is expired or not yet valid. Approaching
        expiry and an over-long total lifetime are reported as warnings, so
        `is_valid` stays `True` while `status` becomes `warn`.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).
            warning_days (float): Warn when this many days or fewer remain. Defaults to 7.
            critical_days (float): Use a critical warning within this many days. Defaults to 1.
            max_lifetime_days (float | str, optional): Warn when the total lifetime from
                notBefore to notAfter exceeds this many days. Defaults to `"public"`, the
                CA/Browser Forum limit that applied on the certificate's issue date (825
                days from March 2018, 398 from September 2020, 200 from March 2026, 100
                from March 2027, 47 from March 2029). Pass a number to set your own limit
                for a private PKI, or `None` to disable the check. Fractional-day
                thresholds are supported, including less than one day remaining.

        Returns:
            dict: A dictionary containing the validation results, including whether the certificate is valid,
                  the number of days until expiry, the expiration date, the total lifetime in days
                  and the limit it was compared with (when notBefore is available), and any warnings.

        Raises:
            ValueError: If thresholds do not satisfy 0 <= critical_days <= warning_days,
                or max_lifetime_days is neither `"public"`, a positive number, nor `None`.

        Examples:
            Example output (success):
                This example shows a certificate that is valid and has 120 days until expiration, so no warnings are present.

                ```json
                {
                    "is_valid": true,
                    "days_to_expiry": 120,
                    "expires_on": "2025-09-01T23:59:59+00:00",
                    "lifetime_days": 365,
                    "lifetime_limit_days": 398,
                    "warnings": []
                }
                ```

            Example output (failure):
                This example shows a certificate that expired 10 days ago, so validation fails and a warning is included.

                ```json
                {
                    "is_valid": false,
                    "days_to_expiry": -10,
                    "expires_on": "2025-04-30T23:59:59+00:00",
                    "lifetime_days": 365,
                    "lifetime_limit_days": 398,
                    "warnings": [
                        "Certificate is expired and has been expired for (-10 days)"
                    ],
                    "reason": "Certificate expired 10 days ago (expired on 2025-04-30)."
                }
                ```
        """
        if not 0 <= critical_days <= warning_days:
            raise ValueError("Require 0 <= critical_days <= warning_days")
        if (
            isinstance(max_lifetime_days, str)
            and max_lifetime_days != PUBLIC_TLS_POLICY
        ):
            raise ValueError(
                f'max_lifetime_days must be "{PUBLIC_TLS_POLICY}", a positive number, or None'
            )
        if isinstance(max_lifetime_days, (int, float)) and max_lifetime_days <= 0:
            raise ValueError("max_lifetime_days must be positive")
        utc = datetime.timezone.utc
        now = datetime.datetime.now(utc)
        not_after = parse_not_after(cert).replace(tzinfo=utc)
        parsed_before = parse_not_before(cert)
        not_before = parsed_before.replace(tzinfo=utc) if parsed_before else None
        remaining = not_after - now
        warnings: list[str] = []
        result: ExpirationResult = {
            "is_valid": now < not_after and (not_before is None or now >= not_before),
            "days_to_expiry": remaining.days,
            "expires_on": not_after.isoformat(),
            "warnings": warnings,
        }
        if now >= not_after:
            result["reason"] = (
                f"Certificate expired {abs(remaining.days)} days ago "
                f"(expired on {not_after.date().isoformat()})."
            )
            warnings.append(
                f"Certificate is expired and has been expired for ({remaining.days} days)"
            )
        elif not_before is not None and now < not_before:
            result["reason"] = "Certificate is not yet valid."
        elif remaining <= datetime.timedelta(days=critical_days):
            warnings.append(
                f"Certificate is expiring within the critical threshold "
                f"({remaining.days} days remaining, threshold {critical_days} days)."
            )
        elif remaining <= datetime.timedelta(days=warning_days):
            warnings.append(
                f"Certificate is expiring within the warning threshold "
                f"({remaining.days} days remaining, threshold {warning_days} days)."
            )

        if not_before is not None:
            lifetime = not_after - not_before
            result["lifetime_days"] = lifetime.days
            limit: float | None
            if max_lifetime_days == PUBLIC_TLS_POLICY:
                limit = public_tls_lifetime_limit(not_before.date())
                label = (
                    f"{limit}-day public TLS limit for certificates issued on "
                    f"{not_before.date().isoformat()}"
                )
            else:
                limit = cast("float | None", max_lifetime_days)
                label = f"{limit}-day limit"
            if limit is not None:
                result["lifetime_limit_days"] = int(limit)
                if lifetime > datetime.timedelta(days=limit):
                    warnings.append(
                        f"Certificate total lifetime ({lifetime.days} days) exceeds the {label}."
                    )
        return result
