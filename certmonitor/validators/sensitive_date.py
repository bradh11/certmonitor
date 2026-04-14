# validators/sensitive_date.py

"""
Module for validating SSL certificates against specified sensitive dates.
"""

from datetime import date, datetime
from typing import Any, Dict, List, NamedTuple, Optional, Tuple, Union

from ._utils import parse_not_after
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


# Any of these forms may appear in the ``dates`` argument of
# :meth:`SensitiveDateValidator.validate`. They are all normalized internally
# to a :class:`SensitiveDate`.
SensitiveDateInput = Union[
    SensitiveDate,
    date,
    str,
    Tuple[str, date],
]


def _normalize(item: Any) -> SensitiveDate:
    """Coerce a user-supplied sensitive-date entry to a ``SensitiveDate``.

    Accepted forms:
      - ``SensitiveDate`` — returned as-is.
      - ``datetime`` — truncated to its date; name defaults to the ISO date.
      - ``date`` — wrapped with an ISO-date name.
      - ``str`` — parsed as ISO 8601 (``YYYY-MM-DD``); name defaults to the string.
      - ``(name, date)`` tuple — unpacked into a ``SensitiveDate``.

    Raises:
        TypeError: if ``item`` matches none of the accepted shapes.
        ValueError: if a string cannot be parsed as an ISO date.
    """
    if isinstance(item, SensitiveDate):
        return item
    # ``datetime`` is a subclass of ``date``, so check it first.
    if isinstance(item, datetime):
        truncated = item.date()
        return SensitiveDate(name=truncated.isoformat(), date=truncated)
    if isinstance(item, date):
        return SensitiveDate(name=item.isoformat(), date=item)
    if isinstance(item, str):
        parsed = date.fromisoformat(item)
        return SensitiveDate(name=item, date=parsed)
    if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
        name, value = item
        if isinstance(value, datetime):
            value = value.date()
        if not isinstance(value, date):
            raise TypeError(
                f"Second element of (name, date) tuple must be a date, "
                f"got {type(value).__name__}: {value!r}"
            )
        return SensitiveDate(name=name, date=value)
    raise TypeError(
        f"Expected SensitiveDate, date, ISO date string, or (name, date) tuple; "
        f"got {type(item).__name__}: {item!r}"
    )


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
        dates: Optional[List[SensitiveDateInput]] = None,
    ) -> Dict[str, Any]:
        """
        Validates the sensitivity of the expiry date of the provided SSL certificate.

        Args:
            cert (dict): The SSL certificate.
            host (str): The hostname (not used in this validator).
            port (int): The port number (not used in this validator).
            dates (list, optional): Sensitive dates to match against the
                certificate's expiration date. Each entry may be a
                ``SensitiveDate``, a plain ``date`` / ``datetime``, an ISO date
                string (``"2025-12-25"``), or a ``(name, date)`` tuple.
                Defaults to ``None`` (no sensitive-date matching; weekend and
                leap-day checks still run).

        Returns:
            dict: A dictionary containing:

                - ``is_valid`` (bool): ``True`` iff none of the checks fired.
                - ``leapday_expiry`` (bool): certificate expires on Feb 29.
                - ``weekend_expiry`` (bool): certificate expires on Saturday/Sunday.
                - ``sensitive_date_matches`` (list): structured records of any
                  user-supplied dates that matched, each with ``name`` and
                  ``date`` (ISO 8601 string).
                - ``warnings`` (list of str): human-readable summary lines for
                  every condition that fired.

        Examples:
            Example output (success):

                ```json
                {
                    "is_valid": true,
                    "leapday_expiry": false,
                    "weekend_expiry": false,
                    "sensitive_date_matches": [],
                    "warnings": []
                }
                ```

            Example output (failure):

                ```json
                {
                    "is_valid": false,
                    "leapday_expiry": false,
                    "weekend_expiry": true,
                    "sensitive_date_matches": [
                        {"name": "Busy Sunday", "date": "2025-11-16"}
                    ],
                    "warnings": [
                        "Certificate expires on a weekend (Sunday)",
                        "Certificate is due to expire on sensitive date \\"Busy Sunday\\" (2025-11-16)"
                    ]
                }
                ```
        """
        normalized: List[SensitiveDate] = []
        if dates:
            for item in dates:
                try:
                    normalized.append(_normalize(item))
                except (TypeError, ValueError) as exc:
                    return {
                        "is_valid": False,
                        "reason": f"Invalid sensitive date input: {exc}",
                        "leapday_expiry": False,
                        "weekend_expiry": False,
                        "sensitive_date_matches": [],
                        "warnings": [],
                    }

        not_after = parse_not_after(cert)
        expiry_date = not_after.date()
        weekday = not_after.weekday()

        leapday_expiry = expiry_date.month == 2 and expiry_date.day == 29
        weekend_expiry = weekday in (5, 6)

        warnings: List[str] = []
        if leapday_expiry:
            warnings.append(
                f"Certificate expires on a leap day ({expiry_date.isoformat()})"
            )
        if weekend_expiry:
            day_name = "Saturday" if weekday == 5 else "Sunday"
            warnings.append(f"Certificate expires on a weekend ({day_name})")

        sensitive_date_matches: List[Dict[str, str]] = []
        for sd in normalized:
            if expiry_date == sd.date:
                sensitive_date_matches.append(
                    {"name": sd.name, "date": sd.date.isoformat()}
                )
                warnings.append(
                    f'Certificate is due to expire on sensitive date "{sd.name}"'
                    f" ({sd.date.isoformat()})"
                )

        is_valid = not (leapday_expiry or weekend_expiry or sensitive_date_matches)

        return {
            "is_valid": is_valid,
            "leapday_expiry": leapday_expiry,
            "weekend_expiry": weekend_expiry,
            "sensitive_date_matches": sensitive_date_matches,
            "warnings": warnings,
        }
