# validators/_utils.py

"""Shared helpers for the built-in validators.

These are package-private (leading underscore) and not part of the public API.
"""

from datetime import datetime
from typing import Any

# The format OpenSSL uses for `notBefore` and `notAfter` in `getpeercert()`.
_VALIDITY_FORMAT = "%b %d %H:%M:%S %Y GMT"
_NOT_AFTER_FORMAT = _VALIDITY_FORMAT


def parse_not_after(cert: dict[str, Any]) -> datetime:
    """Parse the `notAfter` field from a validator's `cert` argument.

    Centralizes the format string so that any future change to how certmonitor
    surfaces expiration timestamps only has to be made in one place. Returns a
    naive `datetime` in UTC; callers that need timezone-aware datetimes
    should attach `timezone.utc` themselves (as `expiration` does).
    """
    return datetime.strptime(cert["cert_info"]["notAfter"], _VALIDITY_FORMAT)


def parse_not_before(cert: dict[str, Any]) -> datetime | None:
    """Parse the optional `notBefore` field from a validator's `cert` argument.

    Returns `None` when the field is absent or not a string, so callers can
    skip validity-start checks instead of failing on partial certificate data.
    Like `parse_not_after`, the result is a naive UTC `datetime`.
    """
    value = cert["cert_info"].get("notBefore")
    if not isinstance(value, str):
        return None
    return datetime.strptime(value, _VALIDITY_FORMAT)
