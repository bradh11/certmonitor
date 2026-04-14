# validators/_utils.py

"""Shared helpers for the built-in validators.

These are package-private (leading underscore) and not part of the public API.
"""

from datetime import datetime
from typing import Any, Dict

_NOT_AFTER_FORMAT = "%b %d %H:%M:%S %Y GMT"


def parse_not_after(cert: Dict[str, Any]) -> datetime:
    """Parse the ``notAfter`` field from a validator's ``cert`` argument.

    Centralizes the format string so that any future change to how certmonitor
    surfaces expiration timestamps only has to be made in one place. Returns a
    naive ``datetime`` in UTC; callers that need timezone-aware datetimes
    should attach ``timezone.utc`` themselves (as ``expiration`` does).
    """
    return datetime.strptime(cert["cert_info"]["notAfter"], _NOT_AFTER_FORMAT)
