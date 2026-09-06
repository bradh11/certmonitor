"""Shared SAN normalization and TLS DNS/IP identity matching."""

import ipaddress
from typing import Any, NamedTuple


class IdentityMatch(NamedTuple):
    """Outcome of matching one identity against a certificate's SANs.

    `matched_name` is the SAN entry that matched (an exact name, a wildcard
    pattern, or an IP address) or `None` when nothing matched. `kind` is
    `"dns"` or `"ip"` depending on how the identity was interpreted.
    """

    is_valid: bool
    reason: str
    matched_name: str | None
    kind: str


def normalize_sans(raw: Any) -> dict[str, list[str]]:
    """Return SANs grouped by type, always including DNS and IP Address lists.

    Accepts the dict form produced by `CertMonitor` as well as the raw
    `getpeercert()` sequence of `(type, value)` pairs. Singleton values are
    wrapped in a list and non-string entries are dropped.
    """
    result: dict[str, list[str]] = {"DNS": [], "IP Address": []}
    entries = raw.items() if isinstance(raw, dict) else (raw or [])
    for kind, values in entries:
        values = [values] if isinstance(values, str) else (values or [])
        result.setdefault(kind, []).extend(v for v in values if isinstance(v, str))
    return result


def dns_match(host: str, pattern: str) -> bool:
    """Return True if `host` matches the DNS SAN `pattern` (RFC 6125 rules)."""
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
        pattern = pattern.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False
    if not host or not pattern or "*" in host:
        return False
    if "*" not in pattern:
        return host == pattern
    return (
        pattern.startswith("*.")
        and pattern.count("*") == 1
        and len(host.split(".")) == len(pattern.split("."))
        and bool(host.split(".")[0])
        and host.split(".")[1:] == pattern.split(".")[1:]
    )


def match_identity(name: str, sans: dict[str, list[str]]) -> IdentityMatch:
    """Match a DNS name or IP address against the normalized SANs."""
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        for pattern in sans["DNS"]:
            if dns_match(name, pattern):
                reason = (
                    f"{name} matches wildcard SAN(s): {pattern}"
                    if "*" in pattern
                    else f"Exact match for {name} found in DNS SANs"
                )
                return IdentityMatch(True, reason, pattern, "dns")
        return IdentityMatch(
            False, f"No match found for {name} in DNS SANs: {sans['DNS']}", None, "dns"
        )
    for candidate in sans["IP Address"]:
        try:
            if address == ipaddress.ip_address(candidate):
                return IdentityMatch(
                    True,
                    f"Exact match for IP {name} found in IP Address SANs",
                    candidate,
                    "ip",
                )
        except ValueError:
            continue
    return IdentityMatch(
        False,
        f"No match found for IP {name} in IP Address SANs: {sans['IP Address']}",
        None,
        "ip",
    )
