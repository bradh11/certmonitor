"""Compare two certificate observations and explain what changed.

`compare_snapshots()` takes yesterday's and today's observation of the same
endpoint, in any of the shapes CertMonitor produces (`get_cert_info()`,
`cert_data`, a `scan_hosts()` result, or an entry from `certmonitor check
--json`), and reports whether the certificate was replaced, what differs,
and whether the difference looks like a routine renewal or something that
deserves attention. Storage is the caller's business: keep the JSON
wherever your automation keeps it and hand two copies here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .validators._utils import parse_not_after, parse_not_before

SEVERITIES = ("info", "notice", "warning")

# Key sizes below which a change to that algorithm counts as weakening.
_KEY_FLOORS = {"rsaEncryption": 2048, "ecPublicKey": 256}


def _certificate(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Pull the parsed certificate fields out of any supported snapshot shape."""
    for key in ("certificate", "cert_info"):
        inner = snapshot.get(key)
        if isinstance(inner, dict):
            return inner
    return snapshot


def _scan_error(snapshot: dict[str, Any]) -> str | None:
    """`"Error: message"` when the snapshot is a failed scan, else `None`."""
    if not isinstance(snapshot.get("error"), str) or snapshot.get("results"):
        return None
    message = snapshot.get("message")
    return f"{snapshot['error']}: {message}" if message else str(snapshot["error"])


def _results(snapshot: dict[str, Any]) -> dict[str, Any]:
    results = snapshot.get("results")
    return results if isinstance(results, dict) else {}


def _fingerprint(snapshot: dict[str, Any], certificate: dict[str, Any]) -> str | None:
    value = snapshot.get("fingerprint_sha256") or certificate.get("fingerprint_sha256")
    return str(value) if value else None


def _sans(certificate: dict[str, Any]) -> set[str]:
    raw = certificate.get("subjectAltName") or {}
    names: set[str] = set()
    if isinstance(raw, dict):
        for kind in ("DNS", "IP Address"):
            values = raw.get(kind) or []
            names.update(
                f"{kind}:{v}" for v in ([values] if isinstance(values, str) else values)
            )
    return names


def _validity(certificate: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    wrapper = {"cert_info": certificate}
    try:
        not_after = parse_not_after(wrapper) if certificate.get("notAfter") else None
    except (KeyError, ValueError, TypeError):
        not_after = None
    try:
        not_before = parse_not_before(wrapper)
    except (KeyError, ValueError, TypeError):
        not_before = None
    return not_before, not_after


def _key(
    snapshot: dict[str, Any], results: dict[str, Any]
) -> tuple[str | None, int | None]:
    info = snapshot.get("public_key_info")
    if isinstance(info, dict) and "algorithm" in info:
        return info.get("algorithm"), info.get("size")
    key_info = results.get("key_info") or {}
    return key_info.get("key_type"), key_info.get("key_size")


def _name(dn: Any) -> str:
    if isinstance(dn, dict):
        return dn.get("commonName") or dn.get("organizationName") or str(dn)
    return str(dn)


def compare_snapshots(
    previous: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Explain how `current` differs from `previous` for the same endpoint.

    Args:
        previous: The earlier observation.
        current: The later observation, in the same or any other supported shape.

    Returns:
        dict: `changed` and `replaced` booleans; `severity` (`"info"` for no
        change or a routine renewal, `"notice"` for changes worth a look,
        `"warning"` for changes that usually mean trouble); a `findings` list of
        one-sentence explanations; and detail sections `fingerprint`, `validity`,
        `sans`, `issuer`, `subject`, `key`, and `status_changes`, each present
        only when that aspect changed. `status_changes` also records checks
        that appeared or disappeared between the two runs. When either
        snapshot is a failed scan, a `scan_error` section carries the error
        and no field-by-field comparison is attempted.

    Example:
        ```python
        from certmonitor.compare import compare_snapshots

        report = compare_snapshots(yesterday, today)
        if report["severity"] == "warning":
            alert("\\n".join(report["findings"]))
        ```
    """
    before, after = _certificate(previous), _certificate(current)
    before_results, after_results = _results(previous), _results(current)
    findings: list[str] = []
    detail: dict[str, Any] = {}
    severity = "info"

    def raise_to(level: str) -> None:
        nonlocal severity
        if SEVERITIES.index(level) > SEVERITIES.index(severity):
            severity = level

    # A scan that failed outright has no certificate to compare. Say so
    # instead of reporting every field as "changed to None".
    errors = {
        side: error
        for side, snapshot in (("previous", previous), ("current", current))
        if (error := _scan_error(snapshot)) is not None
    }
    if errors:
        detail["scan_error"] = errors
        if "current" in errors:
            findings.append(
                f"The current scan failed ({errors['current']}); the certificate "
                "could not be observed."
            )
            raise_to("warning")
        else:
            findings.append(
                f"The previous scan failed ({errors['previous']}); this is the first "
                "successful observation, so there is nothing to compare against."
            )
            raise_to("notice")
        return {
            "changed": "current" in errors,
            "replaced": False,
            "severity": severity,
            "findings": findings,
            **detail,
        }

    old_fp, new_fp = _fingerprint(previous, before), _fingerprint(current, after)
    replaced = bool(old_fp and new_fp and old_fp != new_fp) or (
        not (old_fp and new_fp)
        and before.get("serialNumber") != after.get("serialNumber")
    )
    if replaced:
        detail["fingerprint"] = {"previous": old_fp, "current": new_fp}
        findings.append("The certificate was replaced.")

    old_before, old_after = _validity(before)
    new_before, new_after = _validity(after)
    if old_after and new_after and old_after != new_after:
        delta = (new_after - old_after).days
        detail["validity"] = {
            "previous_not_after": old_after.isoformat(),
            "current_not_after": new_after.isoformat(),
            "extended_days": delta,
        }
        if delta > 0:
            findings.append(
                f"Validity was extended by {delta} days (now expires {new_after.date().isoformat()})."
            )
        else:
            findings.append(
                f"Validity was shortened by {-delta} days (now expires {new_after.date().isoformat()})."
            )
            raise_to("notice")
    if old_before and new_before and old_before != new_before:
        detail.setdefault("validity", {}).update(
            previous_not_before=old_before.isoformat(),
            current_not_before=new_before.isoformat(),
        )

    added, removed = (
        sorted(_sans(after) - _sans(before)),
        sorted(_sans(before) - _sans(after)),
    )
    if added or removed:
        detail["sans"] = {"added": added, "removed": removed}
        if removed:
            findings.append("Names removed from the SANs: " + ", ".join(removed) + ".")
            raise_to("warning")
        if added:
            findings.append("Names added to the SANs: " + ", ".join(added) + ".")
            raise_to("notice")

    if before.get("issuer") != after.get("issuer") and (
        before.get("issuer") or after.get("issuer")
    ):
        detail["issuer"] = {
            "previous": before.get("issuer"),
            "current": after.get("issuer"),
        }
        findings.append(
            f"Issuer changed from {_name(before.get('issuer'))} to {_name(after.get('issuer'))}."
        )
        raise_to("warning")

    if before.get("subject") != after.get("subject") and (
        before.get("subject") or after.get("subject")
    ):
        detail["subject"] = {
            "previous": before.get("subject"),
            "current": after.get("subject"),
        }
        findings.append(
            f"Subject changed from {_name(before.get('subject'))} to {_name(after.get('subject'))}."
        )
        raise_to("notice")

    old_alg, old_size = _key(previous, before_results)
    new_alg, new_size = _key(current, after_results)
    if (old_alg or new_alg) and (old_alg, old_size) != (new_alg, new_size):
        detail["key"] = {
            "previous": {"algorithm": old_alg, "size": old_size},
            "current": {"algorithm": new_alg, "size": new_size},
        }
        weaker = (
            old_alg == new_alg and old_size and new_size and new_size < old_size
        ) or (new_alg in _KEY_FLOORS and new_size and new_size < _KEY_FLOORS[new_alg])
        findings.append(
            f"Public key changed from {old_alg} {old_size or ''} to {new_alg} {new_size or ''}".rstrip()
            + "."
        )
        raise_to("warning" if weaker else "notice")

    status_changes: dict[str, dict[str, Any]] = {}
    for name in sorted(set(before_results) | set(after_results)):
        old_status = (before_results.get(name) or {}).get("status")
        new_status = (after_results.get(name) or {}).get("status")
        if old_status == new_status:
            continue
        status_changes[name] = {"previous": old_status, "current": new_status}
        if old_status and new_status:
            findings.append(f"{name} went from {old_status} to {new_status}.")
            raise_to("warning" if new_status in ("fail", "error") else "notice")
        elif old_status:
            # A check that stopped running is worth knowing about: the
            # validator was disabled, misspelled, or failed to load.
            findings.append(f"{name} is no longer checked (it was {old_status}).")
            raise_to("notice")
        else:
            findings.append(f"{name} is newly checked ({new_status}).")
            raise_to("notice")
    if status_changes:
        detail["status_changes"] = status_changes

    if (
        replaced
        and severity == "info"
        and detail.get("validity", {}).get("extended_days", 0) > 0
    ):
        findings.append(
            "This looks like a routine renewal: same issuer, names, and key, with a later expiry."
        )

    return {
        "changed": bool(findings),
        "replaced": replaced,
        "severity": severity if findings else "info",
        "findings": findings,
        **detail,
    }
