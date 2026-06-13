# Expiration Validator

Catches the most common certificate incident there is: a cert that has expired, or is about to. `expiration` reports how long until the certificate's `notAfter` date and flags certificates that are expired, expiring within a week, or valid for longer than the industry-standard maximum (398 days).

!!! note "Enabled by default"
    `expiration` runs out of the box — it's one of the three default validators (`expiration`, `hostname`, `root_certificate`). No configuration required.

## Example

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["expiration"])
```

A healthy certificate:

```json
{
  "is_valid": true,
  "days_to_expiry": 56,
  "expires_on": "2026-08-08T22:14:02+00:00",
  "warnings": []
}
```

An expired certificate fails with a human-readable `reason` you can put straight into an alert:

```json
{
  "is_valid": false,
  "days_to_expiry": -4080,
  "expires_on": "2015-04-12T23:59:59+00:00",
  "warnings": ["Certificate is expired and has been expired for (-4080 days)"],
  "reason": "Certificate expired 4080 days ago (expired on 2015-04-12)."
}
```

## What it reports

| Field | Meaning |
|---|---|
| `is_valid` | `false` once the certificate is past its `notAfter` date. |
| `days_to_expiry` | Days until expiry; negative once expired. |
| `expires_on` | The `notAfter` timestamp (ISO 8601, UTC). |
| `warnings` | Non-fatal heads-up notices (see below). |
| `reason` | Present only on failure. |

!!! tip "Warnings vs. failure"
    A certificate can be **valid but still warn**. Warnings fire when a cert is expiring in under 7 days (renew soon!) or is valid for more than 398 days (browsers reject over-long certs). Watch `warnings` for early signals, not just `is_valid`.

## API

::: certmonitor.validators.expiration.ExpirationValidator
