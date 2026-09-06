---
title: "SSL/TLS Certificate Expiration Checks in Python"
description: "Check certificate expiration and notBefore in Python, configure warning and critical thresholds, and enforce an optional certificate lifetime policy."
---

# Expiration Validator

This is the validator that catches the most common certificate incident there is: a certificate that has expired, or is about to.

It reports how long until the certificate's `notAfter` date, and it flags the situations you care about: the cert is already expired, isn't valid yet, is approaching expiration, or was issued for longer than your lifetime policy allows.

!!! note "Enabled by default"
    You don't have to turn this one on. `expiration` is one of the three default validators, along with `hostname` and `root_certificate`.

## Try it

Let's run it against a host:

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["expiration"])
```

A healthy certificate comes back valid, with the days remaining:

These examples show selected fields from illustrative scans. `validate()` also adds `status` and `code`, described in the [result contract](index.md#the-result-contract).

```json
{
  "is_valid": true,
  "days_to_expiry": 56,
  "expires_on": "2026-08-08T22:14:02+00:00",
  "lifetime_days": 365,
  "warnings": []
}
```

An expired one flips `is_valid` to `false` and adds a `reason` you can drop straight into an alert:

```json
{
  "is_valid": false,
  "days_to_expiry": -4080,
  "expires_on": "2015-04-12T23:59:59+00:00",
  "warnings": ["Certificate is expired and has been expired for (-4080 days)"],
  "reason": "Certificate expired 4080 days ago (expired on 2015-04-12).",
  "lifetime_days": 3
}
```

!!! tip "A valid certificate can still warn you"
    `is_valid` only turns false when the certificate is expired or not yet valid. A certificate can be perfectly valid and still carry a warning: it expires within the warning threshold (time to renew), including when less than one day remains, or its total lifetime exceeds the limit. So watch the `warnings` list, and `status`, not just `is_valid`.

## Arguments

Pass via `validator_args={"expiration": {...}}`. The arguments and their defaults are documented in the [reference](#reference) below.

Thresholds accept fractional days and require `0 <= critical_days <= warning_days`.

The lifetime policy defaults to 398 days, the CA/Browser Forum limit for publicly trusted certificates, and it warns rather than fails. Lower `max_lifetime_days` to tighten the policy, raise it for a private PKI that issues longer certificates, or pass `None` to skip the check:

```python
results = monitor.validate({"expiration": {"max_lifetime_days": 825}})
```

When `notBefore` is missing from the certificate data, the validity-start and lifetime checks are skipped and `lifetime_days` is omitted.

## Reference

::: certmonitor.validators.expiration.ExpirationValidator
