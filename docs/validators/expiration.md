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
  "lifetime_limit_days": 398,
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
  "lifetime_days": 3,
  "lifetime_limit_days": 1187
}
```

!!! tip "A valid certificate can still warn you"
    `is_valid` only turns false when the certificate is expired or not yet valid. A certificate can be perfectly valid and still carry a warning: it expires within the warning threshold (time to renew), including when less than one day remains, or its total lifetime exceeds the limit. So watch the `warnings` list, and `status`, not just `is_valid`.

## Arguments

Pass via `validator_args={"expiration": {...}}`. The arguments and their defaults are documented in the [reference](#reference) below.

Thresholds accept fractional days and require `0 <= critical_days <= warning_days`.

The lifetime policy defaults to `"public"`: the CA/Browser Forum limit that applied on the certificate's issue date. That is 825 days from March 2018, 398 from September 2020, 200 from March 2026, 100 from March 2027, and 47 from March 2029, so a certificate is judged by the rule it was issued under, and the limit used is reported in `lifetime_limit_days`. The check warns rather than fails. Pass a number for a private PKI policy, or `None` to skip the check:

```python
results = monitor.validate({"expiration": {"max_lifetime_days": 825}})
```

When `notBefore` is missing from the certificate data, the validity-start and lifetime checks are skipped and `lifetime_days` is omitted.

## Reference

::: certmonitor.validators.expiration.ExpirationValidator
