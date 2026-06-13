# Expiration Validator

This is the validator that catches the most common certificate incident there is: a certificate that has expired, or is about to.

It reports how long until the certificate's `notAfter` date, and it flags three situations you care about: the cert is already expired, it's expiring within a week, or it's valid for longer than the industry-standard maximum of 398 days.

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

```json
{
  "is_valid": true,
  "days_to_expiry": 56,
  "expires_on": "2026-08-08T22:14:02+00:00",
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
  "reason": "Certificate expired 4080 days ago (expired on 2015-04-12)."
}
```

!!! tip "A valid certificate can still warn you"
    `is_valid` only tells you whether the certificate has expired. A certificate can be perfectly valid and still carry a warning, for example when it expires in less than a week (time to renew) or when it's valid for more than 398 days (browsers reject over-long certificates). So watch the `warnings` list, not just `is_valid`.

## Reference

::: certmonitor.validators.expiration.ExpirationValidator
