---
title: "TLS Hostname Validation with DNS and IP SANs"
description: "Validate TLS certificate hostname identity using DNS and IP Subject Alternative Names. Inspect Common Name matching without overriding SAN validation."
---

# Hostname Validator

Confirms the certificate was actually issued for the host you connected to. `hostname` matches the host against the certificate's Subject Alternative Names (SANs) including wildcard certificates (`*.example.com`). A mismatch is what your browser shows as "this certificate is not valid for this site."

!!! note "Enabled by default"
    `hostname` is one of the three default validators. The host you pass to `CertMonitor(...)` is the name it checks against. To check a different name, pass `validator_args={"hostname": {"expected_identity": "..."}}`.

## Try it

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["hostname"])
```

A matching hostname reports which name matched and the SANs it considered:

These examples show selected fields from illustrative scans. `validate()` also adds `status` and `code`, described in the [result contract](index.md#the-result-contract).

```json
{
  "is_valid": true,
  "alt_names": [
    "example.com",
    "*.example.com"
  ],
  "identity_source": "subjectAltName",
  "common_name": "example.com",
  "common_name_matches": true,
  "matched_name": "example.com"
}
```

A mismatch fails with a `reason`:

```json
{
  "is_valid": false,
  "alt_names": [
    "*.badssl.com",
    "badssl.com"
  ],
  "identity_source": "subjectAltName",
  "common_name": "*.badssl.com",
  "common_name_matches": false,
  "reason": "Hostname wrong.host.badssl.com doesn't match any of the certificate's subject alternative names"
}
```

## How matching works

1. **Common Name**: `common_name` and `common_name_matches` report the CN comparison for reference. CN does not determine `is_valid` or replace missing SANs.
2. **DNS/IP SANs**: DNS names are checked case-insensitively after IDNA normalization. IP addresses match IP Address SANs by address equality.
3. **Wildcards**: a `*.example.com` SAN matches exactly one label (`api.example.com`), but **not** the bare apex (`example.com`) or nested subdomains (`a.b.example.com`).

!!! tip "Checking with an IP address?"
    Connecting by IP will usually fail `hostname` unless the certificate carries that IP as a SAN (most don't). See [Using IP Addresses](../usage/ip.md) for how CertMonitor handles IP targets.

SAN-based identity validation follows [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html).

## Reference

::: certmonitor.validators.hostname.HostnameValidator
