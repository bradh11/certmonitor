---
title: "TLS Certificate Trust Verification with System or Custom CAs"
description: "Verify TLS certificate trust using Python SSLContext and the system or a custom CA store, separately from permissive certificate collection."
---

# RootCertificate Validator

Checks whether the leaf certificate chains to a trusted CA using a separate, cryptographically verified TLS handshake; for full structural chain analysis use the [Chain](chain.md) validator, and for whether the certificate has since been revoked use the opt-in [Revocation](revocation.md) validator.

!!! note "Enabled by default"
    `root_certificate` is one of the three default validators.

## Try it

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["root_certificate"])
```

A certificate that verifies against the system or configured CA store passes:

These examples show selected fields from illustrative scans. `validate()` also adds `status` and `code`, described in the [result contract](index.md#the-result-contract).

```json
{
  "is_valid": true,
  "trust_verified": true,
  "revocation_status": "not_checked",
  "warnings": [],
  "issuer": {
    "countryName": "US",
    "organizationName": "SSL Corporation",
    "commonName": "Cloudflare TLS Issuing ECC CA 3"
  }
}
```

An untrusted self-signed certificate fails. The result keeps the issuer for context, carries the X.509 verification code from Python's `ssl` module, and explains the failure in `reason`:

```json
{
  "is_valid": false,
  "status": "fail",
  "code": "root_certificate.fail",
  "reason": "Certificate verification failed: self-signed certificate",
  "verify_code": 18,
  "trust_verified": false,
  "issuer": {
    "countryName": "US",
    "stateOrProvinceName": "California",
    "localityName": "San Francisco",
    "organizationName": "BadSSL",
    "commonName": "*.badssl.com"
  },
  "warnings": []
}
```

## What it checks

A certificate is considered trusted only when Python's standard-library `ssl` module verifies the chain against the system trust store, or the `cafile` / `capath` you configure. That module ships with every CPython build and needs no extra installation. The verified handshake must return the same leaf certificate as the collected snapshot; a different leaf returns `SnapshotMismatch`, requiring `refresh()`. The verdict is bound to that snapshot and reused by later `validate()` calls, so trust costs one extra connection per observation rather than per call; `refresh()` collects and verifies again. Issuer names and OCSP/caIssuers URLs do not establish trust.

!!! warning "Collection and verification are separate"
    CertMonitor connects with `CERT_NONE` on purpose so it can inspect misconfigured and legacy servers. Trust is checked on a separate verified connection; hostname identity is checked by [Hostname](hostname.md). For chain structure (missing intermediates, ordering, weak signatures) use [Chain](chain.md); both can be enabled together. Revocation is not checked.

Transport or configuration failures return `status: error`; certificate verification failures return `status: fail`.

The verified handshake first uses the interpreter's default TLS settings (TLS 1.2 or newer, modern ciphers). If that handshake cannot be negotiated, or the server selects a different leaf than the permissive collection connection saw, CertMonitor retries with the collector's legacy settings so the verdict describes the collected certificate. A result verified that way carries a warning naming the legacy settings.




## Use your private CA

For an internal service, configure the CA bundle your organization trusts:

```python
from certmonitor import CertMonitor

# Replace the host and local file path with your own.
with CertMonitor("service.example.com", cafile="/path/to/company-ca.pem") as monitor:
    print(monitor.validate()["root_certificate"])
```

`cafile` and `capath` configure the verified handshake's trust store. If you want public roots as well as private roots, supply a bundle containing the authorities you intend to trust. For mutual TLS, pass `client_cert` and, when separate, `client_key`; those credentials are used for collection and verification.

## Reference

::: certmonitor.validators.root_certificate_validator.RootCertificateValidator
