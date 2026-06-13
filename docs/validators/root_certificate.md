# RootCertificate Validator

Checks whether the leaf certificate looks like it chains to a trusted, well-operated public CA — or whether it's self-signed, missing the metadata real CAs include, or issued by an untrusted root. This is a fast, leaf-level heuristic; for full structural chain analysis use the [Chain](chain.md) validator.

!!! note "Enabled by default"
    `root_certificate` is one of the three default validators.

## Example

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["root_certificate"])
```

A certificate from a public CA passes:

```json
{
  "is_valid": true,
  "issuer": {
    "countryName": "US",
    "organizationName": "SSL Corporation",
    "commonName": "Cloudflare TLS Issuing ECC CA 3"
  },
  "warnings": []
}
```

A self-signed certificate fails, with every contributing signal in `warnings` and a one-line `reason`:

```json
{
  "is_valid": false,
  "issuer": {
    "organizationName": "BadSSL",
    "commonName": "*.badssl.com"
  },
  "warnings": [
    "Certificate does not provide OCSP information.",
    "Certificate does not provide caIssuers information.",
    "Certificate is self-signed.",
    "The certificate is issued by an untrusted root CA: BadSSL (*.badssl.com)"
  ],
  "reason": "Certificate is not issued by a trusted root CA: BadSSL (*.badssl.com)."
}
```

## What it checks

A certificate is considered trusted only when **all** of these hold: it has issuer information, it provides OCSP and caIssuers metadata (which public CAs include), it is not self-signed, and the issuer name doesn't look untrusted. Each failed check appears in `warnings`.

!!! warning "Heuristic, not cryptographic verification"
    This validator inspects metadata — it does **not** build a path to your system trust store or verify signatures. CertMonitor connects with `CERT_NONE` on purpose so it can inspect misconfigured and legacy servers. For chain structure (missing intermediates, ordering, weak signatures) use [Chain](chain.md); both can be enabled together.

## API

::: certmonitor.validators.root_certificate_validator.RootCertificateValidator
