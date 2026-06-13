# CertMonitor: Usage Overview

## Why CertMonitor exists

CertMonitor was born out of real-world frustration. Outages and security incidents caused by expired certificates, missing Subject Alternative Names, or incomplete certificate chains. Like a lot of engineers, I was tired of the late-night alerts, the broken integrations, and the scramble to track down certificate problems before they turned into downtime or a compliance failure.

So I built CertMonitor to take that pain away. The goals were simple:

- **Zero dependencies.** No third-party Python packages, ever. The advanced public key parsing and elliptic curve support are powered by Rust for speed and safety, but you never install a Python dependency to use them.
- **Portable and secure.** It works out of the box in any Python 3.8+ environment, with a minimal attack surface.
- **Extensible.** Add your own validators for organization-specific checks, compliance rules, or custom certificate logic.
- **Fast and reliable.** It's designed for high-throughput, concurrent monitoring across many endpoints.

## What makes CertMonitor different?

A few things set it apart:

- **Zero dependencies, by design.** You can drop CertMonitor into any environment and it just works. (Those advanced public key and elliptic curve features are powered by Rust, but all of the orchestration and logic is pure Python standard library.)
- **Native Python first.** The core features use only the Python standard library. That means maximum compatibility, security, and maintainability.
- **A validator system.** Modular, pluggable checks for everything from expiration to hostname validation, key strength, protocol version, and more.
- **A labor of love.** This is a passion project, not a commercial product. We aim for production quality, and CertMonitor is always improving. Your feedback and contributions are genuinely welcome.

## Example: catching the issues that matter

Here's the whole idea in five lines. Point CertMonitor at a host and ask it to validate:

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    print(monitor.validate())
```

Out of the box, `validate()` runs the three default validators: `expiration`, `hostname`, and `root_certificate`. Each one returns a structured result keyed by its name:

```json
{
  "expiration": {
    "is_valid": true,
    "days_to_expiry": 77,
    "expires_on": "2026-08-29T21:41:26+00:00",
    "warnings": []
  },
  "hostname": {
    "is_valid": true,
    "matched_name": "example.com",
    "alt_names": []
  },
  "root_certificate": {
    "is_valid": true,
    "issuer": {
      "countryName": "US",
      "organizationName": "SSL Corporation",
      "commonName": "Cloudflare TLS Issuing ECC CA 3"
    },
    "warnings": []
  }
}
```

Every result has `is_valid`, and when a check fails it also gets a `reason` you can show in an alert. That's the whole model.

!!! info "Want more checks? Turn them on"
    Plenty more validators ship with CertMonitor, including `subject_alt_names`, `key_info`, `tls_version`, `weak_cipher`, and the post-quantum checks. They're opt-in, so you enable the ones you care about. See the [Validators](../validators/index.md) section for the full list and how to enable them.

!!! note "About that zero-dependency promise"
    CertMonitor is designed to be zero-dependency and portable. The advanced public key parsing and elliptic curve support are powered by Rust, but you never need to install a third-party Python package for the orchestration or logic.
