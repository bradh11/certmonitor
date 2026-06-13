<p align="center">
  <img src="images/logo.svg" alt="CertMonitor Logo" width="180" />
</p>

# CertMonitor

<p align="center">
  <em>Zero-dependency certificate monitoring and validation for Python. Native, portable, extensible, and secure.<br>
  All orchestration and logic are pure Python standard library. Public key parsing and elliptic curve support are powered by Rust. No third-party Python dependencies - ever.</em>
</p>

---

> ⚡️ **Why CertMonitor?**
>
> CertMonitor was born out of real-world frustration: outages and security incidents caused by expired certificates, missing Subject Alternative Names, or incomplete certificate chains. This tool is a labor of love—built to solve those pain points with a zero-dependency, native Python approach. All orchestration and logic are pure Python stdlib, with public key parsing and elliptic curve support powered by Rust for speed, safety, and correctness. CertMonitor is always improving, and your feedback is welcome!

---

## 🚀 Features

- **Easy Certificate Retrieval**: Fetch and parse certificates from any host (domain or IP) with a single call.
- **Pluggable Validators**: Built-in and custom validators for expiration, hostname, SANs, key strength, cipher, protocol version, and more.
- **Post-Quantum Readiness**: Opt-in validators detect post-quantum (hybrid/pure **ML-KEM**) TLS key exchange and post-quantum certificate keys/signatures (**ML-DSA**, **SLH-DSA**, composite) — track quantum-safe migration and *harvest-now-decrypt-later* exposure.
- **Rich API**: Access raw certificate data, cipher info, and validation results in structured Python objects or JSON.
- **Rust-Powered Performance**: Advanced public key parsing and elliptic curve support are powered by Rust for speed and safety. All orchestration and logic are pure Python standard library.
- **Graceful Error Handling**: Robust to network failures, invalid hosts, and edge cases.
- **Modern Python**: Async-ready, type-annotated, and compatible with Python 3.8+.
- **Extensive Documentation**: Usage guides, API reference, and real-world examples.

---

## 📦 Installation & Quickstart

You can install CertMonitor using your preferred Python package manager.

=== "pip"
    ```sh
    pip install certmonitor
    ```

=== "uv"
    ```sh
    uv add certmonitor
    ```

Once installed, you can quickly get started:

```python
from certmonitor import CertMonitor

# Using the context manager (recommended)
with CertMonitor("example.com") as monitor:
    cert_info = monitor.get_cert_info()
    print("Certificate Info:", cert_info)

    # Validate with specific arguments for a validator
    results = monitor.validate(
        validator_args={"subject_alt_names": {"alternate_names": ["example.com", "www.example.com"]}}
    )
    print("\nValidation Results:")
    for validator_name, result in results.items():
        print(f"  {validator_name}: {'Valid' if result['is_valid'] else 'Invalid'} - {result.get('reason', result.get('days_to_expiry', ''))}")

    # Retrieve raw certificate data if needed
    pem_cert = monitor.get_raw_pem()
    # print("\nRaw PEM Certificate:\n", pem_cert)

    der_cert = monitor.get_raw_der()
    # print("\nRaw DER Certificate (first 50 bytes):\n", der_cert[:50])

# For more detailed examples, check the Usage section.
```

---

## 🛠️ Example Output

### Certificate Info

This is a sample of the structured certificate info returned by `monitor.get_cert_info()`:

```json
{
  "subject": {
    "commonName": "example.com"
  },
  "issuer": {
    "organizationName": "DigiCert Inc",
    "commonName": "DigiCert TLS RSA SHA256 2020 CA1"
  },
  "notBefore": "2024-06-01T00:00:00",
  "notAfter": "2025-09-01T23:59:59",
  "serialNumber": "0A1B2C3D4E5F6789",
  "subjectAltName": {
    "DNS": ["example.com", "www.example.com"],
    "IP Address": []
  },
  "publicKeyInfo": {
    "algorithm": "rsaEncryption",
    "size": 2048,
    "curve": null
  }
}
```

### PEM Format

This is a sample of the PEM format returned by `monitor.get_raw_pem()`:

```pem
-----BEGIN CERTIFICATE-----
MIID...snip...IDAQAB
-----END CERTIFICATE-----
```

### DER Format

This is a sample of the DER format returned by `monitor.get_raw_der()` (as bytes, shown here as base64):

```text
MIID...snip...IDAQAB
```

### Validation Results

```json
{
  "expiration": {
    "is_valid": true,
    "days_to_expiry": 120,
    "expires_on": "2025-09-01T23:59:59",
    "warnings": []
  },
  "subject_alt_names": {
    "is_valid": true,
    "sans": {"DNS": ["example.com", "www.example.com"], "IP Address": []},
    "count": 2,
    "contains_host": {"name": "example.com", "is_valid": true, "reason": "Matched DNS SAN"},
    "contains_alternate": {"www.example.com": {"name": "www.example.com", "is_valid": true, "reason": "Matched DNS SAN"}},
    "warnings": []
  }
}
```

---

## 📚 Documentation

CertMonitor provides a robust, extensible system of **validators**—modular checks that automatically assess certificate health, security, and compliance. Validators can:

- Detect expired or soon-to-expire certificates
- Ensure hostnames and SANs match
- Enforce strong key types and lengths
- Require modern TLS versions and strong cipher suites
- Allow you to add custom organization-specific checks

This makes CertMonitor ideal for continuous monitoring, compliance automation, and proactive security.

- [Usage Guide](usage/index.md): Installation, basic usage, advanced features, troubleshooting, and more.
- [Validators](validators/index.md): Built-in and custom validators, with example outputs.
- [API Reference](reference/certmonitor.md): Full Python API docs, including all classes and methods.
- [Development Guide](development.md): Contributing, building, and testing CertMonitor.

---

## 🌐 Links

- [GitHub Repository](https://github.com/bradh11/certmonitor)
- [PyPI Package](https://pypi.org/project/certmonitor/)
- [ReadTheDocs](https://certmonitor.readthedocs.io/)

---

<p align="center">
  <em>CertMonitor: Secure your connections, automatically.</em>
</p>
