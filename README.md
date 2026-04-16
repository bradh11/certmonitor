<p align="center">
  <a href="https://certmonitor.readthedocs.io/">
    <img src="docs/images/logo.svg" alt="CertMonitor Logo" width="120" height="120">
  </a>
</p>

# CertMonitor

<p align="center">
  <em>Zero-dependency certificate monitoring and validation for Python. Native, portable, extensible, and secure.<br>
  All orchestration and logic are pure Python standard library. Public key parsing and elliptic curve support are powered by Rust. No third-party Python dependencies - ever.</em>
</p>
<p align="center">
  <a href="https://github.com/bradh11/certmonitor/actions/workflows/ci.yml?query=branch%3Amain" target="_blank">
    <img src="https://github.com/bradh11/certmonitor/actions/workflows/ci.yml/badge.svg?branch=main" alt="Test Status">
  </a>
  <a href="https://pypi.org/project/certmonitor" target="_blank">
    <img src="https://img.shields.io/pypi/v/certmonitor?color=%234FC3F7&label=pypi%20package" alt="PyPI version">
  </a>
  <a href="https://pypi.org/project/certmonitor" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/certmonitor.svg?color=%234FC3F7" alt="Supported Python versions">
  </a>
  <a href="https://certmonitor.readthedocs.io/" target="_blank">
    <img src="https://readthedocs.org/projects/certmonitor/badge/?version=latest" alt="ReadTheDocs">
  </a>
</p>

---

> ⚡️ **Why CertMonitor?**
>
> CertMonitor was born out of real-world frustration: outages and security incidents caused by expired certificates, missing Subject Alternative Names, or incomplete certificate chains. This tool is a labor of love—built to solve those pain points with a zero-dependency, native Python approach. <strong>All orchestration and logic are pure Python stdlib, but advanced public key parsing and elliptic curve support are powered by Rust for speed, safety, and correctness.</strong> CertMonitor is always improving, and your feedback is welcome!

---

## 🚀 Quick Start

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    print(monitor.get_cert_info())
    print(monitor.validate())
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

## ✨ Features

- 🔒 **Zero Dependencies:** 100% standard library. No third-party Python packages required—ever.
- 🛡️ **Certificate Validators:** Modular checks for expiration, hostname, SANs, key strength, protocol, ciphers, and more.
- ⚡ **High Performance:** Async- and batch-friendly. Designed for speed and concurrency.
- 🧩 **Extensible:** Add your own custom validators for organization-specific checks.
- 🐍 **Native Python First:** Works out-of-the-box in any Python 3.8+ environment.
- 🦀 **Rust-Powered Parsing:** Certificate parsing and public key extraction are handled by a Rust extension for speed, safety, and correctness. <strong>This is required for advanced public key and elliptic curve features, but all orchestration and logic are pure Python stdlib.</strong>
- 📦 **Portable:** No system dependencies. Drop it into any project or CI pipeline.
- 📝 **Comprehensive Docs:** [ReadTheDocs](https://certmonitor.readthedocs.io/) with usage, API, and advanced guides.

---

## 🔍 Validators: The Heart of CertMonitor

CertMonitor uses a powerful system of **validators**—modular checks that automatically assess certificate health, security, and compliance. Validators can:

- Detect expired or soon-to-expire certificates
- Ensure hostnames and SANs match
- Enforce strong key types and lengths
- Require modern TLS versions and strong cipher suites
- Allow you to add custom organization-specific checks

You can enable, disable, or extend validators to fit your needs, making CertMonitor ideal for continuous monitoring, compliance automation, and proactive security.

### Available Validators
- `expiration`: Validates that the certificate is not expired.
- `hostname`: Validates that the hostname matches the certificate's subject alternative names (SANs).
- `subject_alt_names`: Validates the presence and content of the SANs in the certificate.
- `root_certificate`: Validates if the certificate is issued by a trusted root CA.
- `key_info`: Validates the public key type and strength.
- `tls_version`: Validates the negotiated TLS version.
- `weak_cipher`: Validates that the negotiated cipher suite is in the allowed list.
- `sensitive_date`: Validates that the certificate doesn't expire on built-in or user specified sensitive dates.
- `chain`: Validates the full TLS certificate chain for structural problems (missing intermediates, out-of-order, expired members, weak signatures).

---

## 📦 Installation

Install CertMonitor from PyPI using your preferred package manager:

**Using pip:**
```sh
pip install certmonitor
```

**Using uv:**
```sh
uv add certmonitor
```

For instructions on installing from source for development, please see the [Development Guide](docs/development.md).

---

## 🛠️ Usage Examples

### Context Manager Usage (Recommended)
```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert_data = monitor.get_cert_info()
    validation_results = monitor.validate(validator_args={"subject_alt_names": ["www.example.com"]})
    print(cert_data)
    print(validation_results)
```

### Basic Usage (Non-Context Manager)
```python
monitor = CertMonitor("example.com")
cert_data = monitor.get_cert_info()
validation_results = monitor.validate()
monitor.close()
```

### Using IP Address
You can also use an IPv4 or IPv6 address to retrieve and validate the SSL certificate. Note: Using an IP address may not match the certificate's hostname.
```python
with CertMonitor("20.76.201.171") as monitor:
    cert = monitor.get_cert_info()
    validation_results = monitor.validate()
    print(cert)
    print(validation_results)
```

### Retrieving Raw Certificate Data
These methods are only available for SSL/TLS connections:
```python
raw_der = monitor.get_raw_der()  # Returns DER bytes
raw_pem = monitor.get_raw_pem()  # Returns PEM string
```

### Retrieving Cipher Information
You can retrieve and validate cipher suite information:
```python
cipher_info = monitor.get_cipher_info()
print(cipher_info)
```

---

## ⚙️ Configuration

You can configure CertMonitor by specifying which validators to enable in the `enabled_validators` parameter. If not specified, it will use the default validators defined in the configuration.

### Default Validators
By default, the following validators are enabled:
- expiration
- hostname
- root_certificate

### Environment Variables
CertMonitor can also read the list of enabled validators from an environment variable `ENABLED_VALIDATORS`. This is useful for configuring the validators without modifying the code.

Example:
```sh
export ENABLED_VALIDATORS="expiration,hostname,subject_alt_names,root_certificate,key_info,tls_version,weak_cipher"
```

---

## 🔎 Protocol Detection
CertMonitor automatically detects the protocol (SSL/TLS or SSH) for the target host. Most features are focused on SSL/TLS. SSH support is limited.

---

## 🚨 Error Handling
If an error occurs (e.g., connection failure, invalid certificate), CertMonitor methods will return a dictionary with an `error` key and details. Always check for errors in returned data:
```python
cert = monitor.get_cert_info()
if isinstance(cert, dict) and "error" in cert:
    print("Error:", cert["message"])
```

---

## 🔐 Why Trust CertMonitor

CertMonitor's certificate parser handles untrusted bytes from every TLS handshake it monitors. We take that seriously:

- **Zero runtime dependencies.** The Python layer uses only the standard library. The Rust extension's X.509 / DER parser is written in-house against the Rust standard library — no third-party parsing crates in the runtime dependency tree.
- **`#![forbid(unsafe_code)]`** at the Rust crate root. No `unsafe` blocks anywhere in the parser. Memory safety is enforced by the Rust compiler, not by manual auditing.
- **Every parser path returns `Result`.** Malformed input produces a structured error, never a crash. No `.unwrap()` on user-input-derived data.
- **1.7 billion fuzz iterations, zero crashes.** The parser is continuously fuzz-tested with [cargo-fuzz](https://github.com/rust-lang/cargo-fuzz) (libFuzzer) against adversarial byte sequences. A 1-hour soak run explores 310 code-coverage points and 503 libfuzzer features with zero panics. Run it yourself: `make fuzz`.
- **130-cert real-world corpus on every CI run.** Every commit is tested against captured certificates from 101 production hosts spanning Google Trust Services, DigiCert, Let's Encrypt, Sectigo, Cloudflare, and more — covering both RSA and ECDSA key types.
- **425+ Python tests at 99% line coverage, 56 Rust unit tests.** The full test suite runs across Python 3.8–3.13 and Rust stable on macOS, Ubuntu, and Windows.
- **`cargo audit` on every PR.** The Rust dependency tree is 20 crates total (all PyO3 build-time helpers), scanned for known vulnerabilities on every pull request.

---

## 📄 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
