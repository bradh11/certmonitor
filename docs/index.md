<p align="center">
  <a href="https://certmonitor.readthedocs.io/">
    <img src="images/logo.svg" alt="CertMonitor Logo" width="120" height="120">
  </a>
</p>

# CertMonitor

<p align="center">
  <em>Zero-dependency certificate monitoring and validation for Python. Native, portable, extensible, and secure.<br>
  All orchestration and logic are pure Python standard library. Public key parsing and elliptic curve support are powered by Rust. No third-party Python dependencies, ever.</em>
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
> CertMonitor was born out of real-world frustration: outages and security incidents caused by expired certificates, missing Subject Alternative Names, or incomplete certificate chains. This tool is a labor of love, built to solve those pain points with a zero-dependency, native Python approach. <strong>All orchestration and logic are pure Python stdlib, but advanced public key parsing and elliptic curve support are powered by Rust for speed, safety, and correctness.</strong> CertMonitor is always improving, and your feedback is welcome!

---

## ✨ Features

- 🔒 **Zero Dependencies:** 100% standard library. No third-party Python packages required. Ever.
- 🛡️ **Certificate Validators:** Modular checks for expiration, hostname, SANs, key strength, protocol, ciphers, and more.
- ⚡ **High Performance:** Async- and batch-friendly. Designed for speed and concurrency.
- 🧩 **Extensible:** Add your own custom validators for organization-specific checks.
- 🔮 **Post-Quantum Readiness:** Opt-in validators detect post-quantum (hybrid/pure **ML-KEM**) TLS key exchange and post-quantum certificate keys/signatures (**ML-DSA**, **SLH-DSA**, composite), so you can track quantum-safe migration and *harvest-now-decrypt-later* exposure. See [below](#post-quantum-readiness).
- 🐍 **Native Python First:** Works out-of-the-box in any Python 3.8+ environment.
- 🦀 **Rust-Powered Parsing:** Certificate parsing and public key extraction are handled by a Rust extension for speed, safety, and correctness. <strong>This is required for advanced public key and elliptic curve features, but all orchestration and logic are pure Python stdlib.</strong>
- 📦 **Portable:** No system dependencies. Drop it into any project or CI pipeline.
- 📝 **Comprehensive Docs:** Usage guides, API reference, and advanced guides throughout this site.

---

## 🔍 Validators: The Heart of CertMonitor

CertMonitor uses a powerful system of **validators**, modular checks that automatically assess certificate health, security, and compliance. Validators can:

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
- `pq_key_exchange`: Reports whether the TLS 1.3 key exchange is post-quantum (hybrid or pure ML-KEM). This is the *harvest-now-decrypt-later* question. Opt-in.
- `pq_signature`: Reports the leaf certificate's post-quantum posture (the key and signature algorithm: ML-DSA / SLH-DSA / composite). Opt-in.
- `pq_chain`: Reports the post-quantum posture of every certificate in the presented chain. Opt-in.

The full catalog, with arguments and example output, is in the [Validators](validators/index.md) section.

> The `pq_*` validators are **opt-in** (not enabled by default). See [Post-Quantum Readiness](#post-quantum-readiness) below.

---

## 🔮 Post-Quantum Readiness

CertMonitor helps you measure your migration to **post-quantum cryptography (PQC)** across both surfaces that matter, using NIST's finalized standards (FIPS 203 **ML-KEM**, FIPS 204 **ML-DSA**, FIPS 205 **SLH-DSA**):

- **Key exchange (the urgent one).** TLS 1.3 hybrid key exchange (e.g. `X25519MLKEM768`) is what defends today's traffic against *harvest-now-decrypt-later* (HNDL), where an attacker records encrypted traffic now to decrypt once a quantum computer exists. The `pq_key_exchange` validator reads the negotiated group directly off the wire (the Python `ssl` module doesn't expose it) and tells you whether the session is quantum-safe.
- **Certificate keys & signatures.** As CAs and operators roll out ML-DSA / SLH-DSA and composite (hybrid) certificates, `pq_signature` and `pq_chain` report the post-quantum posture of the leaf and the full chain.

"PQ" includes **hybrid** algorithms (classical + post-quantum), which is what real-world deployments use today. Requiring pure PQ would fail every server currently in production.

```python
from certmonitor import CertMonitor

with CertMonitor("cloudflare.com", enabled_validators=["pq_key_exchange", "pq_signature", "pq_chain"]) as monitor:
    results = monitor.validate()
    print(results["pq_key_exchange"])
    # {'kem_id': 4588, 'kem_name': 'X25519MLKEM768', 'kem_kind': 'hybrid_pq',
    #  'is_pq': True, 'is_valid': True}
```

These validators are **opt-in** (not in the default set) while PQC adoption is still ramping. Full details: [PqKeyExchange](validators/pq_key_exchange.md) · [PqSignature](validators/pq_signature.md) · [PqChain](validators/pq_chain.md).

---

## 📚 Learn How It Works

New to TLS, certificates, or the post-quantum transition? The docs include vendor-neutral explainers with diagrams:

- [How TLS & HTTPS Work](concepts/how-tls-works.md): the handshake, and the key-exchange-vs-signatures split.
- [Certificates & PKI](concepts/certificates-and-pki.md): what's in a certificate and how the chain of trust works.
- [Post-Quantum Cryptography](concepts/post-quantum.md): the quantum threat, harvest-now-decrypt-later, and the NIST standards.

---

## 📦 Installation & Quickstart

Install CertMonitor using your preferred Python package manager:

=== "pip"
    ```sh
    pip install certmonitor
    ```

=== "uv"
    ```sh
    uv add certmonitor
    ```

For instructions on installing from source for development, please see the [Development Guide](development.md).

Once installed, here's the pattern you'll use most often. Connect to a host, pull the certificate details, and run the validators:

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert_data = monitor.get_cert_info()
    validation_results = monitor.validate()
    print(cert_data)
    print(validation_results)
```

Two calls do the work. `get_cert_info()` gives you the parsed certificate, and `validate()` runs the checks against it.

### What `get_cert_info()` returns

A structured dictionary describing the certificate:

```json
{
  "subject": {
    "countryName": "US",
    "stateOrProvinceName": "California",
    "localityName": "Los Angeles",
    "organizationName": "Internet Corporation for Assigned Names and Numbers",
    "commonName": "www.example.com"
  },
  "issuer": {
    "countryName": "US",
    "organizationName": "DigiCert Inc",
    "commonName": "DigiCert Global G2 TLS RSA SHA256 2020 CA1"
  },
  "version": 3,
  "serialNumber": "075BCEF30689C8ADDF13E51AF4AFE187",
  "notBefore": "2024-01-30T00:00:00",
  "notAfter": "2025-03-01T23:59:59",
  "subjectAltName": {
    "DNS": ["www.example.com", "example.com"],
    "IP Address": []
  },
  "OCSP": ["http://ocsp.digicert.com"],
  "caIssuers": ["http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt"],
  "crlDistributionPoints": [
    "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
    "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
  ]
}
```

It's all there: who the certificate is for (`subject`), who issued it (`issuer`), how long it's valid (`notBefore` and `notAfter`), the alternate names it covers, and the revocation endpoints.

### What `validate()` returns

A dictionary keyed by validator name, with a structured result under each one:

```json
{
  "expiration": {
    "is_valid": true,
    "days_to_expiry": 120,
    "expires_on": "2025-03-01T23:59:59",
    "warnings": []
  },
  "subject_alt_names": {
    "is_valid": true,
    "sans": {"DNS": ["www.example.com", "example.com"], "IP Address": []},
    "count": 2,
    "contains_host": {"name": "www.example.com", "is_valid": true, "reason": "Exact match for www.example.com found in DNS SANs"},
    "contains_alternate": {"example.com": {"name": "example.com", "is_valid": true, "reason": "Exact match for example.com found in DNS SANs"}},
    "warnings": []
  }
}
```

Each validator reports its own `is_valid` flag plus the details behind its decision. That structure is consistent across every validator, so once you can read one result you can read them all.

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

- **Zero runtime dependencies.** The Python layer uses only the standard library. The Rust extension's X.509 / DER parser is written in-house against the Rust standard library, with no third-party parsing crates in the runtime dependency tree.
- **`#![forbid(unsafe_code)]`** at the Rust crate root. No `unsafe` blocks anywhere in the parser. Memory safety is enforced by the Rust compiler, not by manual auditing.
- **Every parser path returns `Result`.** Malformed input produces a structured error, never a crash. No `.unwrap()` on user-input-derived data.
- **1.7 billion fuzz iterations, zero crashes.** The parser is continuously fuzz-tested with [cargo-fuzz](https://github.com/rust-lang/cargo-fuzz) (libFuzzer) against adversarial byte sequences. A 1-hour soak run explores 310 code-coverage points and 503 libfuzzer features with zero panics. Run it yourself: `make fuzz`.
- **130-cert real-world corpus on every CI run.** Every commit is tested against captured certificates from 101 production hosts spanning Google Trust Services, DigiCert, Let's Encrypt, Sectigo, Cloudflare, and more, covering both RSA and ECDSA key types.
- **540+ Python tests at 99% line coverage, plus 99 Rust unit tests.** The full test suite runs across Python 3.8 to 3.13 and Rust stable on macOS, Ubuntu, and Windows.
- **`cargo audit` on every PR.** CertMonitor declares a single direct Rust dependency, `pyo3` (the Python bridge). The whole compiled tree is 15 crates, all pyo3 and its helpers, with no third-party parsing crates, scanned for known vulnerabilities on every pull request.

---

## 📄 License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/bradh11/certmonitor/blob/main/LICENSE) file for details.

---

<p align="center">
  <em>CertMonitor: Secure your connections, automatically.</em>
</p>
