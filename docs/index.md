---
title: "Python SSL/TLS Certificate Monitoring"
description: "Monitor SSL/TLS certificates with Python: check expiration, validate hostname and SAN identity, analyze X.509 chains, and assess post-quantum readiness."
---

<p align="center">
  <a href="https://certmonitor.readthedocs.io/">
    <img src="images/logo.svg" alt="CertMonitor Logo" width="120" height="120">
  </a>
</p>

# CertMonitor

Check SSL/TLS certificates from Python: expiration, hostname identity, CA trust, and the details behind each result.

<p align="center">
  <em>Zero-dependency certificate monitoring and validation for Python, with no third-party Python runtime dependencies.<br>
  All orchestration and logic are pure Python standard library. Public key parsing and elliptic curve support are powered by a compiled Rust extension that ships inside the wheel.</em>
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
> CertMonitor was born out of real-world frustration: outages and security incidents caused by expired certificates, missing Subject Alternative Names, or incomplete certificate chains. This tool is a labor of love, built to solve those pain points with a zero-dependency, native Python approach: a standard-library orchestration layer and a native Rust parser. <strong>All orchestration and logic are pure Python stdlib, but advanced public key parsing and elliptic curve support are powered by Rust for speed, safety, and correctness.</strong> CertMonitor is always improving, and your feedback is welcome!

---

## Your first certificate check

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

`get_cert_info()` gives you the parsed certificate, and `validate()` runs the checks against it. If you only need the checks, call `validate()` directly; it collects the certificate for you.

!!! tip "New here? Start small"
    The [Basic Usage tutorial](usage/basic.md) walks through the code and its results. You can add more checks once those three defaults make sense.

!!! note "Reading the development docs"
    These pages describe the repository, including unreleased changes. Use a documentation version matching your package and review the [release notes](https://github.com/bradh11/certmonitor/releases) before adopting new behavior.

### What `get_cert_info()` returns

An illustrative certificate dictionary (your host and observation date will differ):

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
  "notBefore": "Jan 30 00:00:00 2024 GMT",
  "notAfter": "Mar  1 23:59:59 2025 GMT",
  "subjectAltName": {
    "DNS": ["www.example.com", "example.com"],
    "IP Address": []
  },
  "OCSP": ["http://ocsp.digicert.com"],
  "caIssuers": ["http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt"],
  "crlDistributionPoints": [
    "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
    "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
  ]  ],
  "fingerprint_sha256": "63ee284705b0cc2a22b72e4a71e60a2516811717f5302b819451852f203b1a7b"
}
```

It's all there: who the certificate is for (`subject`), who issued it (`issuer`), how long it's valid (`notBefore` and `notAfter`), the alternate names it covers, and the revocation endpoints. The dates use the SSL date format shown above. Those endpoint URLs are metadata; CertMonitor does not fetch them to check revocation.

### What `validate()` returns

A dictionary keyed by validator name, with a structured result under each one:

This is the full result of a scan against example.com at the time of writing. Certificate details and dates depend on the endpoint.

```json
{
  "expiration": {
    "is_valid": true,
    "days_to_expiry": 51,
    "expires_on": "2026-10-27T22:17:21+00:00",
    "warnings": [],
    "lifetime_days": 90,
    "lifetime_limit_days": 200,
    "status": "pass",
    "code": "expiration.pass"
  },
  "hostname": {
    "is_valid": true,
    "alt_names": [
      "example.com",
      "*.example.com"
    ],
    "identity_source": "subjectAltName",
    "common_name": "example.com",
    "common_name_matches": true,
    "matched_name": "example.com",
    "status": "pass",
    "code": "hostname.pass"
  },
  "root_certificate": {
    "is_valid": true,
    "status": "pass",
    "trust_verified": true,
    "revocation_status": "not_checked",
    "warnings": [],
    "issuer": {
      "countryName": "US",
      "organizationName": "SSL Corporation",
      "commonName": "Cloudflare TLS Issuing ECC CA 3"
    },
    "code": "root_certificate.pass"
  }
}
```

Each validator reports its own `is_valid` flag plus the details behind its decision. That structure is consistent across every validator, so once you can read one result you can read them all.

---

## What you can check

- 🔒 **Zero Dependencies:** no third-party Python runtime dependencies, ever. The required native extension is included in compatible platform wheels.
- 📄 **Files too:** `CertMonitor.from_file()` runs the certificate checks on a PEM or DER file with no connection at all. See [Certificates from Files](usage/files.md).
- 📮 **STARTTLS too:** mail, directory, and database ports (SMTP, IMAP, POP3, FTP, PostgreSQL, LDAP) are discovered on any port and get the right preamble before the handshake, so their certificates get the same checks; `starttls="smtp"` pins it when you already know. See [STARTTLS Services](usage/starttls.md).
- ⌨️ **Command line:** `certmonitor check example.com` runs the same validators from the shell, with `--json` output and exit codes for cron and CI. See [Command Line](usage/cli.md).
- 🛡️ **Certificate Validators:** Modular checks for expiration, hostname, SANs, key strength, protocol, ciphers, and more.
- ⚡ **Batch Monitoring:** overlap network waits with independent monitors and bounded workers.
- 🧩 **Extensible:** Add your own custom validators for organization-specific checks.
- 🔮 **Post-Quantum Readiness:** Opt-in validators detect post-quantum (hybrid/pure **ML-KEM**) TLS key exchange and post-quantum certificate keys/signatures (**ML-DSA**, **SLH-DSA**, composite), so you can track quantum-safe migration and *harvest-now-decrypt-later* exposure. See [below](#post-quantum-readiness).
- 🐍 **Python API:** package metadata accepts Python 3.10 to 3.15; use a matching native wheel or build from source.
- 🦀 **Rust-Powered Parsing:** Certificate parsing and public key extraction are handled by a Rust extension for speed, safety, and correctness. <strong>This is required for advanced public key and elliptic curve features, but all orchestration and logic are pure Python stdlib.</strong>
- 📦 **Distribution:** install a compatible native wheel, or build from source with Rust and a platform C toolchain.
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
- `expiration`: Checks certificate validity dates, renewal thresholds, and optional lifetime policy.
- `hostname`: Validates that the hostname matches the certificate's subject alternative names (SANs).
- `subject_alt_names`: Checks that every requested alternate hostname/IP is covered by the SANs, or the primary host when none are requested.
- `root_certificate`: Validates if the certificate is issued by a trusted root CA.
- `key_info`: Validates the public key type and strength.
- `tls_version`: Validates the negotiated TLS version.
- `weak_cipher`: Validates that the negotiated cipher suite is in the allowed list.
- `sensitive_date`: Validates that the certificate doesn't expire on built-in or user specified sensitive dates.
- `chain`: Validates the full TLS certificate chain for structural problems (missing intermediates, out-of-order, expired members, weak signatures).
- `pq_key_exchange`: Reports PQ capability observed under a separate, unauthenticated TLS 1.3 probe offer. Opt-in.
- `pq_signature`: Reports the leaf certificate's post-quantum posture (the key and signature algorithm: ML-DSA / SLH-DSA / composite). Opt-in.
- `pq_chain`: Reports the post-quantum posture of every certificate in the presented chain. Opt-in.

The full catalog, with arguments and example output, is in the [Validators](validators/index.md) section.

> The `pq_*` validators are **opt-in** (not enabled by default). See [Post-Quantum Readiness](#post-quantum-readiness) below.

---

## 🔮 Post-Quantum Readiness

CertMonitor helps you measure your migration to **post-quantum cryptography (PQC)** across both surfaces that matter, using NIST's finalized standards (FIPS 203 **ML-KEM**, FIPS 204 **ML-DSA**, FIPS 205 **SLH-DSA**):

- **Key exchange (the urgent one).** TLS 1.3 hybrid key exchange (e.g. `X25519MLKEM768`) is what defends today's traffic against *harvest-now-decrypt-later* (HNDL), where an attacker records encrypted traffic now to decrypt once a quantum computer exists. The `pq_key_exchange` validator reads the negotiated group directly off the wire (the Python `ssl` module doesn't expose it) and reports capability evidence under that probe offer. It does not complete or authenticate a session, or prove protection of application traffic.
- **Certificate keys & signatures.** As CAs and operators roll out ML-DSA / SLH-DSA and composite (hybrid) certificates, `pq_signature` and `pq_chain` report the post-quantum posture of the leaf and the full chain.

"PQ" includes **hybrid** algorithms (classical + post-quantum), which is what real-world deployments use today. Both hybrid and pure PQ groups are recognized by the capability check.

```python
from certmonitor import CertMonitor

with CertMonitor("cloudflare.com", enabled_validators=["pq_key_exchange", "pq_signature", "pq_chain"]) as monitor:
    results = monitor.validate()
    print(results["pq_key_exchange"])
    # Illustrative abbreviated probe result (not a live guarantee):
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
export ENABLED_VALIDATORS="expiration,hostname,root_certificate,key_info,tls_version,weak_cipher"
```

---

## 🔎 Protocol Detection
CertMonitor automatically detects the protocol (SSL/TLS or SSH) for the target host. Services that greet in plaintext and upgrade with STARTTLS (SMTP, IMAP, POP3, FTP, PostgreSQL, LDAP) are discovered on any port and get the right preamble; pass `starttls=` to pin one. See [STARTTLS Services](usage/starttls.md). Most features are focused on SSL/TLS. SSH support is limited.

---

## 🚨 Error Handling
Ordinary retrieval failures return a dictionary with `error` and `message`. Validator failures return `is_valid: false` with a `reason` and dispatcher status. Always check for errors in returned data:
```python
cert = monitor.get_cert_info()
if isinstance(cert, dict) and "error" in cert:
    print("Error:", cert["message"])
```

---

## 🔐 Why Trust CertMonitor

CertMonitor's certificate parser handles untrusted bytes from every TLS handshake it monitors. We take that seriously:

- **Zero runtime dependencies.** No third-party Python packages; the Python layer uses only the standard library. The Rust extension's X.509 / DER parser is written in-house against the Rust standard library, with no third-party parsing crates in the runtime dependency tree.
- **`#![forbid(unsafe_code)]`** at the Rust crate root. No `unsafe` blocks anywhere in the parser. Memory safety is enforced by the Rust compiler, not by manual auditing.
- **Error-aware parsing.** Parser entry points return `Result` for malformed input. Regression tests and fuzzing exercise these paths; this is not proof that every possible input is handled correctly.
- **Manual fuzzing before release.** The repository includes a [cargo-fuzz](https://github.com/rust-lang/cargo-fuzz) target for adversarial byte sequences. Run a smoke check with `make fuzz` or a longer soak with `make fuzz-long`; this is separate from normal CI.
- **130-cert real-world corpus on every CI run.** Every commit is tested against captured certificates from 101 production hosts spanning Google Trust Services, DigiCert, Let's Encrypt, Sectigo, Cloudflare, and more, covering both RSA and ECDSA key types.
- **Python and Rust regression tests.** Local checks require at least 95% Python coverage; CI covers its configured Python and platform matrix. See the workflow and release results for the versions actually exercised.
- **`cargo audit` on every PR.** CertMonitor declares a single direct Rust dependency, `pyo3` (the Python bridge). Its transitive dependencies are recorded in Cargo.lock and scanned for known vulnerabilities on pull requests; no third-party X.509 parsing crate is used.

---

## 📄 License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/bradh11/certmonitor/blob/main/LICENSE) file for details.

---

<p align="center">
  <em>CertMonitor: Understand your certificates before they become an incident.</em>
</p>
