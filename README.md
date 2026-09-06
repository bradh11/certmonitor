<p align="center">
  <a href="https://certmonitor.readthedocs.io/">
    <img src="https://cdn.jsdelivr.net/gh/bradh11/certmonitor@main/docs/images/logo.svg" alt="CertMonitor Logo" width="120" height="120">
  </a>
</p>

# CertMonitor

CertMonitor is a Python library for SSL/TLS certificate monitoring, expiration checks, hostname/SAN validation, X.509 chain analysis, and post-quantum readiness.

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

## 📦 Installation & Quickstart

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

Once installed, here's the pattern you'll use most often. Connect to a host, pull the certificate details, and run the validators:

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    cert_data = monitor.get_cert_info()
    validation_results = monitor.validate()
    print(cert_data)
    print(validation_results)
```

`get_cert_info()` gives you the parsed certificate. `validate()` runs the checks and can collect it automatically if you have not fetched it yet.

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

## ✨ Features

- 🔒 **Zero Dependencies:** no third-party Python runtime dependencies, ever. The required native extension is distributed in platform wheels.
- 📄 **Files too:** `CertMonitor.from_file()` runs the certificate checks on a PEM or DER file with no connection at all. See [Certificates from Files](https://certmonitor.readthedocs.io/en/latest/usage/files/).
- ⌨️ **Command line:** `certmonitor check example.com` runs the same validators from the shell, with `--json` output and exit codes for cron and CI. See [Command Line](https://certmonitor.readthedocs.io/en/latest/usage/cli/).
- 🛡️ **Certificate Validators:** Modular checks for expiration, hostname, SANs, key strength, protocol, ciphers, and more.
- ⚡ **Batch Monitoring:** overlap network waits with independent monitors and bounded workers.
- 🧩 **Extensible:** Add your own custom validators for organization-specific checks.
- 🔮 **Post-Quantum Readiness:** Opt-in validators detect post-quantum (hybrid/pure **ML-KEM**) TLS key exchange and post-quantum certificate keys/signatures (**ML-DSA**, **SLH-DSA**, composite), so you can track quantum-safe migration and *harvest-now-decrypt-later* exposure. See [below](#-post-quantum-readiness).
- 🐍 **Python API:** package metadata accepts Python 3.10 to 3.15; use a matching native wheel or build from source.
- 🦀 **Rust-Powered Parsing:** Certificate parsing and public key extraction are handled by a Rust extension for speed, safety, and correctness. <strong>This is required for advanced public key and elliptic curve features, but all orchestration and logic are pure Python stdlib.</strong>
- 📦 **Distribution:** install a compatible native wheel, or build from source with Rust and a platform C toolchain.
- 📝 **Comprehensive Docs:** [ReadTheDocs](https://certmonitor.readthedocs.io/) with usage, API, and advanced guides.

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
- `subject_alt_names`: Checks requested alternate DNS/IP identities against the SANs, or the primary host when none are given.
- `root_certificate`: Validates if the certificate is issued by a trusted root CA.
- `key_info`: Validates the public key type and strength.
- `tls_version`: Validates the negotiated TLS version.
- `weak_cipher`: Validates that the negotiated cipher suite is in the allowed list.
- `sensitive_date`: Validates that the certificate doesn't expire on built-in or user specified sensitive dates.
- `chain`: Validates the full TLS certificate chain for structural problems (missing intermediates, out-of-order, expired members, weak signatures).
- `pq_key_exchange`: Reports PQ capability observed under a separate, unauthenticated TLS 1.3 probe offer. Opt-in.
- `pq_signature`: Reports the leaf certificate's post-quantum posture (the key and signature algorithm: ML-DSA / SLH-DSA / composite). Opt-in.
- `pq_chain`: Reports the post-quantum posture of every certificate in the presented chain. Opt-in.

> The `pq_*` validators are **opt-in** (not enabled by default). See [Post-Quantum Readiness](#-post-quantum-readiness) below.

---

## 🔮 Post-Quantum Readiness

CertMonitor helps you measure your migration to **post-quantum cryptography (PQC)** across both surfaces that matter, using NIST's finalized standards (FIPS 203 **ML-KEM**, FIPS 204 **ML-DSA**, FIPS 205 **SLH-DSA**):

- **Key exchange (the urgent one).** TLS 1.3 hybrid key exchange (e.g. `X25519MLKEM768`) is what defends today's traffic against *harvest-now-decrypt-later* (HNDL), where an attacker records encrypted traffic now to decrypt once a quantum computer exists. The `pq_key_exchange` validator observes the group selected or requested on a separate, unauthenticated probe. It reports capability under that offer; it does not verify protection of the original session or application traffic.
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

These validators are **opt-in** (not in the default set) while PQC adoption is still ramping. Full details: [PqKeyExchange](docs/validators/pq_key_exchange.md) · [PqSignature](docs/validators/pq_signature.md) · [PqChain](docs/validators/pq_chain.md).

---

## 📚 Learn How It Works

New to TLS, certificates, or the post-quantum transition? The docs include vendor-neutral explainers with diagrams:

- [How TLS & HTTPS Work](docs/concepts/how-tls-works.md): the handshake, and the key-exchange-vs-signatures split.
- [Certificates & PKI](docs/concepts/certificates-and-pki.md): what's in a certificate and how the chain of trust works.
- [Post-Quantum Cryptography](docs/concepts/post-quantum.md): the quantum threat, harvest-now-decrypt-later, and the NIST standards.

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
CertMonitor automatically detects the protocol (SSL/TLS or SSH) for the target host. Most features are focused on SSL/TLS. SSH support is limited.

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
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---


### Validation snapshots and trust

`validate()` collects certificate data automatically. Certificate metadata is
cached as a snapshot with `snapshot_at` in UTC; call `refresh()` to reconnect
and collect a renewal. `close()` clears the connection while retaining the
last snapshot for inspection. A new connection or `refresh()` clears the old
snapshot before collecting another certificate.

The default `root_certificate` check performs a separate verified
handshake using the system trust store (or `cafile` / `capath`). Its leaf
must match the collected snapshot. A changed leaf produces
`SnapshotMismatch`, requiring refresh. Trust verification does not check
revocation; `revocation_status` is `not_checked`. The default `hostname` check uses DNS/IP SANs for identity validation and
reports `common_name` / `common_name_matches` as informational fields.
CN matching never overrides the SAN-based result. The opt-in
`subject_alt_names` validator checks the `alternate_names` you request, or
the primary host when none are given.

```python
from certmonitor import CertMonitor, scan_hosts

with CertMonitor(
    "service.example.com",
    connection_host="192.0.2.10",
    cafile="/path/to/private-ca.pem",
    timeout=5,
) as monitor:
    results = monitor.validate({
        "expiration": {"warning_days": 30, "critical_days": 3,
                       "max_lifetime_days": 200},
    })
    print(results)
    monitor.refresh()

for result in scan_hosts(["example.com", "example.org"], max_workers=4, timeout=5):
    print(result)
```

Client authentication accepts `client_cert` and optional `client_key` paths.
Expiration checks both validity boundaries and warns when the total lifetime
exceeds the public TLS limit that applied on the issue date (200 days from
March 2026, 100 from March 2027, 47 from March 2029). Set `max_lifetime_days`
to a number for a private PKI policy, or `None` to disable the check.
Results from `validate()` retain `is_valid` and add `status`
(`pass`, `warn`, `fail`, `error`, `unsupported`) and a stable
`<validator>.<status>` code.

`chain` reports structural policy separately from trust. Non-CA issuers and
weak signatures fail by default; `reject_weak_signatures=False` permits
weak signatures with warnings. Subject/issuer name equality does not verify
a signature, including for certificates labeled self-signed.

The timeout bounds each network operation, including each connection attempt
made while collecting the certificate, not the entire scan. OS DNS resolution
cannot be interrupted by these socket timeouts. Concurrency and queued
endpoints are bounded by `max_workers`. Cipher/TLS checks describe the
negotiated connection, not an exhaustive inventory of server-supported
protocols or ciphers. The native PQ probe connects to `connection_host` and
offers `server_hostname` as SNI, so split-address configurations are probed.

Release CI builds Linux x64/ARM64 wheels targeting glibc 2.28+, macOS
Intel/ARM64 wheels, Windows x64 wheels, and a source distribution.
These targets require CI verification before release.
