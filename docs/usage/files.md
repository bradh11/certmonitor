---
title: "Validate a Certificate File in Python"
description: "Run CertMonitor's certificate checks on a PEM, DER, or PKCS#7 file without a live TLS connection: expiration, hostname and SAN identity, key strength, chain structure, and post-quantum posture."
---

# Certificates from Files

Most of the time CertMonitor connects to a host and collects the certificate for you. Sometimes you already have the certificate: exported from a load balancer, handed over by a CA, pulled from a backup, or captured during an incident. `CertMonitor.from_file()` runs the same checks on that file, with no connection at all.

## Try it

Point it at a PEM, DER, or PKCS#7 file and say which name the certificate should be valid for:

```python
from certmonitor import CertMonitor

with CertMonitor.from_file("service.pem", host="service.example.com") as monitor:
    results = monitor.validate()
    for name, result in results.items():
        print(f"{name}: {result['status']}")
```

A PEM file may hold a whole chain, leaf first, and the `chain` validator will inspect all of it. A DER file holds one certificate. A certs-only PKCS#7 bundle, the `.p7b` or `.p7c` a Windows CA or a CA portal exports, is accepted in DER or PEM; since a bundle carries no order, CertMonitor picks as the leaf the certificate that issued none of the others, preferring an end-entity certificate over a CA when that is ambiguous, and chains the rest by issuer name. A self-signed certificate on its own, or with certificates it does not chain to, is loaded as the leaf like any other.

If the certificate is already in memory, use `CertMonitor.from_bytes()` with PEM text, DER bytes, or a PKCS#7 message instead. Everything below applies to both.

!!! note "`cafile` and `client_cert` stay PEM"
    Those two options are handed to Python's `ssl` module for the live trust handshake, and it reads PEM only. Convert a PKCS#7 CA bundle with `openssl pkcs7 -print_certs` before using it there.

## What works offline

Every check that only needs the certificate behaves exactly as it does after a live collection:

| Validator | Offline |
|---|---|
| `expiration`, `sensitive_date` | Yes |
| `hostname`, `subject_alt_names` | Yes, against the `host` you pass (or `expected_identity` / `alternate_names`) |
| `key_info`, `pq_signature` | Yes |
| `chain`, `pq_chain` | Yes, for the certificates in the file |
| `tls_version`, `weak_cipher`, `pq_key_exchange` | No: these describe a negotiated connection |
| `root_certificate` | No: trust is verified with a live handshake |

The checks that need a connection do not fail; they report `status: unsupported` with a reason, so a fleet report that mixes live and file-based results stays readable:

```json
{
  "is_valid": false,
  "status": "unsupported",
  "code": "tls_version.unsupported",
  "reason": "Cipher information requires a live connection; this certificate was loaded from a file."
}
```

`get_cert_info()`, `get_raw_der()`, `get_raw_pem()`, and the public key helpers all work. `get_cipher_info()` returns an `OfflineSource` error dict for the same reason.

## Identity needs a name

A file does not tell CertMonitor which host it is for, so pass `host`. Without it, `hostname` and `subject_alt_names` report `unsupported` rather than guessing an identity from the certificate itself, which would make the check pass by construction. You can also supply the identity per call:

```python
with CertMonitor.from_file("service.pem") as monitor:
    results = monitor.validate({
        "hostname": {"expected_identity": "service.example.com"},
        "subject_alt_names": {"alternate_names": ["www.service.example.com"]},
    })
```

## Where the certificate came from

Results carry the same `snapshot_at` timestamp as a live scan, and `monitor.cert_data["source"]` records the origin:

```json
{"type": "file", "path": "/etc/ssl/certs/service.pem"}
```

A live monitor reports `{"type": "connection", "host": ..., "port": ...}` in the same field. `refresh()` re-reads the file, so a monitor can watch a certificate that gets replaced on disk.

## Bad input

An unreadable path, an empty file, a PKCS#7 message with no certificates in it, or content that is not an X.509 certificate produces a `CertificateError` from `get_cert_info()`, and every certificate-based validator reports `status: error` with that class, the same shape a failed connection produces.
