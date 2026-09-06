---
title: "Certificate Revocation Checking with OCSP and CRLs"
description: "Opt-in revocation checking for TLS certificates: OCSP responders and CRL distribution points, with verified CRL answers through OpenSSL and no third-party dependencies."
---

# Revocation Validator

Checks whether the certificate has been revoked, using the pointers the certificate itself carries: its OCSP responder URL and its CRL distribution points.

!!! note "Opt-in"
    `revocation` is registered but off by default. Enable it with `enabled_validators=["revocation"]`, `ENABLED_VALIDATORS=revocation`, or `certmonitor check -v revocation`.

A revoked certificate is otherwise a perfectly healthy one: it chains to a trusted CA, its dates are fine, its hostname matches. Every other validator passes it. This is the one that doesn't.

## Try it

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["revocation"]) as monitor:
    result = monitor.validate()["revocation"]
    print(result["status"], result["revocation_status"], result["source"])
```

```sh
certmonitor check example.com -v revocation
```

A certificate that no source lists as revoked passes:

```json
{
  "is_valid": true,
  "status": "pass",
  "revocation_status": "good",
  "source": "crl",
  "signature_verified": true,
  "this_update": "2026-09-06T00:00:00+00:00",
  "next_update": "2026-09-13T00:00:00+00:00",
  "revocation_time": null,
  "revocation_reason": null,
  "methods": {
    "ocsp": {"status": "good", "signature_verified": false, "url": "http://ocsp.example"},
    "crl": {"status": "good", "signature_verified": true, "url": "http://crl.example/ca.crl", "revoked_count": 1204}
  }
}
```

A revoked one fails, and says when and why:

```json
{
  "is_valid": false,
  "status": "fail",
  "reason": "The certificate was revoked on 2026-09-01T00:00:00+00:00 (key_compromise) according to OCSP.",
  "revocation_status": "revoked",
  "source": "ocsp",
  "revocation_time": "2026-09-01T00:00:00+00:00",
  "revocation_reason": "key_compromise"
}
```

## How the two sources are used

Each method in `methods` is consulted in order, OCSP first by default:

1. **A `revoked` answer from any source fails the check at once.** A forged "revoked" can only cause a false alarm, never hide a real one, so it is acted on even before the signature question below is settled.
2. **A `good` answer passes only when it is proven.** CRL answers are: the CRL is loaded into a verifying TLS context and OpenSSL checks its signature against the trusted CA, its validity window, and the leaf's serial, all in one extra handshake. OCSP answers are not verified yet, so an OCSP `good` on its own is reported as `warn` and the next method is consulted. If the CRL then confirms it, the result is a verified `pass` with `source: "crl"`.
3. **Nothing usable is an error, never a pass.** If every source is unreachable, stale, or answers about the wrong certificate, the result is `status: "error"` with each source's problem in `reason`.

The per-method detail always lands in `methods`, so you can see what each source said even when the verdict came from the other one.

!!! note "Why OCSP is a warning for now"
    Verifying an OCSP response means checking the responder's signature, and the Python standard library has no primitive for that. CertMonitor's zero-dependency rule holds, so verification is being added to the in-house Rust extension. Until it lands, `signature_verified` is `false` on OCSP answers and an OCSP-only `good` is a warning. If you accept the responder's word, set `accept_unverified=True` and it becomes a `pass`.

## Arguments

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `methods` | `list[str]` | `["ocsp", "crl"]` | Sources to consult, in order. Any subset of `ocsp` and `crl`. |
| `accept_unverified` | `bool` | `False` | Treat an OCSP `good` whose signature was not verified as a pass instead of a warning. |

```python
monitor.validate({"revocation": {"methods": ["crl"]}})
monitor.validate({"revocation": {"methods": ["ocsp"], "accept_unverified": True}})
```

```sh
certmonitor check example.com -v revocation --arg 'revocation.methods=["crl"]'
```

## What it costs

- **OCSP** is one small HTTP `POST` to the responder. The request is built from the certificate's serial and its issuer's name and key, so the issuer certificate is needed; it comes from the served chain, or from the certificate's `caIssuers` pointer when the server sends only the leaf.
- **CRL** is one download plus one TLS handshake. CRLs range from a few kilobytes to many megabytes; the download is capped at 16 MiB.
- **Both are cached** process-wide until their `nextUpdate`, so a fleet scan fetches each CA's CRL and each certificate's OCSP answer once. Set `methods=["crl"]` when many hosts share a CA and you want one download for all of them.
- **Fetches respect the monitor's `timeout` and `proxy`**, including SOCKS5, because they go through the same connection code as everything else.

## When it reports `unsupported`

- The certificate carries no OCSP URL and no CRL distribution point. Some private CAs issue certificates like this.
- The monitor was built from a file with `CertMonitor.from_file()`. Offline monitors never touch the network, so both methods report `unsupported` there.
- The only pointers are `ldap://` URIs, which CertMonitor does not fetch.

## Result fields

| Field | Meaning |
|---|---|
| `revocation_status` | `good`, `revoked`, or `unknown` (the source had no record of this certificate). |
| `source` | The method whose answer produced the verdict, `ocsp` or `crl`. |
| `signature_verified` | Whether that answer's signature was checked. Always `true` for CRL answers. |
| `this_update`, `next_update` | The answer's validity window, ISO 8601 UTC. |
| `revocation_time`, `revocation_reason` | Set when revoked; the reason uses RFC 5280 names such as `key_compromise` or `superseded`. |
| `methods` | Every method consulted, with its own status, URL, timing, and any error. |

See also [RootCertificate](root_certificate.md), which establishes trust in the chain, and the [result contract](index.md#the-result-contract) for `status` and `code`.
