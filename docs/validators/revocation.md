---
title: "Certificate Revocation Checking with OCSP and CRLs"
description: "Opt-in revocation checking for TLS certificates: OCSP responders and CRL distribution points, both verified, with no third-party dependencies."
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
  "source": "ocsp",
  "signature_verified": true,
  "this_update": "2026-09-06T00:00:00+00:00",
  "next_update": "2026-09-13T00:00:00+00:00",
  "revocation_time": null,
  "revocation_reason": null,
  "methods": {
    "ocsp": {"status": "good", "signature_verified": true, "url": "http://ocsp.example", "responder_name": {"commonName": "Example Issuing CA"}}
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

1. **Only a proven answer decides.** The signature question comes before the answer's content, for `revoked` as much as for `good` (RFC 6960 §3.2). A response that fails verification was tampered with or signed by the wrong party, and acting on its "revoked" would let anyone on the path to the responder raise false alarms and skip a CRL that holds the truth.
2. **A `good` answer passes only when it is proven.** OCSP answers are verified in-house: the response must be signed by the issuing CA, or by a responder certificate that the CA issued for OCSP signing and that is valid today (RFC 6960 §4.2.2.2), using RSA PKCS#1 v1.5 or ECDSA over P-256 or P-384. CRL answers are proven by OpenSSL: the CRL is loaded into a verifying TLS context and its signature, validity window, and the leaf's serial are checked in one extra handshake. A `good` that cannot be verified, say a response signed with an algorithm CertMonitor does not implement, is reported as `warn` with the reason in `verification_error`, and the next method is consulted; if the CRL then confirms it, the result is a verified `pass` with `source: "crl"`.
3. **A response whose signature was checked and is wrong is no evidence at all**, whether it says `good` or `revoked`. It is discarded before its content is read, not even `accept_unverified` rescues it, the next method is consulted, and if nothing else answers the result is `status: "error"` with `error: "OCSPInvalidSignature"`. A response that could not be checked is held back instead: an unverified `good` is a `warn`, an unverified `revoked` is an `error` with `error: "OCSPUnverifiedRevocation"` so it is visible without being treated as proof. `methods.ocsp.verification` tells the cases apart: `verified`, `unsupported` (could not check), or `failed` (checked and wrong).
4. **Nothing usable is an error, never a pass.** If every source is unreachable, stale, or answers about the wrong certificate, the result is `status: "error"` with each source's problem in `reason`.

The per-method detail always lands in `methods`, so you can see what each source said even when the verdict came from the other one.

!!! note "How verification stays dependency-free"
    The Python standard library has no primitive for checking an RSA or ECDSA signature, so CertMonitor's Rust extension carries its own: big-integer arithmetic, RSASSA-PKCS1-v1_5, and ECDSA over the two NIST curves CAs actually use for responders. It is verification only, tested against RFC 6979 vectors and against real `openssl` output. Responses signed with something else (RSA-PSS, Ed25519, other curves) are reported with `signature_verified: false` and the algorithm named in `verification_error`. Set `accept_unverified=True` if you are willing to take such a responder's word.

## Arguments

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `methods` | `list[str]` | `["ocsp", "crl"]` | Sources to consult, in order. Any subset of `ocsp` and `crl`. |
| `accept_unverified` | `bool` | `False` | Act on an OCSP answer whose signature could not be checked (unsupported algorithm) as if it were verified: `good` passes, `revoked` fails. Never applies to a signature that was checked and failed. |

```python
monitor.validate({"revocation": {"methods": ["crl"]}})
monitor.validate({"revocation": {"methods": ["ocsp"], "accept_unverified": True}})
```

```sh
certmonitor check example.com -v revocation --arg 'revocation.methods=["crl"]'
```

## What it costs

- **OCSP** is one small HTTP `POST` to the responder. The request is built from the certificate's serial and its issuer's name and key, so the issuer certificate is needed; it comes from the served chain, or from the certificate's `caIssuers` pointer when the server sends only the leaf. Verifying the response takes a few milliseconds of arithmetic.
- **CRL** is one download plus one TLS handshake. CRLs range from a few kilobytes to many megabytes; the download is capped at 16 MiB.
- **Both are cached** process-wide until their `nextUpdate` and never a second longer: the cache reuses signed evidence only while the signer said it was valid. A fleet scan therefore fetches each CA's CRL and each certificate's OCSP answer once per validity window. Set `methods=["crl"]` when many hosts share a CA and you want one download for all of them.
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
| `signature_verified` | Whether that answer's signature was checked. Always `true` for CRL answers; `true` for OCSP when the responder's signature verified. `methods.ocsp.verification` is `verified`, `unsupported`, or `failed`, and `verification_error` explains anything but `verified`. |
| `this_update`, `next_update` | The answer's validity window, ISO 8601 UTC. |
| `revocation_time`, `revocation_reason` | Set when revoked; the reason uses RFC 5280 names such as `key_compromise` or `superseded`. |
| `methods` | Every method consulted, with its own status, URL, timing, and any error. |

See also [RootCertificate](root_certificate.md), which establishes trust in the chain, and the [result contract](index.md#the-result-contract) for `status` and `code`.
