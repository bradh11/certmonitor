# Chain Validator

The `chain` validator inspects the **full certificate chain** the server presented during the TLS handshake and reports structural problems: missing intermediates, out-of-order chains, expired members, weak signature algorithms, and non-CA intermediates. It does not perform cryptographic signature verification — that is deliberately left out to keep the Rust dependency footprint minimal.

## Opting in

The chain validator is **registered but disabled by default** because it performs heavier work than the other validators and needs Python 3.10 or newer to retrieve the chain. Enable it by naming it explicitly:

```python
from certmonitor import CertMonitor

with CertMonitor(
    "example.com",
    enabled_validators=["expiration", "hostname", "root_certificate", "chain"],
) as monitor:
    monitor.get_cert_info()
    result = monitor.validate()
    print(result["chain"])
```

Or via the environment:

```sh
ENABLED_VALIDATORS=expiration,hostname,root_certificate,chain
```

## User-configurable arguments

Pass via `validator_args={"chain": {...}}`:

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `min_chain_length` | `int` | `2` | Minimum acceptable number of certificates in the chain. The default rejects servers that only send the leaf. |
| `require_root_in_chain` | `bool` | `False` | Require the chain to terminate in a self-signed root. Most well-configured public servers omit the root, so the default emits a warning rather than failing. |
| `allow_self_signed_leaf` | `bool` | `False` | Accept a self-signed leaf. Useful for internal services. |
| `weak_signature_algorithms` | `Optional[List[str]]` | `None` | Override the default weak-signature OID set. Pass `[]` to disable the weak-signature warning entirely. |

The default weak-signature set includes `sha1WithRSAEncryption`, `md5WithRSAEncryption`, `md2WithRSAEncryption`, `ecdsa-with-SHA1`, and `dsa-with-sha1`.

## Output

```json
{
  "is_valid": true,
  "chain_length": 3,
  "chain_ordered": true,
  "terminates_in_self_signed": true,
  "certs": [
    {
      "position": 0,
      "role": "leaf",
      "subject": {"commonName": "example.com"},
      "issuer": {"commonName": "Intermediate CA"},
      "not_before": "2025-01-01T00:00:00+00:00",
      "not_after": "2026-01-01T00:00:00+00:00",
      "days_to_expiry": 180,
      "is_ca": false,
      "is_self_signed": false,
      "signature_algorithm_oid": "1.2.840.113549.1.1.11",
      "subject_key_identifier": "ac33ac35b5f88ae27b06d23dc7058997d81c2443",
      "authority_key_identifier": "de1b1eed7915d43e3724c321bbec34396d42b230",
      "public_key_info": {"algorithm": "ecPublicKey", "size": 256, "curve": "1.2.840.10045.2.1"},
      "warnings": []
    }
  ],
  "warnings": []
}
```

On failure, `is_valid` is `false` and a `reason` field is added.

## Python version requirement

Chain retrieval relies on `SSLSocket.get_verified_chain()` (Python 3.13+) or the stable `_sslobj.get_unverified_chain()` attribute (Python 3.10–3.12). On Python 3.8 or 3.9 the validator returns an informative error dict rather than silently degrading. The rest of CertMonitor continues to work on 3.8+.

## What is out of scope

- **Cryptographic signature verification.** Structural validation (`subject(parent) == issuer(child)` plus SKI/AKI matching) catches the real-world misconfigurations this validator is built for. Real signature verification would require pulling `ring` into the Rust dependency tree and is deliberately left for a future iteration.
- **OCSP / CRL revocation checks.** Same reasoning — network I/O and responder parsing belong in their own validator.
- **Building a path against the system trust store.** `CertMonitor` intentionally uses `ssl.CERT_NONE` so it can profile misconfigured and legacy servers.

::: certmonitor.validators.chain.ChainValidator
