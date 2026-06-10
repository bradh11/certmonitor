# Validators Overview

CertMonitor provides a modular validator system to check various aspects of SSL/TLS certificates and connections. Each validator can be enabled or disabled as needed, and some accept additional arguments for fine-grained control.

Available validators:

- [Expiration](expiration.md): Checks if the certificate is expired or expiring soon.
- [Hostname](hostname.md): Validates that the certificate matches the expected hostname.
- [SubjectAltNames](subject_alt_names.md): Checks the Subject Alternative Names (SANs) extension.
- [RootCertificate](root_certificate.md): Checks if the certificate is issued by a trusted root CA.
- [KeyInfo](key_info.md): Validates the public key type and strength.
- [TLSVersion](tls_version.md): Validates the negotiated TLS version.
- [WeakCipher](weak_cipher.md): Validates that the negotiated cipher suite is in the allowed list.
- [SensitiveDate](sensitive_date.md): Validates that the certificate doesn't expire on built-in or user specified sensitive dates.
- [Chain](chain.md): Inspects the full TLS certificate chain for structural problems (missing intermediates, out-of-order, expired members). Opt-in; requires Python 3.10+.
- [PqKeyExchange](pq_key_exchange.md): Judges whether the negotiated TLS key exchange is post-quantum (hybrid or pure ML-KEM). Opt-in.
- [PqChain](pq_chain.md): Reports the post-quantum posture of every certificate in the presented chain. Opt-in; requires Python 3.10+.
- [PqSignature](pq_signature.md): Judges the leaf certificate's post-quantum posture (key and signature algorithm). Opt-in.

See each page for usage and output examples.

## The result contract

Every validator returns a plain, JSON-serializable dict. Results from the
post-quantum validators conform to a standard envelope, declared as a
`TypedDict` in `certmonitor.validators.results.ValidationResult` so mypy can
enforce it without changing the runtime type:

| Key | Type | Rule |
|---|---|---|
| `is_valid` | `bool` | Always present, strict bool — never `None`. |
| `reason` | `str` | Present **iff** `is_valid` is `False`. One human-readable sentence stating the primary cause. |
| `warnings` | `List[str]` | Optional. Non-fatal findings. |
| `error` | `str` | Optional. Machine-readable error class on operational failures. |
| `message` | `str` | Optional. Human-readable detail accompanying `error`. |

All other keys are validator-specific **data** fields: snake_case, documented
on the validator's page, and stable across releases. The five reserved keys
above are never reused for data.

Two corollaries:

1. **Operational failures are still results.** A validator whose data source
   cannot be fetched (connection error, probe failure, chain missing) still
   appears in `validate()` output with `is_valid: False` and a `reason` — it
   is never silently omitted, so `results["<name>"]` never raises `KeyError`
   in a monitoring pipeline.
2. **Schema is static-only.** A custom validator declares its full shape by
   extending `ValidationResult` with its data fields (see
   `pq_signature.py` for an example); the value your code receives is still
   an ordinary dict.

The pre-existing validators (`expiration`, `key_info`, …) predate this
contract and keep their legacy shapes for now — notably `key_info` may
return `is_valid: None` for unknown key types. They will migrate behind a
deprecation cycle.

---

<!-- Individual validator API documentation is now only in their respective pages to avoid mkdocs_autorefs duplicate anchor warnings. -->
