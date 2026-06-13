# Validators Overview

CertMonitor provides a modular validator system to check various aspects of SSL/TLS certificates and connections. Each validator returns a structured, JSON-serializable result (not a bare pass/fail), so you can drive alerts, dashboards, and policy from rich data. Validators can be enabled or disabled per call, and some accept arguments for fine-grained control.

This includes **post-quantum readiness**: opt-in validators report whether the TLS key exchange and the certificate's keys/signatures use post-quantum algorithms (hybrid or pure ML-KEM / ML-DSA / SLH-DSA), so you can track quantum-safe migration and *harvest-now-decrypt-later* exposure. See [Post-Quantum Readiness](#post-quantum-readiness) below.

## Registered vs. enabled

Two words worth keeping straight. A validator is **registered** when CertMonitor knows it exists (every built-in, plus any you add yourself). It's **enabled** when it actually runs for a given monitor. Enabled is always a subset of registered: only `expiration`, `hostname`, and `root_certificate` run by default, and everything else is registered but waits until you opt in.

<div class="validator-map">
  <p class="validator-map__label">Registered: every validator CertMonitor knows about</p>
  <div class="validator-group validator-group--enabled">
    <p class="validator-group__title">Enabled by default <small>runs on every <code>validate()</code> call</small></p>
    <div class="validator-chips">
      <span class="validator-chip validator-chip--on">expiration</span>
      <span class="validator-chip validator-chip--on">hostname</span>
      <span class="validator-chip validator-chip--on">root_certificate</span>
    </div>
  </div>
  <div class="validator-group validator-group--optin">
    <p class="validator-group__title">Opt-in <small>registered and ready, off until you enable it</small></p>
    <div class="validator-chips">
      <span class="validator-chip">subject_alt_names</span>
      <span class="validator-chip">key_info</span>
      <span class="validator-chip">tls_version</span>
      <span class="validator-chip">weak_cipher</span>
      <span class="validator-chip">sensitive_date</span>
      <span class="validator-chip">chain</span>
      <span class="validator-chip">pq_key_exchange</span>
      <span class="validator-chip">pq_signature</span>
      <span class="validator-chip">pq_chain</span>
    </div>
  </div>
</div>

The default three run out of the box. The opt-in validators are registered and ready, but stay off until you name them in `enabled_validators` or `ENABLED_VALIDATORS`. To register and enable your own custom validators, see [Custom Validators](../usage/custom_validators.md).

## Available validators

**Enabled by default** (`expiration`, `hostname`, `root_certificate`):

- [Expiration](expiration.md): Checks if the certificate is expired or expiring soon.
- [Hostname](hostname.md): Validates that the certificate matches the expected hostname.
- [RootCertificate](root_certificate.md): Checks if the certificate is issued by a trusted root CA.

**Opt-in** (enable via `enabled_validators=[...]` or `ENABLED_VALIDATORS`):

- [SubjectAltNames](subject_alt_names.md): Checks the Subject Alternative Names (SANs) extension.
- [KeyInfo](key_info.md): Validates the public key type and strength (RSA / EC / post-quantum).
- [TLSVersion](tls_version.md): Validates the negotiated TLS version.
- [WeakCipher](weak_cipher.md): Validates that the negotiated cipher suite is in the allowed list.
- [SensitiveDate](sensitive_date.md): Validates that the certificate doesn't expire on built-in or user specified sensitive dates.
- [Chain](chain.md): Inspects the full TLS certificate chain for structural problems (missing intermediates, out-of-order, expired members). Requires Python 3.10+.
- [PqKeyExchange](pq_key_exchange.md): Judges whether the negotiated TLS key exchange is post-quantum (hybrid or pure ML-KEM).
- [PqChain](pq_chain.md): Reports the post-quantum posture of every certificate in the presented chain. Requires Python 3.10+.
- [PqSignature](pq_signature.md): Judges the leaf certificate's post-quantum posture (key and signature algorithm).

## What the output looks like

Validators return data, not just a boolean. Enable the ones you want and read the structured results:

```python
from certmonitor import CertMonitor

with CertMonitor(
    "example.com",
    enabled_validators=["expiration", "key_info", "tls_version", "weak_cipher"],
) as monitor:
    monitor.get_cert_info()
    results = monitor.validate()
```

```json
{
  "expiration": {
    "is_valid": true,
    "days_to_expiry": 56,
    "expires_on": "2026-08-08T22:14:02+00:00",
    "warnings": []
  },
  "key_info": {
    "key_type": "ecPublicKey",
    "key_size": 256,
    "is_valid": true,
    "curve": "secp256r1"
  },
  "tls_version": {
    "is_valid": true,
    "protocol_version": "TLSv1.3"
  },
  "weak_cipher": {
    "is_valid": true,
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  }
}
```

When a check fails, the same envelope carries a human-readable `reason` you can surface directly in an alert:

```json
{
  "expiration": {
    "is_valid": false,
    "days_to_expiry": -4080,
    "expires_on": "2015-04-12T23:59:59+00:00",
    "warnings": ["Certificate is expired and has been expired for (-4080 days)"],
    "reason": "Certificate expired 4080 days ago (expired on 2015-04-12)."
  }
}
```

Because every validator's result is a plain dict keyed by validator name, a monitoring pipeline can do `if not results["expiration"]["is_valid"]: alert(results["expiration"]["reason"])` without special-casing.

## Post-Quantum Readiness

The `pq_*` validators answer the questions classical TLS tooling can't. `pq_key_exchange` reads the negotiated TLS 1.3 group directly off the wire (the Python `ssl` module doesn't expose it) and tells you whether the session is protected against *harvest-now-decrypt-later*:

```python
with CertMonitor("cloudflare.com", enabled_validators=["pq_key_exchange"]) as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["pq_key_exchange"])
```

```json
{
  "kem_id": 4588,
  "kem_name": "X25519MLKEM768",
  "kem_kind": "hybrid_pq",
  "is_pq": true,
  "is_valid": true
}
```

`pq_signature` and `pq_chain` report the post-quantum posture of the leaf and the full chain as CAs roll out ML-DSA / SLH-DSA and composite certificates. All three are opt-in while PQC adoption ramps. See their pages for the decision flows and field-by-field output.

## The result contract

Every validator returns a plain, JSON-serializable dict. **All** validators
conform to a standard envelope, declared as a `TypedDict` in
`certmonitor.validators.results.ValidationResult` so mypy can enforce it
without changing the runtime type:

| Key | Type | Rule |
|---|---|---|
| `is_valid` | `bool` | Always present, strict bool, never `None`. |
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
   appears in `validate()` output with `is_valid: False` and a `reason`; it
   is never silently omitted, so `results["<name>"]` never raises `KeyError`
   in a monitoring pipeline.
2. **Schema is static-only.** A custom validator declares its full shape by
   extending `ValidationResult` with its data fields (see
   `pq_signature.py` for an example); the value your code receives is still
   an ordinary dict.
3. **`is_valid` is always a strict `bool`.** When a validator cannot
   determine an answer (e.g. `key_info` facing an unrecognized algorithm),
   it fails closed (`is_valid: False` with an explanatory `reason`) rather
   than returning `None`.

---

<!-- Individual validator API documentation is now only in their respective pages to avoid mkdocs_autorefs duplicate anchor warnings. -->
