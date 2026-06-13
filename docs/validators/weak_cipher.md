# WeakCipher Validator

Checks that the connection negotiated a cipher suite on your allow-list. The defaults follow Mozilla's "Intermediate" guidance (modern AEAD suites for TLS 1.2 plus the three TLS 1.3 suites), so legacy or weak ciphers (RC4, 3DES, CBC-mode, anything with MD5) fail.

!!! note "Opt-in"
    Enable via `enabled_validators=["weak_cipher", ...]` or `ENABLED_VALIDATORS`.

## Example

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["weak_cipher"]) as monitor:
    monitor.get_cert_info()
    print(monitor.validate()["weak_cipher"])
```

A strong negotiated suite passes:

```json
{
  "is_valid": true,
  "cipher_suite": "TLS_AES_256_GCM_SHA384"
}
```

A suite outside the allow-list fails with a `reason`:

```json
{
  "is_valid": false,
  "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5",
  "reason": "Cipher suite TLS_RSA_WITH_RC4_128_MD5 is not allowed. Please update your allowed cipher suites or negotiate a supported cipher."
}
```

## Customizing the allow-list

The default allowed set follows Mozilla's "Intermediate" configuration. Override it per call with the `allowed_cipher_suites` argument, passed through `validator_args`:

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["weak_cipher"]) as monitor:
    monitor.get_cert_info()
    result = monitor.validate(
        validator_args={
            "weak_cipher": {
                "allowed_cipher_suites": ["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"]
            }
        }
    )
    print(result["weak_cipher"])
```

!!! tip "TLS 1.2 and TLS 1.3 name suites differently"
    TLS 1.2 uses OpenSSL-style names (`ECDHE-RSA-AES256-GCM-SHA384`); TLS 1.3 uses IANA names (`TLS_AES_256_GCM_SHA384`). The default allow-list includes both families, so TLS 1.3 connections (the modern default) pass on their standard suites. If you supply a custom set, remember to include the TLS 1.3 names you expect to see.

## API

::: certmonitor.validators.weak_cipher.WeakCipherValidator
