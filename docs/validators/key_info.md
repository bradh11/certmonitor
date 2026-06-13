# KeyInfo Validator

The `key_info` validator judges the strength of the certificate's public key, per algorithm family:

- **RSA** — modulus must be at least 2048 bits.
- **EC** — curve must be one of `secp256r1`, `secp384r1`, `secp521r1`.
- **Post-quantum** (ML-DSA, SLH-DSA, composite ML-DSA) — strong by algorithm identity; the FIPS 204/205 parameter sets have no weak sizes or curves. The recognized set comes from the Rust registry via `certinfo.pq_algorithms()`.

Per the result envelope, `is_valid` is always a strict `bool`. When strength **cannot be determined** (an unrecognized algorithm, or a missing size/curve) the key **fails closed** — `is_valid: false` with a `reason` that distinguishes "cannot determine" from "recognized but weak".

## How it decides

```mermaid
flowchart TD
    A[validate called] --> B{public_key_info present?}
    B -- No --> Z["is_valid: false<br/>cannot extract key info"]
    B -- Yes --> C{Algorithm family?}
    C -- "Post-quantum<br/>(ML-DSA / SLH-DSA / composite)" --> D["is_valid: true<br/>strong by identity"]
    C -- RSA --> E{Modulus &ge; 2048 bits?}
    E -- Yes --> D
    E -- "No / size missing" --> F["is_valid: false + reason"]
    C -- EC --> H{Curve in approved set?<br/>secp256r1 / secp384r1 / secp521r1}
    H -- Yes --> D
    H -- "No / curve missing" --> F
    C -- "Other / unknown" --> K["is_valid: false<br/>cannot determine — fails closed"]
```

## API

::: certmonitor.validators.key_info.KeyInfoValidator
