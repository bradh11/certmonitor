# PqKeyExchange Validator

Reports the **post-quantum posture of the TLS key exchange** — the
*harvest-now-decrypt-later* (HNDL) question: is this session's key
agreement protected against a future quantum computer?

It consumes the negotiated cipher info plus a second-connection TLS probe
(`certinfo.probe_tls_handshake`) that reads the negotiated TLS 1.3
key-exchange group off the wire — something the Python `ssl` module does
not expose.

"PQ" includes **hybrid** groups (classical + ML-KEM, e.g.
`X25519MLKEM768`) as well as pure ML-KEM; requiring pure PQ today would
fail every real-world server. `is_valid` is a strict `bool`.

## Opt-in

Registered but **disabled by default** (not in `DEFAULT_VALIDATORS`).
Enable it explicitly:

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["pq_key_exchange"]) as m:
    print(m.validate()["pq_key_exchange"])
```

or via `ENABLED_VALIDATORS=...,pq_key_exchange`.

## Behavior

| Server | Result |
|---|---|
| TLS 1.3 + hybrid/pure PQ group | `is_valid: true` |
| TLS 1.3 + classical group | `is_valid: false` — classical KEX, HNDL-exposed |
| TLS 1.2 or older | `is_valid: false` — no PQ KEMs defined |
| Connection / probe error | `{error, message, is_valid: false}` |

**Skip-for-legacy:** the probe opens a second TCP connection only when the
primary connection negotiated TLS 1.3. For TLS 1.2 and older the result
is determined without any extra connection.

**Second connection:** when it does run, the probe is a separate TCP
connection to the host; IDS/rate-limiters may observe it. This is one
reason the validator is opt-in.

## Example output

Hybrid PQ (pass):

```json
{
    "kem_id": 4588,
    "kem_name": "X25519MLKEM768",
    "kem_kind": "hybrid_pq",
    "is_pq": true,
    "is_valid": true
}
```

Classical (fail):

```json
{
    "kem_id": 29,
    "kem_name": "x25519",
    "kem_kind": "classical_ecdh",
    "is_pq": false,
    "is_valid": false,
    "reason": "classical key exchange (x25519) is vulnerable to harvest-now-decrypt-later"
}
```

::: certmonitor.validators.pq_key_exchange.PqKeyExchangeValidator
