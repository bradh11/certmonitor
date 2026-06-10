# PqChain Validator

Reports the **post-quantum posture of every certificate in the presented
chain**. During the staged PQ migration the leaf, intermediates, and root
rotate independently, so a single yes/no for the whole chain hides the
information operators actually need — this validator gives a per-certificate
view plus a role-level summary.

A certificate counts as PQ when **either** its public key algorithm or
its signature algorithm is post-quantum (standalone ML-DSA/SLH-DSA or a
composite). The signature is the issuing CA's choice rather than the
operator's, so both are tracked separately per link.

By default `is_valid: true` means **the leaf certificate's key is
post-quantum** — the part the operator controls. Pass
`require_full_chain: true` via validator args to demand the whole chain.

!!! note "Classical roots are expected"
    Chains that terminate at public trust anchors will report a
    classical root for the foreseeable future. **This is expected, not a
    bug** — root CAs migrate last.

## Opt-in

Registered but **disabled by default** (not in `DEFAULT_VALIDATORS`):

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["pq_chain"]) as m:
    print(m.validate()["pq_chain"])

# strict mode:
#   m.validate(validator_args={"pq_chain": {"require_full_chain": True}})
```

Chain retrieval requires Python 3.10+ (same constraint as the `chain`
validator); older interpreters get a structured error.

## Example output

A post-quantum leaf on a classical chain (the realistic migration shape):

```json
{
    "chain_length": 3,
    "certs": [
        {"position": 0, "role": "leaf", "key_algorithm": "ml-dsa-65",
         "key_is_pq": true, "signature_algorithm_oid": "1.2.840.113549.1.1.11",
         "signature_is_pq": false, "is_pq": true},
        {"position": 1, "role": "intermediate", "key_algorithm": "rsaEncryption",
         "key_is_pq": false, "signature_is_pq": false, "is_pq": false},
        {"position": 2, "role": "root", "key_algorithm": "rsaEncryption",
         "key_is_pq": false, "signature_is_pq": false, "is_pq": false}
    ],
    "summary": {"leaf_pq": true, "intermediate_pq": false, "root_pq": false},
    "is_valid": true
}
```

`summary` values are `null` for roles with no certificate in the chain
(e.g. a single self-signed cert has no intermediates).

::: certmonitor.validators.pq_chain.PqChainValidator
