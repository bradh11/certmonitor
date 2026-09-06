---
title: "Validate Alternate Hostnames in Certificate SANs"
description: "Check that every requested alternate hostname or IP address appears in a certificate's Subject Alternative Names, with per-name validation results."
---

# SubjectAltNames Validator

Inspects the certificate's Subject Alternative Names (SANs): the authoritative list of hostnames and IPs a certificate is valid for. Use it to check that extra names you expect (apex + `www`, alternate domains) are present, and to surface the full SAN inventory.

!!! note "Opt-in"
    Enable explicitly via `enabled_validators=["subject_alt_names", ...]` or the `ENABLED_VALIDATORS` environment variable.

## Try it

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["subject_alt_names"]) as monitor:
    monitor.get_cert_info()
    result = monitor.validate(
        validator_args={"subject_alt_names": {"alternate_names": ["www.example.com"]}}
    )
    print(result["subject_alt_names"])
```

These examples show selected fields from illustrative scans. `validate()` also adds `status` and `code`, described in the [result contract](index.md#the-result-contract).

```json
{
  "is_valid": true,
  "sans": {"DNS": ["example.com", "*.example.com"], "IP Address": []},
  "count": 2,
  "contains_host": {
    "name": "example.com",
    "is_valid": true,
    "reason": "Exact match for example.com found in DNS SANs"
  },
  "contains_alternate": {
    "www.example.com": {
      "name": "www.example.com",
      "is_valid": true,
      "reason": "www.example.com matches wildcard SAN(s): *.example.com"
    }
  },
  "warnings": []
}
```

## Arguments

Pass via `validator_args={"subject_alt_names": {...}}`:

| Argument | Type | Default | Description |
|---|---|---|---|
| `alternate_names` | `list[str] \| None` | `None` | Extra hostnames/IPs to confirm are covered by the SANs. Each gets its own entry under `contains_alternate`. |

## Reading the result

| Field | Meaning |
|---|---|
| `sans` | The SAN inventory, including `DNS`, `IP Address`, and other types such as email/URI when present. `None` if the extension is absent. |
| `count` | Total number of SANs. |
| `contains_alternate` | One entry per name in `alternate_names`, each with its own match result. |

!!! warning "Top-level `is_valid` vs. per-name results"
    The top-level `is_valid` requires **every requested alternate name** to match. Check each `contains_alternate[...]["is_valid"]` for per-name outcomes. Unmatched names are also surfaced in `warnings`.

Pass the names you require in `alternate_names`; every one of them must match for `is_valid` to be true, and the primary host is still reported in `contains_host` for context. With no requested alternates (`None` or `[]`) the validator falls back to checking the primary host, so enabling it by name alone behaves as it did in 0.4.0. Identity for the host you connected to is still best read from [Hostname](hostname.md).

## Reference

::: certmonitor.validators.subject_alt_names.SubjectAltNamesValidator
