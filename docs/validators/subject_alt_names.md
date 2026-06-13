# SubjectAltNames Validator

Inspects the certificate's Subject Alternative Names (SANs): the authoritative list of hostnames and IPs a certificate is valid for. Use it to confirm the host is covered, to check that extra names you expect (apex + `www`, alternate domains) are present, and to surface the full SAN inventory.

!!! note "Opt-in"
    Enable explicitly via `enabled_validators=["subject_alt_names", ...]` or the `ENABLED_VALIDATORS` environment variable.

## Example

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["subject_alt_names"]) as monitor:
    monitor.get_cert_info()
    result = monitor.validate(
        validator_args={"subject_alt_names": {"alternate_names": ["www.example.com"]}}
    )
    print(result["subject_alt_names"])
```

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
| `alternate_names` | `List[str]` | `None` | Extra hostnames/IPs to confirm are covered by the SANs. Each gets its own entry under `contains_alternate`. |

## Reading the result

| Field | Meaning |
|---|---|
| `sans` | The full SAN inventory, split into `DNS` and `IP Address`. |
| `count` | Total number of SANs. |
| `contains_host` | Whether the connected host is covered, with the matching reason. |
| `contains_alternate` | One entry per name in `alternate_names`, each with its own match result. |

!!! warning "Top-level `is_valid` vs. per-name results"
    The top-level `is_valid` reflects whether the certificate has a usable SAN extension, **not** whether every alternate name matched. Check the nested `contains_host["is_valid"]` and each `contains_alternate[...]["is_valid"]` for per-name outcomes. Unmatched names are also surfaced in `warnings`.

## API

::: certmonitor.validators.subject_alt_names.SubjectAltNamesValidator
