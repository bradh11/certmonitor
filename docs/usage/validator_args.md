# Passing Arguments to Validators

Some validators accept additional arguments to customize their behavior. Pass
them as a dict to the `validate()` method's `validator_args` parameter, keyed by
validator name. Each validator's entry is itself a dict mapping argument names
to values.

## Canonical form

```python
from certmonitor import CertMonitor

with CertMonitor("example.com") as monitor:
    results = monitor.validate(
        validator_args={
            "subject_alt_names": {
                "alternate_names": ["example.com", "www.example.com"],
            },
        }
    )
    print(results["subject_alt_names"])
```

The keys inside each per-validator dict must match the validator's user
parameter names exactly. Unknown keys are reported as a structured error in the
result, so typos are caught loudly:

```python
results = monitor.validate(
    validator_args={"subject_alt_names": {"alt_names": ["example.com"]}}
)
# results["subject_alt_names"] == {
#     "is_valid": False,
#     "reason": "Unknown args for validator 'subject_alt_names': ['alt_names']. "
#               "Accepted args: ['alternate_names']."
# }
```

## Example: sensitive_date

The `sensitive_date` validator accepts a `dates` list. Each entry may be a
`SensitiveDate` named tuple, a plain `date`, an ISO 8601 string, or a
`(name, date)` tuple — whichever fits your config source best.

```python
from datetime import date
from certmonitor import CertMonitor
from certmonitor.validators.sensitive_date import SensitiveDate

with CertMonitor("example.com") as monitor:
    results = monitor.validate(
        validator_args={
            "sensitive_date": {
                "dates": [
                    SensitiveDate("Black Friday", date(2025, 11, 28)),
                    date(2025, 12, 25),           # name defaults to ISO string
                    "2026-01-01",                 # ISO string; name defaults to itself
                    ("Go-live", date(2026, 3, 1)),
                ]
            }
        }
    )
    print(results["sensitive_date"])
```

Every matching date is reported both as a structured entry in
`sensitive_date_matches` (machine-readable) and as a human-readable line in
`warnings`. Weekend and leap-day expiry also produce warning strings.

## Discovering what a validator accepts

Use `describe_validators()` to introspect every registered validator and the
arguments it accepts:

```python
with CertMonitor("example.com") as monitor:
    for name, info in monitor.describe_validators().items():
        if info["args"]:
            print(name, info["args"])
```

Each entry includes the argument's annotation, default value, and the
validator's class docstring — useful for building CLI help, dashboards, or
config validators.

## Deprecated bare-list shorthand

Earlier releases of CertMonitor accepted a bare list for validators with a
single user argument:

```python
# Deprecated — emits DeprecationWarning, will be removed in a future release.
monitor.validate(validator_args={"subject_alt_names": ["example.com"]})
```

This shorthand still works for backwards compatibility but emits a
`DeprecationWarning`. Migrate to the canonical dict form shown above.

## Custom validators

When you write your own validator, declare each user argument as a
**keyword-only** parameter on `validate()` with a **type annotation** and a
**default value**. CertMonitor enforces this at class definition time and will
raise `TypeError` at import if a validator is malformed.

```python
from typing import Optional, List
from certmonitor.validators.base import BaseCertValidator

class MyCustomValidator(BaseCertValidator):
    name = "my_custom"

    def validate(
        self,
        cert,
        host,
        port,
        *,
        threshold: int = 0,
        labels: Optional[List[str]] = None,
    ):
        return {"is_valid": True, "threshold": threshold, "labels": labels or []}
```

Once registered via `register_validator()`, the new validator picks up the
dynamic args dispatch automatically:

```python
results = monitor.validate(
    validator_args={"my_custom": {"threshold": 5, "labels": ["prod"]}}
)
```

No core changes needed — the framework discovers the validator's user arguments
by reading its `validate()` signature once, at class definition time.

---

> **Tip:** See the [Validators Reference](../validators/index.md) for details on
> which built-in validators accept arguments and the expected format.
