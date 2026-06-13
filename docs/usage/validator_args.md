# Passing Arguments to Validators

Most validators just work out of the box. But some of them can be tuned: you might want to tell the SANs validator which hostnames to expect, or hand the sensitive-date validator a list of dates to watch. That's what `validator_args` is for.

You pass it as a dict to the `validate()` method, keyed by validator name. Each validator's entry is itself a dict that maps argument names to values.

## Canonical form

Here's the shape to reach for. Let's say you want the `subject_alt_names` validator to confirm a couple of hostnames are present:

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

The keys inside each per-validator dict have to match the validator's parameter names exactly.

!!! tip "Typos are caught loudly"
    If you pass an argument name the validator doesn't recognize, you won't get a silent no-op. The mistake comes back as a structured error in the result:

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

    Notice that the error even tells you which arguments *are* accepted, so the fix is usually obvious.

## Example: sensitive_date

Here's a more interesting one. The `sensitive_date` validator accepts a `dates` list, and it's flexible about how you describe each date. An entry can be a `SensitiveDate` named tuple, a plain `date`, an ISO 8601 string, or a `(name, date)` tuple. Use whichever fits your config source best:

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

When a date matches, you get told twice. It shows up as a structured entry in `sensitive_date_matches` (machine-readable) and as a human-readable line in `warnings`. Weekend and leap-day expiry produce warning strings too.

## Discovering what a validator accepts

Not sure which validators take arguments, or what those arguments are called? You don't have to guess. Use `describe_validators()` to introspect every registered validator:

```python
with CertMonitor("example.com") as monitor:
    for name, info in monitor.describe_validators().items():
        if info["args"]:
            print(name, info["args"])
```

Each entry includes the argument's annotation, its default value, and the validator's class docstring. That's everything you need to build CLI help, dashboards, or your own config validators.

## Deprecated bare-list shorthand

!!! warning "This form is deprecated"
    Earlier releases of CertMonitor accepted a bare list for validators with a single user argument:

    ```python
    # Deprecated: emits DeprecationWarning, will be removed in a future release.
    monitor.validate(validator_args={"subject_alt_names": ["example.com"]})
    ```

    It still works for backwards compatibility, but it emits a `DeprecationWarning` and will be removed in a future release. Migrate to the canonical dict form shown at the top of this page.

## Custom validators

Writing your own validator? The same dispatch works for it automatically, as long as you declare your arguments the right way.

Each user argument has to be a **keyword-only** parameter on `validate()`, with a **type annotation** and a **default value**. CertMonitor enforces this at class definition time, so a malformed validator raises `TypeError` at import rather than failing mysteriously later:

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

Once you register it with `register_validator()`, the new validator picks up the dynamic args dispatch with no extra wiring:

```python
results = monitor.validate(
    validator_args={"my_custom": {"threshold": 5, "labels": ["prod"]}}
)
```

There are no core changes to make. The framework reads your `validate()` signature once, at class definition time, and discovers the user arguments from there.

!!! tip "More on the built-ins"
    See the [Validators Reference](../validators/index.md) for which built-in validators accept arguments and the format each one expects.
