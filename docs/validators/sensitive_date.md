# SensitiveDate Validator

Flags certificates that expire on a date you'd rather not be doing an emergency renewal — weekends, leap days, or your own list of blackout dates (holidays, change freezes, peak-traffic events). A proactive scheduling check rather than a security one.

!!! note "Opt-in"
    Enable via `enabled_validators=["sensitive_date", ...]` or `ENABLED_VALIDATORS`. Weekend and leap-day checks run automatically; pass `dates` to add your own.

## Example

```python
from certmonitor import CertMonitor

with CertMonitor("example.com", enabled_validators=["sensitive_date"]) as monitor:
    monitor.get_cert_info()
    result = monitor.validate(
        validator_args={"sensitive_date": {"dates": ["2025-12-25", ["Black Friday", "2025-11-28"]]}}
    )
    print(result["sensitive_date"])
```

A certificate expiring on a weekend (built-in check) fails:

```json
{
  "is_valid": false,
  "leapday_expiry": false,
  "weekend_expiry": true,
  "sensitive_date_matches": [],
  "warnings": ["Certificate expires on a weekend (Saturday)"],
  "reason": "Certificate expires on a sensitive date: Certificate expires on a weekend (Saturday)"
}
```

## Arguments

Pass via `validator_args={"sensitive_date": {...}}`:

| Argument | Type | Default | Description |
|---|---|---|---|
| `dates` | `List[...]` | `None` | Extra dates to flag. Each entry may be an ISO string (`"2025-12-25"`), a `date`/`datetime`, a `(name, date)` tuple, or a `SensitiveDate`. |

The accepted entry shapes:

| Form | Example |
|---|---|
| ISO date string | `"2025-12-25"` |
| `(name, date)` tuple | `("Black Friday", "2025-11-28")` |
| `datetime.date` | `date(2025, 12, 25)` |

## Reading the result

| Field | Meaning |
|---|---|
| `weekend_expiry` | Certificate expires on a Saturday or Sunday. |
| `leapday_expiry` | Certificate expires on February 29. |
| `sensitive_date_matches` | Your supplied dates that matched, each with `name` and `date`. |
| `is_valid` | `false` if **any** of the above fired. |

!!! tip "It's about when, not whether"
    A `false` here doesn't mean the certificate is insecure — it means the expiry lands somewhere inconvenient. Use it to nudge renewals onto a business day well ahead of a freeze.

## API

::: certmonitor.validators.sensitive_date.SensitiveDateValidator
