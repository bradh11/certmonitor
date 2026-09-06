---
title: "Detect Certificate Changes Between Scans"
description: "Compare two CertMonitor observations to tell a routine renewal from a suspicious change: removed SANs, a new issuer, a weaker key, or a check that started failing."
---

# Detect Changes Between Scans

A fingerprint tells you a certificate changed. `compare_snapshots()` tells you what changed and whether it matters: a renewal from the same issuer with the same names and key is routine, while a name disappearing from the SANs, a new issuer, a weaker key, or a check that flipped from pass to fail deserves a look.

## Try it

Keep the JSON from each run wherever your automation keeps things, then hand two of them to the comparison:

```python
import json
from certmonitor import compare_snapshots

previous = json.load(open("reports/yesterday.json"))[0]
current = json.load(open("reports/today.json"))[0]

report = compare_snapshots(previous, current)
print(report["severity"], report["findings"])
```

```text
warning ['The certificate was replaced.', 'Validity was extended by 90 days (now expires 2027-01-15).', 'Names removed from the SANs: DNS:api.example.com.']
```

Any observation shape works: an entry from `certmonitor check --json`, a `scan_hosts()` result, or a plain `get_cert_info()` dictionary. Each carries the parsed certificate, and the first two also carry the validator results, so status changes are compared too.

## What it reports

| Section | Present when | Severity |
|---|---|---|
| `fingerprint` | The certificate was replaced | info |
| `validity` | `notAfter` or `notBefore` moved; `extended_days` is positive for a renewal | info, notice if shortened |
| `sans` | Names were `added` or `removed` | notice for added, warning for removed |
| `issuer` | A different CA signed it | warning |
| `subject` | The subject changed | notice |
| `key` | Algorithm or size changed | notice, warning if weaker |
| `status_changes` | A validator's `status` changed | warning if it now fails or errors, notice otherwise |

`severity` is the worst of the above, `changed` is false when nothing differs, and `replaced` is true when the fingerprint (or, failing that, the serial number) differs. A replacement whose only other effect is a later expiry is called out as a routine renewal.

## From the shell

```sh
certmonitor check api.example.com www.example.com --json > today.json
certmonitor diff yesterday.json today.json
```

```text
api.example.com:443  WARNING
  The certificate was replaced.
  Validity was extended by 90 days (now expires 2027-01-15).
  Names removed from the SANs: DNS:api.example.com.
www.example.com:443  SAME
```

Targets are matched by name. A target present in only one file is reported as a notice. The exit status is `1` when any target reaches the `--fail-on` severity (`warning` by default; `notice` to be stricter), so the command slots into the same cron and CI patterns as `certmonitor check`. Add `--json` for the full report.

## What replacement does not prove

A changed fingerprint shows that a new certificate is being served, not that a renewal succeeded. Read the validity section and the validator statuses together: a replacement that shortened the validity window, or that made `root_certificate` fail, is exactly the case this comparison exists to catch.
