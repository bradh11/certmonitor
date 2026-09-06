---
title: "Monitoring Integrations for CertMonitor"
description: "Recipes for running CertMonitor on a schedule: a Prometheus textfile exporter, a GitHub Actions job, a cron entry, and a health check, all using the standard library and the certmonitor command."
---

# Monitoring Integrations

Installing CertMonitor is the easy part. These recipes take you from "I can check a host" to "something tells me before a certificate bites". Each one uses only the standard library and the `certmonitor` command, so there is nothing else to install.

## Prometheus, via the textfile collector

If you already run `node_exporter`, the simplest integration is a script that writes metrics to its textfile directory on a schedule. No HTTP server, no new port, and the file is replaced atomically so a scrape never sees a partial write.

```python
"""Write CertMonitor results as Prometheus metrics for the node_exporter textfile collector.

Run it from cron (see below). Standard library only.
"""

import os
import sys
import tempfile
from pathlib import Path

from certmonitor import scan_hosts

TARGETS = ["example.com", ("expired.badssl.com", 443)]
OUTPUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/var/lib/node_exporter/textfile/certmonitor.prom")


def escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


lines = [
    "# HELP certmonitor_days_to_expiry Days until the certificate expires.",
    "# TYPE certmonitor_days_to_expiry gauge",
    "# HELP certmonitor_check Validator outcome: 1 when status matches the label.",
    "# TYPE certmonitor_check gauge",
    "# HELP certmonitor_scan_error 1 when the endpoint could not be scanned.",
    "# TYPE certmonitor_scan_error gauge",
]
for scan in scan_hosts(TARGETS, max_workers=4, timeout=10):
    target = f'host="{escape(scan["host"])}",port="{scan["port"]}"'
    lines.append(f"certmonitor_scan_error{{{target}}} {1 if 'error' in scan else 0}")
    for name, result in scan["results"].items():
        status = result.get("status", "error")
        for candidate in ("pass", "warn", "fail", "error", "unsupported"):
            value = 1 if status == candidate else 0
            lines.append(f'certmonitor_check{{{target},validator="{name}",status="{candidate}"}} {value}')
        if name == "expiration" and "days_to_expiry" in result:
            lines.append(f"certmonitor_days_to_expiry{{{target}}} {result['days_to_expiry']}")

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile("w", dir=OUTPUT.parent, delete=False) as handle:
    handle.write("\n".join(lines) + "\n")
os.chmod(handle.name, 0o644)  # temp files are owner-only; node_exporter runs as its own user
os.replace(handle.name, OUTPUT)  # atomic: node_exporter never reads a half-written file
```

Add it to cron (every 15 minutes is plenty; certificates do not change often):

```text
*/15 * * * *  /usr/bin/python3 /opt/certmonitor/certmonitor_textfile.py /var/lib/node_exporter/textfile/certmonitor.prom
```

Then alert on the metrics:

```yaml
groups:
  - name: certmonitor
    rules:
      - alert: CertificateExpiringSoon
        expr: certmonitor_days_to_expiry < 14
        for: 1h
        labels: {severity: warning}
        annotations:
          summary: "{{ $labels.host }}:{{ $labels.port }} expires in {{ $value }} days"
      - alert: CertificateCheckFailing
        expr: certmonitor_check{status=~"fail|error"} == 1 or certmonitor_scan_error == 1
        for: 30m
        labels: {severity: critical}
        annotations:
          summary: "{{ $labels.validator }} failing for {{ $labels.host }}:{{ $labels.port }}"
```

Want a live endpoint instead of a file? Wrap the same loop in `http.server` and serve the lines on `/metrics`; the metric names stay the same.

## GitHub Actions

Fail a pipeline when a certificate is wrong, and keep the JSON report as an artifact:

```yaml
name: certificates
on:
  schedule:
    - cron: "0 6 * * *"
  workflow_dispatch:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: pip install certmonitor
      - name: Check certificates
        run: |
          certmonitor check api.example.com www.example.com db.example.com:5432 \
            --arg expiration.warning_days=30 --json > certificates.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: certificate-report
          path: certificates.json
```

`certmonitor check` exits `1` when any validator reports `fail` or `error`, which fails the job. Add `--fail-on-warn` to fail on warnings too, or drop `--json` to see the readable report in the log.

To lint a certificate before it is deployed, check the file instead of the host:

```yaml
      - run: certmonitor check --file deploy/server.pem --host api.example.com --fail-on-warn
```

## Cron with an email

The oldest recipe still works. Cron mails the output of any job that prints, so print only when something is wrong:

```text
0 7 * * *  certmonitor check api.example.com www.example.com --fail-on-warn > /tmp/certmonitor.txt || cat /tmp/certmonitor.txt
```

A clean run is silent; a warning or failure lands in your inbox with the full report.

## A health check for anything that speaks exit codes

Nagios, Icinga, Sensu, Kubernetes probes, and most schedulers understand "exit 0 is fine, anything else is not". One line is enough:

```text
certmonitor check internal.example.com --cafile /etc/pki/private-ca.pem --timeout 5
```

For a single number to graph, read `days_to_expiry` from the JSON:

```sh
certmonitor check api.example.com --json -v expiration | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['results']['expiration']['days_to_expiry'])"
```

## From Python

Every recipe above is a thin wrapper over `scan_hosts()` and `validate()`. If you would rather stay in Python, [Performance Tips](performance.md) shows the bounded scanner and the async pattern, and [Certificates from Files](files.md) covers offline checks. Store each run's JSON: `certmonitor diff yesterday.json today.json` (or `compare_snapshots()`) then tells you whether a replacement was a routine renewal or something that needs a look. See [Detect Changes Between Scans](compare.md).
