---
title: "CertMonitor Command Line"
description: "Check TLS certificates from the shell with the certmonitor command: validate hosts and certificate files, print parsed certificates, and script exit codes for cron and CI."
---

# Command Line

You do not have to write Python to use CertMonitor. Installing the package puts a `certmonitor` command on your path, built on the standard library like everything else here.

## Check a host

```sh
certmonitor check example.com
```

```text
example.com:443
  PASS   expiration         51 days remaining
  PASS   hostname           matched example.com
  PASS   root_certificate   trust verified
```

Targets are `host`, `host:port`, or `[ipv6]:port`, and you can pass several at once. They are checked concurrently (`--workers`, default 8) and reported in the order you gave them:

```sh
certmonitor check example.com db.internal:5432 "[2001:db8::10]:8443" --timeout 5
```

The exit status is `1` if any validator reports `fail` or `error`, and `0` otherwise, so the command drops straight into a cron job or a CI step. Add `--fail-on-warn` to treat warnings as failures too.

## Pick validators and pass arguments

```sh
certmonitor check example.com -v expiration,hostname,chain,pq_key_exchange \
  --arg expiration.warning_days=30 \
  --arg chain.reject_weak_signatures=false \
  --arg subject_alt_names.alternate_names='["www.example.com"]'
```

`-v` takes a comma-separated list of validator names. `--arg` takes `validator.key=value` and is repeatable; the value is parsed as JSON when it looks like JSON (numbers, `true`, `null`, lists) and used as text otherwise. `certmonitor validators` prints every validator with its arguments and defaults, without touching the network.

## Check a certificate file

```sh
certmonitor check --file /etc/ssl/certs/service.pem --host service.example.com
```

`--host` gives the identity for the `hostname` and `subject_alt_names` checks. Validators that need a live connection report `N/A` for a file, exactly as described in [Certificates from Files](files.md). `--file` is repeatable, and files and hosts can be mixed in one run.

## Connection options

`--starttls smtp|imap|pop3|ftp|postgres|ldap` runs the service's STARTTLS preamble before the handshake; see [STARTTLS Services](starttls.md). The constructor's other connection options are available as flags: `--connection-host` and `--server-hostname` to split the address from the SNI name, `--cafile` or `--capath` for a private CA, and `--client-cert` with `--client-key` for mutual TLS. See [Using IP Addresses](ip.md) and [RootCertificate](../validators/root_certificate.md) for what they mean.

## Machine-readable output

```sh
certmonitor check example.com expired.badssl.com --json > report.json
```

`--json` emits a list with one entry per target: `target`, `results` (the same dict `validate()` returns, including `status` and `code`), `snapshot_at`, and `fingerprint_sha256` of the leaf certificate. The human-readable report prints the fingerprint on the target line. A target that could not be scanned at all carries `error` and `message` instead of failing the run.

## Print the certificate

```sh
certmonitor info example.com          # parsed fields as JSON
certmonitor info example.com --pem    # the PEM itself
certmonitor info --file service.pem
```

## Reference

```text
certmonitor --version
certmonitor check [TARGET ...] [--file PATH] [-v NAMES] [--arg V.K=VALUE] [--json] [--fail-on-warn] [--workers N] [connection options]
certmonitor info TARGET | --file PATH [--pem] [connection options]
certmonitor validators [--json]
```

Run `certmonitor check --help` for the full flag list. For Prometheus, GitHub Actions, and cron recipes built on the command, see [Monitoring Integrations](integrations.md).
