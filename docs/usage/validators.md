# Validator System Overview

Validators are modular checks that CertMonitor uses to assess the security and compliance of SSL/TLS certificates and connections. Each validator focuses on a specific aspect (expiration, hostname matching, key strength, protocol version) and returns a structured result indicating success or failure. Validators can be enabled, disabled, or extended with custom logic to fit your organization's needs.

!!! info "Looking for the catalog?"
    This page covers **how to control and extend** validators. For the per-validator reference (what each one checks, its arguments, and example output), see the [Validators section](../validators/index.md).

## Registered vs. enabled

These two words sound similar but mean different things, and the distinction matters once you start customizing.

A validator is **registered** when CertMonitor knows it exists. Every built-in validator is registered out of the box, and you can register your own with `register_validator()` (see [Custom Validators](custom_validators.md)). `list_validators()` shows you everything that's registered.

A validator is **enabled** when it actually runs for a given `CertMonitor`. The enabled set is a subset of the registered ones, and it's what `validate()` executes. `monitor.get_enabled_validators()` shows you that subset.

In other words: *registered* is the menu of everything available, and *enabled* is what you've ordered. A validator has to be registered before you can enable it, but plenty of registered validators stay disabled until you ask for them. For example, all the `pq_*` validators are registered by default but not enabled, so you opt into them when you're ready.

## Enabling/Disabling Validators

You have two ways to control which validators run.

The first is per call, by passing `enabled_validators` when you create the monitor:

```python
with CertMonitor("example.com", enabled_validators=["expiration", "hostname"]) as monitor:
    print(monitor.validate())
```

The second is with the `ENABLED_VALIDATORS` environment variable, which is handy when you want to configure a CI job, container, or cron monitor without touching code. Set it to a comma-separated list:

```sh
export ENABLED_VALIDATORS="expiration,hostname,subject_alt_names,tls_version,weak_cipher"
```

The enabled set is resolved in this order:

1. The `enabled_validators=[...]` argument, if you pass one.
2. Otherwise the `ENABLED_VALIDATORS` environment variable, if it's set.
3. Otherwise the built-in defaults: `expiration`, `hostname`, `root_certificate`.

So the argument always wins over the environment variable, which in turn wins over the defaults.

!!! tip "Turning on post-quantum checks fleet-wide"
    The environment variable is the easiest way to enable the opt-in PQ validators everywhere without editing code. See [Environment Variable Configuration](env.md) for more.

## Validator Convenience Methods

CertMonitor provides several convenience methods to discover and work with validators. These are available both as module-level functions and as instance methods.

## Summary of Methods

| Method | Purpose | Returns |
|--------|---------|---------|
| `certmonitor.validators.list_validators()` | All available validators | All registered validator names |
| `certmonitor.validators.get_enabled_validators()` | Global config defaults | Default enabled validator names from config |
| `monitor.list_validators()` | All available validators | All registered validator names |
| `monitor.get_enabled_validators()` | Instance-specific | Validators enabled for this specific monitor instance |

## Listing All Validators

You can list all currently registered validators (including built-in and custom ones) in two ways:

### From the Validators Module

```python
from certmonitor.validators import list_validators

print(list_validators())
# Output: ['expiration', 'hostname', 'key_info', 'subject_alt_names', 'root_certificate',
#          'sensitive_date', 'tls_version', 'weak_cipher', 'chain',
#          'pq_key_exchange', 'pq_chain', 'pq_signature']
```

### From a CertMonitor Instance

```python
from certmonitor import CertMonitor

monitor = CertMonitor("example.com")
print(monitor.list_validators())
# Output: ['expiration', 'hostname', 'key_info', 'subject_alt_names', 'root_certificate',
#          'sensitive_date', 'tls_version', 'weak_cipher', 'chain',
#          'pq_key_exchange', 'pq_chain', 'pq_signature']
```

Both methods return the same list of all available validators, regardless of which ones are enabled for a specific instance.

## Getting Enabled Validators

You can get enabled validators in two ways:

### Global Configuration Defaults

The `get_enabled_validators()` function returns the global default validators from configuration:

```python
from certmonitor.validators import get_enabled_validators

print(get_enabled_validators())
# Output: ['expiration', 'hostname', 'root_certificate']
```

### Instance-Specific Validators

To get the validators enabled for a specific CertMonitor instance, use the instance method:

```python
from certmonitor import CertMonitor

# Default behavior - uses global config defaults
monitor = CertMonitor("example.com")
print(monitor.get_enabled_validators())
# Output: ['expiration', 'hostname', 'root_certificate']

# Custom validators for this instance
monitor = CertMonitor("example.com", enabled_validators=["hostname", "expiration"])
print(monitor.get_enabled_validators())
# Output: ['hostname', 'expiration']

# No validators enabled
monitor = CertMonitor("example.com", enabled_validators=[])
print(monitor.get_enabled_validators())
# Output: []
```

## Registering Custom Validators

To add your own validator, create a class that inherits from `BaseValidator`, then register it:

```python
from certmonitor.validators import register_validator, list_validators
from certmonitor.validators.base import BaseCertValidator

class MyCustomValidator(BaseCertValidator):
    name = "my_custom_validator"

    def validate(self, cert, host, port):
        # Custom validation logic. Follow the result envelope:
        # always return is_valid (a strict bool); add reason only on failure.
        return {"is_valid": True}

# Register your custom validator
register_validator(MyCustomValidator())

# Now it will appear in list_validators()
print(list_validators())
# Output will include 'my_custom_validator'
```

Subclass `BaseCertValidator` (for certificate checks) or `BaseCipherValidator` (for cipher/connection checks), and follow the [result envelope](../validators/index.md#the-result-contract). See the [Custom Validators](custom_validators.md) guide for the full template, including user-configurable arguments.

## Practical Examples

### Discovering Available vs Enabled Validators

```python
from certmonitor import CertMonitor
from certmonitor.validators import list_validators, get_enabled_validators

# See all available validators
print("All available validators:")
for validator in list_validators():
    print(f"  - {validator}")

print("\nGlobal config defaults:")
for validator in get_enabled_validators():
    print(f"  - {validator}")

# Create monitors with different validator configurations
monitor1 = CertMonitor("example.com")  # Uses defaults
monitor2 = CertMonitor("example.com", enabled_validators=["hostname", "expiration"])
monitor3 = CertMonitor("example.com", enabled_validators=[])  # No validators

print(f"\nMonitor 1 enabled: {monitor1.get_enabled_validators()}")
print(f"Monitor 2 enabled: {monitor2.get_enabled_validators()}")
print(f"Monitor 3 enabled: {monitor3.get_enabled_validators()}")
```

### Dynamically Enabling All Available Validators

```python
from certmonitor import CertMonitor

# Enable all available validators for maximum coverage
monitor = CertMonitor("example.com")
all_validators = monitor.list_validators()
monitor_with_all = CertMonitor("example.com", enabled_validators=all_validators)

print(f"Running {len(monitor_with_all.get_enabled_validators())} validators:")
results = monitor_with_all.validate()
for validator_name, result in results.items():
    status = "✓" if result.get("is_valid") else "✗"
    print(f"  {status} {validator_name}")
```
