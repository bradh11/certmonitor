# Validator System Overview

Validators are modular checks that CertMonitor uses to assess the security and compliance of SSL/TLS certificates and connections. Each validator focuses on a specific aspect—such as expiration, hostname matching, key strength, or protocol version—and returns a structured result indicating success or failure. Validators can be enabled, disabled, or extended with custom logic to fit your organization's needs.

Validators are the core mechanism that makes CertMonitor flexible and powerful for a wide range of certificate monitoring and compliance scenarios.

# Enabling/Disabling Validators

You can control which validators are enabled:

```python
with CertMonitor("example.com", enabled_validators=["expiration", "hostname"]) as monitor:
    print(monitor.validate())
```

# Validator Convenience Methods

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
# Output: ['expiration', 'hostname', 'key_info', 'subject_alt_names', 'root_certificate', 'tls_version', 'weak_cipher']
```

### From a CertMonitor Instance

```python
from certmonitor import CertMonitor

monitor = CertMonitor("example.com")
print(monitor.list_validators())
# Output: ['expiration', 'hostname', 'key_info', 'subject_alt_names', 'root_certificate', 'tls_version', 'weak_cipher']
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
from certmonitor.validators import register_validator, BaseValidator, list_validators

class MyCustomValidator(BaseValidator):
    name = "my_custom_validator"
    def validate(self, cert_info, **kwargs):
        # Custom validation logic
        return {"success": True, "reason": "Custom check passed"}

# Register your custom validator
register_validator(MyCustomValidator())

# Now it will appear in list_validators()
print(list_validators())
# Output will include 'my_custom_validator'
```

See the [Custom Validators](../usage/custom_validators.md) usage guide for more details and a template.

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
