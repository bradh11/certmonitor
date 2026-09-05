# API Reference: Validators

Use the registry functions below to discover and register validators. For a working extension, follow [Custom Validators](../usage/custom_validators.md); for built-in behavior and arguments, use the [validator catalog](../validators/index.md).

## Registry

::: certmonitor.validators

## The result envelope

Every validator returns the envelope described below, and `validate()` adds `status` and `code`. Validator-specific data fields are documented on each page of the [validator catalog](../validators/index.md).

::: certmonitor.validators.results

## Base classes

Choose a certificate or cipher base according to the data your check consumes. User-configurable options must be keyword-only, annotated, and defaulted.

::: certmonitor.validators.base
