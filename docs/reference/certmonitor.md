# API Reference: CertMonitor

Use this page when you know the operation you need and want its exact signature, arguments, or return value. For a guided first check, start with [Basic Usage](../usage/basic.md).

## The monitor

The reference below comes directly from the code's docstrings. Certificate collection, validation, raw formats, connection cleanup, and snapshot refresh all belong to the same monitor.

::: certmonitor.core.CertMonitor
    options:
      show_source: true
      show_docstring_examples: true
      show_docstring_parameters: true
      show_docstring_raises: true

## Scan multiple hosts

`scan_hosts()` creates an independent monitor per worker and yields results in completion order. See [Performance Tips](../usage/performance.md) for a complete example and timeout limits.

::: certmonitor.scanning.scan_hosts
