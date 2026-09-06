---
title: "Install CertMonitor for Python"
description: "Install the CertMonitor Python SSL/TLS certificate monitoring library from PyPI. Learn about supported Python versions, native wheels, and source builds."
---

# Installation

Installing CertMonitor is the easy part. You can use whichever Python package manager you already reach for. Here are the two most common:

=== "pip"
    ```sh
    pip install certmonitor
    ```

=== "uv"
    ```sh
    uv add certmonitor
    ```

That's it. There are no third-party Python packages to pull in, so the install is fast and the footprint is small.

!!! info "Installing a wheel? Rust is already compiled"
    When a wheel is available for your Python version and platform, pip or uv installs the compiled Rust extension for you. No Rust toolchain is needed in that case. If no matching wheel is available, installation falls back to a source build and requires Rust. Check the release's [PyPI files](https://pypi.org/project/certmonitor/#files) for available wheels.

## Supported Python versions

The package metadata accepts Python `>=3.10,<3.16`:

- Python 3.10, 3.11, 3.12, 3.13, 3.14, 3.15

!!! note "Building from source?"
    A Rust toolchain comes into play when you're building from source or developing CertMonitor itself (to compile the Rust extension). If that's you, head over to the [Development Guide](../development.md) for the full setup.

## Check the install

```sh
python -c "from certmonitor import CertMonitor; print(CertMonitor('example.com').list_validators())"
```

This checks the import and lists the available validators without opening a connection. Ready to check your first host? Continue to [Basic Usage](basic.md).

!!! note "Following the development docs?"
    `latest` tracks the repository. Features listed under Unreleased in the [changelog](https://github.com/bradh11/certmonitor/blob/develop/CHANGELOG.md) require the development version until they are published. Use the documentation version that matches your installed release.
