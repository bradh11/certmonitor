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

!!! info "No Rust toolchain needed"
    If you're installing from PyPI with pip or uv, you do not need a Rust toolchain on your machine. Pre-built wheels are provided for all major platforms and Python versions. The advanced public key parsing is powered by Rust, but it's already compiled into the wheel for you.

## Supported Python versions

CertMonitor runs on:

- Python 3.8, 3.9, 3.10, 3.11, 3.12, 3.13

!!! note "Building from source?"
    The note above covers the normal case: installing the published package. A Rust toolchain only comes into play when you're building from source or developing CertMonitor itself (to compile the Rust extension). If that's you, head over to the [Development Guide](../development.md) for the full setup.
