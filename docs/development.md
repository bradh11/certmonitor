# Development Guide

This guide is for contributors and advanced users who want to build CertMonitor from source, work on the codebase, or use the Rust-powered features in development.

## Quick Start

All development tasks are managed through the comprehensive Makefile. To see all available commands:

```sh
make help
```

## Local Development Setup

1. **Clone the repository:**
    ```sh
    git clone <repo-url>
    cd certmonitor
    ```
2. **Install dev dependencies (includes maturin):**

    === "uv"
        ```sh
        uv sync --group dev
        ```

    === "pip"
        ```sh
        pip install -e .[dev]
        ```

3. **Install Rust toolchain:**
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    # Or see https://www.rust-lang.org/tools/install
    ```
4. **Build and install the Rust bindings:**
    ```sh
    make develop
    ```

## Makefile Commands Reference

CertMonitor provides a comprehensive Makefile with unified commands for both Python and Rust development. All commands are designed to work seamlessly together.

### 📦 Development Commands

| Command | Description |
|---------|-------------|
| `make develop` | Install package in development mode (Python + Rust) |
| `make build` | Build release artifacts |
| `make wheel` | Build Python wheel with Rust extension |

### 🧪 Testing & Quality Commands

#### Comprehensive Testing
| Command | Description |
|---------|-------------|
| `make test` | **Run full CI-equivalent test suite** (9 comprehensive checks) |
| `make test-quick` | Run tests only (fast, no quality checks) |
| `make ci` | Alias for `make test` |

#### Code Quality (Unified Python + Rust)
| Command | Description |
|---------|-------------|
| `make check` | Quick code quality checks (lint + format) |
| `make format` | **Format both Python and Rust code** |
| `make format-check` | **Check formatting for both languages** |
| `make lint` | **Lint both Python and Rust code** |
| `make typecheck` | Run mypy type checking |
| `make security` | **Run security vulnerability check** |

#### Language-Specific Commands
| Command | Description |
|---------|-------------|
| `make python-format` | Format Python code only |
| `make python-lint` | Lint Python code only |
| `make rust-format` | Format Rust code only |
| `make rust-format-check` | Check Rust formatting |
| `make rust-lint` | Lint Rust code only |

### 📊 Reporting Commands

| Command | Description |
|---------|-------------|
| `make report` | Generate modularization and quality report |

### 📚 Documentation Commands

| Command | Description |
|---------|-------------|
| `make docs` | Serve documentation locally |

### 🧹 Cleanup Commands

| Command | Description |
|---------|-------------|
| `make clean` | Remove all build artifacts and cache |
| `make verify-wheel` | Verify contents of built wheel |

## Development Workflows

### Daily Development Workflow

1. **Make your changes** to Python or Rust code
2. **Format and lint** your code:
   ```sh
   make format lint
   ```
3. **Run quick quality checks**:
   ```sh
   make check
   ```
4. **Run tests** if needed:
   ```sh
   make test-quick  # Fast tests only
   # OR
   make test        # Full CI-equivalent suite
   ```

### Pre-Commit Workflow

Before committing or creating a PR, run the full test suite:

```sh
make test
```

This runs 9 comprehensive checks:
1. Python code formatting check
2. Python linting check  
3. Rust code formatting check
4. Rust linting check
5. Pytest with coverage (95%+ required)
6. Python type checking (mypy)
7. Security vulnerability check (cargo audit)
8. Build verification
9. Modularization report generation

### Working with Rust Code

When you modify Rust code in `rust_certinfo/`, you need to rebuild:

```sh
make develop  # Rebuilds and installs Rust extension
```

For Rust-specific tasks:
```sh
make rust-format     # Format Rust code
make rust-lint       # Lint Rust code with clippy
```

### Code Quality Standards

The project maintains high code quality standards:

- **Python**: Uses `ruff` for formatting and linting
- **Rust**: Uses `cargo fmt` for formatting and `clippy` for linting  
- **Type Safety**: 100% mypy compliance required
- **Test Coverage**: 95%+ coverage required
- **Documentation**: All public APIs must be documented

### Unified Commands Benefits

The unified `format` and `lint` commands provide several advantages:

- **Single Interface**: Run `make format` to format all code regardless of language
- **Consistent Experience**: Same commands work for Python and Rust
- **CI Alignment**: Local `make test` matches exactly what CI runs
- **Time Saving**: No need to remember separate commands for each language

## Running Tests

### Quick Tests (Fast)
```sh
make test-quick
```

### Full Test Suite (CI-Equivalent)
```sh
make test
```

The full test suite provides detailed progress reporting and matches exactly what runs in CI.

## Running the Docs

```sh
make docs
```

This starts a local development server for the documentation.

## Why Rust for Certificate Parsing?

Parsing X.509 certificates and extracting cryptographic key information is performance-critical and security-sensitive. Python's standard library does not provide low-level, robust, or fast parsing for all certificate fields, especially for public key extraction and ASN.1 parsing. Rust, with its strong safety guarantees and excellent cryptography ecosystem, is ideal for this task.

- **Performance:** Rust code is compiled and runs much faster than pure Python for binary parsing.
- **Safety:** Rust's memory safety model helps prevent many classes of bugs and vulnerabilities.
- **Ecosystem:** The Rust `x509-parser` crate is mature and reliable for certificate parsing.

The Rust extension is built as a Python module using [PyO3](https://pyo3.rs/) and [maturin](https://github.com/PyO3/maturin), and is automatically installed as part of the development workflow.

## Troubleshooting

### Common Issues

1. **Rust compilation errors**: Ensure you have the latest Rust toolchain installed
2. **Import errors**: Run `make develop` to rebuild the Rust extension
3. **Test failures**: Run `make format lint` to fix code quality issues
4. **Type errors**: Run `make typecheck` to see mypy errors

### Getting Help

- Run `make help` to see all available commands
- Check the CI logs if tests pass locally but fail in CI
- Review the `pyproject.toml` for dependency information

---

For more details, see the Makefile commands above and `pyproject.toml` for up-to-date dependencies.
