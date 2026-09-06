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
    git clone https://github.com/bradh11/certmonitor.git
    cd certmonitor
    ```
2. **Install Rust toolchain:**
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    # Or see https://www.rust-lang.org/tools/install
    ```
3. **Install dev dependencies (includes maturin):**

    === "uv"
        ```sh
        uv sync --group dev --group docs
        ```

    === "pip"
        ```sh
        python -m venv .venv
        source .venv/bin/activate
        python -m pip install -e . --group dev --group docs
        ```

4. **Build and install the Rust bindings:**
    ```sh
    make develop
    ```

## Makefile Commands Reference

CertMonitor provides a comprehensive Makefile with unified commands for both Python and Rust development. Most commands use `uv`; install it before following the Makefile workflow. The pip tab uses `--group`, which requires pip 25.1 or newer.

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
| `make test` | **Run full CI-equivalent test suite** (Python/Rust checks and build verification) |
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
| `make clean` | Remove build artifacts, caches, and the local `.venv` |
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

This runs the following checks:
1. Python code formatting check
2. Python linting check  
3. Rust code formatting check
4. Rust linting check
5. Rust unit tests (`cargo test`)
6. Pytest with coverage (95%+ required)
7. Python type checking (mypy)
8. Rust dependency audit (`cargo audit`)
9. Python security scan (Bandit)
10. Wheel build verification, followed by the modularization report

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
- **CI Alignment**: Local checks cover the main quality gates; CI also exercises its configured platform and Python matrix
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

The full local suite provides detailed progress reporting. Check the CI matrix before release too: a local run covers your environment, not every supported platform.

## Running the Docs

```sh
make docs
```

This starts a local development server for the documentation.

## Validator Development

Validators are the heart of CertMonitor, and there are two reasons you might write one. Be clear about which you're doing, because the path is different:

- **For yourself.** You need an organization-specific check (an internal naming policy, a custom compliance rule) and you want to register it at runtime in your own code. You don't touch the CertMonitor repo at all. This is covered in [Custom Validators](usage/custom_validators.md) in the usage guide.
- **To contribute back.** You think the check is useful to everyone and you want it shipped in the library. That means adding it to the codebase with tests, docs, and registration. See [Contributing a Validator](contributing-a-validator.md).

Both paths share the same building blocks (subclass a base validator, follow the result envelope, declare keyword-only arguments). The difference is everything around the validator: a contributed one needs tests, a docs page, a changelog entry, and registration in the shipped registry.

## Why Rust for Certificate Parsing?

Parsing X.509 certificates and extracting cryptographic key information is performance-critical and security-sensitive. Python's standard library does not provide low-level, robust, or fast parsing for all certificate fields, especially for public key extraction and ASN.1 parsing. Rust, with its strong safety guarantees and excellent cryptography ecosystem, is ideal for this task.

- **Performance:** Rust code is compiled and runs much faster than pure Python for binary parsing.
- **Safety:** Rust's memory safety model helps prevent many classes of bugs and vulnerabilities. The in-tree parser is annotated `#![forbid(unsafe_code)]` and parser entry points return `Result` for malformed input. Unit tests, corpus comparisons, and fuzzing exercise the error paths; memory safety does not prove parsing correctness.
- **Zero dependencies:** As of v0.3.0 the entire X.509 / DER parser is written in-house against the Rust standard library, with no third-party parsing crates in the runtime tree.

The Rust extension is built as a Python module using [PyO3](https://pyo3.rs/) and [maturin](https://github.com/PyO3/maturin), and is automatically installed as part of the development workflow.

## Troubleshooting

### Common Issues

1. **Rust compilation errors**: Ensure you have the latest Rust toolchain installed
2. **Import errors**: Run `make develop` to rebuild the Rust extension
3. **Test failures**: Read the failing assertion, reproduce it, and check for regressions; formatting alone does not fix behavioral failures
4. **Type errors**: Run `make typecheck` to see mypy errors

### Getting Help

- Run `make help` to see all available commands
- Check the CI logs if tests pass locally but fail in CI
- Review the `pyproject.toml` for dependency information

---

For more details, see the Makefile commands above and `pyproject.toml` for up-to-date dependencies.

## Writing documentation

Start with the reader's task, show a small working example, then explain the result. Keep the conversational voice: say what the check does, why someone would use it, and what they should try next. Use tips for useful shortcuts and warnings for an actual behavior a reader could miss.

Preserve the full API docstrings. The reference pages render their descriptions, arguments, returns, and examples with mkdocstrings, so shortening a docstring also removes documentation from the site. Update factual details in place when behavior changes.

Enable every opt-in validator used in an example, pass its required policy arguments, and handle error dictionaries before treating a result as bytes or text. Mark sample output as illustrative or abbreviated, and keep `json` fences valid JSON.

Before finishing a docs change, build with warnings treated as errors:

```sh
uv run mkdocs build --strict
```

Preview both light and dark mode, check narrow-screen navigation, and follow the tutorial's internal links. A clean build catches reference problems; it doesn't establish that an example's behavior is correct.
