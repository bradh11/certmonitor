# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- TBD

### Changed
- TBD

### Fixed
- TBD

## [0.2.0] - 2026-04-13

# 📦 CertMonitor v0.2.0 – Dynamic Validator Args & sensitive_date validator

**Release Date:** April 13, 2026
**Repository:** [bradh11/certmonitor](https://github.com/bradh11/certmonitor)

---

## 🚀 Overview

CertMonitor v0.2.0 overhauls how validators receive arguments. New validators can now declare their user arguments directly on the `validate()` method signature — the dispatcher discovers them automatically and no core changes are needed. As part of the same effort, the `sensitive_date` validator — which has been sitting on `develop` since #15 back in June 2025 — finally makes it into a release, and gets ergonomic input forms, a structured match field, and structured error handling along the way.

This is a **minor version bump** to reflect the scale of the changes, not because of any hard break in the public API. Existing callers using `validator_args={"subject_alt_names": [...]}` still work with a `DeprecationWarning`, and no validator output shape has changed for users.

---

## ✨ Added

- **Dynamic validator argument dispatch** ([#18](https://github.com/bradh11/certmonitor/issues/18)): validators declare their user-configurable arguments directly on the `validate()` method signature, and `CertMonitor.validate(validator_args=...)` discovers them automatically. New validators get argument passing for free — zero core changes needed.
- **`CertMonitor.describe_validators()`**: new introspection helper that returns every registered validator's name, docstring, and argument schema (name, annotation, default). Useful for building CLI `--help` pages, config validators, or dashboards.
- **`sensitive_date` validator** finally ships: flags certificates that expire on weekends, leap days, or user-specified dates (e.g. Black Friday, Cyber Monday, go-live dates).
- **`sensitive_date` input ergonomics**: the `dates` argument accepts `SensitiveDate` named tuples, plain `date` / `datetime` values, ISO 8601 strings (`"2025-12-25"`), or `(name, date)` tuples — all mixable in a single call. No need to import `SensitiveDate` from a deeply nested module path just to pass a list of blackout dates.
- **`sensitive_date_matches` structured field**: matching sensitive dates are surfaced as a machine-readable list of `{"name", "date"}` entries in addition to the existing human-readable `warnings` strings.
- **Weekend / leap-day warning strings**: when the `sensitive_date` validator flags a weekend or leap-day expiry, a human-readable warning line is now emitted alongside the existing boolean fields, so log output is self-explanatory when `is_valid` is false.
- **Shared `parse_not_after` helper** (`certmonitor/validators/_utils.py`): centralizes the `notAfter` format string shared by `expiration` and `sensitive_date`.

---

## 🔄 Changed

- **Validator author contract**: user arguments on `validate()` must be keyword-only, type-annotated, and have a default value. Enforcement runs in `BaseCertValidator` / `BaseCipherValidator` `__init_subclass__` at import time, so a malformed validator raises `TypeError` the moment its module is imported. No user-facing impact — every built-in validator conforms, and the dispatcher continues to accept the pre-0.2.0 `validator_args` call style via a deprecation shim.
- **`subject_alt_names` and `sensitive_date` signatures** migrated to keyword-only user arguments (`alternate_names=...`, `dates=...`). Existing users of `monitor.validate(validator_args={...})` are unaffected; callers invoking the validator classes directly with positional arguments need the keyword form.
- **`validator_args` canonical form** is now a nested dict: `validator_args={"subject_alt_names": {"alternate_names": [...]}}`. The pre-0.2.0 bare-list form still works and is transparently rewritten by the dispatcher — with a `DeprecationWarning` — so no user code needs to change immediately.
- **`sensitive_date` error handling**: malformed `dates` input (wrong type, invalid ISO string, bad tuple shape) now returns a structured error dict instead of raising `TypeError`, matching the rest of the validator suite.
- **`expiration` validator**: now uses the shared `parse_not_after` helper; behavior unchanged.
- **`mkdocs.yml`**: added the previously-missing `SensitiveDate` nav entry so the validator's auto-generated reference page is reachable.
- **`docs/usage/validator_args.md`**: rewritten to document the canonical nested-dict form, `describe_validators()`, the bare-list deprecation, and a worked `sensitive_date` example showing all four input forms.
- **Rust toolchain floor** moved to `rustc >= 1.88.0` (transitively via the `time 0.3.47` security bump, see below). Affects contributors and source builds only — published wheels are unaffected.

---

## ⚠️ Deprecated

- **Bare-list shorthand for single-argument validators** (`validator_args={"subject_alt_names": [...]}`) still works but now emits a `DeprecationWarning`. Migrate to the canonical nested-dict form. Scheduled for removal in a future release.

---

## 🔒 Security

- **RUSTSEC-2026-0009**: bumped the `time` crate from `0.3.41` to `0.3.47` (transitively via `x509-parser`) to address the denial-of-service-via-stack-exhaustion advisory.

---

## 🛠️ Fixed

- **`subject_alt_names` core dispatch**: the hardcoded `if validator.name == "subject_alt_names"` special case in `core.validate()` is gone — replaced with the generic argument-resolution helper used by every validator.
- **`CHANGELOG.md`**: backfilled the missing `[0.1.4]` section from the published release notes so the historical record is complete.

---

## 📚 Documentation

Comprehensive documentation is available at [certmonitor.readthedocs.io](https://certmonitor.readthedocs.io/).

---

## 🐍 Python Compatibility

Tested with Python 3.8 and above with 98%+ code coverage across all supported versions.

---

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/bradh11/certmonitor/blob/main/LICENSE) file for details.

**Full Changelog**: https://github.com/bradh11/certmonitor/compare/v0.1.4...v0.2.0

## [0.1.4] - 2025-06-02

Focus: test coverage and CI optimization ([#16](https://github.com/bradh11/certmonitor/issues/16)).

### Added
- Achieved 99% test coverage (up from 95%) with comprehensive edge case testing.
- Instance convenience methods for improved developer experience:
  - `monitor.get_enabled_validators()` — get validators enabled for this specific instance.
  - `monitor.list_validators()` — get all available validators.
- Enhanced test suite with 323 tests covering all edge cases.

### Changed
- Streamlined security scanning: removed heavy semgrep dependency, kept focused bandit scanning.
- Improved test descriptions — removed line-number references for maintainable, functionality-focused tests.
- Enhanced validator configuration: proper distinction between empty lists vs config defaults.

### Fixed
- Default validator behavior: `enabled_validators=[]` now properly means "no validators", vs `None` meaning "use defaults" (see [#16](https://github.com/bradh11/certmonitor/issues/16)).
- Configuration environment handling: proper string parsing for the `ENABLED_VALIDATORS` environment variable.
- Test coverage gaps — targeted testing for previously uncovered edge cases: SSL handler retry exception scenarios, certificate parsing fallback mechanisms, handler-None conditions in raw data operations, and public key parsing error paths.

## [0.1.3] - 2025-05-25

### Added
- Comprehensive GitHub workflows and templates with develop/main branch strategy
- Enhanced type hints throughout entire codebase (zero mypy errors)
- Modularized test suite for better maintainability
- ReadTheDocs integration with proper configuration
- Consolidated CI/CD pipeline with conditional job execution
- **Unified Makefile commands for Python + Rust development workflow**
  - `make format` - Format both Python and Rust code
  - `make format-check` - Check formatting for both languages
  - `make lint` - Lint both Python and Rust code
  - `make security` - Run security vulnerability check (cargo audit)
  - Individual language commands: `python-format`, `python-lint`, `rust-format`, `rust-lint`
  - Enhanced `make test` with 9-step CI-equivalent comprehensive testing including security checks
  - Improved `make help` with clear categorized command documentation

### Changed
- Improved code organization and structure
- Enhanced documentation and contributing guidelines
- Updated all workflows to use develop/main branch strategy
- Removed redundant CI configurations (quality.yml, security.yml, rust.yml, docs.yml)
- Streamlined dependency management (removed Dependabot for stdlib-only project)
- **Enhanced local development experience with unified format/lint commands**
- **Makefile now provides comprehensive Python + Rust development workflow**

### Fixed
- All mypy type errors across 20 source files using proper type annotations and runtime checking
- Import sorting and code quality issues
- SSL handler connection logic and check_connection() functionality
- Python 3.8 compatibility issues (datetime.UTC → datetime.timezone.utc)
- CI workflow syntax errors and redundant documentation building
- Fixed incorrect reporting on root certificate validation
- **Security vulnerability RUSTSEC-2025-0020** by upgrading PyO3 from 0.20.0 to 0.24.1
- **Rust code compatibility** with PyO3 0.24.x API changes (updated module binding syntax)

## [0.1.2] - 2025-05-11

### Added
- ABI3 support for Python wheels for better compatibility

### Changed
- Improved wheel building process for cross-version compatibility

## [0.1.1] - 2025-05-11 [DEPRECATED]

> **Note**: This release has been deprecated. Please use v0.1.2 or later.

### Added
- Python 3.13 support in testing matrix
- Trusted publisher configuration for PyPI releases

### Changed
- Enhanced CI/CD pipeline with proper release permissions
- Updated package structure (moved Rust library outside of Python package)

### Fixed
- CI workflow issues and version bumping process

## [0.1.0] - 2025-05-11 [DEPRECATED]

> **Note**: This release has been deprecated due to Rust build failures. Please use v0.1.2 or later.

### Added
- Initial release of certmonitor
- Certificate validation and monitoring capabilities
- SSL/TLS certificate analysis
- SSH certificate support
- Hybrid Python-Rust implementation for performance
- Virtual environment setup in CI publish job

### Known Issues
- Rust build failures preventing proper installation
