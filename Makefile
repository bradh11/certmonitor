# Makefile for certmonitor project

.PHONY: develop build wheel test test-quick docs clean lint format format-check verify-wheel check report ci help typecheck python-lint python-format rust-format rust-format-check rust-lint security fuzz fuzz-long

# Show available targets and their descriptions
help:
	@echo "🛠️  CertMonitor Makefile Commands"
	@echo "================================="
	@echo ""
	@echo "📦 Development:"
	@echo "  develop      Install package in development mode (Python + Rust)"
	@echo "  build        Build release artifacts"
	@echo "  wheel        Build Python wheel with Rust extension"
	@echo ""
	@echo "🧪 Testing & Quality:"
	@echo "  test         Run comprehensive CI-equivalent test suite"
	@echo "  test-quick   Run tests only (fast)"
	@echo "  check        Quick code quality checks (lint + format)"
	@echo "  lint         Run linting (Python + Rust)"
	@echo "  format       Run formatting (Python + Rust)"
	@echo "  format-check Check formatting (Python + Rust)"
	@echo "  python-lint  Run Python-only linting"
	@echo "  python-format Run Python-only formatting"
	@echo "  rust-format  Run Rust-only formatting"
	@echo "  rust-lint    Run Rust-only linting"
	@echo "  typecheck    Run mypy type checking"
	@echo "  security     Run security vulnerability check (Rust + Python)"
	@echo "  ci           Alias for 'test' (full CI checks)"
	@echo ""
	@echo "📊 Reporting:"
	@echo "  report       Generate modularization and quality report"
	@echo ""
	@echo "📚 Documentation:"
	@echo "  docs         Serve documentation locally"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  clean        Remove all build artifacts and cache"
	@echo "  verify-wheel Verify contents of built wheel"
	@echo ""
	@echo "🐛 Fuzzing (manual pre-release gate, requires nightly Rust):"
	@echo "  fuzz         Run the certificate parser fuzz target for 60s"
	@echo "  fuzz-long    Run the certificate parser fuzz target for 1 hour"

# Install the package in development mode (Python + Rust)
develop:
	uv pip install -e .
	uv run maturin develop

# Build the wheel (Python + Rust)
wheel:
	uv run maturin build --release --out dist

# Full build (build artifacts for release)
build: wheel

# Quick test run (just pytest)
test-quick:
	uv pip install -e .
	uv run pytest -v

# Comprehensive test suite (equivalent to CI checks)
test: develop
	@echo "🧪 Running comprehensive test suite (CI equivalent)..."
	@echo "==================================================="
	@echo ""
	@echo "📋 1/9 Python code formatting check..."
	uv run ruff format --check .
	@echo "✅ Python formatting check complete"
	@echo ""
	@echo "🔍 2/9 Python linting check..."
	uv run ruff check .
	@echo "✅ Python linting check complete"
	@echo ""
	@echo "🦀 3/9 Rust code formatting check..."
	cargo fmt --all -- --check
	@echo "✅ Rust formatting check complete"
	@echo ""
	@echo "🔧 4/9 Rust linting check..."
	cargo clippy --all-targets --all-features -- -D warnings
	@echo "✅ Rust linting check complete"
	@echo ""
	@echo "🧪 5/9 Running pytest with coverage..."
	uv run pytest --cov=certmonitor --cov-report=term-missing --cov-fail-under=95
	@echo "✅ Tests and coverage complete"
	@echo ""
	@echo "🔧 6/9 Python type checking..."
	uv run mypy certmonitor/
	@echo "✅ Type checking complete"
	@echo ""
	@echo "🔒 7/9 Security vulnerability check (Rust)..."
	cargo audit
	@echo "✅ Rust security audit complete"
	@echo ""
	@echo "🛡️  8/9 Python security scanning..."
	uv run bandit -r certmonitor/ -f json -o bandit-report.json -c .bandit
	@echo "✅ Python security scan complete"
	@echo ""
	@echo "🏗️  9/9 Build verification..."
	@$(MAKE) wheel >/dev/null 2>&1 && echo "✅ Build successful" || echo "❌ Build failed"
	@echo ""
	@echo "📊 10/10 Generating modularization report..."
	@python scripts/generate_report.py
	@echo ""
	@echo "🎉 All checks complete! Ready for PR/push."

# Individual check commands for granular testing
check: lint format
	@echo "🔍 Running quick code quality checks..."

# Type checking only
typecheck:
	@echo "🔧 Running mypy type checking..."
	uv run mypy certmonitor/

# Generate modularization and quality report
report:
	@echo "📊 Generating modularization report..."
	@python scripts/generate_report.py

# Run all CI checks locally (alias for test)
ci: test

# Serve documentation
docs:
	uv run mkdocs serve

# Format code (Python and Rust)
format:
	@echo "Formatting Python code..."
	uv run ruff format .
	@echo "Formatting Rust code..."
	cargo fmt --all

# Check formatting (Python and Rust)
format-check:
	@echo "Checking Python formatting..."
	uv run ruff format --check .
	@echo "Checking Rust formatting..."
	cargo fmt --all -- --check

# Lint code (Python and Rust)
lint:
	@echo "Linting Python code..."
	uv run ruff check .
	@echo "Linting Rust code..."
	cargo clippy --all-targets --all-features -- -D warnings

# Python-only formatting
python-format:
	uv run ruff format .

# Python-only linting
python-lint:
	uv run ruff check .

# Rust-only formatting
rust-format:
	cargo fmt --all

# Rust-only formatting check
rust-format-check:
	cargo fmt --all -- --check

# Rust-only linting
rust-lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Security vulnerability check
security:
	@echo "🔒 Running security vulnerability checks..."
	@echo "🦀 Rust security audit..."
	cargo audit
	@echo "🐍 Python security scan..."
	uv run bandit -r certmonitor/ -f json -o bandit-report.json -c .bandit
	@echo "✅ Security scans complete"

# Run the parser fuzz target. Manual pre-release hardening gate; not in
# CI. Requires nightly Rust + cargo-fuzz; the recipe checks for both
# and tells you how to install if missing. Seeds the libfuzzer corpus
# from the captured real-world certs in tests/fixtures/diff_corpus/ so
# the fuzzer starts with realistic inputs.
#
# `fuzz` is a 60-second smoke run for use during development.
# `fuzz-long` is a 1-hour soak for use before tagging a release.
# See fuzz/README.md for details.
fuzz: FUZZ_DURATION ?= 60
fuzz: _fuzz_run

fuzz-long: FUZZ_DURATION = 3600
fuzz-long: _fuzz_run

_fuzz_run:
	@command -v cargo-fuzz >/dev/null 2>&1 || { \
		echo "❌ cargo-fuzz not installed."; \
		echo "   Install with: cargo install cargo-fuzz"; \
		exit 1; \
	}
	@rustup toolchain list 2>/dev/null | grep -q nightly || { \
		echo "❌ nightly Rust toolchain not installed."; \
		echo "   Install with: rustup toolchain install nightly"; \
		exit 1; \
	}
	@echo "🐛 Seeding fuzz corpus from tests/fixtures/diff_corpus/..."
	@mkdir -p fuzz/corpus/parse_certificate
	@cp tests/fixtures/diff_corpus/*.der fuzz/corpus/parse_certificate/ 2>/dev/null || true
	@CORPUS_COUNT=$$(ls fuzz/corpus/parse_certificate/*.der 2>/dev/null | wc -l | tr -d ' '); \
		echo "   $$CORPUS_COUNT seed files in corpus"
	@echo "🐛 Running parse_certificate fuzz target for $(FUZZ_DURATION)s..."
	@echo "   Crashes (if any) will land in fuzz/artifacts/parse_certificate/"
	cargo +nightly fuzz run parse_certificate -- -max_total_time=$(FUZZ_DURATION)
	@echo "✅ Fuzz run complete (no crashes)"

# Clean all build artifacts, cache, eggs, and venv
clean:
	rm -rf \
		build/ \
		dist/ \
		target/ \
		.mypy_cache/ \
		.pytest_cache/ \
		.venv/ \
		certmonitor.egg-info/ \
		__pycache__/ \
		**/__pycache__/ \
		*.egg-info \
		*.pyc \
		*.pyo \
		*.pyd \
		*.log \
		.DS_Store \
		*.so \
		*.c \
		*.o \
		*.rlib \
		*.rmeta \
		*.dll \
		*.dylib \
		*.exe \
		*.a \
		*.out \
		fuzz/target/ \
		fuzz/corpus/ \
		fuzz/artifacts/ \
		fuzz/coverage/

# Verify the contents of the built wheel
verify-wheel:
	@echo "🔍 Verifying wheel contents..."
	unzip -l dist/certmonitor-*.whl | grep certmonitor