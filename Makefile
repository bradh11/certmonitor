# Makefile for certmonitor project

.PHONY: develop build wheel test test-quick docs clean lint format verify-wheel check report ci help typecheck

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
	@echo "  lint         Run ruff linting"
	@echo "  format       Run ruff formatting"
	@echo "  typecheck    Run mypy type checking"
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
	@echo "=================================================="
	@echo ""
	@echo "📋 1/6 Code formatting check..."
	uv run ruff format --check .
	@echo "✅ Formatting check complete"
	@echo ""
	@echo "🔍 2/6 Linting check..."
	uv run ruff check .
	@echo "✅ Linting check complete"
	@echo ""
	@echo "🧪 3/6 Running pytest with coverage..."
	uv run pytest --cov=certmonitor --cov-report=term-missing --cov-fail-under=95
	@echo "✅ Tests and coverage complete"
	@echo ""
	@echo "🔧 4/6 Type checking..."
	uv run mypy certmonitor/
	@echo "✅ Type checking complete"
	@echo ""
	@echo "🏗️  5/6 Build verification..."
	@$(MAKE) wheel >/dev/null 2>&1 && echo "✅ Build successful" || echo "❌ Build failed"
	@echo ""
	@echo "📊 6/6 Generating modularization report..."
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

# Lint code
lint:
	uv run ruff check .

# Format code
format:
	uv run ruff format .

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
		*.out

# Verify the contents of the built wheel
verify-wheel:
	@echo "🔍 Verifying wheel contents..."
	unzip -l dist/certmonitor-*.whl | grep certmonitor