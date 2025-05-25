# Contributing to CertMonitor

Thank you for your interest in contributing to CertMonitor! This guide will help you get started with contributing to the project.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/certmonitor.git
   cd certmonitor
   ```
3. **Set up the development environment** (see [Development Setup](#development-setup))
4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
5. **Make your changes** and commit them
6. **Push to your fork** and create a pull request

## 📋 Table of Contents

- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Issues](#security-issues)
- [Documentation](#documentation)
- [Community Guidelines](#community-guidelines)

## 🛠️ Development Setup

### Prerequisites

- Python 3.8+ 
- Rust toolchain (for building the certificate parsing extension)
- uv (recommended package manager)

### Installation

1. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Install uv** (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **Install dependencies**:
   ```bash
   uv sync --group dev
   ```

4. **Build the Rust extension**:
   ```bash
   make develop
   # OR manually:
   uv run maturin develop
   ```

5. **Run tests** to verify setup:
   ```bash
   make test
   # OR manually:
   uv run pytest
   ```

### Development Commands

```bash
# Run tests
make test
uv run pytest

# Run tests with coverage
uv run pytest --cov=certmonitor

# Format code
uv run ruff format .

# Lint code  
uv run ruff check .

# Build documentation
make docs
uv run mkdocs serve

# Build the Rust extension
make develop
uv run maturin develop
```

## 📏 Code Standards

CertMonitor follows strict coding standards to ensure code quality and consistency:

### Python Standards

- **Python Version**: 3.8+ compatible
- **Type Hints**: Required for all functions and methods
- **Formatting**: Use `ruff format` for code formatting
- **Linting**: Use `ruff check` and fix all issues
- **String Formatting**: Use f-strings for string formatting
- **Dependencies**: Standard library only (no external Python dependencies)
- **Documentation**: Docstrings required for all public functions and classes

### Code Quality Requirements

```bash
# Before submitting a PR, ensure these pass:
uv run ruff format .        # Format code
uv run ruff check .         # Lint code
uv run pytest              # Run all tests
uv run pytest --cov=certmonitor  # Check coverage
```

### Certificate and Crypto Standards

CertMonitor must adhere to the highest standards for certificate and cryptographic operations:

- Support all certificate types, formats, and encodings
- Follow all relevant RFC standards and security best practices
- Maintain compatibility with all major certificate authorities
- Implement robust error handling for edge cases
- Ensure security-first design principles

## 🧪 Testing

### Running Tests

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_core.py

# Run tests with coverage
uv run pytest --cov=certmonitor --cov-report=html

# Run tests for specific functionality
uv run pytest tests/test_validators/
```

### Test Organization

Tests are organized into logical modules:
- `tests/test_core/` - Core functionality tests
- `tests/test_validators/` - Validator-specific tests  
- `tests/test_protocol_handlers/` - Protocol handler tests
- `tests/test_cipher_algorithms.py` - Cipher algorithm tests

### Writing Tests

- Write comprehensive tests for new functionality
- Include edge cases and error conditions
- Use descriptive test names that explain what is being tested
- Follow the existing test patterns and structure
- Aim for high test coverage (current: 98%+)

### Test Requirements

- All new code must have corresponding tests
- Tests must pass on all supported Python versions (3.8-3.13)
- Tests should not require external network access (use mocks)
- Security-related functionality requires extra scrutiny and testing

## 📝 Pull Request Process

### Before Submitting

1. **Create an issue** first (unless it's a trivial fix)
2. **Fork the repository** and create a feature branch
3. **Make your changes** following the code standards
4. **Write or update tests** for your changes
5. **Update documentation** if needed
6. **Run the full test suite** and ensure it passes
7. **Run code quality checks** (ruff format, ruff check)

### PR Requirements

- [ ] Clear description of changes and motivation
- [ ] Reference related issues (e.g., "Fixes #123")
- [ ] All tests pass
- [ ] Code follows project standards
- [ ] Documentation updated (if applicable)
- [ ] Backward compatibility maintained (unless explicitly breaking)

### PR Review Process

1. Automated CI checks must pass
2. Code review by maintainers
3. Discussion and potential requested changes
4. Final approval and merge

## 🐛 Issue Reporting

### Before Creating an Issue

- Search existing issues to avoid duplicates
- Read the documentation thoroughly
- Try the latest version of CertMonitor

### Issue Types

Use the appropriate issue template:
- **🐛 Bug Report** - For reporting bugs
- **✨ Feature Request** - For suggesting new features  
- **📚 Documentation Issue** - For documentation problems
- **🔒 Security Issue** - For security-related concerns
- **❓ Question / Help** - For getting help or asking questions

### Security Issues

For sensitive security vulnerabilities:
- Use GitHub's private vulnerability reporting feature
- Do NOT create public issues for exploitable vulnerabilities
- Provide detailed information privately to maintainers

## 📖 Documentation

### Documentation Types

- **API Reference** - Auto-generated from docstrings
- **Usage Guides** - Step-by-step tutorials and examples
- **Developer Docs** - Contributing, development setup, architecture

### Contributing to Documentation

- Documentation is in the `docs/` directory
- Uses MkDocs with Material theme
- API docs are auto-generated from code docstrings
- Test documentation builds locally: `uv run mkdocs serve`

### Documentation Standards

- Clear, concise language
- Include code examples where appropriate
- Keep examples up-to-date with current API
- Use proper markdown formatting
- Include links to related sections

## 🤝 Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Assume good intentions

### Getting Help

- Check the documentation first
- Search existing issues and discussions
- Ask questions in GitHub Discussions
- Use appropriate issue templates

### Best Practices

- Start with small contributions to get familiar with the project
- Ask questions if anything is unclear
- Be patient with the review process
- Help review other contributors' work when possible

## 🎯 Areas Where We Need Help

### High Priority

- 🧪 **Testing**: More test coverage for edge cases
- 📚 **Documentation**: Usage examples and tutorials
- 🔒 **Security**: Security audits and improvements
- 🌐 **Protocol Support**: Additional protocol implementations

### Good First Issues

Look for issues labeled:
- `good first issue` - Perfect for newcomers
- `help wanted` - Community contributions welcome
- `documentation` - Documentation improvements needed

## 🏆 Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes for significant contributions
- GitHub contributor statistics

## 📞 Contact

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions  
- **Security**: Private vulnerability reporting
- **Email**: For sensitive matters only

---

Thank you for contributing to CertMonitor! Your help makes the project better for everyone. 🙏
