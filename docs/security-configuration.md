# Security Configuration for CertMonitor

## Overview

CertMonitor is a **security assessment tool** designed to analyze and monitor SSL/TLS certificates, including legacy and weak configurations. This creates legitimate security exceptions that need to be documented.

## Intentional Security Exceptions

### 1. Weak SSL/TLS Protocols
**Files**: `certmonitor/protocol_handlers/ssl_handler.py`

**Why**: The tool needs to detect and analyze legacy TLS configurations in production systems. This includes:
- TLS 1.0 and 1.1 (deprecated but still in use)
- SSL 2.3 (legacy systems)
- Weak cipher suites

**Mitigation**: These protocols are only used for **assessment**, not for production connections.

### 2. Subprocess Shell Usage
**Files**: `scripts/generate_report.py`

**Why**: Internal development script that runs controlled commands for report generation.

**Mitigation**: 
- No user input processed
- Commands are hardcoded and controlled
- Only used in development environment

### 3. Certificate Validation Bypassing
**Files**: `certmonitor/validators/`

**Why**: Tool needs to analyze invalid/expired certificates for security assessment.

**Mitigation**: Used only for analysis, never for establishing secure connections.

## Security Scanning Configuration

### Primary Security Tools
1. **Semgrep**: Comprehensive static analysis for security vulnerabilities
2. **Bandit**: Python-specific security linter with configured exceptions
3. **Cargo Audit**: Rust dependency vulnerability scanning

### Tool-Specific Configuration

#### Semgrep Ignores (`.semgrepignore`)
- Weak SSL versions in protocol handlers
- Subprocess shell usage in internal scripts
- Legacy crypto in test files

#### Bandit Configuration (`.bandit`)
- Skips SSL/TLS checks that are intentional for this security tool
- Excludes test files and controlled security assessment code
- Configured exceptions for legitimate certificate monitoring patterns

### Manual Review Required
Security findings should be manually reviewed to ensure they are legitimate exceptions for this security tool's purpose.

## Best Practices

1. **Never use weak TLS in production** - Only for assessment
2. **Isolate assessment code** - Keep detection logic separate from connection logic
3. **Document exceptions** - All security exceptions must be documented
4. **Regular review** - Security configuration should be reviewed regularly

## Certificate Standards Compliance

This tool must maintain compatibility with:
- All certificate types and formats
- All certificate encodings
- All certificate authorities
- All certificate security standards
- All crypto standards and best practices

The security exceptions are necessary to fulfill these comprehensive compatibility requirements.
