# Contributing a Validator

So you've written a check that you think everyone should have, and you want it shipped in CertMonitor itself. This guide walks you through it end to end.

!!! info "Just need it for yourself?"
    If the check is specific to your organization and you only need it in your own code, you don't have to touch the CertMonitor repo at all. Register it at runtime instead. See [Custom Validators](usage/custom_validators.md). This page is for getting a validator *into the library*, which means tests, docs, and registration on top of the validator itself.

The validator code is the easy part. What makes it a contribution is everything around it: registration, tests, a docs page, and a changelog entry. Let's go through each.

## 1. Write the validator

Validators live in `certmonitor/validators/`. Create one file per validator, named after it.

Pick a base class based on what your check looks at:

- **`BaseCertValidator`** if you inspect the certificate. Your `validate` receives the parsed cert data.
- **`BaseCipherValidator`** if you inspect the negotiated connection (TLS version, cipher suite). Your `validate` receives the cipher info.

Here's a complete cert validator. Let's say we want to flag certificates whose Common Name is missing:

```python
# certmonitor/validators/common_name_present.py

from typing import Any, Dict

from .base import BaseCertValidator
from .results import ValidationResult


class CommonNamePresentResult(ValidationResult, total=False):
    """Result shape for CommonNamePresentValidator (envelope + data)."""

    common_name: str


class CommonNamePresentValidator(BaseCertValidator):
    """Flags certificates that do not carry a Subject Common Name."""

    name = "common_name_present"

    def validate(self, cert: Dict[str, Any], host: str, port: int) -> CommonNamePresentResult:
        subject = cert.get("cert_info", {}).get("subject", {})
        common_name = subject.get("commonName")

        if not common_name:
            return {
                "is_valid": False,
                "reason": "Certificate subject has no Common Name.",
            }

        return {"is_valid": True, "common_name": common_name}
```

A few rules to follow, all enforced or expected by the framework:

- **Set a unique `name`.** That's the key users enable and the key your result appears under.
- **Follow the [result envelope](validators/index.md#the-result-contract).** Always return `is_valid` as a strict `bool`. Add `reason` only when `is_valid` is `False`. Never return `None`; if you can't determine an answer, fail closed with a `reason`.
- **Declare a `TypedDict`** that extends `ValidationResult` with your data fields, and annotate `validate` with it. This is what lets mypy check the envelope.

!!! tip "User-configurable arguments"
    If your validator takes options, declare them as **keyword-only** parameters after `host` and `port`, each with a **type annotation** and a **default**. The base class enforces this at import time, so a malformed signature fails fast:

    ```python
    def validate(self, cert, host, port, *, min_length: int = 1) -> MyResult:
        ...
    ```

    Users then pass them through `validator_args`. See [Passing Arguments to Validators](usage/validator_args.md).

## 2. Register it

Add your validator to the registry in `certmonitor/validators/__init__.py`:

```python
from .common_name_present import CommonNamePresentValidator

VALIDATORS = {
    # ... existing validators ...
    "common_name_present": CommonNamePresentValidator(),
}
```

!!! warning "Default or opt-in?"
    New validators should be **opt-in** by default. The default set (`expiration`, `hostname`, `root_certificate`, defined as `DEFAULT_VALIDATORS` in `certmonitor/config.py`) is deliberately small so that `CertMonitor("host")` stays fast and quiet. Only propose adding to the defaults if the check is universally useful and cheap, and call it out explicitly in your PR so it can be discussed.

## 3. Test it

Add `tests/test_validators/test_common_name_present.py`. The project requires **95% coverage**, and every code path your validator has needs a test, including the failure path.

Prefer driving the validator with **real parser output** over hand-built dicts where you can. Hand-built fixtures drift from what the parser actually produces (this is exactly how a stale example once slipped through), so a test against a real certificate catches more:

```python
from certmonitor.validators import VALIDATORS


def test_common_name_present_pass():
    cert = {"cert_info": {"subject": {"commonName": "example.com"}}}
    result = VALIDATORS["common_name_present"].validate(cert, "example.com", 443)
    assert result["is_valid"] is True
    assert result["common_name"] == "example.com"


def test_common_name_present_fail():
    cert = {"cert_info": {"subject": {}}}
    result = VALIDATORS["common_name_present"].validate(cert, "example.com", 443)
    assert result["is_valid"] is False
    assert "reason" in result
```

## 4. Document it

Add `docs/validators/common_name_present.md` following the pattern of the existing pages: a friendly intro that says what it checks and why, a short "Try it" example, any gotchas as admonitions, and a `## Reference` section that pulls the docstring dynamically:

```markdown
# CommonNamePresent Validator

A short, friendly description of what this checks and why it matters.

## Reference

::: certmonitor.validators.common_name_present.CommonNamePresentValidator
```

Then add it to the nav in `mkdocs.yml` under the `Validators` section. Keep your example output in the **docstring** (so the `:::` block renders it) rather than hardcoding it on the page, which keeps the docs from drifting.

## 5. Add a changelog entry

Add a line to the `[Unreleased]` section of `CHANGELOG.md` describing the user-visible change, in past tense.

## 6. Run the full suite

Before opening your PR, run what CI runs:

```sh
make test
```

This formats, lints, type-checks, tests with coverage, and audits, for both Python and Rust. If it's green locally, it'll be green in CI.

## Checklist

- [ ] Validator file in `certmonitor/validators/`, subclassing the right base class
- [ ] Unique `name`, result follows the envelope (`is_valid` strict bool, `reason` on failure)
- [ ] `TypedDict` result type, `validate` annotated with it
- [ ] Any options declared as keyword-only, annotated, defaulted
- [ ] Registered in `certmonitor/validators/__init__.py` (opt-in unless agreed otherwise)
- [ ] Tests in `tests/test_validators/`, 95%+ coverage, both pass and fail paths
- [ ] Docs page added and wired into `mkdocs.yml`
- [ ] Changelog entry under `[Unreleased]`
- [ ] `make test` is green
