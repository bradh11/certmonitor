# validators/revocation.py

"""Opt-in revocation checking through OCSP and CRLs."""

from typing import Any, ClassVar

from .base import _ValidatorBase
from .results import ValidationResult

_DEFAULT_METHODS = ("ocsp", "crl")


class RevocationResult(ValidationResult, total=False):
    """Result shape for `RevocationValidator` (envelope + data)."""

    revocation_status: str
    source: str | None
    signature_verified: bool
    this_update: str | None
    next_update: str | None
    revocation_time: str | None
    revocation_reason: str | None
    methods: dict[str, dict[str, Any]]


class RevocationValidator(_ValidatorBase):
    """Check whether the certificate has been revoked, via OCSP and CRLs.

    Opt-in: enable it with `enabled_validators=["revocation"]` or
    `certmonitor check -v revocation`. The certificate's own pointers are
    used: its OCSP responder URL and its CRL distribution points.

    Each method is tried in order. A `revoked` answer from any method fails
    the check at once. A `good` answer passes only when it is proven: CRL
    answers are, because OpenSSL verifies the CRL's signature and validity
    while loading it; OCSP answers are not yet, so by default an OCSP
    `good` is reported as a warning unless a verified method confirms it.
    Set `accept_unverified=True` to let an unverified OCSP `good` pass.

    Args:
        methods: Order in which to consult `"ocsp"` and `"crl"`. Defaults
            to OCSP first, then the CRL.
        accept_unverified: Treat an OCSP `good` whose signature was not
            verified as a pass instead of a warning.

    Example:
        ```python
        with CertMonitor("example.com", enabled_validators=["revocation"]) as monitor:
            result = monitor.validate()["revocation"]
            print(result["status"], result["revocation_status"], result["source"])
        ```
    """

    name: str = "revocation"
    validator_type: str = "cert"
    requires: ClassVar[tuple[str, ...]] = ("revocation",)

    def validate(
        self,
        evidence: Any,
        host: str,
        port: int,
        *,
        methods: list[str] | None = None,
        accept_unverified: bool = False,
    ) -> RevocationResult:
        order = list(methods) if methods else list(_DEFAULT_METHODS)
        unknown = [method for method in order if method not in _DEFAULT_METHODS]
        if unknown:
            raise ValueError(
                f"unknown revocation method(s) {', '.join(unknown)}; choose from ocsp, crl"
            )
        answers: dict[str, dict[str, Any]] = {}
        unverified_good: dict[str, Any] | None = None
        for method in order:
            answer = dict(evidence.answer(method))
            answer.pop("_next_update", None)
            answers[method] = answer
            if answer["status"] == "revoked":
                return self._verdict(
                    answer,
                    answers,
                    is_valid=False,
                    status="fail",
                    reason=self._revoked_reason(answer),
                )
            if answer["status"] == "good":
                if answer.get("signature_verified") or accept_unverified:
                    return self._verdict(answer, answers, is_valid=True, status="pass")
                unverified_good = unverified_good or answer
        if unverified_good is not None:
            return self._verdict(
                unverified_good,
                answers,
                is_valid=True,
                status="warn",
                warnings=[
                    "The OCSP responder reported the certificate as good, but the "
                    "response signature was not verified. Set accept_unverified=True "
                    "to treat it as proof, or enable the crl method for a verified answer."
                ],
            )
        if all(answer["status"] == "unsupported" for answer in answers.values()):
            reasons = " ".join(answer.get("reason", "") for answer in answers.values())
            return self._verdict(
                None, answers, is_valid=False, status="unsupported", reason=reasons
            )
        problems = [
            f"{method}: {answer.get('reason', answer['status'])}"
            for method, answer in answers.items()
            if answer["status"] != "good"
        ]
        return self._verdict(
            None,
            answers,
            is_valid=False,
            status="error",
            error="RevocationUnavailable",
            reason="No revocation source gave a usable answer ("
            + "; ".join(problems)
            + ")",
        )

    @staticmethod
    def _revoked_reason(answer: dict[str, Any]) -> str:
        when = answer.get("revocation_time")
        why = answer.get("revocation_reason")
        detail = f" on {when}" if when else ""
        if why:
            detail += f" ({why})"
        return f"The certificate was revoked{detail} according to {answer['method'].upper()}."

    @staticmethod
    def _verdict(
        answer: dict[str, Any] | None,
        answers: dict[str, dict[str, Any]],
        *,
        is_valid: bool,
        status: str,
        reason: str | None = None,
        error: str | None = None,
        warnings: list[str] | None = None,
    ) -> RevocationResult:
        result: RevocationResult = {
            "is_valid": is_valid,
            "status": status,
            "warnings": warnings or [],
            "revocation_status": (answer or {}).get("status", "unknown"),
            "source": (answer or {}).get("method"),
            "signature_verified": bool((answer or {}).get("signature_verified", False)),
            "this_update": (answer or {}).get("this_update"),
            "next_update": (answer or {}).get("next_update"),
            "revocation_time": (answer or {}).get("revocation_time"),
            "revocation_reason": (answer or {}).get("revocation_reason"),
            "methods": answers,
        }
        if reason is not None:
            result["reason"] = reason
        if error is not None:
            result["error"] = error
        return result
