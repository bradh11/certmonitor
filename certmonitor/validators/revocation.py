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

    Each method is tried in order and only a proven answer decides: a
    verified `revoked` fails the check, a verified `good` passes it. CRL
    answers are proven by OpenSSL, which verifies the CRL's signature and
    validity while loading it; OCSP answers are proven when the response is
    signed by the issuing CA or an authorized responder with RSA PKCS#1 v1.5
    or ECDSA (P-256, P-384). An OCSP response whose signature was checked and
    is wrong is discarded before its content is read, whatever it claims; if
    no other method answers, the result is an `error` (`OCSPInvalidSignature`).
    An OCSP response that cannot be checked, for example one signed with an
    algorithm CertMonitor does not implement, is held back: a `good` becomes a
    warning and a `revoked` becomes an `error` (`OCSPUnverifiedRevocation`)
    unless a verified method answers or `accept_unverified=True` accepts the
    responder's word for either verdict.

    Args:
        methods: Order in which to consult `"ocsp"` and `"crl"`. Defaults
            to OCSP first, then the CRL.
        accept_unverified: Act on an OCSP answer whose signature could not be
            checked (unsupported algorithm) as if it were verified: `good`
            passes and `revoked` fails. Never applies to a signature that was
            checked and found wrong.

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
        unverified: dict[str, Any] | None = None
        for method in order:
            answer = dict(evidence.answer(method))
            answer.pop("_next_update", None)
            answers[method] = answer
            if answer["status"] not in ("good", "revoked"):
                continue
            # The signature question comes before the answer's content: an
            # unverified response is interpreted neither as good nor as
            # revoked (RFC 6960 §3.2). One whose signature was checked and is
            # wrong is discarded outright, since it was tampered with or came
            # from the wrong signer; one that could not be checked is held
            # back unless the caller opted to take the responder's word.
            if answer.get("verification") == "failed":
                continue
            if not answer.get("signature_verified") and not accept_unverified:
                unverified = unverified or answer
                continue
            if answer["status"] == "revoked":
                return self._verdict(
                    answer,
                    answers,
                    is_valid=False,
                    status="fail",
                    reason=self._revoked_reason(answer),
                )
            return self._verdict(answer, answers, is_valid=True, status="pass")
        if unverified is not None:
            why = str(unverified.get("verification_error", "unknown reason"))
            if unverified["status"] == "good":
                return self._verdict(
                    unverified,
                    answers,
                    is_valid=True,
                    status="warn",
                    warnings=[
                        "The OCSP responder reported the certificate as good, but the "
                        f"response could not be verified ({why}). Set "
                        "accept_unverified=True to treat it as proof, or enable the crl "
                        "method for a verified answer."
                    ],
                )
            return self._verdict(
                unverified,
                answers,
                is_valid=False,
                status="error",
                error="OCSPUnverifiedRevocation",
                reason=(
                    "The OCSP responder reported the certificate as revoked, but the "
                    f"response could not be verified ({why}); the claim was not acted "
                    "on. Set accept_unverified=True to treat it as proof, or enable the "
                    "crl method for a verified answer."
                ),
            )
        if all(answer["status"] == "unsupported" for answer in answers.values()):
            reasons = " ".join(answer.get("reason", "") for answer in answers.values())
            return self._verdict(
                None, answers, is_valid=False, status="unsupported", reason=reasons
            )
        problems = []
        for method, answer in answers.items():
            if answer.get("verification") == "failed":
                problems.append(
                    f"{method}: response signature failed verification "
                    f"({answer.get('verification_error', 'unknown reason')})"
                )
            elif answer["status"] != "good":
                problems.append(f"{method}: {answer.get('reason', answer['status'])}")
        failed = any(a.get("verification") == "failed" for a in answers.values())
        return self._verdict(
            None,
            answers,
            is_valid=False,
            status="error",
            error="OCSPInvalidSignature" if failed else "RevocationUnavailable",
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
