# validators/pq_key_exchange.py

from typing import Any, ClassVar, TypedDict

from .base import BaseCipherValidator
from .results import ValidationResult


class ProbeEvidence(TypedDict):
    observation_scope: str
    handshake_completed: bool
    authenticated: bool
    endpoint: str
    observed_at: str
    offered_groups: list[int]


class PqKeyExchangeResult(ValidationResult, ProbeEvidence, total=False):
    """Result shape for `PqKeyExchangeValidator` (envelope + evidence + data)."""

    kem_id: int | None
    kem_name: str
    kem_kind: str
    is_pq: bool
    via_hello_retry_request: bool


class PqKeyExchangeValidator(BaseCipherValidator):
    """Judge the TLS key exchange's post-quantum posture.

    This validator contributes to *harvest-now-decrypt-later* (HNDL)
    readiness assessment by observing server capability under a probe offer.
    It does not establish protection of the primary session or application
    traffic. It consumes the negotiated cipher info plus the Rust TLS
    probe result (`certinfo.probe_tls_handshake`), which reports the
    selected or requested TLS 1.3 key-exchange group.

    "PQ" includes **hybrid** groups (classical + ML-KEM, e.g.
    `X25519MLKEM768`) as well as pure ML-KEM. A recognized hybrid meets
    this capability policy. `is_valid` is a strict `bool`:
    the result describes this capability policy, not an authenticated handshake.

    Behavior matrix:

    | Server | Result |
    |---|---|
    | TLS 1.3 + hybrid/pure PQ group | `is_valid: True` |
    | TLS 1.3 + classical group | `is_valid: False`, PQ capability not observed under this offer |
    | TLS 1.2 or older | `is_valid: False`, no PQ KEMs defined (probe skipped) |
    | Connection/probe error or TLS alert | `{error, message, reason, is_valid: False}` |

    The skip-for-legacy short-circuit (no second TCP connection for
    TLS < 1.3) lives in the `tls_probe` data source, so by the time this
    validator runs the decision is already free of extra I/O.

    Opt-in: registered in `VALIDATORS` but **not** in
    `DEFAULT_VALIDATORS`, PQ KEX is still rolling out, so it would be
    noisy by default.

    The probe stops at ServerHello or HelloRetryRequest. Results report
    `offered_groups`, `endpoint`, `observed_at`, `handshake_completed: False`,
    and `authenticated: False`. A HelloRetryRequest identifies a requested group.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "pq_key_exchange"
    requires: ClassVar[tuple[str, ...]] = ("cipher_info", "tls_probe")

    def validate(  # type: ignore[override]  # multi-source: dispatcher injects per `requires`
        self,
        cipher_info: dict[str, Any],
        tls_probe: dict[str, Any],
        host: str,
        port: int,
    ) -> PqKeyExchangeResult:
        """Classify the key-exchange group observed by the separate capability probe.

        Args:
            cipher_info: Negotiated cipher info (for the TLS version).
            tls_probe: The `probe_tls_handshake` result dict.
            host: The hostname (unused; dispatcher compatibility).
            port: The port (unused; dispatcher compatibility).

        Returns:
            dict: `{kem_id, kem_name, kem_kind, is_pq, is_valid}` on a
            negotiated group; an `n/a` result for TLS < 1.3; or a
            `{error, message, reason, is_valid}` dict on a
            probe/connection error.

        Examples:
            Hybrid PQ key exchange (success):
                ```json
                {
                    "kem_id": 4588,
                    "kem_name": "X25519MLKEM768",
                    "kem_kind": "hybrid_pq",
                    "is_pq": true,
                    "is_valid": true
                }
                ```

            Classical key exchange (failure):
                ```json
                {
                    "kem_id": 29,
                    "kem_name": "x25519",
                    "kem_kind": "classical_ecdh",
                    "is_pq": false,
                    "is_valid": false,
                    "reason": "This probe selected classical key exchange (x25519); PQ capability was not observed with this offer."
                }
                ```
        """
        result = tls_probe.get("result")
        evidence: ProbeEvidence = {
            "observation_scope": "server_capability_probe",
            "handshake_completed": False,
            "authenticated": False,
            "endpoint": tls_probe.get("endpoint", f"{host}:{port}"),
            "observed_at": tls_probe.get("observed_at", ""),
            "offered_groups": tls_probe.get("offered_groups", []),
        }

        if result == "error":
            # Connection/probe failure, an operational failure is still a
            # result: reason satisfies the envelope, error/message keep the
            # machine-readable class.
            message = tls_probe.get("message", "TLS probe failed")
            return {
                **evidence,
                "status": "error",
                "error": tls_probe.get("error", "ProbeError"),
                "message": message,
                "is_valid": False,
                "reason": message,
            }

        if result == "n/a":
            # TLS < 1.3 (or no key_share). Not PQ-capable at all, a
            # stronger signal than "unknown", so a strict False.
            protocol = tls_probe.get("protocol") or cipher_info.get(
                "protocol_version", "this TLS version"
            )
            return {
                **evidence,
                "status": "unsupported",
                "kem_kind": "n/a",
                "is_pq": False,
                "is_valid": False,
                "reason": tls_probe.get(
                    "reason", f"{protocol} has no post-quantum key exchange"
                ),
            }

        if result == "group":
            is_pq = bool(tls_probe.get("is_pq", False))
            name = tls_probe.get("name", "unknown")
            out: PqKeyExchangeResult = {
                **evidence,
                "kem_id": tls_probe.get("id"),
                "kem_name": name,
                "kem_kind": tls_probe.get("kind", "unknown"),
                "is_pq": is_pq,
                "is_valid": is_pq,
            }
            if tls_probe.get("via_hello_retry_request"):
                # The server asked (via HRR) for this group, it is
                # PQ-capable even though our first flight didn't complete.
                out["via_hello_retry_request"] = True
            if not is_pq:
                out["reason"] = (
                    f"This probe selected classical key exchange ({name}); "
                    "PQ capability was not observed with this offer."
                )
            return out

        # Defensive: an unrecognized probe shape.
        return {
            **evidence,
            "status": "error",
            "is_valid": False,
            "reason": f"Unrecognized TLS probe result: {result!r}",
        }
