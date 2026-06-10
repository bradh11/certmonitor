# validators/pq_key_exchange.py

from typing import Any, ClassVar, Dict, Tuple

from .base import BaseCipherValidator


class PqKeyExchangeValidator(BaseCipherValidator):
    """Judge the TLS key exchange's post-quantum posture.

    This validator answers the *harvest-now-decrypt-later* (HNDL)
    question: is the session key protected against a future quantum
    computer? It consumes the negotiated cipher info plus the Rust TLS
    probe result (``certinfo.probe_tls_handshake``), which reports the
    negotiated TLS 1.3 key-exchange group.

    "PQ" includes **hybrid** groups (classical + ML-KEM, e.g.
    ``X25519MLKEM768``) as well as pure ML-KEM — requiring pure PQ today
    would fail every real-world server. ``is_valid`` is a strict ``bool``:
    the HNDL question is binary at the protocol level.

    Behavior matrix:

    | Server | Result |
    |---|---|
    | TLS 1.3 + hybrid/pure PQ group | ``is_valid: True`` |
    | TLS 1.3 + classical group | ``is_valid: False`` — classical KEX, HNDL-exposed |
    | TLS 1.2 or older | ``is_valid: False`` — no PQ KEMs defined (probe skipped) |
    | Connection/probe error | ``{error, message, is_valid: False}`` |

    The skip-for-legacy short-circuit (no second TCP connection for
    TLS < 1.3) lives in the ``tls_probe`` data source, so by the time this
    validator runs the decision is already free of extra I/O.

    Opt-in: registered in ``VALIDATORS`` but **not** in
    ``DEFAULT_VALIDATORS`` — PQ KEX is still rolling out, so it would be
    noisy by default.

    Attributes:
        name (str): The name of the validator.
    """

    name: str = "pq_key_exchange"
    requires: ClassVar[Tuple[str, ...]] = ("cipher_info", "tls_probe")

    def validate(  # type: ignore[override]  # multi-source: dispatcher injects per `requires`
        self,
        cipher_info: Dict[str, Any],
        tls_probe: Dict[str, Any],
        host: str,
        port: int,
    ) -> Dict[str, Any]:
        """Classify the negotiated key exchange.

        Args:
            cipher_info: Negotiated cipher info (for the TLS version).
            tls_probe: The ``probe_tls_handshake`` result dict.
            host: The hostname (unused; dispatcher compatibility).
            port: The port (unused; dispatcher compatibility).

        Returns:
            dict: ``{kem_id, kem_name, kem_kind, is_pq, is_valid}`` on a
            negotiated group; an ``n/a`` result for TLS < 1.3; or a
            ``{error, message, is_valid}`` dict on a probe/connection error.

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
                    "reason": "classical key exchange (x25519) is vulnerable to harvest-now-decrypt-later"
                }
                ```
        """
        result = tls_probe.get("result")

        if result == "error":
            # Connection/probe failure — surface the standard error shape.
            return {
                "error": tls_probe.get("error", "ProbeError"),
                "message": tls_probe.get("message", "TLS probe failed"),
                "is_valid": False,
            }

        if result == "n/a":
            # TLS < 1.3 (or no key_share). Not PQ-capable at all — a
            # stronger signal than "unknown", so a strict False.
            protocol = tls_probe.get("protocol") or cipher_info.get(
                "protocol_version", "this TLS version"
            )
            return {
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
            out: Dict[str, Any] = {
                "kem_id": tls_probe.get("id"),
                "kem_name": name,
                "kem_kind": tls_probe.get("kind", "unknown"),
                "is_pq": is_pq,
                "is_valid": is_pq,
            }
            if tls_probe.get("via_hello_retry_request"):
                # The server asked (via HRR) for this group — it is
                # PQ-capable even though our first flight didn't complete.
                out["via_hello_retry_request"] = True
            if not is_pq:
                out["reason"] = (
                    f"classical key exchange ({name}) is vulnerable to "
                    "harvest-now-decrypt-later"
                )
            return out

        # Defensive: an unrecognized probe shape.
        return {
            "is_valid": False,
            "reason": f"Unrecognized TLS probe result: {result!r}",
        }
