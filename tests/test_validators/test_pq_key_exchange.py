# tests/test_validators/test_pq_key_exchange.py
#
# Unit tests for the pq_key_exchange validator (#34). The validator is a
# pure function over (cipher_info, tls_probe); the probe result is mocked
# here. The skip-for-legacy short-circuit (no second connection for
# TLS < 1.3) is tested at the dispatcher/source level in test_core.

from unittest.mock import MagicMock, patch

import pytest

from certmonitor.core import CertMonitor
from certmonitor.validators.pq_key_exchange import PqKeyExchangeValidator

TLS13 = {"protocol_version": "TLSv1.3"}
TLS12 = {"protocol_version": "TLSv1.2"}


class TestPqKeyExchangeValidator:
    def setup_method(self):
        self.v = PqKeyExchangeValidator()

    def test_name_type_and_requires(self):
        assert self.v.name == "pq_key_exchange"
        assert self.v.validator_type == "cipher"
        assert self.v.requires == ("cipher_info", "tls_probe")

    def test_hybrid_pq_is_valid(self):
        probe = {
            "result": "group",
            "id": 4588,
            "name": "X25519MLKEM768",
            "kind": "hybrid_pq",
            "is_pq": True,
            "protocol": "tls1.3",
            "via_hello_retry_request": False,
        }
        r = self.v.validate(TLS13, probe, "h", 443)
        assert r == {
            "kem_id": 4588,
            "kem_name": "X25519MLKEM768",
            "kem_kind": "hybrid_pq",
            "is_pq": True,
            "is_valid": True,
        }

    def test_pure_pq_is_valid(self):
        probe = {
            "result": "group",
            "id": 0x0201,
            "name": "MLKEM768",
            "kind": "pure_pq",
            "is_pq": True,
        }
        r = self.v.validate(TLS13, probe, "h", 443)
        assert r["is_pq"] is True
        assert r["is_valid"] is True
        assert r["kem_kind"] == "pure_pq"

    def test_classical_is_invalid_with_reason(self):
        probe = {
            "result": "group",
            "id": 29,
            "name": "x25519",
            "kind": "classical_ecdh",
            "is_pq": False,
        }
        r = self.v.validate(TLS13, probe, "h", 443)
        assert r["is_valid"] is False
        assert r["is_pq"] is False
        assert r["kem_name"] == "x25519"
        assert "harvest-now-decrypt-later" in r["reason"]

    def test_hello_retry_request_pq_counts_as_capable(self):
        probe = {
            "result": "group",
            "id": 4588,
            "name": "X25519MLKEM768",
            "kind": "hybrid_pq",
            "is_pq": True,
            "via_hello_retry_request": True,
        }
        r = self.v.validate(TLS13, probe, "h", 443)
        assert r["is_valid"] is True
        assert r["via_hello_retry_request"] is True

    def test_tls12_is_na_strict_false(self):
        probe = {
            "result": "n/a",
            "protocol": "TLSv1.2",
            "reason": "TLSv1.2 has no post-quantum key exchange",
        }
        r = self.v.validate(TLS12, probe, "h", 443)
        assert r["is_valid"] is False
        assert r["is_pq"] is False
        assert r["kem_kind"] == "n/a"
        assert "TLSv1.2" in r["reason"]

    def test_probe_error_returns_error_shape(self):
        probe = {
            "result": "error",
            "error": "ConnectError",
            "message": "could not connect to h:443",
        }
        r = self.v.validate(TLS13, probe, "h", 443)
        assert r["is_valid"] is False
        assert r["error"] == "ConnectError"
        assert "could not connect" in r["message"]

    def test_unrecognized_probe_shape_is_invalid(self):
        r = self.v.validate(TLS13, {"result": "weird"}, "h", 443)
        assert r["is_valid"] is False
        assert "Unrecognized" in r["reason"]

    def test_is_valid_is_always_strict_bool(self):
        for probe in [
            {"result": "group", "is_pq": True, "name": "x", "kind": "hybrid_pq"},
            {"result": "group", "is_pq": False, "name": "x", "kind": "classical_ecdh"},
            {"result": "n/a", "protocol": "TLSv1.2"},
            {"result": "error", "error": "E", "message": "m"},
        ]:
            r = self.v.validate(TLS13, probe, "h", 443)
            assert isinstance(r["is_valid"], bool)


class TestPqKeyExchangeDispatch:
    """End-to-end through the dispatcher: the tls_probe source short-circuits
    on TLS < 1.3 (no probe call), and runs the probe on TLS 1.3."""

    def _monitor(self, version):
        m = CertMonitor("example.com")
        m.enabled_validators = ["pq_key_exchange"]
        handler = MagicMock()
        handler.get_protocol_version.return_value = version
        m.handler = handler
        return m

    def test_tls12_skips_probe(self):
        m = self._monitor("TLSv1.2")
        with patch.object(
            m, "get_cipher_info", return_value={"protocol_version": "TLSv1.2"}
        ):
            with patch("certmonitor.core.certinfo.probe_tls_handshake") as probe_fn:
                result = m.validate()
        probe_fn.assert_not_called()  # skip-for-legacy: no second connection
        assert result["pq_key_exchange"]["is_valid"] is False
        assert result["pq_key_exchange"]["kem_kind"] == "n/a"

    def test_tls13_runs_probe_and_reports_pq(self):
        m = self._monitor("TLSv1.3")
        probe = {
            "result": "group",
            "id": 4588,
            "name": "X25519MLKEM768",
            "kind": "hybrid_pq",
            "is_pq": True,
        }
        with patch.object(
            m, "get_cipher_info", return_value={"protocol_version": "TLSv1.3"}
        ):
            with patch(
                "certmonitor.core.certinfo.probe_tls_handshake", return_value=probe
            ) as probe_fn:
                result = m.validate()
        probe_fn.assert_called_once()
        assert result["pq_key_exchange"]["is_valid"] is True
        assert result["pq_key_exchange"]["kem_name"] == "X25519MLKEM768"

    def test_not_in_default_validators(self):
        from certmonitor.config import DEFAULT_VALIDATORS
        from certmonitor.validators import VALIDATORS

        assert "pq_key_exchange" in VALIDATORS
        assert "pq_key_exchange" not in DEFAULT_VALIDATORS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
