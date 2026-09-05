"""Regressions for the dispatcher, connection plumbing, and trust verification."""

import ssl
from unittest.mock import MagicMock, patch

import pytest

from certmonitor import CertMonitor
from certmonitor.protocol_handlers.ssh_handler import SSHHandler
from certmonitor.protocol_handlers.ssl_handler import SSLHandler


class TestArgumentErrorsAreOperational:
    def _monitor(self):
        monitor = CertMonitor("example.com", enabled_validators=["expiration"])
        monitor.cert_data = {
            "cert_info": {
                "notBefore": "Jan  1 00:00:00 2026 GMT",
                "notAfter": "Dec 31 00:00:00 2026 GMT",
            }
        }
        return monitor

    def test_unknown_args_report_status_error(self):
        result = self._monitor().validate({"expiration": {"bogus": 1}})["expiration"]
        assert result["status"] == "error"
        assert result["error"] == "UnknownValidatorArgs"
        assert result["code"] == "expiration.error"

    def test_non_dict_args_report_status_error(self):
        result = self._monitor().validate({"expiration": (1, 2)})["expiration"]
        assert result["status"] == "error"
        assert result["error"] == "InvalidValidatorArgs"

    def test_validator_value_error_is_reported_with_its_class(self):
        result = self._monitor().validate({"expiration": {"warning_days": -1}})[
            "expiration"
        ]
        assert result["status"] == "error"
        assert result["error"] == "ValueError"

    def test_unexpected_validator_exceptions_propagate(self):
        monitor = self._monitor()
        validator = MagicMock()
        validator.name = "expiration"
        validator.validator_type = "cert"
        validator._user_param_names = frozenset()
        validator.validate.side_effect = KeyError("missing")
        with patch.object(monitor, "validators", {"expiration": validator}):
            with pytest.raises(KeyError):
                monitor.validate()


class TestConnectionOverridesReachEveryHandler:
    def test_ssh_handler_uses_connection_host_and_timeout(self, monkeypatch):
        monitor = CertMonitor(
            "bastion.internal", 22, connection_host="10.0.0.5", timeout=2
        )
        monkeypatch.setattr(monitor, "detect_protocol", lambda: "ssh")
        with patch("socket.create_connection") as create_connection:
            assert monitor.connect() is None
        create_connection.assert_called_once_with(("10.0.0.5", 22), timeout=2)
        assert isinstance(monitor.handler, SSHHandler)

    def test_ssh_handler_default_timeout(self):
        handler = SSHHandler("host.test", 22, MagicMock())
        with patch("socket.create_connection") as create_connection:
            handler.connect()
        create_connection.assert_called_once_with(("host.test", 22), timeout=10.0)

    def test_ssl_handler_gives_each_protocol_its_own_timeout(self):
        handler = SSLHandler("host.test", 443, MagicMock())
        handler.timeout = 3
        with (
            patch.object(handler, "get_supported_protocols", return_value=[1, 2]),
            patch("socket.create_connection", side_effect=TimeoutError) as create,
            patch("ssl.SSLContext"),
        ):
            handler.connect()
        assert [call.kwargs["timeout"] for call in create.call_args_list] == [3, 3]

    def test_probe_receives_connection_host_and_sni_separately(self):
        monitor = CertMonitor(
            "service.example.com",
            connection_host="192.0.2.10",
            enabled_validators=["pq_key_exchange"],
            timeout=4,
        )
        monitor.protocol = "ssl"
        handler = MagicMock()
        handler.get_protocol_version.return_value = "TLSv1.3"
        monitor.handler = handler
        probe = {"result": "group", "id": 4588, "name": "X25519MLKEM768", "is_pq": True}
        with (
            patch.object(
                monitor, "get_cipher_info", return_value={"protocol_version": "TLSv1.3"}
            ),
            patch(
                "certmonitor.core.certinfo.probe_tls_handshake", return_value=probe
            ) as probe_fn,
        ):
            result = monitor.validate()["pq_key_exchange"]
        probe_fn.assert_called_once_with(
            "192.0.2.10", 443, 4000, server_name="service.example.com"
        )
        assert result["is_valid"] is True
        assert result["endpoint"] == "192.0.2.10:443"


class TestVerifiedTrust:
    def _monitor(self):
        monitor = CertMonitor("example.com", enabled_validators=["root_certificate"])
        monitor.protocol = "ssl"
        monitor.der = b"collected"
        monitor.cert_data = {"cert_info": {"issuer": {"commonName": "CA"}}}
        return monitor

    def test_strict_handshake_passes_without_warning(self):
        monitor = self._monitor()
        with patch.object(monitor, "_verified_peer", return_value=b"collected") as peer:
            result = monitor._verify_trust()
        assert result["is_valid"] is True
        assert result["warnings"] == []
        peer.assert_called_once_with(False)

    def test_legacy_only_server_gets_a_verdict_with_a_warning(self):
        monitor = self._monitor()

        def handshake(legacy):
            if not legacy:
                raise ssl.SSLError("TLSV1_ALERT_PROTOCOL_VERSION")
            return b"collected"

        with patch.object(monitor, "_verified_peer", side_effect=handshake):
            result = monitor._verify_trust()
        assert result["is_valid"] is True
        assert result["status"] == "pass"
        assert "legacy protocol" in result["warnings"][0]

    def test_cipher_dependent_leaf_selection_converges_on_the_collected_leaf(self):
        monitor = self._monitor()
        with patch.object(
            monitor, "_verified_peer", side_effect=[b"other-leaf", b"collected"]
        ):
            result = monitor._verify_trust()
        assert result["is_valid"] is True

    def test_persistent_mismatch_is_reported(self):
        monitor = self._monitor()
        with patch.object(monitor, "_verified_peer", return_value=b"other-leaf"):
            result = monitor._verify_trust()
        assert result["error"] == "SnapshotMismatch"

    def test_untrusted_chain_fails_immediately(self):
        monitor = self._monitor()
        error = ssl.SSLCertVerificationError("self-signed")
        error.verify_code = 18
        with patch.object(monitor, "_verified_peer", side_effect=error) as peer:
            result = monitor._verify_trust()
        assert result["status"] == "fail"
        assert result["verify_code"] == 18
        peer.assert_called_once()

    def test_unreachable_on_both_settings_is_an_error(self):
        monitor = self._monitor()
        with patch.object(monitor, "_verified_peer", side_effect=OSError("refused")):
            result = monitor._verify_trust()
        assert result["status"] == "error"
        assert result["error"] == "OSError"

    def test_failed_collection_is_not_retried_for_trust(self, monkeypatch):
        monitor = CertMonitor("down.example.com")
        calls = []

        def detect_protocol():
            calls.append(1)
            return {"error": "ConnectionError", "message": "timed out"}

        monkeypatch.setattr(monitor, "detect_protocol", detect_protocol)
        results = monitor.validate()
        assert len(calls) == 1
        assert results["root_certificate"]["status"] == "error"
        assert results["root_certificate"]["error"] == "ConnectionError"
        assert results["root_certificate"]["issuer"] == {}

    def test_verify_context_is_built_once_per_setting(self):
        monitor = self._monitor()
        with patch("ssl.create_default_context") as create:
            create.return_value = MagicMock(spec=ssl.SSLContext)
            monitor._verify_context(False)
            monitor._verify_context(False)
            monitor._verify_context(True)
        assert create.call_count == 2
