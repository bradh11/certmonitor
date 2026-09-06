"""The `revocation` validator against a real CA, CRL, and OCSP responder.

The fixture builds a throwaway CA with the OpenSSL CLI, issues one good and
one revoked certificate whose AIA and CRL pointers name servers in this
process, publishes the CRL and the CA certificate over HTTP, and answers
OCSP requests by handing each one to `openssl ocsp`. The monitors under
test talk to small TLS servers presenting those certificates.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from certmonitor import CertMonitor, certinfo, revocation
from certmonitor.protocol_handlers import http
from certmonitor.protocol_handlers.http import HTTPError
from certmonitor.validators.revocation import RevocationValidator

# --- servers -----------------------------------------------------------------------


def _listener() -> socket.socket:
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock


def _serve_http(listener: socket.socket, handler_class) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), handler_class, bind_and_activate=False)
    server.socket.close()
    server.socket = listener
    server.server_address = listener.getsockname()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class TLSServer:
    """Accepts TLS connections presenting one certificate, each in its own thread."""

    def __init__(self, cert_chain: Path, key: Path):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_chain, key)
        self.listener = _listener()
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.listener.close()
        self.thread.join(3)

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(3)
            secure = self.context.wrap_socket(conn, server_side=True)
            self.stop.wait(3)
            secure.close()
        except (OSError, ssl.SSLError):
            conn.close()


# --- the PKI --------------------------------------------------------------------------


class RevocationPKI:
    """A CA with a good and a revoked leaf, a published CRL, and an OCSP responder."""

    def __init__(
        self,
        directory: Path,
        openssl: str,
        key_type: str = "rsa",
        ca_name: str = "CertMonitor Revocation CA",
    ):
        self.directory = directory
        self.openssl = openssl
        self.key_type = key_type
        self.ca_name = ca_name
        self.signer = "ca"  # which key answers OCSP: "ca" or "responder"
        self.crl_listener = _listener()
        self.ocsp_listener = _listener()
        self.crl_port = self.crl_listener.getsockname()[1]
        self.ocsp_port = self.ocsp_listener.getsockname()[1]
        self.ocsp_requests: list[bytes] = []
        self.crl_requests: list[str] = []
        self._build()
        self._publish()

    def run(self, *args: str) -> bytes:
        done = subprocess.run(
            [self.openssl, *args], cwd=self.directory, check=True, capture_output=True
        )
        return done.stdout

    @property
    def ca_pem(self) -> Path:
        return self.directory / "ca.pem"

    @property
    def crl_url(self) -> str:
        return f"http://127.0.0.1:{self.crl_port}/ca.crl"

    @property
    def ocsp_url(self) -> str:
        return f"http://127.0.0.1:{self.ocsp_port}"

    def newkey(self) -> list[str]:
        if self.key_type == "ec":
            return ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"]
        return ["-newkey", "rsa:2048"]

    def _build(self) -> None:
        directory = self.directory
        (directory / "newcerts").mkdir()
        (directory / "index.txt").write_text("")
        (directory / "serial").write_text("1000\n")
        (directory / "crlnumber").write_text("01\n")
        (directory / "ca.cnf").write_text(
            "[ ca ]\ndefault_ca = local\n"
            "[ local ]\ndir = .\ndatabase = index.txt\nnew_certs_dir = newcerts\n"
            "serial = serial\ncrlnumber = crlnumber\ncertificate = ca.pem\n"
            "private_key = ca.key\ndefault_md = sha256\ndefault_days = 1\n"
            "default_crl_days = 1\npolicy = anything\nunique_subject = no\n"
            "[ anything ]\ncommonName = supplied\n"
            "[ v3_leaf ]\nsubjectAltName = DNS:localhost,IP:127.0.0.1\n"
            "basicConstraints = critical,CA:FALSE\n"
            "keyUsage = critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage = serverAuth\nauthorityKeyIdentifier = keyid,issuer\n"
            "subjectKeyIdentifier = hash\n"
            f"authorityInfoAccess = OCSP;URI:{self.ocsp_url},"
            f"caIssuers;URI:http://127.0.0.1:{self.crl_port}/ca.pem\n"
            f"crlDistributionPoints = URI:{self.crl_url}\n"
            "[ v3_ocsp ]\nbasicConstraints = critical,CA:FALSE\n"
            "keyUsage = critical,digitalSignature\nextendedKeyUsage = OCSPSigning\n"
            "authorityKeyIdentifier = keyid,issuer\nsubjectKeyIdentifier = hash\n"
            "[ req ]\ndistinguished_name = dn\n[ dn ]\n"
        )
        self.run(
            "req", "-x509", *self.newkey(), "-nodes", "-keyout", "ca.key",
            "-out", "ca.pem", "-days", "2", "-subj", f"/CN={self.ca_name}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )  # fmt: skip
        for name, section in (
            ("good", "v3_leaf"),
            ("revoked", "v3_leaf"),
            ("responder", "v3_ocsp"),
        ):
            self.run(
                "req", "-new", *self.newkey(), "-nodes", "-keyout", f"{name}.key",
                "-out", f"{name}.csr", "-subj", f"/CN={name}.test",
            )  # fmt: skip
            self.run(
                "ca", "-config", "ca.cnf", "-batch", "-extensions", section,
                "-in", f"{name}.csr", "-out", f"{name}.pem", "-notext",
            )  # fmt: skip
            bundle = (directory / f"{name}.pem").read_text() + self.ca_pem.read_text()
            (directory / f"{name}-chain.pem").write_text(bundle)
        self.run(
            "ca",
            "-config",
            "ca.cnf",
            "-revoke",
            "revoked.pem",
            "-crl_reason",
            "keyCompromise",
        )
        self.run("ca", "-config", "ca.cnf", "-gencrl", "-out", "ca.crl.pem")
        self.run("crl", "-in", "ca.crl.pem", "-outform", "DER", "-out", "ca.crl")

    def _publish(self) -> None:
        pki = self

        class FileHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                pki.crl_requests.append(self.path)
                path = pki.directory / self.path.lstrip("/")
                if self.path == "/ca.crl":
                    body, kind = path.read_bytes(), "application/pkix-crl"
                elif self.path == "/ca.pem":
                    body, kind = path.read_bytes(), "application/x-pem-file"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return None

        class OCSPHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = self.rfile.read(int(self.headers["Content-Length"]))
                pki.ocsp_requests.append(request)
                with tempfile.TemporaryDirectory() as scratch:
                    request_path = Path(scratch) / "request.der"
                    response_path = Path(scratch) / "response.der"
                    request_path.write_bytes(request)
                    pki.run(
                        "ocsp", "-index", "index.txt", "-CA", "ca.pem",
                        "-rsigner", f"{pki.signer}.pem", "-rkey", f"{pki.signer}.key",
                        "-reqin", str(request_path), "-respout", str(response_path),
                        "-ndays", "1",
                    )  # fmt: skip
                    body = response_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/ocsp-response")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return None

        self.crl_server = _serve_http(self.crl_listener, FileHandler)
        self.ocsp_server = _serve_http(self.ocsp_listener, OCSPHandler)

    def close(self) -> None:
        self.crl_server.shutdown()
        self.ocsp_server.shutdown()


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL CLI required to build the revocation fixtures")
    built = RevocationPKI(tmp_path_factory.mktemp("revocation"), openssl)
    yield built
    built.close()


@pytest.fixture(scope="module")
def ec_pki(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL CLI required to build the revocation fixtures")
    built = RevocationPKI(
        tmp_path_factory.mktemp("revocation-ec"),
        openssl,
        key_type="ec",
        ca_name="CertMonitor EC Revocation CA",
    )
    yield built
    built.close()


@pytest.fixture(autouse=True)
def fresh_caches():
    revocation.CRL_CACHE.clear()
    revocation.OCSP_CACHE.clear()
    yield
    revocation.CRL_CACHE.clear()
    revocation.OCSP_CACHE.clear()


def monitor_for(pki, name, *, chain=False, **kwargs):
    cert = pki.directory / (f"{name}-chain.pem" if chain else f"{name}.pem")
    return TLSServer(cert, pki.directory / f"{name}.key"), dict(
        cafile=str(pki.ca_pem),
        timeout=5,
        enabled_validators=["revocation"],
        **kwargs,
    )


# --- request building ------------------------------------------------------------------


def test_ocsp_request_matches_openssl_byte_for_byte(pki):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    ours, expected = revocation.build_ocsp_request(leaf, issuer)
    theirs = pki.run(
        "ocsp", "-issuer", "ca.pem", "-cert", "good.pem", "-no_nonce", "-reqout", "-"
    )
    assert ours == theirs
    assert len(expected["issuer_key_hash"]) == 40


def test_ocsp_request_rejects_the_wrong_issuer(pki):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    with pytest.raises(ValueError, match="does not match"):
        revocation.build_ocsp_request(leaf, leaf)
    assert revocation.find_issuer(leaf, [leaf, b"not a certificate"]) is None


# --- verdicts over live connections -------------------------------------------------


def test_good_certificate_via_crl_is_a_verified_pass(pki):
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["crl"]}})["revocation"]
    assert result["status"] == "pass", result
    assert result["revocation_status"] == "good"
    assert result["source"] == "crl"
    assert result["signature_verified"] is True
    assert result["methods"]["crl"]["revoked_count"] == 1
    assert result["next_update"]
    assert "ocsp" not in result["methods"]


def test_revoked_certificate_via_crl_fails_with_the_entry(pki):
    server, options = monitor_for(pki, "revoked")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["crl"]}})["revocation"]
    assert result["status"] == "fail", result
    assert result["revocation_status"] == "revoked"
    assert result["revocation_reason"] == "key_compromise"
    assert result["revocation_time"]
    assert "revoked" in result["reason"] and "CRL" in result["reason"]
    assert result["methods"]["crl"]["verify_code"] == 23


def test_ocsp_good_signed_by_the_ca_is_a_verified_pass(pki):
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
    assert result["status"] == "pass", result
    assert result["revocation_status"] == "good"
    assert result["source"] == "ocsp"
    assert result["signature_verified"] is True
    assert "verification_error" not in result["methods"]["ocsp"]
    assert result["methods"]["ocsp"]["responder_name"]["commonName"].endswith("CA")
    assert pki.ocsp_requests


def test_ocsp_signed_by_a_delegated_responder_is_verified(pki):
    server, options = monitor_for(pki, "good")
    pki.signer = "responder"
    try:
        with server, CertMonitor("localhost", server.port, **options) as monitor:
            result = monitor.validate({"revocation": {"methods": ["ocsp"]}})[
                "revocation"
            ]
    finally:
        pki.signer = "ca"
    assert result["status"] == "pass", result
    assert result["signature_verified"] is True
    assert result["methods"]["ocsp"]["responder_name"]["commonName"] == "responder.test"


def test_ocsp_signed_by_an_ecdsa_ca_is_verified(ec_pki):
    server, options = monitor_for(ec_pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate()["revocation"]
    assert result["status"] == "pass", result
    assert result["source"] == "ocsp"
    assert result["signature_verified"] is True
    assert result["methods"]["ocsp"]["responder_key_hash"] is None
    revoked_server, options = monitor_for(ec_pki, "revoked")
    with (
        revoked_server,
        CertMonitor("localhost", revoked_server.port, **options) as monitor,
    ):
        result = monitor.validate({"revocation": {"methods": ["crl"]}})["revocation"]
    assert (
        result["status"] == "fail" and result["revocation_reason"] == "key_compromise"
    )


def _flipping_fetch(pki, real_fetch):
    def flip_a_signature_byte(url, **kwargs):
        body = real_fetch(url, **kwargs)
        if url != pki.ocsp_url:
            return body
        body = bytearray(body)
        signature = certinfo.parse_ocsp_response(bytes(body))["signature"]
        body[body.find(signature)] ^= 0x01
        return bytes(body)

    return flip_a_signature_byte


def test_tampered_ocsp_response_is_unusable_evidence(pki, monkeypatch):
    monkeypatch.setattr(http, "fetch", _flipping_fetch(pki, http.fetch))
    server, options = monitor_for(pki, "good", chain=True)
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        # OCSP alone: a wrong signature is an error, never a warning or a pass,
        # and accept_unverified does not rescue it.
        alone = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
        accepted = monitor.validate(
            {"revocation": {"methods": ["ocsp"], "accept_unverified": True}}
        )["revocation"]
        # With the CRL available, the verified CRL answer decides.
        both = monitor.validate()["revocation"]
    for result in (alone, accepted):
        assert result["status"] == "error", result
        assert result["is_valid"] is False
        assert result["error"] == "OCSPInvalidSignature"
        assert "signature does not verify" in result["reason"]
        assert result["methods"]["ocsp"]["verification"] == "failed"
        assert result["methods"]["ocsp"]["signature_verified"] is False
    assert both["status"] == "pass", both
    assert both["source"] == "crl"
    assert both["methods"]["ocsp"]["verification"] == "failed"


def test_ocsp_good_passes_when_unverified_answers_are_accepted(pki, monkeypatch):
    # An algorithm CertMonitor cannot check leaves the answer unverified but not
    # disproven; accept_unverified takes the responder's word for that case.
    monkeypatch.setattr(certinfo, "signature_hash", MagicMock(return_value=None))
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate(
            {"revocation": {"methods": ["ocsp"], "accept_unverified": True}}
        )["revocation"]
        warned = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
    assert result["status"] == "pass"
    assert result["source"] == "ocsp"
    assert result["signature_verified"] is False
    assert result["methods"]["ocsp"]["verification"] == "unsupported"
    assert warned["status"] == "warn"
    assert "unsupported signature algorithm" in warned["warnings"][0]


def test_default_order_stops_at_a_verified_ocsp_answer(pki):
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate()["revocation"]
    assert result["status"] == "pass", result
    assert result["source"] == "ocsp"
    assert "crl" not in result["methods"]


def test_unverifiable_ocsp_falls_through_to_the_verified_crl(pki, monkeypatch):
    # An algorithm CertMonitor cannot verify leaves OCSP unproven; the CRL settles it.
    monkeypatch.setattr(certinfo, "signature_hash", MagicMock(return_value=None))
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate()["revocation"]
    assert result["status"] == "pass", result
    assert result["source"] == "crl"
    assert result["methods"]["ocsp"]["status"] == "good"
    assert (
        "unsupported signature algorithm"
        in result["methods"]["ocsp"]["verification_error"]
    )


def test_verified_revoked_via_ocsp_fails(pki):
    server, options = monitor_for(pki, "revoked")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
    assert result["status"] == "fail"
    assert result["source"] == "ocsp"
    assert result["signature_verified"] is True
    assert result["revocation_reason"] == "key_compromise"
    assert "OCSP" in result["reason"]


def test_forged_revoked_is_discarded_not_acted_on(pki, monkeypatch):
    # A tampered "revoked" must not fail the check nor bypass the CRL.
    monkeypatch.setattr(http, "fetch", _flipping_fetch(pki, http.fetch))
    server, options = monitor_for(pki, "revoked", chain=True)
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        alone = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
        accepted = monitor.validate(
            {"revocation": {"methods": ["ocsp"], "accept_unverified": True}}
        )["revocation"]
        both = monitor.validate()["revocation"]
    for result in (alone, accepted):
        assert result["status"] == "error", result
        assert result["error"] == "OCSPInvalidSignature"
        assert result["revocation_status"] == "unknown"
        assert result["methods"]["ocsp"]["status"] == "revoked"
        assert result["methods"]["ocsp"]["verification"] == "failed"
    # The verified CRL still knows the truth.
    assert both["status"] == "fail" and both["source"] == "crl"
    assert both["revocation_reason"] == "key_compromise"


def test_unverifiable_revoked_is_an_error_unless_accepted(pki, monkeypatch):
    monkeypatch.setattr(certinfo, "signature_hash", MagicMock(return_value=None))
    server, options = monitor_for(pki, "revoked")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        held = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
        accepted = monitor.validate(
            {"revocation": {"methods": ["ocsp"], "accept_unverified": True}}
        )["revocation"]
        with_crl = monitor.validate()["revocation"]
    assert held["status"] == "error", held
    assert held["error"] == "OCSPUnverifiedRevocation"
    assert "could not be verified" in held["reason"]
    assert held["methods"]["ocsp"]["verification"] == "unsupported"
    assert accepted["status"] == "fail" and accepted["source"] == "ocsp"
    assert accepted["signature_verified"] is False
    assert with_crl["status"] == "fail" and with_crl["source"] == "crl"


def test_issuer_comes_from_the_served_chain_when_present(pki):
    server, options = monitor_for(pki, "good", chain=True)
    before = list(pki.crl_requests)
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
    assert result["revocation_status"] == "good"
    assert "/ca.pem" not in pki.crl_requests[len(before) :]


def test_answers_are_cached_across_monitors(pki):
    server, options = monitor_for(pki, "good")
    both = {"revocation": {"methods": ["crl", "ocsp"]}}
    with server:
        with CertMonitor("localhost", server.port, **options) as monitor:
            first = monitor.validate(both)["revocation"]
            # A verified CRL answer settles it, so OCSP is asked separately.
            first_ocsp = monitor.validate({"revocation": {"methods": ["ocsp"]}})
        with CertMonitor("localhost", server.port, **options) as monitor:
            second = monitor.validate(both)["revocation"]
            second_ocsp = monitor.validate({"revocation": {"methods": ["ocsp"]}})
    assert first["methods"]["crl"]["cached"] is False
    assert second["methods"]["crl"]["cached"] is True
    assert first_ocsp["revocation"]["methods"]["ocsp"]["cached"] is False
    assert second_ocsp["revocation"]["methods"]["ocsp"]["cached"] is True


def test_certificate_without_pointers_is_unsupported(local_pki):
    server = TLSServer(local_pki / "one.pem", local_pki / "one.key")
    with (
        server,
        CertMonitor(
            "localhost",
            server.port,
            cafile=str(local_pki / "ca.pem"),
            timeout=3,
            enabled_validators=["revocation"],
        ) as monitor,
    ):
        result = monitor.validate()["revocation"]
    assert result["status"] == "unsupported"
    assert "no OCSP responder URL" in result["reason"]
    assert "no CRL distribution point" in result["reason"]


def test_unreachable_sources_are_an_error_not_a_pass(pki, monkeypatch):
    server, options = monitor_for(pki, "good")
    monkeypatch.setattr(http, "fetch", MagicMock(side_effect=OSError("network down")))
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate()["revocation"]
    assert result["status"] == "error"
    assert result["error"] == "RevocationUnavailable"
    assert "network down" in result["reason"]
    assert result["is_valid"] is False


def test_unknown_method_is_an_argument_error(pki):
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["dns"]}})["revocation"]
    assert result["status"] == "error"
    assert "unknown revocation method" in result["reason"]


def test_crl_check_reports_openssl_problems_and_mismatches(pki, monkeypatch):
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        monitor.validate({"revocation": {"methods": ["crl"]}})
        # A CRL from an unrelated CA cannot be checked against this chain.
        not_a_crl = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
        verdict = monitor._check_crl(not_a_crl)  # OpenSSL refuses to load it
        assert verdict["status"] == "error"
        # A different leaf behind the same port is a snapshot mismatch.
        monkeypatch.setattr(monitor, "der", b"someone else")
        verdict = monitor._check_crl((pki.directory / "ca.crl").read_bytes())
        assert verdict["error"] == "SnapshotMismatch"


def test_crl_check_reports_connection_failures(pki):
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        monitor.validate({"revocation": {"methods": ["crl"]}})
        monitor.port = 9  # nothing listens here
        verdict = monitor._check_crl((pki.directory / "ca.crl").read_bytes())
    assert verdict["status"] == "error"
    assert verdict["error"] in ("ConnectionRefusedError", "OSError")


# --- evidence details ------------------------------------------------------------


def test_ocsp_answer_is_matched_to_the_question(pki, monkeypatch):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    other = ssl.PEM_cert_to_DER_cert((pki.directory / "revoked.pem").read_text())
    other_request, _ = revocation.build_ocsp_request(other, issuer)
    # Ask about `good` but answer about `revoked`.
    real_fetch = http.fetch

    def swap_request(url, **kwargs):
        return real_fetch(url, **{**kwargs, "body": other_request})

    monkeypatch.setattr(http, "fetch", swap_request)
    answer = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5)
    assert answer["status"] == "error"
    assert answer["error"] == "OCSPMismatch"


def test_ocsp_error_statuses_and_staleness(pki, monkeypatch):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    try_later = bytes.fromhex("30030a0103")
    monkeypatch.setattr(http, "fetch", MagicMock(return_value=try_later))
    answer = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5)
    assert answer["error"] == "OCSPResponderError" and "try_later" in answer["reason"]

    monkeypatch.setattr(http, "fetch", MagicMock(return_value=b"garbage"))
    answer = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5)
    assert answer["status"] == "error" and answer["error"] == "ValueError"

    monkeypatch.undo()
    far_future = 4_102_444_800  # 2100-01-01
    answer = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, now=far_future
    )
    assert answer["error"] == "OCSPStale"
    long_ago = 946_684_800  # 2000-01-01
    answer = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5, now=long_ago)
    assert answer["error"] == "OCSPNotYetValid"


def test_issuer_fetch_failures_are_reported(pki, monkeypatch):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    info = {
        "OCSP": [pki.ocsp_url],
        "caIssuers": ["http://127.0.0.1:9/ca.pem"],
        "serialNumber": "1000",
    }
    evidence = revocation.RevocationEvidence(
        leaf_der=leaf, chain_der=[leaf], cert_info=info, timeout=1
    )
    answer = evidence.ocsp()
    assert answer["error"] == "MissingIssuer"
    assert "could not fetch the issuer certificate" in answer["reason"]

    evidence = revocation.RevocationEvidence(
        leaf_der=leaf, chain_der=[leaf], cert_info={"OCSP": [pki.ocsp_url]}, timeout=1
    )
    assert "no AIA pointer" in evidence.ocsp()["reason"]

    pem_issuer = pki.ca_pem.read_bytes()
    monkeypatch.setattr(http, "fetch", MagicMock(return_value=pem_issuer))
    evidence = revocation.RevocationEvidence(
        leaf_der=leaf,
        chain_der=[leaf],
        cert_info={"caIssuers": ["http://issuer.test/ca.pem"]},
        timeout=1,
    )
    assert evidence.issuer() == ssl.PEM_cert_to_DER_cert(pem_issuer.decode())
    assert evidence.issuer() is evidence.issuer()


def test_pem_crls_are_accepted(pki, monkeypatch):
    pem = (pki.directory / "ca.crl.pem").read_bytes()
    monkeypatch.setattr(http, "fetch", MagicMock(return_value=pem))
    der, info, cached = revocation.fetch_crl("http://crl.test/ca.crl", timeout=1)
    assert der == (pki.directory / "ca.crl").read_bytes()
    assert info["revoked_count"] == 1 and cached is False
    assert revocation.fetch_crl("http://crl.test/ca.crl", timeout=1)[2] is True


def test_crl_lookup_and_info_through_the_parser(pki):
    der = (pki.directory / "ca.crl").read_bytes()
    info = certinfo.crl_info(der)
    assert info["issuer"]["commonName"] == "CertMonitor Revocation CA"
    assert info["next_update"] > info["this_update"]
    revoked = ssl.PEM_cert_to_DER_cert((pki.directory / "revoked.pem").read_text())
    serial = certinfo.ocsp_cert_id_inputs(
        revoked, ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    )["serial_number"]
    entry = certinfo.crl_lookup(der, serial)
    assert entry["revocation_reason"] == "key_compromise"
    assert certinfo.crl_lookup(der, b"\x7f") is None
    with pytest.raises(ValueError):
        certinfo.crl_info(b"\x30\x00")


# --- pure helpers ---------------------------------------------------------------


def test_helpers():
    assert revocation.serial_bytes("abc") == b"\x0a\xbc"
    assert revocation.serial_bytes("0A:BC") == b"\x0a\xbc"
    assert revocation.format_time(None) is None
    assert revocation.format_time(0) == "1970-01-01T00:00:00+00:00"
    assert revocation.http_urls(["ldap://x", "http://a", "HTTPS://b", None]) == [
        "http://a",
        "HTTPS://b",
    ]
    assert revocation.http_urls(None) == []
    now = 1_000_000.0
    assert revocation._expiry_for(None, now) == now + 3600
    assert revocation._expiry_for(int(now) + 10, now) == now + 10
    assert revocation._expiry_for(int(now) + 10**7, now) == now + 86400
    assert revocation._still_current(None, now)
    assert revocation._still_current(int(now) + 1, now)
    assert not revocation._still_current(int(now), now)


def test_cache_expires_and_evicts_the_oldest():
    cache = revocation._Cache(limit=2)
    cache.put("a", 1, expires_at=10)
    cache.put("b", 2, expires_at=20)
    assert cache.get("a", now=5) == 1
    cache.put("c", 3, expires_at=30)  # full: evicts a, the entry expiring first
    assert cache.get("a", now=5) is None
    assert cache.get("b", now=5) == 2
    assert cache.get("c", now=5) == 3
    assert cache.get("b", now=20) is None  # expired on read


def test_validator_rejects_a_non_answering_source():
    evidence = MagicMock()
    evidence.answer.side_effect = [
        {"method": "ocsp", "status": "unknown"},
        {"method": "crl", "status": "error", "reason": "boom"},
    ]
    result = RevocationValidator().validate(evidence, "h", 443)
    assert result["status"] == "error"
    assert "ocsp: unknown" in result["reason"] and "crl: boom" in result["reason"]


# --- the HTTP client --------------------------------------------------------------


class _Raw:
    """A one-shot HTTP server that replies with fixed bytes."""

    def __init__(self, reply: bytes, then: bytes = b""):
        self.reply = reply
        self.then = then
        self.listener = _listener()
        self.port = self.listener.getsockname()[1]
        self.received = b""
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        conn, _ = self.listener.accept()
        conn.settimeout(3)
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(4096)
        self.received = data
        conn.sendall(self.reply)
        if self.then:
            time.sleep(0.2)
            conn.sendall(self.then)
        conn.close()
        self.listener.close()


def test_http_client_reads_chunked_bodies_and_sends_headers():
    server = _Raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"
    )
    body = http.fetch(f"http://127.0.0.1:{server.port}/x?y=1", timeout=3, accept="a/b")
    assert body == b"hello world"
    assert server.received.startswith(b"GET /x?y=1 HTTP/1.1\r\n")
    assert b"Accept: a/b\r\n" in server.received
    assert f"Host: 127.0.0.1:{server.port}\r\n".encode() in server.received


def test_http_client_reads_until_close_and_follows_redirects():
    target = _Raw(b"HTTP/1.1 200 OK\r\n\r\nplain body")
    hop = _Raw(
        f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target.port}/there\r\n\r\n".encode()
    )
    body = http.fetch(
        f"http://127.0.0.1:{hop.port}/",
        timeout=3,
        method="POST",
        body=b"q",
        content_type="t/x",
    )
    assert body == b"plain body"
    assert (
        b"Content-Type: t/x\r\n" in hop.received
        and b"Content-Length: 1\r\n" in hop.received
    )
    assert target.received.startswith(b"GET /there ")


@pytest.mark.parametrize(
    "reply,fragment",
    [
        (b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", "HTTP 404"),
        (b"nonsense\r\n\r\n", "malformed status line"),
        (b"", "before sending headers"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", "mid-body"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n", "exceeds"),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            "malformed chunk",
        ),
        (b"HTTP/1.1 302 Found\r\nLocation: /loop\r\n\r\n", "too many redirects"),
    ],
)
def test_http_client_reports_bad_replies(reply, fragment):
    server = _Raw(reply)
    if b"/loop" in reply:
        # Every hop answers with another redirect to itself.
        servers = [server] + [_Raw(reply) for _ in range(3)]
        for a, b in zip(servers, servers[1:]):
            a.reply = reply.replace(
                b"/loop", f"http://127.0.0.1:{b.port}/loop".encode()
            )
    with pytest.raises(HTTPError, match=fragment):
        http.fetch(f"http://127.0.0.1:{server.port}/", timeout=3, max_bytes=1000)


def test_http_client_limits_bodies_and_headers():
    big = _Raw(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 5000)
    with pytest.raises(HTTPError, match="exceeds"):
        http.fetch(f"http://127.0.0.1:{big.port}/", timeout=3, max_bytes=1000)
    long_headers = _Raw(b"HTTP/1.1 200 OK\r\nX: " + b"y" * 70000 + b"\r\n\r\n")
    with pytest.raises(HTTPError, match="headers too long"):
        http.fetch(f"http://127.0.0.1:{long_headers.port}/", timeout=3)
    chunk_big = _Raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + b"7d0\r\n"
        + b"x" * 2000
        + b"\r\n0\r\n\r\n"
    )
    with pytest.raises(HTTPError, match="exceeds"):
        http.fetch(f"http://127.0.0.1:{chunk_big.port}/", timeout=3, max_bytes=1000)


def test_http_client_rejects_other_schemes():
    with pytest.raises(ValueError, match="only http and https"):
        http.fetch("ldap://directory.test/", timeout=1)


def test_http_client_speaks_https(local_pki):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(local_pki / "one.pem", local_pki / "one.key")
    listener = _listener()
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        secure = context.wrap_socket(conn, server_side=True)
        data = b""
        while b"\r\n\r\n" not in data:
            data += secure.recv(4096)
        secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure")
        secure.close()

    threading.Thread(target=serve, daemon=True).start()
    trust = ssl.create_default_context(cafile=str(local_pki / "ca.pem"))
    body = http.fetch(f"https://localhost:{port}/", timeout=3, tls_context=trust)
    assert body == b"secure"


# --- remaining branches -----------------------------------------------------------


def test_revocation_source_needs_a_collected_certificate():
    with CertMonitor(
        "127.0.0.1", 9, timeout=0.5, enabled_validators=["revocation"]
    ) as monitor:
        result = monitor.validate()["revocation"]
    assert result["status"] == "error"
    assert "could not be performed" in result["reason"]


def test_crl_check_with_a_client_certificate_and_a_foreign_trust_store(pki, local_pki):
    server, options = monitor_for(
        pki,
        "good",
        client_cert=str(pki.directory / "good.pem"),
        client_key=str(pki.directory / "good.key"),
    )
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["crl"]}})["revocation"]
        assert result["status"] == "pass"
        # Trusting a different CA makes OpenSSL reject the chain before the
        # CRL is consulted; that is a verification failure, not a revocation.
        monitor.cafile = str(local_pki / "ca.pem")
        verdict = monitor._check_crl((pki.directory / "ca.crl").read_bytes())
    assert verdict["status"] == "error"
    assert verdict["error"] == "CRLVerificationFailed"
    assert verdict["verify_code"] != 23


def test_evidence_remembers_answers_and_needs_a_crl_checker(pki):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    evidence = revocation.RevocationEvidence(
        leaf_der=leaf,
        chain_der=[leaf],
        cert_info={"OCSP": [], "crlDistributionPoints": [pki.crl_url]},
        timeout=1,
    )
    first = evidence.answer("ocsp")
    assert first["status"] == "unsupported"
    assert evidence.ocsp() is first
    crl = evidence.crl()
    assert crl["status"] == "unsupported"
    assert "live connection" in crl["reason"]
    assert evidence.crl() is crl


def test_der_long_form_lengths():
    encoded = revocation._der(0x04, b"x" * 200)
    assert encoded[:3] == b"\x04\x81\xc8"
    assert len(encoded) == 203


def test_http_client_waits_for_a_split_chunk_size_line():
    server = _Raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        then=b"3\r\nabc\r\n0\r\n\r\n",
    )
    assert http.fetch(f"http://127.0.0.1:{server.port}/", timeout=3) == b"abc"


def test_http_client_stops_filling_an_oversized_chunk():
    server = _Raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n" + b"x" * 5000
    )
    with pytest.raises(HTTPError, match="exceeds"):
        http.fetch(f"http://127.0.0.1:{server.port}/", timeout=3, max_bytes=1000)


# --- OCSP response verification ----------------------------------------------------


def _parsed_ocsp(pki, signer="ca"):
    pki.signer = signer
    try:
        leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
        issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
        request, expected = revocation.build_ocsp_request(leaf, issuer)
        body = http.fetch(
            pki.ocsp_url,
            timeout=5,
            method="POST",
            body=request,
            content_type="application/ocsp-request",
        )
    finally:
        pki.signer = "ca"
    return certinfo.parse_ocsp_response(body), issuer, expected["issuer_key_hash"]


def test_verify_ocsp_response_rejects_unauthorized_responders(pki):
    parsed, issuer, key_hash = _parsed_ocsp(pki, signer="responder")
    now = time.time()
    assert revocation.verify_ocsp_response(parsed, issuer, key_hash, now) == (
        "verified",
        None,
    )

    stripped = {**parsed, "certs": []}
    outcome, why = revocation.verify_ocsp_response(stripped, issuer, key_hash, now)
    assert (
        outcome == "failed"
        and "not signed by the issuer or an authorized responder" in why
    )

    # Unparseable and unrelated certificates are skipped; a plain leaf that does
    # name the responder is refused for lacking the OCSP signing purpose.
    leaf_der = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    other_der = ssl.PEM_cert_to_DER_cert((pki.directory / "revoked.pem").read_text())
    leaf_name = certinfo.certificate_signature_parts(leaf_der)["subject_der"]
    impostor = {
        **parsed,
        "certs": [b"junk", other_der, leaf_der],
        "responder_name_der": leaf_name,
    }
    outcome, why = revocation.verify_ocsp_response(impostor, issuer, key_hash, now)
    assert outcome == "failed" and "extended key usage" in why

    expired = revocation.verify_ocsp_response(
        parsed, issuer, key_hash, now + 10 * 86400
    )
    assert expired == ("failed", "responder certificate is not currently valid")

    unsigned = {**parsed, "signature": b""}
    assert revocation.verify_ocsp_response(unsigned, issuer, key_hash, now)[1] == (
        "response carries no signature"
    )


def test_verify_ocsp_response_rejects_a_responder_from_another_ca(pki, ec_pki):
    parsed, issuer, key_hash = _parsed_ocsp(pki, signer="responder")
    foreign = ssl.PEM_cert_to_DER_cert((ec_pki.directory / "responder.pem").read_text())
    foreign_name = certinfo.certificate_signature_parts(foreign)["subject_der"]
    swapped = {**parsed, "certs": [foreign], "responder_name_der": foreign_name}
    outcome, why = revocation.verify_ocsp_response(
        swapped, issuer, key_hash, time.time()
    )
    assert outcome == "failed" and "not issued by the certificate's CA" in why

    # A responder certificate whose own signature is broken is refused.
    responder = ssl.PEM_cert_to_DER_cert((pki.directory / "responder.pem").read_text())
    broken = bytearray(responder)
    broken[-1] ^= 0x01
    outcome, why = revocation.verify_ocsp_response(
        {**parsed, "certs": [bytes(broken)]}, issuer, key_hash, time.time()
    )
    assert outcome == "failed" and why.startswith("responder certificate:")


def test_signature_primitives_surface_errors(pki):
    assert certinfo.signature_hash("1.2.840.113549.1.1.11") == "sha256"
    assert certinfo.signature_hash("1.3.101.112") is None
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    spki = certinfo.certificate_signature_parts(issuer)["spki"]
    with pytest.raises(ValueError, match="digest length"):
        certinfo.verify_signature("1.2.840.113549.1.1.11", b"short", b"sig", spki)
    outcome, why = revocation._signed_by(spki, "1.2.840.113549.1.1.11", b"tbs", b"sig")
    assert outcome == "failed" and why == "signature does not verify"
    outcome, why = revocation._signed_by(spki, "1.3.101.112", b"tbs", b"sig")
    assert outcome == "unsupported" and "unsupported signature algorithm" in why
    ec_spki = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    ec_spki = certinfo.certificate_signature_parts(ec_spki)["spki"]
    outcome, why = revocation._signed_by(ec_spki, "1.2.840.10045.4.3.2", b"tbs", b"sig")
    assert outcome == "unsupported" and "does not match the key type" in why
    outcome, why = revocation._signed_by(
        b"\x30\x00", "1.2.840.113549.1.1.11", b"tbs", b"sig"
    )
    assert outcome == "failed" and "SubjectPublicKeyInfo" in why


def test_cached_answers_never_outlive_next_update(pki):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    now = time.time()
    first = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5, now=now)
    assert first["cached"] is False and first["status"] == "good"
    assert revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5, now=now + 1)[
        "cached"
    ]

    # An entry whose own nextUpdate has passed must not be served, even if
    # something left it in the cache with time to spare.
    _, expected = revocation.build_ocsp_request(leaf, issuer)
    key = (pki.ocsp_url, expected["issuer_key_hash"], expected["serial_number"])
    stale = {**first, "_next_update": int(now) - 1}
    revocation.OCSP_CACHE.put(key, stale, expires_at=now + 3600)
    refreshed = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5, now=now)
    assert refreshed["cached"] is False

    # A CRL past its nextUpdate is fetched again rather than reused.
    der, info, cached = revocation.fetch_crl(pki.crl_url, timeout=5, now=now)
    assert cached is False
    assert revocation.fetch_crl(pki.crl_url, timeout=5, now=now + 1)[2] is True
    revocation.CRL_CACHE.put(
        pki.crl_url, (der, {**info, "next_update": int(now) - 1}), expires_at=now + 3600
    )
    assert revocation.fetch_crl(pki.crl_url, timeout=5, now=now)[2] is False


def test_unknown_validator_names_are_errors(pki):
    server, options = monitor_for(pki, "good")
    options["enabled_validators"] = ["hostname", "expiraton"]
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        results = monitor.validate()
    assert results["expiraton"]["status"] == "error"
    assert results["expiraton"]["error"] == "UnknownValidator"
    assert results["hostname"]["status"] == "pass"
