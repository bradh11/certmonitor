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

    def publish_crl(self, name: str, crl_ext_lines: str) -> str:
        """Publish a CRL carrying the extensions `crl_ext_lines` describes, served at `/{name}.crl`.

        `crl_ext_lines` is the body of an OpenSSL extension section, and may
        define further sections it refers to.
        """
        target = self.directory / f"{name}.crl"
        if not target.exists():
            (self.directory / f"{name}.cnf").write_text(
                (self.directory / "ca.cnf").read_text()
                + "[ extra_crl ]\n"
                + crl_ext_lines
            )
            self.run(
                "ca", "-config", f"{name}.cnf", "-gencrl", "-crlexts", "extra_crl",
                "-out", f"{name}.crl.pem",
            )  # fmt: skip
            self.run(
                "crl",
                "-in",
                f"{name}.crl.pem",
                "-outform",
                "DER",
                "-out",
                f"{name}.crl",
            )
        return f"http://127.0.0.1:{self.crl_port}/{name}.crl"

    def publish_crl_with_idp(self, name: str, idp_lines: str) -> str:
        """Publish a CRL whose issuing distribution point is `idp_lines`."""
        return self.publish_crl(
            name,
            "issuingDistributionPoint = critical, @idp\n[ idp ]\n" + idp_lines,
        )

    def publish_partitioned_crl(self) -> str:
        return self.publish_crl_with_idp(
            "partitioned", "onlysomereasons = keyCompromise\n"
        )

    def publish_crl_with_unknown_critical_extension(self) -> str:
        """A CRL carrying critical extension 1.2.3.4, which nothing can process."""
        return self.publish_crl("weird", "1.2.3.4 = critical, ASN1:NULL\n")

    def _publish(self) -> None:
        pki = self

        class FileHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                pki.crl_requests.append(self.path)
                route = self.path.split("?", 1)[0]
                name = route[1:] if route.startswith("/") else None
                path = pki.directory / name if name else None
                is_bare_name = bool(name) and "/" not in name and name != ".."
                if route.endswith(".crl") and is_bare_name and path.is_file():
                    body, kind = path.read_bytes(), "application/pkix-crl"
                elif route == "/ca.pem":
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
    assert revocation.find_issuer(leaf, [leaf, b"not a certificate"])[0] is None


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
    assert result["methods"]["crl"]["verification"] == "verified"


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


def test_failed_verification_is_not_cached(pki, monkeypatch):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    real_fetch = http.fetch
    monkeypatch.setattr(http, "fetch", _flipping_fetch(pki, real_fetch))
    bad = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5)
    assert bad["verification"] == "failed"
    monkeypatch.setattr(http, "fetch", real_fetch)
    good = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, issuer_binding=revocation.VERIFIED
    )
    assert good["verification"] == "verified" and good["cached"] is False
    again = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, issuer_binding=revocation.VERIFIED
    )
    assert again["cached"] is True


def test_cached_ocsp_answer_is_capped_by_the_current_leafs_binding(pki):
    # The cache holds what the responder proved about the serial; how well
    # the leaf being checked is tied to the issuer is this call's business,
    # so a cache hit under a weaker binding must not inherit the earlier
    # caller's `verified`.
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    proven = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, issuer_binding=revocation.VERIFIED
    )
    assert proven["verification"] == "verified" and proven["cached"] is False
    weaker = revocation.check_ocsp(
        leaf,
        issuer,
        pki.ocsp_url,
        timeout=5,
        issuer_binding=revocation.UNSUPPORTED,
        binding_problem="unsupported leaf signature algorithm",
    )
    assert weaker["cached"] is True
    assert weaker["status"] == "good"
    assert weaker["verification"] == "unsupported"
    assert weaker["signature_verified"] is False
    assert "only name-matched" in weaker["verification_error"]
    assert "unsupported leaf signature algorithm" in weaker["verification_error"]
    # The evidence itself is still good for a leaf that is properly bound.
    again = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, issuer_binding=revocation.VERIFIED
    )
    assert again["cached"] is True and again["verification"] == "verified"
    assert "verification_error" not in again


def test_ocsp_evidence_is_cached_even_when_this_leafs_binding_is_weak(pki):
    # A weak binding caps the answer, but the responder's signature checked,
    # and that is what the cache keeps.
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    first = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5)
    assert first["verification"] == "unsupported" and first["cached"] is False
    second = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, issuer_binding=revocation.VERIFIED
    )
    assert second["cached"] is True and second["verification"] == "verified"


def test_cached_ocsp_evidence_expires_with_the_responder_certificate(pki, monkeypatch):
    # A delegated responder's signature is evidence only while its
    # certificate is valid (RFC 6960 section 4.2.2.2). A fresh fetch checks
    # that; the cache must not keep the answer past it.
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    responder = ssl.PEM_cert_to_DER_cert((pki.directory / "responder.pem").read_text())
    real_parts = certinfo.certificate_signature_parts
    now = time.time()

    def responder_valid_for_ten_more_minutes(der):
        found = real_parts(der)
        if der == responder:
            found["not_after"] = int(now) + 600
        return found

    monkeypatch.setattr(
        certinfo, "certificate_signature_parts", responder_valid_for_ten_more_minutes
    )

    def ask(at):
        return revocation.check_ocsp(
            leaf,
            issuer,
            pki.ocsp_url,
            timeout=5,
            now=at,
            issuer_binding=revocation.VERIFIED,
        )

    pki.signer = "responder"
    try:
        first = ask(now)
        assert first["verification"] == "verified" and first["cached"] is False
        assert first["responder_name"]["commonName"] == "responder.test"
        assert ask(now + 599)["cached"] is True
        later = ask(now + 601)
    finally:
        pki.signer = "ca"
    assert later["cached"] is False
    assert later["verification"] == "failed"
    assert "not currently valid" in later["verification_error"]


def test_cached_ocsp_answer_is_not_served_past_ten_days(pki, monkeypatch):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    real_parse = certinfo.parse_ocsp_response

    def with_far_next_update(body):
        parsed = real_parse(body)
        for single in parsed["responses"]:
            single["next_update"] = single["this_update"] + 30 * 86400
        return parsed

    monkeypatch.setattr(certinfo, "parse_ocsp_response", with_far_next_update)
    produced = time.time()
    almost = produced + 10 * 86400 - 3600
    warm = revocation.check_ocsp(
        leaf,
        issuer,
        pki.ocsp_url,
        timeout=5,
        now=almost,
        issuer_binding=revocation.VERIFIED,
    )
    assert warm["status"] == "good" and warm["cached"] is False
    later = revocation.check_ocsp(
        leaf,
        issuer,
        pki.ocsp_url,
        timeout=5,
        now=almost + 2 * 3600,
        issuer_binding=revocation.VERIFIED,
    )
    # Past the ceiling the cached copy is dropped and the responder is asked
    # again; its answer is the same response, which is now refused.
    assert later["cached"] is False
    assert later["error"] == "OCSPStale" and "10 days" in later["reason"]


def test_cache_expiry_never_passes_the_ten_day_ceiling():
    now = 1_000_000.0
    # thisUpdate nine and a half days ago puts the ceiling twelve hours out,
    # well inside the one-day cap and long before nextUpdate.
    this_update = int(now) - 9 * 86400 - 43200
    ceiling = now + 43200
    assert (
        revocation._expiry_for(this_update, int(now) + 30 * 86400, now, 86400)
        == ceiling
    )
    # Without nextUpdate, the hour lease usually gets there first; move
    # thisUpdate to within half an hour of the ceiling and it wins instead.
    assert revocation._expiry_for(this_update, None, now, 30 * 86400) == now + 3600
    nearly_out = int(now) - 10 * 86400 + 1800
    assert revocation._expiry_for(nearly_out, None, now, 30 * 86400) == now + 1800


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
    # The stub targets OCSP's own verifier rather than certinfo.signature_hash:
    # the CRL is signed with the same algorithm in this PKI and goes
    # through the same primitive, so a global patch would leave it unproven too.
    monkeypatch.setattr(
        revocation,
        "_verify_ocsp_signer",
        MagicMock(
            return_value=(
                revocation.UNSUPPORTED,
                "unsupported signature algorithm test",
                None,
            )
        ),
    )
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
    # The stub targets OCSP's own verifier rather than certinfo.signature_hash:
    # the CRL is signed with the same algorithm in this PKI and goes
    # through the same primitive, so a global patch would leave it unproven too.
    monkeypatch.setattr(
        revocation,
        "_verify_ocsp_signer",
        MagicMock(
            return_value=(
                revocation.UNSUPPORTED,
                "unsupported signature algorithm test",
                None,
            )
        ),
    )
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


def _impostor_ca(pki) -> bytes:
    """A CA with the real CA's subject name and a different key."""
    target = pki.directory / "impostor.pem"
    if not target.exists():
        pki.run(
            "req", "-x509", *pki.newkey(), "-nodes", "-keyout", "impostor.key",
            "-out", "impostor.pem", "-days", "2", "-subj", f"/CN={pki.ca_name}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )  # fmt: skip
    return ssl.PEM_cert_to_DER_cert(target.read_text())


def test_issuer_must_have_signed_the_leaf(pki):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    real = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    impostor = _impostor_ca(pki)
    # Same name, wrong key: a name match alone is not an issuer.
    assert revocation.find_issuer(leaf, [impostor]) == (None, None, None)
    found, binding, problem = revocation.find_issuer(leaf, [impostor, real])
    assert found == real and binding == revocation.VERIFIED and problem is None


def test_find_issuer_skips_unrelated_and_unparsable_candidates(pki):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    other_leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "revoked.pem").read_text())
    real = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    # A sibling leaf has another subject; garbage does not parse; the CA still wins.
    found, binding, _ = revocation.find_issuer(
        leaf, [other_leaf, b"not a certificate", real]
    )
    assert found == real and binding == revocation.VERIFIED
    # A leaf that does not parse cannot be bound to anything.
    assert revocation.find_issuer(b"not a certificate", [real]) == (None, None, None)


def test_impostor_issuer_from_aia_is_rejected(pki, monkeypatch):
    _impostor_ca(pki)
    impostor_pem = (pki.directory / "impostor.pem").read_bytes()
    real_fetch = http.fetch

    def serve_impostor(url, **kwargs):
        if url.endswith("/ca.pem"):
            return impostor_pem
        return real_fetch(url, **kwargs)

    monkeypatch.setattr(http, "fetch", serve_impostor)
    server, options = monitor_for(pki, "good")  # leaf only, issuer via AIA
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
    assert result["status"] == "error", result
    assert result["methods"]["ocsp"]["error"] == "MissingIssuer"
    assert "did not sign" in result["methods"]["ocsp"]["reason"]


def test_unverifiable_issuer_binding_caps_ocsp_at_unsupported(pki, monkeypatch):
    # If the leaf's own signature algorithm cannot be checked, the issuer is
    # only name-matched, so even a correctly signed OCSP answer is not proof.
    real_hash = certinfo.signature_hash
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    leaf_parts = certinfo.certificate_signature_parts(leaf)
    leaf_algorithm = leaf_parts["signature_algorithm"]
    assert "signature_algorithm_params" in leaf_parts
    calls = {"n": 0}

    def unsupported_for_the_leaf_only(algorithm):
        calls["n"] += 1
        if calls["n"] == 1 and algorithm == leaf_algorithm:
            return None
        return real_hash(algorithm)

    monkeypatch.setattr(certinfo, "signature_hash", unsupported_for_the_leaf_only)
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["ocsp"]}})["revocation"]
    assert result["status"] == "warn", result
    assert result["methods"]["ocsp"]["verification"] == "unsupported"
    assert "only name-matched" in result["methods"]["ocsp"]["verification_error"]


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


def test_negative_max_age_hours_is_an_argument_error(pki):
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"max_age_hours": -1}})["revocation"]
    assert result["status"] == "error"
    assert "max_age_hours" in result["reason"]


def test_crl_verdict_is_about_the_collected_certificate_and_needs_no_reconnect(pki):
    server, options = monitor_for(pki, "good")
    with server:
        monitor = CertMonitor("localhost", server.port, **options)
        monitor.__enter__()
    # The server is gone; the CRL is judged against the snapshot alone.
    result = monitor.validate({"revocation": {"methods": ["crl"]}})["revocation"]
    monitor.__exit__(None, None, None)
    assert result["status"] == "pass", result
    assert result["source"] == "crl"
    assert result["signature_verified"] is True
    assert result["methods"]["crl"]["verification"] == "verified"


def test_tampered_crl_is_an_error_not_evidence(pki, monkeypatch):
    real_fetch = http.fetch

    def flip_a_signature_byte(url, **kwargs):
        body = real_fetch(url, **kwargs)
        if url != pki.crl_url:
            return body
        body = bytearray(body)
        signature = certinfo.crl_info(bytes(body))["signature"]
        body[body.find(signature)] ^= 0x01
        return bytes(body)

    monkeypatch.setattr(http, "fetch", flip_a_signature_byte)
    server, options = monitor_for(pki, "revoked")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["crl"]}})["revocation"]
    assert result["status"] == "error", result
    assert result["error"] == "CRLInvalidSignature"
    assert result["methods"]["crl"]["verification"] == "failed"


def test_crl_falls_through_to_the_next_distribution_point_after_a_failed_signature(
    pki, monkeypatch
):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    first_url = pki.crl_url + "?first"
    real_fetch = http.fetch

    def flip_the_first_signature_byte(url, **kwargs):
        body = real_fetch(url, **kwargs)
        if url != first_url:
            return body
        body = bytearray(body)
        signature = certinfo.crl_info(bytes(body))["signature"]
        body[body.find(signature)] ^= 0x01
        return bytes(body)

    monkeypatch.setattr(http, "fetch", flip_the_first_signature_byte)
    info = {
        "crlDistributionPoints": [first_url, pki.crl_url],
        "caIssuers": [f"http://127.0.0.1:{pki.crl_port}/ca.pem"],
    }
    evidence = revocation.RevocationEvidence(
        leaf_der=leaf, chain_der=[leaf, issuer], cert_info=info, timeout=5
    )
    answer = evidence.crl()
    assert answer["verification"] == "verified", answer
    assert answer["url"] == pki.crl_url


def test_crl_from_another_issuer_is_rejected(pki, monkeypatch):
    real_info = certinfo.crl_info

    def issued_by_someone_else(der):
        info = real_info(der)
        info["issuer_der"] = b"\x30\x00"  # an empty Name, nobody's
        return info

    monkeypatch.setattr(certinfo, "crl_info", issued_by_someone_else)
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        result = monitor.validate({"revocation": {"methods": ["crl"]}})["revocation"]
    assert result["status"] == "error", result
    assert result["methods"]["crl"]["error"] == "CRLIssuerMismatch"


def test_stale_and_future_crls_are_errors(pki, monkeypatch):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    info = {
        "crlDistributionPoints": [pki.crl_url],
        "caIssuers": [f"http://127.0.0.1:{pki.crl_port}/ca.pem"],
    }
    far_future = 4_102_444_800  # 2100-01-01
    evidence = revocation.RevocationEvidence(
        leaf_der=leaf, chain_der=[leaf, issuer], cert_info=info, timeout=5
    )
    monkeypatch.setattr(revocation.time, "time", MagicMock(return_value=far_future))
    assert evidence.crl()["error"] == "CRLStale"
    revocation.CRL_CACHE.clear()
    evidence = revocation.RevocationEvidence(
        leaf_der=leaf, chain_der=[leaf, issuer], cert_info=info, timeout=5
    )
    monkeypatch.setattr(revocation.time, "time", MagicMock(return_value=946_684_800))
    assert evidence.crl()["error"] == "CRLNotYetValid"


def test_crl_without_next_update_keeps_a_one_hour_lease(pki, monkeypatch):
    real_info = certinfo.crl_info

    def without_next_update(der):
        info = real_info(der)
        info["next_update"] = None
        info["this_update"] -= 3 * 86400
        return info

    monkeypatch.setattr(certinfo, "crl_info", without_next_update)
    first = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert first["verification"] == "verified" and first["cached"] is False
    second = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert second["cached"] is True


def test_crl_info_reports_scope_extensions(pki):
    full = certinfo.crl_info((pki.directory / "ca.crl").read_bytes())
    assert full["delta_crl_indicator"] is False
    assert full["issuing_distribution_point"] is None
    pki.publish_partitioned_crl()
    partitioned = certinfo.crl_info((pki.directory / "partitioned.crl").read_bytes())
    assert partitioned["issuing_distribution_point"]["only_some_reasons"] is True
    assert partitioned["issuing_distribution_point"]["indirect_crl"] is False


def test_certificate_signature_parts_reports_key_usage(pki):
    ca = certinfo.certificate_signature_parts(
        ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    )
    assert ca["key_usage"] == ["key_cert_sign", "crl_sign"]
    leaf = certinfo.certificate_signature_parts(
        ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    )
    assert leaf["key_usage"] == ["digital_signature", "key_encipherment"]
    responder = certinfo.certificate_signature_parts(
        ssl.PEM_cert_to_DER_cert((pki.directory / "responder.pem").read_text())
    )
    assert responder["key_usage"] == ["digital_signature"]


def test_crl_info_reports_unsupported_critical_extensions(pki):
    plain = certinfo.crl_info((pki.directory / "ca.crl").read_bytes())
    assert plain["unsupported_critical_extensions"] == []
    # The issuing distribution point is critical by definition and is
    # processed, so it is not an obstacle.
    pki.publish_partitioned_crl()
    partitioned = certinfo.crl_info((pki.directory / "partitioned.crl").read_bytes())
    assert partitioned["unsupported_critical_extensions"] == []
    pki.publish_crl_with_unknown_critical_extension()
    weird = certinfo.crl_info((pki.directory / "weird.crl").read_bytes())
    assert weird["unsupported_critical_extensions"] == ["1.2.3.4"]


def test_crl_with_an_unknown_critical_extension_is_refused(pki):
    url = pki.publish_crl_with_unknown_critical_extension()
    answer = _evidence_for_crl(pki, "good", url).crl()
    assert answer["status"] == "error", answer
    assert answer["error"] == "CRLUnsupportedCriticalExtension"
    assert "1.2.3.4" in answer["reason"] and "RFC 5280" in answer["reason"]
    assert answer["signature_verified"] is False
    assert "verification" not in answer
    # The next distribution point is consulted, as for any other refusal.
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    evidence = revocation.RevocationEvidence(
        leaf_der=leaf,
        chain_der=[leaf, issuer],
        cert_info={"crlDistributionPoints": [url, pki.crl_url]},
        timeout=5,
    )
    fallback = evidence.crl()
    assert fallback["verification"] == "verified" and fallback["url"] == pki.crl_url


def test_crl_from_an_issuer_without_crl_sign_is_refused(pki, monkeypatch):
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    real_parts = certinfo.certificate_signature_parts

    def make_issuer_key_usage(usage):
        def parts(der):
            found = real_parts(der)
            if der == issuer:
                found["key_usage"] = usage
            return found

        return parts

    monkeypatch.setattr(
        certinfo,
        "certificate_signature_parts",
        make_issuer_key_usage(["digital_signature", "key_cert_sign"]),
    )
    answer = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert answer["status"] == "error", answer
    assert answer["error"] == "CRLSignerNotAuthorized"
    assert "cRLSign" in answer["reason"]
    assert "verification" not in answer
    # A refused CRL is not cached, and an issuer with no keyUsage extension
    # at all is under no such restriction (RFC 5280 section 6.3.3 step (f)).
    monkeypatch.setattr(
        certinfo, "certificate_signature_parts", make_issuer_key_usage(None)
    )
    relaxed = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert relaxed["verification"] == "verified" and relaxed["cached"] is False


def test_rejected_crl_is_not_cached(pki, monkeypatch):
    real_fetch = http.fetch
    fetches = []

    def flip_the_first_signature_byte_once(url, **kwargs):
        body = real_fetch(url, **kwargs)
        fetches.append(url)
        if url != pki.crl_url or len(fetches) > 1:
            return body
        body = bytearray(body)
        signature = certinfo.crl_info(bytes(body))["signature"]
        body[body.find(signature)] ^= 0x01
        return bytes(body)

    monkeypatch.setattr(http, "fetch", flip_the_first_signature_byte_once)
    first = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert first["verification"] == "failed" and first["cached"] is False
    # The corrupted copy was not kept: the next check fetches again and the
    # server's now-correct CRL is verified and cached.
    second = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert second["verification"] == "verified" and second["cached"] is False
    third = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert third["verification"] == "verified" and third["cached"] is True
    assert len(fetches) == 2


def _evidence_for_crl(pki, name: str, url: str) -> revocation.RevocationEvidence:
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / f"{name}.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    return revocation.RevocationEvidence(
        leaf_der=leaf,
        chain_der=[leaf, issuer],
        cert_info={"crlDistributionPoints": [url]},
        timeout=5,
    )


def test_partitioned_crl_is_refused_not_read_as_good(pki):
    url = pki.publish_partitioned_crl()
    answer = _evidence_for_crl(pki, "good", url).crl()
    assert answer["status"] == "error", answer
    assert answer["error"] == "CRLScopeUnsupported"
    assert "some revocation reasons" in answer["reason"]


def test_crl_naming_its_own_location_is_accepted(pki):
    url = pki.publish_crl_with_idp(
        "here", f"fullname = URI:http://127.0.0.1:{pki.crl_port}/here.crl\n"
    )
    info = certinfo.crl_info((pki.directory / "here.crl").read_bytes())
    assert info["issuing_distribution_point"]["distribution_point_uris"] == [url]
    assert info["issuing_distribution_point"]["names_other_locations"] is False
    answer = _evidence_for_crl(pki, "good", url).crl()
    assert answer["status"] == "good", answer


def test_crl_naming_another_location_is_refused(pki):
    url = pki.publish_crl_with_idp(
        "elsewhere", "fullname = URI:http://crl.other.test/ca.crl\n"
    )
    answer = _evidence_for_crl(pki, "good", url).crl()
    assert answer["error"] == "CRLScopeUnsupported"
    assert "crl.other.test" in answer["reason"] and "6.3.3" in answer["reason"]


def test_crl_naming_only_a_directory_entry_is_refused(pki):
    url = pki.publish_crl_with_idp(
        "ldap-only", "fullname = dirName:dn\n[ dn ]\nCN = CRL Issuer\n"
    )
    answer = _evidence_for_crl(pki, "good", url).crl()
    assert answer["error"] == "CRLScopeUnsupported"
    assert "not URLs" in answer["reason"]


@pytest.mark.parametrize(
    "info,fragment",
    [
        ({"delta_crl_indicator": True}, "delta"),
        ({"issuing_distribution_point": {"indirect_crl": True}}, "indirect"),
        (
            {"issuing_distribution_point": {"only_some_reasons": True}},
            "some revocation reasons",
        ),
        (
            {"issuing_distribution_point": {"only_contains_ca_certs": True}},
            "only CA certificates",
        ),
        (
            {"issuing_distribution_point": {"only_contains_attribute_certs": True}},
            "attribute certificates",
        ),
        (
            {
                "issuing_distribution_point": {
                    "distribution_point_uris": ["http://x.test/a.crl"]
                }
            },
            "x.test",
        ),
        (
            {"issuing_distribution_point": {"names_other_locations": True}},
            "not URLs",
        ),
    ],
)
def test_every_scope_narrowing_is_named(info, fragment):
    problem = revocation._crl_scope_problem(info, "http://crl.test/ca.crl")
    assert problem is not None and fragment in problem


@pytest.mark.parametrize(
    "info",
    [
        {},
        {"issuing_distribution_point": None},
        {"issuing_distribution_point": {"only_contains_user_certs": True}},
        {
            "issuing_distribution_point": {
                "distribution_point_uris": ["http://crl.test/ca.crl"]
            }
        },
    ],
)
def test_in_scope_crls_raise_no_problem(info):
    assert revocation._crl_scope_problem(info, "http://crl.test/ca.crl") is None


def test_same_location_ignores_case_of_scheme_and_host():
    assert revocation._same_location(
        "HTTP://CRL.Example/ca.crl", "http://crl.example/ca.crl"
    )
    assert not revocation._same_location(
        "http://crl.example/ca.crl", "http://crl.example/CA.crl"
    )
    assert revocation._same_location("http://crl.example", "http://crl.example/")
    assert not revocation._same_location(
        "http://crl.example/a", "http://crl.example/a/"
    )


def test_delta_crl_is_refused(pki, monkeypatch):
    real_info = certinfo.crl_info

    def as_delta(der):
        info = real_info(der)
        info["delta_crl_indicator"] = True
        return info

    monkeypatch.setattr(certinfo, "crl_info", as_delta)
    answer = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert answer["error"] == "CRLScopeUnsupported" and "delta" in answer["reason"]


def test_crl_without_next_update_expires_after_ten_days(pki, monkeypatch):
    real_info = certinfo.crl_info

    def old_and_open_ended(der):
        info = real_info(der)
        info["next_update"] = None
        info["this_update"] -= 11 * 86400
        return info

    monkeypatch.setattr(certinfo, "crl_info", old_and_open_ended)
    answer = _evidence_for_crl(pki, "good", pki.crl_url).crl()
    assert answer["error"] == "CRLStale" and "10 days" in answer["reason"]


def test_out_of_scope_crl_falls_through_to_the_next_distribution_point(pki):
    url = pki.publish_partitioned_crl()
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    evidence = revocation.RevocationEvidence(
        leaf_der=leaf,
        chain_der=[leaf, issuer],
        cert_info={
            "crlDistributionPoints": [url, pki.crl_url],
            "OCSP": [pki.ocsp_url],
        },
        timeout=5,
    )
    answer = evidence.crl()
    assert answer["status"] == "good", answer
    assert answer["url"] == pki.crl_url


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


def test_ocsp_answer_must_match_the_whole_cert_id(pki, monkeypatch):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    real_parse = certinfo.parse_ocsp_response

    def with_wrong_name_hash(body):
        parsed = real_parse(body)
        for single in parsed["responses"]:
            single["cert_id"]["issuer_name_hash"] = "00" * 20
        return parsed

    monkeypatch.setattr(certinfo, "parse_ocsp_response", with_wrong_name_hash)
    answer = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5)
    assert answer["error"] == "OCSPMismatch"

    def with_wrong_hash_algorithm(body):
        parsed = real_parse(body)
        for single in parsed["responses"]:
            single["cert_id"]["hash_algorithm"] = "2.16.840.1.101.3.4.2.1"  # sha256
        return parsed

    monkeypatch.setattr(certinfo, "parse_ocsp_response", with_wrong_hash_algorithm)
    answer = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5)
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

    just_expired = time.time() + 30 * 3600  # past nextUpdate, under the ten-day ceiling
    revocation.OCSP_CACHE.clear()
    answer = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, now=just_expired
    )
    assert answer["error"] == "OCSPStale" and "expired at" in answer["reason"]

    long_ago = 946_684_800  # 2000-01-01
    answer = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5, now=long_ago)
    assert answer["error"] == "OCSPNotYetValid"


def _without_next_update(real_parse):
    def parse(body):
        parsed = real_parse(body)
        for single in parsed["responses"]:
            single["next_update"] = None
        return parsed

    return parse


def test_old_ocsp_responses_without_next_update_are_stale(pki, monkeypatch):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    monkeypatch.setattr(
        certinfo,
        "parse_ocsp_response",
        _without_next_update(certinfo.parse_ocsp_response),
    )
    produced = time.time()
    fresh = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, now=produced + 3600
    )
    assert fresh["status"] == "good" and fresh["next_update"] is None
    revocation.OCSP_CACHE.clear()
    old = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, now=produced + 2 * 86400
    )
    assert old["error"] == "OCSPStale" and "no nextUpdate" in old["reason"]
    revocation.OCSP_CACHE.clear()
    tight = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, now=produced + 3600, max_age=1800
    )
    assert tight["error"] == "OCSPStale"


def test_ocsp_responses_older_than_ten_days_are_stale_even_with_next_update(
    pki, monkeypatch
):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    real_parse = certinfo.parse_ocsp_response

    def with_far_next_update(body):
        parsed = real_parse(body)
        for single in parsed["responses"]:
            single["next_update"] = single["this_update"] + 30 * 86400
        return parsed

    monkeypatch.setattr(certinfo, "parse_ocsp_response", with_far_next_update)
    answer = revocation.check_ocsp(
        leaf, issuer, pki.ocsp_url, timeout=5, now=time.time() + 11 * 86400
    )
    assert answer["error"] == "OCSPStale" and "10 days" in answer["reason"]


def test_cache_expiry_is_anchored_to_this_update_without_next_update():
    now = 1_000_000.0
    # No nextUpdate: never past thisUpdate + max_age, never past the default TTL.
    assert revocation._expiry_for(int(now) - 3000, None, now, 3600) == now + 600
    assert revocation._expiry_for(int(now), None, now, 86400) == now + 3600
    # With nextUpdate: the earlier of nextUpdate and the one-day ceiling.
    assert revocation._expiry_for(int(now), int(now) + 100, now, 3600) == now + 100


def test_max_age_hours_is_a_validator_argument(pki, monkeypatch):
    real_parse = certinfo.parse_ocsp_response

    def two_hours_old_without_next_update(body):
        parsed = real_parse(body)
        for single in parsed["responses"]:
            single["next_update"] = None
            single["this_update"] -= 2 * 3600
        return parsed

    monkeypatch.setattr(
        certinfo, "parse_ocsp_response", two_hours_old_without_next_update
    )
    server, options = monitor_for(pki, "good")
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        stale = monitor.validate(
            {"revocation": {"methods": ["ocsp"], "max_age_hours": 1}}
        )["revocation"]
        revocation.OCSP_CACHE.clear()
        fresh = monitor.validate(
            {"revocation": {"methods": ["ocsp"], "max_age_hours": 3}}
        )["revocation"]
        # The cached fresh answer must not satisfy a tighter max_age on reuse.
        tightened = monitor.validate(
            {"revocation": {"methods": ["ocsp"], "max_age_hours": 1}}
        )["revocation"]
    assert stale["status"] == "error", stale
    assert stale["methods"]["ocsp"]["error"] == "OCSPStale"
    assert fresh["status"] == "pass", fresh
    assert tightened["status"] == "error", tightened
    assert tightened["methods"]["ocsp"]["error"] == "OCSPStale"


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
    # Fetching remembers nothing; the caller does, once the signature checks.
    assert revocation.fetch_crl("http://crl.test/ca.crl", timeout=1)[2] is False
    revocation.remember_crl("http://crl.test/ca.crl", der, info)
    assert revocation.fetch_crl("http://crl.test/ca.crl", timeout=1)[2] is True


def test_crl_lookup_and_info_through_the_parser(pki):
    der = (pki.directory / "ca.crl").read_bytes()
    info = certinfo.crl_info(der)
    assert info["issuer"]["commonName"] == "CertMonitor Revocation CA"
    assert info["next_update"] > info["this_update"]
    # sha256WithRSAEncryption carries NULL parameters, reported as None.
    assert info["signature_algorithm_params"] is None
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
    assert revocation.format_time(None) is None
    assert revocation.format_time(0) == "1970-01-01T00:00:00+00:00"
    assert revocation.http_urls(["ldap://x", "http://a", "HTTPS://b", None]) == [
        "http://a",
        "HTTPS://b",
    ]
    assert revocation.http_urls(None) == []
    now = 1_000_000.0
    assert revocation._expiry_for(int(now), None, now, 3600) == now + 3600
    assert revocation._expiry_for(int(now), int(now) + 10, now, 3600) == now + 10
    assert revocation._expiry_for(int(now), int(now) + 10**7, now, 3600) == now + 86400
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


def test_crl_check_with_a_client_certificate(pki, local_pki):
    server, options = monitor_for(
        pki,
        "good",
        client_cert=str(pki.directory / "good.pem"),
        client_key=str(pki.directory / "good.key"),
    )
    with server, CertMonitor("localhost", server.port, **options) as monitor:
        # A foreign trust store, unrelated to pki's CA, is configured after
        # the connection completes: the CRL check must not consult it.
        monitor.cafile = str(local_pki / "ca.pem")
        result = monitor.validate({"revocation": {"methods": ["crl"]}})["revocation"]
    # The CRL is judged against the collected chain alone, so presenting a
    # client certificate to the server, or configuring a foreign trust store,
    # does not affect it.
    assert result["status"] == "pass"
    assert result["source"] == "crl"
    assert result["methods"]["crl"]["signature_verified"] is True


def test_evidence_remembers_answers_and_reports_a_missing_issuer(pki):
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
    assert crl["status"] == "error"
    assert crl["error"] == "MissingIssuer"
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
    # sha256WithRSAEncryption carries NULL parameters, reported as None.
    assert "signature_algorithm_params" in parsed
    assert parsed["signature_algorithm_params"] is None
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
    # Either Edwards OID over an RSA key is a key-type mismatch, not a bad
    # signature.
    outcome, why = revocation._signed_by(spki, "1.3.101.112", b"tbs", b"sig")
    assert outcome == "unsupported" and "does not match the key type" in why
    outcome, why = revocation._signed_by(spki, "1.3.101.113", b"tbs", b"sig")
    assert outcome == "unsupported" and "does not match the key type" in why
    ec_spki = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    ec_spki = certinfo.certificate_signature_parts(ec_spki)["spki"]
    outcome, why = revocation._signed_by(ec_spki, "1.2.840.10045.4.3.2", b"tbs", b"sig")
    assert outcome == "unsupported" and "does not match the key type" in why
    outcome, why = revocation._signed_by(
        b"\x30\x00", "1.2.840.113549.1.1.11", b"tbs", b"sig"
    )
    assert outcome == "failed" and "SubjectPublicKeyInfo" in why


def test_unknown_digest_name_is_unsupported_not_a_crash(monkeypatch):
    monkeypatch.setattr(
        certinfo, "signature_hash", MagicMock(return_value="no-such-digest")
    )
    outcome, problem = revocation._signed_by(
        b"", "1.2.840.113549.1.1.11", b"tbs", b"sig"
    )
    assert outcome == revocation.UNSUPPORTED
    assert "no-such-digest" in problem


def test_cached_answers_never_outlive_next_update(pki):
    leaf = ssl.PEM_cert_to_DER_cert((pki.directory / "good.pem").read_text())
    issuer = ssl.PEM_cert_to_DER_cert(pki.ca_pem.read_text())
    now = time.time()
    first = revocation.check_ocsp(
        leaf,
        issuer,
        pki.ocsp_url,
        timeout=5,
        now=now,
        issuer_binding=revocation.VERIFIED,
    )
    assert first["cached"] is False and first["status"] == "good"
    assert revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5, now=now + 1)[
        "cached"
    ]

    # An entry whose own nextUpdate has passed must not be served, even if
    # something left it in the cache with time to spare.
    _, expected = revocation.build_ocsp_request(leaf, issuer)
    key = (
        pki.ocsp_url,
        expected["issuer_name_hash"],
        expected["issuer_key_hash"],
        expected["serial_number"],
    )
    stale = {**first, "_next_update": int(now) - 1}
    revocation.OCSP_CACHE.put(key, stale, expires_at=now + 3600)
    refreshed = revocation.check_ocsp(leaf, issuer, pki.ocsp_url, timeout=5, now=now)
    assert refreshed["cached"] is False

    # A CRL past its nextUpdate is fetched again rather than reused, and
    # one that is already past it is not remembered in the first place.
    der, info, cached = revocation.fetch_crl(pki.crl_url, timeout=5, now=now)
    assert cached is False
    revocation.remember_crl(
        pki.crl_url, der, {**info, "next_update": int(now) - 1}, now=now
    )
    assert revocation.fetch_crl(pki.crl_url, timeout=5, now=now)[2] is False
    revocation.remember_crl(pki.crl_url, der, info, now=now)
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
