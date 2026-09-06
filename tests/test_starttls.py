"""STARTTLS preambles against in-process fake servers, and a full TLS round trip."""

import socket
import ssl
import struct
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

import certmonitor.cli as cli
import certmonitor.scanning as scanning
from certmonitor import CertMonitor
from certmonitor.protocol_handlers import starttls
from certmonitor.scanning import scan_hosts
from certmonitor.protocol_handlers.starttls import (
    StartTLSError,
    ldap_starttls_request,
    negotiate,
)

LDAP_OK = bytes.fromhex("300c020101780702010004000400")
LDAP_REFUSED = (
    b"\x30\x1d\x02\x01\x01\x78\x18\x0a\x01\x01\x04\x00\x04\x11TLS not supported"
)


# --- server-side preambles ------------------------------------------------------


def _lines(conn):
    return conn.makefile("rb")


def smtp_ok(conn):
    reader = _lines(conn)
    conn.sendall(b"220 fake ESMTP\r\n")
    assert reader.readline().startswith(b"EHLO ")
    conn.sendall(b"250-fake\r\n250-STARTTLS\r\n250 OK\r\n")
    assert reader.readline().strip() == b"STARTTLS"
    conn.sendall(b"220 go ahead\r\n")


def smtp_without_starttls(conn):
    reader = _lines(conn)
    conn.sendall(b"220 fake ESMTP\r\n")
    reader.readline()
    conn.sendall(b"250 fake\r\n")


def smtp_refuses(conn):
    reader = _lines(conn)
    conn.sendall(b"220 fake ESMTP\r\n")
    reader.readline()
    conn.sendall(b"250-fake\r\n250 STARTTLS\r\n")
    reader.readline()
    conn.sendall(b"454 TLS not available\r\n")


def imap_ok(conn):
    reader = _lines(conn)
    conn.sendall(b"* OK fake IMAP ready\r\n")
    assert reader.readline().strip() == b"a001 STARTTLS"
    conn.sendall(b"* some untagged noise\r\na001 OK begin TLS\r\n")


def imap_refuses(conn):
    reader = _lines(conn)
    conn.sendall(b"* OK fake IMAP ready\r\n")
    reader.readline()
    conn.sendall(b"a001 BAD not here\r\n")


def pop3_ok(conn):
    reader = _lines(conn)
    conn.sendall(b"+OK fake POP3\r\n")
    assert reader.readline().strip() == b"STLS"
    conn.sendall(b"+OK begin TLS\r\n")


def pop3_refuses(conn):
    reader = _lines(conn)
    conn.sendall(b"+OK fake POP3\r\n")
    reader.readline()
    conn.sendall(b"-ERR no TLS\r\n")


def ftp_ok(conn):
    reader = _lines(conn)
    conn.sendall(b"220-welcome\r\n220 fake FTP\r\n")
    assert reader.readline().strip() == b"AUTH TLS"
    conn.sendall(b"234 proceed\r\n")


def ftp_refuses(conn):
    reader = _lines(conn)
    conn.sendall(b"220 fake FTP\r\n")
    reader.readline()
    conn.sendall(b"502 not implemented\r\n")


def postgres_ok(conn):
    assert conn.recv(8) == struct.pack("!ii", 8, 80877103)
    conn.sendall(b"S")


def postgres_declines(conn):
    conn.recv(8)
    conn.sendall(b"N")


def ldap_ok(conn):
    request = ldap_starttls_request()
    assert conn.recv(len(request)) == request
    conn.sendall(LDAP_OK)


def ldap_refuses(conn):
    conn.recv(64)
    conn.sendall(LDAP_REFUSED)


class FakeServer:
    """Accept connections on 127.0.0.1, run a preamble, then optionally speak TLS."""

    def __init__(self, preamble, tls_context=None):
        self.preamble = preamble
        self.tls_context = tls_context
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.failures = []
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
            self.preamble(conn)
            if self.tls_context is not None:
                secure = self.tls_context.wrap_socket(conn, server_side=True)
                self.stop.wait(3)
                secure.close()
            else:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            self.failures.append(exc)
            conn.close()


def client(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    sock.settimeout(3)
    return sock


# --- preamble unit tests --------------------------------------------------------


@pytest.mark.parametrize(
    "protocol,preamble",
    [
        ("smtp", smtp_ok),
        ("imap", imap_ok),
        ("pop3", pop3_ok),
        ("ftp", ftp_ok),
        ("postgres", postgres_ok),
        ("ldap", ldap_ok),
    ],
)
def test_each_preamble_reaches_the_tls_handoff(protocol, preamble):
    with FakeServer(preamble) as server:
        with client(server.port) as sock:
            negotiate(sock, protocol)
    assert server.failures == []


@pytest.mark.parametrize(
    "protocol,preamble,fragment",
    [
        ("smtp", smtp_without_starttls, "does not advertise STARTTLS"),
        ("smtp", smtp_refuses, "expected 220"),
        ("imap", imap_refuses, "IMAP STARTTLS"),
        ("pop3", pop3_refuses, "POP3 STLS"),
        ("ftp", ftp_refuses, "expected 234"),
        ("postgres", postgres_declines, "declined SSL"),
        ("ldap", ldap_refuses, "TLS not supported"),
    ],
)
def test_refusals_raise_with_the_server_reply(protocol, preamble, fragment):
    with FakeServer(preamble) as server:
        with client(server.port) as sock:
            with pytest.raises(StartTLSError, match=fragment):
                negotiate(sock, protocol)


def test_unknown_protocol_is_rejected():
    with pytest.raises(ValueError, match="unsupported STARTTLS protocol"):
        negotiate(MagicMock(), "gopher")
    with pytest.raises(ValueError, match="starttls must be one of"):
        CertMonitor("host.test", starttls="gopher")


class ResetSocket:
    """A socket whose peer reset the connection before answering."""

    def sendall(self, data):
        return None

    def recv(self, size):
        raise ConnectionResetError(104, "Connection reset by peer")


def test_reset_during_preamble_is_a_closed_connection():
    with pytest.raises(StartTLSError, match="connection closed"):
        negotiate(ResetSocket(), "smtp")


def test_closed_connection_during_preamble():
    def hang_up(conn):
        conn.sendall(b"220 fake\r\n")
        conn.close()

    with FakeServer(hang_up) as server:
        with client(server.port) as sock:
            with pytest.raises(StartTLSError, match="connection closed"):
                negotiate(sock, "smtp")


def test_ldap_request_is_the_rfc_4511_extended_request():
    request = ldap_starttls_request()
    assert request[:2] == b"\x30\x1d"  # LDAPMessage SEQUENCE, 29 bytes
    assert request[2:5] == b"\x02\x01\x01"  # messageID 1
    assert request[5:7] == b"\x77\x18"  # [APPLICATION 23] ExtendedRequest
    assert request[7:9] == b"\x80\x16"  # [0] requestName
    assert request[9:] == starttls.LDAP_STARTTLS_OID


# --- through CertMonitor -----------------------------------------------------


@pytest.fixture
def server_tls(local_pki):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(local_pki / "one.pem", local_pki / "one.key")
    return context


@pytest.mark.parametrize(
    "protocol,preamble",
    [("smtp", smtp_ok), ("postgres", postgres_ok), ("ldap", ldap_ok)],
)
def test_monitor_collects_and_verifies_over_starttls(
    local_pki, server_tls, protocol, preamble
):
    with FakeServer(preamble, server_tls) as server:
        with CertMonitor(
            "localhost",
            server.port,
            connection_host="127.0.0.1",
            starttls=protocol,
            cafile=str(local_pki / "ca.pem"),
            timeout=3,
            enabled_validators=[
                "hostname",
                "root_certificate",
                "tls_version",
                "pq_key_exchange",
            ],
        ) as monitor:
            results = monitor.validate()
        assert results["hostname"]["is_valid"] is True
        assert results["root_certificate"]["status"] == "pass", results[
            "root_certificate"
        ]
        assert results["tls_version"]["status"] == "pass"
        assert results["pq_key_exchange"]["status"] == "unsupported"
        assert "STARTTLS" in results["pq_key_exchange"]["reason"]
        assert monitor.fingerprint_sha256
    assert server.failures == []


def test_starttls_skips_protocol_detection(monkeypatch):
    monitor = CertMonitor("mail.test", 587, starttls="smtp")
    monkeypatch.setattr(
        monitor,
        "detect_protocol",
        MagicMock(side_effect=AssertionError("must not run")),
    )
    with patch("certmonitor.core.SSLHandler") as handler_class:
        handler_class.return_value.connect.return_value = None
        assert monitor.connect() is None
    assert monitor.protocol == "ssl"
    assert handler_class.return_value.starttls == "smtp"


def test_scan_hosts_passes_starttls_per_endpoint_and_scan_wide(monkeypatch):
    fake = MagicMock()
    fake.return_value.__enter__.return_value.validate.return_value = {}
    fake.return_value.__enter__.return_value.snapshot_at = None
    fake.return_value.__enter__.return_value.fingerprint_sha256 = None
    fake.return_value.__enter__.return_value.connection_host = "x"
    monkeypatch.setattr(scanning, "CertMonitor", fake)
    list(
        scan_hosts(
            [{"host": "mail.test", "port": 587, "starttls": "smtp"}, "db.test"],
            starttls="postgres",
        )
    )
    by_host = {c.args[0]: c.kwargs["starttls"] for c in fake.call_args_list}
    assert by_host == {"mail.test": "smtp", "db.test": "postgres"}


def test_cli_passes_starttls(monkeypatch):
    fake = MagicMock()
    fake.return_value.__enter__.return_value.validate.return_value = {}
    fake.return_value.__enter__.return_value.snapshot_at = None
    fake.return_value.__enter__.return_value.fingerprint_sha256 = None
    fake.return_value.__enter__.return_value.cert_info = {}
    fake.return_value.__enter__.return_value.public_key_info = None
    monkeypatch.setattr(cli, "CertMonitor", fake)
    assert (
        cli.main(
            ["check", "mail.test:587", "--starttls", "smtp", "--json"], out=MagicMock()
        )
        == 0
    )
    assert fake.call_args.kwargs["starttls"] == "smtp"


# --- error branches, driven through socket pairs ------------------------------------


def paired(server_bytes, close_after=False):
    """A client socket whose peer has already sent `server_bytes` (and maybe hung up)."""
    client_end, server_end = socket.socketpair()
    client_end.settimeout(2)
    server_end.sendall(server_bytes)
    if close_after:
        server_end.close()
    return client_end, server_end


def test_overlong_reply_line_is_rejected():
    client_end, server_end = paired(b"2" * 5000 + b"\r\n")
    with client_end, server_end:
        with pytest.raises(StartTLSError, match="too long"):
            negotiate(client_end, "smtp")


@pytest.mark.parametrize(
    "protocol,reply,fragment",
    [
        ("imap", b"* BYE not today\r\n", "IMAP greeting"),
        ("pop3", b"-ERR busy\r\n", "POP3 greeting"),
        ("postgres", b"X", "unexpected reply"),
    ],
)
def test_bad_greetings_and_replies(protocol, reply, fragment):
    client_end, server_end = paired(reply)
    with client_end, server_end:
        with pytest.raises(StartTLSError, match=fragment):
            negotiate(client_end, protocol)


def test_binary_preamble_notices_a_closed_connection():
    def hang_up_after_request(conn):
        conn.recv(8)
        conn.close()

    with FakeServer(hang_up_after_request) as server:
        with client(server.port) as sock:
            with pytest.raises(StartTLSError, match="connection closed"):
                negotiate(sock, "postgres")


def test_ber_long_form_lengths_round_trip():
    payload = b"x" * 300
    encoded = starttls._ber(0x04, payload)
    assert encoded[:4] == b"\x04\x82\x01\x2c"
    tag, content, offset = starttls._ber_read(encoded, 0)
    assert (tag, content, offset) == (0x04, payload, len(encoded))


@pytest.mark.parametrize(
    "data,fragment",
    [
        (b"\x04", "truncated"),
        (b"\x04\x80", "unsupported length"),
        (b"\x04\x05ab", "truncated"),
    ],
)
def test_ber_read_rejects_malformed_input(data, fragment):
    with pytest.raises(StartTLSError, match=fragment):
        starttls._ber_read(data, 0)


@pytest.mark.parametrize(
    "reply,fragment",
    [
        (b"\x04\x00", "expected an LDAPMessage"),
        (b"\x30\x80", "unsupported length"),
        (b"\x30\x07\x02\x01\x01\x04\x02ab", "expected an ExtendedResponse"),
    ],
)
def test_ldap_reply_shape_is_checked(reply, fragment):
    client_end, server_end = paired(reply)
    with client_end, server_end:
        with pytest.raises(StartTLSError, match=fragment):
            negotiate(client_end, "ldap")


def test_ldap_accepts_long_form_message_length():
    body = b"\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00"
    reply = b"\x30\x81" + bytes([len(body)]) + body
    client_end, server_end = paired(reply)
    with client_end, server_end:
        negotiate(client_end, "ldap")


# --- discovery: no protocol given, no port assumptions ------------------------------


def smtp_bare_220(conn):
    """An SMTP server whose greeting text gives nothing away."""
    reader = _lines(conn)
    conn.sendall(b"220 mail.test ready\r\n")
    assert reader.readline().startswith(b"EHLO ")
    conn.sendall(b"250-mail.test\r\n250-STARTTLS\r\n250 OK\r\n")
    line = reader.readline().strip()
    if line == b"STARTTLS":
        conn.sendall(b"220 go ahead\r\n")


def ftp_bare_220(conn):
    """An FTP server whose greeting text gives nothing away."""
    reader = _lines(conn)
    conn.sendall(b"220-welcome\r\n220 files.test\r\n")
    line = reader.readline().strip()
    if line.startswith(b"EHLO"):
        conn.sendall(b"500 Unknown command\r\n")
        return
    if line == b"AUTH TLS":
        conn.sendall(b"234 proceed\r\n")


def ssh_banner(conn):
    conn.sendall(b"SSH-2.0-fake\r\n")
    conn.recv(64)


def silent(conn):
    """Never speaks, never answers."""
    while conn.recv(64):
        pass


def hangs_up(conn):
    conn.close()


def binary_greeting(conn):
    conn.sendall(b"\x4a\x00\x00\x00\x0a5.7.0-fake")
    conn.recv(64)


def greets_then_hangs(conn):
    conn.sendall(b"220 hello\r\n")
    conn.recv(64)
    conn.close()


@pytest.mark.parametrize(
    "preamble,expected",
    [
        (smtp_ok, "smtp"),
        (smtp_bare_220, "smtp"),
        (imap_ok, "imap"),
        (pop3_ok, "pop3"),
        (ftp_ok, "ftp"),
        (ftp_bare_220, "ftp"),
        (postgres_ok, "postgres"),
        (postgres_declines, "postgres"),
        (ldap_ok, "ldap"),
        (ldap_refuses, "ldap"),
        (ssh_banner, "ssh"),
    ],
)
def test_discover_names_each_service_without_a_port_hint(preamble, expected):
    with FakeServer(preamble) as server:
        assert starttls.discover("127.0.0.1", server.port, 2) == expected


@pytest.mark.parametrize(
    "preamble", [silent, hangs_up, binary_greeting, greets_then_hangs]
)
def test_discover_gives_up_on_services_it_cannot_name(preamble):
    with FakeServer(preamble) as server:
        assert starttls.discover("127.0.0.1", server.port, 0.5) is None


def test_discover_is_bounded_by_its_timeout():
    with FakeServer(silent) as server:
        started = time.monotonic()
        assert starttls.discover("127.0.0.1", server.port, 0.4) is None
        assert time.monotonic() - started < 1.5


def test_discover_propagates_a_failed_connection():
    with pytest.raises(OSError):
        starttls.discover("127.0.0.1", 9, 0.5)


@pytest.mark.parametrize(
    "probe", [starttls._answers_ssl_request, starttls._answers_ldap_starttls]
)
def test_probes_treat_a_dead_socket_as_no_answer(probe):
    ours, theirs = socket.socketpair()
    theirs.close()
    with ours:
        assert probe(ours, 0.5) is False


@pytest.mark.parametrize(
    "protocol,preamble",
    [
        ("smtp", smtp_ok),
        ("imap", imap_ok),
        ("pop3", pop3_ok),
        ("ftp", ftp_ok),
        ("postgres", postgres_ok),
        ("ldap", ldap_ok),
    ],
)
def test_monitor_discovers_the_service_when_no_protocol_is_given(
    local_pki, server_tls, protocol, preamble
):
    with FakeServer(preamble, server_tls) as server:
        with CertMonitor(
            "localhost",
            server.port,
            connection_host="127.0.0.1",
            cafile=str(local_pki / "ca.pem"),
            timeout=2,
            enabled_validators=["hostname", "root_certificate"],
        ) as monitor:
            results = monitor.validate()
            assert monitor.starttls == protocol
        assert results["hostname"]["is_valid"] is True
        assert results["root_certificate"]["status"] == "pass", results[
            "root_certificate"
        ]


def test_discovery_runs_after_a_failed_tls_handshake(
    local_pki, server_tls, monkeypatch
):
    with FakeServer(smtp_ok, server_tls) as server:
        monitor = CertMonitor(
            "localhost", server.port, connection_host="127.0.0.1", timeout=2
        )
        # Pretend the greeting had not arrived when detection peeked.
        monkeypatch.setattr(monitor, "detect_protocol", MagicMock(return_value="ssl"))
        with monitor:
            assert monitor.connect() is None
            assert monitor.starttls == "smtp"
            assert monitor.protocol == "ssl"
            assert monitor.get_cert_info()["subject"]


def test_discovery_finds_ssh_after_a_failed_tls_handshake(monkeypatch):
    with FakeServer(ssh_banner) as server:
        monitor = CertMonitor("127.0.0.1", server.port, timeout=2)
        monkeypatch.setattr(monitor, "detect_protocol", MagicMock(return_value="ssl"))
        with monitor:
            assert monitor.connect() is None
            assert monitor.protocol == "ssh"
            assert monitor.starttls is None


def test_unnamed_service_keeps_the_original_tls_error(monkeypatch):
    with FakeServer(silent) as server:
        monitor = CertMonitor("127.0.0.1", server.port, timeout=0.5)
        monkeypatch.setattr(monitor, "detect_protocol", MagicMock(return_value="ssl"))
        result = monitor.connect()
    assert result["error"] == "SSLError"
    assert monitor.starttls is None


def test_discovery_reports_connection_failures_as_not_found(monkeypatch):
    monitor = CertMonitor("127.0.0.1", 9, timeout=0.5)
    monkeypatch.setattr(starttls, "discover", MagicMock(side_effect=OSError("down")))
    assert monitor._discover_service() is None


def test_explicit_protocol_is_the_override(server_tls, monkeypatch):
    discover = MagicMock(return_value="imap")
    monkeypatch.setattr(starttls, "discover", discover)
    with FakeServer(smtp_ok, server_tls) as server:
        with CertMonitor(
            "127.0.0.1", server.port, starttls="smtp", timeout=2
        ) as monitor:
            assert monitor.get_cert_info()["subject"]
            assert monitor.starttls == "smtp"
    discover.assert_not_called()


def test_discover_treats_a_failed_second_connection_as_not_found(monkeypatch):
    real_create_connection = socket.create_connection
    attempts = []

    def refuses_after_the_first(address, timeout=None):
        attempts.append(address)
        if len(attempts) > 1:
            raise OSError("connection refused")
        return real_create_connection(address, timeout=timeout)

    monkeypatch.setattr(socket, "create_connection", refuses_after_the_first)
    with FakeServer(silent) as server:
        assert starttls.discover("127.0.0.1", server.port, 0.5) is None
    assert len(attempts) == 2
