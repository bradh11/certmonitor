"""HTTP CONNECT and SOCKS5 proxies against in-process fakes, end to end through CertMonitor."""

import base64
import socket
import ssl
import struct
import threading
from unittest.mock import MagicMock

import pytest

import certmonitor.cli as cli
import certmonitor.scanning as scanning
from certmonitor import CertMonitor
from certmonitor.protocol_handlers.proxy import (
    ProxyConfig,
    ProxyError,
    open_connection,
    parse_proxy,
)
from certmonitor.scanning import scan_hosts


# --- parsing ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://proxy.test:3128", ProxyConfig("http", "proxy.test", 3128)),
        ("http://proxy.test", ProxyConfig("http", "proxy.test", 3128)),
        (
            "HTTP://alice:s%40cret@proxy.test:8080",
            ProxyConfig("http", "proxy.test", 8080, "alice", "s@cret"),
        ),
        ("socks5://proxy.test", ProxyConfig("socks5", "proxy.test", 1080)),
        (
            "socks5h://bob:pw@proxy.test:1081",
            ProxyConfig("socks5", "proxy.test", 1081, "bob", "pw"),
        ),
        ("socks5://[2001:db8::1]:1080", ProxyConfig("socks5", "2001:db8::1", 1080)),
    ],
)
def test_parse_proxy(url, expected):
    assert parse_proxy(url) == expected


@pytest.mark.parametrize(
    "url",
    ["ftp://proxy.test", "proxy.test:3128", "http://:3128", "http://proxy.test:abc"],
)
def test_parse_proxy_rejects_bad_urls(url):
    with pytest.raises(ValueError):
        parse_proxy(url)


def test_redacted_url_drops_the_password():
    assert (
        parse_proxy("socks5://bob:pw@proxy.test:1081").redacted
        == "socks5://bob@proxy.test:1081"
    )
    assert (
        parse_proxy("http://[2001:db8::1]:8080").redacted == "http://[2001:db8::1]:8080"
    )


# --- fake proxies -----------------------------------------------------------------


class FakeProxy:
    """A single-purpose proxy on 127.0.0.1 that tunnels to `target` after its handshake."""

    def __init__(self, handshake, target=None):
        self.handshake = handshake
        self.target = target
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.requests = []
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
            wanted = self.handshake(conn, self.requests)
            if wanted is None or self.target is None:
                conn.close()
                return
            upstream = socket.create_connection(self.target, timeout=3)
            _pump(conn, upstream, self.stop)
        except Exception as exc:  # noqa: BLE001
            self.failures.append(exc)
            conn.close()


def _pump(a, b, stop):
    def copy(src, dst):
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threads = [
        threading.Thread(target=copy, args=pair, daemon=True)
        for pair in ((a, b), (b, a))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    a.close()
    b.close()


def read_http_request(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(1)
        if not chunk:
            return data
        data += chunk
    return data


def http_connect_ok(conn, requests):
    request = read_http_request(conn)
    requests.append(request)
    conn.sendall(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: fake\r\n\r\n")
    return request.split(b" ")[1]


def http_connect_requires_auth(conn, requests):
    request = read_http_request(conn)
    requests.append(request)
    if b"Proxy-Authorization: Basic " + base64.b64encode(b"alice:secret") in request:
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        return request.split(b" ")[1]
    conn.sendall(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"
    )
    return None


def http_connect_forbidden(conn, requests):
    requests.append(read_http_request(conn))
    conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
    return None


def http_connect_garbage(conn, requests):
    requests.append(read_http_request(conn))
    conn.sendall(b"not http at all\r\n\r\n")
    return None


def socks5_no_auth(conn, requests):
    greeting = conn.recv(3)
    assert greeting[:2] == b"\x05\x01" and greeting[2] == 0
    conn.sendall(b"\x05\x00")
    return _socks5_request(conn, requests, reply=0)


def socks5_password(conn, requests):
    header = conn.recv(2)
    methods = conn.recv(header[1])
    assert 2 in methods
    conn.sendall(b"\x05\x02")
    version, ulen = conn.recv(2)
    username = conn.recv(ulen)
    (plen,) = conn.recv(1)
    password = conn.recv(plen)
    if (username, password) != (b"bob", b"hunter2"):
        conn.sendall(b"\x01\x01")
        return None
    conn.sendall(b"\x01\x00")
    return _socks5_request(conn, requests, reply=0)


def socks5_refuses(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x05\x00")
    return _socks5_request(conn, requests, reply=5)


def socks5_no_acceptable_method(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x05\xff")
    return None


def _socks5_request(conn, requests, reply):
    head = conn.recv(4)
    assert head[:3] == b"\x05\x01\x00"
    if head[3] == 3:
        (length,) = conn.recv(1)
        host = conn.recv(length).decode()
    elif head[3] == 1:
        host = socket.inet_ntoa(conn.recv(4))
    else:
        host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
    (port,) = struct.unpack("!H", conn.recv(2))
    requests.append((host, port))
    conn.sendall(
        b"\x05" + bytes([reply]) + b"\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00"
    )
    return (host, port) if reply == 0 else None


class EchoServer:
    """A plain TCP target that echoes one message, so tunnels can be verified."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
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
            with conn:
                conn.settimeout(3)
                conn.sendall(conn.recv(64))


def tunnel_roundtrip(proxy_url, target_host, target_port):
    sock = open_connection(target_host, target_port, 3, parse_proxy(proxy_url))
    with sock:
        sock.sendall(b"ping")
        return sock.recv(4)


# --- tunnels -----------------------------------------------------------------------


def test_http_connect_tunnels_to_the_target():
    with (
        EchoServer() as echo,
        FakeProxy(http_connect_ok, ("127.0.0.1", echo.port)) as proxy,
    ):
        assert (
            tunnel_roundtrip(f"http://127.0.0.1:{proxy.port}", "target.test", echo.port)
            == b"ping"
        )
    assert proxy.requests[0].startswith(
        f"CONNECT target.test:{echo.port} HTTP/1.1\r\n".encode()
    )
    assert b"Proxy-Authorization" not in proxy.requests[0]


def test_http_connect_sends_basic_credentials():
    with (
        EchoServer() as echo,
        FakeProxy(http_connect_requires_auth, ("127.0.0.1", echo.port)) as proxy,
    ):
        assert (
            tunnel_roundtrip(
                f"http://alice:secret@127.0.0.1:{proxy.port}", "target.test", echo.port
            )
            == b"ping"
        )
        with pytest.raises(ProxyError, match="407"):
            tunnel_roundtrip(f"http://127.0.0.1:{proxy.port}", "target.test", echo.port)


def test_http_connect_ipv6_target_is_bracketed():
    with FakeProxy(http_connect_forbidden) as proxy:
        with pytest.raises(ProxyError, match="refused CONNECT"):
            tunnel_roundtrip(f"http://127.0.0.1:{proxy.port}", "2001:db8::7", 443)
    assert proxy.requests[0].startswith(b"CONNECT [2001:db8::7]:443 ")


def test_http_connect_rejects_garbage_replies():
    with FakeProxy(http_connect_garbage) as proxy:
        with pytest.raises(ProxyError, match="invalid CONNECT reply"):
            tunnel_roundtrip(f"http://127.0.0.1:{proxy.port}", "target.test", 443)


def test_socks5_without_authentication_tunnels_by_name():
    with (
        EchoServer() as echo,
        FakeProxy(socks5_no_auth, ("127.0.0.1", echo.port)) as proxy,
    ):
        assert (
            tunnel_roundtrip(
                f"socks5://127.0.0.1:{proxy.port}", "target.test", echo.port
            )
            == b"ping"
        )
    assert proxy.requests == [("target.test", echo.port)]


def test_socks5_with_username_and_password():
    with (
        EchoServer() as echo,
        FakeProxy(socks5_password, ("127.0.0.1", echo.port)) as proxy,
    ):
        assert (
            tunnel_roundtrip(
                f"socks5://bob:hunter2@127.0.0.1:{proxy.port}", "target.test", echo.port
            )
            == b"ping"
        )
        with pytest.raises(ProxyError, match="username or password"):
            tunnel_roundtrip(
                f"socks5://bob:wrong@127.0.0.1:{proxy.port}", "target.test", echo.port
            )


@pytest.mark.parametrize("target", ["192.0.2.10", "2001:db8::10"])
def test_socks5_sends_ip_literals_as_addresses(target):
    with (
        EchoServer() as echo,
        FakeProxy(socks5_no_auth, ("127.0.0.1", echo.port)) as proxy,
    ):
        assert (
            tunnel_roundtrip(f"socks5://127.0.0.1:{proxy.port}", target, echo.port)
            == b"ping"
        )
    assert proxy.requests == [(target, echo.port)]


def test_socks5_refusal_and_method_rejection():
    with FakeProxy(socks5_refuses) as proxy:
        with pytest.raises(ProxyError, match="connection refused"):
            tunnel_roundtrip(f"socks5://127.0.0.1:{proxy.port}", "target.test", 443)
    with FakeProxy(socks5_no_acceptable_method) as proxy:
        with pytest.raises(ProxyError, match="none of the offered"):
            tunnel_roundtrip(f"socks5://127.0.0.1:{proxy.port}", "target.test", 443)


def test_proxy_closing_early_is_reported():
    def hang_up(conn, requests):
        conn.close()
        return None

    with FakeProxy(hang_up) as proxy:
        with pytest.raises(ProxyError):
            tunnel_roundtrip(f"socks5://127.0.0.1:{proxy.port}", "target.test", 443)
        with pytest.raises(ProxyError):
            tunnel_roundtrip(f"http://127.0.0.1:{proxy.port}", "target.test", 443)


def test_no_proxy_is_a_direct_connection():
    with EchoServer() as echo:
        with open_connection("127.0.0.1", echo.port, 3, None) as sock:
            sock.sendall(b"ping")
            assert sock.recv(4) == b"ping"


# --- through CertMonitor -----------------------------------------------------


@pytest.fixture
def tls_target(local_pki):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(local_pki / "one.pem", local_pki / "one.key")

    def serve_tls(conn, requests):
        secure = context.wrap_socket(conn, server_side=True)
        return secure

    class TLSTarget(EchoServer):
        def _serve(self):
            while not self.stop.is_set():
                try:
                    conn, _ = self.listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                # One thread per connection: a monitor keeps its collection
                # connection open while the trust handshake and the probe
                # connect, so serving them in turn would starve the later ones.
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

        def _handle(self, conn):
            try:
                conn.settimeout(3)
                secure = context.wrap_socket(conn, server_side=True)
                self.stop.wait(3)
                secure.close()
            except (OSError, ssl.SSLError):
                conn.close()

    with TLSTarget() as target:
        yield target


@pytest.mark.parametrize(
    "scheme,handshake", [("http", http_connect_ok), ("socks5", socks5_no_auth)]
)
def test_monitor_collects_and_verifies_through_a_proxy(
    local_pki, tls_target, scheme, handshake
):
    with FakeProxy(handshake, ("127.0.0.1", tls_target.port)) as proxy:
        with CertMonitor(
            "localhost",
            tls_target.port,
            proxy=f"{scheme}://127.0.0.1:{proxy.port}",
            cafile=str(local_pki / "ca.pem"),
            timeout=3,
            enabled_validators=["hostname", "root_certificate", "pq_key_exchange"],
        ) as monitor:
            results = monitor.validate()
        assert results["hostname"]["is_valid"] is True
        assert results["root_certificate"]["status"] == "pass", results[
            "root_certificate"
        ]
        # The native probe tunnels too and negotiates a real group.
        assert results["pq_key_exchange"]["status"] in ("pass", "fail"), results[
            "pq_key_exchange"
        ]
        assert results["pq_key_exchange"]["kem_name"]
        assert (
            monitor.cert_data["source"]["proxy"] == f"{scheme}://127.0.0.1:{proxy.port}"
        )
    # detection, collection, the verified handshake, and the probe all went through the proxy
    assert len(proxy.requests) >= 4
    assert proxy.failures == []


def test_bad_proxy_url_is_rejected_at_construction():
    with pytest.raises(ValueError, match="unsupported proxy scheme"):
        CertMonitor("host.test", proxy="ftp://proxy.test")


def test_proxy_failure_is_a_connection_error_result():
    with FakeProxy(http_connect_forbidden) as proxy:
        monitor = CertMonitor(
            "host.test", proxy=f"http://127.0.0.1:{proxy.port}", timeout=3
        )
        info = monitor.get_cert_info()
    assert info["error"] == "ConnectionError"
    assert "refused CONNECT" in info["message"]


def test_scan_hosts_and_cli_pass_the_proxy(monkeypatch):
    fake = MagicMock()
    entered = fake.return_value.__enter__.return_value
    entered.validate.return_value = {}
    entered.snapshot_at = entered.fingerprint_sha256 = entered.public_key_info = None
    entered.cert_info = {}
    entered.connection_host = "a.test"
    monkeypatch.setattr(scanning, "CertMonitor", fake)
    list(
        scan_hosts(
            [{"host": "a.test", "proxy": "socks5://p.test"}, "b.test"],
            proxy="http://p.test:3128",
        )
    )
    assert {c.args[0]: c.kwargs["proxy"] for c in fake.call_args_list} == {
        "a.test": "socks5://p.test",
        "b.test": "http://p.test:3128",
    }
    monkeypatch.setattr(cli, "CertMonitor", fake)
    assert (
        cli.main(
            ["check", "c.test", "--proxy", "http://p.test:3128", "--json"],
            out=MagicMock(),
        )
        == 0
    )
    assert fake.call_args.kwargs["proxy"] == "http://p.test:3128"


# --- remaining error branches -----------------------------------------------------


def http_partial_then_close(conn, requests):
    read_http_request(conn)
    conn.sendall(b"HTTP/1.1 200 OK\r\n")
    conn.close()
    return None


def http_endless_line(conn, requests):
    read_http_request(conn)
    conn.sendall(b"H" * 5000)
    conn.close()
    return None


def socks5_close_mid_negotiation(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x05")
    conn.close()
    return None


def socks5_wrong_version(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x04\x00")
    return None


def socks5_gssapi_only(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x05\x01")
    return None


def socks5_bad_reply_version(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x05\x00")
    conn.recv(64)
    conn.sendall(b"\x04\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    return None


def socks5_bad_address_type(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x05\x00")
    conn.recv(64)
    conn.sendall(b"\x05\x00\x00\x09\x00\x00")
    return None


def socks5_binds_ipv6(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x05\x00")
    _socks5_read_request(conn, requests)
    conn.sendall(b"\x05\x00\x00\x04" + b"\x00" * 16 + b"\x00\x00")
    return requests[-1]


def socks5_binds_domain(conn, requests):
    conn.recv(3)
    conn.sendall(b"\x05\x00")
    _socks5_read_request(conn, requests)
    conn.sendall(b"\x05\x00\x00\x03\x05proxy\x00\x00")
    return requests[-1]


def _socks5_read_request(conn, requests):
    head = conn.recv(4)
    assert head[:3] == b"\x05\x01\x00" and head[3] == 3
    (length,) = conn.recv(1)
    host = conn.recv(length).decode()
    (port,) = struct.unpack("!H", conn.recv(2))
    requests.append((host, port))


@pytest.mark.parametrize(
    "scheme,handshake,fragment",
    [
        ("http", http_partial_then_close, "closed the connection during CONNECT"),
        ("http", http_endless_line, "reply line too long"),
        ("socks5", socks5_close_mid_negotiation, "closed the connection during SOCKS5"),
        ("socks5", socks5_wrong_version, "not SOCKS5"),
        ("socks5", socks5_gssapi_only, "unsupported SOCKS5 method"),
        ("socks5", socks5_bad_reply_version, "invalid SOCKS5 reply"),
        ("socks5", socks5_bad_address_type, "invalid SOCKS5 address type"),
    ],
)
def test_malformed_proxy_behaviour_is_reported(scheme, handshake, fragment):
    with FakeProxy(handshake) as proxy:
        with pytest.raises(ProxyError, match=fragment):
            tunnel_roundtrip(f"{scheme}://127.0.0.1:{proxy.port}", "target.test", 443)


@pytest.mark.parametrize("handshake", [socks5_binds_ipv6, socks5_binds_domain])
def test_socks5_bind_address_types_are_consumed(handshake):
    with EchoServer() as echo, FakeProxy(handshake, ("127.0.0.1", echo.port)) as proxy:
        assert (
            tunnel_roundtrip(
                f"socks5://127.0.0.1:{proxy.port}", "target.test", echo.port
            )
            == b"ping"
        )


def test_socks5_rejects_overlong_and_invalid_host_names():
    with FakeProxy(socks5_no_auth) as proxy:
        with pytest.raises(ProxyError, match="too long"):
            tunnel_roundtrip(
                f"socks5://127.0.0.1:{proxy.port}", ("a" * 60 + ".") * 5 + "test", 443
            )
        with pytest.raises(ProxyError, match="not a valid IDNA name"):
            tunnel_roundtrip(
                f"socks5://127.0.0.1:{proxy.port}", "a" * 300 + ".test", 443
            )


def test_non_socket_failures_still_close_the_socket(monkeypatch):
    import certmonitor.protocol_handlers.proxy as proxy_module

    closed = []

    class Recorder:
        def close(self):
            closed.append(True)

    monkeypatch.setattr(
        proxy_module.socket, "create_connection", MagicMock(return_value=Recorder())
    )
    monkeypatch.setattr(
        proxy_module, "_http_connect", MagicMock(side_effect=RuntimeError("boom"))
    )
    with pytest.raises(RuntimeError):
        open_connection("target.test", 443, 1, parse_proxy("http://proxy.test"))
    assert closed == [True]


# --- the native probe tunnels through the proxy too ------------------------------


def _probe_proxy(scheme, proxy, username=None, password=None):
    return (scheme, "127.0.0.1", proxy.port, username, password)


@pytest.mark.parametrize(
    "scheme,handshake,username,password",
    [
        ("http", http_connect_ok, None, None),
        ("http", http_connect_requires_auth, "alice", "secret"),
        ("socks5", socks5_no_auth, None, None),
        ("socks5", socks5_password, "bob", "hunter2"),
    ],
)
def test_native_probe_tunnels_through_the_proxy(
    tls_target, scheme, handshake, username, password
):
    from certmonitor import certinfo

    with FakeProxy(handshake, ("127.0.0.1", tls_target.port)) as proxy:
        result = certinfo.probe_tls_handshake(
            "localhost",
            tls_target.port,
            3000,
            proxy=_probe_proxy(scheme, proxy, username, password),
        )
        assert result["result"] == "group", result
        assert result["name"]
        last = proxy.requests[-1]
        if scheme == "http":
            assert last.startswith(b"CONNECT localhost:%d " % tls_target.port)
        else:
            assert last == ("localhost", tls_target.port)
    assert proxy.failures == []


@pytest.mark.parametrize(
    "scheme,handshake,fragment",
    [
        ("http", http_connect_forbidden, "refused CONNECT"),
        ("http", http_connect_requires_auth, "requires authentication"),
        ("socks5", socks5_refuses, "connection refused"),
        ("socks5", socks5_no_acceptable_method, "accepts none"),
    ],
)
def test_native_probe_reports_proxy_refusals(scheme, handshake, fragment):
    from certmonitor import certinfo

    with FakeProxy(handshake) as proxy:
        result = certinfo.probe_tls_handshake(
            "target.test", 443, 3000, proxy=_probe_proxy(scheme, proxy)
        )
    assert result["result"] == "error"
    assert result["error"] == "ProxyError"
    assert fragment in result["message"]


def test_native_probe_reports_an_unreachable_proxy():
    from certmonitor import certinfo

    result = certinfo.probe_tls_handshake(
        "target.test", 443, 1000, proxy=("http", "127.0.0.1", 9, None, None)
    )
    assert result["error"] == "ProxyError"
    assert "could not reach proxy http://127.0.0.1:9" in result["message"]
