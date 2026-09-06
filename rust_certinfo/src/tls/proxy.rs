// rust_certinfo/src/tls/proxy.rs
//
// Outbound proxies for the PQ probe, mirroring
// certmonitor/protocol_handlers/proxy.py: an HTTP CONNECT tunnel (with
// basic authentication) or SOCKS5 (RFC 1928, with RFC 1929 username and
// password). `connect` returns a TcpStream positioned exactly where a
// direct connection to the target would be, ready for a STARTTLS preamble
// or the ClientHello. Every read and write is bounded by the probe's
// deadline. Standard library only.

use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Instant;

use crate::tls::wire;

const WHAT: &str = "proxy negotiation";

/// A parsed proxy, as `certmonitor.protocol_handlers.proxy.ProxyConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Proxy {
    /// The proxy URL without its password, safe for error messages.
    pub fn redacted(&self) -> String {
        let auth = self
            .username
            .as_ref()
            .map(|u| format!("{u}@"))
            .unwrap_or_default();
        format!(
            "{}://{}{}:{}",
            self.scheme,
            auth,
            bracketed(&self.host),
            self.port
        )
    }
}

fn bracketed(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Resolve `host:port` and connect to the first address that answers
/// before `deadline`. The error carries a kind ("ResolveError" or
/// "ConnectError") and a message.
pub fn connect_direct(
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<TcpStream, (String, String)> {
    let addrs = match (host, port).to_socket_addrs() {
        Ok(a) => a,
        Err(e) => {
            return Err((
                "ResolveError".into(),
                format!("could not resolve {host}:{port}: {e}"),
            ))
        }
    };
    let mut last_err = String::from("no addresses resolved");
    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last_err = "timed out before connect".into();
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err((
        "ConnectError".into(),
        format!("could not connect to {host}:{port}: {last_err}"),
    ))
}

/// Connect to `proxy` and open a tunnel to `host:port` through it.
pub fn connect(
    proxy: &Proxy,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<TcpStream, String> {
    let mut stream = connect_direct(&proxy.host, proxy.port, deadline)
        .map_err(|(_, message)| format!("could not reach proxy {}: {message}", proxy.redacted()))?;
    match proxy.scheme.as_str() {
        "http" => http_connect(&mut stream, host, port, proxy, deadline)?,
        "socks5" => socks5_connect(&mut stream, host, port, proxy, deadline)?,
        other => return Err(format!("unsupported proxy scheme {other:?}")),
    }
    Ok(stream)
}

// --- HTTP CONNECT ------------------------------------------------------------

fn http_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    proxy: &Proxy,
    deadline: Instant,
) -> Result<(), String> {
    let target = format!("{}:{port}", bracketed(host));
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(username) = &proxy.username {
        let credentials = format!("{username}:{}", proxy.password.as_deref().unwrap_or(""));
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(credentials.as_bytes())
        ));
    }
    request.push_str("\r\n");
    wire::send(stream, request.as_bytes(), deadline, WHAT)?;

    let status = wire::read_line(stream, deadline, WHAT)?;
    let mut parts = status.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().and_then(|c| c.parse::<u16>().ok());
    let code = match code {
        Some(code) if version.starts_with("HTTP/") => code,
        _ => return Err(format!("proxy sent an invalid CONNECT reply: {status:?}")),
    };
    // Drain the headers up to the blank line so the tunnel starts clean.
    while !wire::read_line(stream, deadline, WHAT)?.is_empty() {}
    if code == 407 {
        return Err("proxy requires authentication (407)".into());
    }
    if !(200..300).contains(&code) {
        return Err(format!("proxy refused CONNECT to {target}: {status}"));
    }
    Ok(())
}

/// Standard base64 with padding, enough for one `Proxy-Authorization` header.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

// --- SOCKS5 (RFC 1928, RFC 1929) ----------------------------------------------

fn socks5_error(code: u8) -> String {
    match code {
        1 => "general SOCKS server failure".into(),
        2 => "connection not allowed by ruleset".into(),
        3 => "network unreachable".into(),
        4 => "host unreachable".into(),
        5 => "connection refused".into(),
        6 => "TTL expired".into(),
        7 => "command not supported".into(),
        8 => "address type not supported".into(),
        other => format!("reply code {other}"),
    }
}

fn socks5_destination(host: &str) -> Result<Vec<u8>, String> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(match address {
            IpAddr::V4(v4) => {
                let mut out = vec![0x01];
                out.extend_from_slice(&v4.octets());
                out
            }
            IpAddr::V6(v6) => {
                let mut out = vec![0x04];
                out.extend_from_slice(&v6.octets());
                out
            }
        });
    }
    if !host.is_ascii() {
        return Err(format!(
            "target host name {host:?} must be given in IDNA (ASCII) form for SOCKS5"
        ));
    }
    if host.len() > 255 {
        return Err("target host name too long for SOCKS5".into());
    }
    let mut out = vec![0x03, host.len() as u8];
    out.extend_from_slice(host.as_bytes());
    Ok(out)
}

fn socks5_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    proxy: &Proxy,
    deadline: Instant,
) -> Result<(), String> {
    let methods: &[u8] = if proxy.username.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(methods);
    wire::send(stream, &greeting, deadline, WHAT)?;
    let choice = wire::read_exact(stream, 2, deadline, WHAT)?;
    if choice[0] != 5 {
        return Err(format!("proxy is not SOCKS5 (version byte {})", choice[0]));
    }
    match choice[1] {
        0x00 => {}
        0x02 => {
            let username = proxy.username.as_deref().unwrap_or("").as_bytes();
            let password = proxy.password.as_deref().unwrap_or("").as_bytes();
            let mut auth = vec![0x01, username.len() as u8];
            auth.extend_from_slice(username);
            auth.push(password.len() as u8);
            auth.extend_from_slice(password);
            wire::send(stream, &auth, deadline, WHAT)?;
            let status = wire::read_exact(stream, 2, deadline, WHAT)?;
            if status[1] != 0 {
                return Err("proxy rejected the SOCKS5 username or password".into());
            }
        }
        0xFF => {
            return Err("proxy accepts none of the offered SOCKS5 authentication methods".into())
        }
        other => {
            return Err(format!(
                "proxy chose an unsupported SOCKS5 method ({other})"
            ))
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    request.extend_from_slice(&socks5_destination(host)?);
    request.extend_from_slice(&port.to_be_bytes());
    wire::send(stream, &request, deadline, WHAT)?;
    let head = wire::read_exact(stream, 4, deadline, WHAT)?;
    if head[0] != 5 {
        return Err("proxy sent an invalid SOCKS5 reply".into());
    }
    match head[3] {
        0x01 => {
            wire::read_exact(stream, 4 + 2, deadline, WHAT)?;
        }
        0x04 => {
            wire::read_exact(stream, 16 + 2, deadline, WHAT)?;
        }
        0x03 => {
            let length = wire::read_exact(stream, 1, deadline, WHAT)?[0] as usize;
            wire::read_exact(stream, length + 2, deadline, WHAT)?;
        }
        _ => return Err("proxy sent an invalid SOCKS5 address type".into()),
    }
    if head[1] != 0 {
        return Err(format!(
            "proxy refused the SOCKS5 connection to {host}:{port}: {}",
            socks5_error(head[1])
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn serve<F>(handler: F) -> u16
    where
        F: FnOnce(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handler(stream);
            }
        });
        port
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn proxy(scheme: &str, port: u16, username: Option<&str>, password: Option<&str>) -> Proxy {
        Proxy {
            scheme: scheme.into(),
            host: "127.0.0.1".into(),
            port,
            username: username.map(str::to_string),
            password: password.map(str::to_string),
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut byte = [0u8; 1];
        while !data.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap() == 0 {
                break;
            }
            data.push(byte[0]);
        }
        String::from_utf8(data).unwrap()
    }

    fn read_exact(stream: &mut TcpStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).unwrap();
        buf
    }

    fn tunnel_carries(mut stream: TcpStream) {
        let mut hello = [0u8; 5];
        stream.read_exact(&mut hello).unwrap();
        assert_eq!(&hello, b"hello");
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"alice:secret"), "YWxpY2U6c2VjcmV0");
    }

    #[test]
    fn redacted_url_drops_the_password() {
        let p = Proxy {
            scheme: "socks5".into(),
            host: "::1".into(),
            port: 1080,
            username: Some("bob".into()),
            password: Some("hunter2".into()),
        };
        assert_eq!(p.redacted(), "socks5://bob@[::1]:1080");
    }

    #[test]
    fn http_connect_with_credentials_positions_the_tunnel_after_the_headers() {
        let port = serve(|mut s| {
            let request = read_http_request(&mut s);
            assert!(request.starts_with("CONNECT target.test:8443 HTTP/1.1\r\n"));
            assert!(request.contains("Host: target.test:8443\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n"));
            s.write_all(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: fake\r\n\r\nhello")
                .unwrap();
        });
        let stream = connect(
            &proxy("http", port, Some("alice"), Some("secret")),
            "target.test",
            8443,
            deadline(),
        )
        .unwrap();
        tunnel_carries(stream);
    }

    #[test]
    fn http_connect_brackets_ipv6_targets() {
        let port = serve(|mut s| {
            let request = read_http_request(&mut s);
            assert!(request.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
            assert!(!request.contains("Proxy-Authorization"));
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        });
        connect(
            &proxy("http", port, None, None),
            "2001:db8::1",
            443,
            deadline(),
        )
        .unwrap();
    }

    #[test]
    fn http_connect_refusals_are_reported() {
        for (reply, fragment) in [
            (
                &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
                "requires authentication",
            ),
            (&b"HTTP/1.1 403 Forbidden\r\n\r\n"[..], "refused CONNECT"),
            (&b"not http at all\r\n\r\n"[..], "invalid CONNECT reply"),
        ] {
            let port = serve(move |mut s| {
                read_http_request(&mut s);
                s.write_all(reply).unwrap();
            });
            let err =
                connect(&proxy("http", port, None, None), "t.test", 443, deadline()).unwrap_err();
            assert!(err.contains(fragment), "{err}");
        }
    }

    #[test]
    fn socks5_without_authentication_sends_the_name() {
        let port = serve(|mut s| {
            assert_eq!(read_exact(&mut s, 3), [0x05, 0x01, 0x00]);
            s.write_all(&[0x05, 0x00]).unwrap();
            let head = read_exact(&mut s, 4);
            assert_eq!(head, [0x05, 0x01, 0x00, 0x03]);
            let len = read_exact(&mut s, 1)[0] as usize;
            assert_eq!(read_exact(&mut s, len), b"target.test");
            assert_eq!(read_exact(&mut s, 2), 8443u16.to_be_bytes());
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            s.write_all(b"hello").unwrap();
        });
        let stream = connect(
            &proxy("socks5", port, None, None),
            "target.test",
            8443,
            deadline(),
        )
        .unwrap();
        tunnel_carries(stream);
    }

    #[test]
    fn socks5_with_password_and_ip_literals() {
        let port = serve(|mut s| {
            assert_eq!(read_exact(&mut s, 4), [0x05, 0x02, 0x00, 0x02]);
            s.write_all(&[0x05, 0x02]).unwrap();
            assert_eq!(read_exact(&mut s, 2), [0x01, 3]);
            assert_eq!(read_exact(&mut s, 3), b"bob");
            assert_eq!(read_exact(&mut s, 1), [7]);
            assert_eq!(read_exact(&mut s, 7), b"hunter2");
            s.write_all(&[0x01, 0x00]).unwrap();
            assert_eq!(read_exact(&mut s, 4), [0x05, 0x01, 0x00, 0x01]);
            assert_eq!(read_exact(&mut s, 4), [192, 0, 2, 10]);
            assert_eq!(read_exact(&mut s, 2), 443u16.to_be_bytes());
            // Reply with a domain-name bound address to exercise that branch.
            s.write_all(&[0x05, 0x00, 0x00, 0x03, 4, b'p', b'r', b'x', b'y', 0, 0])
                .unwrap();
            s.write_all(b"hello").unwrap();
        });
        let stream = connect(
            &proxy("socks5", port, Some("bob"), Some("hunter2")),
            "192.0.2.10",
            443,
            deadline(),
        )
        .unwrap();
        tunnel_carries(stream);
    }

    #[test]
    fn socks5_ipv6_target_and_reply() {
        let port = serve(|mut s| {
            read_exact(&mut s, 3);
            s.write_all(&[0x05, 0x00]).unwrap();
            assert_eq!(read_exact(&mut s, 4), [0x05, 0x01, 0x00, 0x04]);
            let octets = read_exact(&mut s, 16);
            assert_eq!(octets[..4], [0x20, 0x01, 0x0d, 0xb8]);
            read_exact(&mut s, 2);
            let mut reply = vec![0x05, 0x00, 0x00, 0x04];
            reply.extend_from_slice(&[0u8; 18]);
            s.write_all(&reply).unwrap();
        });
        connect(
            &proxy("socks5", port, None, None),
            "2001:db8::1",
            443,
            deadline(),
        )
        .unwrap();
    }

    #[test]
    fn socks5_refusals_are_reported() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0x05, 0xff], "accepts none"),
            (vec![0x04, 0x00], "not SOCKS5"),
            (vec![0x05, 0x01], "unsupported SOCKS5 method"),
        ];
        for (choice, fragment) in cases {
            let port = serve(move |mut s| {
                read_exact(&mut s, 3);
                s.write_all(&choice).unwrap();
            });
            let err = connect(
                &proxy("socks5", port, None, None),
                "t.test",
                443,
                deadline(),
            )
            .unwrap_err();
            assert!(err.contains(fragment), "{err}");
        }

        let port = serve(|mut s| {
            read_exact(&mut s, 3);
            s.write_all(&[0x05, 0x00]).unwrap();
            let len = read_exact(&mut s, 5)[4] as usize;
            read_exact(&mut s, len + 2);
            s.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });
        let err = connect(
            &proxy("socks5", port, None, None),
            "t.test",
            443,
            deadline(),
        )
        .unwrap_err();
        assert!(err.contains("connection refused"), "{err}");

        let port = serve(|mut s| {
            read_exact(&mut s, 4);
            s.write_all(&[0x05, 0x02]).unwrap();
            let ulen = read_exact(&mut s, 2)[1] as usize;
            read_exact(&mut s, ulen);
            let plen = read_exact(&mut s, 1)[0] as usize;
            read_exact(&mut s, plen);
            s.write_all(&[0x01, 0x01]).unwrap();
        });
        let err = connect(
            &proxy("socks5", port, Some("bob"), Some("wrong")),
            "t.test",
            443,
            deadline(),
        )
        .unwrap_err();
        assert!(err.contains("rejected the SOCKS5 username"), "{err}");

        let port = serve(|mut s| {
            read_exact(&mut s, 3);
            s.write_all(&[0x05, 0x00]).unwrap();
            let len = read_exact(&mut s, 5)[4] as usize;
            read_exact(&mut s, len + 2);
            s.write_all(&[0x05, 0x00, 0x00, 0x09]).unwrap();
        });
        let err = connect(
            &proxy("socks5", port, None, None),
            "t.test",
            443,
            deadline(),
        )
        .unwrap_err();
        assert!(err.contains("invalid SOCKS5 address type"), "{err}");
    }

    #[test]
    fn socks5_rejects_names_it_cannot_send() {
        assert!(socks5_destination("bücher.test")
            .unwrap_err()
            .contains("IDNA"));
        assert!(socks5_destination(&"a".repeat(256))
            .unwrap_err()
            .contains("too long"));
    }

    #[test]
    fn unreachable_proxy_and_unknown_scheme_are_errors() {
        let err = connect(&proxy("http", 1, None, None), "t.test", 443, deadline()).unwrap_err();
        assert!(
            err.contains("could not reach proxy http://127.0.0.1:1"),
            "{err}"
        );
        let port = serve(|_s| {});
        let err = connect(
            &proxy("gopher", port, None, None),
            "t.test",
            443,
            deadline(),
        )
        .unwrap_err();
        assert!(err.contains("unsupported proxy scheme"), "{err}");
    }
}
