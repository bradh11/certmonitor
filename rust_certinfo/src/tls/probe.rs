// rust_certinfo/src/tls/probe.rs
//
// The TLS 1.3 key-exchange probe (#28 / #33): open a TCP connection,
// send one ClientHello that offers a real X25519MLKEM768 key_share,
// read the server's first flight, extract the negotiated (or
// HRR-requested) group, and hang up. No crypto, no key derivation, no
// decryption, no certificate validation — this learns only which group
// the server picks.
//
// Reachability decisions baked in (see issue #28 amendment and the
// live smoke test on #33):
//   - Real precomputed ML-KEM-768 key_share (mlkem_kat.rs): a classical
//     or empty share makes PQ-capable CDNs answer classical or alert.
//   - Per-call ClientHello random (no fixed fingerprint), no CSPRNG dep.
//   - Bounded read (<= READ_CAP) with a read timeout — never block
//     forever, never allocate unboundedly.
//   - Returns a result in EVERY terminal state (success / n/a / error);
//     the only `Err` paths are internal bugs, so the Python layer never
//     needs a try/except around the call.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime};

use crate::tls::handshake::{
    self, build_client_hello, parse_server_hello, ClientHelloParams, ServerHelloSummary,
};
use crate::tls::key_exchange_groups as groups;
use crate::tls::mlkem_kat::MLKEM768_KAT_EK;
use crate::tls::records;

/// Named group codepoints the probe offers, PQ-capable first.
const GROUP_X25519MLKEM768: u16 = 0x11EC;
const GROUP_X25519: u16 = 0x001D;
const GROUP_SECP256R1: u16 = 0x0017;

/// Hard cap on bytes read from the peer before bailing (RFC 8446 record
/// limit plus headroom for a coalesced first flight).
const READ_CAP: usize = 16 * 1024;

/// Outcome of one probe. `kind` mirrors `GroupKind::as_str`
/// ("hybrid_pq", "classical_ecdh", ...) for a negotiated group, or is
/// "n/a" / "error" for the non-negotiation cases. Exactly one shape, so
/// the Python validator and `pyobj` translate it uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// A group was negotiated (ServerHello) or requested (HRR).
    Group {
        id: u16,
        name: String,
        kind: &'static str,
        is_pq: bool,
        protocol: &'static str,
        /// True when learned from a HelloRetryRequest rather than a
        /// completed ServerHello group selection.
        via_hello_retry_request: bool,
    },
    /// Reached a TLS server, but PQ key exchange does not apply (TLS 1.2
    /// or older, or the server sent an alert).
    NotApplicable { reason: String, protocol: String },
    /// Could not get a usable TLS response (connect failure, non-TLS
    /// peer, truncated/garbled response).
    Error { kind: String, message: String },
}

/// Fill 32 bytes of ClientHello random without a CSPRNG dependency.
/// A fixed value would make every probe trivially fingerprintable
/// (the WAF-evasion concern in #28); this is per-call varying, which
/// is all that's needed — the bytes are never used cryptographically.
fn client_random() -> [u8; 32] {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix the clock with the stack address of a local for extra
    // per-call variation, then expand with splitmix64.
    let mut state = nanos ^ (&nanos as *const u64 as u64);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_be_bytes()[..chunk.len()]);
    }
    out
}

/// Build the X25519MLKEM768 client share: the ML-KEM-768 encapsulation
/// key followed by a 32-byte X25519 public key (draft-kwiatkowski-tls-
/// ecdhe-mlkem concatenation order for this group). 1184 + 32 = 1216.
fn x25519mlkem768_share() -> Vec<u8> {
    let mut share = Vec::with_capacity(1216);
    share.extend_from_slice(&MLKEM768_KAT_EK);
    // Any 32 bytes is a valid X25519 u-coordinate (RFC 7748); the probe
    // never completes the exchange, so a fixed filler is fine here.
    share.extend_from_slice(&[0x42u8; 32]);
    share
}

/// SNI must be omitted for IP literals (RFC 6066 forbids them). The
/// caller passes `sni: None` for IPs; this is a guard for hostnames
/// that happen to parse as addresses.
fn sni_for(host: &str) -> Option<&str> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host)
    }
}

/// Run the probe against `host:port`. `timeout` bounds the whole probe
/// (connect + write + read), enforced as a deadline. Never panics.
pub fn probe(host: &str, port: u16, timeout: Duration) -> ProbeResult {
    let deadline = SystemTime::now() + timeout;

    // Resolve and connect to the first address that answers.
    let addrs = match (host, port).to_socket_addrs() {
        Ok(a) => a,
        Err(e) => {
            return ProbeResult::Error {
                kind: "ResolveError".into(),
                message: format!("could not resolve {host}:{port}: {e}"),
            }
        }
    };
    let mut stream = None;
    let mut last_err = String::from("no addresses resolved");
    for addr in addrs {
        let remaining = remaining(deadline);
        if remaining.is_zero() {
            last_err = "timed out before connect".into();
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let mut stream = match stream {
        Some(s) => s,
        None => {
            return ProbeResult::Error {
                kind: "ConnectError".into(),
                message: format!("could not connect to {host}:{port}: {last_err}"),
            }
        }
    };

    let share = x25519mlkem768_share();
    let key_shares: [(u16, &[u8]); 1] = [(GROUP_X25519MLKEM768, &share)];
    let client_hello = build_client_hello(&ClientHelloParams {
        random: client_random(),
        session_id: &random_session_id(),
        sni: sni_for(host),
        offered_groups: &[GROUP_X25519MLKEM768, GROUP_X25519, GROUP_SECP256R1],
        key_shares: &key_shares,
        alpn: &[b"h2", b"http/1.1"],
    });
    let record = records::write_record(records::CONTENT_TYPE_HANDSHAKE, &client_hello);

    if let Err(e) = stream.write_all(&record) {
        return ProbeResult::Error {
            kind: "WriteError".into(),
            message: format!("failed to send ClientHello: {e}"),
        };
    }

    // Read until one complete record is buffered, bounded by READ_CAP
    // and the deadline.
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match records::read_record(&buf) {
            Ok((header, payload, _rest)) => return interpret(header, payload),
            Err(crate::tls::TlsParseError::Truncated) => { /* need more bytes */ }
            Err(e) => {
                return ProbeResult::Error {
                    kind: "ProtocolError".into(),
                    message: format!("not a TLS record: {e}"),
                }
            }
        }
        let remaining = remaining(deadline);
        if remaining.is_zero() {
            return ProbeResult::Error {
                kind: "TimeoutError".into(),
                message: "timed out waiting for ServerHello".into(),
            };
        }
        if let Err(e) = stream.set_read_timeout(Some(remaining)) {
            return ProbeResult::Error {
                kind: "ReadError".into(),
                message: format!("set_read_timeout failed: {e}"),
            };
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                return ProbeResult::Error {
                    kind: "ProtocolError".into(),
                    message: "connection closed before a full record arrived".into(),
                }
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > READ_CAP {
                    return ProbeResult::Error {
                        kind: "ProtocolError".into(),
                        message: format!("response exceeded {READ_CAP} byte cap"),
                    };
                }
            }
            Err(e) => {
                return ProbeResult::Error {
                    kind: "ReadError".into(),
                    message: format!("socket read failed: {e}"),
                }
            }
        }
    }
}

fn random_session_id() -> [u8; 32] {
    // A second independent random fill; servers echo this verbatim.
    client_random()
}

fn remaining(deadline: SystemTime) -> Duration {
    deadline
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
}

/// Turn the first record of the server's flight into a `ProbeResult`.
fn interpret(header: records::RecordHeader, payload: &[u8]) -> ProbeResult {
    match header.content_type {
        records::CONTENT_TYPE_ALERT => {
            let code = payload.get(1).copied().unwrap_or(0);
            ProbeResult::NotApplicable {
                reason: format!("server alert: {code}"),
                protocol: "unknown".into(),
            }
        }
        records::CONTENT_TYPE_HANDSHAKE => interpret_handshake(payload),
        other => ProbeResult::Error {
            kind: "ProtocolError".into(),
            message: format!("unexpected TLS content type {other}"),
        },
    }
}

fn interpret_handshake(payload: &[u8]) -> ProbeResult {
    // The first flight may coalesce several handshake messages into one
    // record; slice out just the first (the ServerHello / HRR).
    if payload.len() < 4 {
        return ProbeResult::Error {
            kind: "ProtocolError".into(),
            message: "handshake record too short".into(),
        };
    }
    let msg_len =
        usize::from(payload[1]) << 16 | usize::from(payload[2]) << 8 | usize::from(payload[3]);
    let end = 4 + msg_len;
    let msg = match payload.get(..end) {
        Some(m) => m,
        None => {
            return ProbeResult::Error {
                kind: "ProtocolError".into(),
                message: "ServerHello split across records".into(),
            }
        }
    };

    let summary = match parse_server_hello(msg) {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult::Error {
                kind: "ProtocolError".into(),
                message: format!("malformed ServerHello: {e}"),
            }
        }
    };
    summarize(summary)
}

fn summarize(summary: ServerHelloSummary) -> ProbeResult {
    // A negotiated TLS 1.3 session echoes supported_versions = 0x0304.
    let is_tls13 = summary.selected_version == Some(handshake::TLS13);
    if !is_tls13 {
        return ProbeResult::NotApplicable {
            reason: "server negotiated TLS 1.2 or older — no PQ KEMs defined".into(),
            protocol: "tls1.2_or_older".into(),
        };
    }

    match summary.key_share_group {
        Some(id) => {
            let (name, kind) = match groups::lookup(id) {
                Some(g) => (g.name.to_string(), g.kind),
                None => (format!("unknown(0x{id:04x})"), groups::GroupKind::Unknown),
            };
            ProbeResult::Group {
                id,
                name,
                kind: kind.as_str(),
                is_pq: kind.is_pq(),
                protocol: "tls1.3",
                via_hello_retry_request: summary.is_hello_retry_request,
            }
        }
        None => ProbeResult::NotApplicable {
            reason: "TLS 1.3 negotiated but no key_share group present".into(),
            protocol: "tls1.3".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_random_varies_between_calls() {
        assert_ne!(client_random(), client_random());
    }

    #[test]
    fn share_is_well_formed() {
        let s = x25519mlkem768_share();
        assert_eq!(s.len(), 1216);
        assert_eq!(&s[..1184], &MLKEM768_KAT_EK[..]);
    }

    #[test]
    fn sni_omitted_for_ip_literals() {
        assert_eq!(sni_for("example.com"), Some("example.com"));
        assert_eq!(sni_for("1.1.1.1"), None);
        assert_eq!(sni_for("2606:4700::1111"), None);
    }

    // ---- interpret() over canned bytes (no socket) --------------------

    fn record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        records::write_record(content_type, payload)
    }

    fn parse_first(bytes: &[u8]) -> ProbeResult {
        let (h, p, _) = records::read_record(bytes).unwrap();
        interpret(h, p)
    }

    /// Minimal ServerHello builder mirroring the handshake.rs test
    /// helper, kept local so the probe owns its fixtures.
    fn server_hello(selected_version: Option<u16>, key_share: Option<(u16, usize)>) -> Vec<u8> {
        fn u16b(o: &mut Vec<u8>, v: u16) {
            o.extend_from_slice(&v.to_be_bytes());
        }
        let mut body = Vec::new();
        u16b(&mut body, handshake::TLS12);
        body.extend_from_slice(&[0x55; 32]); // not the HRR magic
        body.push(0); // empty session id echo
        u16b(&mut body, 0x1301);
        body.push(0);
        let mut exts = Vec::new();
        if let Some(v) = selected_version {
            let mut e = Vec::new();
            u16b(&mut e, v);
            u16b(&mut exts, handshake::EXT_SUPPORTED_VERSIONS);
            u16b(&mut exts, e.len() as u16);
            exts.extend_from_slice(&e);
        }
        if let Some((group, kex_len)) = key_share {
            let mut e = Vec::new();
            u16b(&mut e, group);
            u16b(&mut e, kex_len as u16);
            e.extend(std::iter::repeat_n(0xCC, kex_len));
            u16b(&mut exts, handshake::EXT_KEY_SHARE);
            u16b(&mut exts, e.len() as u16);
            exts.extend_from_slice(&e);
        }
        u16b(&mut body, exts.len() as u16);
        body.extend_from_slice(&exts);
        let mut msg = vec![handshake::HANDSHAKE_TYPE_SERVER_HELLO];
        msg.push((body.len() >> 16) as u8);
        msg.push((body.len() >> 8) as u8);
        msg.push(body.len() as u8);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn hybrid_pq_serverhello_reports_pq() {
        let sh = server_hello(Some(handshake::TLS13), Some((0x11EC, 1120)));
        let rec = record(records::CONTENT_TYPE_HANDSHAKE, &sh);
        match parse_first(&rec) {
            ProbeResult::Group {
                name,
                kind,
                is_pq,
                protocol,
                via_hello_retry_request,
                ..
            } => {
                assert_eq!(name, "X25519MLKEM768");
                assert_eq!(kind, "hybrid_pq");
                assert!(is_pq);
                assert_eq!(protocol, "tls1.3");
                assert!(!via_hello_retry_request);
            }
            other => panic!("expected Group, got {other:?}"),
        }
    }

    #[test]
    fn classical_serverhello_reports_not_pq() {
        let sh = server_hello(Some(handshake::TLS13), Some((0x001D, 32)));
        let rec = record(records::CONTENT_TYPE_HANDSHAKE, &sh);
        match parse_first(&rec) {
            ProbeResult::Group { name, is_pq, .. } => {
                assert_eq!(name, "x25519");
                assert!(!is_pq);
            }
            other => panic!("expected Group, got {other:?}"),
        }
    }

    #[test]
    fn tls12_serverhello_is_not_applicable() {
        // No supported_versions extension => TLS 1.2.
        let sh = server_hello(None, None);
        let rec = record(records::CONTENT_TYPE_HANDSHAKE, &sh);
        match parse_first(&rec) {
            ProbeResult::NotApplicable { protocol, .. } => {
                assert_eq!(protocol, "tls1.2_or_older");
            }
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }

    #[test]
    fn alert_is_not_applicable() {
        let rec = record(records::CONTENT_TYPE_ALERT, &[2, 40]); // handshake_failure
        match parse_first(&rec) {
            ProbeResult::NotApplicable { reason, .. } => assert!(reason.contains("40")),
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }

    #[test]
    fn non_tls_content_type_is_error() {
        let rec = record(records::CONTENT_TYPE_APPLICATION_DATA, b"junk");
        match parse_first(&rec) {
            ProbeResult::Error { kind, .. } => assert_eq!(kind, "ProtocolError"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn connect_failure_is_error_not_panic() {
        // Port 1 on localhost: nothing listening, fast refusal.
        let result = probe("127.0.0.1", 1, Duration::from_millis(500));
        match result {
            ProbeResult::Error { kind, .. } => {
                assert!(
                    kind == "ConnectError" || kind == "TimeoutError",
                    "got {kind}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
