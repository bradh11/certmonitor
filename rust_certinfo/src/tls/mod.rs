// rust_certinfo/src/tls/mod.rs
//
// TLS 1.3 post-quantum key-exchange probe (#28 / #32 / #33). The
// parsers are pure byte construction; `probe.rs` is the only part that
// touches a socket. PyO3 exposure lives in `crate::lib` /
// `crate::pyobj`.
//
// Layout follows the issue #28 plan:
//   key_exchange_groups.rs — IANA Supported Groups registry
//                            (contributor data file)
//   records.rs   — TLS record framing (read + write)
//   handshake.rs — ClientHello builder + ServerHello / HRR parser
//   mlkem_kat.rs — a real ML-KEM-768 KAT public key for the probe share
//   probe.rs     — socket orchestration (the only part that does I/O)

pub mod handshake;
pub mod key_exchange_groups;
pub mod mlkem_kat;
pub mod probe;
pub mod records;

/// Errors from TLS record / handshake parsing. Deliberately separate
/// from `der::ParseError` — different wire format, different failure
/// modes. Every parser path returns `Result`; nothing panics on
/// malformed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsParseError {
    /// Input ended before a length-prefixed field was complete.
    Truncated,
    /// A record claimed a payload longer than RFC 8446 allows.
    RecordTooLong,
    /// First record byte was not the expected ContentType.
    UnexpectedContentType { expected: u8, got: u8 },
    /// Handshake message was not the expected HandshakeType.
    UnexpectedHandshakeType { expected: u8, got: u8 },
    /// Structurally invalid field; the message names the spot.
    Malformed(&'static str),
}

impl std::fmt::Display for TlsParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsParseError::Truncated => write!(f, "input truncated"),
            TlsParseError::RecordTooLong => write!(f, "record payload exceeds RFC 8446 limit"),
            TlsParseError::UnexpectedContentType { expected, got } => {
                write!(f, "unexpected content type: expected {expected}, got {got}")
            }
            TlsParseError::UnexpectedHandshakeType { expected, got } => {
                write!(
                    f,
                    "unexpected handshake type: expected {expected}, got {got}"
                )
            }
            TlsParseError::Malformed(what) => write!(f, "malformed {what}"),
        }
    }
}

impl std::error::Error for TlsParseError {}
