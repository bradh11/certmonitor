// rust_certinfo/src/tls/mod.rs
//
// TLS 1.3 handshake building blocks for the post-quantum key-exchange
// probe (#28 / #32). Purely deterministic byte construction and parsing
// — no sockets, no crypto, no PyO3. The networking probe that drives
// these parsers lands separately (`tls/probe.rs`, #33), which is also
// where this module becomes reachable from Python.
//
// Layout follows the issue #28 plan:
//   groups.rs    — IANA Supported Groups registry (contributor data file)
//   records.rs   — TLS record framing (read + write)
//   handshake.rs — ClientHello builder + ServerHello / HRR parser

pub mod groups;
pub mod handshake;
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
