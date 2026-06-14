// rust_certinfo/src/tls/records.rs
//
// TLS record framing (RFC 8446 §5.1):
//
//     struct {
//         ContentType type;            // 1 byte
//         ProtocolVersion legacy_record_version;  // 2 bytes
//         uint16 length;
//         opaque fragment[TLSPlaintext.length];
//     } TLSPlaintext;
//
// Reading is bounded: a record claiming more than `MAX_RECORD_PAYLOAD`
// is rejected before any allocation, which is what lets the probe (#33)
// cap reads against hostile peers.

use crate::tls::TlsParseError;

pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

/// Plaintext record payloads are capped at 2^14 bytes (RFC 8446 §5.1).
pub const MAX_RECORD_PAYLOAD: usize = 16384;
pub const RECORD_HEADER_LEN: usize = 5;

/// `legacy_record_version` value real clients send for the initial
/// ClientHello (TLS 1.0, for middlebox compatibility — RFC 8446 §5.1).
pub const LEGACY_RECORD_VERSION: u16 = 0x0301;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub content_type: u8,
    pub legacy_version: u16,
    pub payload_len: usize,
}

/// Parse the 5-byte record header at the front of `bytes`.
pub fn parse_record_header(bytes: &[u8]) -> Result<RecordHeader, TlsParseError> {
    if bytes.len() < RECORD_HEADER_LEN {
        return Err(TlsParseError::Truncated);
    }
    let payload_len = usize::from(bytes[3]) << 8 | usize::from(bytes[4]);
    if payload_len > MAX_RECORD_PAYLOAD {
        return Err(TlsParseError::RecordTooLong);
    }
    Ok(RecordHeader {
        content_type: bytes[0],
        legacy_version: u16::from(bytes[1]) << 8 | u16::from(bytes[2]),
        payload_len,
    })
}

/// Split one complete record off the front of `bytes`, returning the
/// header, its payload, and the remaining bytes.
pub fn read_record(bytes: &[u8]) -> Result<(RecordHeader, &[u8], &[u8]), TlsParseError> {
    let header = parse_record_header(bytes)?;
    let end = RECORD_HEADER_LEN + header.payload_len;
    if bytes.len() < end {
        return Err(TlsParseError::Truncated);
    }
    Ok((header, &bytes[RECORD_HEADER_LEN..end], &bytes[end..]))
}

/// Frame `payload` as a single plaintext record. Callers only frame
/// messages they built themselves; a ClientHello is well under the
/// record cap.
pub fn write_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_RECORD_PAYLOAD);
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    out.push(content_type);
    out.extend_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_roundtrip() {
        let framed = write_record(CONTENT_TYPE_HANDSHAKE, b"hello");
        let (header, payload, rest) = read_record(&framed).unwrap();
        assert_eq!(header.content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(header.legacy_version, LEGACY_RECORD_VERSION);
        assert_eq!(payload, b"hello");
        assert!(rest.is_empty());
    }

    #[test]
    fn two_records_split_correctly() {
        let mut framed = write_record(CONTENT_TYPE_HANDSHAKE, b"first");
        framed.extend(write_record(CONTENT_TYPE_ALERT, &[2, 40]));
        let (h1, p1, rest) = read_record(&framed).unwrap();
        assert_eq!(h1.content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(p1, b"first");
        let (h2, p2, rest2) = read_record(rest).unwrap();
        assert_eq!(h2.content_type, CONTENT_TYPE_ALERT);
        assert_eq!(p2, &[2, 40]);
        assert!(rest2.is_empty());
    }

    #[test]
    fn truncated_header_rejected() {
        for n in 0..RECORD_HEADER_LEN {
            assert_eq!(
                parse_record_header(&vec![22u8; n]),
                Err(TlsParseError::Truncated)
            );
        }
    }

    #[test]
    fn truncated_payload_rejected() {
        let framed = write_record(CONTENT_TYPE_HANDSHAKE, b"hello");
        assert_eq!(
            read_record(&framed[..framed.len() - 1]),
            Err(TlsParseError::Truncated)
        );
    }

    #[test]
    fn oversized_record_rejected() {
        // Header claims 0x4001 = 16385 bytes — one past the cap.
        let bytes = [CONTENT_TYPE_HANDSHAKE, 0x03, 0x01, 0x40, 0x01];
        assert_eq!(
            parse_record_header(&bytes),
            Err(TlsParseError::RecordTooLong)
        );
    }

    #[test]
    fn max_size_record_accepted() {
        let payload = vec![0u8; MAX_RECORD_PAYLOAD];
        let framed = write_record(CONTENT_TYPE_HANDSHAKE, &payload);
        let (header, parsed, _) = read_record(&framed).unwrap();
        assert_eq!(header.payload_len, MAX_RECORD_PAYLOAD);
        assert_eq!(parsed.len(), MAX_RECORD_PAYLOAD);
    }
}
