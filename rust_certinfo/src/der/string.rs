// rust_certinfo/src/der/string.rs
//
// Decoders for the ASN.1 string types that show up in X.509 Names.
//
// In practice the public web is dominated by UTF8String and PrintableString.
// IA5String shows up for emailAddress (RFC 1779). TeletexString/T61String,
// BMPString and UniversalString are legacy but still appear in older
// certificates — we accept them rather than crash, but use a conservative
// decode that won't introduce its own parser bugs.

use crate::der::tag;
use crate::error::ParseError;

/// Decode a DER string value to an owned `String` based on its ASN.1 tag.
pub fn parse_string(tag_byte: u8, value: &[u8]) -> Result<String, ParseError> {
    match tag_byte {
        tag::TAG_UTF8_STRING => parse_utf8(value),
        tag::TAG_PRINTABLE_STRING => parse_printable(value),
        tag::TAG_IA5_STRING => parse_ascii(value),
        tag::TAG_TELETEX_STRING => parse_teletex(value),
        tag::TAG_BMP_STRING => parse_bmp(value),
        tag::TAG_UNIVERSAL_STRING => parse_universal(value),
        other => Err(ParseError::UnsupportedStringType(other)),
    }
}

fn parse_utf8(value: &[u8]) -> Result<String, ParseError> {
    core::str::from_utf8(value)
        .map(|s| s.to_string())
        .map_err(|_| ParseError::InvalidString)
}

/// PrintableString: subset of ASCII (A-Z a-z 0-9 plus a small punctuation set).
/// We do not strictly enforce the alphabet — real-world certs occasionally
/// stretch the rules — but we do require valid 7-bit ASCII.
fn parse_printable(value: &[u8]) -> Result<String, ParseError> {
    parse_ascii(value)
}

/// IA5String: 7-bit ASCII (the original IA5 alphabet equals US-ASCII for our
/// purposes).
fn parse_ascii(value: &[u8]) -> Result<String, ParseError> {
    if value.iter().any(|&b| b > 0x7f) {
        return Err(ParseError::InvalidString);
    }
    // Safe: validated as ASCII above.
    Ok(String::from_utf8_lossy(value).into_owned())
}

/// TeletexString / T61String: technically a complex 8-bit encoding, but in
/// practice every cert that uses it stores Latin-1-ish bytes. We pass the
/// bytes through as Latin-1, which is the most common real-world content.
fn parse_teletex(value: &[u8]) -> Result<String, ParseError> {
    Ok(value.iter().map(|&b| b as char).collect())
}

/// BMPString: UCS-2 big-endian (the Unicode Basic Multilingual Plane).
/// 2 bytes per code unit. We only accept code points in the BMP.
fn parse_bmp(value: &[u8]) -> Result<String, ParseError> {
    if !value.len().is_multiple_of(2) {
        return Err(ParseError::InvalidString);
    }
    let mut out = String::with_capacity(value.len() / 2);
    for chunk in value.chunks_exact(2) {
        let code = u16::from_be_bytes([chunk[0], chunk[1]]);
        let ch = char::from_u32(code as u32).ok_or(ParseError::InvalidString)?;
        out.push(ch);
    }
    Ok(out)
}

/// UniversalString: UCS-4 big-endian. 4 bytes per code unit.
fn parse_universal(value: &[u8]) -> Result<String, ParseError> {
    if !value.len().is_multiple_of(4) {
        return Err(ParseError::InvalidString);
    }
    let mut out = String::with_capacity(value.len() / 4);
    for chunk in value.chunks_exact(4) {
        let code = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let ch = char::from_u32(code).ok_or(ParseError::InvalidString)?;
        out.push(ch);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_simple() {
        assert_eq!(
            parse_string(tag::TAG_UTF8_STRING, "example.com".as_bytes()).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn utf8_non_ascii() {
        // "café" with é as U+00E9 in UTF-8
        let bytes = [b'c', b'a', b'f', 0xc3, 0xa9];
        assert_eq!(parse_string(tag::TAG_UTF8_STRING, &bytes).unwrap(), "café");
    }

    #[test]
    fn utf8_invalid() {
        let bad = [b'a', 0xc3, 0x28];
        assert_eq!(
            parse_string(tag::TAG_UTF8_STRING, &bad).unwrap_err(),
            ParseError::InvalidString
        );
    }

    #[test]
    fn printable_string() {
        assert_eq!(
            parse_string(tag::TAG_PRINTABLE_STRING, b"DigiCert Inc").unwrap(),
            "DigiCert Inc"
        );
    }

    #[test]
    fn ia5_string() {
        assert_eq!(
            parse_string(tag::TAG_IA5_STRING, b"foo@example.com").unwrap(),
            "foo@example.com"
        );
    }

    #[test]
    fn bmp_string_ascii() {
        // "AB" as BMPString = 0x00 'A' 0x00 'B'
        let bytes = [0x00, b'A', 0x00, b'B'];
        assert_eq!(parse_string(tag::TAG_BMP_STRING, &bytes).unwrap(), "AB");
    }

    #[test]
    fn bmp_string_odd_length() {
        let bytes = [0x00, b'A', 0x00];
        assert_eq!(
            parse_string(tag::TAG_BMP_STRING, &bytes).unwrap_err(),
            ParseError::InvalidString
        );
    }

    #[test]
    fn universal_string_ascii() {
        // "A" as UniversalString = 0x00 0x00 0x00 'A'
        let bytes = [0x00, 0x00, 0x00, b'A'];
        assert_eq!(
            parse_string(tag::TAG_UNIVERSAL_STRING, &bytes).unwrap(),
            "A"
        );
    }

    #[test]
    fn unsupported_tag() {
        assert_eq!(
            parse_string(0x42, b"x").unwrap_err(),
            ParseError::UnsupportedStringType(0x42)
        );
    }
}
