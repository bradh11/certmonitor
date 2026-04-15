// rust_certinfo/src/error.rs
//
// All parser errors flow through this single type. Every public function
// in `der/` and `x509/` returns `Result<_, ParseError>` — there are no
// panics on user-supplied bytes. The PyO3 layer in `lib.rs` translates
// `ParseError` to `pyo3::exceptions::PyValueError` exactly as the previous
// `x509_parser` integration did.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Reader hit end-of-input before a structural element finished.
    UnexpectedEof,
    /// A constructed/sequence had bytes left over after the expected fields.
    TrailingBytes,
    /// Tag at this position did not match what the structure required.
    UnexpectedTag { expected: u8, got: u8 },
    /// Indefinite-length encoding is BER-only and forbidden in DER.
    IndefiniteLengthForbidden,
    /// Length used long form when short form would have sufficed, or
    /// long form used more bytes than necessary.
    NonCanonicalLength,
    /// OID bytes did not decode to a valid dotted identifier.
    InvalidOid,
    /// Bytes claimed to be a UTF-8 / ASCII string failed validation.
    InvalidString,
    /// UTCTime / GeneralizedTime did not parse to a real instant.
    InvalidTime,
    /// String tag was outside the set we know how to decode.
    UnsupportedStringType(u8),
    /// A length or count overflowed our usable range.
    IntegerOverflow,
    /// BIT STRING had a non-zero "unused bits" prefix where one is not allowed.
    InvalidBitString,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::TrailingBytes => f.write_str("trailing bytes after expected structure"),
            Self::UnexpectedTag { expected, got } => {
                write!(
                    f,
                    "unexpected tag: expected 0x{:02x}, got 0x{:02x}",
                    expected, got
                )
            }
            Self::IndefiniteLengthForbidden => {
                f.write_str("indefinite-length encoding is forbidden in DER")
            }
            Self::NonCanonicalLength => f.write_str("non-canonical DER length encoding"),
            Self::InvalidOid => f.write_str("invalid OBJECT IDENTIFIER encoding"),
            Self::InvalidString => f.write_str("invalid string encoding"),
            Self::InvalidTime => f.write_str("invalid time encoding"),
            Self::UnsupportedStringType(t) => write!(f, "unsupported string tag 0x{:02x}", t),
            Self::IntegerOverflow => f.write_str("integer overflow"),
            Self::InvalidBitString => f.write_str("invalid BIT STRING encoding"),
        }
    }
}

impl std::error::Error for ParseError {}
