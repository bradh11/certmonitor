// rust_certinfo/src/der/time.rs
//
// UTCTime and GeneralizedTime decoders. Both encode an instant in UTC.
// We return the Unix timestamp in seconds (i64) — same shape as
// `x509-parser`'s `ASN1Time::timestamp()`.
//
// X.509 (RFC 5280 §4.1.2.5) constrains both forms to a single canonical
// shape: UTCTime is YYMMDDHHMMSSZ (13 ASCII bytes), GeneralizedTime is
// YYYYMMDDHHMMSSZ (15 ASCII bytes). Anything else is rejected.

use crate::der::tag;
use crate::error::ParseError;

/// Dispatch by ASN.1 tag. Most of the parser knows the tag from context
/// and calls `parse_utc_time` or `parse_generalized_time` directly; this
/// helper exists for `Validity` where the field is a CHOICE.
pub fn parse_time(tag_byte: u8, value: &[u8]) -> Result<i64, ParseError> {
    match tag_byte {
        tag::TAG_UTC_TIME => parse_utc_time(value),
        tag::TAG_GENERALIZED_TIME => parse_generalized_time(value),
        other => Err(ParseError::UnexpectedTag {
            expected: tag::TAG_UTC_TIME,
            got: other,
        }),
    }
}

/// UTCTime: YYMMDDHHMMSSZ. Two-digit year is interpreted per RFC 5280
/// §4.1.2.5.1: `YY >= 50` → 19YY, `YY < 50` → 20YY.
pub fn parse_utc_time(value: &[u8]) -> Result<i64, ParseError> {
    if value.len() != 13 || value[12] != b'Z' {
        return Err(ParseError::InvalidTime);
    }
    let year_short = parse_uint(&value[0..2])? as u32;
    let year = if year_short < 50 {
        2000 + year_short
    } else {
        1900 + year_short
    };
    let month = parse_uint(&value[2..4])?;
    let day = parse_uint(&value[4..6])?;
    let hour = parse_uint(&value[6..8])?;
    let minute = parse_uint(&value[8..10])?;
    let second = parse_uint(&value[10..12])?;
    to_unix_secs(year, month, day, hour, minute, second)
}

/// GeneralizedTime: YYYYMMDDHHMMSSZ. RFC 5280 forbids fractional seconds
/// in the X.509 profile, so we don't accept them.
pub fn parse_generalized_time(value: &[u8]) -> Result<i64, ParseError> {
    if value.len() != 15 || value[14] != b'Z' {
        return Err(ParseError::InvalidTime);
    }
    let year = parse_uint(&value[0..4])? as u32;
    let month = parse_uint(&value[4..6])?;
    let day = parse_uint(&value[6..8])?;
    let hour = parse_uint(&value[8..10])?;
    let minute = parse_uint(&value[10..12])?;
    let second = parse_uint(&value[12..14])?;
    to_unix_secs(year, month, day, hour, minute, second)
}

/// Parse a fixed-width run of ASCII digits to an integer.
fn parse_uint(bytes: &[u8]) -> Result<u32, ParseError> {
    let mut value: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(ParseError::InvalidTime);
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as u32))
            .ok_or(ParseError::IntegerOverflow)?;
    }
    Ok(value)
}

/// Convert (Y, M, D, h, m, s) UTC to Unix seconds.
///
/// Hand-rolled to avoid pulling in `chrono`/`time` — we already have to
/// own the parser. Algorithm: count days from 1970-01-01 using the
/// civil-from-days approach, then add seconds.
fn to_unix_secs(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<i64, ParseError> {
    if !(1..=12).contains(&month) {
        return Err(ParseError::InvalidTime);
    }
    if day == 0 || day > days_in_month(year, month) {
        return Err(ParseError::InvalidTime);
    }
    if hour > 23 || minute > 59 || second > 60 {
        // ASN.1 GeneralizedTime allows leap seconds (60) but X.509 does
        // not require us to recognize them as a real instant — we accept
        // and clamp to 59 for the unix timestamp math.
        return Err(ParseError::InvalidTime);
    }

    let days = days_from_civil(year as i32, month as i32, day as i32);
    let unix_days = days - 719468; // days from civil 0000-03-01 to 1970-01-01
    let secs =
        unix_days * 86_400 + (hour as i64) * 3_600 + (minute as i64) * 60 + second.min(59) as i64;
    Ok(secs)
}

/// Howard Hinnant's days_from_civil. Returns the number of days from the
/// civil epoch 0000-03-01 to the given (proleptic Gregorian) date.
/// Reference: http://howardhinnant.github.io/date_algorithms.html
fn days_from_civil(y: i32, m: i32, d: i32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as i64; // [0, 399]
    let doy = ((153 * (m as i64 + if m > 2 { -3 } else { 9 }) + 2) / 5) + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    (era as i64) * 146_097 + doe
}

fn is_leap(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_time_2024_jan_30() {
        // "240130000000Z"
        let v = b"240130000000Z";
        let ts = parse_utc_time(v).unwrap();
        // 2024-01-30T00:00:00Z = 1706572800
        assert_eq!(ts, 1_706_572_800);
    }

    #[test]
    fn generalized_time_2030_mar_01() {
        // "20300301235959Z" = 2030-03-01T23:59:59Z = 1898639999
        let v = b"20300301235959Z";
        assert_eq!(parse_generalized_time(v).unwrap(), 1_898_639_999);
    }

    #[test]
    fn utc_time_century_pivot() {
        // 49 → 2049, 50 → 1950
        assert_eq!(parse_utc_time(b"491231235959Z").unwrap(), 2_524_607_999);
        assert_eq!(parse_utc_time(b"500101000000Z").unwrap(), -631_152_000);
    }

    #[test]
    fn unix_epoch() {
        assert_eq!(parse_utc_time(b"700101000000Z").unwrap(), 0);
    }

    #[test]
    fn leap_year_feb_29() {
        // 2024 is a leap year
        let ts = parse_generalized_time(b"20240229000000Z").unwrap();
        assert_eq!(ts, 1_709_164_800);
        // 2023 is not — Feb 29 should fail
        assert_eq!(
            parse_generalized_time(b"20230229000000Z").unwrap_err(),
            ParseError::InvalidTime
        );
    }

    #[test]
    fn rejects_missing_z() {
        assert_eq!(
            parse_utc_time(b"240130000000X").unwrap_err(),
            ParseError::InvalidTime
        );
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            parse_utc_time(b"24013000Z").unwrap_err(),
            ParseError::InvalidTime
        );
        assert_eq!(
            parse_generalized_time(b"2024013000000Z").unwrap_err(),
            ParseError::InvalidTime
        );
    }

    #[test]
    fn rejects_non_digit() {
        assert_eq!(
            parse_utc_time(b"24x130000000Z").unwrap_err(),
            ParseError::InvalidTime
        );
    }
}
