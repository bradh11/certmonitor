// rust_certinfo/src/pem.rs
//
// Minimal PEM helper. The previous implementation pulled in the `base64`
// crate; this replacement uses an inlined RFC 4648 encoder so the crate
// has zero non-pyo3 runtime deps.

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in chunks.by_ref() {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

/// Wrap raw SubjectPublicKeyInfo DER bytes in a PEM block. Output is
/// byte-identical to the previous `extract_public_key_pem` so the
/// differential test passes for non-EC certs and for the SPKI path.
pub fn wrap_spki_pem(spki_der: &[u8]) -> String {
    let encoded = b64_encode(spki_der);
    let wrapped = encoded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 alphabet is ASCII"))
        .collect::<Vec<&str>>()
        .join("\n");
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        wrapped
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_empty() {
        assert_eq!(b64_encode(b""), "");
    }

    #[test]
    fn b64_one_byte() {
        // RFC 4648 §10: "f" → "Zg=="
        assert_eq!(b64_encode(b"f"), "Zg==");
    }

    #[test]
    fn b64_two_bytes() {
        assert_eq!(b64_encode(b"fo"), "Zm8=");
    }

    #[test]
    fn b64_three_bytes() {
        assert_eq!(b64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn b64_long() {
        // "Hello world" → "SGVsbG8gd29ybGQ="
        assert_eq!(b64_encode(b"Hello world"), "SGVsbG8gd29ybGQ=");
    }

    #[test]
    fn pem_wrapping_at_64() {
        // 48 bytes of input → 64 chars of base64 (one full line, no wrap).
        let input = vec![0u8; 48];
        let pem = wrap_spki_pem(&input);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN PUBLIC KEY-----");
        assert_eq!(lines[lines.len() - 1], "-----END PUBLIC KEY-----");
        // Body is exactly one 64-char line
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn pem_wrapping_over_64() {
        let input = vec![0u8; 96];
        let pem = wrap_spki_pem(&input);
        let lines: Vec<&str> = pem.lines().collect();
        assert!(lines[1].len() <= 64);
        assert!(lines[2].len() <= 64);
    }
}
