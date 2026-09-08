// fuzz/fuzz_targets/eddsa_decode_point.rs
//
// Fuzz the Edwards point decoder (RFC 8032 §5.1.3, §5.2.3) by feeding
// arbitrary bytes as both the public key `A` and the signature's `R` for
// both curves, against a fixed `s` and challenge of the length each curve
// requires so the length checks pass the input through to the decoder, the
// small-order screen, and the group arithmetic. `Ok(false)` and `Err` are
// both fine; a panic is a bug.

#![no_main]

use certinfo::{verify_eddsa, EdCurve};
use libfuzzer_sys::fuzz_target;

/// `len` bytes starting at `start` in `data`, zero-padded if `data` runs out.
fn take(data: &[u8], start: usize, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    if let Some(rest) = data.get(start..) {
        let n = rest.len().min(len);
        buf[..n].copy_from_slice(&rest[..n]);
    }
    buf
}

fuzz_target!(|data: &[u8]| {
    // `A` is decoded before `R`, so the first half of `data` becomes `A` and
    // the second half becomes `R`; both reach the decoder. 32 octets each
    // with a 64-octet challenge for Ed25519 (RFC 8032 §5.1.6)...
    let _ = verify_eddsa(
        EdCurve::Ed25519,
        &take(data, 0, 32),
        &take(data, 32, 32),
        &[0x22u8; 32],
        &[0x33u8; 64],
    );
    // ...and 57 octets each with a 114-octet challenge for Ed448 (§5.2.6).
    let _ = verify_eddsa(
        EdCurve::Ed448,
        &take(data, 0, 57),
        &take(data, 57, 57),
        &[0x22u8; 57],
        &[0x33u8; 114],
    );
});
