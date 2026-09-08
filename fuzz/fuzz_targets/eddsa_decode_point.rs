// fuzz/fuzz_targets/eddsa_decode_point.rs
//
// Fuzz the Edwards point decoder (RFC 8032 §5.1.3, §5.2.3) by feeding
// arbitrary bytes as the public key `A` for both curves, against a fixed
// signature and challenge of the length each curve requires so the length
// checks pass the input through to the decoder, the small-order screen, and
// the group arithmetic. `Ok(false)` and `Err` are both fine; a panic is a
// bug.

#![no_main]

use certinfo::{verify_eddsa, EdCurve};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `A` is decoded before `r` and `s` are looked at, so any fixed
    // signature of the right length reaches the decoder: 32 octets each
    // with a 64-octet challenge for Ed25519 (RFC 8032 §5.1.6)...
    let _ = verify_eddsa(
        EdCurve::Ed25519,
        data,
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 64],
    );
    // ...and 57 octets each with a 114-octet challenge for Ed448 (§5.2.6).
    let _ = verify_eddsa(
        EdCurve::Ed448,
        data,
        &[0x11u8; 57],
        &[0x22u8; 57],
        &[0x33u8; 114],
    );
});
