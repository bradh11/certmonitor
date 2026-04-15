// rust_certinfo/fuzz/fuzz_targets/parse_certificate.rs
//
// libFuzzer target. Feeds arbitrary bytes to `Certificate::from_der` and
// asserts the parser never panics. Combined with `#![forbid(unsafe_code)]`
// at the certinfo crate root, this gives us a concrete pre-merge guarantee
// that malformed DER input cannot crash the parser.
//
// Run this target manually as a release-time gate; it is not part of CI.
// See ../README.md for the procedure.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // We only care that this returns instead of panicking. Any error
    // result is fine — that's what `Certificate::from_der` is supposed
    // to do on malformed input.
    let _ = certinfo::Certificate::from_der(data);
});
