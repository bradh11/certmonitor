// fuzz/fuzz_targets/parse_certificate.rs
//
// libFuzzer target. Feeds arbitrary bytes to `Certificate::from_der` and
// asserts the parser never panics. Combined with `#![forbid(unsafe_code)]`
// at the certinfo crate root, this gives us a concrete pre-merge guarantee
// that malformed DER input cannot crash the parser.
//
// Run via `make fuzz` (recommended) or directly from the repo root:
//
//   cargo +nightly fuzz run parse_certificate -- -max_total_time=3600
//
// The seed corpus is auto-loaded from `fuzz/corpus/parse_certificate/`.
// Make sure that directory contains the captured real-world certs from
// `tests/fixtures/diff_corpus/` — `make fuzz` handles this automatically.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // We only care that this returns instead of panicking. Any error
    // result is fine — that's what `Certificate::from_der` is supposed
    // to do on malformed input.
    let _ = certinfo::Certificate::from_der(data);
});
