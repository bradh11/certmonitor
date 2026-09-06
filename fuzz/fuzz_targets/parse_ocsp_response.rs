// fuzz/fuzz_targets/parse_ocsp_response.rs
//
// Fuzz the OCSP response parser. These bytes come from an OCSP responder
// named by a certificate under test, so they are untrusted network input
// exactly like a certificate. Must never panic; errors are fine.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = certinfo::OcspResponse::from_der(data);
});
