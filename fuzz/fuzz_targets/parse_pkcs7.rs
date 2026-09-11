// fuzz/fuzz_targets/parse_pkcs7.rs
//
// Fuzz the certs-only PKCS#7 walker. Bundles come from files the user
// hands over and from caIssuers URLs named by a certificate, so they are
// untrusted input. Must never panic; errors are fine.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = certinfo::pkcs7_certificates(data);
});
