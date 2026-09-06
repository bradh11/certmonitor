// fuzz/fuzz_targets/parse_crl.rs
//
// Fuzz the CRL parser and its serial lookup. CRLs are fetched from
// distribution points named by the certificate, so they are untrusted
// network input. Must never panic; errors are fine.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(crl) = certinfo::Crl::from_der(data) {
        let _ = crl.revoked_count();
        let probe = &data[..data.len().min(8)];
        let _ = crl.lookup(probe);
    }
});
