#![no_main]
//! Fuzz X.509 certificate parsing: must never panic on arbitrary DER bytes. See plan Section 9.
//! Seed the corpus with the tests/vectors/*.der certificates.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = x509::parse_cert(data);
});
