#![no_main]
//! Fuzz SD-JWT VC parsing: neither the combined-format split nor a single disclosure parse may
//! ever panic on arbitrary input. See plan Section 9.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sdjwt::SdJwtVc::parse(s);
        let _ = sdjwt::Disclosure::parse(s);
    }
});
