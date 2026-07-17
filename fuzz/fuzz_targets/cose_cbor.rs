#![no_main]
//! Fuzz the canonical CBOR decoder: it must never panic on ANY input, and anything it accepts
//! must re-encode to the exact bytes it was decoded from (canonical-form stability).
//! Seed the corpus with ISO 18013-5 Annex D vectors. See plan Section 9.
use cose::cbor::from_canonical_slice;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = from_canonical_slice(data) {
        // If it decoded as canonical, re-encoding must reproduce the input exactly.
        assert_eq!(value.to_canonical(), data);
    }
});
