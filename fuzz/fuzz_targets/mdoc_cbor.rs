#![no_main]
//! Fuzz the canonical-CBOR uint decoder: it must never panic on ANY input, and any input it
//! accepts must re-encode to the exact bytes it consumed (canonical-form stability).
//! See plan Section 9. Seed the corpus with official ISO 18013-5 test vectors.
use libfuzzer_sys::fuzz_target;
use mdoc::cbor::{decode_uint, encode_uint};

fuzz_target!(|data: &[u8]| {
    if let Some((value, rest)) = decode_uint(data) {
        let consumed = data.len() - rest.len();
        // What we accepted must be exactly the canonical encoding of the value.
        assert_eq!(encode_uint(value), &data[..consumed]);
    }
});
