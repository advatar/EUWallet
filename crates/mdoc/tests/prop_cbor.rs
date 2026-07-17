//! Tier-1 property tests for the canonical-CBOR uint codec (plan Section 9).
use mdoc::cbor::{decode_uint, encode_uint};
use proptest::prelude::*;

proptest! {
    /// Round-trip: decoding a canonical encoding recovers the value and consumes all bytes.
    #[test]
    fn roundtrip(n in any::<u64>()) {
        let enc = encode_uint(n);
        let (v, rest) = decode_uint(&enc).expect("must decode");
        prop_assert_eq!(v, n);
        prop_assert!(rest.is_empty());
    }

    /// Determinism: equal inputs always produce byte-identical encodings.
    #[test]
    fn deterministic(n in any::<u64>()) {
        prop_assert_eq!(encode_uint(n), encode_uint(n));
    }

    /// Robustness: decoding ARBITRARY bytes must never panic (it returns Some or None).
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = decode_uint(&bytes);
    }

    /// Canonicalisation: a non-shortest-form encoding (e.g. 0x18 0x05 for the value 5)
    /// must be rejected, otherwise two encodings of the same value could both be accepted.
    #[test]
    fn rejects_non_canonical(small in 0u8..=23) {
        let non_canonical = vec![0x18, small]; // "1-byte-follows" header for a tiny value
        prop_assert!(decode_uint(&non_canonical).is_none());
    }
}
