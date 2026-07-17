//! Certification-oriented tests for the canonical CBOR codec (plan Section 4.2.3 / Section 9):
//! round-trip, canonicalization enforcement, and never-panic on malformed input.
use cose::cbor::{decode_value, from_canonical_slice, write_head, CborError, Value};
use proptest::prelude::*;

/// A recursive proptest strategy generating arbitrary (bounded) CBOR values.
fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Uint),
        any::<u64>().prop_map(Value::Nint),
        proptest::collection::vec(any::<u8>(), 0..20).prop_map(Value::Bytes),
        "[a-z0-9 ]{0,20}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            proptest::collection::vec((inner.clone(), inner.clone()), 0..5).prop_map(Value::Map),
            (0u64..40, inner).prop_map(|(t, v)| Value::Tag(t, Box::new(v))),
        ]
    })
}

/// Two values are "canonically equal" if they encode identically. Map key order and duplicate
/// keys differ from the input after canonicalization, so we compare via the canonical bytes.
fn canon_eq(a: &Value, b: &Value) -> bool {
    a.to_canonical() == b.to_canonical()
}

proptest! {
    /// Round-trip: encoding then decoding yields a canonically-equal value.
    #[test]
    fn roundtrip(v in arb_value()) {
        let bytes = v.to_canonical();
        let decoded = from_canonical_slice(&bytes).expect("canonical bytes must decode");
        prop_assert!(canon_eq(&v, &decoded), "roundtrip mismatch: {:?} vs {:?}", v, decoded);
    }

    /// Encoding is deterministic and idempotent: re-encoding a decoded value is a fixed point.
    #[test]
    fn encode_is_stable_fixed_point(v in arb_value()) {
        let once = v.to_canonical();
        let decoded = from_canonical_slice(&once).unwrap();
        prop_assert_eq!(once, decoded.to_canonical());
    }

    /// Robustness: decoding ARBITRARY bytes must never panic — Ok or Err, never a crash.
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        let _ = from_canonical_slice(&bytes);
        let _ = decode_value(&bytes, 0);
    }
}

#[test]
fn rejects_indefinite_length_array() {
    // 0x9f = array(*) indefinite. Must be rejected.
    assert_eq!(
        from_canonical_slice(&[0x9f, 0x01, 0xff]),
        Err(CborError::IndefiniteLength)
    );
}

#[test]
fn rejects_non_shortest_integer() {
    // 0x18 0x05 encodes 5 in 1 extra byte (shortest would be 0x05).
    assert_eq!(
        from_canonical_slice(&[0x18, 0x05]),
        Err(CborError::NotShortestForm)
    );
}

#[test]
fn rejects_trailing_bytes() {
    // A valid `0` (0x00) followed by junk.
    assert_eq!(
        from_canonical_slice(&[0x00, 0x00]),
        Err(CborError::TrailingBytes)
    );
}

#[test]
fn rejects_out_of_order_map_keys() {
    // map(2) with keys 2 then 1 — not canonically sorted.
    // {2: 0, 1: 0} on the wire: a2 02 00 01 00
    assert_eq!(
        from_canonical_slice(&[0xa2, 0x02, 0x00, 0x01, 0x00]),
        Err(CborError::MapKeysNotSorted)
    );
}

#[test]
fn rejects_duplicate_map_keys() {
    // map(2) with key 1 twice: a2 01 00 01 00
    assert_eq!(
        from_canonical_slice(&[0xa2, 0x01, 0x00, 0x01, 0x00]),
        Err(CborError::DuplicateMapKey)
    );
}

#[test]
fn map_encoding_sorts_keys_canonically() {
    // Build a map with keys deliberately out of order; encoding must sort them.
    let m = Value::Map(vec![
        (Value::Uint(2), Value::Uint(0)),
        (Value::Uint(1), Value::Uint(0)),
    ]);
    // Canonical order is key 1 then key 2: a2 01 00 02 00
    assert_eq!(m.to_canonical(), vec![0xa2, 0x01, 0x00, 0x02, 0x00]);
    // And it now decodes cleanly (keys in order).
    assert!(from_canonical_slice(&m.to_canonical()).is_ok());
}

#[test]
fn tag24_embedded_cbor_roundtrips() {
    // Tag 24 wraps a byte string of embedded CBOR — the pattern used for MSO/IssuerSignedItem.
    let inner = Value::Array(vec![Value::Text("mso".into()), Value::Uint(1)]);
    let tagged = Value::Tag(24, Box::new(Value::Bytes(inner.to_canonical())));
    let bytes = tagged.to_canonical();
    assert_eq!(from_canonical_slice(&bytes).unwrap(), tagged);
}

#[test]
fn write_head_matches_major_and_shortest_form() {
    let mut out = Vec::new();
    write_head(&mut out, 2, 300); // bstr length 300 → 0x59 0x01 0x2c
    assert_eq!(out, vec![0x59, 0x01, 0x2c]);
}
