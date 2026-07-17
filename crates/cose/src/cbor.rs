//! Canonical (deterministic) CBOR primitives — RFC 8949 §4.2.
//!
//! This lives in `cose` (not `mdoc`) because COSE is defined in terms of CBOR and `mdoc`
//! depends on `cose`; putting it here avoids a dependency cycle (plan Section 4). `mdoc`
//! re-exports it as `mdoc::cbor`, so existing call sites and the Tier-1 harness are unchanged.

/// Encode a `u64` as a canonical CBOR unsigned integer (major type 0), shortest form.
pub fn encode_uint(n: u64) -> Vec<u8> {
    if n <= 23 {
        vec![n as u8]
    } else if n <= u8::MAX as u64 {
        vec![0x18, n as u8]
    } else if n <= u16::MAX as u64 {
        let b = (n as u16).to_be_bytes();
        vec![0x19, b[0], b[1]]
    } else if n <= u32::MAX as u64 {
        let b = (n as u32).to_be_bytes();
        let mut v = vec![0x1a];
        v.extend_from_slice(&b);
        v
    } else {
        let b = n.to_be_bytes();
        let mut v = vec![0x1b];
        v.extend_from_slice(&b);
        v
    }
}

/// Decode a CBOR unsigned integer (major type 0) from the front of `bytes`.
/// Returns the value and the remaining bytes. Never panics on malformed input —
/// it returns `None`. Enforces canonical (shortest-form) encoding: a non-shortest
/// encoding is rejected, which is required for deterministic credential comparison.
pub fn decode_uint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    // Major type must be 0 (top 3 bits == 000).
    if first >> 5 != 0 {
        return None;
    }
    let info = first & 0x1f;
    match info {
        0..=23 => Some((info as u64, rest)),
        24 => {
            let (&b, rest) = rest.split_first()?;
            if b <= 23 {
                return None; // not shortest form
            }
            Some((b as u64, rest))
        }
        25 => {
            let b = rest.get(0..2)?;
            let v = u16::from_be_bytes([b[0], b[1]]) as u64;
            if v <= u8::MAX as u64 {
                return None; // not shortest form
            }
            Some((v, &rest[2..]))
        }
        26 => {
            let b = rest.get(0..4)?;
            let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
            if v <= u16::MAX as u64 {
                return None;
            }
            Some((v, &rest[4..]))
        }
        27 => {
            let b = rest.get(0..8)?;
            let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            if v <= u32::MAX as u64 {
                return None;
            }
            Some((v, &rest[8..]))
        }
        _ => None, // 28..=31 are reserved/indefinite: not valid for a canonical uint
    }
}

// Bounded proof harness for the Kani model checker (plan Section 9). Only compiles under
// `cargo kani`, so it never affects normal builds. Run: `cargo kani -p cose`.
#[cfg(kani)]
#[kani::proof]
fn kani_uint_roundtrip() {
    let n: u64 = kani::any();
    let encoded = encode_uint(n);
    let (decoded, rest) = decode_uint(&encoded).expect("canonical encoding must decode");
    assert_eq!(decoded, n);
    assert!(rest.is_empty());
}
