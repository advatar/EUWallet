//! Canonical (deterministic) CBOR — RFC 8949 §4.2, "Core Deterministic Encoding".
//!
//! This lives in `cose` (not `mdoc`) because COSE is defined in terms of CBOR and `mdoc`
//! depends on `cose`; putting it here avoids a dependency cycle (plan Section 4). `mdoc`
//! re-exports it as `mdoc::cbor`.
//!
//! Determinism is the whole point: an issuer signs a digest of these bytes and a verifier
//! recomputes it, so two logically-equal values MUST encode to identical bytes, and a decoder
//! MUST reject any non-canonical encoding (otherwise a credential could be re-encoded and
//! still verify, or two encodings of the same value could disagree). The rules enforced here:
//!
//! * shortest-form integer/length arguments (RFC 8949 §4.2.1);
//! * definite-length strings/arrays/maps only (no indefinite `0x1f` forms);
//! * map keys sorted by their *encoded bytes*, bytewise-lexicographically, with no duplicates;
//! * no trailing bytes after a top-level item.
//!
//! The codec never panics on malformed input — it returns [`CborError`]. This property is
//! enforced continuously by the Tier-1 fuzz target and proptest suite (plan Section 9).

/// A decoded CBOR value, restricted to the subset EUDI credentials use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Major type 0 — unsigned integer.
    Uint(u64),
    /// Major type 1 — negative integer, holding the CBOR argument `n` (the value is `-1 - n`).
    Nint(u64),
    /// Major type 2 — byte string.
    Bytes(Vec<u8>),
    /// Major type 3 — UTF-8 text string.
    Text(String),
    /// Major type 4 — array.
    Array(Vec<Value>),
    /// Major type 5 — map. Kept in canonical key order on encode; verified on decode.
    Map(Vec<(Value, Value)>),
    /// Major type 6 — tagged value (e.g. tag 24 = embedded CBOR, tag 0/1 = date/time).
    Tag(u64, Box<Value>),
    /// Major type 7 — `false`/`true`.
    Bool(bool),
    /// Major type 7 — `null`.
    Null,
}

/// Every way decoding can fail. No variant is ever produced by a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborError {
    /// Ran out of bytes mid-item.
    Truncated,
    /// An integer/length used a longer-than-necessary encoding.
    NotShortestForm,
    /// An indefinite-length string/array/map was used.
    IndefiniteLength,
    /// Additional-information values 28..=30 (reserved).
    Reserved,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// Map keys were not in canonical (strictly ascending encoded-byte) order.
    MapKeysNotSorted,
    /// The same map key appeared twice.
    DuplicateMapKey,
    /// Bytes remained after a complete top-level item.
    TrailingBytes,
    /// A major-7 value we do not accept (only false/true/null are allowed).
    UnsupportedSimple,
    /// Nesting deeper than [`MAX_DEPTH`] (defends against stack exhaustion on hostile input).
    TooDeep,
}

/// Hard cap on nesting depth so a crafted deeply-nested input cannot exhaust the stack.
pub const MAX_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// Low-level primitives (kept public: the COSE layer and the Tier-1 harness use them).
// ---------------------------------------------------------------------------

/// Encode a `u64` as a canonical CBOR unsigned integer (major type 0), shortest form.
pub fn encode_uint(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_head(&mut out, 0, n);
    out
}

/// Decode a CBOR unsigned integer (major type 0) from the front of `bytes`.
/// Returns the value and the remaining bytes; `None` on malformed/non-canonical input.
/// Never panics.
pub fn decode_uint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    match read_head(bytes) {
        Ok((0, arg, rest)) => Some((arg, rest)),
        _ => None,
    }
}

/// Write a CBOR head: the initial byte (major type in the top 3 bits) plus the shortest-form
/// argument encoding.
pub fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg <= 23 {
        out.push(mt | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Read a CBOR head, enforcing shortest-form and rejecting indefinite/reserved forms.
/// Returns `(major_type, argument, rest)`.
pub fn read_head(bytes: &[u8]) -> Result<(u8, u64, &[u8]), CborError> {
    let (&first, rest) = bytes.split_first().ok_or(CborError::Truncated)?;
    let major = first >> 5;
    let info = first & 0x1f;
    let (arg, rest) = match info {
        0..=23 => (info as u64, rest),
        24 => {
            let (&b, rest) = rest.split_first().ok_or(CborError::Truncated)?;
            if b <= 23 {
                return Err(CborError::NotShortestForm);
            }
            (b as u64, rest)
        }
        25 => {
            let b = rest.get(0..2).ok_or(CborError::Truncated)?;
            let v = u16::from_be_bytes([b[0], b[1]]) as u64;
            if v <= u8::MAX as u64 {
                return Err(CborError::NotShortestForm);
            }
            (v, &rest[2..])
        }
        26 => {
            let b = rest.get(0..4).ok_or(CborError::Truncated)?;
            let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
            if v <= u16::MAX as u64 {
                return Err(CborError::NotShortestForm);
            }
            (v, &rest[4..])
        }
        27 => {
            let b = rest.get(0..8).ok_or(CborError::Truncated)?;
            let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            if v <= u32::MAX as u64 {
                return Err(CborError::NotShortestForm);
            }
            (v, &rest[8..])
        }
        31 => return Err(CborError::IndefiniteLength),
        _ => return Err(CborError::Reserved), // 28, 29, 30
    };
    Ok((major, arg, rest))
}

// ---------------------------------------------------------------------------
// Structured, canonical Value codec.
// ---------------------------------------------------------------------------

impl Value {
    /// Serialize this value as canonical CBOR.
    pub fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Uint(n) => write_head(out, 0, *n),
            Value::Nint(n) => write_head(out, 1, *n),
            Value::Bytes(b) => {
                write_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                write_head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(items) => {
                write_head(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out);
                }
            }
            Value::Map(pairs) => {
                // Canonicalize: sort by encoded key bytes; duplicate keys are collapsed by the
                // sort+dedup so re-encoding is stable. (Decoders reject duplicates outright.)
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = pairs
                    .iter()
                    .map(|(k, v)| (k.to_canonical(), v.to_canonical()))
                    .collect();
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                encoded.dedup_by(|a, b| a.0 == b.0);
                write_head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
            Value::Tag(t, inner) => {
                write_head(out, 6, *t);
                inner.encode_into(out);
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }
}

/// Decode exactly one canonical CBOR value from `bytes`, requiring no trailing bytes.
/// This is the entry point credential code should use.
pub fn from_canonical_slice(bytes: &[u8]) -> Result<Value, CborError> {
    let (value, rest) = decode_value(bytes, 0)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(CborError::TrailingBytes)
    }
}

/// Decode one value, returning it and the remaining bytes. Enforces all canonical rules.
pub fn decode_value(bytes: &[u8], depth: usize) -> Result<(Value, &[u8]), CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::TooDeep);
    }
    let first = *bytes.first().ok_or(CborError::Truncated)?;
    let major = first >> 5;
    match major {
        0 => {
            let (_, arg, rest) = read_head(bytes)?;
            Ok((Value::Uint(arg), rest))
        }
        1 => {
            let (_, arg, rest) = read_head(bytes)?;
            Ok((Value::Nint(arg), rest))
        }
        2 => {
            let (_, len, rest) = read_head(bytes)?;
            let len = len as usize;
            let body = rest.get(..len).ok_or(CborError::Truncated)?;
            Ok((Value::Bytes(body.to_vec()), &rest[len..]))
        }
        3 => {
            let (_, len, rest) = read_head(bytes)?;
            let len = len as usize;
            let body = rest.get(..len).ok_or(CborError::Truncated)?;
            let s = core::str::from_utf8(body).map_err(|_| CborError::InvalidUtf8)?;
            Ok((Value::Text(s.into()), &rest[len..]))
        }
        4 => {
            let (_, len, mut rest) = read_head(bytes)?;
            let mut items = Vec::new();
            for _ in 0..len {
                let (item, next) = decode_value(rest, depth + 1)?;
                items.push(item);
                rest = next;
            }
            Ok((Value::Array(items), rest))
        }
        5 => {
            let (_, len, mut rest) = read_head(bytes)?;
            let mut pairs: Vec<(Value, Value)> = Vec::new();
            let mut prev_key: Option<Vec<u8>> = None;
            for _ in 0..len {
                let (key, next) = decode_value(rest, depth + 1)?;
                let key_bytes = key.to_canonical();
                // Enforce strictly-ascending, duplicate-free canonical key order.
                if let Some(prev) = &prev_key {
                    match key_bytes.as_slice().cmp(prev.as_slice()) {
                        core::cmp::Ordering::Less => return Err(CborError::MapKeysNotSorted),
                        core::cmp::Ordering::Equal => return Err(CborError::DuplicateMapKey),
                        core::cmp::Ordering::Greater => {}
                    }
                }
                prev_key = Some(key_bytes);
                let (val, next2) = decode_value(next, depth + 1)?;
                pairs.push((key, val));
                rest = next2;
            }
            Ok((Value::Map(pairs), rest))
        }
        6 => {
            let (_, tag, rest) = read_head(bytes)?;
            let (inner, rest) = decode_value(rest, depth + 1)?;
            Ok((Value::Tag(tag, Box::new(inner)), rest))
        }
        7 => match first {
            0xf4 => Ok((Value::Bool(false), &bytes[1..])),
            0xf5 => Ok((Value::Bool(true), &bytes[1..])),
            0xf6 => Ok((Value::Null, &bytes[1..])),
            _ => Err(CborError::UnsupportedSimple),
        },
        _ => unreachable!("major type is 3 bits, 0..=7"),
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
