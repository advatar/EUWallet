#![forbid(unsafe_code)]
//! `mdoc` — ISO/IEC 18013-5 mdoc credential format with profiled canonical CBOR
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4.2.
//!
//! This crate encodes/decodes the ISO mdoc credential on top of the canonical CBOR codec in
//! `cose::cbor`. Its defining constraint is deterministic encoding: the issuer signs a digest
//! of the credential bytes and the verifier recomputes it, so every structure round-trips to
//! identical bytes. Digests and signatures are computed only through the `crypto-traits`
//! boundary — this crate never implements a cryptographic algorithm.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use cose::cbor::{CborError, Value};
use cose::{CoseError, CoseSign1, UnprotectedHeader};
use crypto_traits::{Alg, Digest, KeyRef, Signer, Verifier};

/// Canonical CBOR primitives live in `cose` (see plan Section 4). Re-exported so existing call
/// sites (`mdoc::cbor::…`, the Tier-1 harness) resolve unchanged.
pub use cose::cbor;

/// A SHA-256 value digest.
pub type Digest32 = [u8; 32];

/// Everything that can go wrong building or verifying an mdoc.
#[derive(Debug, PartialEq, Eq)]
pub enum MdocError {
    Cose(CoseError),
    Cbor(CborError),
    /// The structure decoded but a required field was missing or the wrong CBOR type.
    Malformed(&'static str),
    /// A disclosed item's recomputed digest was not found / did not match the signed MSO.
    DigestMismatch,
}

impl From<CoseError> for MdocError {
    fn from(e: CoseError) -> Self {
        MdocError::Cose(e)
    }
}
impl From<CborError> for MdocError {
    fn from(e: CborError) -> Self {
        MdocError::Cbor(e)
    }
}

// ---------------------------------------------------------------------------
// Small helpers for reading typed fields out of a decoded CBOR map.
// ---------------------------------------------------------------------------

fn map_get<'a>(pairs: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    pairs
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn as_text(v: &Value, ctx: &'static str) -> Result<String, MdocError> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(MdocError::Malformed(ctx)),
    }
}

fn as_bytes(v: &Value, ctx: &'static str) -> Result<Vec<u8>, MdocError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(MdocError::Malformed(ctx)),
    }
}

fn as_uint(v: &Value, ctx: &'static str) -> Result<u64, MdocError> {
    match v {
        Value::Uint(n) => Ok(*n),
        _ => Err(MdocError::Malformed(ctx)),
    }
}

/// A parsed CBOR tag-0 date/time. Ordering is by the represented instant, including an arbitrary
/// number of fractional-second digits, rather than by the original offset spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TDate {
    unix_seconds: i64,
    // Trailing zeroes are removed, so equal instants have equal representations here.
    fraction: Vec<u8>,
}

impl TDate {
    /// Parse RFC 3339 `date-time` as refined for CBOR tag 0 by RFC 8949 / RFC 4287: uppercase `T`,
    /// uppercase `Z` when UTC is named directly, an optional non-empty decimal fraction, and a
    /// required `Z` or numeric offset. Calendar and clock component ranges are checked.
    pub fn parse(value: &str) -> Option<Self> {
        let bytes = value.as_bytes();
        if bytes.len() < 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
        {
            return None;
        }
        let digits = |start: usize, end: usize| -> Option<i64> {
            bytes.get(start..end)?.iter().try_fold(0i64, |n, byte| {
                byte.is_ascii_digit()
                    .then_some(n * 10 + i64::from(byte - b'0'))
            })
        };
        let (year, month, day, hour, minute, second) = (
            digits(0, 4)?,
            digits(5, 7)?,
            digits(8, 10)?,
            digits(11, 13)?,
            digits(14, 16)?,
            digits(17, 19)?,
        );
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let month_days = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        if !(1..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day < 1
            || day > month_days[(month - 1) as usize]
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }

        let mut suffix = 19;
        let mut fraction = Vec::new();
        if bytes.get(suffix) == Some(&b'.') {
            suffix += 1;
            let fraction_start = suffix;
            while bytes.get(suffix).is_some_and(u8::is_ascii_digit) {
                fraction.push(bytes[suffix] - b'0');
                suffix += 1;
            }
            if suffix == fraction_start {
                return None;
            }
            while fraction.last() == Some(&0) {
                fraction.pop();
            }
        }

        let offset_seconds = match bytes.get(suffix) {
            Some(b'Z') if suffix + 1 == bytes.len() => 0i64,
            Some(sign @ (b'+' | b'-')) if suffix + 6 == bytes.len() => {
                if bytes[suffix + 3] != b':' {
                    return None;
                }
                let offset_hour = digits(suffix + 1, suffix + 3)?;
                let offset_minute = digits(suffix + 4, suffix + 6)?;
                if offset_hour > 23 || offset_minute > 59 {
                    return None;
                }
                // RFC 4287 does not permit RFC 3339's "unknown local offset" spelling.
                if *sign == b'-' && offset_hour == 0 && offset_minute == 0 {
                    return None;
                }
                let magnitude = offset_hour * 3_600 + offset_minute * 60;
                if *sign == b'+' {
                    magnitude
                } else {
                    -magnitude
                }
            }
            _ => return None,
        };

        // Howard Hinnant's civil-date conversion. With years constrained to 1..=9999 all
        // intermediate values and the offset adjustment fit comfortably in i64.
        let adjusted_year = year - i64::from(month <= 2);
        let era = adjusted_year / 400;
        let year_of_era = adjusted_year - era * 400;
        let shifted_month = month + if month > 2 { -3 } else { 9 };
        let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        let local_seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
        Some(Self {
            unix_seconds: local_seconds - offset_seconds,
            fraction,
        })
    }

    /// Represent an integral Unix timestamp for comparison with a shell-provided wall clock.
    pub fn from_unix_seconds(unix_seconds: i64) -> Self {
        Self {
            unix_seconds,
            fraction: Vec::new(),
        }
    }

    /// Smallest integral Unix timestamp that is not earlier than this instant. This is suitable
    /// for conservatively retaining a fractional validity boundary when the shell clock exposes
    /// only whole seconds.
    pub fn unix_seconds_ceil(&self) -> i64 {
        self.unix_seconds
            .saturating_add(i64::from(!self.fraction.is_empty()))
    }
}

impl Ord for TDate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.unix_seconds.cmp(&other.unix_seconds).then_with(|| {
            let length = self.fraction.len().max(other.fraction.len());
            (0..length)
                .map(|index| {
                    self.fraction
                        .get(index)
                        .copied()
                        .unwrap_or(0)
                        .cmp(&other.fraction.get(index).copied().unwrap_or(0))
                })
                .find(|ordering| *ordering != Ordering::Equal)
                .unwrap_or(Ordering::Equal)
        })
    }
}

impl PartialOrd for TDate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn tdate_value(value: &str, ctx: &'static str) -> Result<Value, MdocError> {
    TDate::parse(value).ok_or(MdocError::Malformed(ctx))?;
    Ok(Value::Tag(0, Box::new(Value::Text(value.to_string()))))
}

fn as_tdate(v: &Value, ctx: &'static str) -> Result<String, MdocError> {
    let Value::Tag(0, inner) = v else {
        return Err(MdocError::Malformed(ctx));
    };
    let Value::Text(value) = inner.as_ref() else {
        return Err(MdocError::Malformed(ctx));
    };
    TDate::parse(value).ok_or(MdocError::Malformed(ctx))?;
    Ok(value.clone())
}

/// Wrap canonical CBOR bytes as `#6.24(bstr)` — the "embedded CBOR" tag mdoc uses for
/// `IssuerSignedItemBytes` and `MobileSecurityObjectBytes`. Returns the canonical wrapper bytes.
fn tag24(inner_canonical: Vec<u8>) -> Vec<u8> {
    Value::Tag(24, Box::new(Value::Bytes(inner_canonical))).to_canonical()
}

/// Reverse of [`tag24`]: given `#6.24(bstr)` bytes, return the embedded CBOR bytes.
fn untag24(bytes: &[u8]) -> Result<Vec<u8>, MdocError> {
    match cbor::from_canonical_slice(bytes)? {
        Value::Tag(24, inner) => match *inner {
            Value::Bytes(b) => Ok(b),
            _ => Err(MdocError::Malformed("tag24 content not a byte string")),
        },
        _ => Err(MdocError::Malformed("expected tag 24")),
    }
}

// ---------------------------------------------------------------------------
// IssuerSignedItem
// ---------------------------------------------------------------------------

/// One selectively-disclosable data element. On the wire it is a tag-24 byte string wrapping
/// the canonical CBOR of this map (`IssuerSignedItemBytes`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerSignedItem {
    pub digest_id: u64,
    pub random: Vec<u8>,
    pub element_id: String,
    pub element_value: Value,
}

impl IssuerSignedItem {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Text("digestID".into()), Value::Uint(self.digest_id)),
            (
                Value::Text("random".into()),
                Value::Bytes(self.random.clone()),
            ),
            (
                Value::Text("elementIdentifier".into()),
                Value::Text(self.element_id.clone()),
            ),
            (
                Value::Text("elementValue".into()),
                self.element_value.clone(),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, MdocError> {
        let Value::Map(pairs) = v else {
            return Err(MdocError::Malformed("IssuerSignedItem not a map"));
        };
        Ok(IssuerSignedItem {
            digest_id: as_uint(
                map_get(pairs, "digestID").ok_or(MdocError::Malformed("digestID"))?,
                "digestID",
            )?,
            random: as_bytes(
                map_get(pairs, "random").ok_or(MdocError::Malformed("random"))?,
                "random",
            )?,
            element_id: as_text(
                map_get(pairs, "elementIdentifier").ok_or(MdocError::Malformed("elementId"))?,
                "elementIdentifier",
            )?,
            element_value: map_get(pairs, "elementValue")
                .ok_or(MdocError::Malformed("elementValue"))?
                .clone(),
        })
    }

    /// The `IssuerSignedItemBytes`: `#6.24(bstr .cbor IssuerSignedItem)`. This is what gets
    /// digested into the MSO and what travels in `IssuerSigned.nameSpaces`.
    pub fn to_item_bytes(&self) -> Vec<u8> {
        tag24(self.to_value().to_canonical())
    }

    /// Parse an `IssuerSignedItemBytes` (tag-24 wrapper) received from the wire back into an item.
    pub fn from_item_bytes(bytes: &[u8]) -> Result<Self, MdocError> {
        let inner = untag24(bytes)?;
        Self::from_value(&cbor::from_canonical_slice(&inner)?)
    }

    /// The SHA-256 digest of the `IssuerSignedItemBytes`, via the crypto boundary.
    pub fn digest(&self, digest: &dyn Digest) -> Digest32 {
        digest.sha256(&self.to_item_bytes())
    }
}

// ---------------------------------------------------------------------------
// MobileSecurityObject
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidityInfo {
    pub signed: String,
    pub valid_from: String,
    pub valid_until: String,
}

/// Mobile Security Object — the signed digest catalogue of a credential (18013-5 §9.1.2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MobileSecurityObject {
    pub version: String,
    pub digest_algorithm: String,
    pub doc_type: String,
    /// namespace → (digestID → digest).
    pub value_digests: BTreeMap<String, BTreeMap<u64, Digest32>>,
    /// The holder's COSE_Key for device authentication (opaque here).
    pub device_key: Value,
    pub validity_info: ValidityInfo,
}

impl MobileSecurityObject {
    fn to_value(&self) -> Result<Value, MdocError> {
        let value_digests = Value::Map(
            self.value_digests
                .iter()
                .map(|(ns, digests)| {
                    let inner = Value::Map(
                        digests
                            .iter()
                            .map(|(id, d)| (Value::Uint(*id), Value::Bytes(d.to_vec())))
                            .collect(),
                    );
                    (Value::Text(ns.clone()), inner)
                })
                .collect(),
        );
        let validity = Value::Map(vec![
            (
                Value::Text("signed".into()),
                tdate_value(&self.validity_info.signed, "signed tdate")?,
            ),
            (
                Value::Text("validFrom".into()),
                tdate_value(&self.validity_info.valid_from, "validFrom tdate")?,
            ),
            (
                Value::Text("validUntil".into()),
                tdate_value(&self.validity_info.valid_until, "validUntil tdate")?,
            ),
        ]);
        Ok(Value::Map(vec![
            (
                Value::Text("version".into()),
                Value::Text(self.version.clone()),
            ),
            (
                Value::Text("digestAlgorithm".into()),
                Value::Text(self.digest_algorithm.clone()),
            ),
            (Value::Text("valueDigests".into()), value_digests),
            (
                Value::Text("deviceKeyInfo".into()),
                Value::Map(vec![(
                    Value::Text("deviceKey".into()),
                    self.device_key.clone(),
                )]),
            ),
            (
                Value::Text("docType".into()),
                Value::Text(self.doc_type.clone()),
            ),
            (Value::Text("validityInfo".into()), validity),
        ]))
    }

    fn from_value(v: &Value) -> Result<Self, MdocError> {
        let Value::Map(pairs) = v else {
            return Err(MdocError::Malformed("MSO not a map"));
        };
        let vd_val = map_get(pairs, "valueDigests").ok_or(MdocError::Malformed("valueDigests"))?;
        let Value::Map(ns_pairs) = vd_val else {
            return Err(MdocError::Malformed("valueDigests not a map"));
        };
        let mut value_digests = BTreeMap::new();
        for (ns_k, ns_v) in ns_pairs {
            let ns = as_text(ns_k, "namespace")?;
            let Value::Map(digest_pairs) = ns_v else {
                return Err(MdocError::Malformed("namespace not a map"));
            };
            let mut m = BTreeMap::new();
            for (id_k, d_v) in digest_pairs {
                let id = as_uint(id_k, "digestID")?;
                let d = as_bytes(d_v, "digest")?;
                let arr: Digest32 = d
                    .as_slice()
                    .try_into()
                    .map_err(|_| MdocError::Malformed("digest length"))?;
                m.insert(id, arr);
            }
            value_digests.insert(ns, m);
        }

        let device_key = match map_get(pairs, "deviceKeyInfo") {
            Some(Value::Map(dki)) => map_get(dki, "deviceKey").cloned().unwrap_or(Value::Null),
            _ => Value::Null,
        };

        let Some(Value::Map(vi)) = map_get(pairs, "validityInfo") else {
            return Err(MdocError::Malformed("validityInfo"));
        };
        let validity_info = ValidityInfo {
            signed: as_tdate(
                map_get(vi, "signed").ok_or(MdocError::Malformed("signed tdate"))?,
                "signed tdate",
            )?,
            valid_from: as_tdate(
                map_get(vi, "validFrom").ok_or(MdocError::Malformed("validFrom tdate"))?,
                "validFrom tdate",
            )?,
            valid_until: as_tdate(
                map_get(vi, "validUntil").ok_or(MdocError::Malformed("validUntil tdate"))?,
                "validUntil tdate",
            )?,
        };

        Ok(MobileSecurityObject {
            version: as_text(
                map_get(pairs, "version").ok_or(MdocError::Malformed("version"))?,
                "version",
            )?,
            digest_algorithm: as_text(
                map_get(pairs, "digestAlgorithm").ok_or(MdocError::Malformed("digestAlgorithm"))?,
                "digestAlgorithm",
            )?,
            doc_type: as_text(
                map_get(pairs, "docType").ok_or(MdocError::Malformed("docType"))?,
                "docType",
            )?,
            value_digests,
            device_key,
            validity_info,
        })
    }

    /// The `MobileSecurityObjectBytes`: `#6.24(bstr .cbor MSO)` — the COSE_Sign1 payload.
    pub fn to_mso_bytes(&self) -> Result<Vec<u8>, MdocError> {
        Ok(tag24(self.to_value()?.to_canonical()))
    }
}

// ---------------------------------------------------------------------------
// IssuerSigned
// ---------------------------------------------------------------------------

/// The issuer-signed portion of a credential: the disclosable items per namespace, plus the
/// COSE_Sign1 over the MSO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerSigned {
    pub name_spaces: BTreeMap<String, Vec<IssuerSignedItem>>,
    pub issuer_auth: CoseSign1,
}

/// Build value digests for every item, seal them in an MSO, and issuer-sign it.
#[allow(clippy::too_many_arguments)]
pub fn build_and_sign(
    name_spaces: BTreeMap<String, Vec<IssuerSignedItem>>,
    doc_type: &str,
    device_key: Value,
    validity_info: ValidityInfo,
    digest: &dyn Digest,
    signer: &dyn Signer,
    key: &KeyRef,
    alg: Alg,
) -> Result<IssuerSigned, MdocError> {
    let mut value_digests: BTreeMap<String, BTreeMap<u64, Digest32>> = BTreeMap::new();
    for (ns, items) in &name_spaces {
        let mut m = BTreeMap::new();
        for item in items {
            m.insert(item.digest_id, item.digest(digest));
        }
        value_digests.insert(ns.clone(), m);
    }

    let mso = MobileSecurityObject {
        version: "1.0".into(),
        digest_algorithm: "SHA-256".into(),
        doc_type: doc_type.into(),
        value_digests,
        device_key,
        validity_info,
    };
    let mso_bytes = mso.to_mso_bytes()?;
    let issuer_auth = CoseSign1::sign(
        signer,
        key,
        alg,
        &mso_bytes,
        &[],
        UnprotectedHeader::default(),
    )?;
    Ok(IssuerSigned {
        name_spaces,
        issuer_auth,
    })
}

/// Verify the issuer signature over the MSO, then check that every disclosed item's recomputed
/// digest matches the signed MSO. Returns the verified MSO on success.
pub fn verify_issuer_signed(
    issued: &IssuerSigned,
    verifier: &dyn Verifier,
    digest: &dyn Digest,
    issuer_public_key: &[u8],
    alg: Alg,
) -> Result<MobileSecurityObject, MdocError> {
    // 1) The COSE_Sign1 payload is the MobileSecurityObjectBytes.
    let payload = issued
        .issuer_auth
        .payload
        .as_ref()
        .ok_or(MdocError::Malformed("issuerAuth has no payload"))?;

    // 2) Verify the issuer's signature over exactly those bytes.
    issued
        .issuer_auth
        .verify(verifier, alg, issuer_public_key, &[], None)?;

    // 3) Decode the MSO from the signed payload.
    let mso_canonical = untag24(payload)?;
    let mso = MobileSecurityObject::from_value(&cbor::from_canonical_slice(&mso_canonical)?)?;

    // 4) Every disclosed item must hash to the digest the issuer signed.
    for (ns, items) in &issued.name_spaces {
        let signed = mso.value_digests.get(ns).ok_or(MdocError::DigestMismatch)?;
        for item in items {
            let want = signed
                .get(&item.digest_id)
                .ok_or(MdocError::DigestMismatch)?;
            if item.digest(digest) != *want {
                return Err(MdocError::DigestMismatch);
            }
        }
    }
    Ok(mso)
}

// ---------------------------------------------------------------------------
// DeviceResponse assembly (ISO 18013-5 §8.3.2.1.2.2)
// ---------------------------------------------------------------------------

impl IssuerSigned {
    /// Encode as the `IssuerSigned` CBOR map: `{ "nameSpaces": {ns => [IssuerSignedItemBytes]},
    /// "issuerAuth": COSE_Sign1 }`. Each item is a tag-24 `IssuerSignedItemBytes`.
    pub fn to_value(&self) -> Value {
        let ns_pairs: Vec<(Value, Value)> = self
            .name_spaces
            .iter()
            .map(|(ns, items)| {
                let arr = Value::Array(
                    items
                        .iter()
                        .map(|it| {
                            Value::Tag(24, Box::new(Value::Bytes(it.to_value().to_canonical())))
                        })
                        .collect(),
                );
                (Value::Text(ns.clone()), arr)
            })
            .collect();
        Value::Map(vec![
            (Value::Text("nameSpaces".into()), Value::Map(ns_pairs)),
            (
                Value::Text("issuerAuth".into()),
                self.issuer_auth.to_value(),
            ),
        ])
    }

    /// Parse an `IssuerSigned` from canonical CBOR bytes (the inverse of `to_value`), so a wallet
    /// can store and later re-present an mdoc it received over the wire.
    pub fn parse(bytes: &[u8]) -> Result<Self, MdocError> {
        Self::from_value(&cbor::from_canonical_slice(bytes)?)
    }

    /// Parse from a decoded CBOR value.
    pub fn from_value(v: &Value) -> Result<Self, MdocError> {
        let Value::Map(pairs) = v else {
            return Err(MdocError::Malformed("IssuerSigned not a map"));
        };
        let ns_val = map_get(pairs, "nameSpaces").ok_or(MdocError::Malformed("nameSpaces"))?;
        let Value::Map(ns_pairs) = ns_val else {
            return Err(MdocError::Malformed("nameSpaces not a map"));
        };
        let mut name_spaces = BTreeMap::new();
        for (k, arr) in ns_pairs {
            let ns = as_text(k, "namespace")?;
            let Value::Array(items) = arr else {
                return Err(MdocError::Malformed("namespace items not an array"));
            };
            let mut parsed = Vec::with_capacity(items.len());
            for it in items {
                // Each element is an `IssuerSignedItemBytes` (#6.24(bstr .cbor IssuerSignedItem)).
                parsed.push(IssuerSignedItem::from_item_bytes(&it.to_canonical())?);
            }
            name_spaces.insert(ns, parsed);
        }
        let issuer_auth_val =
            map_get(pairs, "issuerAuth").ok_or(MdocError::Malformed("issuerAuth"))?;
        let issuer_auth = CoseSign1::from_value(issuer_auth_val)
            .map_err(|_| MdocError::Malformed("issuerAuth"))?;
        Ok(IssuerSigned {
            name_spaces,
            issuer_auth,
        })
    }

    /// The credential's doctype, read from the MSO embedded in `issuerAuth`.
    pub fn doc_type(&self) -> Result<String, MdocError> {
        let payload = self
            .issuer_auth
            .payload
            .as_ref()
            .ok_or(MdocError::Malformed("issuerAuth payload"))?;
        let mso =
            MobileSecurityObject::from_value(&cbor::from_canonical_slice(&untag24(payload)?)?)?;
        Ok(mso.doc_type)
    }
}

/// The `DeviceAuthenticationBytes` the device key signs (ISO 18013-5 §9.1.3.4):
/// `#6.24(bstr .cbor [ "DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes ])`.
/// `session_transcript` is the canonical CBOR of the SessionTranscript array; it is embedded as a
/// value (not a byte string) so the structure matches the standard exactly.
pub fn device_authentication_bytes(
    session_transcript: &[u8],
    doc_type: &str,
    device_namespaces_bytes: &[u8],
) -> Result<Vec<u8>, MdocError> {
    let transcript = cbor::from_canonical_slice(session_transcript)?;
    let device_auth = Value::Array(vec![
        Value::Text("DeviceAuthentication".into()),
        transcript,
        Value::Text(doc_type.into()),
        Value::Tag(24, Box::new(Value::Bytes(device_namespaces_bytes.to_vec()))),
    ]);
    Ok(tag24(device_auth.to_canonical()))
}

/// The OpenID4VP `SessionTranscript` for an mdoc presentation carried over OpenID4VP
/// (ISO/IEC 18013-7 Annex B / OpenID4VP 1.0): `[ null, null, OID4VPHandover ]`, where
/// `OID4VPHandover = [ clientIdHash, responseUriHash, nonce ]`,
/// `clientIdHash = SHA-256( CBOR([ client_id, mdoc_generated_nonce ]) )`, and likewise for
/// `responseUriHash`. `nonce` is the OpenID4VP request nonce; `mdoc_generated_nonce` is the
/// wallet-chosen nonce that also binds the response channel. The device authentication signs
/// over this transcript, so it defeats replay/relay of the presentation to a different verifier.
pub fn oid4vp_session_transcript(
    digest: &dyn Digest,
    client_id: &str,
    response_uri: &str,
    nonce: &str,
    mdoc_generated_nonce: &str,
) -> Vec<u8> {
    let hash_of = |value: &str| -> Vec<u8> {
        let to_hash = Value::Array(vec![
            Value::Text(value.into()),
            Value::Text(mdoc_generated_nonce.into()),
        ])
        .to_canonical();
        digest.sha256(&to_hash).to_vec()
    };
    let handover = Value::Array(vec![
        Value::Bytes(hash_of(client_id)),
        Value::Bytes(hash_of(response_uri)),
        Value::Text(nonce.into()),
    ]);
    Value::Array(vec![Value::Null, Value::Null, handover]).to_canonical()
}

/// The `DeviceNameSpaces` a wallet sends when it adds no device-signed namespaces: an empty map,
/// as the canonical-CBOR bytes that get tag-24 wrapped into `DeviceNameSpacesBytes`.
pub fn empty_device_namespaces_bytes() -> Vec<u8> {
    Value::Map(vec![]).to_canonical()
}

/// Assemble a real ISO 18013-5 `DeviceResponse` (one document):
/// `{ "version": "1.0", "documents": [ { docType, issuerSigned, deviceSigned } ], "status": 0 }`,
/// where `deviceSigned = { nameSpaces: #6.24(bstr), deviceAuth: { deviceSignature: COSE_Sign1 } }`.
pub fn device_response(
    doc_type: &str,
    issuer_signed: &IssuerSigned,
    device_namespaces_bytes: &[u8],
    device_signature: &CoseSign1,
) -> Vec<u8> {
    let device_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Tag(24, Box::new(Value::Bytes(device_namespaces_bytes.to_vec()))),
        ),
        (
            Value::Text("deviceAuth".into()),
            Value::Map(vec![(
                Value::Text("deviceSignature".into()),
                device_signature.to_value(),
            )]),
        ),
    ]);
    let document = Value::Map(vec![
        (Value::Text("docType".into()), Value::Text(doc_type.into())),
        (Value::Text("issuerSigned".into()), issuer_signed.to_value()),
        (Value::Text("deviceSigned".into()), device_signed),
    ]);
    Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("documents".into()),
            Value::Array(vec![document]),
        ),
        (Value::Text("status".into()), Value::Uint(0)),
    ])
    .to_canonical()
}
