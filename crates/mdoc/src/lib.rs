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

#[derive(Clone, Debug, PartialEq, Eq, Default)]
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
    fn to_value(&self) -> Value {
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
                Value::Text(self.validity_info.signed.clone()),
            ),
            (
                Value::Text("validFrom".into()),
                Value::Text(self.validity_info.valid_from.clone()),
            ),
            (
                Value::Text("validUntil".into()),
                Value::Text(self.validity_info.valid_until.clone()),
            ),
        ]);
        Value::Map(vec![
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
        ])
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

        let validity_info = match map_get(pairs, "validityInfo") {
            Some(Value::Map(vi)) => ValidityInfo {
                signed: map_get(vi, "signed")
                    .and_then(|v| as_text(v, "signed").ok())
                    .unwrap_or_default(),
                valid_from: map_get(vi, "validFrom")
                    .and_then(|v| as_text(v, "validFrom").ok())
                    .unwrap_or_default(),
                valid_until: map_get(vi, "validUntil")
                    .and_then(|v| as_text(v, "validUntil").ok())
                    .unwrap_or_default(),
            },
            _ => ValidityInfo::default(),
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
    pub fn to_mso_bytes(&self) -> Vec<u8> {
        tag24(self.to_value().to_canonical())
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
    let mso_bytes = mso.to_mso_bytes();
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

/// Device-signed portion (holder binding). Structure placeholder — the `SessionTranscript`
/// binding is supplied by the `iso18013-5` machine (plan Section 5.3).
#[derive(Clone, Debug, Default)]
pub struct DeviceSigned;
