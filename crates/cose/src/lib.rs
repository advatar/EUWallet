#![forbid(unsafe_code)]
//! `cose` — COSE structures over the crypto trait boundary (RFC 9052/9053)
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4.1.
//!
//! This crate builds and verifies `COSE_Sign1` messages — the single-signer CBOR signature
//! envelope used by mdoc `IssuerSigned`/`DeviceSigned` and by the Wallet Unit Attestation.
//! It never computes a signature or digest itself: it constructs the exact bytes to be signed
//! (`Sig_structure`, RFC 9052 §4.4) and hands them to [`crypto_traits::Signer`] /
//! [`crypto_traits::Verifier`].

pub mod cbor;

use cbor::{write_head, Value};
use crypto_traits::{Alg, CryptoError, KeyRef, Signer, Verifier};

/// COSE header label constants (RFC 9052 §3.1).
mod label {
    pub const ALG: u64 = 1; // algorithm identifier (int)
    pub const CRIT: u64 = 2; // critical headers (array of labels)
    pub const KID: u64 = 4; // key id (bstr)
}

/// Map a `crypto_traits::Alg` to its COSE algorithm identifier (RFC 9053 §2). These are
/// negative integers, encoded as CBOR major type 1 with argument `-1 - id`.
fn cose_alg_id(alg: Alg) -> i64 {
    match alg {
        Alg::Es256 => -7,
        Alg::Es384 => -35,
        Alg::EdDsa => -8,
    }
}

/// Inverse of [`cose_alg_id`].
fn alg_from_id(id: i64) -> Option<Alg> {
    match id {
        -7 => Some(Alg::Es256),
        -35 => Some(Alg::Es384),
        -8 => Some(Alg::EdDsa),
        _ => None,
    }
}

/// Everything that can go wrong building or verifying a COSE_Sign1.
#[derive(Debug, PartialEq, Eq)]
pub enum CoseError {
    /// The signing/verification backend failed.
    Crypto(CryptoError),
    /// A `crit` header listed a label we do not understand → MUST reject (RFC 9052 §3.1).
    UnknownCriticalParam(i64),
    /// Protected header was not canonical CBOR, not a map, or `alg` was missing/unknown.
    MalformedHeader,
    /// Detached-payload mismatch, wrong structure, etc.
    MalformedStructure,
    /// The header's `alg` did not match the algorithm the caller expected.
    AlgMismatch,
}

impl From<CryptoError> for CoseError {
    fn from(e: CryptoError) -> Self {
        CoseError::Crypto(e)
    }
}

/// The unprotected header (not covered by the signature).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnprotectedHeader {
    pub kid: Option<Vec<u8>>,
}

/// A COSE_Sign1 message. `protected` is the *serialized* protected-header byte string exactly
/// as it appears on the wire and inside the `Sig_structure`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoseSign1 {
    pub protected: Vec<u8>,
    pub unprotected: UnprotectedHeader,
    /// `None` means the payload is detached (supplied out of band at verify time).
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

/// Build the `Sig_structure` for a COSE_Sign1 (RFC 9052 §4.4):
/// `[ "Signature1", body_protected, external_aad, payload ]`, canonically encoded.
/// These are the exact bytes handed to the signer/verifier — build them in ONE place only.
pub fn sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let s = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(external_aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]);
    s.to_canonical()
}

/// Encode the canonical protected header `{1: alg}` as a CBOR byte string body (the bytes
/// that go on the wire and into the Sig_structure). Public so a sans-IO caller that has the
/// signature produced out of band (e.g. an mdoc DeviceAuth signed by the Secure Enclave) can
/// reassemble the exact `CoseSign1` and its `Sig_structure`.
pub fn encode_protected_header(alg: Alg) -> Vec<u8> {
    // A one-entry map {1: alg_id}. alg_id is negative → CBOR major type 1 (Nint(arg)).
    let id = cose_alg_id(alg);
    let alg_val = if id < 0 {
        Value::Nint((-1 - id) as u64)
    } else {
        Value::Uint(id as u64)
    };
    Value::Map(vec![(Value::Uint(label::ALG), alg_val)]).to_canonical()
}

/// Parse a protected header, reject unknown critical params, and return its `alg`.
fn parse_and_check_protected_header(protected: &[u8]) -> Result<Alg, CoseError> {
    let value = cbor::from_canonical_slice(protected).map_err(|_| CoseError::MalformedHeader)?;
    let Value::Map(pairs) = value else {
        return Err(CoseError::MalformedHeader);
    };

    // If `crit` is present, every listed label must be one we understand, or we fail closed.
    if let Some((_, crit)) = pairs.iter().find(|(k, _)| *k == Value::Uint(label::CRIT)) {
        let Value::Array(items) = crit else {
            return Err(CoseError::MalformedHeader);
        };
        for item in items {
            let lbl = match item {
                Value::Uint(n) => *n as i64,
                Value::Nint(n) => -1 - (*n as i64),
                _ => return Err(CoseError::MalformedHeader),
            };
            // The only protected-header labels we implement.
            if lbl != label::ALG as i64 && lbl != label::CRIT as i64 && lbl != label::KID as i64 {
                return Err(CoseError::UnknownCriticalParam(lbl));
            }
        }
    }

    // Extract and map the algorithm.
    let (_, alg_val) = pairs
        .iter()
        .find(|(k, _)| *k == Value::Uint(label::ALG))
        .ok_or(CoseError::MalformedHeader)?;
    let id = match alg_val {
        Value::Uint(n) => *n as i64,
        Value::Nint(n) => -1 - (*n as i64),
        _ => return Err(CoseError::MalformedHeader),
    };
    alg_from_id(id).ok_or(CoseError::MalformedHeader)
}

impl CoseSign1 {
    /// Build the protected header, assemble the `Sig_structure`, and sign it via the boundary.
    pub fn sign(
        signer: &dyn Signer,
        key: &KeyRef,
        alg: Alg,
        payload: &[u8],
        external_aad: &[u8],
        unprotected: UnprotectedHeader,
    ) -> Result<Self, CoseError> {
        let protected = encode_protected_header(alg);
        let tbs = sig_structure(&protected, external_aad, payload);
        let signature = signer.sign(key, alg, &tbs)?; // <-- crypto boundary
        Ok(CoseSign1 {
            protected,
            unprotected,
            payload: Some(payload.to_vec()),
            signature,
        })
    }

    /// Verify the signature: re-derive the Sig_structure from our own re-encode of the header,
    /// reject unknown crit params, check the algorithm, then call the verifier.
    pub fn verify(
        &self,
        verifier: &dyn Verifier,
        expected_alg: Alg,
        public_key: &[u8],
        external_aad: &[u8],
        detached_payload: Option<&[u8]>,
    ) -> Result<(), CoseError> {
        let hdr_alg = parse_and_check_protected_header(&self.protected)?;
        if hdr_alg != expected_alg {
            return Err(CoseError::AlgMismatch);
        }
        let payload = match (&self.payload, detached_payload) {
            (Some(p), None) => p.as_slice(),
            (None, Some(p)) => p,
            _ => return Err(CoseError::MalformedStructure),
        };
        let tbs = sig_structure(&self.protected, external_aad, payload);
        verifier.verify(expected_alg, public_key, &tbs, &self.signature)?; // <-- crypto boundary
        Ok(())
    }

    /// Encode as the COSE_Sign1 wire structure (RFC 9052 §4.2):
    /// `[ protected: bstr, unprotected: map, payload: bstr / nil, signature: bstr ]`.
    /// A detached payload (`None`) is encoded as CBOR `null`.
    pub fn to_value(&self) -> Value {
        let unprotected = match &self.unprotected.kid {
            Some(kid) => Value::Map(vec![(Value::Uint(label::KID), Value::Bytes(kid.clone()))]),
            None => Value::Map(vec![]),
        };
        let payload = match &self.payload {
            Some(p) => Value::Bytes(p.clone()),
            None => Value::Null,
        };
        Value::Array(vec![
            Value::Bytes(self.protected.clone()),
            unprotected,
            payload,
            Value::Bytes(self.signature.clone()),
        ])
    }
}

/// Helper for building a `crit` protected header in tests (and for callers that legitimately
/// need critical params later). Encodes `{1: alg, 2: [crit labels...]}` canonically.
pub fn encode_protected_header_with_crit(alg: Alg, crit_labels: &[i64]) -> Vec<u8> {
    let id = cose_alg_id(alg);
    let alg_val = if id < 0 {
        Value::Nint((-1 - id) as u64)
    } else {
        Value::Uint(id as u64)
    };
    let crit = Value::Array(
        crit_labels
            .iter()
            .map(|&l| {
                if l < 0 {
                    Value::Nint((-1 - l) as u64)
                } else {
                    Value::Uint(l as u64)
                }
            })
            .collect(),
    );
    Value::Map(vec![
        (Value::Uint(label::ALG), alg_val),
        (Value::Uint(label::CRIT), crit),
    ])
    .to_canonical()
}

// Re-export a tiny helper so downstream crates can prepend a CBOR head without re-importing.
#[doc(hidden)]
pub fn _write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    write_head(out, major, arg)
}
