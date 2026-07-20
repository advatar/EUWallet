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
    pub const X5CHAIN: u64 = 33; // X.509 certificate or leaf-first chain (RFC 9360)
}

/// Resource limits for remotely supplied RFC 9360 certificate-chain evidence. These bounds apply
/// before certificate bytes are cloned into the retained header representation.
pub const MAX_X5CHAIN_CERTIFICATES: usize = 8;
pub const MAX_X5CHAIN_CERTIFICATE_BYTES: usize = 64 * 1024;
pub const MAX_X5CHAIN_TOTAL_BYTES: usize = 256 * 1024;

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

/// The two wire representations permitted for the RFC 9360 `x5chain` header. Certificates are
/// retained as DER bytes in leaf-first order. This is evidence only; presence never establishes
/// trust or proves that a certification path is valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X5Chain {
    Single(Vec<u8>),
    Chain(Vec<Vec<u8>>),
}

impl X5Chain {
    /// Certificates in RFC 9360 leaf-first order.
    pub fn certificates(&self) -> Vec<&[u8]> {
        match self {
            Self::Single(certificate) => vec![certificate],
            Self::Chain(certificates) => certificates.iter().map(Vec::as_slice).collect(),
        }
    }

    fn validate(&self) -> Result<(), CoseError> {
        match self {
            Self::Single(certificate) => {
                let mut total = 0;
                check_certificate_size(certificate, &mut total)
            }
            Self::Chain(certificates) => {
                if !(2..=MAX_X5CHAIN_CERTIFICATES).contains(&certificates.len()) {
                    return Err(CoseError::MalformedHeader);
                }
                let mut total = 0;
                for certificate in certificates {
                    check_certificate_size(certificate, &mut total)?;
                }
                Ok(())
            }
        }
    }

    fn from_value(value: &Value) -> Result<Self, CoseError> {
        match value {
            Value::Bytes(certificate) => {
                let mut total = 0;
                check_certificate_size(certificate, &mut total)?;
                Ok(Self::Single(certificate.clone()))
            }
            Value::Array(certificates) => {
                if !(2..=MAX_X5CHAIN_CERTIFICATES).contains(&certificates.len()) {
                    return Err(CoseError::MalformedHeader);
                }
                let mut total = 0;
                for certificate in certificates {
                    let Value::Bytes(certificate) = certificate else {
                        return Err(CoseError::MalformedHeader);
                    };
                    check_certificate_size(certificate, &mut total)?;
                }
                // Shape and sizes are bounded before retaining a second Vec-of-DER copy.
                Ok(Self::Chain(
                    certificates
                        .iter()
                        .map(|certificate| match certificate {
                            Value::Bytes(bytes) => Ok(bytes.clone()),
                            _ => Err(CoseError::MalformedHeader),
                        })
                        .collect::<Result<_, _>>()?,
                ))
            }
            _ => Err(CoseError::MalformedHeader),
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Single(certificate) => Value::Bytes(certificate.clone()),
            Self::Chain(certificates) => Value::Array(
                certificates
                    .iter()
                    .map(|certificate| Value::Bytes(certificate.clone()))
                    .collect(),
            ),
        }
    }
}

fn check_certificate_size(certificate: &[u8], total: &mut usize) -> Result<(), CoseError> {
    if certificate.is_empty() || certificate.len() > MAX_X5CHAIN_CERTIFICATE_BYTES {
        return Err(CoseError::MalformedHeader);
    }
    *total = total
        .checked_add(certificate.len())
        .filter(|total| *total <= MAX_X5CHAIN_TOTAL_BYTES)
        .ok_or(CoseError::MalformedHeader)?;
    Ok(())
}

/// The unprotected header (not covered by the signature).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnprotectedHeader {
    pub kid: Option<Vec<u8>>,
    pub x5chain: Option<Box<X5Chain>>,
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

#[derive(Debug)]
struct ProtectedHeader {
    alg: Alg,
    kid: Option<Vec<u8>>,
    x5chain: Option<X5Chain>,
}

fn integer_label(value: &Value) -> Result<i64, CoseError> {
    match value {
        Value::Uint(value) => i64::try_from(*value).map_err(|_| CoseError::MalformedHeader),
        Value::Nint(value) => i64::try_from(*value)
            .map(|value| -1 - value)
            .map_err(|_| CoseError::MalformedHeader),
        _ => Err(CoseError::MalformedHeader),
    }
}

fn header_value(pairs: &[(Value, Value)], label: u64) -> Option<&Value> {
    pairs
        .iter()
        .find_map(|(key, value)| (key == &Value::Uint(label)).then_some(value))
}

fn check_unique_header_labels(pairs: &[(Value, Value)]) -> Result<(), CoseError> {
    for (index, (label, _)) in pairs.iter().enumerate() {
        if pairs[..index]
            .iter()
            .any(|(previous_label, _)| previous_label == label)
        {
            return Err(CoseError::MalformedHeader);
        }
    }
    Ok(())
}

/// Parse a protected header and reject malformed or unsupported critical parameters.
fn parse_and_check_protected_header(protected: &[u8]) -> Result<ProtectedHeader, CoseError> {
    let value = cbor::from_canonical_slice(protected).map_err(|_| CoseError::MalformedHeader)?;
    let Value::Map(pairs) = value else {
        return Err(CoseError::MalformedHeader);
    };
    check_unique_header_labels(&pairs)?;

    // If `crit` is present, every listed label must be one we understand, or we fail closed.
    if let Some(crit) = header_value(&pairs, label::CRIT) {
        let Value::Array(items) = crit else {
            return Err(CoseError::MalformedHeader);
        };
        if items.is_empty() {
            return Err(CoseError::MalformedHeader);
        }
        let mut seen = Vec::new();
        for item in items {
            let lbl = integer_label(item)?;
            // The only protected-header labels we implement.
            if lbl == label::CRIT as i64 {
                return Err(CoseError::MalformedHeader);
            }
            if lbl != label::ALG as i64 && lbl != label::KID as i64 && lbl != label::X5CHAIN as i64
            {
                return Err(CoseError::UnknownCriticalParam(lbl));
            }
            if seen.iter().any(|seen_item| seen_item == item)
                || !pairs.iter().any(|(key, _)| key == item)
            {
                return Err(CoseError::MalformedHeader);
            }
            seen.push(item.clone());
        }
    }

    // Extract and map the algorithm.
    let alg = alg_from_id(integer_label(
        header_value(&pairs, label::ALG).ok_or(CoseError::MalformedHeader)?,
    )?)
    .ok_or(CoseError::MalformedHeader)?;
    let kid = match header_value(&pairs, label::KID) {
        Some(Value::Bytes(kid)) => Some(kid.clone()),
        Some(_) => return Err(CoseError::MalformedHeader),
        None => None,
    };
    let x5chain = header_value(&pairs, label::X5CHAIN)
        .map(X5Chain::from_value)
        .transpose()?;
    Ok(ProtectedHeader { alg, kid, x5chain })
}

fn parse_unprotected_header(value: &Value) -> Result<UnprotectedHeader, CoseError> {
    let Value::Map(pairs) = value else {
        return Err(CoseError::MalformedStructure);
    };
    check_unique_header_labels(pairs)?;
    // This profile requires `alg` and `crit` to be integrity-protected. `alg` is already present
    // in the protected bucket, so accepting it here would also violate COSE's no-duplicate rule.
    if header_value(pairs, label::ALG).is_some() || header_value(pairs, label::CRIT).is_some() {
        return Err(CoseError::MalformedHeader);
    }
    let kid = match header_value(pairs, label::KID) {
        Some(Value::Bytes(kid)) => Some(kid.clone()),
        Some(_) => return Err(CoseError::MalformedHeader),
        None => None,
    };
    let x5chain = header_value(pairs, label::X5CHAIN)
        .map(X5Chain::from_value)
        .transpose()?
        .map(Box::new);
    // Unknown unprotected labels are permitted by COSE because they are not declared critical.
    // This profile ignores and does not re-emit them. Every supported label is parsed above;
    // unknown labels named by protected `crit` still fail closed in the protected parser.
    Ok(UnprotectedHeader { kid, x5chain })
}

fn check_header_collisions(
    protected: &ProtectedHeader,
    unprotected: &UnprotectedHeader,
) -> Result<(), CoseError> {
    if protected.kid.is_some() && unprotected.kid.is_some()
        || protected.x5chain.is_some() && unprotected.x5chain.is_some()
    {
        return Err(CoseError::MalformedHeader);
    }
    if let Some(x5chain) = &unprotected.x5chain {
        x5chain.validate()?;
    }
    Ok(())
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
        let protected_header = parse_and_check_protected_header(&protected)?;
        check_header_collisions(&protected_header, &unprotected)?;
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
        let protected_header = parse_and_check_protected_header(&self.protected)?;
        check_header_collisions(&protected_header, &self.unprotected)?;
        if protected_header.alg != expected_alg {
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

    /// Return RFC 9360 certificate-chain evidence from either header bucket after validating its
    /// shape and the COSE no-duplicate rule. The result is intentionally just evidence: callers
    /// must authenticate and path-validate it against an approved trust policy before use.
    pub fn x5chain(&self) -> Result<Option<X5Chain>, CoseError> {
        let protected = parse_and_check_protected_header(&self.protected)?;
        check_header_collisions(&protected, &self.unprotected)?;
        Ok(protected
            .x5chain
            .or_else(|| self.unprotected.x5chain.as_deref().cloned()))
    }

    /// Parse a COSE_Sign1 from its wire structure (the inverse of [`to_value`]):
    /// `[ protected: bstr, unprotected: map, payload: bstr / nil, signature: bstr ]`.
    /// The supported `kid` and RFC 9360 `x5chain` parameters are retained; protected bytes remain
    /// byte-for-byte intact because they are part of the signature input. Unknown noncritical
    /// unprotected parameters are accepted but ignored and therefore are not re-emitted.
    pub fn from_value(v: &Value) -> Result<Self, CoseError> {
        let Value::Array(items) = v else {
            return Err(CoseError::MalformedStructure);
        };
        if items.len() != 4 {
            return Err(CoseError::MalformedStructure);
        }
        let protected = match &items[0] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(CoseError::MalformedStructure),
        };
        let protected_header = parse_and_check_protected_header(&protected)?;
        let unprotected = parse_unprotected_header(&items[1])?;
        check_header_collisions(&protected_header, &unprotected)?;
        let payload = match &items[2] {
            Value::Bytes(b) => Some(b.clone()),
            Value::Null => None,
            _ => return Err(CoseError::MalformedStructure),
        };
        let signature = match &items[3] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(CoseError::MalformedStructure),
        };
        Ok(CoseSign1 {
            protected,
            unprotected,
            payload,
            signature,
        })
    }

    /// Encode as the COSE_Sign1 wire structure (RFC 9052 §4.2):
    /// `[ protected: bstr, unprotected: map, payload: bstr / nil, signature: bstr ]`.
    /// A detached payload (`None`) is encoded as CBOR `null`.
    pub fn to_value(&self) -> Value {
        let mut unprotected_pairs = Vec::new();
        if let Some(kid) = &self.unprotected.kid {
            unprotected_pairs.push((Value::Uint(label::KID), Value::Bytes(kid.clone())));
        }
        if let Some(x5chain) = &self.unprotected.x5chain {
            unprotected_pairs.push((Value::Uint(label::X5CHAIN), x5chain.to_value()));
        }
        let unprotected = Value::Map(unprotected_pairs);
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
