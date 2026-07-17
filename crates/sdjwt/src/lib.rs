#![forbid(unsafe_code)]
//! `sdjwt` — SD-JWT VC credential format (IETF draft-17) with selective disclosure.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4.3.
//!
//! An SD-JWT VC is an issuer-signed JWT (RFC 7515 JWS over RFC 7519 claims), a set of
//! base64url **Disclosures**, and an optional **Key-Binding JWT**, serialized as
//! `<issuer-jwt>~<disclosure>~...~<optional-kb-jwt>`. This crate parses that structure,
//! verifies the issuer signature through the [`crypto_traits`] boundary (it never implements a
//! signature algorithm), and reconstructs the disclosed claim set. It is pinned to draft-17 and
//! all draft-specific choices are gated behind [`SD_JWT_VC_DRAFT`].

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, CryptoError, Verifier};
use serde_json::Value as Json;

/// Pinned wire version. Isolate the codec behind this marker: SD-JWT VC is a moving draft, not
/// an RFC (register change-watch). A silent bump must break the build (see the test).
pub const SD_JWT_VC_DRAFT: &str = "draft-17";

/// The claim carrying the array of selectively-disclosable digests (draft-17 §4.2.4.1).
const SD_CLAIM: &str = "_sd";
/// The claim naming the hash algorithm for disclosure digests (default SHA-256).
const SD_ALG_CLAIM: &str = "_sd_alg";

#[derive(Debug, PartialEq, Eq)]
pub enum SdJwtError {
    /// Combined serialization was structurally invalid (segments, `~`, JWT dots).
    Malformed,
    /// A base64url segment did not decode.
    InvalidBase64,
    /// A JSON segment did not parse, or was not the expected shape.
    InvalidJson,
    /// The JOSE header used `alg: none`, which is never acceptable.
    AlgNone,
    /// The JOSE header `alg` was missing or not one we support.
    UnsupportedAlg,
    /// A `crit` header member we do not understand → fail closed.
    UnknownCriticalParam,
    /// `_sd_alg` named a hash we do not implement.
    UnsupportedHashAlg,
    /// A presented disclosure's digest was not present in the SD-JWT's `_sd` array → tampering.
    UnknownDisclosure,
    /// The signature did not verify.
    Crypto(CryptoError),
}

impl From<CryptoError> for SdJwtError {
    fn from(e: CryptoError) -> Self {
        SdJwtError::Crypto(e)
    }
}

/// One disclosure. For an object member it is `[salt, name, value]`; for an array element it is
/// `[salt, value]` (draft-17 §4.2). `raw` is the exact base64url text — its ASCII bytes are what
/// gets hashed, so we keep it verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    pub raw: String,
    pub salt: String,
    pub name: Option<String>,
    pub value: Json,
}

impl Disclosure {
    /// Parse a single base64url disclosure string.
    pub fn parse(raw: &str) -> Result<Self, SdJwtError> {
        let bytes = Base64UrlUnpadded::decode_vec(raw).map_err(|_| SdJwtError::InvalidBase64)?;
        let json: Json = serde_json::from_slice(&bytes).map_err(|_| SdJwtError::InvalidJson)?;
        let arr = json.as_array().ok_or(SdJwtError::InvalidJson)?;
        match arr.len() {
            // Object member: [salt, name, value]
            3 => {
                let salt = arr[0].as_str().ok_or(SdJwtError::InvalidJson)?.to_string();
                let name = arr[1].as_str().ok_or(SdJwtError::InvalidJson)?.to_string();
                Ok(Disclosure {
                    raw: raw.to_string(),
                    salt,
                    name: Some(name),
                    value: arr[2].clone(),
                })
            }
            // Array element: [salt, value]
            2 => {
                let salt = arr[0].as_str().ok_or(SdJwtError::InvalidJson)?.to_string();
                Ok(Disclosure {
                    raw: raw.to_string(),
                    salt,
                    name: None,
                    value: arr[1].clone(),
                })
            }
            _ => Err(SdJwtError::InvalidJson),
        }
    }

    /// The draft-17 digest: `base64url( SHA-256( ASCII(raw) ) )`, hashed via the crypto boundary.
    pub fn digest_b64(&self, digest: &dyn crypto_traits::Digest) -> String {
        let h = digest.sha256(self.raw.as_bytes());
        Base64UrlUnpadded::encode_string(&h)
    }
}

/// A parsed SD-JWT VC in combined serialization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SdJwtVc {
    pub issuer_jwt: String,
    pub disclosures: Vec<String>,
    pub key_binding_jwt: Option<String>,
}

impl SdJwtVc {
    /// Split the combined serialization on `~`. Per draft-17 §4, the last element is the
    /// (possibly empty) key-binding JWT: a trailing `~` means "no KB-JWT".
    pub fn parse(compact: &str) -> Result<Self, SdJwtError> {
        let mut parts: Vec<&str> = compact.split('~').collect();
        if parts.len() < 2 {
            // Must be at least "<jwt>~".
            return Err(SdJwtError::Malformed);
        }
        let issuer_jwt = parts.remove(0).to_string();
        if issuer_jwt.is_empty() || issuer_jwt.matches('.').count() != 2 {
            return Err(SdJwtError::Malformed);
        }
        // The final element is the KB-JWT slot (empty string when absent).
        let kb = parts.pop().unwrap_or("");
        let key_binding_jwt = if kb.is_empty() {
            None
        } else {
            if kb.matches('.').count() != 2 {
                return Err(SdJwtError::Malformed);
            }
            Some(kb.to_string())
        };
        // Remaining parts are disclosures; none may be empty.
        if parts.iter().any(|p| p.is_empty()) {
            return Err(SdJwtError::Malformed);
        }
        Ok(SdJwtVc {
            issuer_jwt,
            disclosures: parts.into_iter().map(|s| s.to_string()).collect(),
            key_binding_jwt,
        })
    }

    /// Verify the issuer signature and reconstruct the disclosed claim set: every presented
    /// disclosure must hash to an entry in the JWT's `_sd` array (else `UnknownDisclosure`), and
    /// the always-present (non-`_sd`) claims are included as-is.
    pub fn verify_and_disclose(
        &self,
        verifier: &dyn Verifier,
        digest: &dyn crypto_traits::Digest,
        issuer_public_key: &[u8],
        expected_alg: Alg,
    ) -> Result<serde_json::Map<String, Json>, SdJwtError> {
        let (header, payload_bytes, signing_input, signature) = split_jws(&self.issuer_jwt)?;

        // 1) Header: reject alg:none / unknown alg / unknown crit; enforce the expected alg.
        let hdr_alg = parse_jose_alg(&header)?;
        if hdr_alg != expected_alg {
            return Err(SdJwtError::UnsupportedAlg);
        }

        // 2) Verify the signature over ASCII(header_b64 "." payload_b64).
        verifier.verify(
            expected_alg,
            issuer_public_key,
            signing_input.as_bytes(),
            &signature,
        )?;

        // 3) Parse the payload and confirm the hash algorithm.
        let payload: Json =
            serde_json::from_slice(&payload_bytes).map_err(|_| SdJwtError::InvalidJson)?;
        let obj = payload.as_object().ok_or(SdJwtError::InvalidJson)?;
        match obj.get(SD_ALG_CLAIM).and_then(|v| v.as_str()) {
            None | Some("sha-256") | Some("SHA-256") => {}
            Some(_) => return Err(SdJwtError::UnsupportedHashAlg),
        }

        // 4) Collect the set of digests the issuer committed to.
        let sd_digests: Vec<String> = obj
            .get(SD_CLAIM)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // 5) Start from the plain (non-selective) claims.
        let mut result = serde_json::Map::new();
        for (k, v) in obj {
            if k != SD_CLAIM && k != SD_ALG_CLAIM {
                result.insert(k.clone(), v.clone());
            }
        }

        // 6) Add each disclosed object member, checking its digest is one the issuer signed.
        for raw in &self.disclosures {
            let d = Disclosure::parse(raw)?;
            let dig = d.digest_b64(digest);
            if !sd_digests.contains(&dig) {
                return Err(SdJwtError::UnknownDisclosure);
            }
            if let Some(name) = d.name {
                result.insert(name, d.value);
            }
        }
        Ok(result)
    }
}

/// Split a compact JWS into (decoded header JSON, decoded payload bytes, signing input, signature).
fn split_jws(jwt: &str) -> Result<(Json, Vec<u8>, String, Vec<u8>), SdJwtError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(SdJwtError::Malformed);
    }
    let header_bytes =
        Base64UrlUnpadded::decode_vec(parts[0]).map_err(|_| SdJwtError::InvalidBase64)?;
    let header: Json =
        serde_json::from_slice(&header_bytes).map_err(|_| SdJwtError::InvalidJson)?;
    let payload_bytes =
        Base64UrlUnpadded::decode_vec(parts[1]).map_err(|_| SdJwtError::InvalidBase64)?;
    let signature =
        Base64UrlUnpadded::decode_vec(parts[2]).map_err(|_| SdJwtError::InvalidBase64)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    Ok((header, payload_bytes, signing_input, signature))
}

/// Parse and validate the JOSE header, returning its algorithm.
fn parse_jose_alg(header: &Json) -> Result<Alg, SdJwtError> {
    let obj = header.as_object().ok_or(SdJwtError::InvalidJson)?;
    // Reject unknown critical parameters (RFC 7515 §4.1.11): every listed name must be understood.
    if let Some(crit) = obj.get("crit") {
        let arr = crit.as_array().ok_or(SdJwtError::InvalidJson)?;
        for c in arr {
            let name = c.as_str().ok_or(SdJwtError::InvalidJson)?;
            if !matches!(name, "alg" | "typ" | "kid") {
                return Err(SdJwtError::UnknownCriticalParam);
            }
        }
    }
    match obj.get("alg").and_then(|v| v.as_str()) {
        Some("none") => Err(SdJwtError::AlgNone),
        Some("ES256") => Ok(Alg::Es256),
        Some("ES384") => Ok(Alg::Es384),
        Some("EdDSA") => Ok(Alg::EdDsa),
        _ => Err(SdJwtError::UnsupportedAlg),
    }
}
