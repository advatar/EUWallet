#![forbid(unsafe_code)]
//! `sdjwt` — RFC 9901 SD-JWT processing with an SD-JWT VC draft-17 profile.
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
use std::collections::{BTreeMap, BTreeSet};

const MAX_COMPACT_BYTES: usize = 1024 * 1024;
const MAX_JWS_BYTES: usize = 512 * 1024;
const MAX_DISCLOSURE_BYTES: usize = 64 * 1024;
const MAX_DISCLOSURES: usize = 256;
const MAX_NESTING_DEPTH: usize = 32;
const MAX_EMBEDDED_DIGESTS: usize = 4_096;
const MAX_PROCESSED_JSON_BYTES: usize = 2 * 1024 * 1024;

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
    /// An input exceeded the wallet's explicit parser budget.
    TooLarge,
    /// A JSON segment did not parse, or was not the expected shape.
    InvalidJson,
    /// The JOSE header used `alg: none`, which is never acceptable.
    AlgNone,
    /// The JOSE header `alg` was missing or not one we support.
    UnsupportedAlg,
    /// The JOSE `typ` header was not the required `dc+sd-jwt` media type.
    InvalidType,
    /// A `crit` header member we do not understand → fail closed.
    UnknownCriticalParam,
    /// `_sd_alg` named a hash we do not implement.
    UnsupportedHashAlg,
    /// A presented disclosure's digest was not present in the SD-JWT's `_sd` array → tampering.
    UnknownDisclosure,
    /// A claim name or disclosure digest appeared more than once.
    DuplicateClaim,
    /// The key-binding JWT was missing, or its aud/nonce/sd_hash did not match expectations.
    KeyBindingMismatch,
    /// The signature did not verify.
    Crypto(CryptoError),
}

/// What the relying party checks the holder's key-binding JWT against.
pub struct KeyBindingCheck<'a> {
    /// The holder/device public key (raw), from the credential's `cnf` in production.
    pub device_public_key: &'a [u8],
    /// The RP's client_id — must equal the KB-JWT `aud`.
    pub expected_aud: &'a str,
    /// The nonce from the RP's request — must equal the KB-JWT `nonce`. OpenID4VP 1.0 defines the
    /// nonce as an opaque string, so this compares byte-for-byte, never numerically.
    pub expected_nonce: &'a str,
    /// The algorithm the device signs with.
    pub device_alg: Alg,
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

/// One component of a verified disclosure's exact location in the processed JSON document.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimPathElement {
    Name(String),
    Index(usize),
}

/// A disclosure that was reached from an issuer-signed digest placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDisclosure {
    pub raw: String,
    pub digest: String,
    pub path: Vec<ClaimPathElement>,
    /// The closest enclosing disclosure. A child cannot be presented without this dependency.
    pub parent_digest: Option<String>,
    pub value: Json,
}

/// RFC 9901's Processed SD-JWT Payload plus authenticated disclosure locations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessedSdJwt {
    pub claims: serde_json::Map<String, Json>,
    pub disclosures: Vec<VerifiedDisclosure>,
}

impl Disclosure {
    /// Parse a single base64url disclosure string.
    pub fn parse(raw: &str) -> Result<Self, SdJwtError> {
        if raw.len() > MAX_DISCLOSURE_BYTES {
            return Err(SdJwtError::TooLarge);
        }
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
        if compact.len() > MAX_COMPACT_BYTES {
            return Err(SdJwtError::TooLarge);
        }
        let mut parts: Vec<&str> = compact.split('~').collect();
        if parts.len() < 2 {
            // Must be at least "<jwt>~".
            return Err(SdJwtError::Malformed);
        }
        let issuer_jwt = parts.remove(0).to_string();
        if issuer_jwt.len() > MAX_JWS_BYTES {
            return Err(SdJwtError::TooLarge);
        }
        if issuer_jwt.is_empty() || issuer_jwt.matches('.').count() != 2 {
            return Err(SdJwtError::Malformed);
        }
        // The final element is the KB-JWT slot (empty string when absent).
        let kb = parts.pop().unwrap_or("");
        let key_binding_jwt = if kb.is_empty() {
            None
        } else {
            if kb.len() > MAX_JWS_BYTES {
                return Err(SdJwtError::TooLarge);
            }
            if kb.matches('.').count() != 2 {
                return Err(SdJwtError::Malformed);
            }
            Some(kb.to_string())
        };
        // Remaining parts are disclosures; none may be empty.
        if parts.len() > MAX_DISCLOSURES || parts.iter().any(|p| p.len() > MAX_DISCLOSURE_BYTES) {
            return Err(SdJwtError::TooLarge);
        }
        if parts.iter().any(|p| p.is_empty()) {
            return Err(SdJwtError::Malformed);
        }
        Ok(SdJwtVc {
            issuer_jwt,
            disclosures: parts.into_iter().map(|s| s.to_string()).collect(),
            key_binding_jwt,
        })
    }

    /// Verify the issuer signature and run RFC 9901's recursive disclosure-processing algorithm.
    pub fn verify_and_process(
        &self,
        verifier: &dyn Verifier,
        digest: &dyn crypto_traits::Digest,
        issuer_public_key: &[u8],
        expected_alg: Alg,
    ) -> Result<ProcessedSdJwt, SdJwtError> {
        let (header, payload_bytes, signing_input, signature) = split_jws(&self.issuer_jwt)?;

        // 1) Header: reject alg:none / unknown alg / unknown crit; enforce the expected alg and
        // the SD-JWT VC media type. `typ: dc+sd-jwt` is mandatory in draft-17 and prevents a JWT
        // minted for another protocol from being confused for a credential.
        let hdr_alg = parse_jose_alg(&header)?;
        if hdr_alg != expected_alg {
            return Err(SdJwtError::UnsupportedAlg);
        }
        if header.get("typ").and_then(|v| v.as_str()) != Some("dc+sd-jwt") {
            return Err(SdJwtError::InvalidType);
        }

        // 2) Verify the signature over ASCII(header_b64 "." payload_b64).
        verifier.verify(
            expected_alg,
            issuer_public_key,
            signing_input.as_bytes(),
            &signature,
        )?;

        // 3) Parse the payload and confirm the hash algorithm.
        let mut payload: Json =
            serde_json::from_slice(&payload_bytes).map_err(|_| SdJwtError::InvalidJson)?;
        let obj = payload.as_object().ok_or(SdJwtError::InvalidJson)?;
        match obj.get(SD_ALG_CLAIM) {
            None => {}
            Some(Json::String(value)) if value == "sha-256" => {}
            Some(Json::String(_)) => return Err(SdJwtError::UnsupportedHashAlg),
            Some(_) => return Err(SdJwtError::InvalidJson),
        }

        // 4) Index every provided Disclosure once. A repeated Disclosure (or digest collision) is
        // invalid even when the duplicate appears at a different place in the combined format.
        let mut disclosure_by_digest = BTreeMap::new();
        for raw in &self.disclosures {
            let disclosure = Disclosure::parse(raw)?;
            let disclosure_digest = disclosure.digest_b64(digest);
            if disclosure_by_digest
                .insert(disclosure_digest, disclosure)
                .is_some()
            {
                return Err(SdJwtError::DuplicateClaim);
            }
        }

        // 5) Recursively replace matching object and array placeholders. Missing matches are
        // decoys or intentionally undisclosed claims and are removed from the processed payload.
        let initial_bytes = serde_json::to_vec(&payload)
            .map_err(|_| SdJwtError::InvalidJson)?
            .len();
        let mut processor = DisclosureProcessor {
            disclosure_by_digest,
            used_disclosures: BTreeSet::new(),
            encountered_digests: BTreeSet::new(),
            verified: Vec::new(),
            embedded_digest_count: 0,
            output_budget: initial_bytes,
        };
        processor.process_value(&mut payload, &[], None, 0, true)?;
        if processor.used_disclosures.len() != processor.disclosure_by_digest.len() {
            return Err(SdJwtError::UnknownDisclosure);
        }
        if serde_json::to_vec(&payload)
            .map_err(|_| SdJwtError::InvalidJson)?
            .len()
            > MAX_PROCESSED_JSON_BYTES
        {
            return Err(SdJwtError::TooLarge);
        }
        let claims = payload
            .as_object()
            .cloned()
            .ok_or(SdJwtError::InvalidJson)?;
        Ok(ProcessedSdJwt {
            claims,
            disclosures: processor.verified,
        })
    }

    /// Compatibility wrapper returning only the processed claim map.
    pub fn verify_and_disclose(
        &self,
        verifier: &dyn Verifier,
        digest: &dyn crypto_traits::Digest,
        issuer_public_key: &[u8],
        expected_alg: Alg,
    ) -> Result<serde_json::Map<String, Json>, SdJwtError> {
        self.verify_and_process(verifier, digest, issuer_public_key, expected_alg)
            .map(|processed| processed.claims)
    }

    /// Parse and validate the issuer JWT's JOSE header and return its signing algorithm.
    ///
    /// Holders use this before signature verification so algorithm selection comes from the
    /// protected header and is still constrained by their local algorithm policy.
    pub fn issuer_algorithm(&self) -> Result<Alg, SdJwtError> {
        let (header, _, _, _) = split_jws(&self.issuer_jwt)?;
        if header.get("typ").and_then(|v| v.as_str()) != Some("dc+sd-jwt") {
            return Err(SdJwtError::InvalidType);
        }
        parse_jose_alg(&header)
    }

    /// Decode the issuer-signed payload without applying disclosures.
    ///
    /// Callers use this only after signature verification to enforce that protocol control claims
    /// such as `vct` and `cnf` were not made selectively disclosable.
    pub fn issuer_payload(&self) -> Result<serde_json::Map<String, Json>, SdJwtError> {
        let (_, payload, _, _) = split_jws(&self.issuer_jwt)?;
        serde_json::from_slice::<Json>(&payload)
            .map_err(|_| SdJwtError::InvalidJson)?
            .as_object()
            .cloned()
            .ok_or(SdJwtError::InvalidJson)
    }
}

struct DisclosureProcessor {
    disclosure_by_digest: BTreeMap<String, Disclosure>,
    used_disclosures: BTreeSet<String>,
    encountered_digests: BTreeSet<String>,
    verified: Vec<VerifiedDisclosure>,
    embedded_digest_count: usize,
    output_budget: usize,
}

impl DisclosureProcessor {
    fn process_value(
        &mut self,
        value: &mut Json,
        path: &[ClaimPathElement],
        parent_digest: Option<&str>,
        depth: usize,
        is_root: bool,
    ) -> Result<(), SdJwtError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(SdJwtError::TooLarge);
        }
        match value {
            Json::Object(object) => {
                if is_root {
                    object.remove(SD_ALG_CLAIM);
                } else if object.contains_key(SD_ALG_CLAIM) {
                    return Err(SdJwtError::InvalidJson);
                }
                if object.contains_key("...") {
                    // `...` is legal only as the sole member of an array placeholder object.
                    return Err(SdJwtError::InvalidJson);
                }

                let digest_values = match object.remove(SD_CLAIM) {
                    None => Vec::new(),
                    Some(Json::Array(values)) => values,
                    Some(_) => return Err(SdJwtError::InvalidJson),
                };

                // Permanent nested values can themselves contain digest placeholders.
                let permanent_names: Vec<String> = object.keys().cloned().collect();
                for name in permanent_names {
                    let mut child_path = path.to_vec();
                    child_path.push(ClaimPathElement::Name(name.clone()));
                    let child = object.get_mut(&name).ok_or(SdJwtError::InvalidJson)?;
                    self.process_value(child, &child_path, parent_digest, depth + 1, false)?;
                }

                for digest_value in digest_values {
                    let disclosure_digest = digest_value
                        .as_str()
                        .ok_or(SdJwtError::InvalidJson)?
                        .to_string();
                    self.encounter_digest(&disclosure_digest)?;
                    let Some(disclosure) =
                        self.disclosure_by_digest.get(&disclosure_digest).cloned()
                    else {
                        continue;
                    };
                    let name = disclosure.name.clone().ok_or(SdJwtError::InvalidJson)?;
                    if matches!(name.as_str(), SD_CLAIM | SD_ALG_CLAIM | "...") {
                        return Err(SdJwtError::InvalidJson);
                    }
                    if object.contains_key(&name) {
                        return Err(SdJwtError::DuplicateClaim);
                    }
                    self.consume_budget(&disclosure.value)?;
                    let mut child_path = path.to_vec();
                    child_path.push(ClaimPathElement::Name(name.clone()));
                    self.record_disclosure(
                        &disclosure_digest,
                        &disclosure,
                        &child_path,
                        parent_digest,
                    )?;
                    let mut disclosed_value = disclosure.value;
                    self.process_value(
                        &mut disclosed_value,
                        &child_path,
                        Some(&disclosure_digest),
                        depth + 1,
                        false,
                    )?;
                    object.insert(name, disclosed_value);
                }
            }
            Json::Array(array) => {
                let original = core::mem::take(array);
                let mut processed = Vec::with_capacity(original.len());
                for mut element in original {
                    let placeholder = match &element {
                        Json::Object(object) if object.contains_key("...") => {
                            if object.len() != 1 {
                                return Err(SdJwtError::InvalidJson);
                            }
                            Some(
                                object
                                    .get("...")
                                    .and_then(Json::as_str)
                                    .ok_or(SdJwtError::InvalidJson)?
                                    .to_string(),
                            )
                        }
                        _ => None,
                    };
                    if let Some(disclosure_digest) = placeholder {
                        self.encounter_digest(&disclosure_digest)?;
                        let Some(disclosure) =
                            self.disclosure_by_digest.get(&disclosure_digest).cloned()
                        else {
                            // Undisclosed array elements and decoys disappear entirely.
                            continue;
                        };
                        if disclosure.name.is_some() {
                            return Err(SdJwtError::InvalidJson);
                        }
                        self.consume_budget(&disclosure.value)?;
                        let mut child_path = path.to_vec();
                        child_path.push(ClaimPathElement::Index(processed.len()));
                        self.record_disclosure(
                            &disclosure_digest,
                            &disclosure,
                            &child_path,
                            parent_digest,
                        )?;
                        let mut disclosed_value = disclosure.value;
                        self.process_value(
                            &mut disclosed_value,
                            &child_path,
                            Some(&disclosure_digest),
                            depth + 1,
                            false,
                        )?;
                        processed.push(disclosed_value);
                    } else {
                        let mut child_path = path.to_vec();
                        child_path.push(ClaimPathElement::Index(processed.len()));
                        self.process_value(
                            &mut element,
                            &child_path,
                            parent_digest,
                            depth + 1,
                            false,
                        )?;
                        processed.push(element);
                    }
                }
                *array = processed;
            }
            _ => {}
        }
        Ok(())
    }

    fn encounter_digest(&mut self, digest: &str) -> Result<(), SdJwtError> {
        let decoded =
            Base64UrlUnpadded::decode_vec(digest).map_err(|_| SdJwtError::InvalidBase64)?;
        if decoded.len() != 32 {
            return Err(SdJwtError::InvalidJson);
        }
        self.embedded_digest_count = self
            .embedded_digest_count
            .checked_add(1)
            .ok_or(SdJwtError::TooLarge)?;
        if self.embedded_digest_count > MAX_EMBEDDED_DIGESTS {
            return Err(SdJwtError::TooLarge);
        }
        if !self.encountered_digests.insert(digest.to_string()) {
            return Err(SdJwtError::DuplicateClaim);
        }
        Ok(())
    }

    fn consume_budget(&mut self, value: &Json) -> Result<(), SdJwtError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|_| SdJwtError::InvalidJson)?
            .len();
        self.output_budget = self
            .output_budget
            .checked_add(bytes)
            .ok_or(SdJwtError::TooLarge)?;
        if self.output_budget > MAX_PROCESSED_JSON_BYTES {
            return Err(SdJwtError::TooLarge);
        }
        Ok(())
    }

    fn record_disclosure(
        &mut self,
        digest: &str,
        disclosure: &Disclosure,
        path: &[ClaimPathElement],
        parent_digest: Option<&str>,
    ) -> Result<(), SdJwtError> {
        if !self.used_disclosures.insert(digest.to_string()) {
            return Err(SdJwtError::DuplicateClaim);
        }
        self.verified.push(VerifiedDisclosure {
            raw: disclosure.raw.clone(),
            digest: digest.to_string(),
            path: path.to_vec(),
            parent_digest: parent_digest.map(String::from),
            value: disclosure.value.clone(),
        });
        Ok(())
    }
}

impl SdJwtVc {
    /// Full presentation verification (RP side): verify the issuer signature and disclosures,
    /// then verify the holder's key-binding JWT — its signature (device key), `aud` (this RP),
    /// `nonce` (this request), and `sd_hash` (binds to exactly these disclosures). Returns the
    /// disclosed claims only if everything checks out.
    pub fn verify_presentation(
        &self,
        verifier: &dyn Verifier,
        digest: &dyn crypto_traits::Digest,
        issuer_public_key: &[u8],
        issuer_alg: Alg,
        kb: &KeyBindingCheck,
    ) -> Result<serde_json::Map<String, Json>, SdJwtError> {
        let claims = self.verify_and_disclose(verifier, digest, issuer_public_key, issuer_alg)?;

        let kb_jwt = self
            .key_binding_jwt
            .as_ref()
            .ok_or(SdJwtError::KeyBindingMismatch)?;
        let (header, payload_bytes, signing_input, signature) = split_jws(kb_jwt)?;
        let kb_alg = parse_jose_alg(&header)?;
        if kb_alg != kb.device_alg || header.get("typ").and_then(Json::as_str) != Some("kb+jwt") {
            return Err(SdJwtError::KeyBindingMismatch);
        }
        verifier.verify(
            kb.device_alg,
            kb.device_public_key,
            signing_input.as_bytes(),
            &signature,
        )?;

        let payload: Json =
            serde_json::from_slice(&payload_bytes).map_err(|_| SdJwtError::InvalidJson)?;
        let obj = payload.as_object().ok_or(SdJwtError::InvalidJson)?;

        if obj.get("iat").and_then(Json::as_i64).is_none() {
            return Err(SdJwtError::KeyBindingMismatch);
        }

        if obj.get("aud").and_then(|v| v.as_str()) != Some(kb.expected_aud) {
            return Err(SdJwtError::KeyBindingMismatch);
        }
        // The KB-JWT `nonce` MUST echo the verifier's opaque request nonce verbatim as a JSON
        // string (OpenID4VP 1.0); a numeric or mismatched nonce is a binding failure.
        if obj.get("nonce").and_then(|v| v.as_str()) != Some(kb.expected_nonce) {
            return Err(SdJwtError::KeyBindingMismatch);
        }

        // sd_hash must be base64url(SHA-256(<issuer-jwt>~<disclosure>~...~)).
        let mut presentation = String::from(&self.issuer_jwt);
        for d in &self.disclosures {
            presentation.push('~');
            presentation.push_str(d);
        }
        presentation.push('~');
        let want = Base64UrlUnpadded::encode_string(&digest.sha256(presentation.as_bytes()));
        if obj.get("sd_hash").and_then(|v| v.as_str()) != Some(want.as_str()) {
            return Err(SdJwtError::KeyBindingMismatch);
        }

        Ok(claims)
    }
}

/// Split a compact JWS into (decoded header JSON, decoded payload bytes, signing input, signature).
fn split_jws(jwt: &str) -> Result<(Json, Vec<u8>, String, Vec<u8>), SdJwtError> {
    if jwt.len() > MAX_JWS_BYTES {
        return Err(SdJwtError::TooLarge);
    }
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
