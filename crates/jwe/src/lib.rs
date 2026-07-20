#![forbid(unsafe_code)]
//! JWE compact serialization for OpenID4VP `direct_post.jwt` response encryption.
//!
//! Implements the single profile HAIP / OpenID4VP 1.0 §8.3 require for an encrypted authorization
//! response: key management **`ECDH-ES`** (direct key agreement, P-256) with content encryption
//! **`A256GCM`**. The content-encryption key is the ECDH shared secret run through the Concat KDF
//! (RFC 7518 §4.6 / NIST SP 800-56A — a single SHA-256 round for a 256-bit key).
//!
//! This crate is **pure assembly**: every primitive (ECDH agreement, SHA-256, AES-256-GCM, random
//! IV) comes through the [`crypto_traits`] boundary, so the wallet's real backend supplies them and
//! nothing here invents crypto. The wallet only ever *encrypts* (it is the sender); [`parse_compact`]
//! + [`JweParts::open`] exist for a verifier / the round-trip test that decrypts.

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Aead, CryptoError, Digest, KeyAgreement, Random};

/// Content-encryption algorithm: AES-256-GCM (matches the backend's AEAD).
const ENC: &str = "A256GCM";
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Derived-key length in **bits** for the Concat KDF `SuppPubInfo` (A256GCM ⇒ 256).
const KEYDATALEN_BITS: u32 = 256;

/// Failure assembling or opening a JWE.
#[derive(Debug)]
pub enum JweError {
    Crypto(CryptoError),
    Malformed(&'static str),
}

impl From<CryptoError> for JweError {
    fn from(e: CryptoError) -> Self {
        JweError::Crypto(e)
    }
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn unb64(s: &str, what: &'static str) -> Result<Vec<u8>, JweError> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| JweError::Malformed(what))
}

/// The Concat KDF (NIST SP 800-56A / RFC 7518 §4.6) for `ECDH-ES` + `A256GCM`. A 256-bit key fits
/// one SHA-256 round, so the derived key is `SHA-256(counter=1 ‖ Z ‖ OtherInfo)` where
/// `OtherInfo = AlgorithmID ‖ PartyUInfo ‖ PartyVInfo ‖ SuppPubInfo` — each of the first three is
/// length-prefixed (32-bit big-endian), and `SuppPubInfo` is the 32-bit key length in bits. `apu`
/// and `apv` are the **raw** (decoded) values, not their base64url header forms.
fn concat_kdf_a256gcm(digest: &dyn Digest, z: &[u8], apu: &[u8], apv: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(4 + z.len() + 32 + apu.len() + apv.len());
    input.extend_from_slice(&1u32.to_be_bytes()); // counter
    input.extend_from_slice(z);
    // AlgorithmID = Datalen ‖ "A256GCM"
    input.extend_from_slice(&(ENC.len() as u32).to_be_bytes());
    input.extend_from_slice(ENC.as_bytes());
    // PartyUInfo = Datalen ‖ apu
    input.extend_from_slice(&(apu.len() as u32).to_be_bytes());
    input.extend_from_slice(apu);
    // PartyVInfo = Datalen ‖ apv
    input.extend_from_slice(&(apv.len() as u32).to_be_bytes());
    input.extend_from_slice(apv);
    // SuppPubInfo = keydatalen in bits (not length-prefixed); SuppPrivInfo is empty.
    input.extend_from_slice(&KEYDATALEN_BITS.to_be_bytes());
    digest.sha256(&input)
}

/// Encrypt `plaintext` to `recipient_public` (uncompressed SEC1 P-256) as a compact JWE
/// (`ECDH-ES` + `A256GCM`), binding `apu`/`apv` (raw bytes) into both the key derivation and the
/// protected header. Returns the five-segment compact serialization.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_ecdh_es_a256gcm(
    plaintext: &[u8],
    recipient_public: &[u8],
    apu: &[u8],
    apv: &[u8],
    agreement: &dyn KeyAgreement,
    digest: &dyn Digest,
    aead: &dyn Aead,
    random: &dyn Random,
) -> Result<String, JweError> {
    let ecdh = agreement.ecdh_es_p256(recipient_public)?;
    if ecdh.ephemeral_public.len() != 65 || ecdh.ephemeral_public[0] != 0x04 {
        return Err(JweError::Malformed(
            "ephemeral key is not an uncompressed P-256 point",
        ));
    }
    let x = &ecdh.ephemeral_public[1..33];
    let y = &ecdh.ephemeral_public[33..65];

    // Protected header. Fixed key order; the verifier reads it back verbatim as the AEAD AAD.
    let header = format!(
        concat!(
            r#"{{"alg":"ECDH-ES","enc":"A256GCM","#,
            r#""epk":{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}},"#,
            r#""apu":"{}","apv":"{}"}}"#
        ),
        b64(x),
        b64(y),
        b64(apu),
        b64(apv)
    );
    let protected_b64 = b64(header.as_bytes());

    let cek = concat_kdf_a256gcm(digest, &ecdh.shared_secret, apu, apv);
    let mut iv = [0u8; IV_LEN];
    random.fill(&mut iv);

    // AAD = ASCII(protected header b64). The backend's `seal` returns ciphertext ‖ tag.
    let sealed = aead.seal(&cek, &iv, protected_b64.as_bytes(), plaintext)?;
    if sealed.len() < TAG_LEN {
        return Err(JweError::Malformed("aead output shorter than the tag"));
    }
    let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_LEN);

    // Compact: protected . encrypted_key(empty for ECDH-ES direct) . iv . ciphertext . tag
    Ok(format!(
        "{protected_b64}..{}.{}.{}",
        b64(&iv),
        b64(ciphertext),
        b64(tag)
    ))
}

/// The parsed pieces a recipient needs to recover `Z` (via its own key) and open a compact JWE.
pub struct JweParts {
    /// The sender's ephemeral public key (uncompressed SEC1 P-256) — agree against this for `Z`.
    pub ephemeral_public: Vec<u8>,
    /// The raw (decoded) `apu` / `apv`, fed back into the Concat KDF.
    pub apu: Vec<u8>,
    pub apv: Vec<u8>,
    protected_b64: String,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

fn epk_coord(epk: &serde_json::Value, key: &str) -> Result<Vec<u8>, JweError> {
    let s = epk
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or(JweError::Malformed("epk missing a coordinate"))?;
    let v = unb64(s, "bad epk coordinate base64")?;
    if v.len() != 32 {
        return Err(JweError::Malformed("epk coordinate is not 32 bytes"));
    }
    Ok(v)
}

/// Parse a compact JWE, enforcing the supported profile (`ECDH-ES` + `A256GCM`, empty
/// encrypted_key, P-256 `epk`) and exposing the ephemeral public key so the recipient can agree.
pub fn parse_compact(compact: &str) -> Result<JweParts, JweError> {
    let seg: Vec<&str> = compact.split('.').collect();
    if seg.len() != 5 {
        return Err(JweError::Malformed(
            "a compact JWE has exactly five segments",
        ));
    }
    if !seg[1].is_empty() {
        return Err(JweError::Malformed(
            "ECDH-ES direct requires an empty encrypted_key",
        ));
    }
    let header_bytes = unb64(seg[0], "bad protected-header base64")?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| JweError::Malformed("bad header JSON"))?;
    if header["alg"] != "ECDH-ES" || header["enc"] != "A256GCM" {
        return Err(JweError::Malformed("unsupported JWE alg/enc"));
    }
    let epk = &header["epk"];
    if epk["kty"] != "EC" || epk["crv"] != "P-256" {
        return Err(JweError::Malformed("epk is not a P-256 EC key"));
    }
    let x = epk_coord(epk, "x")?;
    let y = epk_coord(epk, "y")?;
    let mut ephemeral_public = Vec::with_capacity(65);
    ephemeral_public.push(0x04);
    ephemeral_public.extend_from_slice(&x);
    ephemeral_public.extend_from_slice(&y);

    let field = |k: &str| -> Vec<u8> {
        header
            .get(k)
            .and_then(|v| v.as_str())
            .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
            .unwrap_or_default()
    };
    Ok(JweParts {
        ephemeral_public,
        apu: field("apu"),
        apv: field("apv"),
        protected_b64: seg[0].to_string(),
        iv: unb64(seg[2], "bad iv base64")?,
        ciphertext: unb64(seg[3], "bad ciphertext base64")?,
        tag: unb64(seg[4], "bad tag base64")?,
    })
}

impl JweParts {
    /// Open the JWE given the recovered shared secret `Z`: re-derive the CEK via Concat KDF and
    /// AES-256-GCM-decrypt with the protected header as AAD. Fails closed on any tamper.
    pub fn open(
        &self,
        z: &[u8],
        digest: &dyn Digest,
        aead: &dyn Aead,
    ) -> Result<Vec<u8>, JweError> {
        let cek = concat_kdf_a256gcm(digest, z, &self.apu, &self.apv);
        let mut ct_and_tag = Vec::with_capacity(self.ciphertext.len() + self.tag.len());
        ct_and_tag.extend_from_slice(&self.ciphertext);
        ct_and_tag.extend_from_slice(&self.tag);
        aead.open(&cek, &self.iv, self.protected_b64.as_bytes(), &ct_and_tag)
            .map_err(JweError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_backend::{AwsLc, P256AgreementKey};

    #[test]
    fn ecdh_es_a256gcm_round_trips_to_a_stand_in_verifier() {
        let recipient = P256AgreementKey::generate().unwrap();
        let plaintext = br#"{"vp_token":{"mdl":"ZGV2aWNlcmVzcG9uc2U"},"state":"st-1"}"#;
        let apu = b"mdoc-generated-nonce-xyz";
        let apv = b"request-nonce-424242";

        let jwe = encrypt_ecdh_es_a256gcm(
            plaintext,
            recipient.public_raw(),
            apu,
            apv,
            &AwsLc,
            &AwsLc,
            &AwsLc,
            &AwsLc,
        )
        .expect("encrypt");
        assert_eq!(jwe.split('.').count(), 5, "five-segment compact JWE");
        assert!(
            jwe.contains(".."),
            "ECDH-ES direct ⇒ empty encrypted_key segment"
        );

        // The verifier parses, agrees to the same Z with its private key, and opens the response.
        let parts = parse_compact(&jwe).expect("parse");
        assert_eq!(parts.apu, apu, "apu recovered verbatim");
        assert_eq!(parts.apv, apv);
        let z = recipient
            .agree(&parts.ephemeral_public)
            .expect("recipient agrees");
        let opened = parts.open(&z, &AwsLc, &AwsLc).expect("open");
        assert_eq!(opened, plaintext, "decrypted plaintext matches");
    }

    #[test]
    fn a_tampered_ciphertext_fails_closed() {
        let recipient = P256AgreementKey::generate().unwrap();
        let jwe = encrypt_ecdh_es_a256gcm(
            b"secret",
            recipient.public_raw(),
            b"u",
            b"v",
            &AwsLc,
            &AwsLc,
            &AwsLc,
            &AwsLc,
        )
        .unwrap();
        // Flip the last character of the ciphertext segment.
        let mut seg: Vec<String> = jwe.split('.').map(String::from).collect();
        let ct = &mut seg[3];
        let last = ct.pop().unwrap();
        ct.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = seg.join(".");
        let parts = parse_compact(&tampered).unwrap();
        let z = recipient.agree(&parts.ephemeral_public).unwrap();
        assert!(
            parts.open(&z, &AwsLc, &AwsLc).is_err(),
            "GCM tag rejects tampering"
        );
    }

    #[test]
    fn a_wrong_recipient_cannot_open() {
        let recipient = P256AgreementKey::generate().unwrap();
        let attacker = P256AgreementKey::generate().unwrap();
        let jwe = encrypt_ecdh_es_a256gcm(
            b"secret",
            recipient.public_raw(),
            b"u",
            b"v",
            &AwsLc,
            &AwsLc,
            &AwsLc,
            &AwsLc,
        )
        .unwrap();
        let parts = parse_compact(&jwe).unwrap();
        // The attacker agrees with its OWN key → a different Z → wrong CEK → open fails.
        let z = attacker.agree(&parts.ephemeral_public).unwrap();
        assert!(
            parts.open(&z, &AwsLc, &AwsLc).is_err(),
            "only the intended recipient can open"
        );
    }
}
