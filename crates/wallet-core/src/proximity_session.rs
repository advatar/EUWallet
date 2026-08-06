//! ISO/IEC 18013-5 §9.1.1.4 / §9.1.1.5 "Session encryption" (cipher suite 1: ECDH P-256 +
//! HKDF-SHA-256 + AES-256-GCM).
//!
//! This is the **facade-side** crypto that sits *above* the sans-IO `iso18013-5` state machine.
//! That machine stays crypto-free and Lean-refined (all crypto facts reach it as `Env` booleans);
//! the key agreement, key derivation, and AEAD live here, mirroring how `encrypt_direct_post_jwt`
//! keeps JWE out of the sans-IO `oid4vp` core.
//!
//! Derivation (matches the two interop-tested reference implementations — spruceid/isomdl and
//! OpenWallet-Foundation/multipaz):
//! ```text
//! Z        = ECDH_P256(EDeviceKey.Priv, EReaderKey.Pub)          ; raw shared secret (32 bytes)
//! salt     = SHA-256( SessionTranscriptBytes )                   ; #6.24(bstr .cbor SessionTranscript)
//! SKDevice = HKDF-SHA256(ikm = Z, salt, info = "SKDevice", 32)
//! SKReader = HKDF-SHA256(ikm = Z, salt, info = "SKReader", 32)
//! ```
//! Encryption is AES-256-GCM with a 12-byte IV = `identifier(8) || counter(4, big-endian)`; the
//! mdoc identifier ends `..01`, the reader's `..00`; each direction keeps its own counter, first
//! value 1. The mdoc seals its SessionData with `SKDevice` and opens the reader's with `SKReader`.
//! AAD is empty; the GCM tag is appended to the ciphertext.
//!
//! NOTE (honest limit): no in-repo interop vector pins these constants, and the free 2020 *draft*
//! of 18013-5 specified a different, now-superseded scheme (empty `info` + a 1-byte salt). The
//! values here are the final 2021 edition as implemented by isomdl/multipaz; they are isolated as
//! named constants + one derivation function so a real-reader interop test can correct them in one
//! place if ever needed.

use cose::cbor::{decode_value, Value};
use crypto_traits::{Aead, Digest, Kdf};

/// HKDF `info` label for the mdoc/device session key (ASCII, no CBOR wrapping).
const INFO_SK_DEVICE: &[u8] = b"SKDevice";
/// HKDF `info` label for the reader session key.
const INFO_SK_READER: &[u8] = b"SKReader";
/// AES-256-GCM key length.
const SK_LEN: usize = 32;
/// AES-GCM IV length (the backend hard-asserts exactly this).
const IV_LEN: usize = 12;
/// The 8-byte IV identifier prefix for messages the mdoc/device sends (§9.1.1.5).
const IDENTIFIER_MDOC: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];
/// The 8-byte IV identifier prefix for messages the reader sends.
const IDENTIFIER_READER: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

/// Failures in session-encryption setup or use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// A COSE_Key was structurally invalid (not an EC2 map with 32-byte X/Y).
    MalformedKey,
    /// A COSE_Key was well-formed but not EC2 / P-256.
    UnsupportedKey,
    /// A SessionEstablishment / SessionData CBOR message was malformed.
    MalformedMessage,
    /// The AEAD rejected the input (bad tag / wrong key / tampering).
    Crypto,
    /// The per-direction message counter overflowed `u32` (2^32 messages — never in practice).
    CounterExhausted,
}

/// The two AES-256-GCM session keys derived per §9.1.1.4.
#[derive(Clone)]
pub struct SessionKeys {
    /// Key the mdoc encrypts with / the reader decrypts with.
    pub sk_device: Vec<u8>,
    /// Key the reader encrypts with / the mdoc decrypts with.
    pub sk_reader: Vec<u8>,
}

/// Derive `SKDevice` / `SKReader` from the raw ECDH shared secret `z` and the proximity
/// `session_transcript` bytes (the bare array from `iso18013_5::session_transcript`). The salt is
/// `SHA-256` of the tag-24-wrapped `SessionTranscriptBytes`.
pub fn derive_session_keys<P: Digest + Kdf>(
    provider: &P,
    z: &[u8],
    session_transcript: &[u8],
) -> SessionKeys {
    let salt = provider.sha256(&iso18013_5::session_transcript_bytes(session_transcript));
    SessionKeys {
        sk_device: provider.hkdf_sha256(z, &salt, INFO_SK_DEVICE, SK_LEN),
        sk_reader: provider.hkdf_sha256(z, &salt, INFO_SK_READER, SK_LEN),
    }
}

/// Construct the 12-byte AES-GCM IV = `identifier(8) || counter(4, big-endian)`.
fn iv(identifier: [u8; 8], counter: u32) -> [u8; IV_LEN] {
    let mut out = [0u8; IV_LEN];
    out[..8].copy_from_slice(&identifier);
    out[8..].copy_from_slice(&counter.to_be_bytes());
    out
}

/// Stateful AES-256-GCM SessionData cipher for one party, holding both keys and the two
/// per-direction message counters. Each party constructs one; the mdoc uses
/// [`seal_from_device`](Self::seal_from_device) + [`open_from_reader`](Self::open_from_reader), the
/// reader the mirror pair. Counters start at 0 and are pre-incremented, so the first message in each
/// direction uses counter value 1 on both ends.
pub struct SessionCipher {
    sk_device: Vec<u8>,
    sk_reader: Vec<u8>,
    device_counter: u32,
    reader_counter: u32,
}

impl SessionCipher {
    /// Build a cipher from derived keys.
    #[must_use]
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            sk_device: keys.sk_device,
            sk_reader: keys.sk_reader,
            device_counter: 0,
            reader_counter: 0,
        }
    }

    fn next_device(&mut self) -> Result<u32, SessionError> {
        self.device_counter = self
            .device_counter
            .checked_add(1)
            .ok_or(SessionError::CounterExhausted)?;
        Ok(self.device_counter)
    }

    fn next_reader(&mut self) -> Result<u32, SessionError> {
        self.reader_counter = self
            .reader_counter
            .checked_add(1)
            .ok_or(SessionError::CounterExhausted)?;
        Ok(self.reader_counter)
    }

    /// Seal an outgoing mdoc→reader message (SKDevice, mdoc identifier). Output is `ciphertext||tag`.
    pub fn seal_from_device<A: Aead>(
        &mut self,
        aead: &A,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let iv = iv(IDENTIFIER_MDOC, self.next_device()?);
        aead.seal(&self.sk_device, &iv, b"", plaintext)
            .map_err(|_| SessionError::Crypto)
    }

    /// Open an incoming reader→mdoc message (SKReader, reader identifier).
    pub fn open_from_reader<A: Aead>(
        &mut self,
        aead: &A,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let iv = iv(IDENTIFIER_READER, self.next_reader()?);
        aead.open(&self.sk_reader, &iv, b"", ciphertext)
            .map_err(|_| SessionError::Crypto)
    }

    /// Seal an outgoing reader→mdoc message (SKReader, reader identifier). The reader side — also
    /// used by tests / a reader emulator.
    pub fn seal_from_reader<A: Aead>(
        &mut self,
        aead: &A,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let iv = iv(IDENTIFIER_READER, self.next_reader()?);
        aead.seal(&self.sk_reader, &iv, b"", plaintext)
            .map_err(|_| SessionError::Crypto)
    }

    /// Open an incoming mdoc→reader message (SKDevice, mdoc identifier). The reader side.
    pub fn open_from_device<A: Aead>(
        &mut self,
        aead: &A,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let iv = iv(IDENTIFIER_MDOC, self.next_device()?);
        aead.open(&self.sk_device, &iv, b"", ciphertext)
            .map_err(|_| SessionError::Crypto)
    }
}

/// Convert a COSE_Key (EC2 / P-256) to the uncompressed SEC1 point `0x04 || X || Y` that
/// [`crypto_backend::P256AgreementKey::agree`](../../crypto_backend/struct.P256AgreementKey.html)
/// consumes. COSE labels are `kty`=1 (=2 EC2), `crv`=-1 (=1 P-256), `x`=-2, `y`=-3; in
/// `cose::cbor::Value` the negative labels are `Nint(0/1/2)`.
pub fn cose_ec2_to_sec1(cose_key: &[u8]) -> Result<Vec<u8>, SessionError> {
    let (value, _) = decode_value(cose_key, 0).map_err(|_| SessionError::MalformedKey)?;
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(SessionError::MalformedKey),
    };
    let get = |k: &Value| map.iter().find(|(kk, _)| kk == k).map(|(_, vv)| vv.clone());
    // kty (1) must be EC2 (2); crv (-1 => Nint(0)) must be P-256 (1).
    match get(&Value::Uint(1)) {
        Some(Value::Uint(2)) => {}
        _ => return Err(SessionError::UnsupportedKey),
    }
    match get(&Value::Nint(0)) {
        Some(Value::Uint(1)) => {}
        _ => return Err(SessionError::UnsupportedKey),
    }
    let coord = |v: Option<Value>| match v {
        Some(Value::Bytes(b)) if b.len() == 32 => Some(b),
        _ => None,
    };
    let x = coord(get(&Value::Nint(1))).ok_or(SessionError::MalformedKey)?; // -2
    let y = coord(get(&Value::Nint(2))).ok_or(SessionError::MalformedKey)?; // -3
    let mut sec1 = Vec::with_capacity(1 + 32 + 32);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    Ok(sec1)
}

/// Encode an EC2/P-256 public key (uncompressed SEC1 `0x04||X||Y`) as a COSE_Key — the inverse of
/// [`cose_ec2_to_sec1`], used to place `EDeviceKey` into the DeviceEngagement.
pub fn sec1_to_cose_ec2(sec1: &[u8]) -> Result<Vec<u8>, SessionError> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return Err(SessionError::MalformedKey);
    }
    let x = sec1[1..33].to_vec();
    let y = sec1[33..65].to_vec();
    Ok(Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),  // kty: EC2
        (Value::Nint(0), Value::Uint(1)),  // crv: P-256 (label -1)
        (Value::Nint(1), Value::Bytes(x)), // x   (label -2)
        (Value::Nint(2), Value::Bytes(y)), // y   (label -3)
    ])
    .to_canonical())
}

/// The reader's first message (§9.1.1): its ephemeral key + the encrypted mdoc request.
pub struct SessionEstablishment {
    /// The reader ephemeral key as a bare COSE_Key (the inner value of `EReaderKeyBytes`).
    pub e_reader_key_cose: Vec<u8>,
    /// The AES-256-GCM SessionData ciphertext of the reader's request.
    pub data: Vec<u8>,
}

/// Parse a `SessionEstablishment = { "eReaderKey": #6.24(bstr COSE_Key), "data": bstr }`.
pub fn parse_session_establishment(bytes: &[u8]) -> Result<SessionEstablishment, SessionError> {
    let map = decode_map(bytes)?;
    let e_reader_key_cose = match text_entry(&map, "eReaderKey") {
        // EReaderKeyBytes = #6.24(bstr .cbor COSE_Key) — unwrap to the bare COSE_Key.
        Some(Value::Tag(24, inner)) => match *inner.clone() {
            Value::Bytes(b) => b,
            _ => return Err(SessionError::MalformedMessage),
        },
        _ => return Err(SessionError::MalformedMessage),
    };
    let data = match text_entry(&map, "data") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err(SessionError::MalformedMessage),
    };
    Ok(SessionEstablishment {
        e_reader_key_cose,
        data,
    })
}

/// Build a `SessionData = { "data": bstr }` carrying an encrypted message.
#[must_use]
pub fn session_data(encrypted: &[u8]) -> Vec<u8> {
    Value::Map(vec![(
        Value::Text("data".into()),
        Value::Bytes(encrypted.to_vec()),
    )])
    .to_canonical()
}

/// Extract the encrypted `"data"` from a `SessionData` map.
pub fn parse_session_data(bytes: &[u8]) -> Result<Vec<u8>, SessionError> {
    let map = decode_map(bytes)?;
    match text_entry(&map, "data") {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(SessionError::MalformedMessage),
    }
}

fn decode_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>, SessionError> {
    let (value, _) = decode_value(bytes, 0).map_err(|_| SessionError::MalformedMessage)?;
    match value {
        Value::Map(m) => Ok(m),
        _ => Err(SessionError::MalformedMessage),
    }
}

fn text_entry<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

/// Extract the device ephemeral COSE_Key (bare) from a `DeviceEngagement` — the reader needs it to
/// run ECDH. `DeviceEngagement` map key `1` is `Security = [cipherSuite, DeviceKeyBytes]`, where
/// `DeviceKeyBytes = #6.24(bstr .cbor COSE_Key)`.
pub fn device_key_from_engagement(engagement: &[u8]) -> Result<Vec<u8>, SessionError> {
    let map = decode_map(engagement)?;
    let security = map
        .iter()
        .find(|(k, _)| matches!(k, Value::Uint(1)))
        .map(|(_, v)| v);
    let items = match security {
        Some(Value::Array(a)) => a,
        _ => return Err(SessionError::MalformedMessage),
    };
    match items.get(1) {
        Some(Value::Tag(24, inner)) => match inner.as_ref() {
            Value::Bytes(b) => Ok(b.clone()),
            _ => Err(SessionError::MalformedMessage),
        },
        _ => Err(SessionError::MalformedMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_backend::{AwsLc, P256AgreementKey};

    /// A COSE_Key for a freshly generated agreement key (round-trips SEC1 ⇄ COSE_Key).
    fn cose_key_of(key: &P256AgreementKey) -> Vec<u8> {
        sec1_to_cose_ec2(key.public_raw()).expect("valid SEC1")
    }

    #[test]
    fn sec1_cose_key_round_trips() {
        let key = P256AgreementKey::generate().unwrap();
        let cose = cose_key_of(&key);
        let sec1 = cose_ec2_to_sec1(&cose).expect("parse");
        assert_eq!(sec1, key.public_raw(), "SEC1 → COSE_Key → SEC1 is identity");
    }

    #[test]
    fn cose_ec2_rejects_non_ec2_and_short_coords() {
        // kty = OKP (1) instead of EC2 (2) → UnsupportedKey.
        let okp = Value::Map(vec![
            (Value::Uint(1), Value::Uint(1)),
            (Value::Nint(0), Value::Uint(1)),
            (Value::Nint(1), Value::Bytes(vec![0u8; 32])),
            (Value::Nint(2), Value::Bytes(vec![0u8; 32])),
        ])
        .to_canonical();
        assert_eq!(cose_ec2_to_sec1(&okp), Err(SessionError::UnsupportedKey));
        // Short X coordinate → MalformedKey.
        let short = Value::Map(vec![
            (Value::Uint(1), Value::Uint(2)),
            (Value::Nint(0), Value::Uint(1)),
            (Value::Nint(1), Value::Bytes(vec![0u8; 8])),
            (Value::Nint(2), Value::Bytes(vec![0u8; 32])),
        ])
        .to_canonical();
        assert_eq!(cose_ec2_to_sec1(&short), Err(SessionError::MalformedKey));
    }

    #[test]
    fn ecdh_both_sides_derive_identical_keys() {
        let device = P256AgreementKey::generate().unwrap();
        let reader = P256AgreementKey::generate().unwrap();

        // Both sides agree on the same raw Z.
        let z_device = device.agree(reader.public_raw()).unwrap();
        let z_reader = reader.agree(device.public_raw()).unwrap();
        assert_eq!(z_device, z_reader, "ECDH is symmetric");

        // A representative proximity transcript over both engagement + reader key.
        let de = b"device-engagement-bytes".to_vec();
        let transcript = iso18013_5::session_transcript(&de, &cose_key_of(&reader));

        let kd = derive_session_keys(&AwsLc, &z_device, &transcript);
        let kr = derive_session_keys(&AwsLc, &z_reader, &transcript);
        assert_eq!(kd.sk_device, kr.sk_device);
        assert_eq!(kd.sk_reader, kr.sk_reader);
        assert_ne!(
            kd.sk_device, kd.sk_reader,
            "the two keys differ (distinct info)"
        );
        assert_eq!(kd.sk_device.len(), 32);
    }

    #[test]
    fn session_round_trips_in_both_directions() {
        let device = P256AgreementKey::generate().unwrap();
        let reader = P256AgreementKey::generate().unwrap();
        let z = device.agree(reader.public_raw()).unwrap();
        let de = b"engagement".to_vec();
        let transcript = iso18013_5::session_transcript(&de, &cose_key_of(&reader));
        let keys = derive_session_keys(&AwsLc, &z, &transcript);

        let mut mdoc = SessionCipher::new(keys.clone()); // the wallet
        let mut rdr = SessionCipher::new(keys); // the reader

        // mdoc → reader (DeviceResponse)
        let response = b"the-device-response-cbor".to_vec();
        let ct = mdoc.seal_from_device(&AwsLc, &response).unwrap();
        assert_ne!(ct, response);
        assert_eq!(rdr.open_from_device(&AwsLc, &ct).unwrap(), response);

        // reader → mdoc (a follow-up request)
        let request = b"a-followup-request".to_vec();
        let ct2 = rdr.seal_from_reader(&AwsLc, &request).unwrap();
        assert_eq!(mdoc.open_from_reader(&AwsLc, &ct2).unwrap(), request);

        // Counters advance: a second mdoc→reader message uses a fresh IV, so the ciphertext of the
        // SAME plaintext differs.
        let ct_again = mdoc.seal_from_device(&AwsLc, &response).unwrap();
        assert_ne!(ct, ct_again, "per-message counter makes each IV unique");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let device = P256AgreementKey::generate().unwrap();
        let reader = P256AgreementKey::generate().unwrap();
        let z = device.agree(reader.public_raw()).unwrap();
        let transcript = iso18013_5::session_transcript(b"e", &cose_key_of(&reader));
        let keys = derive_session_keys(&AwsLc, &z, &transcript);
        let mut mdoc = SessionCipher::new(keys.clone());
        let mut rdr = SessionCipher::new(keys);

        let mut ct = mdoc.seal_from_device(&AwsLc, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // flip a tag bit
        assert_eq!(
            rdr.open_from_device(&AwsLc, &ct),
            Err(SessionError::Crypto),
            "GCM tag mismatch is rejected"
        );
    }

    #[test]
    fn wrong_direction_key_fails() {
        let device = P256AgreementKey::generate().unwrap();
        let reader = P256AgreementKey::generate().unwrap();
        let z = device.agree(reader.public_raw()).unwrap();
        let transcript = iso18013_5::session_transcript(b"e", &cose_key_of(&reader));
        let keys = derive_session_keys(&AwsLc, &z, &transcript);
        let mut mdoc = SessionCipher::new(keys.clone());
        let mut rdr = SessionCipher::new(keys);

        // A device-sealed message opened as if it were a reader message (wrong key + identifier).
        let ct = mdoc.seal_from_device(&AwsLc, b"hello").unwrap();
        assert_eq!(rdr.open_from_reader(&AwsLc, &ct), Err(SessionError::Crypto));
    }

    #[test]
    fn session_establishment_round_trips() {
        let reader = P256AgreementKey::generate().unwrap();
        let ereader = cose_key_of(&reader);
        let ereader_bytes = Value::Tag(24, Box::new(Value::Bytes(ereader.clone()))).to_canonical();
        let msg = Value::Map(vec![
            (Value::Text("eReaderKey".into()), {
                let (v, _) = decode_value(&ereader_bytes, 0).unwrap();
                v
            }),
            (
                Value::Text("data".into()),
                Value::Bytes(b"ciphertext".to_vec()),
            ),
        ])
        .to_canonical();

        let parsed = parse_session_establishment(&msg).expect("parse");
        assert_eq!(parsed.e_reader_key_cose, ereader);
        assert_eq!(parsed.data, b"ciphertext");
        // And the extracted COSE_Key is usable for ECDH.
        let sec1 = cose_ec2_to_sec1(&parsed.e_reader_key_cose).unwrap();
        assert_eq!(sec1, reader.public_raw());
    }

    #[test]
    fn session_data_round_trips() {
        let sd = session_data(b"encrypted-response");
        assert_eq!(parse_session_data(&sd).unwrap(), b"encrypted-response");
    }
}
