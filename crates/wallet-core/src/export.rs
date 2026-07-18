//! `export` — portable, integrity-protected export of the holder's wallet data (P1 / TS10).
//!
//! Data portability (GDPR Art. 20) means the holder can take THEIR data — their held credential(s)
//! and their activity log — off the device in a machine-readable form. This module assembles that
//! bundle and protects it with a SHA-256 integrity hash over a canonical (length-prefixed, so
//! injective) byte encoding, so any tampering with a saved export is detectable on re-import.
//!
//! This is the holder's OWN data, exported by their explicit action; it is not a disclosure to a
//! relying party. The shell is responsible for at-rest protection (e.g. passphrase encryption)
//! before the bundle leaves the device.

use std::collections::BTreeMap;

use crypto_traits::Digest;
use serde::{Deserialize, Serialize};

use crate::{hex32, HeldCredential};

const EXPORT_VERSION: u64 = 1;

/// A held credential, in export form (the holder's own credential material).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportCredential {
    pub issuer_jwt: String,
    /// Claim name → base64url disclosure (BTreeMap ⇒ deterministic order).
    pub disclosures: BTreeMap<String, String>,
    pub status_index: Option<u64>,
}

/// A payment summary in export form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportPayment {
    pub payee: String,
    pub amount_minor: u64,
    pub currency: String,
}

/// One audit-log entry in export form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportEntry {
    pub seq: u64,
    pub epoch: i64,
    pub kind: String,
    pub counterparty: String,
    /// Hex of the consent hash (never claim values).
    pub consent_hash: String,
    pub claim_paths: Vec<String>,
    pub outcome: String,
    pub payment: Option<ExportPayment>,
    pub redacted: bool,
}

/// The portable payload (everything the integrity hash covers).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportData {
    pub version: u64,
    pub epoch: i64,
    pub credential: Option<ExportCredential>,
    pub transaction_log: Vec<ExportEntry>,
}

/// The signed-ish bundle: the payload plus its integrity hash (hex).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Export {
    #[serde(flatten)]
    pub data: ExportData,
    pub integrity_hash: String,
}

/// Assemble the export payload from the holder's credential and audit log.
pub fn build_data(
    epoch: i64,
    credential: Option<&HeldCredential>,
    log: &txnlog::TransactionLog,
) -> ExportData {
    let credential = credential.map(|c| ExportCredential {
        issuer_jwt: c.issuer_jwt.clone(),
        disclosures: c.disclosures_by_claim.clone(),
        status_index: c.status_index,
    });
    let transaction_log = log
        .entries()
        .iter()
        .map(|e| ExportEntry {
            seq: e.seq,
            epoch: e.epoch,
            kind: e.kind.name().to_string(),
            counterparty: e.counterparty.clone(),
            consent_hash: hex32(&e.consent_hash),
            claim_paths: e.claim_paths.clone(),
            outcome: e.outcome.name().to_string(),
            payment: e.payment.as_ref().map(|p| ExportPayment {
                payee: p.payee.clone(),
                amount_minor: p.amount_minor,
                currency: p.currency.clone(),
            }),
            redacted: e.redacted,
        })
        .collect();
    ExportData {
        version: EXPORT_VERSION,
        epoch,
        credential,
        transaction_log,
    }
}

/// Canonical, length-prefixed encoding of the payload — injective, so the integrity hash is a
/// faithful commitment. Domain-separated and versioned.
fn canonical(d: &ExportData) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"eudi-wallet-export-v1");
    b.extend_from_slice(&d.version.to_le_bytes());
    b.extend_from_slice(&d.epoch.to_le_bytes());
    match &d.credential {
        None => b.push(0),
        Some(c) => {
            b.push(1);
            put(&mut b, c.issuer_jwt.as_bytes());
            b.extend_from_slice(&(c.disclosures.len() as u64).to_le_bytes());
            for (k, v) in &c.disclosures {
                put(&mut b, k.as_bytes());
                put(&mut b, v.as_bytes());
            }
            match c.status_index {
                None => b.push(0),
                Some(i) => {
                    b.push(1);
                    b.extend_from_slice(&i.to_le_bytes());
                }
            }
        }
    }
    b.extend_from_slice(&(d.transaction_log.len() as u64).to_le_bytes());
    for e in &d.transaction_log {
        b.extend_from_slice(&e.seq.to_le_bytes());
        b.extend_from_slice(&e.epoch.to_le_bytes());
        put(&mut b, e.kind.as_bytes());
        put(&mut b, e.counterparty.as_bytes());
        put(&mut b, e.consent_hash.as_bytes());
        put(&mut b, e.outcome.as_bytes());
        b.push(e.redacted as u8);
        b.extend_from_slice(&(e.claim_paths.len() as u64).to_le_bytes());
        for p in &e.claim_paths {
            put(&mut b, p.as_bytes());
        }
        match &e.payment {
            None => b.push(0),
            Some(p) => {
                b.push(1);
                put(&mut b, p.payee.as_bytes());
                b.extend_from_slice(&p.amount_minor.to_le_bytes());
                put(&mut b, p.currency.as_bytes());
            }
        }
    }
    b
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Build the full integrity-protected bundle as JSON.
pub fn export_json(
    digest: &dyn Digest,
    epoch: i64,
    credential: Option<&HeldCredential>,
    log: &txnlog::TransactionLog,
) -> String {
    let data = build_data(epoch, credential, log);
    let integrity_hash = hex32(&digest.sha256(&canonical(&data)));
    serde_json::to_string(&Export {
        data,
        integrity_hash,
    })
    .expect("serialize export")
}

/// Verify a previously-produced export: recompute the integrity hash over its payload and compare.
/// Returns false on malformed JSON or a hash mismatch (tampering).
pub fn verify_export(digest: &dyn Digest, json: &str) -> bool {
    let export: Export = match serde_json::from_str(json) {
        Ok(e) => e,
        Err(_) => return false,
    };
    hex32(&digest.sha256(&canonical(&export.data))) == export.integrity_hash
}
