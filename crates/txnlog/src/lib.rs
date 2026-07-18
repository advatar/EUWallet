#![forbid(unsafe_code)]
//! `txnlog` — the wallet's transaction (audit) log (P1 / TS06).
//!
//! Two properties define this module, both by construction:
//!
//!  * **Privacy-preserving.** An [`Entry`] records the *identity* of a counterparty, the claim
//!    *paths* that were shared, a `consent_hash` that cryptographically commits to exactly what was
//!    disclosed (it is computed by the core over the value *digests* — see `presenter`), a
//!    timestamp and an outcome. It has NO field for raw claim values, credential bytes, or secrets:
//!    it is impossible to store PII here (plan §7.9). For payments the payer-visible essence
//!    (amount, currency, payee) is retained so the user can review — this is transaction data, not
//!    credential PII, and it is already what dynamic linking bound.
//!
//!  * **Tamper-evident.** Entries form a hash chain: each entry commits to the previous entry's
//!    hash, so the [`TransactionLog::head`] hash fixes the entire history. Any reordering,
//!    insertion, deletion, or field edit breaks [`TransactionLog::verify_integrity`].
//!
//! Sans-IO: the log is an in-memory value the shell persists. No clock, disk, or network here.

use crypto_traits::Digest;

/// What kind of interaction produced this entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An OpenID4VP identity presentation.
    Presentation,
    /// An OID4VCI credential issuance.
    Issuance,
    /// A payment authorisation (PSD2/TS12 SCA).
    Payment,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Presentation => 1,
            Kind::Issuance => 2,
            Kind::Payment => 3,
        }
    }
    /// Stable string form (matches the JSON the FFI/UI reads).
    pub fn name(self) -> &'static str {
        match self {
            Kind::Presentation => "presentation",
            Kind::Issuance => "issuance",
            Kind::Payment => "payment",
        }
    }
}

/// How the interaction ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    Declined,
    Aborted,
}

impl Outcome {
    fn tag(self) -> u8 {
        match self {
            Outcome::Completed => 1,
            Outcome::Declined => 2,
            Outcome::Aborted => 3,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Completed => "completed",
            Outcome::Declined => "declined",
            Outcome::Aborted => "aborted",
        }
    }
}

/// The payer-visible essence of a payment (retained so the user can review their payment history).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentSummary {
    pub payee: String,
    pub amount_minor: u64,
    pub currency: String,
}

/// Everything the shell must supply to record one interaction. Deliberately has NO field for raw
/// claim values or credential bytes — only paths and the committing `consent_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewEntry {
    pub epoch: i64,
    pub kind: Kind,
    /// RP `client_id` / issuer id / creditor identity.
    pub counterparty: String,
    /// The core's consent hash: commits to exactly what was shared, over value digests.
    pub consent_hash: [u8; 32],
    /// Claim IDENTITIES (paths) that were shared — never the values.
    pub claim_paths: Vec<String>,
    pub outcome: Outcome,
    /// Present only for `Kind::Payment`.
    pub payment: Option<PaymentSummary>,
}

/// A committed log entry: a `NewEntry` plus its position, chain linkage, and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub epoch: i64,
    pub kind: Kind,
    pub counterparty: String,
    pub consent_hash: [u8; 32],
    pub claim_paths: Vec<String>,
    pub outcome: Outcome,
    pub payment: Option<PaymentSummary>,
    /// Hash of the previous entry ( `[0u8; 32]` for the first entry).
    pub prev_hash: [u8; 32],
    /// `H(canonical(this entry, including prev_hash))`.
    pub entry_hash: [u8; 32],
}

/// The append-only, hash-chained transaction log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionLog {
    entries: Vec<Entry>,
}

impl TransactionLog {
    pub fn new() -> Self {
        TransactionLog { entries: Vec::new() }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The chain head: the hash of the last entry, or `[0u8; 32]` when empty. This value fixes the
    /// entire history — persist it (e.g. in the Secure Enclave / a signed anchor) to detect
    /// off-device tampering with the stored log.
    pub fn head(&self) -> [u8; 32] {
        self.entries.last().map(|e| e.entry_hash).unwrap_or([0u8; 32])
    }

    /// Append an interaction, extending the hash chain. Returns the committed entry.
    pub fn append(&mut self, digest: &dyn Digest, e: NewEntry) -> &Entry {
        let seq = self.entries.len() as u64;
        let prev_hash = self.head();
        let entry_hash = hash_entry(digest, seq, prev_hash, &e);
        self.entries.push(Entry {
            seq,
            epoch: e.epoch,
            kind: e.kind,
            counterparty: e.counterparty,
            consent_hash: e.consent_hash,
            claim_paths: e.claim_paths,
            outcome: e.outcome,
            payment: e.payment,
            prev_hash,
            entry_hash,
        });
        self.entries.last().expect("just pushed")
    }

    /// Recompute the whole chain and check it is intact: gapless monotonic `seq`, correct `prev`
    /// linkage, and each `entry_hash` matching its recomputed value. Any tampering fails this.
    pub fn verify_integrity(&self, digest: &dyn Digest) -> bool {
        let mut prev = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev {
                return false;
            }
            let ne = NewEntry {
                epoch: e.epoch,
                kind: e.kind,
                counterparty: e.counterparty.clone(),
                consent_hash: e.consent_hash,
                claim_paths: e.claim_paths.clone(),
                outcome: e.outcome,
                payment: e.payment.clone(),
            };
            if hash_entry(digest, e.seq, e.prev_hash, &ne) != e.entry_hash {
                return false;
            }
            prev = e.entry_hash;
        }
        true
    }
}

/// Deterministic, length-prefixed serialisation of an entry, then SHA-256. Length prefixes make
/// the encoding injective (no field-boundary ambiguity), so distinct entries never collide on the
/// pre-image. Domain-separated by a version tag.
fn hash_entry(digest: &dyn Digest, seq: u64, prev_hash: [u8; 32], e: &NewEntry) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"eudi-txnlog-v1");
    buf.extend_from_slice(&prev_hash);
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&e.epoch.to_le_bytes());
    buf.push(e.kind.tag());
    buf.push(e.outcome.tag());
    put_bytes(&mut buf, e.counterparty.as_bytes());
    buf.extend_from_slice(&e.consent_hash);
    buf.extend_from_slice(&(e.claim_paths.len() as u64).to_le_bytes());
    for p in &e.claim_paths {
        put_bytes(&mut buf, p.as_bytes());
    }
    match &e.payment {
        None => buf.push(0),
        Some(p) => {
            buf.push(1);
            put_bytes(&mut buf, p.payee.as_bytes());
            buf.extend_from_slice(&p.amount_minor.to_le_bytes());
            put_bytes(&mut buf, p.currency.as_bytes());
        }
    }
    digest.sha256(&buf)
}

/// Append a `u64` length prefix (LE) followed by the bytes.
fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_backend::AwsLc;

    fn presentation(epoch: i64, rp: &str, claims: &[&str]) -> NewEntry {
        NewEntry {
            epoch,
            kind: Kind::Presentation,
            counterparty: rp.into(),
            consent_hash: AwsLc.sha256(rp.as_bytes()),
            claim_paths: claims.iter().map(|c| c.to_string()).collect(),
            outcome: Outcome::Completed,
            payment: None,
        }
    }

    #[test]
    fn append_chains_and_verifies() {
        let mut log = TransactionLog::new();
        assert!(log.is_empty());
        assert_eq!(log.head(), [0u8; 32]);

        log.append(&AwsLc, presentation(1000, "rp.example", &["age_over_18"]));
        log.append(&AwsLc, presentation(1001, "shop.example", &["family_name"]));

        assert_eq!(log.len(), 2);
        assert_eq!(log.entries()[0].seq, 0);
        assert_eq!(log.entries()[1].seq, 1);
        // Chain linkage: the second entry commits to the first.
        assert_eq!(log.entries()[1].prev_hash, log.entries()[0].entry_hash);
        assert_eq!(log.head(), log.entries()[1].entry_hash);
        assert!(log.verify_integrity(&AwsLc));
    }

    #[test]
    fn tampering_with_a_field_breaks_the_chain() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "rp.example", &["age_over_18"]));
        log.append(&AwsLc, presentation(1001, "shop.example", &["family_name"]));
        assert!(log.verify_integrity(&AwsLc));

        // Edit a recorded counterparty after the fact — integrity must fail.
        log.entries[0].counterparty = "evil.example".into();
        assert!(!log.verify_integrity(&AwsLc));
    }

    #[test]
    fn reordering_entries_breaks_the_chain() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "a.example", &["x"]));
        log.append(&AwsLc, presentation(1001, "b.example", &["y"]));
        log.entries.swap(0, 1);
        assert!(!log.verify_integrity(&AwsLc), "reordering must be detected");
    }

    #[test]
    fn deleting_an_entry_breaks_the_chain() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "a.example", &["x"]));
        log.append(&AwsLc, presentation(1001, "b.example", &["y"]));
        log.append(&AwsLc, presentation(1002, "c.example", &["z"]));
        // Remove the middle entry: seq gap + broken linkage.
        log.entries.remove(1);
        assert!(!log.verify_integrity(&AwsLc));
    }

    #[test]
    fn payment_summary_is_retained_and_committed() {
        let mut log = TransactionLog::new();
        log.append(
            &AwsLc,
            NewEntry {
                epoch: 2000,
                kind: Kind::Payment,
                counterparty: "Acme Store".into(),
                consent_hash: [7u8; 32],
                claim_paths: vec![],
                outcome: Outcome::Completed,
                payment: Some(PaymentSummary {
                    payee: "Acme Store".into(),
                    amount_minor: 1299,
                    currency: "EUR".into(),
                }),
            },
        );
        let e = &log.entries()[0];
        assert_eq!(e.payment.as_ref().unwrap().amount_minor, 1299);
        assert!(log.verify_integrity(&AwsLc));
        // Editing the amount after the fact breaks the chain (dynamic-linking audit trail).
        log.entries[0].payment.as_mut().unwrap().amount_minor = 9999;
        assert!(!log.verify_integrity(&AwsLc));
    }
}
