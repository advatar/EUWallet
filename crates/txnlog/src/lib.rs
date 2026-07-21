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
//!    hash, so an externally authenticated [`TransactionLog::head`] fixes the entire history.
//!    Any reordering, insertion, deletion, or live-entry field edit breaks validation; redacted
//!    tombstones require [`TransactionLog::restore_checked`] because their original body is gone.
//!
//! Sans-IO: the log is an in-memory value the shell persists. No clock, disk, or network here.

use crypto_traits::Digest;

/// Maximum number of retained audit records. Exhaustion is an explicit error: old history is
/// never silently evicted to make room for a new interaction.
pub const MAX_ENTRIES: usize = 4_096;
/// Maximum UTF-8 byte length of an RP, issuer, peer, or payee identity.
pub const MAX_COUNTERPARTY_BYTES: usize = 4_096;
/// Maximum number of disclosed claim identities recorded for one interaction.
pub const MAX_CLAIM_PATHS_PER_ENTRY: usize = 128;
/// Maximum UTF-8 byte length of one disclosed claim identity.
pub const MAX_CLAIM_PATH_BYTES: usize = 1_024;
/// Maximum UTF-8 byte length of the payer-visible payee name.
pub const MAX_PAYMENT_PAYEE_BYTES: usize = 4_096;
/// Maximum canonical-accounting size of one retained entry.
pub const MAX_ENTRY_BYTES: usize = 64 * 1_024;
/// Maximum canonical-accounting size of the complete retained log.
pub const MAX_AGGREGATE_BYTES: usize = 4 * 1_024 * 1_024;

const HASH_DOMAIN: &[u8] = b"eudi-txnlog-v1";
const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Text fields whose bounds or canonical form can make an append/import fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextField {
    Counterparty,
    ClaimPath,
    PaymentPayee,
    PaymentCurrency,
}

/// Typed, fail-closed validation failures for append and durable-state restoration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    EntryLimitExceeded {
        max: usize,
    },
    FieldEmpty {
        field: TextField,
    },
    FieldTooLong {
        field: TextField,
        max: usize,
        actual: usize,
    },
    NonCanonicalText {
        field: TextField,
    },
    TooManyClaimPaths {
        max: usize,
        actual: usize,
    },
    DuplicateClaimPath,
    ClaimPathsNotCanonical,
    InvalidEpoch {
        seq: u64,
    },
    PaymentKindMismatch {
        seq: u64,
    },
    PaymentCounterpartyMismatch {
        seq: u64,
    },
    InvalidPaymentAmount {
        seq: u64,
    },
    InvalidPaymentCurrency {
        seq: u64,
    },
    EntryByteLimitExceeded {
        max: usize,
        actual: usize,
    },
    AggregateByteLimitExceeded {
        max: usize,
        actual: usize,
    },
    SizeOverflow,
    SequenceMismatch {
        expected: u64,
        actual: u64,
    },
    PreviousHashMismatch {
        seq: u64,
    },
    ZeroEntryHash {
        seq: u64,
    },
    EntryHashMismatch {
        seq: u64,
    },
    RedactedEntryNotCanonical {
        seq: u64,
    },
    AnchoredHeadMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "transaction log validation failed: {self:?}")
    }
}

impl std::error::Error for Error {}

/// What kind of interaction produced this entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An OpenID4VP identity presentation.
    Presentation,
    /// An OID4VCI credential issuance.
    Issuance,
    /// A payment authorisation (PSD2/TS12 SCA).
    Payment,
    /// A wallet-to-wallet credential received from a peer (TS09).
    Transfer,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Presentation => 1,
            Kind::Issuance => 2,
            Kind::Payment => 3,
            Kind::Transfer => 4,
        }
    }
    /// Stable string form (matches the JSON the FFI/UI reads).
    pub fn name(self) -> &'static str {
        match self {
            Kind::Presentation => "presentation",
            Kind::Issuance => "issuance",
            Kind::Payment => "payment",
            Kind::Transfer => "transfer",
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
    /// `H(canonical(this entry, including prev_hash))`. For a redacted entry this is the ORIGINAL
    /// hash, retained so the chain still links even though the content is gone.
    pub entry_hash: [u8; 32],
    /// True once the content has been erased (TS07). A redacted entry is a tombstone: only its
    /// position and chain hashes remain. Every other field has one canonical blank value so an
    /// importer can reject unauthenticated metadata changes that cannot be re-hashed after erasure.
    pub redacted: bool,
}

/// The append-only, hash-chained transaction log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionLog {
    entries: Vec<Entry>,
    /// Canonical-accounting bytes for `entries`. Rebuilt from checked input during restoration and
    /// updated with checked arithmetic on append/redaction, so append remains O(1).
    accounted_bytes: usize,
}

impl TransactionLog {
    pub fn new() -> Self {
        TransactionLog {
            entries: Vec::new(),
            accounted_bytes: 0,
        }
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

    /// Whether no entry of any size can be appended because a hard global limit is already
    /// reached. A larger candidate can still fail before this returns true; [`Self::append`]
    /// remains the authoritative check.
    pub fn is_exhausted(&self) -> bool {
        self.entries.len() >= MAX_ENTRIES || self.accounted_bytes >= MAX_AGGREGATE_BYTES
    }

    /// Whether the log can guarantee admission of any individually valid entry. A single-flow
    /// caller can use this before consent/signing/delivery, then validate the exact eventual entry
    /// with [`Self::check_append`].
    pub fn can_guarantee_max_entry(&self) -> bool {
        self.entries.len() < MAX_ENTRIES
            && self
                .accounted_bytes
                .checked_add(MAX_ENTRY_BYTES)
                .is_some_and(|bytes| bytes <= MAX_AGGREGATE_BYTES)
    }

    /// Validate an append candidate and current capacity without mutating the log or hashing. Claim
    /// path order is not significant for a new candidate (append sorts it), but duplicates and all
    /// other non-canonical/bounded values are rejected.
    pub fn check_append(&self, entry: &NewEntry) -> Result<(), Error> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(Error::EntryLimitExceeded { max: MAX_ENTRIES });
        }
        let seq = u64::try_from(self.entries.len()).map_err(|_| Error::SizeOverflow)?;
        let entry_bytes = validate_new_entry(entry, seq, false)?;
        let aggregate_bytes = self
            .accounted_bytes
            .checked_add(entry_bytes)
            .ok_or(Error::SizeOverflow)?;
        if aggregate_bytes > MAX_AGGREGATE_BYTES {
            return Err(Error::AggregateByteLimitExceeded {
                max: MAX_AGGREGATE_BYTES,
                actual: aggregate_bytes,
            });
        }
        Ok(())
    }

    /// The chain head: the hash of the last entry, or `[0u8; 32]` when empty. This value fixes the
    /// entire history — persist it (e.g. in the Secure Enclave / a signed anchor) to detect
    /// off-device tampering with the stored log.
    pub fn head(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or(ZERO_HASH)
    }

    /// Append an interaction, extending the hash chain. Claim paths are sorted into their unique
    /// canonical order before hashing. Bounds and semantic invariants are checked before mutation;
    /// exhaustion never evicts prior entries.
    pub fn append(&mut self, digest: &dyn Digest, mut e: NewEntry) -> Result<&Entry, Error> {
        self.check_append(&e)?;
        e.claim_paths.sort();
        let seq = u64::try_from(self.entries.len()).map_err(|_| Error::SizeOverflow)?;
        let entry_bytes = validate_new_entry(&e, seq, true)?;
        let aggregate_bytes = self
            .accounted_bytes
            .checked_add(entry_bytes)
            .ok_or(Error::SizeOverflow)?;
        if aggregate_bytes > MAX_AGGREGATE_BYTES {
            return Err(Error::AggregateByteLimitExceeded {
                max: MAX_AGGREGATE_BYTES,
                actual: aggregate_bytes,
            });
        }
        let prev_hash = self.head();
        let entry_hash = hash_entry(digest, seq, prev_hash, &e);
        if entry_hash == ZERO_HASH {
            return Err(Error::ZeroEntryHash { seq });
        }
        let index = self.entries.len();
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
            redacted: false,
        });
        self.accounted_bytes = aggregate_bytes;
        Ok(&self.entries[index])
    }

    /// Erase the content of the entry at `seq` — the data-subject right to erasure (TS07). Leaves a
    /// TOMBSTONE: the position, `prev_hash`, and `entry_hash` remain (so the chain still links and
    /// the fact that an entry existed-and-was-deleted stays evident), while every content field is
    /// replaced by its canonical blank value. One-way; returns whether `seq` existed.
    pub fn redact(&mut self, seq: u64) -> bool {
        let Some(index) = usize::try_from(seq).ok() else {
            return false;
        };
        let Some(entry) = self.entries.get(index) else {
            return false;
        };
        if entry.redacted {
            return true;
        }
        let Ok(old_bytes) = accounted_entry_bytes(entry) else {
            return false;
        };
        let Ok(tombstone_bytes) = accounted_tombstone_bytes() else {
            return false;
        };
        let Some(next_accounted_bytes) = self
            .accounted_bytes
            .checked_sub(old_bytes)
            .and_then(|bytes| bytes.checked_add(tombstone_bytes))
        else {
            return false;
        };
        match self.entries.get_mut(index) {
            Some(e) => {
                e.epoch = 0;
                e.kind = Kind::Presentation;
                e.redacted = true;
                e.counterparty = String::new();
                e.claim_paths = Vec::new();
                e.consent_hash = ZERO_HASH;
                e.outcome = Outcome::Aborted;
                e.payment = None;
                self.accounted_bytes = next_accounted_bytes;
                true
            }
            None => false,
        }
    }

    /// Erase the ENTIRE log (full right-to-erasure / device reset). After this the chain restarts
    /// from empty; there is nothing left to link to.
    pub fn wipe(&mut self) {
        self.entries.clear();
        self.accounted_bytes = 0;
    }

    /// A privacy-preserving activity summary for data-subject access / oversight reporting (TS08):
    /// counts by kind, how many entries were redacted, and the distinct (non-redacted)
    /// counterparties. Contains no claim values.
    pub fn report(&self) -> Report {
        let (mut presentations, mut issuances, mut payments, mut transfers, mut redacted) =
            (0, 0, 0, 0, 0);
        let mut counterparties: Vec<String> = Vec::new();
        for e in &self.entries {
            if e.redacted {
                redacted += 1;
                continue;
            }
            match e.kind {
                Kind::Presentation => presentations += 1,
                Kind::Issuance => issuances += 1,
                Kind::Payment => payments += 1,
                Kind::Transfer => transfers += 1,
            }
            if !counterparties.contains(&e.counterparty) {
                counterparties.push(e.counterparty.clone());
            }
        }
        counterparties.sort();
        Report {
            total: self.entries.len(),
            presentations,
            issuances,
            payments,
            transfers,
            redacted,
            counterparties,
        }
    }

    /// Recompute the whole chain and check its internal structure, bounds and canonical form.
    ///
    /// This method cannot authenticate the hash of a final redacted tombstone because its original
    /// content is gone. Durable restoration must use [`Self::restore_checked`] with a head loaded
    /// from an external authenticated anchor.
    pub fn verify_integrity(&self, digest: &dyn Digest) -> bool {
        validate_entries(digest, &self.entries, self.head())
            .is_ok_and(|bytes| bytes == self.accounted_bytes)
    }

    /// Atomically construct a log from externally decoded entries. The caller must provide the
    /// exact head obtained from a separately authenticated/rollback-protected anchor. No entry is
    /// exposed unless the entire bounded chain validates.
    pub fn restore_checked(
        digest: &dyn Digest,
        entries: Vec<Entry>,
        expected_anchored_head: [u8; 32],
    ) -> Result<Self, Error> {
        let accounted_bytes = validate_entries(digest, &entries, expected_anchored_head)?;
        Ok(Self {
            entries,
            accounted_bytes,
        })
    }

    /// Atomically replace this log after performing the same complete checked restoration. On
    /// failure `self` is unchanged, which lets a durable-state coordinator stage a checkpoint
    /// before committing any restored wallet state.
    pub fn replace_checked(
        &mut self,
        digest: &dyn Digest,
        entries: Vec<Entry>,
        expected_anchored_head: [u8; 32],
    ) -> Result<(), Error> {
        let restored = Self::restore_checked(digest, entries, expected_anchored_head)?;
        *self = restored;
        Ok(())
    }
}

/// A privacy-preserving activity summary (TS08). Counts and distinct counterparties only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub total: usize,
    pub presentations: usize,
    pub issuances: usize,
    pub payments: usize,
    pub transfers: usize,
    pub redacted: usize,
    pub counterparties: Vec<String>,
}

// Canonical accounting covers every encoded field plus its fixed-width tag/length. It is not a
// persistence format; it is an architecture-independent resource budget for any later decoder.
const ACCOUNTED_ENTRY_FIXED_BYTES: usize = 8 + 8 + 1 + 1 + 32 + 32 + 32 + 1 + 8 + 8 + 1;

fn validate_text(
    value: &str,
    field: TextField,
    max: usize,
    allow_empty: bool,
) -> Result<(), Error> {
    if value.is_empty() && !allow_empty {
        return Err(Error::FieldEmpty { field });
    }
    if value.len() > max {
        return Err(Error::FieldTooLong {
            field,
            max,
            actual: value.len(),
        });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(Error::NonCanonicalText { field });
    }
    Ok(())
}

fn validate_claim_paths(paths: &[String], require_canonical_order: bool) -> Result<(), Error> {
    if paths.len() > MAX_CLAIM_PATHS_PER_ENTRY {
        return Err(Error::TooManyClaimPaths {
            max: MAX_CLAIM_PATHS_PER_ENTRY,
            actual: paths.len(),
        });
    }
    for path in paths {
        validate_text(path, TextField::ClaimPath, MAX_CLAIM_PATH_BYTES, false)?;
    }
    for (index, path) in paths.iter().enumerate() {
        if paths[index + 1..].contains(path) {
            return Err(Error::DuplicateClaimPath);
        }
    }
    if !require_canonical_order {
        return Ok(());
    }
    for pair in paths.windows(2) {
        match pair[0].cmp(&pair[1]) {
            core::cmp::Ordering::Less => {}
            core::cmp::Ordering::Equal => return Err(Error::DuplicateClaimPath),
            core::cmp::Ordering::Greater => return Err(Error::ClaimPathsNotCanonical),
        }
    }
    Ok(())
}

fn accounted_fields_bytes(
    counterparty: &str,
    claim_paths: &[String],
    payment: Option<&PaymentSummary>,
) -> Result<usize, Error> {
    let mut bytes = ACCOUNTED_ENTRY_FIXED_BYTES
        .checked_add(counterparty.len())
        .ok_or(Error::SizeOverflow)?;
    for path in claim_paths {
        bytes = bytes
            .checked_add(8)
            .and_then(|total| total.checked_add(path.len()))
            .ok_or(Error::SizeOverflow)?;
    }
    if let Some(payment) = payment {
        bytes = bytes
            .checked_add(8)
            .and_then(|total| total.checked_add(payment.payee.len()))
            .and_then(|total| total.checked_add(8))
            .and_then(|total| total.checked_add(8))
            .and_then(|total| total.checked_add(payment.currency.len()))
            .ok_or(Error::SizeOverflow)?;
    }
    if bytes > MAX_ENTRY_BYTES {
        return Err(Error::EntryByteLimitExceeded {
            max: MAX_ENTRY_BYTES,
            actual: bytes,
        });
    }
    Ok(bytes)
}

fn accounted_new_entry_bytes(entry: &NewEntry) -> Result<usize, Error> {
    accounted_fields_bytes(
        &entry.counterparty,
        &entry.claim_paths,
        entry.payment.as_ref(),
    )
}

fn accounted_entry_bytes(entry: &Entry) -> Result<usize, Error> {
    accounted_fields_bytes(
        &entry.counterparty,
        &entry.claim_paths,
        entry.payment.as_ref(),
    )
}

fn accounted_tombstone_bytes() -> Result<usize, Error> {
    accounted_new_entry_bytes(&NewEntry {
        epoch: 0,
        kind: Kind::Presentation,
        counterparty: String::new(),
        consent_hash: ZERO_HASH,
        claim_paths: Vec::new(),
        outcome: Outcome::Aborted,
        payment: None,
    })
}

fn validate_entry_fields(
    epoch: i64,
    kind: Kind,
    counterparty: &str,
    claim_paths: &[String],
    payment: Option<&PaymentSummary>,
    seq: u64,
    paths_are_canonical: bool,
) -> Result<usize, Error> {
    if epoch < 0 {
        return Err(Error::InvalidEpoch { seq });
    }
    validate_text(
        counterparty,
        TextField::Counterparty,
        MAX_COUNTERPARTY_BYTES,
        false,
    )?;
    validate_claim_paths(claim_paths, paths_are_canonical)?;

    match (kind, payment) {
        (Kind::Payment, Some(payment)) => {
            if !claim_paths.is_empty() {
                return Err(Error::PaymentKindMismatch { seq });
            }
            validate_text(
                &payment.payee,
                TextField::PaymentPayee,
                MAX_PAYMENT_PAYEE_BYTES,
                false,
            )?;
            if payment.payee != counterparty {
                return Err(Error::PaymentCounterpartyMismatch { seq });
            }
            if payment.amount_minor == 0 {
                return Err(Error::InvalidPaymentAmount { seq });
            }
            validate_text(&payment.currency, TextField::PaymentCurrency, 3, false)?;
            if payment.currency.len() != 3
                || !payment
                    .currency
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase())
            {
                return Err(Error::InvalidPaymentCurrency { seq });
            }
        }
        (Kind::Payment, None) | (_, Some(_)) => {
            return Err(Error::PaymentKindMismatch { seq });
        }
        (_, None) => {}
    }

    accounted_fields_bytes(counterparty, claim_paths, payment)
}

fn validate_new_entry(
    entry: &NewEntry,
    seq: u64,
    paths_are_canonical: bool,
) -> Result<usize, Error> {
    validate_entry_fields(
        entry.epoch,
        entry.kind,
        &entry.counterparty,
        &entry.claim_paths,
        entry.payment.as_ref(),
        seq,
        paths_are_canonical,
    )
}

fn redacted_entry_is_canonical(entry: &Entry) -> bool {
    entry.epoch == 0
        && entry.kind == Kind::Presentation
        && entry.counterparty.is_empty()
        && entry.consent_hash == ZERO_HASH
        && entry.claim_paths.is_empty()
        && entry.outcome == Outcome::Aborted
        && entry.payment.is_none()
}

fn validate_entries(
    digest: &dyn Digest,
    entries: &[Entry],
    expected_anchored_head: [u8; 32],
) -> Result<usize, Error> {
    if entries.len() > MAX_ENTRIES {
        return Err(Error::EntryLimitExceeded { max: MAX_ENTRIES });
    }

    let mut previous_hash = ZERO_HASH;
    let mut aggregate_bytes = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let expected_seq = u64::try_from(index).map_err(|_| Error::SizeOverflow)?;
        if entry.seq != expected_seq {
            return Err(Error::SequenceMismatch {
                expected: expected_seq,
                actual: entry.seq,
            });
        }
        if entry.prev_hash != previous_hash {
            return Err(Error::PreviousHashMismatch { seq: entry.seq });
        }
        if entry.entry_hash == ZERO_HASH {
            return Err(Error::ZeroEntryHash { seq: entry.seq });
        }

        let entry_bytes = if entry.redacted {
            if !redacted_entry_is_canonical(entry) {
                return Err(Error::RedactedEntryNotCanonical { seq: entry.seq });
            }
            accounted_entry_bytes(entry)?
        } else {
            let bytes = validate_entry_fields(
                entry.epoch,
                entry.kind,
                &entry.counterparty,
                &entry.claim_paths,
                entry.payment.as_ref(),
                entry.seq,
                true,
            )?;
            let new_entry = NewEntry {
                epoch: entry.epoch,
                kind: entry.kind,
                counterparty: entry.counterparty.clone(),
                consent_hash: entry.consent_hash,
                claim_paths: entry.claim_paths.clone(),
                outcome: entry.outcome,
                payment: entry.payment.clone(),
            };
            if hash_entry(digest, entry.seq, entry.prev_hash, &new_entry) != entry.entry_hash {
                return Err(Error::EntryHashMismatch { seq: entry.seq });
            }
            bytes
        };
        aggregate_bytes = aggregate_bytes
            .checked_add(entry_bytes)
            .ok_or(Error::SizeOverflow)?;
        if aggregate_bytes > MAX_AGGREGATE_BYTES {
            return Err(Error::AggregateByteLimitExceeded {
                max: MAX_AGGREGATE_BYTES,
                actual: aggregate_bytes,
            });
        }
        previous_hash = entry.entry_hash;
    }

    if previous_hash != expected_anchored_head {
        return Err(Error::AnchoredHeadMismatch {
            expected: expected_anchored_head,
            actual: previous_hash,
        });
    }
    Ok(aggregate_bytes)
}

/// Deterministic, length-prefixed serialisation of an entry, then SHA-256. Length prefixes make
/// the encoding injective (no field-boundary ambiguity), so distinct entries never collide on the
/// pre-image. Domain-separated by a version tag.
fn hash_entry(digest: &dyn Digest, seq: u64, prev_hash: [u8; 32], e: &NewEntry) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(HASH_DOMAIN);
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

    fn payment(payee: &str, amount_minor: u64, currency: &str) -> NewEntry {
        NewEntry {
            epoch: 2_000,
            kind: Kind::Payment,
            counterparty: payee.into(),
            consent_hash: [7u8; 32],
            claim_paths: Vec::new(),
            outcome: Outcome::Completed,
            payment: Some(PaymentSummary {
                payee: payee.into(),
                amount_minor,
                currency: currency.into(),
            }),
        }
    }

    fn max_sized_entry() -> NewEntry {
        let path_bytes = MAX_ENTRY_BYTES
            - ACCOUNTED_ENTRY_FIXED_BYTES
            - 1 // counterparty
            - (MAX_CLAIM_PATHS_PER_ENTRY * 8); // per-path length prefixes
        let base_len = path_bytes / MAX_CLAIM_PATHS_PER_ENTRY;
        let remainder = path_bytes % MAX_CLAIM_PATHS_PER_ENTRY;
        let claim_paths = (0..MAX_CLAIM_PATHS_PER_ENTRY)
            .map(|index| {
                let prefix = format!("{index:03}:");
                let len = base_len + usize::from(index < remainder);
                format!("{prefix}{}", "x".repeat(len - prefix.len()))
            })
            .collect();
        let entry = NewEntry {
            epoch: 1,
            kind: Kind::Presentation,
            counterparty: "r".into(),
            consent_hash: [1u8; 32],
            claim_paths,
            outcome: Outcome::Completed,
            payment: None,
        };
        assert_eq!(accounted_new_entry_bytes(&entry).unwrap(), MAX_ENTRY_BYTES);
        entry
    }

    fn committed_entry(seq: u64, prev_hash: [u8; 32], entry: NewEntry) -> Entry {
        let entry_hash = hash_entry(&AwsLc, seq, prev_hash, &entry);
        Entry {
            seq,
            epoch: entry.epoch,
            kind: entry.kind,
            counterparty: entry.counterparty,
            consent_hash: entry.consent_hash,
            claim_paths: entry.claim_paths,
            outcome: entry.outcome,
            payment: entry.payment,
            prev_hash,
            entry_hash,
            redacted: false,
        }
    }

    #[test]
    fn append_chains_and_verifies() {
        let mut log = TransactionLog::new();
        assert!(log.is_empty());
        assert_eq!(log.head(), [0u8; 32]);

        log.append(&AwsLc, presentation(1000, "rp.example", &["age_over_18"]))
            .unwrap();
        log.append(&AwsLc, presentation(1001, "shop.example", &["family_name"]))
            .unwrap();

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
        log.append(&AwsLc, presentation(1000, "rp.example", &["age_over_18"]))
            .unwrap();
        log.append(&AwsLc, presentation(1001, "shop.example", &["family_name"]))
            .unwrap();
        assert!(log.verify_integrity(&AwsLc));

        // Edit a recorded counterparty after the fact — integrity must fail.
        log.entries[0].counterparty = "evil.example".into();
        assert!(!log.verify_integrity(&AwsLc));
    }

    #[test]
    fn reordering_entries_breaks_the_chain() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "a.example", &["x"]))
            .unwrap();
        log.append(&AwsLc, presentation(1001, "b.example", &["y"]))
            .unwrap();
        log.entries.swap(0, 1);
        assert!(!log.verify_integrity(&AwsLc), "reordering must be detected");
    }

    #[test]
    fn deleting_an_entry_breaks_the_chain() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "a.example", &["x"]))
            .unwrap();
        log.append(&AwsLc, presentation(1001, "b.example", &["y"]))
            .unwrap();
        log.append(&AwsLc, presentation(1002, "c.example", &["z"]))
            .unwrap();
        // Remove the middle entry: seq gap + broken linkage.
        log.entries.remove(1);
        assert!(!log.verify_integrity(&AwsLc));
    }

    #[test]
    fn redaction_erases_content_but_preserves_the_chain() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "rp.example", &["age_over_18"]))
            .unwrap();
        log.append(&AwsLc, presentation(1001, "shop.example", &["family_name"]))
            .unwrap();
        log.append(&AwsLc, presentation(1002, "third.example", &["birthdate"]))
            .unwrap();
        let head_before = log.head();

        // Erase the middle entry (data-subject right to erasure).
        assert!(log.redact(1));
        let e = &log.entries()[1];
        assert!(e.redacted);
        assert_eq!(e.epoch, 0);
        assert_eq!(e.kind, Kind::Presentation);
        assert_eq!(e.counterparty, ""); // content gone
        assert!(e.claim_paths.is_empty());
        assert_eq!(e.consent_hash, [0u8; 32]);
        assert_eq!(e.outcome, Outcome::Aborted);
        assert_eq!(e.payment, None);

        // The chain still verifies and the head is unchanged (linkage intact, deletion evident).
        assert!(log.verify_integrity(&AwsLc), "chain intact after redaction");
        assert_eq!(log.head(), head_before, "head unchanged: hashes retained");
        // The un-redacted neighbours are untouched.
        assert_eq!(log.entries()[0].counterparty, "rp.example");
        assert_eq!(log.entries()[2].counterparty, "third.example");
    }

    #[test]
    fn redacting_a_missing_entry_is_a_noop() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "rp.example", &["x"]))
            .unwrap();
        assert!(!log.redact(5));
        assert!(log.verify_integrity(&AwsLc));
    }

    #[test]
    fn wipe_erases_everything() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "a", &["x"])).unwrap();
        log.append(&AwsLc, presentation(1001, "b", &["y"])).unwrap();
        log.wipe();
        assert!(log.is_empty());
        assert_eq!(log.head(), [0u8; 32]);
        assert!(log.verify_integrity(&AwsLc));
    }

    #[test]
    fn report_summarises_without_values() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1000, "rp.example", &["age_over_18"]))
            .unwrap();
        log.append(&AwsLc, presentation(1001, "rp.example", &["family_name"]))
            .unwrap(); // same RP again
        log.append(
            &AwsLc,
            NewEntry {
                epoch: 1002,
                kind: Kind::Payment,
                counterparty: "Acme Store".into(),
                consent_hash: [1u8; 32],
                claim_paths: vec![],
                outcome: Outcome::Completed,
                payment: Some(PaymentSummary {
                    payee: "Acme Store".into(),
                    amount_minor: 500,
                    currency: "EUR".into(),
                }),
            },
        )
        .unwrap();
        log.redact(0); // erase one presentation

        let r = log.report();
        assert_eq!(r.total, 3);
        assert_eq!(r.redacted, 1);
        assert_eq!(r.presentations, 1); // one remains un-redacted
        assert_eq!(r.payments, 1);
        assert_eq!(r.issuances, 0);
        // Distinct non-redacted counterparties, sorted; the redacted one is excluded.
        assert_eq!(
            r.counterparties,
            vec!["Acme Store".to_string(), "rp.example".to_string()]
        );
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
        )
        .unwrap();
        let e = &log.entries()[0];
        assert_eq!(e.payment.as_ref().unwrap().amount_minor, 1299);
        assert!(log.verify_integrity(&AwsLc));
        // Editing the amount after the fact breaks the chain (dynamic-linking audit trail).
        log.entries[0].payment.as_mut().unwrap().amount_minor = 9999;
        assert!(!log.verify_integrity(&AwsLc));
    }

    #[test]
    fn empty_and_valid_logs_restore_only_against_the_exact_anchor() {
        let empty = TransactionLog::restore_checked(&AwsLc, Vec::new(), ZERO_HASH).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.accounted_bytes, 0);
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, Vec::new(), [1u8; 32]),
            Err(Error::AnchoredHeadMismatch {
                expected: [1u8; 32],
                actual: ZERO_HASH,
            })
        );

        let mut original = TransactionLog::new();
        original
            .append(
                &AwsLc,
                presentation(1, "rp.example", &["z_claim", "a_claim"]),
            )
            .unwrap();
        assert_eq!(
            original.entries()[0].claim_paths,
            vec!["a_claim".to_string(), "z_claim".to_string()]
        );
        let restored =
            TransactionLog::restore_checked(&AwsLc, original.entries().to_vec(), original.head())
                .unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn append_stops_exactly_at_the_entry_cap_without_eviction() {
        let mut log = TransactionLog::new();
        for epoch in 0..MAX_ENTRIES {
            log.append(
                &AwsLc,
                presentation(i64::try_from(epoch).unwrap(), "r", &[]),
            )
            .unwrap();
        }
        let head = log.head();
        let accounted_bytes = log.accounted_bytes;
        assert_eq!(log.len(), MAX_ENTRIES);
        assert_eq!(
            log.append(&AwsLc, presentation(5_000, "r", &[])),
            Err(Error::EntryLimitExceeded { max: MAX_ENTRIES })
        );
        assert_eq!(log.len(), MAX_ENTRIES);
        assert_eq!(log.head(), head);
        assert_eq!(log.accounted_bytes, accounted_bytes);

        let mut too_many = log.entries().to_vec();
        too_many.push(log.entries()[0].clone());
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, too_many, head),
            Err(Error::EntryLimitExceeded { max: MAX_ENTRIES })
        );
    }

    #[test]
    fn byte_budgets_accept_exact_boundaries_and_reject_one_more_atomically() {
        let exact = max_sized_entry();
        let mut oversized = exact.clone();
        oversized.claim_paths[0].push('x');
        let mut single = TransactionLog::new();
        assert_eq!(
            single.append(&AwsLc, oversized),
            Err(Error::EntryByteLimitExceeded {
                max: MAX_ENTRY_BYTES,
                actual: MAX_ENTRY_BYTES + 1,
            })
        );
        assert!(single.is_empty());

        // 64 maximum-sized entries are exactly the 4 MiB aggregate budget.
        for _ in 0..(MAX_AGGREGATE_BYTES / MAX_ENTRY_BYTES) {
            single.append(&AwsLc, exact.clone()).unwrap();
        }
        assert_eq!(single.accounted_bytes, MAX_AGGREGATE_BYTES);
        let head = single.head();
        assert!(matches!(
            single.append(&AwsLc, presentation(2, "r", &[])),
            Err(Error::AggregateByteLimitExceeded {
                max: MAX_AGGREGATE_BYTES,
                ..
            })
        ));
        assert_eq!(single.head(), head);
        assert_eq!(single.accounted_bytes, MAX_AGGREGATE_BYTES);

        // A decoder cannot bypass append: the same over-budget chain fails checked import.
        let mut imported = single.entries().to_vec();
        let next = committed_entry(
            u64::try_from(imported.len()).unwrap(),
            head,
            presentation(2, "r", &[]),
        );
        let next_head = next.entry_hash;
        imported.push(next);
        assert!(matches!(
            TransactionLog::restore_checked(&AwsLc, imported, next_head),
            Err(Error::AggregateByteLimitExceeded {
                max: MAX_AGGREGATE_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn field_and_cardinality_bounds_reject_hostile_entries_before_hashing() {
        let mut log = TransactionLog::new();
        let exact_counterparty = "x".repeat(MAX_COUNTERPARTY_BYTES);
        log.append(&AwsLc, presentation(1, &exact_counterparty, &[]))
            .unwrap();
        let head = log.head();

        let huge_counterparty = "x".repeat(MAX_AGGREGATE_BYTES + 1);
        assert!(matches!(
            log.append(&AwsLc, presentation(2, &huge_counterparty, &[])),
            Err(Error::FieldTooLong {
                field: TextField::Counterparty,
                max: MAX_COUNTERPARTY_BYTES,
                ..
            })
        ));
        assert_eq!(log.head(), head);

        let long_path = "x".repeat(MAX_CLAIM_PATH_BYTES + 1);
        let mut entry = presentation(2, "r", &[]);
        entry.claim_paths.push(long_path);
        assert!(matches!(
            log.append(&AwsLc, entry),
            Err(Error::FieldTooLong {
                field: TextField::ClaimPath,
                max: MAX_CLAIM_PATH_BYTES,
                ..
            })
        ));

        let mut entry = presentation(2, "r", &[]);
        entry.claim_paths = (0..=MAX_CLAIM_PATHS_PER_ENTRY)
            .map(|index| format!("claim-{index:03}"))
            .collect();
        assert_eq!(
            log.append(&AwsLc, entry),
            Err(Error::TooManyClaimPaths {
                max: MAX_CLAIM_PATHS_PER_ENTRY,
                actual: MAX_CLAIM_PATHS_PER_ENTRY + 1,
            })
        );
        assert_eq!(log.head(), head);
    }

    #[test]
    fn text_and_claim_paths_have_one_unambiguous_canonical_form() {
        let mut log = TransactionLog::new();
        assert_eq!(
            log.append(&AwsLc, presentation(1, "", &[])),
            Err(Error::FieldEmpty {
                field: TextField::Counterparty,
            })
        );
        assert_eq!(
            log.append(&AwsLc, presentation(1, " rp.example", &[])),
            Err(Error::NonCanonicalText {
                field: TextField::Counterparty,
            })
        );
        assert_eq!(
            log.append(&AwsLc, presentation(1, "rp\n.example", &[])),
            Err(Error::NonCanonicalText {
                field: TextField::Counterparty,
            })
        );
        assert_eq!(
            log.append(&AwsLc, presentation(1, "rp", &["claim", "claim"])),
            Err(Error::DuplicateClaimPath)
        );

        let mut canonical = TransactionLog::new();
        canonical
            .append(&AwsLc, presentation(1, "rp", &["a", "b"]))
            .unwrap();
        let anchor = canonical.head();
        let mut out_of_order = canonical.entries().to_vec();
        out_of_order[0].claim_paths.swap(0, 1);
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, out_of_order, anchor),
            Err(Error::ClaimPathsNotCanonical)
        );
        let mut duplicate = canonical.entries().to_vec();
        duplicate[0].claim_paths[1] = "a".into();
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, duplicate, anchor),
            Err(Error::DuplicateClaimPath)
        );
    }

    #[test]
    fn payment_kind_and_summary_invariants_are_enforced() {
        let mut log = TransactionLog::new();

        let mut missing = payment("Acme", 100, "EUR");
        missing.payment = None;
        assert_eq!(
            log.append(&AwsLc, missing),
            Err(Error::PaymentKindMismatch { seq: 0 })
        );

        let mut unexpected = presentation(1, "rp", &[]);
        unexpected.payment = payment("rp", 100, "EUR").payment;
        assert_eq!(
            log.append(&AwsLc, unexpected),
            Err(Error::PaymentKindMismatch { seq: 0 })
        );

        let mut mismatch = payment("Acme", 100, "EUR");
        mismatch.payment.as_mut().unwrap().payee = "Mallory".into();
        assert_eq!(
            log.append(&AwsLc, mismatch),
            Err(Error::PaymentCounterpartyMismatch { seq: 0 })
        );
        assert_eq!(
            log.append(&AwsLc, payment("Acme", 0, "EUR")),
            Err(Error::InvalidPaymentAmount { seq: 0 })
        );
        assert_eq!(
            log.append(&AwsLc, payment("Acme", 100, "eur")),
            Err(Error::InvalidPaymentCurrency { seq: 0 })
        );

        let mut with_claim = payment("Acme", 100, "EUR");
        with_claim.claim_paths.push("identity".into());
        assert_eq!(
            log.append(&AwsLc, with_claim),
            Err(Error::PaymentKindMismatch { seq: 0 })
        );
        assert!(log.is_empty());
    }

    #[test]
    fn restore_rejects_bad_sequence_link_hash_and_external_head() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, presentation(1, "a", &[])).unwrap();
        log.append(&AwsLc, presentation(2, "b", &[])).unwrap();
        let entries = log.entries().to_vec();
        let anchor = log.head();

        let mut bad = entries.clone();
        bad[1].seq = 7;
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, bad, anchor),
            Err(Error::SequenceMismatch {
                expected: 1,
                actual: 7,
            })
        );

        let mut bad = entries.clone();
        bad[1].prev_hash = [9u8; 32];
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, bad, anchor),
            Err(Error::PreviousHashMismatch { seq: 1 })
        );

        let mut bad = entries.clone();
        bad[0].entry_hash = ZERO_HASH;
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, bad, anchor),
            Err(Error::ZeroEntryHash { seq: 0 })
        );

        let mut bad = entries.clone();
        bad[0].entry_hash[0] ^= 1;
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, bad, anchor),
            Err(Error::EntryHashMismatch { seq: 0 })
        );

        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, entries, [8u8; 32]),
            Err(Error::AnchoredHeadMismatch {
                expected: [8u8; 32],
                actual: anchor,
            })
        );
    }

    #[test]
    fn redacted_import_requires_every_non_linkage_field_to_be_canonical() {
        let mut log = TransactionLog::new();
        log.append(&AwsLc, payment("Acme", 100, "EUR")).unwrap();
        let original_head = log.head();
        assert!(log.redact(0));
        let tombstone = log.entries()[0].clone();
        TransactionLog::restore_checked(&AwsLc, vec![tombstone.clone()], original_head).unwrap();

        let assert_rejected = |mut candidate: Entry, mutate: fn(&mut Entry)| {
            mutate(&mut candidate);
            assert_eq!(
                TransactionLog::restore_checked(&AwsLc, vec![candidate], original_head),
                Err(Error::RedactedEntryNotCanonical { seq: 0 })
            );
        };
        assert_rejected(tombstone.clone(), |entry| entry.epoch = 1);
        assert_rejected(tombstone.clone(), |entry| entry.kind = Kind::Payment);
        assert_rejected(tombstone.clone(), |entry| {
            entry.counterparty = "Acme".into();
        });
        assert_rejected(tombstone.clone(), |entry| {
            entry.consent_hash = [1u8; 32];
        });
        assert_rejected(tombstone.clone(), |entry| {
            entry.claim_paths = vec!["claim".into()];
        });
        assert_rejected(tombstone.clone(), |entry| {
            entry.outcome = Outcome::Completed;
        });
        assert_rejected(tombstone.clone(), |entry| {
            entry.payment = payment("Acme", 100, "EUR").payment;
        });

        let mut no_longer_redacted = tombstone.clone();
        no_longer_redacted.redacted = false;
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, vec![no_longer_redacted], original_head,),
            Err(Error::FieldEmpty {
                field: TextField::Counterparty,
            })
        );

        // Even a canonical final tombstone cannot substitute a different retained original hash:
        // only the externally authenticated head can authorize it.
        let mut replaced_hash = tombstone;
        replaced_hash.entry_hash = [9u8; 32];
        assert_eq!(
            TransactionLog::restore_checked(&AwsLc, vec![replaced_hash], original_head),
            Err(Error::AnchoredHeadMismatch {
                expected: original_head,
                actual: [9u8; 32],
            })
        );
    }

    #[test]
    fn failed_replace_is_atomic_and_preserves_the_prior_log() {
        let mut current = TransactionLog::new();
        current
            .append(&AwsLc, presentation(1, "current", &[]))
            .unwrap();
        let before = current.clone();

        let mut replacement = TransactionLog::new();
        replacement
            .append(&AwsLc, presentation(2, "replacement-a", &[]))
            .unwrap();
        replacement
            .append(&AwsLc, presentation(3, "replacement-b", &[]))
            .unwrap();
        let replacement_head = replacement.head();
        let mut corrupt = replacement.entries().to_vec();
        corrupt[1].prev_hash = [4u8; 32];
        assert_eq!(
            current.replace_checked(&AwsLc, corrupt, replacement_head),
            Err(Error::PreviousHashMismatch { seq: 1 })
        );
        assert_eq!(current, before);

        current
            .replace_checked(&AwsLc, replacement.entries().to_vec(), replacement_head)
            .unwrap();
        assert_eq!(current, replacement);
    }
}
