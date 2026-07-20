//! Durable-delivery ledger primitives.
//!
//! This module deliberately does not dispatch effects. It provides the bounded, correlated state
//! machine that checkpoint-v2 can persist and a later aggregate can drive atomically.

// This entire foundation is intentionally dormant until checkpoint-v2 and aggregate wiring land.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::fmt;
use std::num::NonZeroU64;

use crypto_backend::AwsLc;
use crypto_traits::{Digest, Random};
use zeroize::Zeroizing;

pub(super) const MAX_LIVE_DELIVERIES: usize = 32;
pub(super) const MAX_RESERVED_DELIVERY_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_DELIVERY_TOMBSTONES: usize = 64;
pub(super) const MAX_DELIVERY_SEQUENCE: u64 = i64::MAX as u64;
pub(super) const MAX_DELIVERY_ATTEMPTS: u8 = 3;

const DELIVERY_ID_DOMAIN: &[u8] = b"euwallet.delivery-ledger.id.v1\0";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct DeliveryId([u8; 32]);

impl DeliveryId {
    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DeliveryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeliveryId(<redacted>)")
    }
}

/// Closed classification of work that may eventually cross the Core/native boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeliveryKind {
    ResolveRpTrust,
    PersistNonce,
    Render,
    Sign,
    Http,
    PushPar,
    OpenAuthBrowser,
    PromptTxCode,
    RequestToken,
    RequestCredential,
    FetchStatusList,
    PublishTransferOffer,
    Close,
}

impl DeliveryKind {
    fn tag(self) -> u8 {
        match self {
            Self::ResolveRpTrust => 1,
            Self::PersistNonce => 2,
            Self::Render => 3,
            Self::Sign => 4,
            Self::Http => 5,
            Self::PushPar => 6,
            Self::OpenAuthBrowser => 7,
            Self::PromptTxCode => 8,
            Self::RequestToken => 9,
            Self::RequestCredential => 10,
            Self::FetchStatusList => 11,
            Self::PublishTransferOffer => 12,
            Self::Close => 13,
        }
    }

    /// Recovery is a Core-owned security decision, never a shell-provided parameter.
    pub(super) fn recovery_policy(self) -> RecoveryPolicy {
        match self {
            Self::PersistNonce | Self::Render | Self::FetchStatusList | Self::Close => {
                RecoveryPolicy::ReplaySafe
            }
            Self::OpenAuthBrowser | Self::PromptTxCode => RecoveryPolicy::AwaitCallback,
            Self::Sign | Self::RequestCredential => RecoveryPolicy::NeverReplay,
            Self::ResolveRpTrust
            | Self::Http
            | Self::PushPar
            | Self::RequestToken
            | Self::PublishTransferOffer => RecoveryPolicy::ReconcileBeforeRetry,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryPolicy {
    ReplaySafe,
    ReconcileBeforeRetry,
    NeverReplay,
    AwaitCallback,
}

impl RecoveryPolicy {
    fn tag(self) -> u8 {
        match self {
            Self::ReplaySafe => 1,
            Self::ReconcileBeforeRetry => 2,
            Self::NeverReplay => 3,
            Self::AwaitCallback => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeliveryState {
    Queued,
    Dispatching,
    ResultReady,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TombstoneDisposition {
    ResultConsumed,
}

#[derive(Clone)]
struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl SensitiveBytes {
    /// Callers wrap raw input before performing any fallible validation.
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl PartialEq for SensitiveBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for SensitiveBytes {}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveBytes(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct DeliveryCorrelation {
    id: DeliveryId,
    request_hash: [u8; 32],
    attempt: u8,
    adapter_contract: NonZeroU64,
}

impl fmt::Debug for DeliveryCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeliveryCorrelation(<redacted>)")
    }
}

impl DeliveryCorrelation {
    pub(super) fn id(&self) -> DeliveryId {
        self.id
    }

    pub(super) fn request_hash(&self) -> &[u8; 32] {
        &self.request_hash
    }

    pub(super) fn attempt(&self) -> u8 {
        self.attempt
    }

    pub(super) fn adapter_contract(&self) -> u64 {
        self.adapter_contract.get()
    }
}

#[derive(Clone)]
pub(super) struct DeliverySpec {
    kind: DeliveryKind,
    request: SensitiveBytes,
    result_capacity: usize,
}

impl DeliverySpec {
    pub(super) fn new(kind: DeliveryKind, request: Vec<u8>, result_capacity: usize) -> Self {
        Self {
            kind,
            request: SensitiveBytes::new(request),
            result_capacity,
        }
    }
}

impl fmt::Debug for DeliverySpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliverySpec")
            .field("kind", &self.kind)
            .field("recovery_policy", &self.kind.recovery_policy())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(super) struct PreparedDelivery {
    namespace: Zeroizing<[u8; 32]>,
    id: DeliveryId,
    sequence: u64,
    kind: DeliveryKind,
    recovery_policy: RecoveryPolicy,
    request: SensitiveBytes,
    request_hash: [u8; 32],
    result_capacity: usize,
}

impl PartialEq for PreparedDelivery {
    fn eq(&self, other: &Self) -> bool {
        self.namespace.as_slice() == other.namespace.as_slice()
            && self.id == other.id
            && self.sequence == other.sequence
            && self.kind == other.kind
            && self.recovery_policy == other.recovery_policy
            && self.request == other.request
            && self.request_hash == other.request_hash
            && self.result_capacity == other.result_capacity
    }
}

impl Eq for PreparedDelivery {}

impl fmt::Debug for PreparedDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDelivery")
            .field("kind", &self.kind)
            .field("recovery_policy", &self.recovery_policy)
            .finish_non_exhaustive()
    }
}

impl PreparedDelivery {
    pub(super) fn id(&self) -> DeliveryId {
        self.id
    }

    pub(super) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(super) fn recovery_policy(&self) -> RecoveryPolicy {
        self.recovery_policy
    }
}

#[derive(Clone)]
pub(super) struct PreparedDeliveryBatch {
    entries: Vec<PreparedDelivery>,
}

impl fmt::Debug for PreparedDeliveryBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedDeliveryBatch(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct DeliveryEntry {
    id: DeliveryId,
    sequence: u64,
    kind: DeliveryKind,
    recovery_policy: RecoveryPolicy,
    state: DeliveryState,
    request: SensitiveBytes,
    request_hash: [u8; 32],
    result_capacity: usize,
    result: Option<SensitiveBytes>,
    result_hash: Option<[u8; 32]>,
    attempt: u8,
    adapter_contract: Option<NonZeroU64>,
}

impl fmt::Debug for DeliveryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryEntry")
            .field("kind", &self.kind)
            .field("recovery_policy", &self.recovery_policy)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl DeliveryEntry {
    fn correlation(&self) -> Option<DeliveryCorrelation> {
        Some(DeliveryCorrelation {
            id: self.id,
            request_hash: self.request_hash,
            attempt: self.attempt,
            adapter_contract: self.adapter_contract?,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct ClaimedDelivery {
    correlation: DeliveryCorrelation,
    sequence: u64,
    kind: DeliveryKind,
    recovery_policy: RecoveryPolicy,
    request: SensitiveBytes,
    result_capacity: usize,
}

impl fmt::Debug for ClaimedDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedDelivery")
            .field("kind", &self.kind)
            .field("recovery_policy", &self.recovery_policy)
            .finish_non_exhaustive()
    }
}

impl ClaimedDelivery {
    pub(super) fn correlation(&self) -> &DeliveryCorrelation {
        &self.correlation
    }

    pub(super) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(super) fn kind(&self) -> DeliveryKind {
        self.kind
    }

    pub(super) fn recovery_policy(&self) -> RecoveryPolicy {
        self.recovery_policy
    }

    pub(super) fn request(&self) -> &[u8] {
        self.request.as_slice()
    }

    pub(super) fn result_capacity(&self) -> usize {
        self.result_capacity
    }

    pub(super) fn attempt(&self) -> u8 {
        self.correlation.attempt()
    }

    pub(super) fn adapter_contract(&self) -> u64 {
        self.correlation.adapter_contract()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecordResultOutcome {
    Recorded,
    AlreadyRecorded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ConsumeReadyOutcome {
    /// Rotation is explicit to the caller; a tombstone is never evicted silently.
    pub(super) rotated_out: Option<DeliveryId>,
}

#[derive(Clone, PartialEq, Eq)]
struct DeliveryTombstone {
    id: DeliveryId,
    sequence: u64,
    request_hash: [u8; 32],
    attempt: u8,
    adapter_contract: NonZeroU64,
    result_hash: [u8; 32],
    disposition: TombstoneDisposition,
}

impl fmt::Debug for DeliveryTombstone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryTombstone")
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DeliveryLedgerError {
    LiveCapacity,
    ByteCapacity,
    SequenceExhausted,
    AttemptsExhausted,
    DuplicateId,
    StalePreparation,
    EmptyBatch,
    InvalidAdapterContract,
    AdapterContractMismatch,
    StaleAttempt,
    DispatchInProgress,
    NoQueuedDelivery,
    HeadOfLineBlocked {
        state: DeliveryState,
    },
    UnknownDelivery,
    ResultConsumed,
    CorrelationMismatch,
    InvalidTransition {
        from: DeliveryState,
        operation: &'static str,
    },
    RecoveryPolicyDenied {
        policy: RecoveryPolicy,
    },
    ResultTooLarge,
    ConflictingResult,
}

#[derive(Clone)]
pub(super) struct DeliveryLedger {
    namespace: Zeroizing<[u8; 32]>,
    next_sequence: u64,
    live: Vec<DeliveryEntry>,
    tombstones: VecDeque<DeliveryTombstone>,
    reserved_bytes: usize,
}

impl PartialEq for DeliveryLedger {
    fn eq(&self, other: &Self) -> bool {
        self.namespace.as_slice() == other.namespace.as_slice()
            && self.next_sequence == other.next_sequence
            && self.live == other.live
            && self.tombstones == other.tombstones
            && self.reserved_bytes == other.reserved_bytes
    }
}

impl Eq for DeliveryLedger {}

impl fmt::Debug for DeliveryLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryLedger")
            .field("live", &count_bucket(self.live.len()))
            .field("tombstones", &count_bucket(self.tombstones.len()))
            .finish_non_exhaustive()
    }
}

impl DeliveryLedger {
    pub(super) fn new() -> Self {
        Self::with_random(&AwsLc)
    }

    fn with_random(random: &dyn Random) -> Self {
        let mut namespace = Zeroizing::new([0u8; 32]);
        random.fill(&mut *namespace);
        Self {
            namespace,
            next_sequence: 1,
            live: Vec::new(),
            tombstones: VecDeque::new(),
            reserved_bytes: 0,
        }
    }

    pub(super) fn namespace(&self) -> &[u8; 32] {
        &self.namespace
    }

    pub(super) fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub(super) fn live_len(&self) -> usize {
        self.live.len()
    }

    pub(super) fn tombstone_len(&self) -> usize {
        self.tombstones.len()
    }

    pub(super) fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    pub(super) fn state(&self, id: DeliveryId) -> Option<DeliveryState> {
        self.live
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.state)
    }

    /// Stage one entry without changing the ledger. Raw request bytes are zeroizing before the
    /// first capacity or sequence check can fail.
    pub(super) fn prepare(
        &self,
        kind: DeliveryKind,
        request: Vec<u8>,
        result_capacity: usize,
    ) -> Result<PreparedDelivery, DeliveryLedgerError> {
        self.prepare_sensitive(kind, SensitiveBytes::new(request), result_capacity)
    }

    fn prepare_sensitive(
        &self,
        kind: DeliveryKind,
        request: SensitiveBytes,
        result_capacity: usize,
    ) -> Result<PreparedDelivery, DeliveryLedgerError> {
        if self.live.len() >= MAX_LIVE_DELIVERIES {
            return Err(DeliveryLedgerError::LiveCapacity);
        }
        let reservation = reservation_size(request.len(), result_capacity)?;
        ensure_budget(self.reserved_bytes, reservation)?;
        if self.next_sequence == 0 || self.next_sequence > MAX_DELIVERY_SEQUENCE {
            return Err(DeliveryLedgerError::SequenceExhausted);
        }

        let recovery_policy = kind.recovery_policy();
        let request_hash = AwsLc.sha256(request.as_slice());
        let id = derive_id(
            &self.namespace,
            self.next_sequence,
            kind,
            recovery_policy,
            &request_hash,
            result_capacity,
        );
        if self.contains_id(id) {
            return Err(DeliveryLedgerError::DuplicateId);
        }
        Ok(PreparedDelivery {
            namespace: self.namespace.clone(),
            id,
            sequence: self.next_sequence,
            kind,
            recovery_policy,
            request,
            request_hash,
            result_capacity,
        })
    }

    /// Stage an entire successor batch on a cloned ledger. Any boundary failure leaves `self`
    /// byte-for-byte unchanged and drops all staged secrets through `Zeroizing`.
    pub(super) fn prepare_batch(
        &self,
        specs: Vec<DeliverySpec>,
    ) -> Result<PreparedDeliveryBatch, DeliveryLedgerError> {
        if specs.is_empty() {
            return Err(DeliveryLedgerError::EmptyBatch);
        }
        let remaining = MAX_LIVE_DELIVERIES
            .checked_sub(self.live.len())
            .ok_or(DeliveryLedgerError::LiveCapacity)?;
        if specs.len() > remaining {
            return Err(DeliveryLedgerError::LiveCapacity);
        }
        let mut staged = self.clone();
        let mut entries = Vec::with_capacity(specs.len());
        for spec in specs {
            let prepared =
                staged.prepare_sensitive(spec.kind, spec.request, spec.result_capacity)?;
            staged.enqueue(prepared.clone())?;
            entries.push(prepared);
        }
        Ok(PreparedDeliveryBatch { entries })
    }

    /// Commit one prepared entry only after every freshness, capacity and hash check passes.
    pub(super) fn enqueue(
        &mut self,
        prepared: PreparedDelivery,
    ) -> Result<DeliveryId, DeliveryLedgerError> {
        if self.contains_id(prepared.id) {
            return Err(DeliveryLedgerError::DuplicateId);
        }
        if prepared.namespace.as_slice() != self.namespace.as_slice()
            || prepared.sequence != self.next_sequence
        {
            return Err(DeliveryLedgerError::StalePreparation);
        }
        if self.live.len() >= MAX_LIVE_DELIVERIES {
            return Err(DeliveryLedgerError::LiveCapacity);
        }
        let reservation = reservation_size(prepared.request.len(), prepared.result_capacity)?;
        ensure_budget(self.reserved_bytes, reservation)?;
        if prepared.sequence == 0 || prepared.sequence > MAX_DELIVERY_SEQUENCE {
            return Err(DeliveryLedgerError::SequenceExhausted);
        }
        let request_hash = AwsLc.sha256(prepared.request.as_slice());
        let expected_id = derive_id(
            &self.namespace,
            prepared.sequence,
            prepared.kind,
            prepared.recovery_policy,
            &request_hash,
            prepared.result_capacity,
        );
        if request_hash != prepared.request_hash || expected_id != prepared.id {
            return Err(DeliveryLedgerError::CorrelationMismatch);
        }

        let id = prepared.id;
        self.live.push(DeliveryEntry {
            id,
            sequence: prepared.sequence,
            kind: prepared.kind,
            recovery_policy: prepared.recovery_policy,
            state: DeliveryState::Queued,
            request: prepared.request,
            request_hash: prepared.request_hash,
            result_capacity: prepared.result_capacity,
            result: None,
            result_hash: None,
            attempt: 0,
            adapter_contract: None,
        });
        self.reserved_bytes += reservation;
        self.next_sequence += 1;
        Ok(id)
    }

    /// Atomically commit a prepared batch by validating it on a clone before replacing `self`.
    pub(super) fn enqueue_batch(
        &mut self,
        batch: PreparedDeliveryBatch,
    ) -> Result<Vec<DeliveryId>, DeliveryLedgerError> {
        if batch.entries.is_empty() {
            return Err(DeliveryLedgerError::EmptyBatch);
        }
        let mut staged = self.clone();
        let mut ids = Vec::with_capacity(batch.entries.len());
        for prepared in batch.entries {
            ids.push(staged.enqueue(prepared)?);
        }
        *self = staged;
        Ok(ids)
    }

    /// Claim the strict head-of-line entry. The nonzero adapter contract is fixed by the first
    /// claim and every retry must use exactly the same contract.
    pub(super) fn claim_oldest(
        &mut self,
        adapter_contract: u64,
    ) -> Result<ClaimedDelivery, DeliveryLedgerError> {
        let adapter_contract =
            NonZeroU64::new(adapter_contract).ok_or(DeliveryLedgerError::InvalidAdapterContract)?;
        if self
            .live
            .iter()
            .any(|entry| entry.state == DeliveryState::Dispatching)
        {
            return Err(DeliveryLedgerError::DispatchInProgress);
        }
        let Some((index, state)) = self
            .live
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.sequence)
            .map(|(index, entry)| (index, entry.state))
        else {
            return Err(DeliveryLedgerError::NoQueuedDelivery);
        };
        if state != DeliveryState::Queued {
            return Err(DeliveryLedgerError::HeadOfLineBlocked { state });
        }

        let entry = &self.live[index];
        if let Some(expected) = entry.adapter_contract {
            if expected != adapter_contract {
                return Err(DeliveryLedgerError::AdapterContractMismatch);
            }
        }
        if entry.attempt >= MAX_DELIVERY_ATTEMPTS {
            return Err(DeliveryLedgerError::AttemptsExhausted);
        }

        let entry = &mut self.live[index];
        entry.adapter_contract.get_or_insert(adapter_contract);
        entry.attempt += 1;
        entry.state = DeliveryState::Dispatching;
        let correlation = entry
            .correlation()
            .expect("a claimed entry always has a nonzero adapter contract");
        Ok(ClaimedDelivery {
            correlation,
            sequence: entry.sequence,
            kind: entry.kind,
            recovery_policy: entry.recovery_policy,
            request: entry.request.clone(),
            result_capacity: entry.result_capacity,
        })
    }

    /// Record the exact result for a live dispatch or recognize a duplicate of a retained consumed
    /// result. Raw result bytes are zeroizing before any lookup or validation can fail.
    pub(super) fn record_result(
        &mut self,
        correlation: &DeliveryCorrelation,
        result: Vec<u8>,
    ) -> Result<RecordResultOutcome, DeliveryLedgerError> {
        let result = SensitiveBytes::new(result);
        if result.len() > MAX_RESERVED_DELIVERY_BYTES {
            return Err(DeliveryLedgerError::ResultTooLarge);
        }
        let location = self.correlated_location(correlation)?;
        if let CorrelatedLocation::Live(index) = location {
            if result.len() > self.live[index].result_capacity {
                return Err(DeliveryLedgerError::ResultTooLarge);
            }
        }
        let result_hash = AwsLc.sha256(result.as_slice());
        match location {
            CorrelatedLocation::Tombstone(index) => {
                if self.tombstones[index].result_hash == result_hash {
                    Ok(RecordResultOutcome::AlreadyRecorded)
                } else {
                    Err(DeliveryLedgerError::ConflictingResult)
                }
            }
            CorrelatedLocation::Live(index) => {
                let entry = &self.live[index];
                match entry.state {
                    DeliveryState::Dispatching | DeliveryState::Ambiguous => {}
                    DeliveryState::ResultReady => {
                        if entry.result.as_ref().map(SensitiveBytes::as_slice)
                            == Some(result.as_slice())
                            && entry.result_hash == Some(result_hash)
                        {
                            return Ok(RecordResultOutcome::AlreadyRecorded);
                        }
                        return Err(DeliveryLedgerError::ConflictingResult);
                    }
                    DeliveryState::Queued => {
                        return Err(DeliveryLedgerError::InvalidTransition {
                            from: DeliveryState::Queued,
                            operation: "recordResult",
                        });
                    }
                }

                let entry = &mut self.live[index];
                entry.result = Some(result);
                entry.result_hash = Some(result_hash);
                entry.state = DeliveryState::ResultReady;
                Ok(RecordResultOutcome::Recorded)
            }
        }
    }

    pub(super) fn mark_ambiguous(
        &mut self,
        correlation: &DeliveryCorrelation,
    ) -> Result<(), DeliveryLedgerError> {
        let index = self.live_location(correlation)?;
        match self.live[index].state {
            DeliveryState::Dispatching => {
                self.live[index].state = DeliveryState::Ambiguous;
                Ok(())
            }
            from => Err(DeliveryLedgerError::InvalidTransition {
                from,
                operation: "markAmbiguous",
            }),
        }
    }

    /// A positive "not performed" reconciliation may requeue only policy-approved ambiguous work.
    pub(super) fn resolve_not_performed(
        &mut self,
        correlation: &DeliveryCorrelation,
    ) -> Result<(), DeliveryLedgerError> {
        let index = self.live_location(correlation)?;
        let entry = &self.live[index];
        if entry.state != DeliveryState::Ambiguous {
            return Err(DeliveryLedgerError::InvalidTransition {
                from: entry.state,
                operation: "resolveNotPerformed",
            });
        }
        let policy = entry.recovery_policy;
        if !matches!(
            policy,
            RecoveryPolicy::ReplaySafe | RecoveryPolicy::ReconcileBeforeRetry
        ) {
            return Err(DeliveryLedgerError::RecoveryPolicyDenied { policy });
        }
        if entry.attempt >= MAX_DELIVERY_ATTEMPTS {
            return Err(DeliveryLedgerError::AttemptsExhausted);
        }
        self.live[index].state = DeliveryState::Queued;
        Ok(())
    }

    pub(super) fn ready_result(
        &self,
        correlation: &DeliveryCorrelation,
    ) -> Result<&[u8], DeliveryLedgerError> {
        let index = self.live_location(correlation)?;
        let entry = &self.live[index];
        if entry.state != DeliveryState::ResultReady {
            return Err(DeliveryLedgerError::InvalidTransition {
                from: entry.state,
                operation: "readyResult",
            });
        }
        Ok(entry
            .result
            .as_ref()
            .expect("ResultReady entries always hold a correlated result")
            .as_slice())
    }

    /// Consume only an exact, committed result. Result-free actions first record an empty result.
    pub(super) fn consume_ready(
        &mut self,
        correlation: &DeliveryCorrelation,
    ) -> Result<ConsumeReadyOutcome, DeliveryLedgerError> {
        let index = self.live_location(correlation)?;
        let state = self.live[index].state;
        if state != DeliveryState::ResultReady {
            return Err(DeliveryLedgerError::InvalidTransition {
                from: state,
                operation: "consumeReady",
            });
        }

        let entry = self.live.remove(index);
        let reservation = reservation_size(entry.request.len(), entry.result_capacity)
            .expect("live entry reservation was validated before insertion");
        self.reserved_bytes -= reservation;
        let rotated_out = if self.tombstones.len() == MAX_DELIVERY_TOMBSTONES {
            self.tombstones.pop_front().map(|tombstone| tombstone.id)
        } else {
            None
        };
        self.tombstones.push_back(DeliveryTombstone {
            id: entry.id,
            sequence: entry.sequence,
            request_hash: entry.request_hash,
            attempt: entry.attempt,
            adapter_contract: entry
                .adapter_contract
                .expect("ResultReady entries were first claimed with a contract"),
            result_hash: entry
                .result_hash
                .expect("ResultReady entries always have a result hash"),
            disposition: TombstoneDisposition::ResultConsumed,
        });
        Ok(ConsumeReadyOutcome { rotated_out })
    }

    fn live_location(
        &self,
        correlation: &DeliveryCorrelation,
    ) -> Result<usize, DeliveryLedgerError> {
        match self.correlated_location(correlation)? {
            CorrelatedLocation::Live(index) => Ok(index),
            CorrelatedLocation::Tombstone(_) => Err(DeliveryLedgerError::ResultConsumed),
        }
    }

    fn correlated_location(
        &self,
        correlation: &DeliveryCorrelation,
    ) -> Result<CorrelatedLocation, DeliveryLedgerError> {
        if let Some(index) = self
            .live
            .iter()
            .position(|entry| entry.id == correlation.id)
        {
            validate_correlation(
                correlation,
                self.live[index].request_hash,
                self.live[index].attempt,
                self.live[index].adapter_contract,
            )?;
            return Ok(CorrelatedLocation::Live(index));
        }
        if let Some(index) = self
            .tombstones
            .iter()
            .position(|tombstone| tombstone.id == correlation.id)
        {
            let tombstone = &self.tombstones[index];
            validate_correlation(
                correlation,
                tombstone.request_hash,
                tombstone.attempt,
                Some(tombstone.adapter_contract),
            )?;
            return Ok(CorrelatedLocation::Tombstone(index));
        }
        Err(DeliveryLedgerError::UnknownDelivery)
    }

    fn contains_id(&self, id: DeliveryId) -> bool {
        self.live.iter().any(|entry| entry.id == id)
            || self.tombstones.iter().any(|tombstone| tombstone.id == id)
    }
}

#[derive(Clone, Copy)]
enum CorrelatedLocation {
    Live(usize),
    Tombstone(usize),
}

fn validate_correlation(
    correlation: &DeliveryCorrelation,
    request_hash: [u8; 32],
    attempt: u8,
    adapter_contract: Option<NonZeroU64>,
) -> Result<(), DeliveryLedgerError> {
    if correlation.request_hash != request_hash {
        return Err(DeliveryLedgerError::CorrelationMismatch);
    }
    if Some(correlation.adapter_contract) != adapter_contract {
        return Err(DeliveryLedgerError::AdapterContractMismatch);
    }
    if correlation.attempt != attempt {
        return Err(DeliveryLedgerError::StaleAttempt);
    }
    Ok(())
}

fn reservation_size(
    request_len: usize,
    result_capacity: usize,
) -> Result<usize, DeliveryLedgerError> {
    request_len
        .checked_add(result_capacity)
        .ok_or(DeliveryLedgerError::ByteCapacity)
}

fn ensure_budget(current: usize, additional: usize) -> Result<(), DeliveryLedgerError> {
    let total = current
        .checked_add(additional)
        .ok_or(DeliveryLedgerError::ByteCapacity)?;
    if total > MAX_RESERVED_DELIVERY_BYTES {
        return Err(DeliveryLedgerError::ByteCapacity);
    }
    Ok(())
}

fn derive_id(
    namespace: &[u8; 32],
    sequence: u64,
    kind: DeliveryKind,
    recovery_policy: RecoveryPolicy,
    request_hash: &[u8; 32],
    result_capacity: usize,
) -> DeliveryId {
    let mut input = Zeroizing::new(Vec::with_capacity(
        DELIVERY_ID_DOMAIN.len() + 32 + 8 + 1 + 1 + 32 + 8,
    ));
    input.extend_from_slice(DELIVERY_ID_DOMAIN);
    input.extend_from_slice(namespace);
    input.extend_from_slice(&sequence.to_be_bytes());
    input.push(kind.tag());
    input.push(recovery_policy.tag());
    input.extend_from_slice(request_hash);
    input.extend_from_slice(&(result_capacity as u64).to_be_bytes());
    DeliveryId(AwsLc.sha256(&input))
}

fn count_bucket(count: usize) -> &'static str {
    match count {
        0 => "empty",
        1 => "one",
        2..=7 => "few",
        8..=31 => "many",
        _ => "full",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: u64 = 0x7fff_ffff_ffff_ffc5;

    struct FixedRandom(u8);

    impl Random for FixedRandom {
        fn fill(&self, out: &mut [u8]) {
            out.fill(self.0);
        }
    }

    fn ledger() -> DeliveryLedger {
        DeliveryLedger::with_random(&FixedRandom(0x5a))
    }

    fn enqueue_kind(
        ledger: &mut DeliveryLedger,
        kind: DeliveryKind,
        request: &[u8],
        result_capacity: usize,
    ) -> DeliveryId {
        let prepared = ledger
            .prepare(kind, request.to_vec(), result_capacity)
            .unwrap();
        ledger.enqueue(prepared).unwrap()
    }

    fn enqueue_http(
        ledger: &mut DeliveryLedger,
        request: &[u8],
        result_capacity: usize,
    ) -> DeliveryId {
        enqueue_kind(ledger, DeliveryKind::Http, request, result_capacity)
    }

    fn claim(ledger: &mut DeliveryLedger) -> ClaimedDelivery {
        ledger.claim_oldest(CONTRACT).unwrap()
    }

    fn ambiguous_http(ledger: &mut DeliveryLedger) -> DeliveryCorrelation {
        enqueue_http(ledger, b"request", 8);
        let correlation = claim(ledger).correlation().clone();
        ledger.mark_ambiguous(&correlation).unwrap();
        correlation
    }

    #[test]
    fn recovery_policy_is_exhaustively_core_owned() {
        let cases = [
            (
                DeliveryKind::ResolveRpTrust,
                RecoveryPolicy::ReconcileBeforeRetry,
            ),
            (DeliveryKind::PersistNonce, RecoveryPolicy::ReplaySafe),
            (DeliveryKind::Render, RecoveryPolicy::ReplaySafe),
            (DeliveryKind::Sign, RecoveryPolicy::NeverReplay),
            (DeliveryKind::Http, RecoveryPolicy::ReconcileBeforeRetry),
            (DeliveryKind::PushPar, RecoveryPolicy::ReconcileBeforeRetry),
            (DeliveryKind::OpenAuthBrowser, RecoveryPolicy::AwaitCallback),
            (DeliveryKind::PromptTxCode, RecoveryPolicy::AwaitCallback),
            (
                DeliveryKind::RequestToken,
                RecoveryPolicy::ReconcileBeforeRetry,
            ),
            (DeliveryKind::RequestCredential, RecoveryPolicy::NeverReplay),
            (DeliveryKind::FetchStatusList, RecoveryPolicy::ReplaySafe),
            (
                DeliveryKind::PublishTransferOffer,
                RecoveryPolicy::ReconcileBeforeRetry,
            ),
            (DeliveryKind::Close, RecoveryPolicy::ReplaySafe),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.recovery_policy(), expected);
        }
        let mut kind_tags = cases.map(|(kind, _)| kind.tag());
        kind_tags.sort_unstable();
        assert!(kind_tags.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[test]
    fn stable_id_binds_namespace_sequence_kind_request_and_capacity() {
        let ledger = ledger();
        let first = ledger
            .prepare(DeliveryKind::Http, b"request".to_vec(), 17)
            .unwrap();
        let again = ledger
            .prepare(DeliveryKind::Http, b"request".to_vec(), 17)
            .unwrap();
        assert_eq!(first.id(), again.id());
        assert_eq!(
            first.id().0,
            [
                0x10, 0xe0, 0x48, 0x65, 0x3c, 0x66, 0xb0, 0x01, 0x4b, 0x34, 0xb1, 0x65, 0x4f, 0x26,
                0x7e, 0xac, 0x09, 0x7d, 0xea, 0x7f, 0x66, 0x56, 0x6b, 0xd3, 0x85, 0x02, 0xfa, 0x66,
                0xd8, 0x31, 0x51, 0x31,
            ]
        );
        assert_eq!(first.sequence(), 1);
        assert_eq!(
            first.recovery_policy(),
            RecoveryPolicy::ReconcileBeforeRetry
        );
        assert_ne!(
            first.id(),
            ledger
                .prepare(DeliveryKind::Sign, b"request".to_vec(), 17)
                .unwrap()
                .id()
        );
        assert_ne!(
            first.id(),
            ledger
                .prepare(DeliveryKind::Http, b"different".to_vec(), 17)
                .unwrap()
                .id()
        );
        assert_ne!(
            first.id(),
            ledger
                .prepare(DeliveryKind::Http, b"request".to_vec(), 18)
                .unwrap()
                .id()
        );
        let foreign = DeliveryLedger::with_random(&FixedRandom(0x33))
            .prepare(DeliveryKind::Http, b"request".to_vec(), 17)
            .unwrap();
        assert_ne!(first.id(), foreign.id());
    }

    #[test]
    fn core_selected_policy_is_persisted_across_prepare_enqueue_and_claim() {
        let mut ledger = ledger();
        let prepared = ledger
            .prepare(DeliveryKind::Http, b"request".to_vec(), 1)
            .unwrap();
        let selected = prepared.recovery_policy();
        assert_eq!(selected, RecoveryPolicy::ReconcileBeforeRetry);
        ledger.enqueue(prepared).unwrap();
        assert_eq!(ledger.live[0].recovery_policy, selected);
        let claimed = claim(&mut ledger);
        assert_eq!(claimed.recovery_policy(), selected);
        assert_eq!(ledger.live[0].recovery_policy, selected);
    }

    #[test]
    fn claim_requires_nonzero_contract_and_correlates_attempt_and_contract() {
        let mut ledger = ledger();
        enqueue_http(&mut ledger, b"request", 1);
        let before = ledger.clone();
        assert_eq!(
            ledger.claim_oldest(0),
            Err(DeliveryLedgerError::InvalidAdapterContract)
        );
        assert_eq!(ledger, before);

        let claimed = claim(&mut ledger);
        assert_eq!(claimed.attempt(), 1);
        assert_eq!(claimed.correlation().attempt(), 1);
        assert_eq!(claimed.adapter_contract(), CONTRACT);
        assert_eq!(claimed.correlation().adapter_contract(), CONTRACT);
    }

    #[test]
    fn stale_attempt_and_wrong_contract_reject_without_mutation() {
        let mut ledger = ledger();
        let first = ambiguous_http(&mut ledger);
        ledger.resolve_not_performed(&first).unwrap();

        let before = ledger.clone();
        assert_eq!(
            ledger.claim_oldest(CONTRACT - 1),
            Err(DeliveryLedgerError::AdapterContractMismatch)
        );
        assert_eq!(ledger, before);

        let second = claim(&mut ledger).correlation().clone();
        assert_eq!(second.attempt(), 2);
        let before = ledger.clone();
        assert_eq!(
            ledger.record_result(&first, b"old".to_vec()),
            Err(DeliveryLedgerError::StaleAttempt)
        );
        assert_eq!(ledger, before);

        let mut wrong_contract = second.clone();
        wrong_contract.adapter_contract = NonZeroU64::new(CONTRACT - 1).unwrap();
        assert_eq!(
            ledger.record_result(&wrong_contract, b"wrong".to_vec()),
            Err(DeliveryLedgerError::AdapterContractMismatch)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn retry_attempts_are_capped_at_three_without_partial_mutation() {
        let mut ledger = ledger();
        let mut correlation = ambiguous_http(&mut ledger);
        for expected in 2..=MAX_DELIVERY_ATTEMPTS {
            ledger.resolve_not_performed(&correlation).unwrap();
            correlation = claim(&mut ledger).correlation().clone();
            assert_eq!(correlation.attempt(), expected);
            ledger.mark_ambiguous(&correlation).unwrap();
        }
        let before = ledger.clone();
        assert_eq!(
            ledger.resolve_not_performed(&correlation),
            Err(DeliveryLedgerError::AttemptsExhausted)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn recovery_resolution_obeys_policy() {
        for kind in [DeliveryKind::Render, DeliveryKind::Http] {
            let mut ledger = ledger();
            enqueue_kind(&mut ledger, kind, b"request", 0);
            let correlation = claim(&mut ledger).correlation().clone();
            ledger.mark_ambiguous(&correlation).unwrap();
            ledger.resolve_not_performed(&correlation).unwrap();
            assert_eq!(ledger.state(correlation.id()), Some(DeliveryState::Queued));
        }

        for kind in [DeliveryKind::OpenAuthBrowser, DeliveryKind::Sign] {
            let mut ledger = ledger();
            enqueue_kind(&mut ledger, kind, b"request", 0);
            let correlation = claim(&mut ledger).correlation().clone();
            ledger.mark_ambiguous(&correlation).unwrap();
            let before = ledger.clone();
            assert_eq!(
                ledger.resolve_not_performed(&correlation),
                Err(DeliveryLedgerError::RecoveryPolicyDenied {
                    policy: kind.recovery_policy(),
                })
            );
            assert_eq!(ledger, before);
        }
    }

    #[test]
    fn strict_head_of_line_never_skips_ambiguous_or_ready_work() {
        let mut ledger = ledger();
        let first = enqueue_http(&mut ledger, b"first", 1);
        let second = enqueue_http(&mut ledger, b"second", 1);
        let correlation = claim(&mut ledger).correlation().clone();
        ledger.mark_ambiguous(&correlation).unwrap();
        assert_eq!(
            ledger.claim_oldest(CONTRACT),
            Err(DeliveryLedgerError::HeadOfLineBlocked {
                state: DeliveryState::Ambiguous,
            })
        );
        ledger.record_result(&correlation, vec![1]).unwrap();
        assert_eq!(
            ledger.claim_oldest(CONTRACT),
            Err(DeliveryLedgerError::HeadOfLineBlocked {
                state: DeliveryState::ResultReady,
            })
        );
        ledger.consume_ready(&correlation).unwrap();
        assert_eq!(ledger.state(first), None);
        assert_eq!(claim(&mut ledger).correlation().id(), second);
    }

    #[test]
    fn only_one_delivery_may_be_dispatching() {
        let mut ledger = ledger();
        enqueue_http(&mut ledger, b"first", 1);
        enqueue_http(&mut ledger, b"second", 1);
        claim(&mut ledger);
        let before = ledger.clone();
        assert_eq!(
            ledger.claim_oldest(CONTRACT),
            Err(DeliveryLedgerError::DispatchInProgress)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn exact_duplicate_result_is_idempotent_and_conflict_is_atomic() {
        let mut ledger = ledger();
        enqueue_http(&mut ledger, b"request", 6);
        let correlation = claim(&mut ledger).correlation().clone();
        assert_eq!(
            ledger.record_result(&correlation, b"result".to_vec()),
            Ok(RecordResultOutcome::Recorded)
        );
        assert_eq!(ledger.ready_result(&correlation), Ok(b"result".as_slice()));
        let before = ledger.clone();
        assert_eq!(
            ledger.record_result(&correlation, b"result".to_vec()),
            Ok(RecordResultOutcome::AlreadyRecorded)
        );
        assert_eq!(ledger, before);
        assert_eq!(
            ledger.record_result(&correlation, b"other!".to_vec()),
            Err(DeliveryLedgerError::ConflictingResult)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn consumed_tombstone_validates_full_correlation_and_result_hash() {
        let mut ledger = ledger();
        enqueue_http(&mut ledger, b"request", 6);
        let correlation = claim(&mut ledger).correlation().clone();
        ledger
            .record_result(&correlation, b"result".to_vec())
            .unwrap();
        ledger.consume_ready(&correlation).unwrap();

        assert_eq!(
            ledger.record_result(&correlation, b"result".to_vec()),
            Ok(RecordResultOutcome::AlreadyRecorded)
        );
        assert_eq!(
            ledger.record_result(&correlation, b"other!".to_vec()),
            Err(DeliveryLedgerError::ConflictingResult)
        );

        let before = ledger.clone();
        let mut wrong_hash = correlation.clone();
        wrong_hash.request_hash = [7; 32];
        assert_eq!(
            ledger.record_result(&wrong_hash, b"result".to_vec()),
            Err(DeliveryLedgerError::CorrelationMismatch)
        );
        let mut stale = correlation.clone();
        stale.attempt -= 1;
        assert_eq!(
            ledger.record_result(&stale, b"result".to_vec()),
            Err(DeliveryLedgerError::StaleAttempt)
        );
        let mut wrong_contract = correlation.clone();
        wrong_contract.adapter_contract = NonZeroU64::new(CONTRACT - 1).unwrap();
        assert_eq!(
            ledger.record_result(&wrong_contract, b"result".to_vec()),
            Err(DeliveryLedgerError::AdapterContractMismatch)
        );
        assert_eq!(ledger, before);
        assert_eq!(
            ledger.ready_result(&correlation),
            Err(DeliveryLedgerError::ResultConsumed)
        );
    }

    #[test]
    fn result_free_action_requires_committed_empty_result_before_consume() {
        let mut ledger = ledger();
        enqueue_kind(&mut ledger, DeliveryKind::Close, Vec::new().as_slice(), 0);
        let correlation = claim(&mut ledger).correlation().clone();
        let before = ledger.clone();
        assert_eq!(
            ledger.consume_ready(&correlation),
            Err(DeliveryLedgerError::InvalidTransition {
                from: DeliveryState::Dispatching,
                operation: "consumeReady",
            })
        );
        assert_eq!(ledger, before);
        ledger.record_result(&correlation, Vec::new()).unwrap();
        assert_eq!(ledger.ready_result(&correlation), Ok([].as_slice()));
        ledger.consume_ready(&correlation).unwrap();
    }

    #[test]
    fn invalid_result_and_correlation_errors_never_mutate() {
        let mut ledger = ledger();
        enqueue_http(&mut ledger, b"request", 2);
        let correlation = claim(&mut ledger).correlation().clone();
        let before = ledger.clone();
        assert_eq!(
            ledger.record_result(&correlation, vec![1, 2, 3]),
            Err(DeliveryLedgerError::ResultTooLarge)
        );
        assert_eq!(ledger, before);

        let mut wrong_hash = correlation.clone();
        wrong_hash.request_hash = [8; 32];
        assert_eq!(
            ledger.record_result(&wrong_hash, vec![1]),
            Err(DeliveryLedgerError::CorrelationMismatch)
        );
        let unknown = DeliveryCorrelation {
            id: DeliveryId([9; 32]),
            request_hash: [8; 32],
            attempt: 1,
            adapter_contract: NonZeroU64::new(CONTRACT).unwrap(),
        };
        assert_eq!(
            ledger.record_result(&unknown, vec![1]),
            Err(DeliveryLedgerError::UnknownDelivery)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn atomic_batch_accepts_exact_boundary() {
        let mut ledger = ledger();
        let batch = ledger
            .prepare_batch(vec![
                DeliverySpec::new(DeliveryKind::PersistNonce, vec![1], 1),
                DeliverySpec::new(
                    DeliveryKind::Http,
                    vec![2; MAX_RESERVED_DELIVERY_BYTES - 3],
                    1,
                ),
            ])
            .unwrap();
        let ids = ledger.enqueue_batch(batch).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ledger.live_len(), 2);
        assert_eq!(ledger.reserved_bytes(), MAX_RESERVED_DELIVERY_BYTES);
    }

    #[test]
    fn atomic_batch_boundary_failure_leaves_original_identical() {
        let ledger = ledger();
        let before = ledger.clone();
        assert!(matches!(
            ledger.prepare_batch(vec![
                DeliverySpec::new(
                    DeliveryKind::Http,
                    vec![1; MAX_RESERVED_DELIVERY_BYTES - 1],
                    0,
                ),
                DeliverySpec::new(DeliveryKind::Close, vec![2, 3], 0),
            ]),
            Err(DeliveryLedgerError::ByteCapacity)
        ));
        assert_eq!(ledger, before);
    }

    #[test]
    fn oversized_batch_count_fails_before_staging_or_allocating_entries() {
        let ledger = ledger();
        let specs = (0..=MAX_LIVE_DELIVERIES)
            .map(|_| DeliverySpec::new(DeliveryKind::Close, Vec::new(), 0))
            .collect();
        let before = ledger.clone();
        assert!(matches!(
            ledger.prepare_batch(specs),
            Err(DeliveryLedgerError::LiveCapacity)
        ));
        assert_eq!(ledger, before);
    }

    #[test]
    fn oversized_result_is_rejected_before_hashing_for_live_unknown_and_consumed_ids() {
        let mut ledger = ledger();
        enqueue_http(&mut ledger, b"request", 0);
        let correlation = claim(&mut ledger).correlation().clone();
        let before = ledger.clone();
        assert!(matches!(
            ledger.record_result(&correlation, vec![0; MAX_RESERVED_DELIVERY_BYTES + 1],),
            Err(DeliveryLedgerError::ResultTooLarge)
        ));
        assert_eq!(ledger, before);

        let unknown = DeliveryCorrelation {
            id: DeliveryId([9; 32]),
            request_hash: [8; 32],
            attempt: 1,
            adapter_contract: NonZeroU64::new(CONTRACT).unwrap(),
        };
        assert!(matches!(
            ledger.record_result(&unknown, vec![0; MAX_RESERVED_DELIVERY_BYTES + 1]),
            Err(DeliveryLedgerError::ResultTooLarge)
        ));
        assert_eq!(ledger, before);

        ledger.record_result(&correlation, Vec::new()).unwrap();
        ledger.consume_ready(&correlation).unwrap();
        let consumed = ledger.clone();
        assert!(matches!(
            ledger.record_result(&correlation, vec![0; MAX_RESERVED_DELIVERY_BYTES + 1],),
            Err(DeliveryLedgerError::ResultTooLarge)
        ));
        assert_eq!(ledger, consumed);
    }

    #[test]
    fn stale_batch_enqueue_is_atomic() {
        let mut ledger = ledger();
        let batch = ledger
            .prepare_batch(vec![
                DeliverySpec::new(DeliveryKind::Http, vec![1], 0),
                DeliverySpec::new(DeliveryKind::Http, vec![2], 0),
            ])
            .unwrap();
        enqueue_http(&mut ledger, b"intervening", 0);
        let before = ledger.clone();
        assert!(matches!(
            ledger.enqueue_batch(batch),
            Err(DeliveryLedgerError::StalePreparation) | Err(DeliveryLedgerError::DuplicateId)
        ));
        assert_eq!(ledger, before);
    }

    #[test]
    fn exact_live_sequence_and_tombstone_bounds_hold() {
        let mut live = ledger();
        for byte in 0..MAX_LIVE_DELIVERIES {
            enqueue_http(&mut live, &[byte as u8], 0);
        }
        let before = live.clone();
        assert!(matches!(
            live.prepare(DeliveryKind::Http, vec![0], 0),
            Err(DeliveryLedgerError::LiveCapacity)
        ));
        assert_eq!(live, before);

        let mut sequence = ledger();
        sequence.next_sequence = MAX_DELIVERY_SEQUENCE;
        let last = sequence
            .prepare(DeliveryKind::Close, Vec::new(), 0)
            .unwrap();
        assert_eq!(last.sequence(), MAX_DELIVERY_SEQUENCE);
        sequence.enqueue(last).unwrap();
        assert!(matches!(
            sequence.prepare(DeliveryKind::Close, Vec::new(), 0),
            Err(DeliveryLedgerError::SequenceExhausted)
        ));

        let mut tombstones = ledger();
        let mut first = None;
        for index in 0..=MAX_DELIVERY_TOMBSTONES {
            let id = enqueue_kind(&mut tombstones, DeliveryKind::Close, &[index as u8], 0);
            first.get_or_insert(id);
            let correlation = claim(&mut tombstones).correlation().clone();
            tombstones.record_result(&correlation, Vec::new()).unwrap();
            let outcome = tombstones.consume_ready(&correlation).unwrap();
            if index == MAX_DELIVERY_TOMBSTONES {
                assert_eq!(outcome.rotated_out, first);
            }
        }
        assert_eq!(tombstones.tombstone_len(), MAX_DELIVERY_TOMBSTONES);
    }

    #[test]
    fn debug_redacts_every_sensitive_or_correlation_value() {
        let mut ledger = ledger();
        ledger.next_sequence = 4_242_424_242;
        let prepared = ledger
            .prepare(
                DeliveryKind::Http,
                b"request-super-secret".to_vec(),
                1_234_567,
            )
            .unwrap();
        let prepared_debug = format!("{prepared:?}");
        assert!(!prepared_debug.contains("request-super-secret"));
        assert!(!prepared_debug.contains("4242424242"));
        assert!(!prepared_debug.contains("1234567"));
        ledger.enqueue(prepared).unwrap();
        let claimed = ledger.claim_oldest(CONTRACT).unwrap();
        let correlation = claimed.correlation().clone();
        for debug in [
            format!("{claimed:?}"),
            format!("{correlation:?}"),
            format!("{ledger:?}"),
        ] {
            assert!(!debug.contains("request-super-secret"));
            assert!(!debug.contains(&CONTRACT.to_string()));
            assert!(!debug.contains("4242424242"));
            assert!(!debug.contains("1234567"));
            assert!(!debug.contains("DeliveryId(["));
            assert!(!debug.contains("90, 90, 90"));
        }
        ledger
            .record_result(&correlation, b"result-super-secret".to_vec())
            .unwrap();
        let debug = format!("{ledger:?}");
        assert!(!debug.contains("result-super-secret"));
        assert!(!debug.contains("request-super-secret"));
    }
}
