//! Versioned durable-state checkpoint boundary for `wallet-core`.
//!
//! This is deliberately not a serialization of [`Core`]. Checkpoint v1 contains only source
//! evidence for authenticated production credentials, replay-membership sets and the bounded
//! transaction log. Every protocol machine, pending callback, status-cache value, consent value,
//! fixture and current trust/WUA/configuration object is excluded by construction.
//!
//! The bytes returned here are plaintext canonical CBOR. A platform store must authenticate and
//! encrypt the complete byte string and bind its own monotonic generation to the generation passed
//! to [`Core::export_durable_checkpoint`]. Import requires that authenticated envelope generation
//! again. The transaction head inside this checkpoint detects corruption only because that outer
//! authenticated envelope pins the complete checkpoint; the internal head alone is not rollback
//! protection.
//!
//! Production export/restore remains schema v1. A private, dormant schema-v2 codec models an Idle
//! aggregate plus the delivery ledger, but it is intentionally not accepted by the public restore
//! boundary until every resumable protocol aggregate is persisted. This prevents false Idle
//! checkpoints and v2-to-v1 downgrade. Schema v1 preserves the current replay representation for
//! OID4VCI `c_nonce`: a numeric `u64`; the final string nonce model still requires migration.

use core::cmp::Ordering;

use crypto_traits::Digest;
use zeroize::Zeroizing;

use super::*;

/// Maximum authenticated plaintext checkpoint accepted from a platform store.
///
/// The platform envelope itself is capped at 32 MiB. Android has the larger fixed envelope
/// overhead (120 bytes), so this cross-platform plaintext contract leaves exactly enough room for
/// either native store to authenticate and encrypt every checkpoint Core accepts.
pub const MAX_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024 - 120;
/// Maximum number of authenticated production credentials in one checkpoint.
pub const MAX_CREDENTIALS: usize = 128;
/// Maximum encoded source credential size.
pub const MAX_RAW_CREDENTIAL_BYTES: usize = 2 * 1024 * 1024;
/// Maximum authenticated issuer identity size.
pub const MAX_ISSUER_ID_BYTES: usize = 2 * 1024;
/// Maximum certificates retained for one validated credential path.
pub const MAX_CERTIFICATES_PER_PATH: usize = 16;
/// Maximum DER size of one certificate.
pub const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;
/// Maximum combined raw credential, issuer identity and certificate bytes.
pub const MAX_CREDENTIAL_EVIDENCE_BYTES: usize = 24 * 1024 * 1024;
/// Maximum membership values in each durable replay set. Entries are never silently evicted.
pub const MAX_REPLAY_VALUES: usize = 65_536;

const MAGIC: &[u8] = b"EUWALLET-CHECKPOINT";
const VERSION: u64 = 1;
const DORMANT_VERSION_V2: u64 = 2;
// Exact canonical maximum for Idle + zero live entries + 64 maximum-width tombstones:
// continuation framing (8) + ledger framing excluding tombstones (86) + 64 * 140 bytes.
const MAX_DORMANT_CONTINUATION_BYTES: usize = 9_054;
const MAX_CONTEXT_VALUE_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_DEPTH: usize = 8;
const MAX_CONTAINER_ITEMS: usize = MAX_REPLAY_VALUES;
const MAX_MAP_PAIRS: usize = 16;
const MAX_STRUCTURAL_NODES: usize = 1_000_000;
// The structural scanner must accept every byte string that the domain budgets and shared native
// plaintext ceiling can produce. Per-field and aggregate credential/log limits remain tighter.
const MAX_DECODED_PAYLOAD_BYTES: usize = MAX_CHECKPOINT_BYTES;
const CONTEXT_HASH_DOMAIN: &[u8] = b"eudi-wallet-checkpoint-context-v1";

/// Environment value whose authenticated checkpoint binding did not match the current wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextField {
    WalletClientId,
    DeviceKeyReference,
    DevicePublicKey,
}

/// Resource whose hard persistence limit was exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    CheckpointBytes,
    ContextValue,
    StructuralDepth,
    StructuralNodes,
    ContainerItems,
    DecodedPayloadBytes,
    ContinuationBytes,
    DeliveryReservedBytes,
    Credentials,
    RawCredentialBytes,
    IssuerIdentityBytes,
    Certificates,
    CertificateBytes,
    CredentialEvidenceBytes,
    ReplayValues,
    EncodingBytes,
}

/// Typed, fail-closed export/import errors for durable checkpoint coordination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableCheckpointError {
    ResourceLimit {
        resource: Resource,
        max: usize,
        actual: usize,
    },
    SizeOverflow,
    Truncated,
    NonCanonical,
    Malformed,
    UnsupportedVersion(u64),
    InvalidGeneration,
    GenerationMismatch {
        envelope: u64,
        embedded: u64,
    },
    ContextMismatch(ContextField),
    ClockUnavailable,
    ClockRollback {
        checkpoint: i64,
        current: i64,
    },
    DeviceKeyUnavailable,
    DeviceKeyInvalid,
    TrustListUnavailable,
    TrustListExpired,
    TrustListRollback {
        checkpoint: u64,
        current: u64,
    },
    WuaUnavailable,
    WuaInvalid,
    AuditLogUnavailable,
    AuditTimestampAfterClock {
        seq: u64,
        epoch: i64,
        clock_high_water: i64,
    },
    CredentialInvalid {
        index: usize,
        error: CredentialIngestionError,
    },
    CredentialEvidenceMismatch {
        index: usize,
    },
    DuplicateCredential,
    DormantDeliveryLedgerNotPristine,
    IdleAggregateHasLiveDeliveries,
    InvalidDeliveryLedger,
    TransactionLog(txnlog::Error),
}

impl core::fmt::Display for DurableCheckpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "durable wallet checkpoint rejected: {self:?}")
    }
}

impl std::error::Error for DurableCheckpointError {}

impl From<txnlog::Error> for DurableCheckpointError {
    fn from(value: txnlog::Error) -> Self {
        Self::TransactionLog(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ContextHashes {
    wallet_client_id: [u8; 32],
    device_key_ref: [u8; 32],
    device_public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CredentialRecord {
    format: u8,
    raw: Vec<u8>,
    issuer_identity: String,
    certificate_path: Vec<Vec<u8>>,
}

impl CredentialRecord {
    fn format(&self) -> Result<oid4vci::CredentialFormat, DurableCheckpointError> {
        match self.format {
            1 => Ok(oid4vci::CredentialFormat::DcSdJwt),
            2 => Ok(oid4vci::CredentialFormat::MsoMdoc),
            _ => Err(DurableCheckpointError::Malformed),
        }
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.format
            .cmp(&other.format)
            .then_with(|| self.raw.cmp(&other.raw))
            .then_with(|| self.issuer_identity.cmp(&other.issuer_identity))
            .then_with(|| self.certificate_path.cmp(&other.certificate_path))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplaySets {
    presentation: Vec<u64>,
    payment: Vec<u64>,
    issuance: Vec<u64>,
    qes: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Checkpoint {
    generation: u64,
    context: ContextHashes,
    clock_high_water: i64,
    trust_sequence_high_water: u64,
    credentials: Vec<CredentialRecord>,
    replay: ReplaySets,
    transaction_entries: Vec<txnlog::Entry>,
    transaction_head: [u8; 32],
    continuation: Option<Continuation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Continuation {
    delivery_ledger: delivery::DeliveryLedger,
}

fn resource_limit(resource: Resource, max: usize, actual: usize) -> DurableCheckpointError {
    DurableCheckpointError::ResourceLimit {
        resource,
        max,
        actual,
    }
}

fn checked_total(total: &mut usize, add: usize) -> Result<(), DurableCheckpointError> {
    *total = total
        .checked_add(add)
        .ok_or(DurableCheckpointError::SizeOverflow)?;
    if *total > MAX_CREDENTIAL_EVIDENCE_BYTES {
        return Err(resource_limit(
            Resource::CredentialEvidenceBytes,
            MAX_CREDENTIAL_EVIDENCE_BYTES,
            *total,
        ));
    }
    Ok(())
}

fn context_hash(label: u8, value: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(CONTEXT_HASH_DOMAIN.len() + 1 + 8 + value.len());
    input.extend_from_slice(CONTEXT_HASH_DOMAIN);
    input.push(label);
    input.extend_from_slice(&(value.len() as u64).to_be_bytes());
    input.extend_from_slice(value);
    AwsLc.sha256(&input)
}

fn current_context(core: &Core) -> Result<ContextHashes, DurableCheckpointError> {
    for value in [
        core.config.wallet_client_id.as_bytes(),
        core.config.device_key_ref.as_bytes(),
    ] {
        if value.is_empty() || value.len() > MAX_CONTEXT_VALUE_BYTES {
            return Err(resource_limit(
                Resource::ContextValue,
                MAX_CONTEXT_VALUE_BYTES,
                value.len(),
            ));
        }
    }
    if core.device_public_key.is_empty() {
        return Err(DurableCheckpointError::DeviceKeyUnavailable);
    }
    if core.device_public_key.len() != 65 || core.device_public_key.first() != Some(&0x04) {
        return Err(DurableCheckpointError::DeviceKeyInvalid);
    }
    Ok(ContextHashes {
        wallet_client_id: context_hash(1, core.config.wallet_client_id.as_bytes()),
        device_key_ref: context_hash(2, core.config.device_key_ref.as_bytes()),
        device_public_key: context_hash(3, &core.device_public_key),
    })
}

fn require_current_environment(core: &Core) -> Result<u64, DurableCheckpointError> {
    if core.now_epoch <= 0 {
        return Err(DurableCheckpointError::ClockUnavailable);
    }
    let sequence = core
        .trust_store
        .sequence_number()
        .ok_or(DurableCheckpointError::TrustListUnavailable)?;
    if !core.trust_store.is_valid_at(core.now_epoch) {
        return Err(DurableCheckpointError::TrustListExpired);
    }
    let wua = core
        .wua
        .as_ref()
        .ok_or(DurableCheckpointError::WuaUnavailable)?;
    if !wua.is_valid_for_at(
        &core.device_public_key,
        wua::AssuranceLevel::High,
        core.now_epoch,
    ) {
        return Err(DurableCheckpointError::WuaInvalid);
    }
    Ok(sequence)
}

fn sorted_replay(values: &[u64]) -> Result<Vec<u64>, DurableCheckpointError> {
    // Runtime replay vectors are intended to be sets already. Check before cloning/sorting so a
    // corrupted in-memory value cannot make checkpoint export allocate past the durable bound.
    if values.len() > MAX_REPLAY_VALUES {
        return Err(resource_limit(
            Resource::ReplayValues,
            MAX_REPLAY_VALUES,
            values.len(),
        ));
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    Ok(sorted)
}

fn validate_transaction_clock(
    entries: &[txnlog::Entry],
    clock_high_water: i64,
) -> Result<(), DurableCheckpointError> {
    if let Some(entry) = entries
        .iter()
        .find(|entry| !entry.redacted && entry.epoch > clock_high_water)
    {
        return Err(DurableCheckpointError::AuditTimestampAfterClock {
            seq: entry.seq,
            epoch: entry.epoch,
            clock_high_water,
        });
    }
    Ok(())
}

fn validate_record_parts(
    raw: &[u8],
    issuer_identity: &str,
    certificate_path: &[Vec<u8>],
    aggregate: &mut usize,
) -> Result<(), DurableCheckpointError> {
    if raw.len() > MAX_RAW_CREDENTIAL_BYTES {
        return Err(resource_limit(
            Resource::RawCredentialBytes,
            MAX_RAW_CREDENTIAL_BYTES,
            raw.len(),
        ));
    }
    checked_total(aggregate, raw.len())?;
    if issuer_identity.is_empty() || issuer_identity.len() > MAX_ISSUER_ID_BYTES {
        return Err(resource_limit(
            Resource::IssuerIdentityBytes,
            MAX_ISSUER_ID_BYTES,
            issuer_identity.len(),
        ));
    }
    checked_total(aggregate, issuer_identity.len())?;
    if certificate_path.is_empty() || certificate_path.len() > MAX_CERTIFICATES_PER_PATH {
        return Err(resource_limit(
            Resource::Certificates,
            MAX_CERTIFICATES_PER_PATH,
            certificate_path.len(),
        ));
    }
    for certificate in certificate_path {
        if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
            return Err(resource_limit(
                Resource::CertificateBytes,
                MAX_CERTIFICATE_BYTES,
                certificate.len(),
            ));
        }
        checked_total(aggregate, certificate.len())?;
    }
    Ok(())
}

fn authenticated_provenances(core: &Core) -> impl Iterator<Item = &CredentialProvenance> {
    core.credentials
        .iter()
        .filter_map(|stored| match &stored.provenance {
            StoredProvenance::Authenticated(provenance) => Some(provenance),
            StoredProvenance::TestFixture => None,
        })
        .chain(
            core.mdoc_holdings
                .iter()
                .filter_map(|stored| match &stored.provenance {
                    StoredProvenance::Authenticated(provenance) => Some(provenance),
                    StoredProvenance::TestFixture => None,
                }),
        )
}

fn matching_authenticated_provenance<'a>(
    core: &'a Core,
    candidate: &AuthenticatedCredential,
) -> Option<&'a CredentialProvenance> {
    match &candidate.credential {
        VerifiedCredential::SdJwt { holding, .. } => core
            .credentials
            .iter()
            .find(|stored| stored.holding == *holding)
            .and_then(|stored| match &stored.provenance {
                StoredProvenance::Authenticated(provenance) => Some(provenance),
                StoredProvenance::TestFixture => None,
            }),
        VerifiedCredential::Mdoc { holding, .. } => core
            .mdoc_holdings
            .iter()
            .find(|stored| stored.holding == *holding)
            .and_then(|stored| match &stored.provenance {
                StoredProvenance::Authenticated(provenance) => Some(provenance),
                StoredProvenance::TestFixture => None,
            }),
    }
}

fn record_evidence_bytes(
    provenance: &CredentialProvenance,
) -> Result<usize, DurableCheckpointError> {
    let mut total = 0usize;
    validate_record_parts(
        &provenance.raw_credential,
        &provenance.issuer.identity,
        &provenance.issuer.certificate_path,
        &mut total,
    )?;
    Ok(total)
}

/// Project the exact authenticated upsert before any holding changes. This shares the component
/// and aggregate limits with checkpoint export so an accepted credential can never make the
/// in-memory wallet impossible to commit solely because of credential count/evidence capacity.
pub(super) fn ensure_credential_storage_admission(
    core: &Core,
    candidate: &AuthenticatedCredential,
) -> Result<(), CredentialIngestionError> {
    ensure_credential_storage_admission_with_limits(
        core,
        candidate,
        MAX_CREDENTIALS,
        MAX_CREDENTIAL_EVIDENCE_BYTES,
    )
}

fn ensure_credential_storage_admission_with_limits(
    core: &Core,
    candidate: &AuthenticatedCredential,
    max_credentials: usize,
    max_evidence_bytes: usize,
) -> Result<(), CredentialIngestionError> {
    let current_count = authenticated_provenances(core).count();
    let replaced = matching_authenticated_provenance(core, candidate);
    let projected_count = current_count
        .checked_add(usize::from(replaced.is_none()))
        .ok_or(CredentialIngestionError::CredentialStoreFull)?;
    if projected_count > max_credentials {
        return Err(CredentialIngestionError::CredentialStoreFull);
    }

    let mut current_evidence = 0usize;
    for provenance in authenticated_provenances(core) {
        validate_record_parts(
            &provenance.raw_credential,
            &provenance.issuer.identity,
            &provenance.issuer.certificate_path,
            &mut current_evidence,
        )
        .map_err(|_| CredentialIngestionError::CredentialEvidenceLimitExceeded)?;
    }
    let replaced_evidence = replaced
        .map(record_evidence_bytes)
        .transpose()
        .map_err(|_| CredentialIngestionError::CredentialEvidenceLimitExceeded)?
        .unwrap_or(0);
    let candidate_evidence = record_evidence_bytes(&candidate.provenance)
        .map_err(|_| CredentialIngestionError::CredentialEvidenceLimitExceeded)?;
    let projected_evidence = current_evidence
        .checked_sub(replaced_evidence)
        .and_then(|total| total.checked_add(candidate_evidence))
        .ok_or(CredentialIngestionError::CredentialEvidenceLimitExceeded)?;
    if projected_evidence > max_evidence_bytes {
        return Err(CredentialIngestionError::CredentialEvidenceLimitExceeded);
    }
    Ok(())
}

fn authenticated_records(core: &Core) -> Result<Vec<CredentialRecord>, DurableCheckpointError> {
    let authenticated_count = core
        .credentials
        .iter()
        .filter(|stored| matches!(stored.provenance, StoredProvenance::Authenticated(_)))
        .count()
        .checked_add(
            core.mdoc_holdings
                .iter()
                .filter(|stored| matches!(stored.provenance, StoredProvenance::Authenticated(_)))
                .count(),
        )
        .ok_or(DurableCheckpointError::SizeOverflow)?;
    if authenticated_count > MAX_CREDENTIALS {
        return Err(resource_limit(
            Resource::Credentials,
            MAX_CREDENTIALS,
            authenticated_count,
        ));
    }

    for (index, stored) in core.credentials.iter().enumerate() {
        if !matches!(stored.provenance, StoredProvenance::Authenticated(_)) {
            continue;
        }
        if core.credentials[index + 1..].iter().any(|candidate| {
            matches!(candidate.provenance, StoredProvenance::Authenticated(_))
                && candidate.holding == stored.holding
        }) {
            return Err(DurableCheckpointError::DuplicateCredential);
        }
    }
    for (index, stored) in core.mdoc_holdings.iter().enumerate() {
        if !matches!(stored.provenance, StoredProvenance::Authenticated(_)) {
            continue;
        }
        if core.mdoc_holdings[index + 1..].iter().any(|candidate| {
            matches!(candidate.provenance, StoredProvenance::Authenticated(_))
                && candidate.holding == stored.holding
        }) {
            return Err(DurableCheckpointError::DuplicateCredential);
        }
    }

    let mut records = Vec::with_capacity(authenticated_count);
    let mut aggregate = 0usize;
    for stored in &core.credentials {
        let StoredProvenance::Authenticated(provenance) = &stored.provenance else {
            continue;
        };
        let index = records.len();
        validate_record_parts(
            &provenance.raw_credential,
            &provenance.issuer.identity,
            &provenance.issuer.certificate_path,
            &mut aggregate,
        )?;
        let fresh = core
            .authenticate_received_credential(
                provenance.format,
                &provenance.raw_credential,
                &provenance.issuer.certificate_path,
                &provenance.issuer.identity,
            )
            .map_err(|error| DurableCheckpointError::CredentialInvalid { index, error })?;
        let matches = fresh.provenance == *provenance
            && matches!(
                fresh.credential,
                VerifiedCredential::SdJwt {
                    holding,
                    authenticated,
                    validity,
                } if holding == stored.holding
                    && stored.authenticated.as_ref() == Some(&authenticated)
                    && validity == stored.validity
            );
        if !matches {
            return Err(DurableCheckpointError::CredentialEvidenceMismatch { index });
        }
        let record = CredentialRecord {
            format: 1,
            raw: provenance.raw_credential.clone(),
            issuer_identity: provenance.issuer.identity.clone(),
            certificate_path: provenance.issuer.certificate_path.clone(),
        };
        records.push(record);
    }
    for stored in &core.mdoc_holdings {
        let StoredProvenance::Authenticated(provenance) = &stored.provenance else {
            continue;
        };
        let index = records.len();
        validate_record_parts(
            &provenance.raw_credential,
            &provenance.issuer.identity,
            &provenance.issuer.certificate_path,
            &mut aggregate,
        )?;
        let fresh = core
            .authenticate_received_credential(
                provenance.format,
                &provenance.raw_credential,
                &provenance.issuer.certificate_path,
                &provenance.issuer.identity,
            )
            .map_err(|error| DurableCheckpointError::CredentialInvalid { index, error })?;
        let matches = fresh.provenance == *provenance
            && matches!(
                fresh.credential,
                VerifiedCredential::Mdoc { holding, validity }
                    if holding == stored.holding && validity == stored.validity
            );
        if !matches {
            return Err(DurableCheckpointError::CredentialEvidenceMismatch { index });
        }
        let record = CredentialRecord {
            format: 2,
            raw: provenance.raw_credential.clone(),
            issuer_identity: provenance.issuer.identity.clone(),
            certificate_path: provenance.issuer.certificate_path.clone(),
        };
        records.push(record);
    }
    records.sort_by(CredentialRecord::cmp_canonical);
    if records
        .windows(2)
        .any(|pair| pair[0].cmp_canonical(&pair[1]) != Ordering::Less)
    {
        return Err(DurableCheckpointError::DuplicateCredential);
    }
    Ok(records)
}

impl Core {
    /// Export durable state for one non-zero generation of the platform authenticated envelope.
    ///
    /// The current environment and every production credential are revalidated before bytes are
    /// emitted. Test fixtures are deliberately absent. This method performs no I/O or encryption.
    pub fn export_durable_checkpoint(
        &self,
        envelope_generation: u64,
    ) -> Result<Vec<u8>, DurableCheckpointError> {
        if envelope_generation == 0 {
            return Err(DurableCheckpointError::InvalidGeneration);
        }
        if !self.delivery_ledger.is_pristine() {
            return Err(DurableCheckpointError::DormantDeliveryLedgerNotPristine);
        }
        let context = current_context(self)?;
        let trust_sequence_high_water = require_current_environment(self)?;
        if !self.audit_log_available {
            return Err(DurableCheckpointError::AuditLogUnavailable);
        }
        let credentials = authenticated_records(self)?;
        let replay = ReplaySets {
            presentation: sorted_replay(&self.seen_nonces)?,
            payment: sorted_replay(&self.pay_seen_nonces)?,
            issuance: sorted_replay(&self.iss_seen_c_nonces)?,
            qes: sorted_replay(&self.qes_seen_nonces)?,
        };
        if self.log.len() > txnlog::MAX_ENTRIES {
            return Err(txnlog::Error::EntryLimitExceeded {
                max: txnlog::MAX_ENTRIES,
            }
            .into());
        }
        validate_transaction_clock(self.log.entries(), self.now_epoch)?;
        let transaction_entries = self.log.entries().to_vec();
        let transaction_head = self.log.head();
        txnlog::TransactionLog::restore_checked(
            &AwsLc,
            transaction_entries.clone(),
            transaction_head,
        )?;
        encode_checkpoint(&Checkpoint {
            generation: envelope_generation,
            context,
            clock_high_water: self.now_epoch,
            trust_sequence_high_water,
            credentials,
            replay,
            transaction_entries,
            transaction_head,
            continuation: None,
        })
    }

    /// Atomically restore authenticated durable state from a platform envelope.
    ///
    /// `authenticated_envelope_generation` must be the generation authenticated outside the core
    /// and must exactly equal the embedded generation. All parsing, environment checks,
    /// credential authentication and transaction-chain validation finish before any field changes.
    pub fn restore_durable_checkpoint(
        &mut self,
        bytes: &[u8],
        authenticated_envelope_generation: u64,
    ) -> Result<(), DurableCheckpointError> {
        if authenticated_envelope_generation == 0 {
            return Err(DurableCheckpointError::InvalidGeneration);
        }
        if !self.delivery_ledger.is_pristine() {
            return Err(DurableCheckpointError::DormantDeliveryLedgerNotPristine);
        }
        let checkpoint = decode_checkpoint(bytes)?;
        if checkpoint.generation != authenticated_envelope_generation {
            return Err(DurableCheckpointError::GenerationMismatch {
                envelope: authenticated_envelope_generation,
                embedded: checkpoint.generation,
            });
        }

        let current_context = current_context(self)?;
        if checkpoint.context.wallet_client_id != current_context.wallet_client_id {
            return Err(DurableCheckpointError::ContextMismatch(
                ContextField::WalletClientId,
            ));
        }
        if checkpoint.context.device_key_ref != current_context.device_key_ref {
            return Err(DurableCheckpointError::ContextMismatch(
                ContextField::DeviceKeyReference,
            ));
        }
        if checkpoint.context.device_public_key != current_context.device_public_key {
            return Err(DurableCheckpointError::ContextMismatch(
                ContextField::DevicePublicKey,
            ));
        }
        let current_trust_sequence = require_current_environment(self)?;
        if self.now_epoch < checkpoint.clock_high_water {
            return Err(DurableCheckpointError::ClockRollback {
                checkpoint: checkpoint.clock_high_water,
                current: self.now_epoch,
            });
        }
        if current_trust_sequence < checkpoint.trust_sequence_high_water {
            return Err(DurableCheckpointError::TrustListRollback {
                checkpoint: checkpoint.trust_sequence_high_water,
                current: current_trust_sequence,
            });
        }

        let mut staged_sdjwt = Vec::new();
        let mut staged_mdoc = Vec::new();
        for (index, record) in checkpoint.credentials.iter().enumerate() {
            let authenticated = self
                .authenticate_received_credential(
                    record.format()?,
                    &record.raw,
                    &record.certificate_path,
                    &record.issuer_identity,
                )
                .map_err(|error| DurableCheckpointError::CredentialInvalid { index, error })?;
            if authenticated.provenance.format != record.format()?
                || authenticated.provenance.raw_credential != record.raw
                || authenticated.provenance.issuer.identity != record.issuer_identity
                || authenticated.provenance.issuer.certificate_path != record.certificate_path
            {
                return Err(DurableCheckpointError::CredentialEvidenceMismatch { index });
            }
            let provenance = StoredProvenance::Authenticated(authenticated.provenance);
            match authenticated.credential {
                VerifiedCredential::SdJwt {
                    holding,
                    authenticated,
                    validity,
                } => {
                    if staged_sdjwt
                        .iter()
                        .any(|stored: &StoredSdJwtCredential| stored.holding == holding)
                    {
                        return Err(DurableCheckpointError::DuplicateCredential);
                    }
                    staged_sdjwt.push(StoredSdJwtCredential {
                        holding,
                        authenticated: Some(authenticated),
                        validity,
                        provenance,
                    });
                }
                VerifiedCredential::Mdoc { holding, validity } => {
                    if staged_mdoc
                        .iter()
                        .any(|stored: &StoredMdocCredential| stored.holding == holding)
                    {
                        return Err(DurableCheckpointError::DuplicateCredential);
                    }
                    staged_mdoc.push(StoredMdocCredential {
                        holding,
                        validity,
                        provenance,
                    });
                }
            }
        }
        validate_transaction_clock(&checkpoint.transaction_entries, checkpoint.clock_high_water)?;
        let staged_log = txnlog::TransactionLog::restore_checked(
            &AwsLc,
            checkpoint.transaction_entries,
            checkpoint.transaction_head,
        )?;
        let staged_delivery_ledger = delivery::DeliveryLedger::new();
        let mut staged_next_operation_id = operation_id_seed();
        if staged_next_operation_id == self.next_operation_id {
            // Preserve the random 62-bit namespace while making a collision with this live Core's
            // current next ID impossible. (A prior process remains protected probabilistically by
            // the fresh random namespace; none of its pending IDs is serialized.)
            staged_next_operation_id = (staged_next_operation_id % (1u64 << 62)) + 1;
        }

        // Everything above is fallible and read-only. The assignments below are the atomic commit
        // point and deliberately retain config, trusted time/list, device key, WUA, catalogue and
        // the audit fault latch. A fresh Core starts healthy; import must never heal a live append
        // fault and thereby bypass incomplete history.
        self.credentials = staged_sdjwt;
        self.mdoc_holdings = staged_mdoc;
        self.seen_nonces = checkpoint.replay.presentation;
        self.pay_seen_nonces = checkpoint.replay.payment;
        self.iss_seen_c_nonces = checkpoint.replay.issuance;
        self.qes_seen_nonces = checkpoint.replay.qes;
        self.log = staged_log;

        self.vp = State::Idle;
        self.session = None;
        self.pending_rp_provenance = None;
        self.payment = payment::State::Idle;
        self.pay_pending = None;
        self.active = ActiveFlow::None;
        self.next_operation_id = staged_next_operation_id;
        self.pending_operations.clear();
        self.delivery_ledger = staged_delivery_ledger;
        self.issuance = oid4vci::State::Idle;
        self.issuer_trusted_current = false;
        self.issuer_id_current.clear();
        self.issuer_cert_chain_current.clear();
        self.issuer_id_assertion_current.clear();
        self.issuer_candidates_current.clear();
        self.pending_verified_credential = None;
        self.last_credential_ingestion_error = None;
        self.status_lists.clear();
        self.pending_status_references.clear();
        self.pay_summary = None;
        self.pay_consent_hash = [0u8; 32];
        self.qes = qes::QesState::Idle;
        self.qes_consent_hash = [0u8; 32];
        self.w2w = w2w::State::Idle;
        self.w2w_credential = None;
        Ok(())
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(4096),
        }
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), DurableCheckpointError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        if next > MAX_CHECKPOINT_BYTES {
            return Err(resource_limit(
                Resource::EncodingBytes,
                MAX_CHECKPOINT_BYTES,
                next,
            ));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn head(&mut self, major: u8, argument: u64) -> Result<(), DurableCheckpointError> {
        let mut head = Vec::with_capacity(9);
        cose::cbor::write_head(&mut head, major, argument);
        self.extend(&head)
    }

    fn uint(&mut self, value: u64) -> Result<(), DurableCheckpointError> {
        self.head(0, value)
    }

    fn int(&mut self, value: i64) -> Result<(), DurableCheckpointError> {
        if value >= 0 {
            self.uint(value as u64)
        } else {
            self.head(1, (-1i128 - i128::from(value)) as u64)
        }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), DurableCheckpointError> {
        self.head(
            2,
            u64::try_from(value.len()).map_err(|_| DurableCheckpointError::SizeOverflow)?,
        )?;
        self.extend(value)
    }

    fn text(&mut self, value: &str) -> Result<(), DurableCheckpointError> {
        self.head(
            3,
            u64::try_from(value.len()).map_err(|_| DurableCheckpointError::SizeOverflow)?,
        )?;
        self.extend(value.as_bytes())
    }

    fn array(&mut self, len: usize) -> Result<(), DurableCheckpointError> {
        self.head(
            4,
            u64::try_from(len).map_err(|_| DurableCheckpointError::SizeOverflow)?,
        )
    }

    fn map(&mut self, len: usize) -> Result<(), DurableCheckpointError> {
        self.head(
            5,
            u64::try_from(len).map_err(|_| DurableCheckpointError::SizeOverflow)?,
        )
    }

    fn bool(&mut self, value: bool) -> Result<(), DurableCheckpointError> {
        self.extend(&[if value { 0xf5 } else { 0xf4 }])
    }

    fn null(&mut self) -> Result<(), DurableCheckpointError> {
        self.extend(&[0xf6])
    }
}

fn encode_checkpoint(checkpoint: &Checkpoint) -> Result<Vec<u8>, DurableCheckpointError> {
    if checkpoint.continuation.is_some() {
        return Err(DurableCheckpointError::DormantDeliveryLedgerNotPristine);
    }
    encode_checkpoint_version(checkpoint, VERSION)
}

#[allow(dead_code)]
fn encode_checkpoint_v2(checkpoint: &Checkpoint) -> Result<Vec<u8>, DurableCheckpointError> {
    let continuation = checkpoint
        .continuation
        .as_ref()
        .ok_or(DurableCheckpointError::InvalidDeliveryLedger)?;
    if continuation.delivery_ledger.live_len() != 0 {
        return Err(DurableCheckpointError::IdleAggregateHasLiveDeliveries);
    }
    encode_checkpoint_version(checkpoint, DORMANT_VERSION_V2)
}

fn encode_checkpoint_version(
    checkpoint: &Checkpoint,
    version: u64,
) -> Result<Vec<u8>, DurableCheckpointError> {
    let mut out = Encoder::new();
    out.map(if version == VERSION { 8 } else { 9 })?;
    out.uint(1)?;
    out.bytes(MAGIC)?;
    out.uint(2)?;
    out.uint(version)?;
    out.uint(3)?;
    out.uint(checkpoint.generation)?;
    out.uint(4)?;
    out.map(3)?;
    out.uint(1)?;
    out.bytes(&checkpoint.context.wallet_client_id)?;
    out.uint(2)?;
    out.bytes(&checkpoint.context.device_key_ref)?;
    out.uint(3)?;
    out.bytes(&checkpoint.context.device_public_key)?;
    out.uint(5)?;
    out.map(2)?;
    out.uint(1)?;
    out.int(checkpoint.clock_high_water)?;
    out.uint(2)?;
    out.uint(checkpoint.trust_sequence_high_water)?;
    out.uint(6)?;
    out.array(checkpoint.credentials.len())?;
    for credential in &checkpoint.credentials {
        out.map(4)?;
        out.uint(1)?;
        out.uint(u64::from(credential.format))?;
        out.uint(2)?;
        out.bytes(&credential.raw)?;
        out.uint(3)?;
        out.text(&credential.issuer_identity)?;
        out.uint(4)?;
        out.array(credential.certificate_path.len())?;
        for certificate in &credential.certificate_path {
            out.bytes(certificate)?;
        }
    }
    out.uint(7)?;
    out.map(4)?;
    for (key, values) in [
        (1, &checkpoint.replay.presentation),
        (2, &checkpoint.replay.payment),
        (3, &checkpoint.replay.issuance),
        (4, &checkpoint.replay.qes),
    ] {
        out.uint(key)?;
        out.array(values.len())?;
        for value in values {
            out.uint(*value)?;
        }
    }
    out.uint(8)?;
    out.map(2)?;
    out.uint(1)?;
    out.array(checkpoint.transaction_entries.len())?;
    for entry in &checkpoint.transaction_entries {
        encode_transaction_entry(&mut out, entry)?;
    }
    out.uint(2)?;
    out.bytes(&checkpoint.transaction_head)?;
    if version == DORMANT_VERSION_V2 {
        out.uint(9)?;
        let continuation_start = out.bytes.len();
        encode_continuation(
            &mut out,
            checkpoint
                .continuation
                .as_ref()
                .ok_or(DurableCheckpointError::InvalidDeliveryLedger)?,
        )?;
        let continuation_bytes = out
            .bytes
            .len()
            .checked_sub(continuation_start)
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        if continuation_bytes > MAX_DORMANT_CONTINUATION_BYTES {
            return Err(resource_limit(
                Resource::ContinuationBytes,
                MAX_DORMANT_CONTINUATION_BYTES,
                continuation_bytes,
            ));
        }
    }
    Ok(out.bytes)
}

fn encode_continuation(
    out: &mut Encoder,
    continuation: &Continuation,
) -> Result<(), DurableCheckpointError> {
    out.map(2)?;
    out.uint(1)?;
    // Fixed aggregate envelope. Only Idle is defined while the v2 capability is dormant.
    out.map(2)?;
    out.uint(1)?;
    out.uint(0)?;
    out.uint(2)?;
    out.null()?;
    out.uint(2)?;
    encode_delivery_ledger(out, &continuation.delivery_ledger)
}

fn encode_delivery_ledger(
    out: &mut Encoder,
    ledger: &delivery::DeliveryLedger,
) -> Result<(), DurableCheckpointError> {
    out.map(5)?;
    out.uint(1)?;
    out.bytes(ledger.namespace())?;
    out.uint(2)?;
    out.uint(ledger.next_sequence())?;
    out.uint(3)?;
    out.array(ledger.live_len())?;
    for entry in ledger.live_entries() {
        out.map(12)?;
        out.uint(1)?;
        out.bytes(entry.id().as_bytes())?;
        out.uint(2)?;
        out.uint(entry.sequence())?;
        out.uint(3)?;
        out.uint(u64::from(entry.kind().tag()))?;
        out.uint(4)?;
        out.uint(u64::from(entry.recovery_policy().tag()))?;
        out.uint(5)?;
        out.uint(u64::from(entry.state().tag()))?;
        out.uint(6)?;
        out.bytes(entry.request())?;
        out.uint(7)?;
        out.bytes(entry.request_hash())?;
        out.uint(8)?;
        out.uint(
            u64::try_from(entry.result_capacity())
                .map_err(|_| DurableCheckpointError::SizeOverflow)?,
        )?;
        out.uint(9)?;
        if let Some(result) = entry.result() {
            out.bytes(result)?;
        } else {
            out.null()?;
        }
        out.uint(10)?;
        if let Some(result_hash) = entry.result_hash() {
            out.bytes(result_hash)?;
        } else {
            out.null()?;
        }
        out.uint(11)?;
        out.uint(u64::from(entry.attempt()))?;
        out.uint(12)?;
        if let Some(adapter_contract) = entry.adapter_contract() {
            out.uint(adapter_contract)?;
        } else {
            out.null()?;
        }
    }
    out.uint(4)?;
    out.array(ledger.tombstone_len())?;
    for tombstone in ledger.tombstones() {
        out.map(10)?;
        out.uint(1)?;
        out.bytes(tombstone.id().as_bytes())?;
        out.uint(2)?;
        out.uint(tombstone.sequence())?;
        out.uint(3)?;
        out.uint(u64::from(tombstone.kind().tag()))?;
        out.uint(4)?;
        out.uint(u64::from(tombstone.recovery_policy().tag()))?;
        out.uint(5)?;
        out.bytes(tombstone.request_hash())?;
        out.uint(6)?;
        out.uint(
            u64::try_from(tombstone.result_capacity())
                .map_err(|_| DurableCheckpointError::SizeOverflow)?,
        )?;
        out.uint(7)?;
        out.uint(u64::from(tombstone.attempt()))?;
        out.uint(8)?;
        out.uint(tombstone.adapter_contract())?;
        out.uint(9)?;
        out.bytes(tombstone.result_hash())?;
        out.uint(10)?;
        out.uint(u64::from(tombstone.disposition().tag()))?;
    }
    out.uint(5)?;
    out.bytes(&ledger.digest())
}

fn encode_transaction_entry(
    out: &mut Encoder,
    entry: &txnlog::Entry,
) -> Result<(), DurableCheckpointError> {
    out.map(11)?;
    out.uint(1)?;
    out.uint(entry.seq)?;
    out.uint(2)?;
    out.int(entry.epoch)?;
    out.uint(3)?;
    out.uint(match entry.kind {
        txnlog::Kind::Presentation => 1,
        txnlog::Kind::Issuance => 2,
        txnlog::Kind::Payment => 3,
        txnlog::Kind::Transfer => 4,
    })?;
    out.uint(4)?;
    out.text(&entry.counterparty)?;
    out.uint(5)?;
    out.bytes(&entry.consent_hash)?;
    out.uint(6)?;
    out.array(entry.claim_paths.len())?;
    for claim in &entry.claim_paths {
        out.text(claim)?;
    }
    out.uint(7)?;
    out.uint(match entry.outcome {
        txnlog::Outcome::Completed => 1,
        txnlog::Outcome::Declined => 2,
        txnlog::Outcome::Aborted => 3,
    })?;
    out.uint(8)?;
    if let Some(payment) = &entry.payment {
        out.map(3)?;
        out.uint(1)?;
        out.text(&payment.payee)?;
        out.uint(2)?;
        out.uint(payment.amount_minor)?;
        out.uint(3)?;
        out.text(&payment.currency)?;
    } else {
        out.null()?;
    }
    out.uint(9)?;
    out.bytes(&entry.prev_hash)?;
    out.uint(10)?;
    out.bytes(&entry.entry_hash)?;
    out.uint(11)?;
    out.bool(entry.redacted)
}

struct ScanBudget {
    remaining_nodes: usize,
    payload_bytes: usize,
}

fn cbor_error(error: cose::cbor::CborError) -> DurableCheckpointError {
    use cose::cbor::CborError;
    match error {
        CborError::Truncated => DurableCheckpointError::Truncated,
        CborError::NotShortestForm
        | CborError::IndefiniteLength
        | CborError::MapKeysNotSorted
        | CborError::DuplicateMapKey => DurableCheckpointError::NonCanonical,
        CborError::Reserved
        | CborError::InvalidUtf8
        | CborError::TrailingBytes
        | CborError::UnsupportedSimple
        | CborError::TooDeep => DurableCheckpointError::Malformed,
    }
}

fn usize_argument(value: u64) -> Result<usize, DurableCheckpointError> {
    usize::try_from(value).map_err(|_| DurableCheckpointError::SizeOverflow)
}

fn scan_item(
    bytes: &[u8],
    start: usize,
    depth: usize,
    budget: &mut ScanBudget,
) -> Result<usize, DurableCheckpointError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(resource_limit(
            Resource::StructuralDepth,
            MAX_SCHEMA_DEPTH,
            depth,
        ));
    }
    if budget.remaining_nodes == 0 {
        return Err(resource_limit(
            Resource::StructuralNodes,
            MAX_STRUCTURAL_NODES,
            MAX_STRUCTURAL_NODES + 1,
        ));
    }
    budget.remaining_nodes -= 1;
    let input = bytes
        .get(start..)
        .ok_or(DurableCheckpointError::Truncated)?;
    let first = *input.first().ok_or(DurableCheckpointError::Truncated)?;
    let (major, argument, rest) = cose::cbor::read_head(input).map_err(cbor_error)?;
    let header_len = input
        .len()
        .checked_sub(rest.len())
        .ok_or(DurableCheckpointError::SizeOverflow)?;
    let mut cursor = start
        .checked_add(header_len)
        .ok_or(DurableCheckpointError::SizeOverflow)?;
    match major {
        0 | 1 => Ok(cursor),
        2 | 3 => {
            let len = usize_argument(argument)?;
            if len > MAX_RAW_CREDENTIAL_BYTES {
                return Err(resource_limit(
                    Resource::DecodedPayloadBytes,
                    MAX_RAW_CREDENTIAL_BYTES,
                    len,
                ));
            }
            budget.payload_bytes = budget
                .payload_bytes
                .checked_add(len)
                .ok_or(DurableCheckpointError::SizeOverflow)?;
            if budget.payload_bytes > MAX_DECODED_PAYLOAD_BYTES {
                return Err(resource_limit(
                    Resource::DecodedPayloadBytes,
                    MAX_DECODED_PAYLOAD_BYTES,
                    budget.payload_bytes,
                ));
            }
            let end = cursor
                .checked_add(len)
                .ok_or(DurableCheckpointError::SizeOverflow)?;
            let body = bytes
                .get(cursor..end)
                .ok_or(DurableCheckpointError::Truncated)?;
            if major == 3 && core::str::from_utf8(body).is_err() {
                return Err(DurableCheckpointError::Malformed);
            }
            Ok(end)
        }
        4 => {
            let len = usize_argument(argument)?;
            if len > MAX_CONTAINER_ITEMS {
                return Err(resource_limit(
                    Resource::ContainerItems,
                    MAX_CONTAINER_ITEMS,
                    len,
                ));
            }
            if len > budget.remaining_nodes {
                return Err(resource_limit(
                    Resource::StructuralNodes,
                    MAX_STRUCTURAL_NODES,
                    MAX_STRUCTURAL_NODES + 1,
                ));
            }
            for _ in 0..len {
                cursor = scan_item(bytes, cursor, depth + 1, budget)?;
            }
            Ok(cursor)
        }
        5 => {
            let len = usize_argument(argument)?;
            if len > MAX_MAP_PAIRS {
                return Err(resource_limit(Resource::ContainerItems, MAX_MAP_PAIRS, len));
            }
            let minimum_nodes = len
                .checked_mul(2)
                .ok_or(DurableCheckpointError::SizeOverflow)?;
            if minimum_nodes > budget.remaining_nodes {
                return Err(resource_limit(
                    Resource::StructuralNodes,
                    MAX_STRUCTURAL_NODES,
                    MAX_STRUCTURAL_NODES + 1,
                ));
            }
            let mut previous_key: Option<(usize, usize)> = None;
            for _ in 0..len {
                let key_start = cursor;
                cursor = scan_item(bytes, cursor, depth + 1, budget)?;
                if let Some((previous_start, previous_end)) = previous_key {
                    match bytes[previous_start..previous_end].cmp(&bytes[key_start..cursor]) {
                        Ordering::Less => {}
                        Ordering::Equal => return Err(DurableCheckpointError::NonCanonical),
                        Ordering::Greater => return Err(DurableCheckpointError::NonCanonical),
                    }
                }
                previous_key = Some((key_start, cursor));
                cursor = scan_item(bytes, cursor, depth + 1, budget)?;
            }
            Ok(cursor)
        }
        6 => scan_item(bytes, cursor, depth + 1, budget),
        7 if matches!(first, 0xf4..=0xf6) => Ok(cursor),
        7 => Err(DurableCheckpointError::Malformed),
        _ => Err(DurableCheckpointError::Malformed),
    }
}

fn structural_preflight(bytes: &[u8]) -> Result<(), DurableCheckpointError> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(resource_limit(
            Resource::CheckpointBytes,
            MAX_CHECKPOINT_BYTES,
            bytes.len(),
        ));
    }
    let mut budget = ScanBudget {
        remaining_nodes: MAX_STRUCTURAL_NODES,
        payload_bytes: 0,
    };
    let end = scan_item(bytes, 0, 0, &mut budget)?;
    if end != bytes.len() {
        return Err(DurableCheckpointError::NonCanonical);
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn head(&mut self, expected_major: u8) -> Result<u64, DurableCheckpointError> {
        let input = self
            .bytes
            .get(self.position..)
            .ok_or(DurableCheckpointError::Truncated)?;
        let (major, value, rest) = cose::cbor::read_head(input).map_err(cbor_error)?;
        if major != expected_major {
            return Err(DurableCheckpointError::Malformed);
        }
        self.position = self
            .position
            .checked_add(input.len() - rest.len())
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        Ok(value)
    }

    fn uint(&mut self) -> Result<u64, DurableCheckpointError> {
        self.head(0)
    }

    fn int(&mut self) -> Result<i64, DurableCheckpointError> {
        let input = self
            .bytes
            .get(self.position..)
            .ok_or(DurableCheckpointError::Truncated)?;
        let (major, value, rest) = cose::cbor::read_head(input).map_err(cbor_error)?;
        self.position = self
            .position
            .checked_add(input.len() - rest.len())
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        match major {
            0 => i64::try_from(value).map_err(|_| DurableCheckpointError::Malformed),
            1 if value <= i64::MAX as u64 => Ok((-1i128 - i128::from(value)) as i64),
            _ => Err(DurableCheckpointError::Malformed),
        }
    }

    fn container(&mut self, major: u8, max: usize) -> Result<usize, DurableCheckpointError> {
        let len = usize_argument(self.head(major)?)?;
        if len > max {
            return Err(resource_limit(Resource::ContainerItems, max, len));
        }
        Ok(len)
    }

    fn exact_map(&mut self, len: usize) -> Result<(), DurableCheckpointError> {
        if self.container(5, len)? != len {
            return Err(DurableCheckpointError::Malformed);
        }
        Ok(())
    }

    fn key(&mut self, expected: u64) -> Result<(), DurableCheckpointError> {
        if self.uint()? != expected {
            return Err(DurableCheckpointError::Malformed);
        }
        Ok(())
    }

    fn borrowed_bytes(&mut self, max: usize) -> Result<&'a [u8], DurableCheckpointError> {
        let len = usize_argument(self.head(2)?)?;
        if len > max {
            return Err(resource_limit(Resource::DecodedPayloadBytes, max, len));
        }
        let end = self
            .position
            .checked_add(len)
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(DurableCheckpointError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn hash(&mut self) -> Result<[u8; 32], DurableCheckpointError> {
        self.borrowed_bytes(32)?
            .try_into()
            .map_err(|_| DurableCheckpointError::Malformed)
    }

    fn borrowed_text(&mut self, max: usize) -> Result<&'a str, DurableCheckpointError> {
        let len = usize_argument(self.head(3)?)?;
        if len > max {
            return Err(resource_limit(Resource::DecodedPayloadBytes, max, len));
        }
        let end = self
            .position
            .checked_add(len)
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(DurableCheckpointError::Truncated)?;
        self.position = end;
        core::str::from_utf8(value).map_err(|_| DurableCheckpointError::Malformed)
    }

    fn bool(&mut self) -> Result<bool, DurableCheckpointError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(DurableCheckpointError::Truncated)?;
        match value {
            0xf4 => {
                self.position += 1;
                Ok(false)
            }
            0xf5 => {
                self.position += 1;
                Ok(true)
            }
            _ => Err(DurableCheckpointError::Malformed),
        }
    }

    fn consume_null(&mut self) -> bool {
        if self.bytes.get(self.position) == Some(&0xf6) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn optional_borrowed_bytes(
        &mut self,
        max: usize,
    ) -> Result<Option<&'a [u8]>, DurableCheckpointError> {
        if self.consume_null() {
            return Ok(None);
        }
        self.borrowed_bytes(max).map(Some)
    }

    fn optional_hash(&mut self) -> Result<Option<[u8; 32]>, DurableCheckpointError> {
        if self.consume_null() {
            Ok(None)
        } else {
            self.hash().map(Some)
        }
    }

    fn optional_uint(&mut self) -> Result<Option<u64>, DurableCheckpointError> {
        if self.consume_null() {
            Ok(None)
        } else {
            self.uint().map(Some)
        }
    }

    fn null_or_payment(
        &mut self,
        transaction_payload_bytes: &mut usize,
    ) -> Result<Option<txnlog::PaymentSummary>, DurableCheckpointError> {
        if self.consume_null() {
            return Ok(None);
        }
        self.exact_map(3)?;
        self.key(1)?;
        let payee = self.borrowed_text(txnlog::MAX_PAYMENT_PAYEE_BYTES)?;
        charge_transaction_payload(transaction_payload_bytes, payee.len())?;
        let payee = payee.to_owned();
        self.key(2)?;
        let amount_minor = self.uint()?;
        self.key(3)?;
        let currency = self.borrowed_text(3)?;
        charge_transaction_payload(transaction_payload_bytes, currency.len())?;
        let currency = currency.to_owned();
        Ok(Some(txnlog::PaymentSummary {
            payee,
            amount_minor,
            currency,
        }))
    }
}

fn decode_checkpoint(bytes: &[u8]) -> Result<Checkpoint, DurableCheckpointError> {
    decode_checkpoint_version(bytes, VERSION)
}

#[allow(dead_code)]
fn decode_checkpoint_v2(bytes: &[u8]) -> Result<Checkpoint, DurableCheckpointError> {
    decode_checkpoint_version(bytes, DORMANT_VERSION_V2)
}

fn decode_checkpoint_version(
    bytes: &[u8],
    expected_version: u64,
) -> Result<Checkpoint, DurableCheckpointError> {
    structural_preflight(bytes)?;
    let mut input = Cursor::new(bytes);
    let root_fields = input.container(5, MAX_MAP_PAIRS)?;
    input.key(1)?;
    if input.borrowed_bytes(MAGIC.len())? != MAGIC {
        return Err(DurableCheckpointError::Malformed);
    }
    input.key(2)?;
    let version = input.uint()?;
    if version != expected_version {
        return Err(DurableCheckpointError::UnsupportedVersion(version));
    }
    let expected_root_fields = if version == VERSION { 8 } else { 9 };
    if root_fields != expected_root_fields {
        return Err(DurableCheckpointError::Malformed);
    }
    input.key(3)?;
    let generation = input.uint()?;
    if generation == 0 {
        return Err(DurableCheckpointError::InvalidGeneration);
    }
    input.key(4)?;
    input.exact_map(3)?;
    input.key(1)?;
    let wallet_client_id = input.hash()?;
    input.key(2)?;
    let device_key_ref = input.hash()?;
    input.key(3)?;
    let device_public_key = input.hash()?;
    input.key(5)?;
    input.exact_map(2)?;
    input.key(1)?;
    let clock_high_water = input.int()?;
    if clock_high_water <= 0 {
        return Err(DurableCheckpointError::ClockUnavailable);
    }
    input.key(2)?;
    let trust_sequence_high_water = input.uint()?;
    input.key(6)?;
    let credential_count = input.container(4, MAX_CREDENTIALS)?;
    let mut credentials = Vec::with_capacity(credential_count);
    let mut credential_bytes = 0usize;
    for _ in 0..credential_count {
        input.exact_map(4)?;
        input.key(1)?;
        let format = u8::try_from(input.uint()?).map_err(|_| DurableCheckpointError::Malformed)?;
        if !matches!(format, 1 | 2) {
            return Err(DurableCheckpointError::Malformed);
        }
        input.key(2)?;
        let raw = input.borrowed_bytes(MAX_RAW_CREDENTIAL_BYTES)?;
        checked_total(&mut credential_bytes, raw.len())?;
        let raw = raw.to_vec();
        input.key(3)?;
        let issuer_identity = input.borrowed_text(MAX_ISSUER_ID_BYTES)?;
        if issuer_identity.is_empty() {
            return Err(resource_limit(
                Resource::IssuerIdentityBytes,
                MAX_ISSUER_ID_BYTES,
                0,
            ));
        }
        checked_total(&mut credential_bytes, issuer_identity.len())?;
        let issuer_identity = issuer_identity.to_owned();
        input.key(4)?;
        let path_len = input.container(4, MAX_CERTIFICATES_PER_PATH)?;
        if path_len == 0 {
            return Err(resource_limit(
                Resource::Certificates,
                MAX_CERTIFICATES_PER_PATH,
                0,
            ));
        }
        let mut certificate_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let certificate = input.borrowed_bytes(MAX_CERTIFICATE_BYTES)?;
            if certificate.is_empty() {
                return Err(resource_limit(
                    Resource::CertificateBytes,
                    MAX_CERTIFICATE_BYTES,
                    0,
                ));
            }
            checked_total(&mut credential_bytes, certificate.len())?;
            certificate_path.push(certificate.to_vec());
        }
        let record = CredentialRecord {
            format,
            raw,
            issuer_identity,
            certificate_path,
        };
        if credentials
            .last()
            .is_some_and(|previous: &CredentialRecord| {
                previous.cmp_canonical(&record) != Ordering::Less
            })
        {
            return Err(DurableCheckpointError::DuplicateCredential);
        }
        credentials.push(record);
    }
    input.key(7)?;
    input.exact_map(4)?;
    input.key(1)?;
    let presentation = decode_replay(&mut input)?;
    input.key(2)?;
    let payment = decode_replay(&mut input)?;
    input.key(3)?;
    let issuance = decode_replay(&mut input)?;
    input.key(4)?;
    let qes = decode_replay(&mut input)?;
    input.key(8)?;
    input.exact_map(2)?;
    input.key(1)?;
    let entry_count = input.container(4, txnlog::MAX_ENTRIES)?;
    let mut transaction_entries = Vec::with_capacity(entry_count);
    let mut transaction_payload_bytes = 0usize;
    for _ in 0..entry_count {
        transaction_entries.push(decode_transaction_entry(
            &mut input,
            &mut transaction_payload_bytes,
        )?);
    }
    input.key(2)?;
    let transaction_head = input.hash()?;
    let continuation = if version == DORMANT_VERSION_V2 {
        input.key(9)?;
        let continuation_start = input.position;
        let mut continuation_budget = ScanBudget {
            remaining_nodes: MAX_STRUCTURAL_NODES,
            payload_bytes: 0,
        };
        let continuation_end = scan_item(bytes, continuation_start, 0, &mut continuation_budget)?;
        let continuation_bytes = continuation_end
            .checked_sub(continuation_start)
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        if continuation_bytes > MAX_DORMANT_CONTINUATION_BYTES {
            return Err(resource_limit(
                Resource::ContinuationBytes,
                MAX_DORMANT_CONTINUATION_BYTES,
                continuation_bytes,
            ));
        }
        let continuation = decode_continuation(&mut input)?;
        if input.position != continuation_end {
            return Err(DurableCheckpointError::Malformed);
        }
        if continuation.delivery_ledger.live_len() != 0 {
            return Err(DurableCheckpointError::IdleAggregateHasLiveDeliveries);
        }
        Some(continuation)
    } else {
        None
    };
    if input.position != bytes.len() {
        return Err(DurableCheckpointError::NonCanonical);
    }
    Ok(Checkpoint {
        generation,
        context: ContextHashes {
            wallet_client_id,
            device_key_ref,
            device_public_key,
        },
        clock_high_water,
        trust_sequence_high_water,
        credentials,
        replay: ReplaySets {
            presentation,
            payment,
            issuance,
            qes,
        },
        transaction_entries,
        transaction_head,
        continuation,
    })
}

fn decode_continuation(input: &mut Cursor<'_>) -> Result<Continuation, DurableCheckpointError> {
    input.exact_map(2)?;
    input.key(1)?;
    input.exact_map(2)?;
    input.key(1)?;
    if input.uint()? != 0 {
        return Err(DurableCheckpointError::Malformed);
    }
    input.key(2)?;
    if !input.consume_null() {
        return Err(DurableCheckpointError::Malformed);
    }
    input.key(2)?;
    Ok(Continuation {
        delivery_ledger: decode_delivery_ledger(input)?,
    })
}

fn decode_delivery_ledger(
    input: &mut Cursor<'_>,
) -> Result<delivery::DeliveryLedger, DurableCheckpointError> {
    input.exact_map(5)?;
    input.key(1)?;
    let namespace = Zeroizing::new(input.hash()?);
    input.key(2)?;
    let next_sequence = input.uint()?;
    input.key(3)?;
    let live_count = input.container(4, delivery::MAX_LIVE_DELIVERIES)?;
    let mut live = Vec::with_capacity(live_count);
    let mut reserved_delivery_bytes = 0usize;
    for _ in 0..live_count {
        input.exact_map(12)?;
        input.key(1)?;
        let id = input.hash()?;
        input.key(2)?;
        let sequence = input.uint()?;
        input.key(3)?;
        let kind = delivery::DeliveryKind::from_tag(input.uint()?)
            .ok_or(DurableCheckpointError::Malformed)?;
        input.key(4)?;
        let recovery_policy = delivery::RecoveryPolicy::from_tag(input.uint()?)
            .ok_or(DurableCheckpointError::Malformed)?;
        input.key(5)?;
        let state = delivery::DeliveryState::from_tag(input.uint()?)
            .ok_or(DurableCheckpointError::Malformed)?;
        input.key(6)?;
        let request = input.borrowed_bytes(delivery::MAX_DELIVERY_BLOB_BYTES)?;
        input.key(7)?;
        let request_hash = input.hash()?;
        input.key(8)?;
        let result_capacity = usize_argument(input.uint()?)?;
        if result_capacity > delivery::MAX_DELIVERY_BLOB_BYTES {
            return Err(resource_limit(
                Resource::DecodedPayloadBytes,
                delivery::MAX_DELIVERY_BLOB_BYTES,
                result_capacity,
            ));
        }
        input.key(9)?;
        let result = input.optional_borrowed_bytes(delivery::MAX_DELIVERY_BLOB_BYTES)?;
        input.key(10)?;
        let result_hash = input.optional_hash()?;
        input.key(11)?;
        let attempt = u8::try_from(input.uint()?).map_err(|_| DurableCheckpointError::Malformed)?;
        input.key(12)?;
        let adapter_contract = input.optional_uint()?;
        if result.is_some_and(|value| value.len() > result_capacity) {
            return Err(DurableCheckpointError::InvalidDeliveryLedger);
        }
        let reservation = request
            .len()
            .checked_add(result_capacity)
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        reserved_delivery_bytes = reserved_delivery_bytes
            .checked_add(reservation)
            .ok_or(DurableCheckpointError::SizeOverflow)?;
        if reserved_delivery_bytes > delivery::MAX_RESERVED_DELIVERY_BYTES {
            return Err(resource_limit(
                Resource::DeliveryReservedBytes,
                delivery::MAX_RESERVED_DELIVERY_BYTES,
                reserved_delivery_bytes,
            ));
        }
        // No fallible domain parsing follows these copies before they enter the zeroizing DTO.
        let request = delivery::SensitiveBytes::new(request.to_vec());
        let result = result.map(|value| delivery::SensitiveBytes::new(value.to_vec()));
        live.push(delivery::RestoredDelivery::from_sensitive_parts(
            id,
            sequence,
            kind,
            recovery_policy,
            state,
            request,
            request_hash,
            result_capacity,
            result,
            result_hash,
            attempt,
            adapter_contract,
        ));
    }
    input.key(4)?;
    let tombstone_count = input.container(4, delivery::MAX_DELIVERY_TOMBSTONES)?;
    let mut tombstones = Vec::with_capacity(tombstone_count);
    for _ in 0..tombstone_count {
        input.exact_map(10)?;
        input.key(1)?;
        let id = input.hash()?;
        input.key(2)?;
        let sequence = input.uint()?;
        input.key(3)?;
        let kind = delivery::DeliveryKind::from_tag(input.uint()?)
            .ok_or(DurableCheckpointError::Malformed)?;
        input.key(4)?;
        let recovery_policy = delivery::RecoveryPolicy::from_tag(input.uint()?)
            .ok_or(DurableCheckpointError::Malformed)?;
        input.key(5)?;
        let request_hash = input.hash()?;
        input.key(6)?;
        let result_capacity = usize_argument(input.uint()?)?;
        if result_capacity > delivery::MAX_DELIVERY_BLOB_BYTES {
            return Err(resource_limit(
                Resource::DecodedPayloadBytes,
                delivery::MAX_DELIVERY_BLOB_BYTES,
                result_capacity,
            ));
        }
        input.key(7)?;
        let attempt = u8::try_from(input.uint()?).map_err(|_| DurableCheckpointError::Malformed)?;
        input.key(8)?;
        let adapter_contract = input.uint()?;
        input.key(9)?;
        let result_hash = input.hash()?;
        input.key(10)?;
        let disposition = delivery::TombstoneDisposition::from_tag(input.uint()?)
            .ok_or(DurableCheckpointError::Malformed)?;
        tombstones.push(delivery::RestoredTombstone::new(
            id,
            sequence,
            kind,
            recovery_policy,
            request_hash,
            result_capacity,
            attempt,
            adapter_contract,
            result_hash,
            disposition,
        ));
    }
    input.key(5)?;
    let digest = input.hash()?;
    delivery::DeliveryLedger::restore_checked(namespace, next_sequence, live, tombstones, digest)
        .map_err(|_| DurableCheckpointError::InvalidDeliveryLedger)
}

fn decode_replay(input: &mut Cursor<'_>) -> Result<Vec<u64>, DurableCheckpointError> {
    let len = input.container(4, MAX_REPLAY_VALUES)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let value = input.uint()?;
        if values.last().is_some_and(|previous| *previous >= value) {
            return Err(DurableCheckpointError::NonCanonical);
        }
        values.push(value);
    }
    Ok(values)
}

fn decode_transaction_entry(
    input: &mut Cursor<'_>,
    transaction_payload_bytes: &mut usize,
) -> Result<txnlog::Entry, DurableCheckpointError> {
    input.exact_map(11)?;
    input.key(1)?;
    let seq = input.uint()?;
    input.key(2)?;
    let epoch = input.int()?;
    input.key(3)?;
    let kind = match input.uint()? {
        1 => txnlog::Kind::Presentation,
        2 => txnlog::Kind::Issuance,
        3 => txnlog::Kind::Payment,
        4 => txnlog::Kind::Transfer,
        _ => return Err(DurableCheckpointError::Malformed),
    };
    input.key(4)?;
    let counterparty = input.borrowed_text(txnlog::MAX_COUNTERPARTY_BYTES)?;
    charge_transaction_payload(transaction_payload_bytes, counterparty.len())?;
    let counterparty = counterparty.to_owned();
    input.key(5)?;
    let consent_hash = input.hash()?;
    input.key(6)?;
    let claims_len = input.container(4, txnlog::MAX_CLAIM_PATHS_PER_ENTRY)?;
    let mut claim_paths = Vec::with_capacity(claims_len);
    for _ in 0..claims_len {
        let claim = input.borrowed_text(txnlog::MAX_CLAIM_PATH_BYTES)?;
        charge_transaction_payload(transaction_payload_bytes, claim.len())?;
        claim_paths.push(claim.to_owned());
    }
    input.key(7)?;
    let outcome = match input.uint()? {
        1 => txnlog::Outcome::Completed,
        2 => txnlog::Outcome::Declined,
        3 => txnlog::Outcome::Aborted,
        _ => return Err(DurableCheckpointError::Malformed),
    };
    input.key(8)?;
    let payment = input.null_or_payment(transaction_payload_bytes)?;
    input.key(9)?;
    let prev_hash = input.hash()?;
    input.key(10)?;
    let entry_hash = input.hash()?;
    input.key(11)?;
    let redacted = input.bool()?;
    Ok(txnlog::Entry {
        seq,
        epoch,
        kind,
        counterparty,
        consent_hash,
        claim_paths,
        outcome,
        payment,
        prev_hash,
        entry_hash,
        redacted,
    })
}

fn charge_transaction_payload(total: &mut usize, add: usize) -> Result<(), DurableCheckpointError> {
    *total = total
        .checked_add(add)
        .ok_or(DurableCheckpointError::SizeOverflow)?;
    if *total > txnlog::MAX_AGGREGATE_BYTES {
        return Err(resource_limit(
            Resource::DecodedPayloadBytes,
            txnlog::MAX_AGGREGATE_BYTES,
            *total,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use crypto_backend::SoftwareSigner;
    use crypto_traits::{Alg, KeyRef, Signer};
    use serde_json::json;
    use trust::{ServiceStatus, TrustAnchor, TrustList};

    use super::*;

    const ISSUER_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");

    fn configured_core(
        scenario: &IssuanceScenario,
        wallet_client_id: &str,
        device_key_ref: &str,
    ) -> Core {
        let mut core = Core::new(wallet_client_id, device_key_ref);
        assert!(core
            .handle_event(Event::SetClock {
                epoch: scenario.epoch,
            })
            .is_empty());
        core.load_device_key(scenario.device_public_key.clone());
        core.load_trust_list(&scenario.trust_list, &scenario.operator_public_key)
            .unwrap();
        core.load_wua(&scenario.wua_jwt, &scenario.wallet_provider_public_key)
            .unwrap();
        core
    }

    fn assert_replay_capacity_effects(effects: &[Effect]) {
        assert!(effects.iter().any(|effect| matches!(
            effect,
            Effect::Render {
                screen: ScreenDescription::Error { code, .. }
            } if code == "durable_replay_capacity_exhausted"
        )));
        assert!(effects.iter().any(|effect| matches!(effect, Effect::Close)));
        assert!(effects.iter().all(|effect| matches!(
            effect,
            Effect::Render {
                screen: ScreenDescription::Error { .. }
            } | Effect::Close
        )));
    }

    fn append_history(core: &mut Core) {
        core.log
            .append(
                &AwsLc,
                txnlog::NewEntry {
                    epoch: core.now_epoch,
                    kind: txnlog::Kind::Presentation,
                    counterparty: "https://rp.example".into(),
                    consent_hash: [7u8; 32],
                    claim_paths: vec!["age_over_18".into(), "family_name".into()],
                    outcome: txnlog::Outcome::Completed,
                    payment: None,
                },
            )
            .unwrap();
        core.log
            .append(
                &AwsLc,
                txnlog::NewEntry {
                    epoch: core.now_epoch,
                    kind: txnlog::Kind::Payment,
                    counterparty: "Acme Store".into(),
                    consent_hash: [8u8; 32],
                    claim_paths: Vec::new(),
                    outcome: txnlog::Outcome::Completed,
                    payment: Some(txnlog::PaymentSummary {
                        payee: "Acme Store".into(),
                        amount_minor: 1299,
                        currency: "EUR".into(),
                    }),
                },
            )
            .unwrap();
        assert!(
            core.log.redact(1),
            "final entry becomes an anchored tombstone"
        );
    }

    fn populated_core(scenario: &IssuanceScenario) -> Core {
        let mut core = configured_core(scenario, "wallet.example", "device-key");
        core.ingest_credential(
            "dc+sd-jwt",
            scenario.pid_credential_compact.as_bytes(),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        )
        .unwrap();
        core.ingest_credential(
            "mso_mdoc",
            scenario.mdl_mdoc_credential.as_bytes(),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        )
        .unwrap();
        core.seen_nonces = vec![91, 7];
        core.pay_seen_nonces = vec![21];
        core.iss_seen_c_nonces = vec![31, 30];
        core.qes_seen_nonces = vec![41];
        append_history(&mut core);
        core
    }

    fn advance_trust(core: &mut Core, sequence_number: u64, valid_until: i64) {
        let mut anchors = Vec::new();
        for service_type in [
            ServiceType::PidProvider,
            ServiceType::AttestationProvider,
            ServiceType::RelyingPartyAccessCa,
            ServiceType::StatusProvider,
        ] {
            anchors.extend(
                core.trust_store
                    .granted_anchors(service_type)
                    .into_iter()
                    .map(|certificate_der| TrustAnchor {
                        certificate_der,
                        service_type,
                        status: ServiceStatus::Granted,
                    }),
            );
        }
        core.trust_store
            .update(TrustList {
                sequence_number,
                valid_from: 0,
                valid_until,
                anchors,
            })
            .unwrap();
    }

    fn empty_checkpoint() -> Checkpoint {
        Checkpoint {
            generation: 1,
            context: ContextHashes {
                wallet_client_id: [1u8; 32],
                device_key_ref: [2u8; 32],
                device_public_key: [3u8; 32],
            },
            clock_high_water: 1,
            trust_sequence_high_water: 1,
            credentials: Vec::new(),
            replay: ReplaySets {
                presentation: Vec::new(),
                payment: Vec::new(),
                issuance: Vec::new(),
                qes: Vec::new(),
            },
            transaction_entries: Vec::new(),
            transaction_head: [0u8; 32],
            continuation: None,
        }
    }

    fn dormant_checkpoint(ledger: delivery::DeliveryLedger) -> Checkpoint {
        let mut checkpoint = empty_checkpoint();
        checkpoint.continuation = Some(Continuation {
            delivery_ledger: ledger,
        });
        checkpoint
    }

    fn fixed_delivery_ledger() -> delivery::DeliveryLedger {
        delivery::DeliveryLedger::with_namespace_for_testing([0x5a; 32])
    }

    fn enqueue_delivery(
        ledger: &mut delivery::DeliveryLedger,
        kind: delivery::DeliveryKind,
        request: &[u8],
        result_capacity: usize,
    ) -> delivery::DeliveryId {
        let prepared = ledger
            .prepare(kind, request.to_vec(), result_capacity)
            .unwrap();
        ledger.enqueue(prepared).unwrap()
    }

    fn encode_ledger_bytes(ledger: &delivery::DeliveryLedger) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encode_delivery_ledger(&mut encoder, ledger).unwrap();
        encoder.bytes
    }

    fn decode_ledger_bytes(
        bytes: &[u8],
    ) -> Result<delivery::DeliveryLedger, DurableCheckpointError> {
        structural_preflight(bytes)?;
        let mut cursor = Cursor::new(bytes);
        let ledger = decode_delivery_ledger(&mut cursor)?;
        if cursor.position != bytes.len() {
            return Err(DurableCheckpointError::NonCanonical);
        }
        Ok(ledger)
    }

    fn encode_hostile_queued_delivery(
        out: &mut Encoder,
        sequence: u64,
        kind_tag: u64,
        recovery_tag: u64,
        state_tag: u64,
        request: &[u8],
        result_capacity: usize,
    ) {
        out.map(12).unwrap();
        out.uint(1).unwrap();
        out.bytes(&[0; 32]).unwrap();
        out.uint(2).unwrap();
        out.uint(sequence).unwrap();
        out.uint(3).unwrap();
        out.uint(kind_tag).unwrap();
        out.uint(4).unwrap();
        out.uint(recovery_tag).unwrap();
        out.uint(5).unwrap();
        out.uint(state_tag).unwrap();
        out.uint(6).unwrap();
        out.bytes(request).unwrap();
        out.uint(7).unwrap();
        out.bytes(&[0; 32]).unwrap();
        out.uint(8).unwrap();
        out.uint(u64::try_from(result_capacity).unwrap()).unwrap();
        out.uint(9).unwrap();
        out.null().unwrap();
        out.uint(10).unwrap();
        out.null().unwrap();
        out.uint(11).unwrap();
        out.uint(0).unwrap();
        out.uint(12).unwrap();
        out.null().unwrap();
    }

    fn encode_hostile_single_live_ledger(
        kind_tag: u64,
        recovery_tag: u64,
        state_tag: u64,
    ) -> Vec<u8> {
        let mut out = Encoder::new();
        out.map(5).unwrap();
        out.uint(1).unwrap();
        out.bytes(&[0x5a; 32]).unwrap();
        out.uint(2).unwrap();
        out.uint(2).unwrap();
        out.uint(3).unwrap();
        out.array(1).unwrap();
        encode_hostile_queued_delivery(&mut out, 1, kind_tag, recovery_tag, state_tag, &[], 0);
        out.uint(4).unwrap();
        out.array(0).unwrap();
        out.uint(5).unwrap();
        out.bytes(&[0; 32]).unwrap();
        out.bytes
    }

    fn encode_hostile_tombstone_ledger(disposition_tag: u64) -> Vec<u8> {
        let mut out = Encoder::new();
        out.map(5).unwrap();
        out.uint(1).unwrap();
        out.bytes(&[0x5a; 32]).unwrap();
        out.uint(2).unwrap();
        out.uint(2).unwrap();
        out.uint(3).unwrap();
        out.array(0).unwrap();
        out.uint(4).unwrap();
        out.array(1).unwrap();
        out.map(10).unwrap();
        out.uint(1).unwrap();
        out.bytes(&[0; 32]).unwrap();
        out.uint(2).unwrap();
        out.uint(1).unwrap();
        out.uint(3).unwrap();
        out.uint(5).unwrap();
        out.uint(4).unwrap();
        out.uint(2).unwrap();
        out.uint(5).unwrap();
        out.bytes(&[0; 32]).unwrap();
        out.uint(6).unwrap();
        out.uint(0).unwrap();
        out.uint(7).unwrap();
        out.uint(1).unwrap();
        out.uint(8).unwrap();
        out.uint(7).unwrap();
        out.uint(9).unwrap();
        out.bytes(&[0; 32]).unwrap();
        out.uint(10).unwrap();
        out.uint(disposition_tag).unwrap();
        out.uint(5).unwrap();
        out.bytes(&[0; 32]).unwrap();
        out.bytes
    }

    fn record(first_byte: u8, raw_len: usize) -> CredentialRecord {
        CredentialRecord {
            format: 1,
            raw: vec![first_byte; raw_len],
            issuer_identity: "i".into(),
            certificate_path: vec![vec![1]],
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CoreSnapshot {
        wallet_client_id: String,
        device_key_ref: String,
        vp: State,
        credentials: Vec<StoredSdJwtCredential>,
        mdoc_holdings: Vec<StoredMdocCredential>,
        session_present: bool,
        pending_rp_present: bool,
        now_epoch: i64,
        payment: payment::State,
        active: ActiveFlow,
        next_operation_id: u64,
        pending_operations: BTreeMap<u64, PendingOperation>,
        delivery_ledger: delivery::DeliveryLedger,
        issuance: oid4vci::State,
        seen_nonces: Vec<u64>,
        pay_seen_nonces: Vec<u64>,
        iss_seen_c_nonces: Vec<u64>,
        qes_seen_nonces: Vec<u64>,
        device_public_key: Vec<u8>,
        wua: Option<wua::WalletUnitAttestation>,
        issuer_id_current: String,
        issuer_chain_current: Vec<Vec<u8>>,
        issuer_assertion_current: String,
        issuer_candidates_current: Vec<CredentialIssuerEvidence>,
        pending_verified_credential: Option<AuthenticatedCredential>,
        last_credential_ingestion_error: Option<CredentialIngestionError>,
        status_keys: Vec<String>,
        pending_status_references: Vec<StatusReference>,
        log: txnlog::TransactionLog,
        audit_log_available: bool,
        pay_summary: Option<txnlog::PaymentSummary>,
        pay_consent_hash: [u8; 32],
        qes: qes::QesState,
        qes_consent_hash: [u8; 32],
        w2w: w2w::State,
        w2w_credential: Option<Vec<u8>>,
        trust_sequence: Option<u64>,
    }

    fn snapshot(core: &Core) -> CoreSnapshot {
        CoreSnapshot {
            wallet_client_id: core.config.wallet_client_id.clone(),
            device_key_ref: core.config.device_key_ref.clone(),
            vp: core.vp.clone(),
            credentials: core.credentials.clone(),
            mdoc_holdings: core.mdoc_holdings.clone(),
            session_present: core.session.is_some(),
            pending_rp_present: core.pending_rp_provenance.is_some(),
            now_epoch: core.now_epoch,
            payment: core.payment.clone(),
            active: core.active,
            next_operation_id: core.next_operation_id,
            pending_operations: core.pending_operations.clone(),
            delivery_ledger: core.delivery_ledger.clone(),
            issuance: core.issuance.clone(),
            seen_nonces: core.seen_nonces.clone(),
            pay_seen_nonces: core.pay_seen_nonces.clone(),
            iss_seen_c_nonces: core.iss_seen_c_nonces.clone(),
            qes_seen_nonces: core.qes_seen_nonces.clone(),
            device_public_key: core.device_public_key.clone(),
            wua: core.wua.clone(),
            issuer_id_current: core.issuer_id_current.clone(),
            issuer_chain_current: core.issuer_cert_chain_current.clone(),
            issuer_assertion_current: core.issuer_id_assertion_current.clone(),
            issuer_candidates_current: core.issuer_candidates_current.clone(),
            pending_verified_credential: core.pending_verified_credential.clone(),
            last_credential_ingestion_error: core.last_credential_ingestion_error.clone(),
            status_keys: core.status_lists.keys().cloned().collect(),
            pending_status_references: core.pending_status_references.clone(),
            log: core.log.clone(),
            audit_log_available: core.audit_log_available,
            pay_summary: core.pay_summary.clone(),
            pay_consent_hash: core.pay_consent_hash,
            qes: core.qes.clone(),
            qes_consent_hash: core.qes_consent_hash,
            w2w: core.w2w.clone(),
            w2w_credential: core.w2w_credential.clone(),
            trust_sequence: core.trust_store.sequence_number(),
        }
    }

    fn atomic_error(core: &mut Core, bytes: &[u8], generation: u64) -> DurableCheckpointError {
        let before = snapshot(core);
        let error = core
            .restore_durable_checkpoint(bytes, generation)
            .expect_err("hostile checkpoint must fail");
        assert_eq!(snapshot(core), before, "rejection must be fully atomic");
        error
    }

    fn signed_pid_with_expiry(
        device_public_key: &[u8],
        issued_at: i64,
        expires_at: i64,
    ) -> Vec<u8> {
        signed_pid_variant(device_public_key, issued_at, expires_at, 0)
    }

    fn signed_pid_variant(
        device_public_key: &[u8],
        issued_at: i64,
        expires_at: i64,
        variant: usize,
    ) -> Vec<u8> {
        let issuer = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).unwrap();
        let claims = [
            ("family_name", json!("Andersson")),
            ("given_name", json!("Astrid")),
            ("birthdate", json!("1988-04-12")),
        ];
        let mut disclosures = Vec::new();
        let mut digests = Vec::new();
        for (index, (name, value)) in claims.into_iter().enumerate() {
            let disclosure = Base64UrlUnpadded::encode_string(
                serde_json::to_string(&json!([format!("s{variant}-{index}"), name, value]))
                    .unwrap()
                    .as_bytes(),
            );
            digests.push(json!(Base64UrlUnpadded::encode_string(
                &AwsLc.sha256(disclosure.as_bytes())
            )));
            disclosures.push(disclosure);
        }
        let header = Base64UrlUnpadded::encode_string(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
        let payload = Base64UrlUnpadded::encode_string(
            serde_json::to_string(&json!({
                "iss": "https://issuer.example",
                "iat": issued_at,
                "exp": expires_at,
                "vct": "urn:eudi:pid:1",
                "_sd_alg": "sha-256",
                "_sd": digests,
                "cnf": { "jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": Base64UrlUnpadded::encode_string(&device_public_key[1..33]),
                    "y": Base64UrlUnpadded::encode_string(&device_public_key[33..65]),
                }},
            }))
            .unwrap()
            .as_bytes(),
        );
        let signing_input = format!("{header}.{payload}");
        let signature = issuer
            .sign(
                &KeyRef("issuer".into()),
                Alg::Es256,
                signing_input.as_bytes(),
            )
            .unwrap();
        format!(
            "{signing_input}.{}~{}~",
            Base64UrlUnpadded::encode_string(&signature),
            disclosures.join("~")
        )
        .into_bytes()
    }

    #[test]
    fn projected_credential_admission_accounts_for_replacement_promotion_and_evidence() {
        let scenario = DemoWallet::new().issuance_scenario();
        let mut core = configured_core(&scenario, "wallet.example", "device-key");
        let first_raw = signed_pid_variant(
            &scenario.device_public_key,
            scenario.epoch,
            scenario.epoch + 10_000,
            1,
        );
        let second_raw = signed_pid_variant(
            &scenario.device_public_key,
            scenario.epoch,
            scenario.epoch + 10_000,
            2,
        );
        let first = core
            .authenticate_received_credential(
                oid4vci::CredentialFormat::DcSdJwt,
                &first_raw,
                &scenario.issuer_cert_chain,
                &scenario.issuer_id,
            )
            .unwrap();
        let second = core
            .authenticate_received_credential(
                oid4vci::CredentialFormat::DcSdJwt,
                &second_raw,
                &scenario.issuer_cert_chain,
                &scenario.issuer_id,
            )
            .unwrap();
        let VerifiedCredential::SdJwt { holding, .. } = &first.credential else {
            panic!("PID test credential must be SD-JWT");
        };
        core.load_unverified_credential_for_testing(holding.clone());
        let fixture_checkpoint = core.export_durable_checkpoint(21).unwrap();
        let fixture_log = core.log.clone();

        assert_eq!(
            ensure_credential_storage_admission_with_limits(
                &core,
                &first,
                0,
                MAX_CREDENTIAL_EVIDENCE_BYTES,
            ),
            Err(CredentialIngestionError::CredentialStoreFull),
            "promoting a fixture consumes one authenticated slot"
        );
        assert_eq!(
            core.export_durable_checkpoint(21).unwrap(),
            fixture_checkpoint
        );
        assert_eq!(core.log, fixture_log);

        core.store_verified_credential(first.clone()).unwrap();
        let admitted_checkpoint = core.export_durable_checkpoint(22).unwrap();
        let admitted_log = core.log.clone();
        let first_evidence = record_evidence_bytes(&first.provenance).unwrap();
        let second_evidence = record_evidence_bytes(&second.provenance).unwrap();
        let combined = first_evidence.checked_add(second_evidence).unwrap();

        assert!(
            ensure_credential_storage_admission_with_limits(&core, &second, 2, combined,).is_ok()
        );
        assert_eq!(
            ensure_credential_storage_admission_with_limits(&core, &second, 2, combined - 1,),
            Err(CredentialIngestionError::CredentialEvidenceLimitExceeded),
            "aggregate evidence is checked before appending a distinct credential"
        );

        let mut larger_replacement = first;
        larger_replacement.provenance.raw_credential.push(b' ');
        let replacement_evidence = record_evidence_bytes(&larger_replacement.provenance).unwrap();
        assert!(ensure_credential_storage_admission_with_limits(
            &core,
            &larger_replacement,
            1,
            replacement_evidence,
        )
        .is_ok());
        assert_eq!(
            ensure_credential_storage_admission_with_limits(
                &core,
                &larger_replacement,
                1,
                replacement_evidence - 1,
            ),
            Err(CredentialIngestionError::CredentialEvidenceLimitExceeded),
            "replacement subtracts old evidence and admits only the projected new total"
        );
        assert_eq!(
            core.export_durable_checkpoint(22).unwrap(),
            admitted_checkpoint
        );
        assert_eq!(core.log, admitted_log);
    }

    #[test]
    fn count_capacity_rejects_direct_and_issuance_storage_without_wedging_checkpoint() {
        let scenario = DemoWallet::new().issuance_scenario();
        let mut core = configured_core(&scenario, "wallet.example", "device-key");
        let mut first_raw = None;
        for variant in 0..MAX_CREDENTIALS {
            let raw = signed_pid_variant(
                &scenario.device_public_key,
                scenario.epoch,
                scenario.epoch + 10_000,
                100 + variant,
            );
            if first_raw.is_none() {
                first_raw = Some(raw.clone());
            }
            core.ingest_credential(
                "dc+sd-jwt",
                &raw,
                &scenario.issuer_cert_chain,
                &scenario.issuer_id,
            )
            .unwrap();
        }
        let checkpoint = core.export_durable_checkpoint(23).unwrap();
        let audit = core.log.clone();

        core.ingest_credential(
            "dc+sd-jwt",
            &first_raw.unwrap(),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        )
        .expect("replacing an authenticated holding does not consume another slot");
        assert_eq!(core.export_durable_checkpoint(23).unwrap(), checkpoint);

        let overflow_raw = signed_pid_variant(
            &scenario.device_public_key,
            scenario.epoch,
            scenario.epoch + 10_000,
            10_000,
        );
        assert_eq!(
            core.ingest_credential(
                "dc+sd-jwt",
                &overflow_raw,
                &scenario.issuer_cert_chain,
                &scenario.issuer_id,
            ),
            Err(CredentialIngestionError::CredentialStoreFull)
        );
        assert_eq!(core.export_durable_checkpoint(23).unwrap(), checkpoint);
        assert_eq!(core.log, audit);

        let overflow = core
            .authenticate_received_credential(
                oid4vci::CredentialFormat::DcSdJwt,
                &overflow_raw,
                &scenario.issuer_cert_chain,
                &scenario.issuer_id,
            )
            .unwrap();
        let VerifiedCredential::SdJwt { holding, .. } = &overflow.credential else {
            panic!("PID test credential must be SD-JWT");
        };
        core.load_unverified_credential_for_testing(holding.clone());
        assert_eq!(
            core.ingest_credential(
                "dc+sd-jwt",
                &overflow_raw,
                &scenario.issuer_cert_chain,
                &scenario.issuer_id,
            ),
            Err(CredentialIngestionError::CredentialStoreFull),
            "promoting a fixture must not bypass the combined authenticated count"
        );
        assert_eq!(core.export_durable_checkpoint(23).unwrap(), checkpoint);
        assert_eq!(core.log, audit);

        core.active = ActiveFlow::Issuance;
        core.issuance = oid4vci::State::RequestingCredential {
            format: oid4vci::CredentialFormat::DcSdJwt,
        };
        core.issuer_cert_chain_current = scenario.issuer_cert_chain.clone();
        core.issuer_id_current = scenario.issuer_id.clone();
        core.issuer_id_assertion_current = scenario.issuer_id.clone();
        core.issuer_candidates_current =
            core.resolve_credential_issuers(&core.issuer_cert_chain_current);
        core.issuer_trusted_current = true;
        let effects = core.handle_event(Event::CredentialReceived {
            format: "dc+sd-jwt".into(),
            bytes: overflow_raw,
        });
        assert_eq!(
            core.last_credential_ingestion_error(),
            Some(&CredentialIngestionError::CredentialStoreFull)
        );
        assert!(matches!(
            core.issuance,
            oid4vci::State::Aborted(oid4vci::AbortReason::CredentialInvalid)
        ));
        assert!(core.pending_verified_credential.is_none());
        assert!(matches!(
            effects.as_slice(),
            [
                Effect::Render {
                    screen: ScreenDescription::Error { code, .. }
                },
                Effect::Close
            ] if code == "credential_issuance_rejected"
        ));
        assert_eq!(core.active, ActiveFlow::None);
        assert_eq!(core.export_durable_checkpoint(23).unwrap(), checkpoint);
        assert_eq!(
            core.log, audit,
            "capacity rejection must not append issuance audit"
        );
    }

    #[test]
    fn round_trip_reauthenticates_state_and_resets_every_ephemeral_machine() {
        let demo = DemoWallet::new();
        let scenario = demo.issuance_scenario();
        let source = populated_core(&scenario);
        let bytes = source.export_durable_checkpoint(7).unwrap();

        let mut target = configured_core(&scenario, "wallet.example", "device-key");
        target.handle_event(Event::SetClock {
            epoch: scenario.epoch + 10,
        });
        advance_trust(&mut target, 2, i64::MAX);
        let retained_clock = target.now_epoch;
        let retained_wua = target.wua.clone();
        let retained_device_key = target.device_public_key.clone();
        let prior_delivery_namespace = *target.delivery_ledger.namespace();

        target.load_unverified_credential_for_testing(HeldCredential {
            issuer_jwt: "fixture".into(),
            disclosures_by_claim: BTreeMap::new(),
            status: None,
        });
        target.vp = State::Aborted(AbortReason::MalformedRequest);
        target.session = Some(SessionInfo::default());
        target.pending_rp_provenance = Some(RelyingPartyProvenance::default());
        target.payment = payment::State::Aborted(payment::AbortReason::MalformedRequest);
        target.active = ActiveFlow::Payment;
        target.next_operation_id = 42;
        target.pending_operations.insert(
            42,
            PendingOperation {
                flow: ActiveFlow::Payment,
                result: OperationResultKind::Persisted,
                authorization_hash: Some([4u8; 32]),
            },
        );
        target.issuance = oid4vci::State::Aborted(oid4vci::AbortReason::UnsupportedGrant);
        target.issuer_trusted_current = true;
        target.issuer_id_current = "stale issuer".into();
        target.issuer_cert_chain_current = vec![vec![1]];
        target.issuer_id_assertion_current = "stale assertion".into();
        target.last_credential_ingestion_error = Some(CredentialIngestionError::SignatureInvalid);
        target.pending_status_references.push(StatusReference {
            uri: "https://status.example/list".into(),
            index: 4,
        });
        target.pay_summary = Some(txnlog::PaymentSummary {
            payee: "stale".into(),
            amount_minor: 1,
            currency: "EUR".into(),
        });
        target.pay_consent_hash = [9u8; 32];
        target.qes = qes::QesState::Aborted(qes::AbortReason::MalformedRequest);
        target.qes_consent_hash = [10u8; 32];
        target.w2w = w2w::State::Accepted {
            credential: vec![1, 2, 3],
        };
        target.w2w_credential = Some(vec![1, 2, 3]);

        target.restore_durable_checkpoint(&bytes, 7).unwrap();

        assert_eq!(target.credentials, source.credentials);
        assert_eq!(target.mdoc_holdings, source.mdoc_holdings);
        assert_eq!(target.seen_nonces, vec![7, 91]);
        assert_eq!(target.pay_seen_nonces, vec![21]);
        assert_eq!(target.iss_seen_c_nonces, vec![30, 31]);
        assert_eq!(target.qes_seen_nonces, vec![41]);
        assert_eq!(target.log, source.log);
        assert!(matches!(target.vp, State::Idle));
        assert!(matches!(target.payment, payment::State::Idle));
        assert!(matches!(target.issuance, oid4vci::State::Idle));
        assert!(matches!(target.qes, qes::QesState::Idle));
        assert!(matches!(target.w2w, w2w::State::Idle));
        assert_eq!(target.active, ActiveFlow::None);
        assert!(target.session.is_none());
        assert!(target.pending_rp_provenance.is_none());
        assert!(target.pending_operations.is_empty());
        assert!(target.delivery_ledger.is_pristine());
        assert_ne!(
            *target.delivery_ledger.namespace(),
            prior_delivery_namespace
        );
        assert!((1..=(1u64 << 62)).contains(&target.next_operation_id));
        assert_ne!(target.next_operation_id, 42);
        assert!(target.status_lists.is_empty());
        assert!(target.pending_status_references.is_empty());
        assert!(target.issuer_id_current.is_empty());
        assert!(target.issuer_cert_chain_current.is_empty());
        assert!(target.issuer_id_assertion_current.is_empty());
        assert!(target.issuer_candidates_current.is_empty());
        assert!(target.pending_verified_credential.is_none());
        assert!(target.last_credential_ingestion_error.is_none());
        assert!(target.audit_log_available);
        assert!(target.pay_summary.is_none());
        assert_eq!(target.pay_consent_hash, [0u8; 32]);
        assert_eq!(target.qes_consent_hash, [0u8; 32]);
        assert!(target.w2w_credential.is_none());
        assert_eq!(target.now_epoch, retained_clock);
        assert_eq!(target.trust_store.sequence_number(), Some(2));
        assert_eq!(target.wua, retained_wua);
        assert_eq!(target.device_public_key, retained_device_key);

        let stale = target
            .handle_event_json(r#"{"type":"operationSucceeded","operationId":42}"#)
            .unwrap_err();
        assert!(stale.contains("stale or unknown operationId 42"));
    }

    #[test]
    fn history_mutation_events_fail_closed_during_flows_and_round_trip_durably() {
        let scenario = DemoWallet::new().issuance_scenario();
        let mut source = configured_core(&scenario, "wallet.example", "device-key");
        append_history(&mut source);
        let original = source.export_durable_checkpoint(30).unwrap();

        source.active = ActiveFlow::Presentation;
        for effects in [
            source.handle_event(Event::RedactTransaction { seq: 0 }),
            source.handle_event(Event::WipeTransactionLog),
        ] {
            assert!(matches!(
                effects.as_slice(),
                [Effect::Render {
                    screen: ScreenDescription::Error { code, .. }
                }] if code == "history_mutation_in_progress"
            ));
        }
        assert_eq!(source.active, ActiveFlow::Presentation);
        source.active = ActiveFlow::None;
        assert_eq!(
            source.export_durable_checkpoint(30).unwrap(),
            original,
            "history must not change while a protocol flow is active"
        );

        source.pending_operations.insert(
            42,
            PendingOperation {
                flow: ActiveFlow::Presentation,
                result: OperationResultKind::Persisted,
                authorization_hash: None,
            },
        );
        for effects in [
            source.handle_event(Event::RedactTransaction { seq: 0 }),
            source.handle_event(Event::WipeTransactionLog),
        ] {
            assert!(matches!(
                effects.as_slice(),
                [Effect::Render {
                    screen: ScreenDescription::Error { code, .. }
                }] if code == "history_mutation_in_progress"
            ));
        }
        assert!(source.pending_operations.contains_key(&42));
        source.pending_operations.clear();
        assert_eq!(
            source.export_durable_checkpoint(30).unwrap(),
            original,
            "history must not change while a native callback is pending"
        );

        assert!(source
            .handle_event(Event::RedactTransaction { seq: 0 })
            .is_empty());
        assert!(source.log.entries()[0].redacted);
        let redacted_checkpoint = source.export_durable_checkpoint(31).unwrap();

        let mut redacted_target = configured_core(&scenario, "wallet.example", "device-key");
        redacted_target
            .restore_durable_checkpoint(&redacted_checkpoint, 31)
            .unwrap();
        assert_eq!(redacted_target.log, source.log);
        assert!(redacted_target.log.entries()[0].redacted);
        assert!(redacted_target.log.verify_integrity(&AwsLc));

        source.audit_log_available = false;
        assert!(source.handle_event(Event::WipeTransactionLog).is_empty());
        assert!(source.audit_log_available);
        assert!(source.log.is_empty());
        let wiped_checkpoint = source.export_durable_checkpoint(32).unwrap();

        let mut wiped_target = configured_core(&scenario, "wallet.example", "device-key");
        wiped_target
            .restore_durable_checkpoint(&wiped_checkpoint, 32)
            .unwrap();
        assert!(wiped_target.log.is_empty());
        assert!(wiped_target.audit_log_available);
    }

    #[test]
    fn canonical_export_is_deterministic_and_excludes_fixtures_and_ephemeral_state() {
        let scenario = DemoWallet::new().issuance_scenario();
        let mut core = configured_core(&scenario, "wallet.example", "device-key");
        core.load_unverified_credential_for_testing(HeldCredential {
            issuer_jwt: "fixture-only".into(),
            disclosures_by_claim: BTreeMap::new(),
            status: None,
        });
        let first = core.export_durable_checkpoint(1).unwrap();
        core.vp = State::Aborted(AbortReason::MalformedRequest);
        core.active = ActiveFlow::Presentation;
        core.next_operation_id = 9;
        core.pending_operations.insert(
            8,
            PendingOperation {
                flow: ActiveFlow::Presentation,
                result: OperationResultKind::Persisted,
                authorization_hash: None,
            },
        );
        let second = core.export_durable_checkpoint(1).unwrap();
        assert_eq!(first, second);
        let decoded = decode_checkpoint(&first).unwrap();
        assert!(decoded.credentials.is_empty());
        assert_eq!(encode_checkpoint(&decoded).unwrap(), first);
        core.audit_log_available = false;
        assert_eq!(
            core.export_durable_checkpoint(1),
            Err(DurableCheckpointError::AuditLogUnavailable)
        );

        let mut latched_target = configured_core(&scenario, "wallet.example", "device-key");
        latched_target.audit_log_available = false;
        let mut corrupt = first.clone();
        corrupt.push(0);
        atomic_error(&mut latched_target, &corrupt, 1);
        assert!(!latched_target.audit_log_available);
        latched_target
            .restore_durable_checkpoint(&first, 1)
            .unwrap();
        assert!(
            !latched_target.audit_log_available,
            "valid import must not heal a live append fault"
        );

        let mut production = populated_core(&scenario);
        assert_eq!(
            production.export_durable_checkpoint(4).unwrap(),
            production.export_durable_checkpoint(4).unwrap()
        );
        production
            .credentials
            .push(production.credentials[0].clone());
        assert_eq!(
            production.export_durable_checkpoint(4),
            Err(DurableCheckpointError::DuplicateCredential)
        );
    }

    #[test]
    fn production_boundary_remains_canonical_v1_and_rejects_dormant_v2() {
        let checkpoint = empty_checkpoint();
        let v1 = encode_checkpoint(&checkpoint).unwrap();
        assert_eq!(
            v1[0], 0xa8,
            "production schema keeps the exact eight-field map"
        );
        let mut cursor = Cursor::new(&v1);
        cursor.exact_map(8).unwrap();
        cursor.key(1).unwrap();
        assert_eq!(cursor.borrowed_bytes(MAGIC.len()).unwrap(), MAGIC);
        cursor.key(2).unwrap();
        assert_eq!(cursor.uint().unwrap(), VERSION);
        assert_eq!(decode_checkpoint(&v1).unwrap(), checkpoint);
        assert_eq!(
            hex_bytes(&AwsLc.sha256(&v1)),
            "bb65949db0a7b9f7a33bd52e458e7d543eed681efc95be9b24fcf0517c549cfb"
        );

        let v2_checkpoint = dormant_checkpoint(fixed_delivery_ledger());
        let v2 = encode_checkpoint_v2(&v2_checkpoint).unwrap();
        assert_eq!(v2[0], 0xa9);
        assert_eq!(
            hex_bytes(&AwsLc.sha256(&v2)),
            "05a428e705ae64cd215f6710d916e2b4d4c279f8bf838725319f42a66a8a0c45"
        );
        assert_eq!(decode_checkpoint_v2(&v2).unwrap(), v2_checkpoint);
        assert_eq!(
            decode_checkpoint(&v2),
            Err(DurableCheckpointError::UnsupportedVersion(2))
        );

        let scenario = DemoWallet::new().issuance_scenario();
        let mut core = configured_core(&scenario, "wallet.example", "device-key");
        assert_eq!(
            atomic_error(&mut core, &v2, 1),
            DurableCheckpointError::UnsupportedVersion(2)
        );
        let exported = core.export_durable_checkpoint(1).unwrap();
        let mut exported_cursor = Cursor::new(&exported);
        exported_cursor.exact_map(8).unwrap();
        exported_cursor.key(1).unwrap();
        exported_cursor.borrowed_bytes(MAGIC.len()).unwrap();
        exported_cursor.key(2).unwrap();
        assert_eq!(exported_cursor.uint().unwrap(), VERSION);
    }

    #[test]
    fn dormant_ledger_codec_round_trips_all_states_without_enabling_idle_live_work() {
        let mut queued = fixed_delivery_ledger();
        enqueue_delivery(&mut queued, delivery::DeliveryKind::Http, b"queued", 8);

        let mut dispatching = fixed_delivery_ledger();
        enqueue_delivery(
            &mut dispatching,
            delivery::DeliveryKind::Http,
            b"dispatching",
            8,
        );
        let dispatching_correlation = dispatching.claim_oldest(7).unwrap().correlation().clone();

        let mut ambiguous = dispatching.clone();
        ambiguous.mark_ambiguous(&dispatching_correlation).unwrap();

        let mut ready = fixed_delivery_ledger();
        enqueue_delivery(&mut ready, delivery::DeliveryKind::Http, b"ready", 8);
        let ready_correlation = ready.claim_oldest(7).unwrap().correlation().clone();
        ready
            .record_result(&ready_correlation, b"result".to_vec())
            .unwrap();

        let mut terminal = ready.clone();
        terminal.consume_ready(&ready_correlation).unwrap();

        for ledger in [queued, dispatching, ambiguous, ready, terminal.clone()] {
            let bytes = encode_ledger_bytes(&ledger);
            assert_eq!(decode_ledger_bytes(&bytes).unwrap(), ledger);
            assert_eq!(
                encode_ledger_bytes(&decode_ledger_bytes(&bytes).unwrap()),
                bytes
            );
        }

        let terminal_checkpoint = dormant_checkpoint(terminal);
        let bytes = encode_checkpoint_v2(&terminal_checkpoint).unwrap();
        assert_eq!(decode_checkpoint_v2(&bytes).unwrap(), terminal_checkpoint);

        let mut live_checkpoint = dormant_checkpoint(fixed_delivery_ledger());
        enqueue_delivery(
            &mut live_checkpoint
                .continuation
                .as_mut()
                .unwrap()
                .delivery_ledger,
            delivery::DeliveryKind::Close,
            &[],
            0,
        );
        assert_eq!(
            encode_checkpoint_v2(&live_checkpoint),
            Err(DurableCheckpointError::IdleAggregateHasLiveDeliveries)
        );
        let hostile = encode_checkpoint_version(&live_checkpoint, DORMANT_VERSION_V2).unwrap();
        assert_eq!(
            decode_checkpoint_v2(&hostile),
            Err(DurableCheckpointError::IdleAggregateHasLiveDeliveries)
        );
    }

    #[test]
    fn dormant_continuation_exact_bound_and_one_over_fail_before_decode() {
        let maximal = delivery::DeliveryLedger::maximal_tombstone_ledger_for_testing();
        let continuation = Continuation {
            delivery_ledger: maximal,
        };
        let mut encoded = Encoder::new();
        encode_continuation(&mut encoded, &continuation).unwrap();
        assert_eq!(encoded.bytes.len(), MAX_DORMANT_CONTINUATION_BYTES);

        let checkpoint = dormant_checkpoint(continuation.delivery_ledger);
        let exact = encode_checkpoint_v2(&checkpoint).unwrap();
        assert_eq!(decode_checkpoint_v2(&exact).unwrap(), checkpoint);

        let mut hostile = encode_checkpoint(&empty_checkpoint()).unwrap();
        hostile[0] = 0xa9;
        let mut cursor = Cursor::new(&hostile);
        cursor.exact_map(9).unwrap();
        cursor.key(1).unwrap();
        cursor.borrowed_bytes(MAGIC.len()).unwrap();
        cursor.key(2).unwrap();
        let version_position = cursor.position;
        hostile[version_position] = DORMANT_VERSION_V2 as u8;
        hostile.push(9);
        cose::cbor::write_head(
            &mut hostile,
            2,
            u64::try_from(MAX_DORMANT_CONTINUATION_BYTES - 2).unwrap(),
        );
        hostile.extend(std::iter::repeat_n(0, MAX_DORMANT_CONTINUATION_BYTES - 2));
        assert!(matches!(
            decode_checkpoint_v2(&hostile),
            Err(DurableCheckpointError::ResourceLimit {
                resource: Resource::ContinuationBytes,
                max: MAX_DORMANT_CONTINUATION_BYTES,
                actual,
            }) if actual == MAX_DORMANT_CONTINUATION_BYTES + 1
        ));
    }

    #[test]
    fn ledger_decoder_rejects_aggregate_and_variant_bounds_before_reconstruction() {
        let mut over_aggregate = Encoder::new();
        over_aggregate.map(5).unwrap();
        over_aggregate.uint(1).unwrap();
        over_aggregate.bytes(&[0x5a; 32]).unwrap();
        over_aggregate.uint(2).unwrap();
        over_aggregate.uint(4).unwrap();
        over_aggregate.uint(3).unwrap();
        over_aggregate.array(3).unwrap();
        let exact_blob = vec![7; delivery::MAX_DELIVERY_BLOB_BYTES];
        encode_hostile_queued_delivery(&mut over_aggregate, 1, 5, 2, 1, &exact_blob, 0);
        encode_hostile_queued_delivery(&mut over_aggregate, 2, 5, 2, 1, &exact_blob, 0);
        encode_hostile_queued_delivery(&mut over_aggregate, 3, 5, 2, 1, &[], 1);
        over_aggregate.uint(4).unwrap();
        over_aggregate.array(0).unwrap();
        over_aggregate.uint(5).unwrap();
        over_aggregate.bytes(&[0; 32]).unwrap();
        assert!(matches!(
            decode_ledger_bytes(&over_aggregate.bytes),
            Err(DurableCheckpointError::ResourceLimit {
                resource: Resource::DeliveryReservedBytes,
                max: delivery::MAX_RESERVED_DELIVERY_BYTES,
                actual,
            }) if actual == delivery::MAX_RESERVED_DELIVERY_BYTES + 1
        ));

        for hostile in [
            encode_hostile_single_live_ledger(14, 2, 1),
            encode_hostile_single_live_ledger(5, 5, 1),
            encode_hostile_single_live_ledger(5, 2, 5),
            encode_hostile_tombstone_ledger(2),
        ] {
            assert_eq!(
                decode_ledger_bytes(&hostile),
                Err(DurableCheckpointError::Malformed)
            );
        }
    }

    #[test]
    fn dormant_ledger_rejects_duplicate_and_non_shortest_map_keys() {
        let valid = encode_ledger_bytes(&fixed_delivery_ledger());
        let mut cursor = Cursor::new(&valid);
        cursor.exact_map(5).unwrap();
        let key_one_position = cursor.position;
        cursor.key(1).unwrap();
        cursor.borrowed_bytes(32).unwrap();
        let key_two_position = cursor.position;
        assert_eq!(valid[key_one_position], 1);
        assert_eq!(valid[key_two_position], 2);

        let mut duplicate = valid.clone();
        duplicate[key_two_position] = 1;
        assert_eq!(
            decode_ledger_bytes(&duplicate),
            Err(DurableCheckpointError::NonCanonical)
        );

        let mut non_shortest = Vec::with_capacity(valid.len() + 1);
        non_shortest.extend_from_slice(&valid[..key_one_position]);
        non_shortest.extend_from_slice(&[0x18, 0x01]);
        non_shortest.extend_from_slice(&valid[key_one_position + 1..]);
        assert_eq!(
            decode_ledger_bytes(&non_shortest),
            Err(DurableCheckpointError::NonCanonical)
        );
    }

    #[test]
    fn non_pristine_dormant_ledger_can_neither_be_omitted_nor_wiped_by_v1() {
        let scenario = DemoWallet::new().issuance_scenario();
        let source = configured_core(&scenario, "wallet.example", "device-key");
        let v1 = source.export_durable_checkpoint(1).unwrap();
        let mut target = configured_core(&scenario, "wallet.example", "device-key");
        enqueue_delivery(
            &mut target.delivery_ledger,
            delivery::DeliveryKind::Close,
            &[],
            0,
        );
        let before = snapshot(&target);
        assert_eq!(
            target.export_durable_checkpoint(1),
            Err(DurableCheckpointError::DormantDeliveryLedgerNotPristine)
        );
        assert_eq!(
            target.restore_durable_checkpoint(&v1, 1),
            Err(DurableCheckpointError::DormantDeliveryLedgerNotPristine)
        );
        assert_eq!(snapshot(&target), before);
    }

    #[test]
    fn generation_context_clock_trust_and_wua_gates_are_atomic() {
        let demo = DemoWallet::new();
        let scenario = demo.issuance_scenario();
        let source = populated_core(&scenario);
        let bytes = source.export_durable_checkpoint(5).unwrap();

        let mut target = configured_core(&scenario, "wallet.example", "device-key");
        assert_eq!(
            atomic_error(&mut target, &bytes, 0),
            DurableCheckpointError::InvalidGeneration
        );
        assert!(matches!(
            atomic_error(&mut target, &bytes, 6),
            DurableCheckpointError::GenerationMismatch { .. }
        ));

        let mut wrong_client = configured_core(&scenario, "other-wallet", "device-key");
        assert_eq!(
            atomic_error(&mut wrong_client, &bytes, 5),
            DurableCheckpointError::ContextMismatch(ContextField::WalletClientId)
        );
        let mut wrong_ref = configured_core(&scenario, "wallet.example", "other-key-ref");
        assert_eq!(
            atomic_error(&mut wrong_ref, &bytes, 5),
            DurableCheckpointError::ContextMismatch(ContextField::DeviceKeyReference)
        );
        let other_scenario = DemoWallet::new().issuance_scenario();
        let mut wrong_key = configured_core(&other_scenario, "wallet.example", "device-key");
        assert_eq!(
            atomic_error(&mut wrong_key, &bytes, 5),
            DurableCheckpointError::ContextMismatch(ContextField::DevicePublicKey)
        );

        let mut rolled_clock = configured_core(&scenario, "wallet.example", "device-key");
        rolled_clock.now_epoch = scenario.epoch - 1;
        assert!(matches!(
            atomic_error(&mut rolled_clock, &bytes, 5),
            DurableCheckpointError::ClockRollback { .. }
        ));

        let mut higher_checkpoint = decode_checkpoint(&bytes).unwrap();
        higher_checkpoint.trust_sequence_high_water = 2;
        let higher_checkpoint = encode_checkpoint(&higher_checkpoint).unwrap();
        assert!(matches!(
            atomic_error(&mut target, &higher_checkpoint, 5),
            DurableCheckpointError::TrustListRollback { .. }
        ));

        let mut no_key = configured_core(&scenario, "wallet.example", "device-key");
        no_key.device_public_key.clear();
        assert_eq!(
            atomic_error(&mut no_key, &bytes, 5),
            DurableCheckpointError::DeviceKeyUnavailable
        );
        let mut invalid_key = configured_core(&scenario, "wallet.example", "device-key");
        invalid_key.device_public_key[0] = 0;
        invalid_key.wua = Some(wua::WalletUnitAttestation {
            device_public_key: invalid_key.device_public_key.clone(),
            assurance_level: wua::AssuranceLevel::High,
            valid_until: i64::MAX,
        });
        assert_eq!(
            atomic_error(&mut invalid_key, &bytes, 5),
            DurableCheckpointError::DeviceKeyInvalid
        );
        let mut no_trust = Core::new("wallet.example", "device-key");
        no_trust.now_epoch = scenario.epoch;
        no_trust.device_public_key = scenario.device_public_key.clone();
        no_trust.wua = source.wua.clone();
        assert_eq!(
            atomic_error(&mut no_trust, &bytes, 5),
            DurableCheckpointError::TrustListUnavailable
        );
        let mut no_wua = configured_core(&scenario, "wallet.example", "device-key");
        no_wua.wua = None;
        assert_eq!(
            atomic_error(&mut no_wua, &bytes, 5),
            DurableCheckpointError::WuaUnavailable
        );
        let mut low_wua = configured_core(&scenario, "wallet.example", "device-key");
        low_wua.wua = Some(wua::WalletUnitAttestation {
            device_public_key: low_wua.device_public_key.clone(),
            assurance_level: wua::AssuranceLevel::Low,
            valid_until: i64::MAX,
        });
        assert_eq!(
            atomic_error(&mut low_wua, &bytes, 5),
            DurableCheckpointError::WuaInvalid
        );
        let mut expired_trust = configured_core(&scenario, "wallet.example", "device-key");
        expired_trust.now_epoch = 4_000_000_001;
        assert_eq!(
            atomic_error(&mut expired_trust, &bytes, 5),
            DurableCheckpointError::TrustListExpired
        );
    }

    #[test]
    fn malformed_untrusted_expired_and_wrong_bound_credentials_leave_no_partial_restore() {
        let scenario = DemoWallet::new().issuance_scenario();
        let source = populated_core(&scenario);
        let bytes = source.export_durable_checkpoint(9).unwrap();

        let mut malformed = decode_checkpoint(&bytes).unwrap();
        malformed.credentials[1].raw[0] = b'!';
        let malformed = encode_checkpoint(&malformed).unwrap();
        let mut target = configured_core(&scenario, "wallet.example", "device-key");
        target.load_unverified_credential_for_testing(HeldCredential {
            issuer_jwt: "must-survive".into(),
            disclosures_by_claim: BTreeMap::new(),
            status: None,
        });
        assert!(matches!(
            atomic_error(&mut target, &malformed, 9),
            DurableCheckpointError::CredentialInvalid { index: 1, .. }
        ));

        let mut untrusted = configured_core(&scenario, "wallet.example", "device-key");
        untrusted
            .trust_store
            .update(TrustList {
                sequence_number: 2,
                valid_from: 0,
                valid_until: i64::MAX,
                anchors: Vec::new(),
            })
            .unwrap();
        assert!(matches!(
            atomic_error(&mut untrusted, &bytes, 9),
            DurableCheckpointError::CredentialInvalid {
                error: CredentialIngestionError::UntrustedIssuer,
                ..
            }
        ));

        let expiring_raw = signed_pid_with_expiry(
            &scenario.device_public_key,
            scenario.epoch,
            scenario.epoch + 100,
        );
        let mut expiring_source = configured_core(&scenario, "wallet.example", "device-key");
        expiring_source
            .ingest_credential(
                "dc+sd-jwt",
                &expiring_raw,
                &scenario.issuer_cert_chain,
                &scenario.issuer_id,
            )
            .unwrap();
        let expiring_bytes = expiring_source.export_durable_checkpoint(10).unwrap();
        let mut expired = configured_core(&scenario, "wallet.example", "device-key");
        expired.now_epoch = scenario.epoch + 101;
        assert!(matches!(
            atomic_error(&mut expired, &expiring_bytes, 10),
            DurableCheckpointError::CredentialInvalid {
                error: CredentialIngestionError::CredentialExpired,
                ..
            }
        ));

        let other = DemoWallet::new().issuance_scenario();
        let mut wrong_bound = configured_core(&scenario, "wallet.example", "device-key");
        wrong_bound.device_public_key = other.device_public_key.clone();
        wrong_bound.wua = Some(wua::WalletUnitAttestation {
            device_public_key: other.device_public_key,
            assurance_level: wua::AssuranceLevel::High,
            valid_until: i64::MAX,
        });
        let mut wrong_bound_checkpoint = decode_checkpoint(&bytes).unwrap();
        wrong_bound_checkpoint.context = current_context(&wrong_bound).unwrap();
        let wrong_bound_bytes = encode_checkpoint(&wrong_bound_checkpoint).unwrap();
        assert!(matches!(
            atomic_error(&mut wrong_bound, &wrong_bound_bytes, 9),
            DurableCheckpointError::CredentialInvalid {
                error: CredentialIngestionError::DeviceBindingMismatch,
                ..
            }
        ));
    }

    #[test]
    fn issuer_path_mismatch_after_one_valid_credential_is_atomic() {
        let scenario = DemoWallet::new().issuance_scenario();
        let source = populated_core(&scenario);
        let mut checkpoint =
            decode_checkpoint(&source.export_durable_checkpoint(11).unwrap()).unwrap();
        assert_eq!(checkpoint.credentials.len(), 2);
        let extra = checkpoint.credentials[1].certificate_path[0].clone();
        checkpoint.credentials[1].certificate_path.push(extra);
        let bytes = encode_checkpoint(&checkpoint).unwrap();

        let mut target = configured_core(&scenario, "wallet.example", "device-key");
        target.load_unverified_credential_for_testing(HeldCredential {
            issuer_jwt: "existing-fixture".into(),
            disclosures_by_claim: BTreeMap::new(),
            status: None,
        });
        assert_eq!(
            atomic_error(&mut target, &bytes, 11),
            DurableCheckpointError::CredentialEvidenceMismatch { index: 1 }
        );
    }

    #[test]
    fn replay_sets_are_sorted_unique_bounded_and_rejected_atomically_when_hostile() {
        let scenario = DemoWallet::new().issuance_scenario();
        let mut source = configured_core(&scenario, "wallet.example", "device-key");
        source.seen_nonces = vec![9, 1, 9, 4];
        let bytes = source.export_durable_checkpoint(12).unwrap();
        assert_eq!(
            decode_checkpoint(&bytes).unwrap().replay.presentation,
            vec![1, 4, 9]
        );

        source.seen_nonces = (0..MAX_REPLAY_VALUES as u64).rev().collect();
        let exact = source.export_durable_checkpoint(12).unwrap();
        assert_eq!(
            decode_checkpoint(&exact).unwrap().replay.presentation.len(),
            MAX_REPLAY_VALUES
        );
        source.seen_nonces.push(MAX_REPLAY_VALUES as u64);
        assert!(matches!(
            source.export_durable_checkpoint(12),
            Err(DurableCheckpointError::ResourceLimit {
                resource: Resource::ReplayValues,
                ..
            })
        ));

        let mut target = configured_core(&scenario, "wallet.example", "device-key");
        let mut duplicate = decode_checkpoint(&bytes).unwrap();
        duplicate.replay.presentation = vec![1, 1];
        assert_eq!(
            atomic_error(&mut target, &encode_checkpoint(&duplicate).unwrap(), 12),
            DurableCheckpointError::NonCanonical
        );
        let mut unordered = decode_checkpoint(&bytes).unwrap();
        unordered.replay.presentation = vec![2, 1];
        assert_eq!(
            atomic_error(&mut target, &encode_checkpoint(&unordered).unwrap(), 12),
            DurableCheckpointError::NonCanonical
        );
        let mut over = decode_checkpoint(&bytes).unwrap();
        over.replay.presentation = (0..=MAX_REPLAY_VALUES as u64).collect();
        assert!(matches!(
            atomic_error(&mut target, &encode_checkpoint(&over).unwrap(), 12),
            DurableCheckpointError::ResourceLimit {
                resource: Resource::ContainerItems,
                ..
            }
        ));
    }

    #[test]
    fn full_replay_sets_reject_each_valid_flow_before_mutation_and_remain_exportable() {
        let wallet = DemoWallet::new();
        let scenario = wallet.issuance_scenario();
        let exact_values: Vec<u64> = (0..MAX_REPLAY_VALUES as u64).collect();

        let mut presentation_core = configured_core(&scenario, "wallet.example", "device-key");
        presentation_core.seen_nonces = exact_values.clone();
        let before = presentation_core.export_durable_checkpoint(1).unwrap();
        let effects = presentation_core.handle_event(Event::AuthorizationRequestReceived {
            request: wallet.presentation_request(u64::MAX),
        });
        assert_replay_capacity_effects(&effects);
        assert_eq!(presentation_core.seen_nonces, exact_values);
        assert_eq!(
            presentation_core.export_durable_checkpoint(1).unwrap(),
            before
        );
        assert!(matches!(presentation_core.vp, State::Idle));

        let mut payment_core = configured_core(&scenario, "wallet.example", "device-key");
        payment_core.pay_seen_nonces = exact_values.clone();
        let before = payment_core.export_durable_checkpoint(1).unwrap();
        let effects = payment_core.handle_event(Event::PaymentAuthorizationRequestReceived {
            request: wallet.payment_request(u64::MAX),
        });
        assert_replay_capacity_effects(&effects);
        assert_eq!(payment_core.pay_seen_nonces, exact_values);
        assert_eq!(payment_core.export_durable_checkpoint(1).unwrap(), before);
        assert!(matches!(payment_core.payment, payment::State::Idle));

        let mut issuance_core = configured_core(&scenario, "wallet.example", "device-key");
        issuance_core.iss_seen_c_nonces = exact_values.clone();
        let before = issuance_core.export_durable_checkpoint(1).unwrap();
        let effects = issuance_core.handle_event(Event::CredentialOfferReceived {
            offer: scenario.offer.clone(),
            issuer_cert_chain: scenario.issuer_cert_chain.clone(),
            issuer_id: scenario.issuer_id.clone(),
        });
        assert_replay_capacity_effects(&effects);
        assert_eq!(issuance_core.iss_seen_c_nonces, exact_values);
        assert_eq!(issuance_core.export_durable_checkpoint(1).unwrap(), before);
        assert!(matches!(issuance_core.issuance, oid4vci::State::Idle));

        let mut qes_core = configured_core(&scenario, "wallet.example", "device-key");
        qes_core.qes_seen_nonces = exact_values.clone();
        let before = qes_core.export_durable_checkpoint(1).unwrap();
        let effects = qes_core.handle_event(Event::QesSignRequestReceived {
            request: br#"{"document_name":"Contract.pdf","document_hash_hex":"deadbeef","qtsp_id":"qtsp.example","nonce":18446744073709551615}"#.to_vec(),
        });
        assert_replay_capacity_effects(&effects);
        assert_eq!(qes_core.qes_seen_nonces, exact_values);
        assert_eq!(qes_core.export_durable_checkpoint(1).unwrap(), before);
        assert!(matches!(qes_core.qes, qes::QesState::Idle));
    }

    #[test]
    fn final_available_replay_slot_is_admitted_and_exports_at_the_exact_count() {
        let scenario = DemoWallet::new().issuance_scenario();
        let mut core = configured_core(&scenario, "wallet.example", "device-key");
        core.qes_seen_nonces = (0..(MAX_REPLAY_VALUES as u64 - 1)).collect();

        let effects = core.handle_event(Event::QesSignRequestReceived {
            request: br#"{"document_name":"Contract.pdf","document_hash_hex":"deadbeef","qtsp_id":"qtsp.example","nonce":18446744073709551615}"#.to_vec(),
        });

        assert!(effects.iter().any(|effect| matches!(
            effect,
            Effect::Render {
                screen: ScreenDescription::SignConfirmation(_)
            }
        )));
        assert_eq!(core.qes_seen_nonces.len(), MAX_REPLAY_VALUES);
        assert!(core.qes_seen_nonces.contains(&u64::MAX));
        let checkpoint = core.export_durable_checkpoint(2).unwrap();
        assert_eq!(
            decode_checkpoint(&checkpoint).unwrap().replay.qes.len(),
            MAX_REPLAY_VALUES
        );
    }

    #[test]
    fn reservation_rejection_resets_the_active_flow_and_duplicate_output_never_pushes() {
        let wallet = DemoWallet::new();
        let scenario = wallet.issuance_scenario();
        let mut core = configured_core(&scenario, "wallet.example", "device-key");
        core.iss_seen_c_nonces = (0..(MAX_REPLAY_VALUES as u64 - 1)).collect();
        let started = core.handle_event(Event::CredentialOfferReceived {
            offer: scenario.offer.clone(),
            issuer_cert_chain: scenario.issuer_cert_chain.clone(),
            issuer_id: scenario.issuer_id.clone(),
        });
        assert!(started
            .iter()
            .any(|effect| matches!(effect, Effect::RequestToken)));
        assert_eq!(core.active, ActiveFlow::Issuance);
        assert!(matches!(
            core.issuance,
            oid4vci::State::RequestingToken { .. }
        ));

        core.iss_seen_c_nonces.push(MAX_REPLAY_VALUES as u64 - 1);
        core.pending_operations.insert(
            7,
            PendingOperation {
                flow: ActiveFlow::Issuance,
                result: OperationResultKind::Token,
                authorization_hash: None,
            },
        );
        let before = core.export_durable_checkpoint(3).unwrap();
        let rejected = core.handle_event(Event::TokenReceived {
            bound: true,
            c_nonce: u64::MAX,
        });
        assert_replay_capacity_effects(&rejected);
        assert_eq!(core.active, ActiveFlow::None);
        assert!(matches!(core.issuance, oid4vci::State::Idle));
        assert!(!core.pending_operations.contains_key(&7));
        assert_eq!(core.export_durable_checkpoint(3).unwrap(), before);

        let mut presentation = configured_core(&scenario, "wallet.example", "device-key");
        presentation.active = ActiveFlow::Presentation;
        presentation.seen_nonces = vec![42];
        let before = presentation.export_durable_checkpoint(4).unwrap();
        let rejected = presentation.translate(oid4vp::Output::PersistNonce(42));
        assert_replay_capacity_effects(&rejected);
        assert_eq!(presentation.seen_nonces, vec![42]);
        assert_eq!(presentation.active, ActiveFlow::None);
        assert!(matches!(presentation.vp, State::Idle));
        assert_eq!(presentation.export_durable_checkpoint(4).unwrap(), before);
    }

    #[test]
    fn transaction_head_chain_and_canonical_tombstones_are_checked_atomically() {
        let scenario = DemoWallet::new().issuance_scenario();
        let source = populated_core(&scenario);
        let bytes = source.export_durable_checkpoint(13).unwrap();
        let checkpoint = decode_checkpoint(&bytes).unwrap();
        assert!(checkpoint.transaction_entries.last().unwrap().redacted);

        let mut target = configured_core(&scenario, "wallet.example", "device-key");
        let mut bad_head = checkpoint.clone();
        bad_head.transaction_head[0] ^= 1;
        assert!(matches!(
            atomic_error(&mut target, &encode_checkpoint(&bad_head).unwrap(), 13),
            DurableCheckpointError::TransactionLog(txnlog::Error::AnchoredHeadMismatch { .. })
        ));
        let mut bad_link = checkpoint.clone();
        bad_link.transaction_entries[1].prev_hash[0] ^= 1;
        assert!(matches!(
            atomic_error(&mut target, &encode_checkpoint(&bad_link).unwrap(), 13),
            DurableCheckpointError::TransactionLog(txnlog::Error::PreviousHashMismatch { .. })
        ));
        let mut bad_tombstone = checkpoint;
        bad_tombstone.transaction_entries[1].counterparty = "forged".into();
        assert!(matches!(
            atomic_error(&mut target, &encode_checkpoint(&bad_tombstone).unwrap(), 13),
            DurableCheckpointError::TransactionLog(txnlog::Error::RedactedEntryNotCanonical { .. })
        ));

        let mut future_log = txnlog::TransactionLog::new();
        future_log
            .append(
                &AwsLc,
                txnlog::NewEntry {
                    epoch: source.now_epoch + 1,
                    kind: txnlog::Kind::Transfer,
                    counterparty: "peer.example".into(),
                    consent_hash: [3u8; 32],
                    claim_paths: Vec::new(),
                    outcome: txnlog::Outcome::Completed,
                    payment: None,
                },
            )
            .unwrap();
        let mut future = decode_checkpoint(&bytes).unwrap();
        future.transaction_entries = future_log.entries().to_vec();
        future.transaction_head = future_log.head();
        assert!(matches!(
            atomic_error(&mut target, &encode_checkpoint(&future).unwrap(), 13),
            DurableCheckpointError::AuditTimestampAfterClock { seq: 0, .. }
        ));

        let mut future_source = configured_core(&scenario, "wallet.example", "device-key");
        future_source.log = future_log;
        assert!(matches!(
            future_source.export_durable_checkpoint(13),
            Err(DurableCheckpointError::AuditTimestampAfterClock { seq: 0, .. })
        ));
    }

    #[test]
    fn canonical_parser_rejects_tamper_truncation_trailing_duplicates_and_future_schema() {
        let scenario = DemoWallet::new().issuance_scenario();
        let source = populated_core(&scenario);
        let valid = source.export_durable_checkpoint(14).unwrap();
        let mut target = configured_core(&scenario, "wallet.example", "device-key");

        for length in [0, 1, valid.len() / 2, valid.len() - 1] {
            atomic_error(&mut target, &valid[..length], 14);
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            atomic_error(&mut target, &trailing, 14),
            DurableCheckpointError::NonCanonical
        );
        let mut nonshortest_map = Vec::with_capacity(valid.len() + 1);
        nonshortest_map.extend_from_slice(&[0xb8, 8]);
        nonshortest_map.extend_from_slice(&valid[1..]);
        assert_eq!(
            atomic_error(&mut target, &nonshortest_map, 14),
            DurableCheckpointError::NonCanonical
        );

        let mut cursor = Cursor::new(&valid);
        cursor.exact_map(8).unwrap();
        cursor.key(1).unwrap();
        cursor.borrowed_bytes(MAGIC.len()).unwrap();
        let second_key = cursor.position;
        assert_eq!(valid[second_key], 2);
        let mut duplicate_key = valid.clone();
        duplicate_key[second_key] = 1;
        assert_eq!(
            atomic_error(&mut target, &duplicate_key, 14),
            DurableCheckpointError::NonCanonical
        );

        cursor.key(2).unwrap();
        let version_position = cursor.position;
        assert_eq!(valid[version_position], 1);
        let mut future = valid.clone();
        future[version_position] = 2;
        assert_eq!(
            atomic_error(&mut target, &future, 14),
            DurableCheckpointError::UnsupportedVersion(2)
        );
        let mut zero_version = valid.clone();
        zero_version[version_position] = 0;
        assert_eq!(
            atomic_error(&mut target, &zero_version, 14),
            DurableCheckpointError::UnsupportedVersion(0)
        );
        let mut nonshortest_version = valid.clone();
        nonshortest_version.splice(version_position..=version_position, [0x18, 0x01]);
        assert_eq!(
            atomic_error(&mut target, &nonshortest_version, 14),
            DurableCheckpointError::NonCanonical
        );

        let mut wrong_magic = valid.clone();
        let magic_position = wrong_magic
            .windows(MAGIC.len())
            .position(|window| window == MAGIC)
            .unwrap();
        wrong_magic[magic_position] ^= 1;
        assert_eq!(
            atomic_error(&mut target, &wrong_magic, 14),
            DurableCheckpointError::Malformed
        );
        let mut unknown_first_key = valid.clone();
        unknown_first_key[1] = 0;
        assert_eq!(
            atomic_error(&mut target, &unknown_first_key, 14),
            DurableCheckpointError::Malformed
        );

        let mut zero_generation = decode_checkpoint(&valid).unwrap();
        zero_generation.generation = 0;
        assert_eq!(
            atomic_error(
                &mut target,
                &encode_checkpoint(&zero_generation).unwrap(),
                14
            ),
            DurableCheckpointError::InvalidGeneration
        );
    }

    #[test]
    fn hostile_declared_lengths_and_depth_fail_before_allocation_and_are_atomic() {
        assert_eq!(MAX_CHECKPOINT_BYTES, 33_554_312);
        let scenario = DemoWallet::new().issuance_scenario();
        let mut target = configured_core(&scenario, "wallet.example", "device-key");
        let cases = [
            (4, MAX_CONTAINER_ITEMS as u64 + 1),
            (5, MAX_MAP_PAIRS as u64 + 1),
            (2, MAX_RAW_CREDENTIAL_BYTES as u64 + 1),
            (3, MAX_RAW_CREDENTIAL_BYTES as u64 + 1),
        ];
        for (major, declared) in cases {
            let mut hostile = Vec::new();
            cose::cbor::write_head(&mut hostile, major, declared);
            assert!(matches!(
                atomic_error(&mut target, &hostile, 1),
                DurableCheckpointError::ResourceLimit { .. }
            ));
        }
        let mut absent_body = Vec::new();
        cose::cbor::write_head(&mut absent_body, 2, 8);
        assert_eq!(
            atomic_error(&mut target, &absent_body, 1),
            DurableCheckpointError::Truncated
        );
        let mut too_deep = vec![0xc0; MAX_SCHEMA_DEPTH + 1];
        too_deep.push(0);
        assert!(matches!(
            atomic_error(&mut target, &too_deep, 1),
            DurableCheckpointError::ResourceLimit {
                resource: Resource::StructuralDepth,
                ..
            }
        ));

        let exact_input = vec![0u8; MAX_CHECKPOINT_BYTES];
        assert!(!matches!(
            atomic_error(&mut target, &exact_input, 1),
            DurableCheckpointError::ResourceLimit {
                resource: Resource::CheckpointBytes,
                ..
            }
        ));
        drop(exact_input);
        let one_over = vec![0u8; MAX_CHECKPOINT_BYTES + 1];
        assert!(matches!(
            atomic_error(&mut target, &one_over, 1),
            DurableCheckpointError::ResourceLimit {
                resource: Resource::CheckpointBytes,
                ..
            }
        ));
    }

    #[test]
    fn credential_component_boundaries_and_near_budget_encoding_round_trip() {
        let mut checkpoint = empty_checkpoint();
        checkpoint.credentials = (0..MAX_CREDENTIALS)
            .map(|index| record(index as u8, 1))
            .collect();
        let exact_count = encode_checkpoint(&checkpoint).unwrap();
        assert_eq!(
            decode_checkpoint(&exact_count).unwrap().credentials.len(),
            MAX_CREDENTIALS
        );
        checkpoint.credentials.push(record(128, 1));
        assert!(matches!(
            decode_checkpoint(&encode_checkpoint(&checkpoint).unwrap()),
            Err(DurableCheckpointError::ResourceLimit {
                resource: Resource::ContainerItems,
                ..
            })
        ));

        let mut identity = empty_checkpoint();
        let mut identity_record = record(1, 1);
        identity_record.issuer_identity = "i".repeat(MAX_ISSUER_ID_BYTES);
        identity.credentials.push(identity_record.clone());
        assert!(decode_checkpoint(&encode_checkpoint(&identity).unwrap()).is_ok());
        identity_record.issuer_identity.push('i');
        identity.credentials = vec![identity_record];
        assert!(matches!(
            decode_checkpoint(&encode_checkpoint(&identity).unwrap()),
            Err(DurableCheckpointError::ResourceLimit { .. })
        ));

        let mut certificate = empty_checkpoint();
        let mut certificate_record = record(1, 1);
        certificate_record.certificate_path = vec![vec![1; MAX_CERTIFICATE_BYTES]];
        certificate.credentials.push(certificate_record.clone());
        assert!(decode_checkpoint(&encode_checkpoint(&certificate).unwrap()).is_ok());
        certificate_record.certificate_path[0].push(1);
        certificate.credentials = vec![certificate_record];
        assert!(matches!(
            decode_checkpoint(&encode_checkpoint(&certificate).unwrap()),
            Err(DurableCheckpointError::ResourceLimit { .. })
        ));

        let mut path = empty_checkpoint();
        let mut path_record = record(1, 1);
        path_record.certificate_path = vec![vec![1]; MAX_CERTIFICATES_PER_PATH];
        path.credentials.push(path_record.clone());
        assert!(decode_checkpoint(&encode_checkpoint(&path).unwrap()).is_ok());
        path_record.certificate_path.push(vec![1]);
        path.credentials = vec![path_record];
        assert!(matches!(
            decode_checkpoint(&encode_checkpoint(&path).unwrap()),
            Err(DurableCheckpointError::ResourceLimit { .. })
        ));

        // Exactly 24 MiB of credential evidence plus CBOR/context overhead must remain below the
        // 32 MiB envelope and survive the structural scanner and domain decoder unchanged.
        let mut near_budget = empty_checkpoint();
        let last_raw = MAX_RAW_CREDENTIAL_BYTES - 24;
        near_budget.credentials = (0..12)
            .map(|index| {
                record(
                    u8::try_from(index + 1).unwrap(),
                    if index == 11 {
                        last_raw
                    } else {
                        MAX_RAW_CREDENTIAL_BYTES
                    },
                )
            })
            .collect();
        let near_budget_bytes = encode_checkpoint(&near_budget).unwrap();
        assert!(near_budget_bytes.len() < MAX_CHECKPOINT_BYTES);
        assert_eq!(decode_checkpoint(&near_budget_bytes).unwrap(), near_budget);
    }

    #[test]
    fn credential_order_duplicates_and_transaction_cardinality_are_closed() {
        let mut checkpoint = empty_checkpoint();
        checkpoint.credentials = vec![record(1, 1), record(1, 1)];
        assert_eq!(
            decode_checkpoint(&encode_checkpoint(&checkpoint).unwrap()),
            Err(DurableCheckpointError::DuplicateCredential)
        );
        checkpoint.credentials = vec![record(2, 1), record(1, 1)];
        assert_eq!(
            decode_checkpoint(&encode_checkpoint(&checkpoint).unwrap()),
            Err(DurableCheckpointError::DuplicateCredential)
        );

        let dummy_entry = txnlog::Entry {
            seq: 0,
            epoch: 1,
            kind: txnlog::Kind::Transfer,
            counterparty: "p".into(),
            consent_hash: [1u8; 32],
            claim_paths: Vec::new(),
            outcome: txnlog::Outcome::Completed,
            payment: None,
            prev_hash: [0u8; 32],
            entry_hash: [1u8; 32],
            redacted: false,
        };
        checkpoint.credentials.clear();
        checkpoint.transaction_entries = vec![dummy_entry.clone(); txnlog::MAX_ENTRIES];
        assert_eq!(
            decode_checkpoint(&encode_checkpoint(&checkpoint).unwrap())
                .unwrap()
                .transaction_entries
                .len(),
            txnlog::MAX_ENTRIES
        );
        checkpoint.transaction_entries.push(dummy_entry);
        assert!(matches!(
            decode_checkpoint(&encode_checkpoint(&checkpoint).unwrap()),
            Err(DurableCheckpointError::ResourceLimit {
                resource: Resource::ContainerItems,
                ..
            })
        ));
    }
}
