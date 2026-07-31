//! Compile-time and runtime rollout controls for the experimental hybrid-PQ programme.
//!
//! Release builds default to [`HybridPqMode::Disabled`]. Remote configuration alone can never
//! enable post-quantum behavior: only a local operator action may raise the mode, while any
//! origin may lower it or activate the kill switch. `HybridRequired` never falls back silently;
//! telemetry is structurally restricted to profile/version, outcome class and latency bucket; and
//! versioned decoders make read/migrate behavior explicit.

use crate::use_cases::{HYBRID_EXPORT_VERSION, LEGACY_EXPORT_VERSION};
use crate::{HybridCryptoError, HybridErrorClass, HybridSignatureProfile};

/// True only when this build opted into the experimental hybrid-PQ surface.
pub const HYBRID_PQ_COMPILED: bool = cfg!(feature = "experimental-hybrid-pq");

/// Runtime rollout modes in strictly increasing capability order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HybridPqMode {
    /// No experimental operation may start. Release default.
    #[default]
    Disabled,
    /// Local test/experiment operations only; no external negotiation.
    ExperimentalLocalOnly,
    /// Allow-listed private-provider hybrid negotiation is permitted.
    PrivateProfileAllowed,
    /// Hybrid is mandatory; classical fallback is a hard downgrade failure.
    HybridRequired,
}

/// Provenance of a configuration request. Remote configuration can only restrict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigOrigin {
    LocalOperator,
    Remote,
}

/// Operations the policy authorizes. Opening existing artifacts is deliberately separate so the
/// kill switch and mode changes cannot strand already-created user data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridOperation {
    NewLocalExperiment,
    NewPrivateProfileSession,
    NewHybridRequiredSession,
    OpenExistingArtifact,
}

impl HybridOperation {
    const fn required_mode(self) -> HybridPqMode {
        match self {
            Self::NewLocalExperiment => HybridPqMode::ExperimentalLocalOnly,
            Self::NewPrivateProfileSession => HybridPqMode::PrivateProfileAllowed,
            Self::NewHybridRequiredSession => HybridPqMode::HybridRequired,
            Self::OpenExistingArtifact => HybridPqMode::Disabled,
        }
    }
}

/// Runtime rollout policy: configured mode plus a restrict-only kill switch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HybridRolloutPolicy {
    configured_mode: HybridPqMode,
    kill_switch: bool,
}

impl HybridRolloutPolicy {
    /// Raise or lower the mode. Remote origins may only lower the effective capability; a remote
    /// request above the current mode is rejected without changing state.
    pub fn request_mode(
        &mut self,
        origin: ConfigOrigin,
        mode: HybridPqMode,
    ) -> Result<(), HybridCryptoError> {
        if origin == ConfigOrigin::Remote && mode > self.configured_mode {
            return Err(HybridCryptoError::PolicyDenied);
        }
        self.configured_mode = mode;
        Ok(())
    }

    /// Any origin may activate the kill switch; only a local operator may clear it.
    pub fn activate_kill_switch(&mut self, _origin: ConfigOrigin) {
        self.kill_switch = true;
    }

    pub fn clear_kill_switch(&mut self, origin: ConfigOrigin) -> Result<(), HybridCryptoError> {
        if origin == ConfigOrigin::Remote {
            return Err(HybridCryptoError::PolicyDenied);
        }
        self.kill_switch = false;
        Ok(())
    }

    #[must_use]
    pub fn kill_switch_active(&self) -> bool {
        self.kill_switch
    }

    /// The mode new operations actually run under: `Disabled` unless the build compiled the
    /// experimental feature, regardless of any configured value.
    #[must_use]
    pub fn effective_mode(&self) -> HybridPqMode {
        if HYBRID_PQ_COMPILED {
            self.configured_mode
        } else {
            HybridPqMode::Disabled
        }
    }

    /// Authorize one operation. New operations require the compiled feature, a sufficient mode
    /// and an inactive kill switch. Opening an existing artifact is always permitted so user data
    /// stays accessible after rollback or kill.
    pub fn authorize(&self, operation: HybridOperation) -> Result<(), HybridCryptoError> {
        if operation == HybridOperation::OpenExistingArtifact {
            return Ok(());
        }
        if self.kill_switch {
            return Err(HybridCryptoError::PolicyDenied);
        }
        if self.effective_mode() < operation.required_mode() {
            return Err(HybridCryptoError::PolicyDenied);
        }
        Ok(())
    }

    /// Whether a session may proceed classically when hybrid is unavailable. Under
    /// `HybridRequired` this is a hard, typed downgrade failure — never a silent fallback — and
    /// the kill switch does not soften it into classical continuation.
    pub fn classical_fallback(&self) -> Result<ClassicalFallback, HybridCryptoError> {
        if self.effective_mode() == HybridPqMode::HybridRequired {
            return Err(HybridCryptoError::DowngradeDetected);
        }
        Ok(ClassicalFallback::ClassicalOnly)
    }
}

/// The only non-error fallback outcome: continue with certified classical behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassicalFallback {
    ClassicalOnly,
}

/// Explicit read/migrate plan for versioned wallet-export artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactReadPlan {
    /// Version 1: owned by the existing production reader.
    ReadLegacy,
    /// Version 2: read with the hybrid decoder.
    ReadHybrid,
}

/// Decide how to read a stored export version. Unknown versions are rejected explicitly instead
/// of being coerced to a known decoder. Reading requires no mode or kill-switch state.
pub fn plan_export_read(version: u16) -> Result<ArtifactReadPlan, HybridCryptoError> {
    match version {
        LEGACY_EXPORT_VERSION => Ok(ArtifactReadPlan::ReadLegacy),
        HYBRID_EXPORT_VERSION => Ok(ArtifactReadPlan::ReadHybrid),
        _ => Err(HybridCryptoError::UnsupportedProfile),
    }
}

/// Migrating a legacy artifact to the hybrid version is a new experimental operation: it needs an
/// explicit request and an authorizing policy, and it never runs implicitly during read.
pub fn plan_export_migration(
    policy: &HybridRolloutPolicy,
    from_version: u16,
) -> Result<(), HybridCryptoError> {
    if from_version != LEGACY_EXPORT_VERSION {
        return Err(HybridCryptoError::UnsupportedProfile);
    }
    policy.authorize(HybridOperation::NewLocalExperiment)
}

/// Coarse latency buckets — the only timing granularity telemetry may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LatencyBucket {
    Under10Ms,
    Under100Ms,
    Under1S,
    Over1S,
}

impl LatencyBucket {
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        match millis {
            0..=9 => Self::Under10Ms,
            10..=99 => Self::Under100Ms,
            100..=999 => Self::Under1S,
            _ => Self::Over1S,
        }
    }
}

/// Success or a bounded failure class. Failure detail beyond the class cannot be represented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TelemetryOutcome {
    Success,
    Failure(HybridErrorClass),
}

/// Telemetry record whose fields are all closed enums, a frozen profile identifier and an
/// artifact version. Keys, payloads, signatures and ciphertext bodies are unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridTelemetryRecord {
    profile: HybridSignatureProfile,
    artifact_version: u16,
    outcome: TelemetryOutcome,
    latency: LatencyBucket,
}

impl HybridTelemetryRecord {
    #[must_use]
    pub const fn new(
        profile: HybridSignatureProfile,
        artifact_version: u16,
        outcome: TelemetryOutcome,
        latency: LatencyBucket,
    ) -> Self {
        Self {
            profile,
            artifact_version,
            outcome,
            latency,
        }
    }

    /// Canonical low-cardinality emission format.
    #[must_use]
    pub fn emit(&self) -> String {
        let outcome = match self.outcome {
            TelemetryOutcome::Success => "success".to_string(),
            TelemetryOutcome::Failure(class) => format!("failure:{class:?}"),
        };
        format!(
            "profile={} version={} outcome={} latency={:?}",
            self.profile.id(),
            self.artifact_version,
            outcome,
            self.latency
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_default_is_disabled_with_inactive_kill_switch() {
        let policy = HybridRolloutPolicy::default();
        assert_eq!(policy.effective_mode(), HybridPqMode::Disabled);
        assert!(!policy.kill_switch_active());
        for operation in [
            HybridOperation::NewLocalExperiment,
            HybridOperation::NewPrivateProfileSession,
            HybridOperation::NewHybridRequiredSession,
        ] {
            assert_eq!(
                policy.authorize(operation),
                Err(HybridCryptoError::PolicyDenied)
            );
        }
        assert_eq!(
            policy.authorize(HybridOperation::OpenExistingArtifact),
            Ok(())
        );
    }

    #[test]
    fn remote_configuration_alone_cannot_enable_pq() {
        let mut policy = HybridRolloutPolicy::default();
        for mode in [
            HybridPqMode::ExperimentalLocalOnly,
            HybridPqMode::PrivateProfileAllowed,
            HybridPqMode::HybridRequired,
        ] {
            assert_eq!(
                policy.request_mode(ConfigOrigin::Remote, mode),
                Err(HybridCryptoError::PolicyDenied)
            );
            assert_eq!(policy.effective_mode(), HybridPqMode::Disabled);
        }
        // Remote may lower a locally raised mode but never raise it back.
        policy
            .request_mode(ConfigOrigin::LocalOperator, HybridPqMode::HybridRequired)
            .unwrap();
        policy
            .request_mode(ConfigOrigin::Remote, HybridPqMode::Disabled)
            .unwrap();
        assert_eq!(
            policy.request_mode(ConfigOrigin::Remote, HybridPqMode::ExperimentalLocalOnly),
            Err(HybridCryptoError::PolicyDenied)
        );
    }

    #[cfg(feature = "experimental-hybrid-pq")]
    #[test]
    fn local_operator_enablement_is_ordered_by_mode() {
        let mut policy = HybridRolloutPolicy::default();
        policy
            .request_mode(
                ConfigOrigin::LocalOperator,
                HybridPqMode::ExperimentalLocalOnly,
            )
            .unwrap();
        assert_eq!(
            policy.authorize(HybridOperation::NewLocalExperiment),
            Ok(())
        );
        assert_eq!(
            policy.authorize(HybridOperation::NewPrivateProfileSession),
            Err(HybridCryptoError::PolicyDenied)
        );
        policy
            .request_mode(ConfigOrigin::LocalOperator, HybridPqMode::HybridRequired)
            .unwrap();
        assert_eq!(
            policy.authorize(HybridOperation::NewHybridRequiredSession),
            Ok(())
        );
    }

    #[cfg(not(feature = "experimental-hybrid-pq"))]
    #[test]
    fn without_the_compile_time_feature_local_enablement_stays_disabled() {
        let mut policy = HybridRolloutPolicy::default();
        policy
            .request_mode(ConfigOrigin::LocalOperator, HybridPqMode::HybridRequired)
            .unwrap();
        assert_eq!(policy.effective_mode(), HybridPqMode::Disabled);
        assert_eq!(
            policy.authorize(HybridOperation::NewLocalExperiment),
            Err(HybridCryptoError::PolicyDenied)
        );
    }

    #[test]
    fn hybrid_required_never_falls_back_silently() {
        let mut policy = HybridRolloutPolicy::default();
        policy
            .request_mode(ConfigOrigin::LocalOperator, HybridPqMode::HybridRequired)
            .unwrap();
        if HYBRID_PQ_COMPILED {
            assert_eq!(
                policy.classical_fallback(),
                Err(HybridCryptoError::DowngradeDetected)
            );
            // The kill switch stops new hybrid operations without licensing classical fallback.
            policy.activate_kill_switch(ConfigOrigin::Remote);
            assert_eq!(
                policy.authorize(HybridOperation::NewHybridRequiredSession),
                Err(HybridCryptoError::PolicyDenied)
            );
            assert_eq!(
                policy.classical_fallback(),
                Err(HybridCryptoError::DowngradeDetected)
            );
        } else {
            // Feature-off builds have no hybrid surface: classical continuation is explicit.
            assert_eq!(
                policy.classical_fallback(),
                Ok(ClassicalFallback::ClassicalOnly)
            );
        }
    }

    #[test]
    fn kill_switch_stops_new_operations_but_preserves_artifact_access() {
        let mut policy = HybridRolloutPolicy::default();
        policy
            .request_mode(
                ConfigOrigin::LocalOperator,
                HybridPqMode::PrivateProfileAllowed,
            )
            .unwrap();
        policy.activate_kill_switch(ConfigOrigin::Remote);
        for operation in [
            HybridOperation::NewLocalExperiment,
            HybridOperation::NewPrivateProfileSession,
        ] {
            assert_eq!(
                policy.authorize(operation),
                Err(HybridCryptoError::PolicyDenied)
            );
        }
        assert_eq!(
            policy.authorize(HybridOperation::OpenExistingArtifact),
            Ok(())
        );
        assert_eq!(
            plan_export_read(HYBRID_EXPORT_VERSION),
            Ok(ArtifactReadPlan::ReadHybrid)
        );
        // Only a local operator can clear the kill switch.
        assert_eq!(
            policy.clear_kill_switch(ConfigOrigin::Remote),
            Err(HybridCryptoError::PolicyDenied)
        );
        policy
            .clear_kill_switch(ConfigOrigin::LocalOperator)
            .unwrap();
        assert!(!policy.kill_switch_active());
    }

    #[test]
    fn versioned_decoders_read_exact_versions_and_reject_unknown() {
        assert_eq!(
            plan_export_read(LEGACY_EXPORT_VERSION),
            Ok(ArtifactReadPlan::ReadLegacy)
        );
        assert_eq!(
            plan_export_read(HYBRID_EXPORT_VERSION),
            Ok(ArtifactReadPlan::ReadHybrid)
        );
        for unknown in [0, 3, u16::MAX] {
            assert_eq!(
                plan_export_read(unknown),
                Err(HybridCryptoError::UnsupportedProfile)
            );
        }
    }

    #[test]
    fn migration_is_explicit_and_policy_gated() {
        let mut policy = HybridRolloutPolicy::default();
        assert_eq!(
            plan_export_migration(&policy, LEGACY_EXPORT_VERSION),
            Err(HybridCryptoError::PolicyDenied)
        );
        assert_eq!(
            plan_export_migration(&policy, HYBRID_EXPORT_VERSION),
            Err(HybridCryptoError::UnsupportedProfile)
        );
        policy
            .request_mode(
                ConfigOrigin::LocalOperator,
                HybridPqMode::ExperimentalLocalOnly,
            )
            .unwrap();
        let migration = plan_export_migration(&policy, LEGACY_EXPORT_VERSION);
        if HYBRID_PQ_COMPILED {
            assert_eq!(migration, Ok(()));
        } else {
            assert_eq!(migration, Err(HybridCryptoError::PolicyDenied));
        }
    }

    #[test]
    fn telemetry_is_limited_to_profile_version_outcome_and_latency_bucket() {
        assert_eq!(LatencyBucket::from_millis(0), LatencyBucket::Under10Ms);
        assert_eq!(LatencyBucket::from_millis(10), LatencyBucket::Under100Ms);
        assert_eq!(LatencyBucket::from_millis(999), LatencyBucket::Under1S);
        assert_eq!(LatencyBucket::from_millis(60_000), LatencyBucket::Over1S);

        let success = HybridTelemetryRecord::new(
            HybridSignatureProfile::Es256MlDsa65V1,
            HYBRID_EXPORT_VERSION,
            TelemetryOutcome::Success,
            LatencyBucket::Under100Ms,
        );
        assert_eq!(
            success.emit(),
            "profile=euwallet-hybrid-pq-v1 version=2 outcome=success latency=Under100Ms"
        );
        let failure = HybridTelemetryRecord::new(
            HybridSignatureProfile::Es256MlDsa65V1,
            HYBRID_EXPORT_VERSION,
            TelemetryOutcome::Failure(HybridErrorClass::DowngradeDetected),
            LatencyBucket::Under10Ms,
        );
        assert_eq!(
            failure.emit(),
            "profile=euwallet-hybrid-pq-v1 version=2 outcome=failure:DowngradeDetected latency=Under10Ms"
        );
    }
}
