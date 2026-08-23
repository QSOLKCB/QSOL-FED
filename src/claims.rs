//! Release-claim boundaries.
//!
//! `PHASE0_CLAIMS` is an immutable historical baseline. Phase 2 is preserved by
//! `claims/phase2.json`. `CURRENT_CLAIMS` is the current Phase 3 release surface.
//! None of these are runtime configuration.

pub const PHASE0_GATE_ID: &str = "qsol-fed-phase0-claim-gate/1";
pub const PHASE2_GATE_ID: &str = "qsol-fed-phase2-claim-gate/1";
pub const PHASE3_GATE_ID: &str = "qsol-fed-phase3-claim-gate/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase0Claims {
    pub constitutional_model: bool,
    pub machine_contracts: bool,
    pub fail_closed_admission_skeleton: bool,
    pub tested_constitutional_core: bool,
    pub production_networking: bool,
    pub cryptographic_identity: bool,
    pub remote_execution: bool,
    pub interoperable_federation: bool,
}

pub const PHASE0_CLAIMS: Phase0Claims = Phase0Claims {
    constitutional_model: true,
    machine_contracts: true,
    fail_closed_admission_skeleton: true,
    tested_constitutional_core: true,
    production_networking: false,
    cryptographic_identity: false,
    remote_execution: false,
    interoperable_federation: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentClaims {
    pub constitutional_model: bool,
    pub machine_contracts: bool,
    pub fail_closed_admission_skeleton: bool,
    pub tested_constitutional_core: bool,
    pub canonical_wire_contract: bool,
    pub cryptographic_identity: bool,
    pub signed_envelope_verification: bool,
    pub key_lifecycle: bool,
    pub durable_replay_protection: bool,
    pub reference_http_service: bool,
    pub opt_in_network_listener: bool,
    pub bounded_api_limits: bool,
    pub tls_deployment_profile: bool,
    pub secret_safe_audit_log: bool,
    pub api_fuzz_adversarial_suite: bool,
    pub production_networking: bool,
    pub remote_execution: bool,
    pub interoperable_federation: bool,
}

pub const CURRENT_CLAIMS: CurrentClaims = CurrentClaims {
    constitutional_model: true,
    machine_contracts: true,
    fail_closed_admission_skeleton: true,
    tested_constitutional_core: true,
    canonical_wire_contract: true,
    cryptographic_identity: true,
    signed_envelope_verification: true,
    key_lifecycle: true,
    durable_replay_protection: true,
    reference_http_service: true,
    opt_in_network_listener: true,
    bounded_api_limits: true,
    tls_deployment_profile: true,
    secret_safe_audit_log: true,
    api_fuzz_adversarial_suite: true,
    production_networking: false,
    remote_execution: false,
    interoperable_federation: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseClaim {
    ConstitutionalModel,
    MachineContracts,
    FailClosedAdmissionSkeleton,
    TestedConstitutionalCore,
    CanonicalWireContract,
    CryptographicIdentity,
    SignedEnvelopeVerification,
    KeyLifecycle,
    DurableReplayProtection,
    ReferenceHttpService,
    OptInNetworkListener,
    BoundedApiLimits,
    TlsDeploymentProfile,
    SecretSafeAuditLog,
    ApiFuzzAdversarialSuite,
    ProductionNetworking,
    RemoteExecution,
    InteroperableFederation,
}

/// Current release claim. No peer, model, environment variable, API request,
/// signature, trust decision, HTTP header, or listener option can change this
/// compile-time surface.
pub const fn is_established(claim: ReleaseClaim) -> bool {
    match claim {
        ReleaseClaim::ConstitutionalModel => CURRENT_CLAIMS.constitutional_model,
        ReleaseClaim::MachineContracts => CURRENT_CLAIMS.machine_contracts,
        ReleaseClaim::FailClosedAdmissionSkeleton => CURRENT_CLAIMS.fail_closed_admission_skeleton,
        ReleaseClaim::TestedConstitutionalCore => CURRENT_CLAIMS.tested_constitutional_core,
        ReleaseClaim::CanonicalWireContract => CURRENT_CLAIMS.canonical_wire_contract,
        ReleaseClaim::CryptographicIdentity => CURRENT_CLAIMS.cryptographic_identity,
        ReleaseClaim::SignedEnvelopeVerification => CURRENT_CLAIMS.signed_envelope_verification,
        ReleaseClaim::KeyLifecycle => CURRENT_CLAIMS.key_lifecycle,
        ReleaseClaim::DurableReplayProtection => CURRENT_CLAIMS.durable_replay_protection,
        ReleaseClaim::ReferenceHttpService => CURRENT_CLAIMS.reference_http_service,
        ReleaseClaim::OptInNetworkListener => CURRENT_CLAIMS.opt_in_network_listener,
        ReleaseClaim::BoundedApiLimits => CURRENT_CLAIMS.bounded_api_limits,
        ReleaseClaim::TlsDeploymentProfile => CURRENT_CLAIMS.tls_deployment_profile,
        ReleaseClaim::SecretSafeAuditLog => CURRENT_CLAIMS.secret_safe_audit_log,
        ReleaseClaim::ApiFuzzAdversarialSuite => CURRENT_CLAIMS.api_fuzz_adversarial_suite,
        ReleaseClaim::ProductionNetworking => CURRENT_CLAIMS.production_networking,
        ReleaseClaim::RemoteExecution => CURRENT_CLAIMS.remote_execution,
        ReleaseClaim::InteroperableFederation => CURRENT_CLAIMS.interoperable_federation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase0_historical_baseline_remains_immutable() {
        assert_eq!(PHASE0_GATE_ID, "qsol-fed-phase0-claim-gate/1");
        assert!(PHASE0_CLAIMS.constitutional_model);
        assert!(!PHASE0_CLAIMS.production_networking);
        assert!(!PHASE0_CLAIMS.cryptographic_identity);
        assert!(!PHASE0_CLAIMS.remote_execution);
        assert!(!PHASE0_CLAIMS.interoperable_federation);
    }

    #[test]
    fn phase3_promotes_only_reviewed_reference_api_capabilities() {
        for claim in [
            ReleaseClaim::ConstitutionalModel,
            ReleaseClaim::MachineContracts,
            ReleaseClaim::FailClosedAdmissionSkeleton,
            ReleaseClaim::TestedConstitutionalCore,
            ReleaseClaim::CanonicalWireContract,
            ReleaseClaim::CryptographicIdentity,
            ReleaseClaim::SignedEnvelopeVerification,
            ReleaseClaim::KeyLifecycle,
            ReleaseClaim::DurableReplayProtection,
            ReleaseClaim::ReferenceHttpService,
            ReleaseClaim::OptInNetworkListener,
            ReleaseClaim::BoundedApiLimits,
            ReleaseClaim::TlsDeploymentProfile,
            ReleaseClaim::SecretSafeAuditLog,
            ReleaseClaim::ApiFuzzAdversarialSuite,
        ] {
            assert!(is_established(claim), "reviewed Phase 3 claim unexpectedly disabled: {claim:?}");
        }
        for claim in [
            ReleaseClaim::ProductionNetworking,
            ReleaseClaim::RemoteExecution,
            ReleaseClaim::InteroperableFederation,
        ] {
            assert!(!is_established(claim), "premature production claim enabled: {claim:?}");
        }
    }

    #[test]
    fn current_claim_gate_is_not_runtime_configurable() {
        assert_eq!(PHASE3_GATE_ID, "qsol-fed-phase3-claim-gate/1");
        assert!(CURRENT_CLAIMS.reference_http_service);
        assert!(CURRENT_CLAIMS.opt_in_network_listener);
        assert!(!CURRENT_CLAIMS.production_networking);
        assert!(!CURRENT_CLAIMS.remote_execution);
        assert!(!CURRENT_CLAIMS.interoperable_federation);
    }
}
