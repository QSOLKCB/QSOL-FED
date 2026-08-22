//! Phase 0 release-claim boundary.
//!
//! These claims describe what the repository may say it has established at the
//! current bootstrap phase. They are deliberately compile-time constants rather
//! than runtime configuration so no peer, model, environment variable or API
//! request can promote an unimplemented capability into an established claim.

pub const PHASE0_GATE_ID: &str = "qsol-fed-phase0-claim-gate/1";

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
pub enum ReleaseClaim {
    ConstitutionalModel,
    MachineContracts,
    FailClosedAdmissionSkeleton,
    TestedConstitutionalCore,
    ProductionNetworking,
    CryptographicIdentity,
    RemoteExecution,
    InteroperableFederation,
}

/// Return whether a capability may currently be described as established.
///
/// This is intentionally not parameterized by configuration or peer input.
pub const fn is_established(claim: ReleaseClaim) -> bool {
    match claim {
        ReleaseClaim::ConstitutionalModel => PHASE0_CLAIMS.constitutional_model,
        ReleaseClaim::MachineContracts => PHASE0_CLAIMS.machine_contracts,
        ReleaseClaim::FailClosedAdmissionSkeleton => PHASE0_CLAIMS.fail_closed_admission_skeleton,
        ReleaseClaim::TestedConstitutionalCore => PHASE0_CLAIMS.tested_constitutional_core,
        ReleaseClaim::ProductionNetworking => PHASE0_CLAIMS.production_networking,
        ReleaseClaim::CryptographicIdentity => PHASE0_CLAIMS.cryptographic_identity,
        ReleaseClaim::RemoteExecution => PHASE0_CLAIMS.remote_execution,
        ReleaseClaim::InteroperableFederation => PHASE0_CLAIMS.interoperable_federation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase0_allows_only_bootstrap_claims() {
        for claim in [
            ReleaseClaim::ConstitutionalModel,
            ReleaseClaim::MachineContracts,
            ReleaseClaim::FailClosedAdmissionSkeleton,
            ReleaseClaim::TestedConstitutionalCore,
        ] {
            assert!(is_established(claim), "bootstrap claim unexpectedly disabled: {claim:?}");
        }
    }

    #[test]
    fn phase0_forbids_premature_capability_claims() {
        for claim in [
            ReleaseClaim::ProductionNetworking,
            ReleaseClaim::CryptographicIdentity,
            ReleaseClaim::RemoteExecution,
            ReleaseClaim::InteroperableFederation,
        ] {
            assert!(!is_established(claim), "premature capability claim enabled: {claim:?}");
        }
    }

    #[test]
    fn phase0_gate_is_not_runtime_configurable() {
        assert_eq!(PHASE0_GATE_ID, "qsol-fed-phase0-claim-gate/1");
        assert!(!PHASE0_CLAIMS.production_networking);
        assert!(!PHASE0_CLAIMS.cryptographic_identity);
        assert!(!PHASE0_CLAIMS.remote_execution);
        assert!(!PHASE0_CLAIMS.interoperable_federation);
    }
}
