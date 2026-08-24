//! Release-claim boundaries.
//!
//! Phase 0, Phase 2, Phase 3, Phase 4, Phase 5A, Phase 5, Phase 5C, Phase 6,
//! and Phase 7 manifests remain historical baselines. `CURRENT_CLAIMS` is the
//! current Phase 8 transport-resilience surface. None of these values are runtime
//! configuration.

pub const PHASE0_GATE_ID: &str = "qsol-fed-phase0-claim-gate/1";
pub const PHASE2_GATE_ID: &str = "qsol-fed-phase2-claim-gate/1";
pub const PHASE3_GATE_ID: &str = "qsol-fed-phase3-claim-gate/1";
pub const PHASE4_GATE_ID: &str = "qsol-fed-phase4-claim-gate/1";
pub const PHASE5A_GATE_ID: &str = "qsol-fed-phase5a-holodeck-gate/1";
pub const PHASE5_GATE_ID: &str = "qsol-fed-phase5-adapter-gate/1";
pub const PHASE5C_GATE_ID: &str = "qsol-fed-phase5c-oracle-live-gate/1";
pub const PHASE6_GATE_ID: &str = "qsol-fed-phase6-sdk-gate/1";
pub const PHASE7_GATE_ID: &str = "qsol-fed-phase7-assembly-gate/1";
pub const PHASE8_GATE_ID: &str = "qsol-fed-phase8-transport-resilience-gate/1";

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
    pub foreign_object_store: bool,
    pub quarantine_namespace: bool,
    pub provenance_preserving_descendants: bool,
    pub durable_peer_registry: bool,
    pub separate_trust_registry: bool,
    pub expiring_capability_advertisements: bool,
    pub local_capability_policy: bool,
    pub partition_rejoin_control: bool,
    pub portable_federation_bundle: bool,
    pub offline_bundle_verification: bool,
    pub nexus_world_source_contract: bool,
    pub sandboxed_synthetic_world_kernel: bool,
    pub deterministic_holodeck_world_plan: bool,
    pub holodeck_computer_safeguards: bool,
    pub holodeck_teardown_receipts: bool,
    pub live_nexus_runtime_adapter: bool,
    pub nexus_council_report_adapter: bool,
    pub nexus_synthetic_actor_seam: bool,
    pub nexus_independent_redeliberation: bool,
    pub council_of_councils_reports_only: bool,
    pub oracle_evidence_membrane: bool,
    pub oracle_live_transport: bool,
    pub oracle_holodeck_synthetic_admission: bool,
    pub ark_offline_preservation_adapter: bool,
    pub minimal_protocol_sdk_contract: bool,
    pub rust_protocol_sdk: bool,
    pub python_protocol_sdk: bool,
    pub typescript_protocol_sdk: bool,
    pub language_neutral_sdk_conformance: bool,
    pub third_party_node_conformance: bool,
    pub three_implementation_sdk_interop: bool,
    pub institutional_integration_docs: bool,
    pub assembly_membership_separate_from_network: bool,
    pub assembly_proposal_lifecycle: bool,
    pub assembly_representation_model: bool,
    pub assembly_anti_sybil_contract: bool,
    pub deterministic_charter_gate: bool,
    pub assembly_member_local_sovereignty: bool,
    pub nexus_assembly_advisory_only: bool,
    pub assembly_fork_version_path: bool,
    pub assembly_governance_receipts: bool,
    pub bounded_transport_frame_contract: bool,
    pub websocket_transport_profile: bool,
    pub quic_transport_profile: bool,
    pub unix_local_ipc_profile: bool,
    pub offline_sneakernet_profile: bool,
    pub store_forward_profile: bool,
    pub nat_traversal_identity_binding: bool,
    pub multi_relay_provenance: bool,
    pub disaster_recovery_key_compromise_drills: bool,
    pub long_lived_archive_compatibility: bool,
    pub transport_resource_partition_drills: bool,
    pub holodeck_transport_independence: bool,
    pub host_level_sandbox: bool,
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
    foreign_object_store: true,
    quarantine_namespace: true,
    provenance_preserving_descendants: true,
    durable_peer_registry: true,
    separate_trust_registry: true,
    expiring_capability_advertisements: true,
    local_capability_policy: true,
    partition_rejoin_control: true,
    portable_federation_bundle: true,
    offline_bundle_verification: true,
    nexus_world_source_contract: true,
    sandboxed_synthetic_world_kernel: true,
    deterministic_holodeck_world_plan: true,
    holodeck_computer_safeguards: true,
    holodeck_teardown_receipts: true,
    live_nexus_runtime_adapter: true,
    nexus_council_report_adapter: true,
    nexus_synthetic_actor_seam: true,
    nexus_independent_redeliberation: true,
    council_of_councils_reports_only: true,
    oracle_evidence_membrane: true,
    oracle_live_transport: true,
    oracle_holodeck_synthetic_admission: false,
    ark_offline_preservation_adapter: true,
    minimal_protocol_sdk_contract: true,
    rust_protocol_sdk: true,
    python_protocol_sdk: true,
    typescript_protocol_sdk: true,
    language_neutral_sdk_conformance: true,
    third_party_node_conformance: true,
    three_implementation_sdk_interop: true,
    institutional_integration_docs: true,
    assembly_membership_separate_from_network: true,
    assembly_proposal_lifecycle: true,
    assembly_representation_model: true,
    assembly_anti_sybil_contract: true,
    deterministic_charter_gate: true,
    assembly_member_local_sovereignty: true,
    nexus_assembly_advisory_only: true,
    assembly_fork_version_path: true,
    assembly_governance_receipts: true,
    bounded_transport_frame_contract: true,
    websocket_transport_profile: true,
    quic_transport_profile: true,
    unix_local_ipc_profile: true,
    offline_sneakernet_profile: true,
    store_forward_profile: true,
    nat_traversal_identity_binding: true,
    multi_relay_provenance: true,
    disaster_recovery_key_compromise_drills: true,
    long_lived_archive_compatibility: true,
    transport_resource_partition_drills: true,
    holodeck_transport_independence: true,
    host_level_sandbox: false,
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
    ForeignObjectStore,
    QuarantineNamespace,
    ProvenancePreservingDescendants,
    DurablePeerRegistry,
    SeparateTrustRegistry,
    ExpiringCapabilityAdvertisements,
    LocalCapabilityPolicy,
    PartitionRejoinControl,
    PortableFederationBundle,
    OfflineBundleVerification,
    NexusWorldSourceContract,
    SandboxedSyntheticWorldKernel,
    DeterministicHolodeckWorldPlan,
    HolodeckComputerSafeguards,
    HolodeckTeardownReceipts,
    LiveNexusRuntimeAdapter,
    NexusCouncilReportAdapter,
    NexusSyntheticActorSeam,
    NexusIndependentRedeliberation,
    CouncilOfCouncilsReportsOnly,
    OracleEvidenceMembrane,
    OracleLiveTransport,
    OracleHolodeckSyntheticAdmission,
    ArkOfflinePreservationAdapter,
    MinimalProtocolSdkContract,
    RustProtocolSdk,
    PythonProtocolSdk,
    TypescriptProtocolSdk,
    LanguageNeutralSdkConformance,
    ThirdPartyNodeConformance,
    ThreeImplementationSdkInterop,
    InstitutionalIntegrationDocs,
    AssemblyMembershipSeparateFromNetwork,
    AssemblyProposalLifecycle,
    AssemblyRepresentationModel,
    AssemblyAntiSybilContract,
    DeterministicCharterGate,
    AssemblyMemberLocalSovereignty,
    NexusAssemblyAdvisoryOnly,
    AssemblyForkVersionPath,
    AssemblyGovernanceReceipts,
    BoundedTransportFrameContract,
    WebsocketTransportProfile,
    QuicTransportProfile,
    UnixLocalIpcProfile,
    OfflineSneakernetProfile,
    StoreForwardProfile,
    NatTraversalIdentityBinding,
    MultiRelayProvenance,
    DisasterRecoveryKeyCompromiseDrills,
    LongLivedArchiveCompatibility,
    TransportResourcePartitionDrills,
    HolodeckTransportIndependence,
    HostLevelSandbox,
    ProductionNetworking,
    RemoteExecution,
    InteroperableFederation,
}

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
        ReleaseClaim::ForeignObjectStore => CURRENT_CLAIMS.foreign_object_store,
        ReleaseClaim::QuarantineNamespace => CURRENT_CLAIMS.quarantine_namespace,
        ReleaseClaim::ProvenancePreservingDescendants => CURRENT_CLAIMS.provenance_preserving_descendants,
        ReleaseClaim::DurablePeerRegistry => CURRENT_CLAIMS.durable_peer_registry,
        ReleaseClaim::SeparateTrustRegistry => CURRENT_CLAIMS.separate_trust_registry,
        ReleaseClaim::ExpiringCapabilityAdvertisements => CURRENT_CLAIMS.expiring_capability_advertisements,
        ReleaseClaim::LocalCapabilityPolicy => CURRENT_CLAIMS.local_capability_policy,
        ReleaseClaim::PartitionRejoinControl => CURRENT_CLAIMS.partition_rejoin_control,
        ReleaseClaim::PortableFederationBundle => CURRENT_CLAIMS.portable_federation_bundle,
        ReleaseClaim::OfflineBundleVerification => CURRENT_CLAIMS.offline_bundle_verification,
        ReleaseClaim::NexusWorldSourceContract => CURRENT_CLAIMS.nexus_world_source_contract,
        ReleaseClaim::SandboxedSyntheticWorldKernel => CURRENT_CLAIMS.sandboxed_synthetic_world_kernel,
        ReleaseClaim::DeterministicHolodeckWorldPlan => CURRENT_CLAIMS.deterministic_holodeck_world_plan,
        ReleaseClaim::HolodeckComputerSafeguards => CURRENT_CLAIMS.holodeck_computer_safeguards,
        ReleaseClaim::HolodeckTeardownReceipts => CURRENT_CLAIMS.holodeck_teardown_receipts,
        ReleaseClaim::LiveNexusRuntimeAdapter => CURRENT_CLAIMS.live_nexus_runtime_adapter,
        ReleaseClaim::NexusCouncilReportAdapter => CURRENT_CLAIMS.nexus_council_report_adapter,
        ReleaseClaim::NexusSyntheticActorSeam => CURRENT_CLAIMS.nexus_synthetic_actor_seam,
        ReleaseClaim::NexusIndependentRedeliberation => CURRENT_CLAIMS.nexus_independent_redeliberation,
        ReleaseClaim::CouncilOfCouncilsReportsOnly => CURRENT_CLAIMS.council_of_councils_reports_only,
        ReleaseClaim::OracleEvidenceMembrane => CURRENT_CLAIMS.oracle_evidence_membrane,
        ReleaseClaim::OracleLiveTransport => CURRENT_CLAIMS.oracle_live_transport,
        ReleaseClaim::OracleHolodeckSyntheticAdmission => CURRENT_CLAIMS.oracle_holodeck_synthetic_admission,
        ReleaseClaim::ArkOfflinePreservationAdapter => CURRENT_CLAIMS.ark_offline_preservation_adapter,
        ReleaseClaim::MinimalProtocolSdkContract => CURRENT_CLAIMS.minimal_protocol_sdk_contract,
        ReleaseClaim::RustProtocolSdk => CURRENT_CLAIMS.rust_protocol_sdk,
        ReleaseClaim::PythonProtocolSdk => CURRENT_CLAIMS.python_protocol_sdk,
        ReleaseClaim::TypescriptProtocolSdk => CURRENT_CLAIMS.typescript_protocol_sdk,
        ReleaseClaim::LanguageNeutralSdkConformance => CURRENT_CLAIMS.language_neutral_sdk_conformance,
        ReleaseClaim::ThirdPartyNodeConformance => CURRENT_CLAIMS.third_party_node_conformance,
        ReleaseClaim::ThreeImplementationSdkInterop => CURRENT_CLAIMS.three_implementation_sdk_interop,
        ReleaseClaim::InstitutionalIntegrationDocs => CURRENT_CLAIMS.institutional_integration_docs,
        ReleaseClaim::AssemblyMembershipSeparateFromNetwork => CURRENT_CLAIMS.assembly_membership_separate_from_network,
        ReleaseClaim::AssemblyProposalLifecycle => CURRENT_CLAIMS.assembly_proposal_lifecycle,
        ReleaseClaim::AssemblyRepresentationModel => CURRENT_CLAIMS.assembly_representation_model,
        ReleaseClaim::AssemblyAntiSybilContract => CURRENT_CLAIMS.assembly_anti_sybil_contract,
        ReleaseClaim::DeterministicCharterGate => CURRENT_CLAIMS.deterministic_charter_gate,
        ReleaseClaim::AssemblyMemberLocalSovereignty => CURRENT_CLAIMS.assembly_member_local_sovereignty,
        ReleaseClaim::NexusAssemblyAdvisoryOnly => CURRENT_CLAIMS.nexus_assembly_advisory_only,
        ReleaseClaim::AssemblyForkVersionPath => CURRENT_CLAIMS.assembly_fork_version_path,
        ReleaseClaim::AssemblyGovernanceReceipts => CURRENT_CLAIMS.assembly_governance_receipts,
        ReleaseClaim::BoundedTransportFrameContract => CURRENT_CLAIMS.bounded_transport_frame_contract,
        ReleaseClaim::WebsocketTransportProfile => CURRENT_CLAIMS.websocket_transport_profile,
        ReleaseClaim::QuicTransportProfile => CURRENT_CLAIMS.quic_transport_profile,
        ReleaseClaim::UnixLocalIpcProfile => CURRENT_CLAIMS.unix_local_ipc_profile,
        ReleaseClaim::OfflineSneakernetProfile => CURRENT_CLAIMS.offline_sneakernet_profile,
        ReleaseClaim::StoreForwardProfile => CURRENT_CLAIMS.store_forward_profile,
        ReleaseClaim::NatTraversalIdentityBinding => CURRENT_CLAIMS.nat_traversal_identity_binding,
        ReleaseClaim::MultiRelayProvenance => CURRENT_CLAIMS.multi_relay_provenance,
        ReleaseClaim::DisasterRecoveryKeyCompromiseDrills => CURRENT_CLAIMS.disaster_recovery_key_compromise_drills,
        ReleaseClaim::LongLivedArchiveCompatibility => CURRENT_CLAIMS.long_lived_archive_compatibility,
        ReleaseClaim::TransportResourcePartitionDrills => CURRENT_CLAIMS.transport_resource_partition_drills,
        ReleaseClaim::HolodeckTransportIndependence => CURRENT_CLAIMS.holodeck_transport_independence,
        ReleaseClaim::HostLevelSandbox => CURRENT_CLAIMS.host_level_sandbox,
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
    fn phase7_assembly_capabilities_remain_established() {
        for claim in [
            ReleaseClaim::AssemblyMembershipSeparateFromNetwork,
            ReleaseClaim::AssemblyProposalLifecycle,
            ReleaseClaim::AssemblyRepresentationModel,
            ReleaseClaim::AssemblyAntiSybilContract,
            ReleaseClaim::DeterministicCharterGate,
            ReleaseClaim::AssemblyMemberLocalSovereignty,
            ReleaseClaim::NexusAssemblyAdvisoryOnly,
            ReleaseClaim::AssemblyForkVersionPath,
            ReleaseClaim::AssemblyGovernanceReceipts,
        ] {
            assert!(is_established(claim), "historical Phase 7 Assembly capability disabled: {claim:?}");
        }
    }

    #[test]
    fn phase8_adds_transports_without_deployment_overclaim() {
        for claim in [
            ReleaseClaim::BoundedTransportFrameContract,
            ReleaseClaim::WebsocketTransportProfile,
            ReleaseClaim::QuicTransportProfile,
            ReleaseClaim::UnixLocalIpcProfile,
            ReleaseClaim::OfflineSneakernetProfile,
            ReleaseClaim::StoreForwardProfile,
            ReleaseClaim::NatTraversalIdentityBinding,
            ReleaseClaim::MultiRelayProvenance,
            ReleaseClaim::DisasterRecoveryKeyCompromiseDrills,
            ReleaseClaim::LongLivedArchiveCompatibility,
            ReleaseClaim::TransportResourcePartitionDrills,
            ReleaseClaim::HolodeckTransportIndependence,
        ] {
            assert!(is_established(claim), "Phase 8 transport capability disabled: {claim:?}");
        }
        for claim in [
            ReleaseClaim::OracleHolodeckSyntheticAdmission,
            ReleaseClaim::HostLevelSandbox,
            ReleaseClaim::ProductionNetworking,
            ReleaseClaim::RemoteExecution,
            ReleaseClaim::InteroperableFederation,
        ] {
            assert!(!is_established(claim), "Phase 8 deployment/authority overclaim enabled: {claim:?}");
        }
    }

    #[test]
    fn current_claim_gate_is_not_runtime_configurable() {
        assert_eq!(PHASE8_GATE_ID, "qsol-fed-phase8-transport-resilience-gate/1");
        assert!(CURRENT_CLAIMS.bounded_transport_frame_contract);
        assert!(CURRENT_CLAIMS.websocket_transport_profile);
        assert!(CURRENT_CLAIMS.quic_transport_profile);
        assert!(CURRENT_CLAIMS.nat_traversal_identity_binding);
        assert!(CURRENT_CLAIMS.multi_relay_provenance);
        assert!(CURRENT_CLAIMS.transport_resource_partition_drills);
        assert!(CURRENT_CLAIMS.holodeck_transport_independence);
        assert!(!CURRENT_CLAIMS.oracle_holodeck_synthetic_admission);
        assert!(!CURRENT_CLAIMS.host_level_sandbox);
        assert!(!CURRENT_CLAIMS.production_networking);
        assert!(!CURRENT_CLAIMS.remote_execution);
        assert!(!CURRENT_CLAIMS.interoperable_federation);
    }
}
