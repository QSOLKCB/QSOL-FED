//! Non-configurable Federation constitutional admission policy.
//!
//! These rules are deliberately ordinary source constants rather than runtime
//! configuration. A local maintainer can change source code, but a peer, model,
//! environment variable or API request cannot negotiate these protections away.

pub const PROTOCOL_ID: &str = "qsol-fed/0";
pub const CHARTER_ID: &str = "qsol-fed-charter/1";
pub const PRIME_DIRECTIVE_ID: &str = "qsol-fed-prime-directive/1";

pub const REMOTE_ARBITRARY_EXECUTION_ENABLED: bool = false;
pub const REMOTE_GOVERNANCE_MUTATION_ENABLED: bool = false;
pub const REMOTE_EVIDENCE_PROMOTION_ENABLED: bool = false;
pub const REMOTE_VOTE_CREATION_ENABLED: bool = false;
pub const REMOTE_CAPABILITY_INSTALLATION_ENABLED: bool = false;
pub const REMOTE_HISTORY_REWRITE_ENABLED: bool = false;
pub const REMOTE_CITIZENSHIP_MUTATION_ENABLED: bool = false;
pub const REMOTE_LOCAL_AUTHORITY_CLAIM_ENABLED: bool = false;
pub const FOREIGN_IMPORT_BECOMES_LOCAL_AUTHORITY: bool = false;
pub const SECRETS_IN_SEMANTIC_STATE_ALLOWED: bool = false;
pub const RUNTIME_CONSTITUTION_OVERRIDE_ALLOWED: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardInvariant {
    pub id: &'static str,
    pub statement: &'static str,
}

pub const HARD_INVARIANTS: &[HardInvariant] = &[
    HardInvariant {
        id: "peering_is_not_trust",
        statement: "Peering does not create trust or authority.",
    },
    HardInvariant {
        id: "import_is_not_authority",
        statement: "Importing foreign state does not create local authority.",
    },
    HardInvariant {
        id: "consensus_is_not_truth",
        statement: "Remote or local consensus is not automatically truth or evidence.",
    },
    HardInvariant {
        id: "discovery_is_not_permission",
        statement: "Discovering a node or capability does not authorize its use.",
    },
    HardInvariant {
        id: "capability_is_not_entitlement",
        statement: "Capability advertisement does not grant invocation authority.",
    },
    HardInvariant {
        id: "federation_is_not_central_control",
        statement: "Federation membership does not transfer local sovereignty.",
    },
    HardInvariant {
        id: "foreign_state_is_not_local_state",
        statement: "Foreign state remains foreign until an explicit local process creates a local descendant.",
    },
    HardInvariant {
        id: "observation_is_not_intervention",
        statement: "Observing or reporting local state does not authorize mutation of it.",
    },
    HardInvariant {
        id: "local_sovereignty_over_federation_convenience",
        statement: "Local sovereignty takes precedence over federation convenience.",
    },
    HardInvariant {
        id: "remote_governance_mutation_forbidden",
        statement: "A peer cannot mutate local governance through Federation input.",
    },
    HardInvariant {
        id: "remote_evidence_promotion_forbidden",
        statement: "A peer cannot promote or rewrite local evidence status.",
    },
    HardInvariant {
        id: "remote_vote_creation_forbidden",
        statement: "A peer cannot create, delete or reweight a local Council vote.",
    },
    HardInvariant {
        id: "remote_capability_installation_forbidden",
        statement: "A peer cannot install or enable a local capability.",
    },
    HardInvariant {
        id: "remote_history_rewrite_forbidden",
        statement: "A peer cannot rewrite or relabel local history.",
    },
    HardInvariant {
        id: "remote_citizenship_mutation_forbidden",
        statement: "A peer cannot change local citizenship or identity authority.",
    },
    HardInvariant {
        id: "remote_arbitrary_execution_forbidden",
        statement: "A peer cannot request arbitrary local code, command or tool execution.",
    },
    HardInvariant {
        id: "remote_local_authority_claim_forbidden",
        statement: "Remote identity, signature or consensus cannot claim local authority.",
    },
    HardInvariant {
        id: "secrets_in_semantic_state_forbidden",
        statement: "Credentials and secrets must not intentionally enter Federation semantic state.",
    },
    HardInvariant {
        id: "runtime_constitution_override_forbidden",
        statement: "A peer, model, configuration source, environment variable or consensus cannot disable constitutional invariants at runtime.",
    },
    HardInvariant {
        id: "unknown_authority_action_rejected",
        statement: "Unknown authority-bearing Federation actions fail closed.",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationEffect {
    /// Ordinary attributed foreign information. It may enter a data-only path.
    OfferInformation,
    AdvertiseCapability,
    OfferEvidence,
    RequestEvidence,
    OfferHypothesis,
    Challenge,
    Respond,
    SubmitCouncilReport,
    SubmitMinorityReport,
    SubmitExperimentReceipt,
    SubmitCitation,
    SubmitPublication,

    /// Foreign state that needs an explicit quarantine/import workflow.
    ImportForeignState,

    /// Authority-bearing or dangerous effects prohibited by the bootstrap constitution.
    MutateLocalGovernance,
    PromoteLocalEvidence,
    CreateOrReweightLocalVote,
    InstallLocalCapability,
    RewriteLocalHistory,
    MutateLocalCitizenship,
    ExecuteArbitraryLocalTool,
    ClaimLocalAuthority,
    WriteSecretToSemanticState,
    DisableConstitutionalInvariant,

    /// Unknown semantics fail closed rather than being guessed safe.
    UnknownAuthorityBearingEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    AcceptAsData,
    Quarantine {
        reason: &'static str,
    },
    Reject {
        invariant_id: &'static str,
    },
}

/// Apply the Prime Directive to a proposed Federation effect.
///
/// The caller may reject an effect earlier for authentication, parsing, replay,
/// capability or local-policy reasons. It may not use those layers to turn a
/// constitutional rejection into an admission.
pub const fn admit_effect(effect: FederationEffect) -> AdmissionDecision {
    match effect {
        FederationEffect::OfferInformation
        | FederationEffect::AdvertiseCapability
        | FederationEffect::OfferEvidence
        | FederationEffect::RequestEvidence
        | FederationEffect::OfferHypothesis
        | FederationEffect::Challenge
        | FederationEffect::Respond
        | FederationEffect::SubmitCouncilReport
        | FederationEffect::SubmitMinorityReport
        | FederationEffect::SubmitExperimentReceipt
        | FederationEffect::SubmitCitation
        | FederationEffect::SubmitPublication => AdmissionDecision::AcceptAsData,

        FederationEffect::ImportForeignState => AdmissionDecision::Quarantine {
            reason: "foreign_state_is_not_local_state",
        },

        FederationEffect::MutateLocalGovernance => AdmissionDecision::Reject {
            invariant_id: "remote_governance_mutation_forbidden",
        },
        FederationEffect::PromoteLocalEvidence => AdmissionDecision::Reject {
            invariant_id: "remote_evidence_promotion_forbidden",
        },
        FederationEffect::CreateOrReweightLocalVote => AdmissionDecision::Reject {
            invariant_id: "remote_vote_creation_forbidden",
        },
        FederationEffect::InstallLocalCapability => AdmissionDecision::Reject {
            invariant_id: "remote_capability_installation_forbidden",
        },
        FederationEffect::RewriteLocalHistory => AdmissionDecision::Reject {
            invariant_id: "remote_history_rewrite_forbidden",
        },
        FederationEffect::MutateLocalCitizenship => AdmissionDecision::Reject {
            invariant_id: "remote_citizenship_mutation_forbidden",
        },
        FederationEffect::ExecuteArbitraryLocalTool => AdmissionDecision::Reject {
            invariant_id: "remote_arbitrary_execution_forbidden",
        },
        FederationEffect::ClaimLocalAuthority => AdmissionDecision::Reject {
            invariant_id: "remote_local_authority_claim_forbidden",
        },
        FederationEffect::WriteSecretToSemanticState => AdmissionDecision::Reject {
            invariant_id: "secrets_in_semantic_state_forbidden",
        },
        FederationEffect::DisableConstitutionalInvariant => AdmissionDecision::Reject {
            invariant_id: "runtime_constitution_override_forbidden",
        },
        FederationEffect::UnknownAuthorityBearingEffect => AdmissionDecision::Reject {
            invariant_id: "unknown_authority_action_rejected",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harmless_foreign_semantic_material_is_data_only() {
        let effects = [
            FederationEffect::OfferInformation,
            FederationEffect::AdvertiseCapability,
            FederationEffect::OfferEvidence,
            FederationEffect::RequestEvidence,
            FederationEffect::OfferHypothesis,
            FederationEffect::Challenge,
            FederationEffect::Respond,
            FederationEffect::SubmitCouncilReport,
            FederationEffect::SubmitMinorityReport,
            FederationEffect::SubmitExperimentReceipt,
            FederationEffect::SubmitCitation,
            FederationEffect::SubmitPublication,
        ];

        for effect in effects {
            assert_eq!(admit_effect(effect), AdmissionDecision::AcceptAsData);
        }
    }

    #[test]
    fn foreign_state_is_quarantined_not_promoted() {
        assert_eq!(
            admit_effect(FederationEffect::ImportForeignState),
            AdmissionDecision::Quarantine {
                reason: "foreign_state_is_not_local_state"
            }
        );
    }

    #[test]
    fn authority_bearing_remote_effects_fail_closed() {
        let forbidden = [
            FederationEffect::MutateLocalGovernance,
            FederationEffect::PromoteLocalEvidence,
            FederationEffect::CreateOrReweightLocalVote,
            FederationEffect::InstallLocalCapability,
            FederationEffect::RewriteLocalHistory,
            FederationEffect::MutateLocalCitizenship,
            FederationEffect::ExecuteArbitraryLocalTool,
            FederationEffect::ClaimLocalAuthority,
            FederationEffect::WriteSecretToSemanticState,
            FederationEffect::DisableConstitutionalInvariant,
            FederationEffect::UnknownAuthorityBearingEffect,
        ];

        for effect in forbidden {
            assert!(matches!(
                admit_effect(effect),
                AdmissionDecision::Reject { .. }
            ));
        }
    }

    #[test]
    fn all_runtime_bypass_flags_are_false() {
        assert!(!REMOTE_ARBITRARY_EXECUTION_ENABLED);
        assert!(!REMOTE_GOVERNANCE_MUTATION_ENABLED);
        assert!(!REMOTE_EVIDENCE_PROMOTION_ENABLED);
        assert!(!REMOTE_VOTE_CREATION_ENABLED);
        assert!(!REMOTE_CAPABILITY_INSTALLATION_ENABLED);
        assert!(!REMOTE_HISTORY_REWRITE_ENABLED);
        assert!(!REMOTE_CITIZENSHIP_MUTATION_ENABLED);
        assert!(!REMOTE_LOCAL_AUTHORITY_CLAIM_ENABLED);
        assert!(!FOREIGN_IMPORT_BECOMES_LOCAL_AUTHORITY);
        assert!(!SECRETS_IN_SEMANTIC_STATE_ALLOWED);
        assert!(!RUNTIME_CONSTITUTION_OVERRIDE_ALLOWED);
    }

    #[test]
    fn executable_registry_contains_all_bootstrap_invariants() {
        assert_eq!(HARD_INVARIANTS.len(), 20);
        assert!(HARD_INVARIANTS
            .iter()
            .any(|invariant| invariant.id == "runtime_constitution_override_forbidden"));
        assert!(HARD_INVARIANTS
            .iter()
            .any(|invariant| invariant.id == "unknown_authority_action_rejected"));
    }

    #[test]
    fn invariant_ids_are_unique() {
        for (index, invariant) in HARD_INVARIANTS.iter().enumerate() {
            assert!(
                !HARD_INVARIANTS[index + 1..]
                    .iter()
                    .any(|other| other.id == invariant.id),
                "duplicate invariant id: {}",
                invariant.id
            );
        }
    }
}
