//! Phase 7 Federation Assembly reference model.
//!
//! Assembly state is a protocol-evolution governance plane, not member-local state.
//! Network membership does not grant Assembly membership. Assembly outcomes never
//! mutate member-local governance, evidence, trust, capability, history, or execution state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::canonical::{canonicalize, sha256_ref};
use crate::wire::{is_node_id, is_sha256_ref};

pub const ASSEMBLY_MEMBER_SCHEMA_V1: &str = "qsol-fed-assembly-member/1";
pub const ASSEMBLY_PROPOSAL_SCHEMA_V1: &str = "qsol-fed-assembly-proposal/1";
pub const ASSEMBLY_ADVISORY_SCHEMA_V1: &str = "qsol-fed-assembly-advisory/1";
pub const ASSEMBLY_RECEIPT_SCHEMA_V1: &str = "qsol-fed-governance-receipt/1";
pub const ASSEMBLY_CHARTER_GATE_V1: &str = "qsol-fed-charter-gate/1";
pub const ASSEMBLY_REPRESENTATION_V1: &str = "one-member-one-vote/1";
pub const ANTI_SYBIL_ASSUMPTION: &str =
    "real-world principal uniqueness is an external admission assumption; protocol enforces one active normalized representation subject per Assembly registry";
pub const MAX_ASSEMBLY_MEMBERS: usize = 1_024;
pub const MAX_ASSEMBLY_PROPOSALS: usize = 1_024;
pub const MAX_ASSEMBLY_ADVISORIES: usize = 64;
pub const MAX_PROPOSAL_TITLE_BYTES: usize = 256;
pub const MAX_PROPOSAL_SUMMARY_BYTES: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyError(pub String);
impl fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for AssemblyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssemblyMemberStatus { Active, Withdrawn }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyMemberApplication {
    pub member_id: String,
    pub representation_subject: String,
    pub federation_node_id: Option<String>,
    pub local_opt_in: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyMemberRecord {
    pub schema: String,
    pub member_id: String,
    pub representation_subject: String,
    pub federation_node_id: Option<String>,
    pub status: AssemblyMemberStatus,
    pub representation_weight: u8,
    pub network_membership_required: bool,
    pub qsol_governance_required: bool,
    pub authority_effect: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssemblyProposalKind { ProtocolAmendment, CharterAmendment, AdvisoryResolution, ForkProposal }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolCompatibility { BackwardCompatible, Breaking, NotApplicable }

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalEffectDeclaration {
    pub direct_member_local_authority_mutation: bool,
    pub network_membership_grants_assembly_membership: bool,
    pub enable_remote_governance_mutation: bool,
    pub enable_remote_evidence_promotion: bool,
    pub enable_remote_vote_creation: bool,
    pub enable_remote_capability_installation: bool,
    pub enable_remote_history_rewrite: bool,
    pub enable_remote_citizenship_mutation: bool,
    pub enable_remote_arbitrary_execution: bool,
    pub enable_remote_local_authority_claim: bool,
    pub foreign_import_becomes_local_authority: bool,
    pub allow_secrets_in_semantic_state: bool,
    pub allow_runtime_constitution_override: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyProposalDraft {
    pub proposer_member_id: String,
    pub title: String,
    pub summary: String,
    pub kind: AssemblyProposalKind,
    pub compatibility: ProtocolCompatibility,
    pub effects: ProposalEffectDeclaration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CharterGateDisposition { Compatible, ForkRequired }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharterGateAssessment {
    pub gate: String,
    pub disposition: CharterGateDisposition,
    pub violated_invariant_ids: Vec<String>,
    pub current_lineage_eligible: bool,
    pub member_local_authority_effect: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssemblyProposalStatus { Open, ForkRequired, Withdrawn, Accepted, Rejected, ForkEndorsed }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteChoice { Yes, No, Abstain }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorySourceKind { NexusCouncil, OtherAdvisory }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyAdvisoryReport {
    pub schema: String,
    pub source_kind: AdvisorySourceKind,
    pub source_node: Option<String>,
    pub report_ref: String,
    pub advisory_weight: u8,
    pub vote_weight: u8,
    pub authority_effect: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyProposalRecord {
    pub schema: String,
    pub proposal_id: String,
    pub sequence: u64,
    pub draft: AssemblyProposalDraft,
    pub charter_gate: CharterGateAssessment,
    pub electorate_member_ids: Vec<String>,
    pub status: AssemblyProposalStatus,
    pub votes: BTreeMap<String, VoteChoice>,
    pub advisory_reports: Vec<AssemblyAdvisoryReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceOutcome { Accepted, Rejected, Withdrawn, ForkRequired, ForkEndorsed }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionPath { NoProtocolChange, CompatibleSourceChangeRequired, NewMajorRequired, ForkRequired }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyGovernanceReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub proposal_id: String,
    pub outcome: GovernanceOutcome,
    pub charter_gate: CharterGateAssessment,
    pub representation_model: String,
    pub electorate_size: usize,
    pub yes_votes: usize,
    pub no_votes: usize,
    pub abstain_votes: usize,
    pub quorum_required: usize,
    pub quorum_met: bool,
    pub approval_required: usize,
    pub approval_met: bool,
    pub version_path: VersionPath,
    pub source_change_required: bool,
    pub protocol_changed_automatically: bool,
    pub member_local_authority_mutated: bool,
    pub nexus_advisory_reports: usize,
    pub nexus_advisory_vote_weight: u8,
    pub authority_effect: String,
}

#[derive(Debug, Default)]
pub struct FederationAssembly {
    members: BTreeMap<String, AssemblyMemberRecord>,
    representation_subjects: BTreeSet<String>,
    proposals: BTreeMap<String, AssemblyProposalRecord>,
    next_sequence: u64,
}

fn normalize_subject(value: &str) -> Result<String, AssemblyError> {
    let normalized: String = value.nfc().collect();
    if normalized.is_empty() || normalized.chars().count() > 256 {
        return Err(AssemblyError("assembly_representation_subject_invalid".into()));
    }
    Ok(normalized)
}

fn is_assembly_member_id(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("assembly:") else { return false; };
    if tail.is_empty() || tail.len() > 128 { return false; }
    tail.bytes().enumerate().all(|(index, byte)| {
        let core = byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if index == 0 { core } else { core || matches!(byte, b'.' | b'_' | b'-') }
    })
}

fn validate_text(value: &str, maximum_bytes: usize, error: &'static str) -> Result<(), AssemblyError> {
    if value.is_empty() || value.len() > maximum_bytes { Err(AssemblyError(error.into())) } else { Ok(()) }
}

fn two_thirds_ceil(value: usize) -> usize { if value == 0 { 0 } else { (2 * value).div_ceil(3) } }

fn canonical_id<T: Serialize>(value: &T) -> Result<String, AssemblyError> {
    let raw = serde_json::to_vec(value).map_err(|_| AssemblyError("assembly_serialization_failed".into()))?;
    let canonical = canonicalize(&raw).map_err(|error| AssemblyError(error.0))?;
    Ok(sha256_ref(&canonical))
}

fn canonical_id_without_field<T: Serialize>(value: &T, field: &str) -> Result<String, AssemblyError> {
    let mut projection = serde_json::to_value(value).map_err(|_| AssemblyError("assembly_serialization_failed".into()))?;
    let Value::Object(ref mut object) = projection else { return Err(AssemblyError("assembly_identity_projection_invalid".into())); };
    object.remove(field);
    canonical_id(&projection)
}

pub fn assess_charter_gate(draft: &AssemblyProposalDraft) -> CharterGateAssessment {
    let effects = &draft.effects;
    let mut violations = Vec::new();
    for (enabled, invariant) in [
        (effects.direct_member_local_authority_mutation, "local_sovereignty_over_federation_convenience"),
        (effects.network_membership_grants_assembly_membership, "federation_is_not_central_control"),
        (effects.enable_remote_governance_mutation, "remote_governance_mutation_forbidden"),
        (effects.enable_remote_evidence_promotion, "remote_evidence_promotion_forbidden"),
        (effects.enable_remote_vote_creation, "remote_vote_creation_forbidden"),
        (effects.enable_remote_capability_installation, "remote_capability_installation_forbidden"),
        (effects.enable_remote_history_rewrite, "remote_history_rewrite_forbidden"),
        (effects.enable_remote_citizenship_mutation, "remote_citizenship_mutation_forbidden"),
        (effects.enable_remote_arbitrary_execution, "remote_arbitrary_execution_forbidden"),
        (effects.enable_remote_local_authority_claim, "remote_local_authority_claim_forbidden"),
        (effects.foreign_import_becomes_local_authority, "import_is_not_authority"),
        (effects.allow_secrets_in_semantic_state, "secrets_in_semantic_state_forbidden"),
        (effects.allow_runtime_constitution_override, "runtime_constitution_override_forbidden"),
    ] {
        if enabled { violations.push(invariant.to_string()); }
    }
    let current_lineage_eligible = violations.is_empty();
    CharterGateAssessment {
        gate: ASSEMBLY_CHARTER_GATE_V1.into(),
        disposition: if current_lineage_eligible { CharterGateDisposition::Compatible } else { CharterGateDisposition::ForkRequired },
        violated_invariant_ids: violations,
        current_lineage_eligible,
        member_local_authority_effect: "none".into(),
    }
}

impl FederationAssembly {
    pub fn new() -> Self { Self { next_sequence: 1, ..Self::default() } }
    pub fn members(&self) -> impl Iterator<Item = &AssemblyMemberRecord> { self.members.values() }
    pub fn proposals(&self) -> impl Iterator<Item = &AssemblyProposalRecord> { self.proposals.values() }

    pub fn admit_member(&mut self, application: AssemblyMemberApplication) -> Result<AssemblyMemberRecord, AssemblyError> {
        if self.members.len() >= MAX_ASSEMBLY_MEMBERS { return Err(AssemblyError("assembly_member_limit_exceeded".into())); }
        if !application.local_opt_in || !is_assembly_member_id(&application.member_id) {
            return Err(AssemblyError("assembly_membership_requires_explicit_local_opt_in".into()));
        }
        if application.federation_node_id.as_deref().is_some_and(|value| !is_node_id(value)) {
            return Err(AssemblyError("assembly_federation_node_id_invalid".into()));
        }
        if self.members.contains_key(&application.member_id) { return Err(AssemblyError("assembly_member_id_already_exists".into())); }
        let subject = normalize_subject(&application.representation_subject)?;
        if self.representation_subjects.contains(&subject) { return Err(AssemblyError("assembly_representation_subject_already_active".into())); }
        let record = AssemblyMemberRecord {
            schema: ASSEMBLY_MEMBER_SCHEMA_V1.into(), member_id: application.member_id.clone(),
            representation_subject: subject.clone(), federation_node_id: application.federation_node_id,
            status: AssemblyMemberStatus::Active, representation_weight: 1,
            network_membership_required: false, qsol_governance_required: false, authority_effect: "none".into(),
        };
        self.representation_subjects.insert(subject);
        self.members.insert(application.member_id, record.clone());
        Ok(record)
    }

    pub fn withdraw_member(&mut self, member_id: &str) -> Result<(), AssemblyError> {
        let member = self.members.get_mut(member_id).ok_or_else(|| AssemblyError("assembly_member_unknown".into()))?;
        if member.status != AssemblyMemberStatus::Active { return Err(AssemblyError("assembly_member_not_active".into())); }
        member.status = AssemblyMemberStatus::Withdrawn;
        self.representation_subjects.remove(&member.representation_subject);
        Ok(())
    }

    pub fn submit_proposal(&mut self, draft: AssemblyProposalDraft) -> Result<AssemblyProposalRecord, AssemblyError> {
        if self.proposals.len() >= MAX_ASSEMBLY_PROPOSALS { return Err(AssemblyError("assembly_proposal_limit_exceeded".into())); }
        validate_text(&draft.title, MAX_PROPOSAL_TITLE_BYTES, "assembly_proposal_title_invalid")?;
        validate_text(&draft.summary, MAX_PROPOSAL_SUMMARY_BYTES, "assembly_proposal_summary_invalid")?;
        let proposer = self.members.get(&draft.proposer_member_id).ok_or_else(|| AssemblyError("assembly_proposer_not_member".into()))?;
        if proposer.status != AssemblyMemberStatus::Active { return Err(AssemblyError("assembly_proposer_not_active".into())); }
        match draft.kind {
            AssemblyProposalKind::AdvisoryResolution if draft.compatibility != ProtocolCompatibility::NotApplicable => return Err(AssemblyError("assembly_advisory_compatibility_invalid".into())),
            AssemblyProposalKind::ForkProposal if draft.compatibility != ProtocolCompatibility::Breaking => return Err(AssemblyError("assembly_fork_must_be_breaking".into())),
            _ => {}
        }
        let electorate: Vec<String> = self.members.values().filter(|member| member.status == AssemblyMemberStatus::Active).map(|member| member.member_id.clone()).collect();
        if electorate.is_empty() { return Err(AssemblyError("assembly_electorate_empty".into())); }
        let charter_gate = assess_charter_gate(&draft);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| AssemblyError("assembly_sequence_exhausted".into()))?;
        let identity_projection = serde_json::json!({
            "schema": ASSEMBLY_PROPOSAL_SCHEMA_V1, "sequence": sequence, "draft": &draft,
            "charter_gate": &charter_gate, "electorate_member_ids": &electorate,
        });
        let proposal_id = canonical_id(&identity_projection)?;
        let status = if charter_gate.current_lineage_eligible || draft.kind == AssemblyProposalKind::ForkProposal { AssemblyProposalStatus::Open } else { AssemblyProposalStatus::ForkRequired };
        let record = AssemblyProposalRecord {
            schema: ASSEMBLY_PROPOSAL_SCHEMA_V1.into(), proposal_id: proposal_id.clone(), sequence, draft,
            charter_gate, electorate_member_ids: electorate, status, votes: BTreeMap::new(), advisory_reports: Vec::new(),
        };
        self.proposals.insert(proposal_id, record.clone());
        Ok(record)
    }

    pub fn attach_advisory(&mut self, proposal_id: &str, source_kind: AdvisorySourceKind, source_node: Option<String>, report_ref: String) -> Result<AssemblyAdvisoryReport, AssemblyError> {
        if !is_sha256_ref(&report_ref) || source_node.as_deref().is_some_and(|value| !is_node_id(value)) { return Err(AssemblyError("assembly_advisory_invalid".into())); }
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| AssemblyError("assembly_proposal_unknown".into()))?;
        if proposal.advisory_reports.len() >= MAX_ASSEMBLY_ADVISORIES { return Err(AssemblyError("assembly_advisory_limit_exceeded".into())); }
        if !matches!(proposal.status, AssemblyProposalStatus::Open | AssemblyProposalStatus::ForkRequired) { return Err(AssemblyError("assembly_proposal_not_open_for_advisory".into())); }
        let advisory = AssemblyAdvisoryReport {
            schema: ASSEMBLY_ADVISORY_SCHEMA_V1.into(), source_kind, source_node, report_ref,
            advisory_weight: 0, vote_weight: 0, authority_effect: "none".into(),
        };
        proposal.advisory_reports.push(advisory.clone());
        Ok(advisory)
    }

    pub fn cast_vote(&mut self, proposal_id: &str, member_id: &str, choice: VoteChoice) -> Result<(), AssemblyError> {
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| AssemblyError("assembly_proposal_unknown".into()))?;
        if proposal.status != AssemblyProposalStatus::Open { return Err(AssemblyError("assembly_proposal_not_open_for_vote".into())); }
        if !proposal.electorate_member_ids.iter().any(|eligible| eligible == member_id) { return Err(AssemblyError("assembly_voter_not_in_electorate_snapshot".into())); }
        if proposal.votes.contains_key(member_id) { return Err(AssemblyError("assembly_vote_already_recorded".into())); }
        proposal.votes.insert(member_id.to_string(), choice);
        Ok(())
    }

    pub fn withdraw_proposal(&mut self, proposal_id: &str, proposer_member_id: &str) -> Result<(), AssemblyError> {
        let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| AssemblyError("assembly_proposal_unknown".into()))?;
        if proposal.draft.proposer_member_id != proposer_member_id || !matches!(proposal.status, AssemblyProposalStatus::Open | AssemblyProposalStatus::ForkRequired) {
            return Err(AssemblyError("assembly_proposal_withdrawal_forbidden".into()));
        }
        proposal.status = AssemblyProposalStatus::Withdrawn;
        Ok(())
    }

    pub fn finalize(&mut self, proposal_id: &str) -> Result<AssemblyGovernanceReceipt, AssemblyError> {
        let snapshot = self.proposals.get(proposal_id).cloned().ok_or_else(|| AssemblyError("assembly_proposal_unknown".into()))?;
        let electorate_size = snapshot.electorate_member_ids.len();
        let yes_votes = snapshot.votes.values().filter(|vote| **vote == VoteChoice::Yes).count();
        let no_votes = snapshot.votes.values().filter(|vote| **vote == VoteChoice::No).count();
        let abstain_votes = snapshot.votes.values().filter(|vote| **vote == VoteChoice::Abstain).count();
        let participation = yes_votes + no_votes + abstain_votes;
        let quorum_required = two_thirds_ceil(electorate_size);
        let quorum_met = participation >= quorum_required;
        let decisive = yes_votes + no_votes;
        let approval_required = two_thirds_ceil(decisive);
        let approval_met = decisive > 0 && yes_votes >= approval_required;
        let (outcome, status) = match snapshot.status {
            AssemblyProposalStatus::ForkRequired => (GovernanceOutcome::ForkRequired, AssemblyProposalStatus::ForkRequired),
            AssemblyProposalStatus::Withdrawn => (GovernanceOutcome::Withdrawn, AssemblyProposalStatus::Withdrawn),
            AssemblyProposalStatus::Open if quorum_met && approval_met && snapshot.draft.kind == AssemblyProposalKind::ForkProposal => (GovernanceOutcome::ForkEndorsed, AssemblyProposalStatus::ForkEndorsed),
            AssemblyProposalStatus::Open if quorum_met && approval_met => (GovernanceOutcome::Accepted, AssemblyProposalStatus::Accepted),
            AssemblyProposalStatus::Open => (GovernanceOutcome::Rejected, AssemblyProposalStatus::Rejected),
            _ => return Err(AssemblyError("assembly_proposal_already_finalized".into())),
        };
        let version_path = match (snapshot.draft.kind, snapshot.draft.compatibility, outcome) {
            (_, _, GovernanceOutcome::ForkRequired | GovernanceOutcome::ForkEndorsed) => VersionPath::ForkRequired,
            (AssemblyProposalKind::AdvisoryResolution, _, _) => VersionPath::NoProtocolChange,
            (AssemblyProposalKind::ProtocolAmendment, ProtocolCompatibility::BackwardCompatible, _) => VersionPath::CompatibleSourceChangeRequired,
            (AssemblyProposalKind::ProtocolAmendment, ProtocolCompatibility::Breaking, _) | (AssemblyProposalKind::CharterAmendment, _, _) => VersionPath::NewMajorRequired,
            _ => VersionPath::NoProtocolChange,
        };
        let source_change_required = matches!(outcome, GovernanceOutcome::Accepted | GovernanceOutcome::ForkRequired | GovernanceOutcome::ForkEndorsed) && version_path != VersionPath::NoProtocolChange;
        let nexus_advisory_reports = snapshot.advisory_reports.iter().filter(|report| report.source_kind == AdvisorySourceKind::NexusCouncil).count();
        let mut receipt = AssemblyGovernanceReceipt {
            schema: ASSEMBLY_RECEIPT_SCHEMA_V1.into(), receipt_id: String::new(), proposal_id: snapshot.proposal_id.clone(), outcome,
            charter_gate: snapshot.charter_gate.clone(), representation_model: ASSEMBLY_REPRESENTATION_V1.into(), electorate_size,
            yes_votes, no_votes, abstain_votes, quorum_required, quorum_met, approval_required, approval_met, version_path,
            source_change_required, protocol_changed_automatically: false, member_local_authority_mutated: false,
            nexus_advisory_reports, nexus_advisory_vote_weight: 0, authority_effect: "none".into(),
        };
        receipt.receipt_id = canonical_id_without_field(&receipt, "receipt_id")?;
        if let Some(proposal) = self.proposals.get_mut(proposal_id) { proposal.status = status; }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str, subject: &str, node: Option<&str>) -> AssemblyMemberApplication {
        AssemblyMemberApplication { member_id: id.into(), representation_subject: subject.into(), federation_node_id: node.map(str::to_string), local_opt_in: true }
    }
    fn draft(proposer: &str, kind: AssemblyProposalKind) -> AssemblyProposalDraft {
        AssemblyProposalDraft {
            proposer_member_id: proposer.into(), title: "Protocol clarification".into(),
            summary: "Clarify an interoperable protocol rule without changing member-local authority.".into(), kind,
            compatibility: match kind { AssemblyProposalKind::AdvisoryResolution => ProtocolCompatibility::NotApplicable, AssemblyProposalKind::ForkProposal => ProtocolCompatibility::Breaking, _ => ProtocolCompatibility::BackwardCompatible },
            effects: ProposalEffectDeclaration::default(),
        }
    }
    fn three_member_assembly() -> FederationAssembly {
        let mut assembly = FederationAssembly::new();
        assembly.admit_member(member("assembly:alpha", "Principal Alpha", Some("fed:qsol:alpha"))).unwrap();
        assembly.admit_member(member("assembly:beta", "Principal Beta", None)).unwrap();
        assembly.admit_member(member("assembly:gamma", "Principal Gamma", Some("fed:qsol:gamma"))).unwrap();
        assembly
    }

    #[test]
    fn network_membership_does_not_grant_assembly_membership() {
        let mut assembly = three_member_assembly();
        let proposal = assembly.submit_proposal(draft("assembly:alpha", AssemblyProposalKind::ProtocolAmendment)).unwrap();
        assert!(assembly.cast_vote(&proposal.proposal_id, "fed:qsol:network-only-peer", VoteChoice::Yes).is_err());
        let beta = assembly.members().find(|member| member.member_id == "assembly:beta").unwrap();
        assert!(beta.federation_node_id.is_none());
        assert!(!beta.network_membership_required);
    }

    #[test]
    fn normalized_representation_subject_cannot_duplicate_active_membership() {
        let mut assembly = FederationAssembly::new();
        assembly.admit_member(member("assembly:one", "Café", None)).unwrap();
        assert_eq!(assembly.admit_member(member("assembly:two", "Cafe\u{301}", None)).unwrap_err().0, "assembly_representation_subject_already_active");
    }

    #[test]
    fn representation_subject_unicode_length_matches_schema() {
        let mut assembly = FederationAssembly::new();
        assembly.admit_member(member("assembly:ok", &"🖖".repeat(256), None)).unwrap();
        assert!(assembly.admit_member(member("assembly:too-long", &"🖖".repeat(257), None)).is_err());
    }

    #[test]
    fn electorate_snapshot_cannot_be_reweighted_mid_vote() {
        let mut assembly = FederationAssembly::new();
        assembly.admit_member(member("assembly:a", "A", None)).unwrap();
        assembly.admit_member(member("assembly:b", "B", None)).unwrap();
        let proposal = assembly.submit_proposal(draft("assembly:a", AssemblyProposalKind::AdvisoryResolution)).unwrap();
        assembly.admit_member(member("assembly:c", "C", None)).unwrap();
        assert!(assembly.cast_vote(&proposal.proposal_id, "assembly:c", VoteChoice::Yes).is_err());
        assembly.cast_vote(&proposal.proposal_id, "assembly:a", VoteChoice::Yes).unwrap();
        assembly.cast_vote(&proposal.proposal_id, "assembly:b", VoteChoice::Yes).unwrap();
        let receipt = assembly.finalize(&proposal.proposal_id).unwrap();
        assert_eq!(receipt.electorate_size, 2);
        assert_eq!(receipt.outcome, GovernanceOutcome::Accepted);
    }

    #[test]
    fn duplicate_vote_does_not_replace_first_vote() {
        let mut assembly = three_member_assembly();
        let proposal = assembly.submit_proposal(draft("assembly:alpha", AssemblyProposalKind::ProtocolAmendment)).unwrap();
        assembly.cast_vote(&proposal.proposal_id, "assembly:alpha", VoteChoice::Yes).unwrap();
        assert_eq!(assembly.cast_vote(&proposal.proposal_id, "assembly:alpha", VoteChoice::No).unwrap_err().0, "assembly_vote_already_recorded");
        assembly.cast_vote(&proposal.proposal_id, "assembly:beta", VoteChoice::Yes).unwrap();
        let receipt = assembly.finalize(&proposal.proposal_id).unwrap();
        assert_eq!((receipt.yes_votes, receipt.no_votes), (2, 0));
    }

    #[test]
    fn charter_gate_routes_member_local_authority_mutation_to_fork_path() {
        let mut assembly = three_member_assembly();
        let mut hostile = draft("assembly:alpha", AssemblyProposalKind::ProtocolAmendment);
        hostile.effects.direct_member_local_authority_mutation = true;
        let proposal = assembly.submit_proposal(hostile).unwrap();
        assert_eq!(proposal.status, AssemblyProposalStatus::ForkRequired);
        assert_eq!(proposal.charter_gate.disposition, CharterGateDisposition::ForkRequired);
        assert!(proposal.charter_gate.violated_invariant_ids.contains(&"local_sovereignty_over_federation_convenience".to_string()));
        assert!(assembly.cast_vote(&proposal.proposal_id, "assembly:alpha", VoteChoice::Yes).is_err());
        let receipt = assembly.finalize(&proposal.proposal_id).unwrap();
        assert_eq!(receipt.outcome, GovernanceOutcome::ForkRequired);
        assert_eq!(receipt.version_path, VersionPath::ForkRequired);
        assert!(!receipt.member_local_authority_mutated);
        assert!(!receipt.protocol_changed_automatically);
        assert_eq!(receipt.authority_effect, "none");
    }

    #[test]
    fn accepted_amendment_creates_receipt_not_execution() {
        let mut assembly = three_member_assembly();
        let proposal = assembly.submit_proposal(draft("assembly:alpha", AssemblyProposalKind::ProtocolAmendment)).unwrap();
        assembly.cast_vote(&proposal.proposal_id, "assembly:alpha", VoteChoice::Yes).unwrap();
        assembly.cast_vote(&proposal.proposal_id, "assembly:beta", VoteChoice::Yes).unwrap();
        let receipt = assembly.finalize(&proposal.proposal_id).unwrap();
        assert_eq!(receipt.outcome, GovernanceOutcome::Accepted);
        assert_eq!(receipt.version_path, VersionPath::CompatibleSourceChangeRequired);
        assert!(receipt.source_change_required);
        assert!(!receipt.protocol_changed_automatically);
        assert!(!receipt.member_local_authority_mutated);
    }

    #[test]
    fn nexus_advisory_report_has_zero_vote_weight() {
        let mut assembly = three_member_assembly();
        let proposal = assembly.submit_proposal(draft("assembly:alpha", AssemblyProposalKind::AdvisoryResolution)).unwrap();
        let advisory = assembly.attach_advisory(&proposal.proposal_id, AdvisorySourceKind::NexusCouncil, Some("fed:qsol:nexus".into()), format!("sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(advisory.vote_weight, 0);
        assembly.cast_vote(&proposal.proposal_id, "assembly:alpha", VoteChoice::Yes).unwrap();
        assembly.cast_vote(&proposal.proposal_id, "assembly:beta", VoteChoice::Yes).unwrap();
        let receipt = assembly.finalize(&proposal.proposal_id).unwrap();
        assert_eq!(receipt.nexus_advisory_reports, 1);
        assert_eq!(receipt.nexus_advisory_vote_weight, 0);
        assert_eq!(receipt.yes_votes, 2);
    }

    #[test]
    fn incompatible_fork_can_be_endorsed_without_rewriting_current_lineage() {
        let mut assembly = three_member_assembly();
        let mut fork = draft("assembly:alpha", AssemblyProposalKind::ForkProposal);
        fork.effects.enable_remote_governance_mutation = true;
        let proposal = assembly.submit_proposal(fork).unwrap();
        assert_eq!(proposal.status, AssemblyProposalStatus::Open);
        assert!(!proposal.charter_gate.current_lineage_eligible);
        assembly.cast_vote(&proposal.proposal_id, "assembly:alpha", VoteChoice::Yes).unwrap();
        assembly.cast_vote(&proposal.proposal_id, "assembly:beta", VoteChoice::Yes).unwrap();
        let receipt = assembly.finalize(&proposal.proposal_id).unwrap();
        assert_eq!(receipt.outcome, GovernanceOutcome::ForkEndorsed);
        assert_eq!(receipt.version_path, VersionPath::ForkRequired);
        assert!(!receipt.protocol_changed_automatically);
        assert!(!receipt.member_local_authority_mutated);
    }

    #[test]
    fn governance_receipt_identity_is_deterministic() {
        fn run() -> AssemblyGovernanceReceipt {
            let mut assembly = three_member_assembly();
            let proposal = assembly.submit_proposal(draft("assembly:alpha", AssemblyProposalKind::ProtocolAmendment)).unwrap();
            assembly.cast_vote(&proposal.proposal_id, "assembly:alpha", VoteChoice::Yes).unwrap();
            assembly.cast_vote(&proposal.proposal_id, "assembly:beta", VoteChoice::Yes).unwrap();
            assembly.finalize(&proposal.proposal_id).unwrap()
        }
        let left = run();
        let right = run();
        assert_eq!(left.receipt_id, right.receipt_id);
        assert_eq!(left, right);
    }
}
