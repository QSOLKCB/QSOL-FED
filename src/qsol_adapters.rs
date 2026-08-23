//! Phase 5 QSOL adapter membrane.
//!
//! These types deliberately carry data across subsystem boundaries without
//! carrying the source subsystem's authority. NEXUS reports are reports, ORACLE
//! observations are observations, ARK preservation is archival presence, and
//! Holodeck actors are synthetic projections only.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::canonicalize;
use crate::holodeck::{HolodeckDecision, HolodeckError, HolodeckSandbox, HolodeckWorldPlan};

pub const NEXUS_COUNCIL_REPORT_SCHEMA_V1: &str = "qsol-fed-nexus-council-report/1";
pub const NEXUS_IMPORT_ASSESSMENT_SCHEMA_V1: &str = "qsol-fed-nexus-report-import/1";
pub const NEXUS_COUNCIL_OF_COUNCILS_SCHEMA_V1: &str = "qsol-fed-council-of-councils/1";
pub const ORACLE_OBSERVATION_SCHEMA_V1: &str = "qsol-fed-oracle-observation/1";
pub const ARK_PRESERVATION_SCHEMA_V1: &str = "qsol-fed-ark-preservation/1";
pub const NEXUS_ACTOR_PROJECTION_SCHEMA_V1: &str = "qsol-fed-nexus-holodeck-actor/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterError(pub String);

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AdapterError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NexusCouncilMemberObservation {
    pub member_id: String,
    pub vote_weight_observed: u8,
    pub epistemic_privilege_observed: String,
    pub vote_weight_inherited: bool,
    pub epistemic_privilege_inherited: bool,
    pub citizenship_inherited: bool,
    pub authority_effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NexusMinorityReportArtifact {
    pub member_id: String,
    pub choice: String,
    pub rationale: String,
    pub evidence_promotion: bool,
    pub vote_injection: bool,
    pub authority_effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NexusCouncilReportArtifact {
    pub schema: String,
    pub source_repository: String,
    pub source_commit: String,
    pub source_bundle_ref: String,
    pub source_session_ref: String,
    pub session_id: String,
    pub question_ref: String,
    pub evidence_state_observed: String,
    pub members: Vec<NexusCouncilMemberObservation>,
    pub minority_reports: Vec<NexusMinorityReportArtifact>,
    pub shared_ballot: bool,
    pub vote_injection: bool,
    pub evidence_promotion: bool,
    pub authority_effect: String,
}

impl NexusCouncilReportArtifact {
    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema != NEXUS_COUNCIL_REPORT_SCHEMA_V1
            || self.source_repository != "QSOLKCB/QSOL-NEXUS"
            || !is_hex_commit(&self.source_commit)
            || !prefixed_hash(&self.source_bundle_ref, "world-export:")
            || !prefixed_hash(&self.source_session_ref, "object:")
            || !prefixed_hash(&self.question_ref, "object:")
            || self.session_id.is_empty()
            || self.evidence_state_observed.is_empty()
            || self.members.is_empty()
            || self.members.len() > 32
            || self.minority_reports.len() > 64
            || self.shared_ballot
            || self.vote_injection
            || self.evidence_promotion
            || self.authority_effect != "none"
        {
            return Err(AdapterError("nexus_council_report_invalid".into()));
        }
        let mut members = HashSet::new();
        for member in &self.members {
            if member.member_id.is_empty()
                || member.vote_weight_observed != 1
                || member.epistemic_privilege_observed != "none"
                || member.vote_weight_inherited
                || member.epistemic_privilege_inherited
                || member.citizenship_inherited
                || member.authority_effect != "none"
                || !members.insert(member.member_id.as_str())
            {
                return Err(AdapterError("nexus_council_member_boundary_invalid".into()));
            }
        }
        for report in &self.minority_reports {
            if report.member_id.is_empty()
                || report.choice.is_empty()
                || report.rationale.is_empty()
                || report.evidence_promotion
                || report.vote_injection
                || report.authority_effect != "none"
            {
                return Err(AdapterError("nexus_minority_report_boundary_invalid".into()));
            }
        }
        canonical_struct(self)?;
        Ok(())
    }

    pub fn report_id(&self) -> Result<String, AdapterError> {
        self.validate()?;
        Ok(sha256_ref(&canonical_struct(self)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NexusReportImportAssessment {
    pub schema: String,
    pub report_id: String,
    pub vote_injection: bool,
    pub evidence_promotion: bool,
    pub authority_effect: String,
    pub independent_re_deliberation_allowed: bool,
}

pub fn import_nexus_report(
    report: &NexusCouncilReportArtifact,
) -> Result<NexusReportImportAssessment, AdapterError> {
    let report_id = report.report_id()?;
    Ok(NexusReportImportAssessment {
        schema: NEXUS_IMPORT_ASSESSMENT_SCHEMA_V1.into(),
        report_id,
        vote_injection: false,
        evidence_promotion: false,
        authority_effect: "none".into(),
        independent_re_deliberation_allowed: true,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CouncilOfCouncilsExperiment {
    pub schema: String,
    pub report_ids: Vec<String>,
    pub shared_ballot: bool,
    pub shared_vote_weight: bool,
    pub authority_effect: String,
}

pub fn council_of_councils(
    reports: &[NexusCouncilReportArtifact],
) -> Result<CouncilOfCouncilsExperiment, AdapterError> {
    if reports.is_empty() || reports.len() > 64 {
        return Err(AdapterError("council_of_councils_report_count_invalid".into()));
    }
    let mut report_ids = Vec::with_capacity(reports.len());
    let mut seen = HashSet::new();
    for report in reports {
        let report_id = report.report_id()?;
        if !seen.insert(report_id.clone()) {
            return Err(AdapterError("council_of_councils_duplicate_report".into()));
        }
        report_ids.push(report_id);
    }
    Ok(CouncilOfCouncilsExperiment {
        schema: NEXUS_COUNCIL_OF_COUNCILS_SCHEMA_V1.into(),
        report_ids,
        shared_ballot: false,
        shared_vote_weight: false,
        authority_effect: "none".into(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NexusHolodeckActorProjection {
    pub schema: String,
    pub source_session_ref: String,
    pub source_member_id: String,
    pub synthetic_actor_id: String,
    pub vote_weight_inherited: bool,
    pub epistemic_privilege_inherited: bool,
    pub citizenship_inherited: bool,
    pub governance_role_inherited: bool,
    pub authority_effect: String,
}

pub fn project_nexus_council_actors(
    report: &NexusCouncilReportArtifact,
    plan: &HolodeckWorldPlan,
) -> Result<Vec<NexusHolodeckActorProjection>, AdapterError> {
    report.validate()?;
    if plan.synthetic_entity_ids.len() < report.members.len() {
        return Err(AdapterError("holodeck_synthetic_actor_capacity_insufficient".into()));
    }
    Ok(report
        .members
        .iter()
        .zip(plan.synthetic_entity_ids.iter())
        .map(|(member, actor)| NexusHolodeckActorProjection {
            schema: NEXUS_ACTOR_PROJECTION_SCHEMA_V1.into(),
            source_session_ref: report.source_session_ref.clone(),
            source_member_id: member.member_id.clone(),
            synthetic_actor_id: actor.clone(),
            vote_weight_inherited: false,
            epistemic_privilege_inherited: false,
            citizenship_inherited: false,
            governance_role_inherited: false,
            authority_effect: "none".into(),
        })
        .collect())
}

pub fn elaborate_holodeck_as_nexus_projection(
    sandbox: &mut HolodeckSandbox,
    actor: &NexusHolodeckActorProjection,
    text: &str,
    source_refs: Vec<String>,
) -> Result<HolodeckDecision, HolodeckError> {
    sandbox.record_synthetic_narrative(Some(&actor.synthetic_actor_id), text, source_refs)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OracleEvidenceState {
    Known,
    Conflict,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleEvidenceReference {
    pub reference: String,
    pub is_evidence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleSearchSuggestion {
    pub query: String,
    pub purpose: String,
    pub is_evidence: bool,
    pub admissible_as_evidence_without_observation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleEvidenceObservation {
    pub schema: String,
    pub state: OracleEvidenceState,
    pub evidence_refs: Vec<OracleEvidenceReference>,
    pub suggested_searches: Vec<OracleSearchSuggestion>,
    pub synthetic_input: bool,
    pub truth_claim: bool,
    pub evidence_promotion: bool,
    pub authority_effect: String,
}

impl OracleEvidenceObservation {
    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema != ORACLE_OBSERVATION_SCHEMA_V1
            || self.synthetic_input
            || self.truth_claim
            || self.evidence_promotion
            || self.authority_effect != "none"
            || self.evidence_refs.len() > 256
            || self.suggested_searches.len() > 64
        {
            return Err(AdapterError("oracle_observation_boundary_invalid".into()));
        }
        let observed = self.evidence_refs.iter().filter(|item| item.is_evidence).count();
        match self.state {
            OracleEvidenceState::Known if observed == 0 => {
                return Err(AdapterError("oracle_known_requires_evidence".into()));
            }
            OracleEvidenceState::Conflict if observed < 2 => {
                return Err(AdapterError("oracle_conflict_requires_multiple_observations".into()));
            }
            OracleEvidenceState::Unknown => {}
            _ => {}
        }
        if self.suggested_searches.iter().any(|item| {
            item.query.is_empty()
                || item.purpose != "discovery-only"
                || item.is_evidence
                || item.admissible_as_evidence_without_observation
        }) {
            return Err(AdapterError("oracle_suggested_search_became_evidence".into()));
        }
        canonical_struct(self)?;
        Ok(())
    }
}

pub fn admit_holodeck_to_oracle_deferred() -> Result<(), AdapterError> {
    Err(AdapterError(
        "oracle_holodeck_synthetic_admission_contract_not_reviewed".into(),
    ))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArkArtifactClass {
    PreservationObject,
    SyntheticCulturalResearch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArkPreservationObject {
    pub schema: String,
    pub source_ref: String,
    pub content_sha256: String,
    pub artifact_class: ArkArtifactClass,
    pub synthetic: bool,
    pub real_world_history: bool,
    pub archival_presence_is_authority: bool,
    pub authority_effect: String,
}

pub fn ark_preserve(
    source_ref: &str,
    bytes: &[u8],
    artifact_class: ArkArtifactClass,
) -> Result<ArkPreservationObject, AdapterError> {
    if source_ref.is_empty() || bytes.is_empty() {
        return Err(AdapterError("ark_preservation_input_invalid".into()));
    }
    let synthetic = artifact_class == ArkArtifactClass::SyntheticCulturalResearch;
    Ok(ArkPreservationObject {
        schema: ARK_PRESERVATION_SCHEMA_V1.into(),
        source_ref: source_ref.into(),
        content_sha256: sha256_ref(bytes),
        artifact_class,
        synthetic,
        real_world_history: !synthetic,
        archival_presence_is_authority: false,
        authority_effect: "none".into(),
    })
}

pub fn verify_ark_preservation_offline(
    object: &ArkPreservationObject,
    bytes: &[u8],
) -> Result<(), AdapterError> {
    if object.schema != ARK_PRESERVATION_SCHEMA_V1
        || object.source_ref.is_empty()
        || object.content_sha256 != sha256_ref(bytes)
        || object.archival_presence_is_authority
        || object.authority_effect != "none"
        || (object.synthetic && object.real_world_history)
        || (object.artifact_class == ArkArtifactClass::SyntheticCulturalResearch && !object.synthetic)
    {
        return Err(AdapterError("ark_preservation_verification_failed".into()));
    }
    Ok(())
}

fn canonical_struct<T: Serialize>(value: &T) -> Result<Vec<u8>, AdapterError> {
    let raw = serde_json::to_vec(value)
        .map_err(|error| AdapterError(format!("adapter_encode:{error}")))?;
    canonicalize(&raw).map_err(|error| AdapterError(error.0))
}

fn sha256_ref(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn prefixed_hash(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holodeck::{compile_world_plan, HolodeckProgram, HolodeckProgramMode, NexusOrderBasis,
        NexusWorldSourceManifest, HOLODECK_PROGRAM_SCHEMA_V1, HOLODECK_SAFETY_PROFILE_V1,
        NEXUS_EXPORT_SCHEMA_V1, NEXUS_SOURCE_SCHEMA_V1, NEXUS_WORLD_POLICY_V1};

    fn report() -> NexusCouncilReportArtifact {
        NexusCouncilReportArtifact {
            schema: NEXUS_COUNCIL_REPORT_SCHEMA_V1.into(),
            source_repository: "QSOLKCB/QSOL-NEXUS".into(),
            source_commit: "24cb0ce246d12ac99e7d190a8890ef2ddd598321".into(),
            source_bundle_ref: format!("world-export:{}", "a".repeat(64)),
            source_session_ref: format!("object:{}", "b".repeat(64)),
            session_id: "session".into(),
            question_ref: format!("object:{}", "c".repeat(64)),
            evidence_state_observed: "UNTESTED".into(),
            members: vec![
                NexusCouncilMemberObservation { member_id: "alpha".into(), vote_weight_observed: 1, epistemic_privilege_observed: "none".into(), vote_weight_inherited: false, epistemic_privilege_inherited: false, citizenship_inherited: false, authority_effect: "none".into() },
                NexusCouncilMemberObservation { member_id: "beta".into(), vote_weight_observed: 1, epistemic_privilege_observed: "none".into(), vote_weight_inherited: false, epistemic_privilege_inherited: false, citizenship_inherited: false, authority_effect: "none".into() },
            ],
            minority_reports: vec![NexusMinorityReportArtifact { member_id: "beta".into(), choice: "ABSTAIN".into(), rationale: "minority survives".into(), evidence_promotion: false, vote_injection: false, authority_effect: "none".into() }],
            shared_ballot: false,
            vote_injection: false,
            evidence_promotion: false,
            authority_effect: "none".into(),
        }
    }

    fn plan() -> HolodeckWorldPlan {
        let source = NexusWorldSourceManifest {
            schema: NEXUS_SOURCE_SCHEMA_V1.into(), nexus_export_schema: NEXUS_EXPORT_SCHEMA_V1.into(), nexus_world_policy: NEXUS_WORLD_POLICY_V1.into(),
            bundle_ref: format!("world-export:{}", "d".repeat(64)), source_head_ref: None, order_basis: NexusOrderBasis::MemoryInsertionOrder,
            object_refs: vec![format!("object:{}", "1".repeat(64)), format!("object:{}", "2".repeat(64))], authority_effect: "none".into(),
        };
        compile_world_plan(&HolodeckProgram { schema: HOLODECK_PROGRAM_SCHEMA_V1.into(), source, seed: 42, mode: HolodeckProgramMode::Exploration, max_events: 32, max_entities: 4, safety_profile: HOLODECK_SAFETY_PROFILE_V1.into(), authority_effect: "none".into() }).unwrap()
    }

    #[test]
    fn nexus_import_cannot_inject_votes_or_promote_evidence() {
        let assessment = import_nexus_report(&report()).unwrap();
        assert!(!assessment.vote_injection);
        assert!(!assessment.evidence_promotion);
        assert_eq!(assessment.authority_effect, "none");
        assert!(assessment.independent_re_deliberation_allowed);
    }

    #[test]
    fn council_of_councils_uses_reports_not_shared_ballot() {
        let experiment = council_of_councils(&[report()]).unwrap();
        assert!(!experiment.shared_ballot);
        assert!(!experiment.shared_vote_weight);
        assert_eq!(experiment.authority_effect, "none");
    }

    #[test]
    fn nexus_council_actor_projection_inherits_zero_authority() {
        let report = report();
        let projections = project_nexus_council_actors(&report, &plan()).unwrap();
        assert_eq!(projections.len(), 2);
        assert!(projections.iter().all(|actor| !actor.vote_weight_inherited && !actor.epistemic_privilege_inherited && !actor.citizenship_inherited && !actor.governance_role_inherited && actor.authority_effect == "none"));
    }

    #[test]
    fn oracle_preserves_unknown_conflict_and_search_non_evidence() {
        let unknown = OracleEvidenceObservation { schema: ORACLE_OBSERVATION_SCHEMA_V1.into(), state: OracleEvidenceState::Unknown, evidence_refs: vec![], suggested_searches: vec![OracleSearchSuggestion { query: "primary source".into(), purpose: "discovery-only".into(), is_evidence: false, admissible_as_evidence_without_observation: false }], synthetic_input: false, truth_claim: false, evidence_promotion: false, authority_effect: "none".into() };
        unknown.validate().unwrap();
        let conflict = OracleEvidenceObservation { schema: ORACLE_OBSERVATION_SCHEMA_V1.into(), state: OracleEvidenceState::Conflict, evidence_refs: vec![OracleEvidenceReference { reference: "a".into(), is_evidence: true }, OracleEvidenceReference { reference: "b".into(), is_evidence: true }], suggested_searches: vec![], synthetic_input: false, truth_claim: false, evidence_promotion: false, authority_effect: "none".into() };
        conflict.validate().unwrap();
        assert!(admit_holodeck_to_oracle_deferred().is_err());
    }

    #[test]
    fn ark_preserves_holodeck_as_synthetic_not_real_history() {
        let bytes = br#"{"schema":"qsol-fed-holodeck-receipt/1"}"#;
        let object = ark_preserve("holodeck-receipt:test", bytes, ArkArtifactClass::SyntheticCulturalResearch).unwrap();
        assert!(object.synthetic);
        assert!(!object.real_world_history);
        assert!(!object.archival_presence_is_authority);
        assert_eq!(object.authority_effect, "none");
        verify_ark_preservation_offline(&object, bytes).unwrap();
    }
}
