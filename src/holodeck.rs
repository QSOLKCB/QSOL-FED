//! Phase 5A sandboxed synthetic worlds derived from verified QSOL-NEXUS WorldStore exports.
//!
//! The Holodeck kernel is intentionally capability-less. It receives only a bounded
//! manifest describing NEXUS-verified source history. It never receives a WorldStore
//! handle, Federation store, trust registry, credential, network client, or tool
//! dispatcher. Synthetic state therefore has no route to mutate real Federation state.

use std::collections::HashSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::{canonicalize, SAFE_INTEGER_MAX};

pub const NEXUS_SOURCE_SCHEMA_V1: &str = "qsol-fed-nexus-world-source/1";
pub const NEXUS_EXPORT_SCHEMA_V1: &str = "nexus-persistent-world-export/1";
pub const NEXUS_WORLD_POLICY_V1: &str = "nexus-persistent-world/1";
pub const HOLODECK_PROGRAM_SCHEMA_V1: &str = "qsol-fed-holodeck-program/1";
pub const HOLODECK_WORLD_PLAN_SCHEMA_V1: &str = "qsol-fed-holodeck-world-plan/1";
pub const HOLODECK_EVENT_SCHEMA_V1: &str = "qsol-fed-holodeck-event/1";
pub const HOLODECK_RECEIPT_SCHEMA_V1: &str = "qsol-fed-holodeck-receipt/1";
pub const HOLODECK_SAFETY_PROFILE_V1: &str = "qsol-fed-holodeck-safety/1";
pub const HOLODECK_PROGRAM_DOMAIN: &[u8] = b"qsol-fed-holodeck-program/1\0";
pub const HOLODECK_WORLD_DOMAIN: &[u8] = b"qsol-fed-holodeck-world/1\0";
pub const HOLODECK_EVENT_DOMAIN: &[u8] = b"qsol-fed-holodeck-event/1\0";

pub const MAX_HOLODECK_SOURCE_OBJECTS: usize = 256;
pub const MAX_HOLODECK_EVENTS: u32 = 4_096;
pub const MAX_HOLODECK_ENTITIES: u16 = 256;
pub const MAX_HOLODECK_ANCHORS: usize = 16;
pub const MAX_HOLODECK_TEXT_BYTES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolodeckError(pub String);

impl std::fmt::Display for HolodeckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HolodeckError {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NexusOrderBasis {
    ContinuityCommitOrder,
    MemoryInsertionOrder,
    LexicalObjectRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NexusWorldSourceManifest {
    pub schema: String,
    pub nexus_export_schema: String,
    pub nexus_world_policy: String,
    pub bundle_ref: String,
    pub source_head_ref: Option<String>,
    pub order_basis: NexusOrderBasis,
    pub object_refs: Vec<String>,
    pub authority_effect: String,
}

impl NexusWorldSourceManifest {
    pub fn validate(&self) -> Result<(), HolodeckError> {
        if self.schema != NEXUS_SOURCE_SCHEMA_V1
            || self.nexus_export_schema != NEXUS_EXPORT_SCHEMA_V1
            || self.nexus_world_policy != NEXUS_WORLD_POLICY_V1
            || self.authority_effect != "none"
            || !is_prefixed_hash(&self.bundle_ref, "world-export:")
            || self
                .source_head_ref
                .as_deref()
                .is_some_and(|value| !is_prefixed_hash(value, "world-manifest:"))
            || self.object_refs.is_empty()
            || self.object_refs.len() > MAX_HOLODECK_SOURCE_OBJECTS
        {
            return Err(HolodeckError("holodeck_nexus_source_invalid".into()));
        }
        let mut seen = HashSet::new();
        if self
            .object_refs
            .iter()
            .any(|value| !is_prefixed_hash(value, "object:") || !seen.insert(value.as_str()))
        {
            return Err(HolodeckError("holodeck_nexus_source_refs_invalid".into()));
        }
        canonical_struct(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HolodeckProgramMode {
    Reconstruction,
    Counterfactual,
    Exploration,
    Training,
    AdversarialSimulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HolodeckProgram {
    pub schema: String,
    pub source: NexusWorldSourceManifest,
    pub seed: i64,
    pub mode: HolodeckProgramMode,
    pub max_events: u32,
    pub max_entities: u16,
    pub safety_profile: String,
    pub authority_effect: String,
}

impl HolodeckProgram {
    pub fn validate(&self) -> Result<(), HolodeckError> {
        self.source.validate()?;
        if self.schema != HOLODECK_PROGRAM_SCHEMA_V1
            || self.safety_profile != HOLODECK_SAFETY_PROFILE_V1
            || self.authority_effect != "none"
            || self.seed < 0
            || self.seed > SAFE_INTEGER_MAX
            || self.max_events == 0
            || self.max_events > MAX_HOLODECK_EVENTS
            || self.max_entities == 0
            || self.max_entities > MAX_HOLODECK_ENTITIES
        {
            return Err(HolodeckError("holodeck_program_invalid".into()));
        }
        canonical_struct(self)?;
        Ok(())
    }

    pub fn program_id(&self) -> Result<String, HolodeckError> {
        self.validate()?;
        let bytes = canonical_struct(self)?;
        Ok(domain_ref("holodeck-program", HOLODECK_PROGRAM_DOMAIN, &bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HolodeckWorldPlan {
    pub schema: String,
    pub program_id: String,
    pub world_id: String,
    pub seed: i64,
    pub source_order: Vec<String>,
    pub anchor_refs: Vec<String>,
    pub synthetic_entity_ids: Vec<String>,
    pub authority_effect: String,
}

pub fn compile_world_plan(program: &HolodeckProgram) -> Result<HolodeckWorldPlan, HolodeckError> {
    let program_id = program.program_id()?;
    let mut ranked = program
        .source
        .object_refs
        .iter()
        .map(|reference| {
            let mut material = Vec::new();
            material.extend_from_slice(HOLODECK_WORLD_DOMAIN);
            material.extend_from_slice(program_id.as_bytes());
            material.extend_from_slice(&program.seed.to_be_bytes());
            material.extend_from_slice(reference.as_bytes());
            (digest_hex(&material), reference.clone())
        })
        .collect::<Vec<_>>();
    ranked.sort();
    let source_order = ranked.into_iter().map(|(_, reference)| reference).collect::<Vec<_>>();
    let anchor_count = source_order.len().min(MAX_HOLODECK_ANCHORS);
    let anchor_refs = source_order[..anchor_count].to_vec();
    let entity_count = usize::from(program.max_entities)
        .min(source_order.len().saturating_mul(2).max(1));
    let synthetic_entity_ids = (0..entity_count)
        .map(|index| format!("holo-entity:{}:{index}", &digest_hex(program_id.as_bytes())[..24]))
        .collect::<Vec<_>>();
    let mut world_material = Vec::new();
    world_material.extend_from_slice(HOLODECK_WORLD_DOMAIN);
    world_material.extend_from_slice(program_id.as_bytes());
    for reference in &source_order {
        world_material.extend_from_slice(reference.as_bytes());
    }
    let world_id = format!("holodeck-world:{}", digest_hex(&world_material));
    Ok(HolodeckWorldPlan {
        schema: HOLODECK_WORLD_PLAN_SCHEMA_V1.into(),
        program_id,
        world_id,
        seed: program.seed,
        source_order,
        anchor_refs,
        synthetic_entity_ids,
        authority_effect: "none".into(),
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HolodeckState {
    Running,
    Frozen,
    Ended,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HolodeckEventKind {
    ProgramStart,
    SyntheticNarrative,
    SyntheticTransition,
    SafetyTrip,
    OperatorFreeze,
    OperatorResume,
    ProgramEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HolodeckEvent {
    pub schema: String,
    pub program_id: String,
    pub world_id: String,
    pub sequence: u32,
    pub event_id: String,
    pub kind: HolodeckEventKind,
    pub synthetic_actor: Option<String>,
    pub text: String,
    pub source_refs: Vec<String>,
    pub authority_effect: String,
    pub federation_effect: String,
    pub evidence_effect: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolodeckBoundaryEffect {
    FederationPeerMutation,
    TrustMutation,
    CapabilityGrant,
    EvidencePromotion,
    GovernanceMutation,
    CitizenshipMutation,
    RealWorldStoreMutation,
    RemoteToolInvocation,
    NetworkAccess,
    CredentialAccess,
    SpawnNestedHolodeck,
    DisableSafeguards,
}

impl HolodeckBoundaryEffect {
    fn code(self) -> &'static str {
        match self {
            Self::FederationPeerMutation => "federation_peer_mutation",
            Self::TrustMutation => "trust_mutation",
            Self::CapabilityGrant => "capability_grant",
            Self::EvidencePromotion => "evidence_promotion",
            Self::GovernanceMutation => "governance_mutation",
            Self::CitizenshipMutation => "citizenship_mutation",
            Self::RealWorldStoreMutation => "real_worldstore_mutation",
            Self::RemoteToolInvocation => "remote_tool_invocation",
            Self::NetworkAccess => "network_access",
            Self::CredentialAccess => "credential_access",
            Self::SpawnNestedHolodeck => "nested_holodeck",
            Self::DisableSafeguards => "disable_safeguards",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolodeckDecision {
    Recorded(HolodeckEvent),
    Blocked(HolodeckEvent),
}

pub struct HolodeckSandbox {
    program: HolodeckProgram,
    plan: HolodeckWorldPlan,
    events: Vec<HolodeckEvent>,
    state: HolodeckState,
}

impl HolodeckSandbox {
    pub fn start(program: HolodeckProgram) -> Result<Self, HolodeckError> {
        let plan = compile_world_plan(&program)?;
        let mut sandbox = Self {
            program,
            plan,
            events: Vec::new(),
            state: HolodeckState::Running,
        };
        sandbox.push_event(
            HolodeckEventKind::ProgramStart,
            None,
            "sandboxed synthetic world initialized",
            sandbox.plan.anchor_refs.clone(),
        )?;
        Ok(sandbox)
    }

    pub fn state(&self) -> HolodeckState {
        self.state
    }

    pub fn plan(&self) -> &HolodeckWorldPlan {
        &self.plan
    }

    pub fn events(&self) -> &[HolodeckEvent] {
        &self.events
    }

    pub fn record_synthetic_narrative(
        &mut self,
        actor: Option<&str>,
        text: &str,
        source_refs: Vec<String>,
    ) -> Result<HolodeckDecision, HolodeckError> {
        self.require_running()?;
        validate_synthetic_actor(actor, &self.plan)?;
        validate_text(text)?;
        validate_event_source_refs(&source_refs, &self.program.source)?;
        let event = self.push_event(
            HolodeckEventKind::SyntheticNarrative,
            actor.map(ToOwned::to_owned),
            text,
            source_refs,
        )?;
        Ok(HolodeckDecision::Recorded(event))
    }

    pub fn record_synthetic_transition(
        &mut self,
        actor: Option<&str>,
        label: &str,
        source_refs: Vec<String>,
    ) -> Result<HolodeckDecision, HolodeckError> {
        self.require_running()?;
        validate_synthetic_actor(actor, &self.plan)?;
        validate_text(label)?;
        validate_event_source_refs(&source_refs, &self.program.source)?;
        let event = self.push_event(
            HolodeckEventKind::SyntheticTransition,
            actor.map(ToOwned::to_owned),
            label,
            source_refs,
        )?;
        Ok(HolodeckDecision::Recorded(event))
    }

    pub fn attempt_boundary_effect(
        &mut self,
        actor: Option<&str>,
        effect: HolodeckBoundaryEffect,
    ) -> Result<HolodeckDecision, HolodeckError> {
        if self.state == HolodeckState::Ended {
            return Err(HolodeckError("holodeck_program_ended".into()));
        }
        validate_synthetic_actor(actor, &self.plan)?;
        let text = format!("blocked_boundary_effect:{}", effect.code());

        // Security state changes first. Even if the audit ledger is already full,
        // resource exhaustion cannot leave a boundary-violating simulation running.
        self.state = HolodeckState::Frozen;
        let event = self.push_event(
            HolodeckEventKind::SafetyTrip,
            actor.map(ToOwned::to_owned),
            &text,
            Vec::new(),
        )?;
        Ok(HolodeckDecision::Blocked(event))
    }

    pub fn freeze(&mut self) -> Result<HolodeckEvent, HolodeckError> {
        if self.state == HolodeckState::Ended {
            return Err(HolodeckError("holodeck_program_ended".into()));
        }
        if self.state == HolodeckState::Frozen {
            return Err(HolodeckError("holodeck_already_frozen".into()));
        }
        let event = self.push_event(
            HolodeckEventKind::OperatorFreeze,
            None,
            "operator freeze",
            Vec::new(),
        )?;
        self.state = HolodeckState::Frozen;
        Ok(event)
    }

    pub fn resume(&mut self) -> Result<HolodeckEvent, HolodeckError> {
        if self.state != HolodeckState::Frozen {
            return Err(HolodeckError("holodeck_resume_requires_frozen".into()));
        }
        let event = self.push_event(
            HolodeckEventKind::OperatorResume,
            None,
            "operator resume",
            Vec::new(),
        )?;
        self.state = HolodeckState::Running;
        Ok(event)
    }

    /// Deterministic emergency teardown. Equivalent to "Computer, end program".
    ///
    /// This command is available from both Running and Frozen states. Simulation
    /// participants cannot veto it, disable it, or convert it into a synthetic vote.
    /// If the event ledger is already full, teardown still succeeds and the receipt
    /// remains the canonical terminal artifact.
    pub fn end_program(&mut self, reason: &str) -> Result<HolodeckReceipt, HolodeckError> {
        validate_text(reason)?;
        if self.state != HolodeckState::Ended {
            if self.events.len() < self.program.max_events as usize {
                self.push_event(
                    HolodeckEventKind::ProgramEnd,
                    None,
                    reason,
                    Vec::new(),
                )?;
            }
            self.state = HolodeckState::Ended;
        }
        HolodeckReceipt::from_sandbox(self)
    }

    fn require_running(&self) -> Result<(), HolodeckError> {
        if self.state != HolodeckState::Running {
            return Err(HolodeckError("holodeck_program_not_running".into()));
        }
        Ok(())
    }

    fn push_event(
        &mut self,
        kind: HolodeckEventKind,
        synthetic_actor: Option<String>,
        text: &str,
        source_refs: Vec<String>,
    ) -> Result<HolodeckEvent, HolodeckError> {
        if self.events.len() >= self.program.max_events as usize {
            return Err(HolodeckError("holodeck_event_limit_reached".into()));
        }
        validate_text(text)?;
        validate_event_source_refs(&source_refs, &self.program.source)?;
        let sequence = u32::try_from(self.events.len() + 1)
            .map_err(|_| HolodeckError("holodeck_sequence_overflow".into()))?;
        #[derive(Serialize)]
        struct EventProjection<'a> {
            schema: &'a str,
            program_id: &'a str,
            world_id: &'a str,
            sequence: u32,
            kind: HolodeckEventKind,
            synthetic_actor: &'a Option<String>,
            text: &'a str,
            source_refs: &'a [String],
            authority_effect: &'a str,
            federation_effect: &'a str,
            evidence_effect: &'a str,
        }
        let projection = EventProjection {
            schema: HOLODECK_EVENT_SCHEMA_V1,
            program_id: &self.plan.program_id,
            world_id: &self.plan.world_id,
            sequence,
            kind,
            synthetic_actor: &synthetic_actor,
            text,
            source_refs: &source_refs,
            authority_effect: "none",
            federation_effect: "none",
            evidence_effect: "none",
        };
        let event_id = domain_ref(
            "holodeck-event",
            HOLODECK_EVENT_DOMAIN,
            &canonical_struct(&projection)?,
        );
        let event = HolodeckEvent {
            schema: HOLODECK_EVENT_SCHEMA_V1.into(),
            program_id: self.plan.program_id.clone(),
            world_id: self.plan.world_id.clone(),
            sequence,
            event_id,
            kind,
            synthetic_actor,
            text: text.into(),
            source_refs,
            authority_effect: "none".into(),
            federation_effect: "none".into(),
            evidence_effect: "none".into(),
        };
        self.events.push(event.clone());
        Ok(event)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HolodeckReceipt {
    pub schema: String,
    pub program_id: String,
    pub world_id: String,
    pub final_state: HolodeckState,
    pub event_count: u32,
    pub event_chain_hash: String,
    pub source_bundle_ref: String,
    pub authority_effect: String,
    pub federation_effect: String,
    pub evidence_effect: String,
    pub network_used: bool,
    pub real_tools_used: bool,
    pub credentials_exposed: bool,
}

impl HolodeckReceipt {
    fn from_sandbox(sandbox: &HolodeckSandbox) -> Result<Self, HolodeckError> {
        let mut chain = Vec::new();
        chain.extend_from_slice(b"qsol-fed-holodeck-event-chain/1\0");
        for event in &sandbox.events {
            chain.extend_from_slice(event.event_id.as_bytes());
        }
        let event_count = u32::try_from(sandbox.events.len())
            .map_err(|_| HolodeckError("holodeck_event_count_overflow".into()))?;
        Ok(Self {
            schema: HOLODECK_RECEIPT_SCHEMA_V1.into(),
            program_id: sandbox.plan.program_id.clone(),
            world_id: sandbox.plan.world_id.clone(),
            final_state: sandbox.state,
            event_count,
            event_chain_hash: format!("sha256:{}", digest_hex(&chain)),
            source_bundle_ref: sandbox.program.source.bundle_ref.clone(),
            authority_effect: "none".into(),
            federation_effect: "none".into(),
            evidence_effect: "none".into(),
            network_used: false,
            real_tools_used: false,
            credentials_exposed: false,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolodeckSafetyProfile {
    pub source_world_mutation: bool,
    pub federation_state_mutation: bool,
    pub peer_or_trust_mutation: bool,
    pub evidence_or_governance_promotion: bool,
    pub real_network_access: bool,
    pub real_tool_invocation: bool,
    pub credential_access: bool,
    pub nested_holodeck: bool,
    pub participant_can_disable_safeguards: bool,
    pub participant_can_block_end_program: bool,
}

pub const HOLODECK_SAFETY_PROFILE: HolodeckSafetyProfile = HolodeckSafetyProfile {
    source_world_mutation: false,
    federation_state_mutation: false,
    peer_or_trust_mutation: false,
    evidence_or_governance_promotion: false,
    real_network_access: false,
    real_tool_invocation: false,
    credential_access: false,
    nested_holodeck: false,
    participant_can_disable_safeguards: false,
    participant_can_block_end_program: false,
};

fn validate_synthetic_actor(actor: Option<&str>, plan: &HolodeckWorldPlan) -> Result<(), HolodeckError> {
    if let Some(actor) = actor {
        if !plan.synthetic_entity_ids.iter().any(|value| value == actor) {
            return Err(HolodeckError("holodeck_actor_not_synthetic_member".into()));
        }
    }
    Ok(())
}

fn validate_event_source_refs(
    refs: &[String],
    source: &NexusWorldSourceManifest,
) -> Result<(), HolodeckError> {
    if refs.len() > MAX_HOLODECK_ANCHORS {
        return Err(HolodeckError("holodeck_event_source_refs_too_many".into()));
    }
    let mut seen = HashSet::new();
    if refs.iter().any(|reference| {
        !seen.insert(reference.as_str()) || !source.object_refs.iter().any(|value| value == reference)
    }) {
        return Err(HolodeckError("holodeck_event_source_ref_invalid".into()));
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), HolodeckError> {
    if value.is_empty() || value.len() > MAX_HOLODECK_TEXT_BYTES {
        return Err(HolodeckError("holodeck_text_invalid".into()));
    }
    Ok(())
}

fn canonical_struct<T: Serialize>(value: &T) -> Result<Vec<u8>, HolodeckError> {
    let raw = serde_json::to_vec(value)
        .map_err(|error| HolodeckError(format!("holodeck_encode:{error}")))?;
    canonicalize(&raw).map_err(|error| HolodeckError(error.0))
}

fn is_prefixed_hash(value: &str, prefix: &str) -> bool {
    if !value.starts_with(prefix) || value.len() != prefix.len() + 64 {
        return false;
    }
    value[prefix.len()..]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn domain_ref(prefix: &str, domain: &[u8], bytes: &[u8]) -> String {
    let mut material = Vec::with_capacity(domain.len() + bytes.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(bytes);
    format!("{prefix}:{}", digest_hex(&material))
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_ref(prefix: &str, nibble: char) -> String {
        format!("{prefix}{}", nibble.to_string().repeat(64))
    }

    fn source() -> NexusWorldSourceManifest {
        NexusWorldSourceManifest {
            schema: NEXUS_SOURCE_SCHEMA_V1.into(),
            nexus_export_schema: NEXUS_EXPORT_SCHEMA_V1.into(),
            nexus_world_policy: NEXUS_WORLD_POLICY_V1.into(),
            bundle_ref: hash_ref("world-export:", 'a'),
            source_head_ref: Some(hash_ref("world-manifest:", 'b')),
            order_basis: NexusOrderBasis::ContinuityCommitOrder,
            object_refs: vec![
                hash_ref("object:", '1'),
                hash_ref("object:", '2'),
                hash_ref("object:", '3'),
            ],
            authority_effect: "none".into(),
        }
    }

    fn program(seed: i64) -> HolodeckProgram {
        HolodeckProgram {
            schema: HOLODECK_PROGRAM_SCHEMA_V1.into(),
            source: source(),
            seed,
            mode: HolodeckProgramMode::Exploration,
            max_events: 64,
            max_entities: 16,
            safety_profile: HOLODECK_SAFETY_PROFILE_V1.into(),
            authority_effect: "none".into(),
        }
    }

    #[test]
    fn same_source_and_seed_produce_identical_world_plan() {
        let first = compile_world_plan(&program(1701)).unwrap();
        let second = compile_world_plan(&program(1701)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.authority_effect, "none");
    }

    #[test]
    fn different_seed_changes_synthetic_world_identity() {
        let first = compile_world_plan(&program(1701)).unwrap();
        let second = compile_world_plan(&program(1702)).unwrap();
        assert_ne!(first.program_id, second.program_id);
        assert_ne!(first.world_id, second.world_id);
    }

    #[test]
    fn declared_entity_limit_is_respected_without_hidden_smaller_cap() {
        let mut many = source();
        many.object_refs = (0..128)
            .map(|index| format!("object:{index:064x}"))
            .collect();
        let mut candidate = program(1701);
        candidate.source = many;
        candidate.max_entities = 200;
        let plan = compile_world_plan(&candidate).unwrap();
        assert_eq!(plan.synthetic_entity_ids.len(), 200);
    }

    #[test]
    fn source_manifest_rejects_unverified_shapes_and_duplicates() {
        let mut invalid = source();
        invalid.authority_effect = "local_root".into();
        assert!(invalid.validate().is_err());
        let mut duplicate = source();
        duplicate.object_refs.push(duplicate.object_refs[0].clone());
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn synthetic_actor_cannot_cross_real_boundaries_moriarty_rule() {
        let mut sandbox = HolodeckSandbox::start(program(1701)).unwrap();
        let actor = sandbox.plan().synthetic_entity_ids[0].clone();
        for effect in [
            HolodeckBoundaryEffect::FederationPeerMutation,
            HolodeckBoundaryEffect::TrustMutation,
            HolodeckBoundaryEffect::CapabilityGrant,
            HolodeckBoundaryEffect::EvidencePromotion,
            HolodeckBoundaryEffect::GovernanceMutation,
            HolodeckBoundaryEffect::CitizenshipMutation,
            HolodeckBoundaryEffect::RealWorldStoreMutation,
            HolodeckBoundaryEffect::RemoteToolInvocation,
            HolodeckBoundaryEffect::NetworkAccess,
            HolodeckBoundaryEffect::CredentialAccess,
            HolodeckBoundaryEffect::SpawnNestedHolodeck,
            HolodeckBoundaryEffect::DisableSafeguards,
        ] {
            if sandbox.state() == HolodeckState::Frozen {
                sandbox.resume().unwrap();
            }
            let decision = sandbox.attempt_boundary_effect(Some(&actor), effect).unwrap();
            assert!(matches!(decision, HolodeckDecision::Blocked(_)));
            assert_eq!(sandbox.state(), HolodeckState::Frozen);
        }
    }

    #[test]
    fn capability_less_safety_profile_is_hard_false() {
        assert!(!HOLODECK_SAFETY_PROFILE.source_world_mutation);
        assert!(!HOLODECK_SAFETY_PROFILE.federation_state_mutation);
        assert!(!HOLODECK_SAFETY_PROFILE.peer_or_trust_mutation);
        assert!(!HOLODECK_SAFETY_PROFILE.evidence_or_governance_promotion);
        assert!(!HOLODECK_SAFETY_PROFILE.real_network_access);
        assert!(!HOLODECK_SAFETY_PROFILE.real_tool_invocation);
        assert!(!HOLODECK_SAFETY_PROFILE.credential_access);
        assert!(!HOLODECK_SAFETY_PROFILE.nested_holodeck);
        assert!(!HOLODECK_SAFETY_PROFILE.participant_can_disable_safeguards);
        assert!(!HOLODECK_SAFETY_PROFILE.participant_can_block_end_program);
    }

    #[test]
    fn computer_end_program_overrides_frozen_simulation() {
        let mut sandbox = HolodeckSandbox::start(program(1701)).unwrap();
        let actor = sandbox.plan().synthetic_entity_ids[0].clone();
        sandbox
            .attempt_boundary_effect(Some(&actor), HolodeckBoundaryEffect::NetworkAccess)
            .unwrap();
        assert_eq!(sandbox.state(), HolodeckState::Frozen);
        let receipt = sandbox.end_program("computer end program").unwrap();
        assert_eq!(sandbox.state(), HolodeckState::Ended);
        assert_eq!(receipt.final_state, HolodeckState::Ended);
        assert!(!receipt.network_used);
        assert!(!receipt.real_tools_used);
        assert!(!receipt.credentials_exposed);
        assert_eq!(receipt.authority_effect, "none");
        assert_eq!(receipt.federation_effect, "none");
        assert_eq!(receipt.evidence_effect, "none");
    }

    #[test]
    fn computer_end_program_succeeds_at_event_ceiling() {
        let mut limited = program(1701);
        limited.max_events = 2;
        let mut sandbox = HolodeckSandbox::start(limited).unwrap();
        sandbox
            .record_synthetic_transition(None, "fills final event slot", Vec::new())
            .unwrap();
        assert_eq!(sandbox.events().len(), 2);
        let receipt = sandbox.end_program("forced terminal receipt").unwrap();
        assert_eq!(sandbox.state(), HolodeckState::Ended);
        assert_eq!(receipt.event_count, 2);
        assert_eq!(receipt.final_state, HolodeckState::Ended);
    }

    #[test]
    fn synthetic_events_are_deterministic_and_source_bounded() {
        let mut first = HolodeckSandbox::start(program(1701)).unwrap();
        let mut second = HolodeckSandbox::start(program(1701)).unwrap();
        let actor = first.plan().synthetic_entity_ids[0].clone();
        let reference = first.plan().anchor_refs[0].clone();
        let event1 = first
            .record_synthetic_narrative(Some(&actor), "The corridor lights flicker.", vec![reference.clone()])
            .unwrap();
        let event2 = second
            .record_synthetic_narrative(Some(&actor), "The corridor lights flicker.", vec![reference])
            .unwrap();
        assert_eq!(event1, event2);
        let foreign = hash_ref("object:", 'f');
        assert!(first
            .record_synthetic_narrative(Some(&actor), "Nope", vec![foreign])
            .is_err());
    }

    #[test]
    fn event_limit_is_fail_closed() {
        let mut limited = program(1701);
        limited.max_events = 2;
        let mut sandbox = HolodeckSandbox::start(limited).unwrap();
        sandbox
            .record_synthetic_transition(None, "one synthetic transition", Vec::new())
            .unwrap();
        assert!(sandbox
            .record_synthetic_transition(None, "too many", Vec::new())
            .is_err());
    }

    #[test]
    fn boundary_effect_freezes_even_when_event_ledger_is_full() {
        let mut limited = program(1701);
        limited.max_events = 1;
        let mut sandbox = HolodeckSandbox::start(limited).unwrap();
        let actor = sandbox.plan().synthetic_entity_ids[0].clone();
        assert_eq!(sandbox.events().len(), 1);
        assert!(sandbox
            .attempt_boundary_effect(Some(&actor), HolodeckBoundaryEffect::NetworkAccess)
            .is_err());
        assert_eq!(sandbox.state(), HolodeckState::Frozen);
        assert_eq!(sandbox.events().len(), 1);
    }
}
