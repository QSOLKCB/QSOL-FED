//! Phase 4 durable peer lifecycle, trust separation, and capability policy.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::canonical::{canonicalize, derive_message_id, object_id};
use crate::envelope::{AuthorityClaim, FederationEnvelope, MessageClass};
use crate::wire::{is_capability_id, is_node_id, is_wire_timestamp, PROTOCOL_V1};
use crate::{
    sign_envelope, verify_signed_envelope, IdentityState, KeyRotationRecord, KeyStatusRecord,
    LocalSigningKey, NodeIdentityDocument, SignatureValidity, SignedEnvelope,
};

pub const PEER_RECORD_SCHEMA_V1: &str = "qsol-fed-peer-record/1";
pub const TRUST_REGISTRY_SCHEMA_V1: &str = "qsol-fed-trust-registry/1";
pub const CAPABILITY_ADVERTISEMENT_SCHEMA_V1: &str = "qsol-fed-capability-advertisement/1";
pub const CAPABILITY_POLICY_SCHEMA_V1: &str = "qsol-fed-capability-policy/1";
pub const MAX_CAPABILITY_ADVERTISEMENT_LIFETIME_SECONDS: i64 = 86_400;
pub const MAX_PEER_LIFECYCLE_RECORDS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeeringError(pub String);

impl std::fmt::Display for PeeringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PeeringError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PeerLifecycleRecord {
    Rotation(KeyRotationRecord),
    Status(KeyStatusRecord),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerLifecycleState {
    Introduced,
    Admitted,
    Quarantined,
    Revoked,
    Disconnected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerStateView {
    Unknown,
    Introduced,
    Admitted,
    Quarantined,
    Revoked,
    Disconnected,
}

impl From<PeerLifecycleState> for PeerStateView {
    fn from(value: PeerLifecycleState) -> Self {
        match value {
            PeerLifecycleState::Introduced => Self::Introduced,
            PeerLifecycleState::Admitted => Self::Admitted,
            PeerLifecycleState::Quarantined => Self::Quarantined,
            PeerLifecycleState::Revoked => Self::Revoked,
            PeerLifecycleState::Disconnected => Self::Disconnected,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalTrustLevel {
    Unknown,
    Trusted,
    Distrusted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejoinDisposition {
    Clean,
    ExplicitReconciliationRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryWriteDisposition {
    Applied,
    Duplicate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAdvertisement {
    pub schema: String,
    pub node_id: String,
    pub sequence: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub capabilities: Vec<String>,
    pub proof: SignedEnvelope,
}

#[derive(Serialize)]
struct CapabilityAdvertisementPayload<'a> {
    schema: &'a str,
    node_id: &'a str,
    sequence: u64,
    issued_at: &'a str,
    expires_at: &'a str,
    capabilities: &'a [String],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerRecord {
    pub schema: String,
    pub node_id: String,
    pub identity: NodeIdentityDocument,
    pub lifecycle: Vec<PeerLifecycleRecord>,
    pub identity_fingerprint: String,
    pub lifecycle_sequence: u64,
    pub state: PeerLifecycleState,
    pub pre_disconnect_state: Option<PeerLifecycleState>,
    pub partition_snapshot: Option<String>,
    pub capability_advertisement: Option<CapabilityAdvertisement>,
    pub local_event_sequence: u64,
    pub updated_at: String,
    pub authority: String,
}

pub struct PeerRegistry {
    root: PathBuf,
}

impl PeerRegistry {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, PeeringError> {
        let root = root.as_ref();
        fs::create_dir_all(root).map_err(|error| PeeringError(format!("peer_root_create:{error}")))?;
        let root = fs::canonicalize(root).map_err(|error| PeeringError(format!("peer_root_canonicalize:{error}")))?;
        fs::create_dir_all(root.join("peers"))
            .map_err(|error| PeeringError(format!("peer_directory_create:{error}")))?;
        Ok(Self { root })
    }

    pub fn state(&self, node_id: &str) -> Result<PeerStateView, PeeringError> {
        Ok(self.get(node_id)?.map(|record| record.state.into()).unwrap_or(PeerStateView::Unknown))
    }

    pub fn get(&self, node_id: &str) -> Result<Option<PeerRecord>, PeeringError> {
        if !is_node_id(node_id) {
            return Err(PeeringError("peer_node_id_invalid".into()));
        }
        let path = peer_path(&self.root, node_id)?;
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path).map_err(|error| PeeringError(format!("peer_read:{error}")))?;
        require_exact_canonical(&raw)?;
        let record: PeerRecord = serde_json::from_slice(&raw)
            .map_err(|error| PeeringError(format!("peer_schema:{error}")))?;
        validate_peer_record(&record)?;
        Ok(Some(record))
    }

    pub fn identity_state(&self, node_id: &str) -> Result<Option<IdentityState>, PeeringError> {
        let Some(record) = self.get(node_id)? else { return Ok(None); };
        Ok(Some(rebuild_peer_identity(&record.identity, &record.lifecycle)?))
    }

    pub fn introduce(
        &self,
        identity: NodeIdentityDocument,
        lifecycle: Vec<PeerLifecycleRecord>,
        observed_snapshot: Option<String>,
        updated_at: &str,
    ) -> Result<RegistryWriteDisposition, PeeringError> {
        if lifecycle.len() > MAX_PEER_LIFECYCLE_RECORDS || !valid_timestamp(updated_at) {
            return Err(PeeringError("peer_introduction_limits_invalid".into()));
        }
        if observed_snapshot.as_deref().is_some_and(|value| !crate::wire::is_sha256_ref(value)) {
            return Err(PeeringError("peer_snapshot_invalid".into()));
        }
        let identity_state = rebuild_peer_identity(&identity, &lifecycle)?;
        let fingerprint = identity_fingerprint(&identity, &lifecycle)?;
        let node_id = identity.node_id.clone();
        if let Some(mut old) = self.get(&node_id)? {
            if old.state == PeerLifecycleState::Revoked {
                return Err(PeeringError("revoked_peer_cannot_reintroduce".into()));
            }
            if identity_state.sequence < old.lifecycle_sequence {
                return Err(PeeringError("peer_lifecycle_rollback_forbidden".into()));
            }
            if identity_state.sequence == old.lifecycle_sequence {
                if old.identity_fingerprint == fingerprint {
                    return Ok(RegistryWriteDisposition::Duplicate);
                }
                return Err(PeeringError("peer_same_sequence_divergence".into()));
            }
            if old.identity.root_key_id != identity.root_key_id || old.identity.node_id != identity.node_id {
                return Err(PeeringError("peer_root_identity_changed".into()));
            }
            old.identity = identity;
            old.lifecycle = lifecycle;
            old.identity_fingerprint = fingerprint;
            old.lifecycle_sequence = identity_state.sequence;
            old.partition_snapshot = observed_snapshot.or(old.partition_snapshot);
            old.local_event_sequence = old.local_event_sequence.saturating_add(1);
            old.updated_at = updated_at.into();
            write_peer(&self.root, &old)?;
            return Ok(RegistryWriteDisposition::Applied);
        }

        let record = PeerRecord {
            schema: PEER_RECORD_SCHEMA_V1.into(),
            node_id: node_id.clone(),
            identity,
            lifecycle,
            identity_fingerprint: fingerprint,
            lifecycle_sequence: identity_state.sequence,
            state: PeerLifecycleState::Introduced,
            pre_disconnect_state: None,
            partition_snapshot: observed_snapshot,
            capability_advertisement: None,
            local_event_sequence: 1,
            updated_at: updated_at.into(),
            authority: "none".into(),
        };
        write_peer(&self.root, &record)?;
        Ok(RegistryWriteDisposition::Applied)
    }

    pub fn import_quarantined(
        &self,
        identity: NodeIdentityDocument,
        lifecycle: Vec<PeerLifecycleRecord>,
        updated_at: &str,
    ) -> Result<RegistryWriteDisposition, PeeringError> {
        let disposition = self.introduce(identity.clone(), lifecycle, None, updated_at)?;
        let Some(record) = self.get(&identity.node_id)? else {
            return Err(PeeringError("imported_peer_missing_after_introduce".into()));
        };
        if record.state != PeerLifecycleState::Quarantined {
            self.transition(&identity.node_id, PeerLifecycleState::Quarantined, updated_at)?;
            return Ok(RegistryWriteDisposition::Applied);
        }
        Ok(disposition)
    }

    pub fn attach_archival_capability_advertisement(
        &self,
        node_id: &str,
        advertisement: CapabilityAdvertisement,
        updated_at: &str,
    ) -> Result<(), PeeringError> {
        if !valid_timestamp(updated_at) || advertisement.node_id != node_id {
            return Err(PeeringError("archival_capability_identity_invalid".into()));
        }
        let mut record = self.get(node_id)?.ok_or_else(|| PeeringError("capability_peer_unknown".into()))?;
        let identity = rebuild_peer_identity(&record.identity, &record.lifecycle)?;
        verify_capability_advertisement_signature(&advertisement, &identity)?;
        if let Some(old) = &record.capability_advertisement {
            if advertisement.sequence < old.sequence {
                return Err(PeeringError("capability_advertisement_rollback".into()));
            }
            if advertisement.sequence == old.sequence && canonical_struct(old)? != canonical_struct(&advertisement)? {
                return Err(PeeringError("capability_same_sequence_divergence".into()));
            }
        }
        record.capability_advertisement = Some(advertisement);
        record.local_event_sequence = record.local_event_sequence.saturating_add(1);
        record.updated_at = updated_at.into();
        write_peer(&self.root, &record)
    }

    pub fn transition(&self, node_id: &str, target: PeerLifecycleState, updated_at: &str) -> Result<(), PeeringError> {
        if !valid_timestamp(updated_at) { return Err(PeeringError("peer_transition_time_invalid".into())); }
        let mut record = self.get(node_id)?.ok_or_else(|| PeeringError("peer_unknown".into()))?;
        if !transition_allowed(record.state, target) { return Err(PeeringError("peer_transition_forbidden".into())); }
        if target == PeerLifecycleState::Disconnected {
            record.pre_disconnect_state = Some(record.state);
        } else if record.state != PeerLifecycleState::Disconnected {
            record.pre_disconnect_state = None;
        }
        record.state = target;
        record.local_event_sequence = record.local_event_sequence.saturating_add(1);
        record.updated_at = updated_at.into();
        write_peer(&self.root, &record)
    }

    pub fn disconnect(&self, node_id: &str, local_snapshot: &str, updated_at: &str) -> Result<(), PeeringError> {
        if !crate::wire::is_sha256_ref(local_snapshot) || !valid_timestamp(updated_at) {
            return Err(PeeringError("partition_snapshot_or_time_invalid".into()));
        }
        let mut record = self.get(node_id)?.ok_or_else(|| PeeringError("peer_unknown".into()))?;
        if record.state == PeerLifecycleState::Revoked || record.state == PeerLifecycleState::Disconnected {
            return Err(PeeringError("peer_disconnect_forbidden".into()));
        }
        record.pre_disconnect_state = Some(record.state);
        record.state = PeerLifecycleState::Disconnected;
        record.partition_snapshot = Some(local_snapshot.into());
        record.local_event_sequence = record.local_event_sequence.saturating_add(1);
        record.updated_at = updated_at.into();
        write_peer(&self.root, &record)
    }

    pub fn propose_rejoin(&self, node_id: &str, remote_snapshot: &str) -> Result<RejoinDisposition, PeeringError> {
        if !crate::wire::is_sha256_ref(remote_snapshot) { return Err(PeeringError("rejoin_snapshot_invalid".into())); }
        let record = self.get(node_id)?.ok_or_else(|| PeeringError("peer_unknown".into()))?;
        if record.state != PeerLifecycleState::Disconnected { return Err(PeeringError("rejoin_requires_disconnected_peer".into())); }
        Ok(if record.partition_snapshot.as_deref() == Some(remote_snapshot) {
            RejoinDisposition::Clean
        } else {
            RejoinDisposition::ExplicitReconciliationRequired
        })
    }

    pub fn confirm_rejoin(
        &self,
        node_id: &str,
        remote_snapshot: &str,
        explicit_reconciliation: bool,
        updated_at: &str,
    ) -> Result<(), PeeringError> {
        if !valid_timestamp(updated_at) { return Err(PeeringError("rejoin_time_invalid".into())); }
        let disposition = self.propose_rejoin(node_id, remote_snapshot)?;
        if disposition == RejoinDisposition::ExplicitReconciliationRequired && !explicit_reconciliation {
            return Err(PeeringError("silent_reconciliation_forbidden".into()));
        }
        let mut record = self.get(node_id)?.ok_or_else(|| PeeringError("peer_unknown".into()))?;
        let target = record.pre_disconnect_state.unwrap_or(PeerLifecycleState::Introduced);
        if target == PeerLifecycleState::Revoked || target == PeerLifecycleState::Disconnected {
            return Err(PeeringError("rejoin_target_invalid".into()));
        }
        record.state = target;
        record.pre_disconnect_state = None;
        record.partition_snapshot = Some(remote_snapshot.into());
        record.local_event_sequence = record.local_event_sequence.saturating_add(1);
        record.updated_at = updated_at.into();
        write_peer(&self.root, &record)
    }

    pub fn record_capability_advertisement(
        &self,
        advertisement: CapabilityAdvertisement,
        now_unix: i64,
        updated_at: &str,
    ) -> Result<RegistryWriteDisposition, PeeringError> {
        if !valid_timestamp(updated_at) { return Err(PeeringError("capability_update_time_invalid".into())); }
        let mut record = self.get(&advertisement.node_id)?.ok_or_else(|| PeeringError("capability_peer_unknown".into()))?;
        let identity = rebuild_peer_identity(&record.identity, &record.lifecycle)?;
        verify_capability_advertisement(&advertisement, &identity, now_unix)?;
        if let Some(old) = &record.capability_advertisement {
            if advertisement.sequence < old.sequence { return Err(PeeringError("capability_advertisement_rollback".into())); }
            if advertisement.sequence == old.sequence {
                if canonical_struct(&advertisement)? == canonical_struct(old)? { return Ok(RegistryWriteDisposition::Duplicate); }
                return Err(PeeringError("capability_same_sequence_divergence".into()));
            }
        }
        record.capability_advertisement = Some(advertisement);
        record.local_event_sequence = record.local_event_sequence.saturating_add(1);
        record.updated_at = updated_at.into();
        write_peer(&self.root, &record)?;
        Ok(RegistryWriteDisposition::Applied)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustSnapshot {
    schema: String,
    entries: BTreeMap<String, LocalTrustLevel>,
}

pub struct TrustRegistry {
    path: PathBuf,
    entries: BTreeMap<String, LocalTrustLevel>,
}

impl TrustRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PeeringError> {
        let path = prepare_file_path(path.as_ref())?;
        let entries = if path.exists() {
            let raw = fs::read(&path).map_err(|error| PeeringError(format!("trust_read:{error}")))?;
            require_exact_canonical(&raw)?;
            let snapshot: TrustSnapshot = serde_json::from_slice(&raw).map_err(|error| PeeringError(format!("trust_schema:{error}")))?;
            if snapshot.schema != TRUST_REGISTRY_SCHEMA_V1 || snapshot.entries.keys().any(|node| !is_node_id(node)) {
                return Err(PeeringError("trust_registry_corrupt".into()));
            }
            snapshot.entries
        } else { BTreeMap::new() };
        Ok(Self { path, entries })
    }

    pub fn get(&self, node_id: &str) -> LocalTrustLevel {
        self.entries.get(node_id).copied().unwrap_or(LocalTrustLevel::Unknown)
    }

    pub fn set(&mut self, node_id: &str, level: LocalTrustLevel) -> Result<(), PeeringError> {
        if !is_node_id(node_id) { return Err(PeeringError("trust_node_invalid".into())); }
        if level == LocalTrustLevel::Unknown { self.entries.remove(node_id); } else { self.entries.insert(node_id.into(), level); }
        self.persist()
    }

    fn persist(&self) -> Result<(), PeeringError> {
        atomic_replace(&self.path, &canonical_struct(&TrustSnapshot { schema: TRUST_REGISTRY_SCHEMA_V1.into(), entries: self.entries.clone() })?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityPolicySnapshot {
    schema: String,
    entries: BTreeMap<String, BTreeMap<String, CapabilityDecision>>,
}

pub struct LocalCapabilityPolicy {
    path: PathBuf,
    entries: BTreeMap<String, BTreeMap<String, CapabilityDecision>>,
}

impl LocalCapabilityPolicy {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PeeringError> {
        let path = prepare_file_path(path.as_ref())?;
        let entries = if path.exists() {
            let raw = fs::read(&path).map_err(|error| PeeringError(format!("policy_read:{error}")))?;
            require_exact_canonical(&raw)?;
            let snapshot: CapabilityPolicySnapshot = serde_json::from_slice(&raw).map_err(|error| PeeringError(format!("policy_schema:{error}")))?;
            if snapshot.schema != CAPABILITY_POLICY_SCHEMA_V1 { return Err(PeeringError("capability_policy_corrupt".into())); }
            for (node, capabilities) in &snapshot.entries {
                if !is_node_id(node) || capabilities.keys().any(|capability| !is_capability_id(capability)) {
                    return Err(PeeringError("capability_policy_corrupt".into()));
                }
            }
            snapshot.entries
        } else { BTreeMap::new() };
        Ok(Self { path, entries })
    }

    pub fn decision(&self, node_id: &str, capability: &str) -> CapabilityDecision {
        self.entries.get(node_id).and_then(|values| values.get(capability)).copied().unwrap_or(CapabilityDecision::Deny)
    }

    pub fn set(&mut self, node_id: &str, capability: &str, decision: CapabilityDecision) -> Result<(), PeeringError> {
        if !is_node_id(node_id) || !is_capability_id(capability) { return Err(PeeringError("capability_policy_key_invalid".into())); }
        self.entries.entry(node_id.into()).or_default().insert(capability.into(), decision);
        self.persist()
    }

    pub fn advertised_and_allowed(&self, peer: &PeerRecord, capability: &str, now_unix: i64) -> bool {
        let Some(advertisement) = &peer.capability_advertisement else { return false; };
        if advertisement_is_active(advertisement, now_unix).is_err() { return false; }
        advertisement.capabilities.iter().any(|value| value == capability)
            && self.decision(&peer.node_id, capability) == CapabilityDecision::Allow
    }

    fn persist(&self) -> Result<(), PeeringError> {
        atomic_replace(&self.path, &canonical_struct(&CapabilityPolicySnapshot { schema: CAPABILITY_POLICY_SCHEMA_V1.into(), entries: self.entries.clone() })?)
    }
}

pub fn create_capability_advertisement(
    identity: &IdentityState,
    signing_key: &LocalSigningKey,
    sequence: u64,
    issued_at: &str,
    expires_at: &str,
    mut capabilities: Vec<String>,
) -> Result<CapabilityAdvertisement, PeeringError> {
    validate_capability_set(&capabilities)?;
    capabilities.sort();
    let issued = parse_timestamp(issued_at)?;
    let expires = parse_timestamp(expires_at)?;
    if sequence == 0 || expires <= issued || expires - issued > MAX_CAPABILITY_ADVERTISEMENT_LIFETIME_SECONDS {
        return Err(PeeringError("capability_expiry_or_sequence_invalid".into()));
    }
    let payload = CapabilityAdvertisementPayload {
        schema: CAPABILITY_ADVERTISEMENT_SCHEMA_V1,
        node_id: &identity.node_id,
        sequence,
        issued_at,
        expires_at,
        capabilities: &capabilities,
    };
    let payload_bytes = canonical_struct(&payload)?;
    let payload_ref = object_id(&payload_bytes).map_err(|error| PeeringError(error.0))?;
    let mut envelope = FederationEnvelope {
        protocol: PROTOCOL_V1.into(),
        message_id: format!("sha256:{}", "0".repeat(64)),
        sender: identity.node_id.clone(),
        recipient: identity.node_id.clone(),
        message_class: MessageClass::Capabilities,
        payload_ref,
        provenance_ref: None,
        issued_at: issued_at.into(),
        expires_at: Some(expires_at.into()),
        authority_claim: AuthorityClaim::None,
        signature: (),
    };
    let envelope_bytes = canonical_struct(&envelope)?;
    envelope.message_id = derive_message_id(&envelope_bytes).map_err(|error| PeeringError(error.0))?;
    let proof = sign_envelope(identity, signing_key, envelope).map_err(|error| PeeringError(error.0))?;
    Ok(CapabilityAdvertisement {
        schema: CAPABILITY_ADVERTISEMENT_SCHEMA_V1.into(),
        node_id: identity.node_id.clone(),
        sequence,
        issued_at: issued_at.into(),
        expires_at: expires_at.into(),
        capabilities,
        proof,
    })
}

pub fn verify_capability_advertisement(
    advertisement: &CapabilityAdvertisement,
    identity: &IdentityState,
    now_unix: i64,
) -> Result<(), PeeringError> {
    verify_capability_advertisement_signature(advertisement, identity)?;
    advertisement_is_active(advertisement, now_unix)
}

pub fn verify_capability_advertisement_signature(
    advertisement: &CapabilityAdvertisement,
    identity: &IdentityState,
) -> Result<(), PeeringError> {
    validate_advertisement_shape(advertisement)?;
    if advertisement.node_id != identity.node_id { return Err(PeeringError("capability_node_mismatch".into())); }
    let payload_ref = object_id(&canonical_struct(&CapabilityAdvertisementPayload {
        schema: &advertisement.schema,
        node_id: &advertisement.node_id,
        sequence: advertisement.sequence,
        issued_at: &advertisement.issued_at,
        expires_at: &advertisement.expires_at,
        capabilities: &advertisement.capabilities,
    })?).map_err(|error| PeeringError(error.0))?;
    let envelope = &advertisement.proof.envelope;
    if advertisement.proof.node_id != advertisement.node_id
        || envelope.sender != advertisement.node_id
        || envelope.recipient != advertisement.node_id
        || envelope.message_class != MessageClass::Capabilities
        || envelope.payload_ref != payload_ref
        || envelope.issued_at != advertisement.issued_at
        || envelope.expires_at.as_deref() != Some(advertisement.expires_at.as_str())
    {
        return Err(PeeringError("capability_proof_binding_invalid".into()));
    }
    let issued = parse_timestamp(&advertisement.issued_at)?;
    let assessment = verify_signed_envelope(&advertisement.proof, identity, issued)
        .map_err(|error| PeeringError(error.0))?;
    if assessment.signature == SignatureValidity::Valid { Ok(()) } else { Err(PeeringError("capability_signature_invalid".into())) }
}

fn advertisement_is_active(advertisement: &CapabilityAdvertisement, now_unix: i64) -> Result<(), PeeringError> {
    let issued = parse_timestamp(&advertisement.issued_at)?;
    let expires = parse_timestamp(&advertisement.expires_at)?;
    if expires <= issued || expires - issued > MAX_CAPABILITY_ADVERTISEMENT_LIFETIME_SECONDS {
        return Err(PeeringError("capability_expiry_invalid".into()));
    }
    if now_unix < issued || now_unix > expires { return Err(PeeringError("capability_advertisement_inactive".into())); }
    Ok(())
}

fn validate_advertisement_shape(advertisement: &CapabilityAdvertisement) -> Result<(), PeeringError> {
    if advertisement.schema != CAPABILITY_ADVERTISEMENT_SCHEMA_V1
        || !is_node_id(&advertisement.node_id)
        || advertisement.sequence == 0
        || !valid_timestamp(&advertisement.issued_at)
        || !valid_timestamp(&advertisement.expires_at)
    {
        return Err(PeeringError("capability_advertisement_shape_invalid".into()));
    }
    validate_capability_set(&advertisement.capabilities)
}

fn validate_capability_set(capabilities: &[String]) -> Result<(), PeeringError> {
    if capabilities.len() > 128 { return Err(PeeringError("capability_advertisement_too_large".into())); }
    let mut seen = HashSet::new();
    if capabilities.iter().any(|value| !is_capability_id(value) || !seen.insert(value.as_str())) {
        return Err(PeeringError("capability_advertisement_invalid".into()));
    }
    Ok(())
}

pub fn rebuild_peer_identity(identity: &NodeIdentityDocument, lifecycle: &[PeerLifecycleRecord]) -> Result<IdentityState, PeeringError> {
    let mut state = IdentityState::from_document(identity).map_err(|error| PeeringError(format!("peer_identity:{error}")))?;
    for record in lifecycle {
        match record {
            PeerLifecycleRecord::Rotation(value) => state.apply_rotation(value).map_err(|error| PeeringError(format!("peer_rotation:{error}")))?,
            PeerLifecycleRecord::Status(value) => state.apply_key_status(value).map_err(|error| PeeringError(format!("peer_status:{error}")))?,
        }
    }
    Ok(state)
}

fn identity_fingerprint(identity: &NodeIdentityDocument, lifecycle: &[PeerLifecycleRecord]) -> Result<String, PeeringError> {
    #[derive(Serialize)] struct Snapshot<'a> { identity: &'a NodeIdentityDocument, lifecycle: &'a [PeerLifecycleRecord] }
    object_id(&canonical_struct(&Snapshot { identity, lifecycle })?).map_err(|error| PeeringError(error.0))
}

fn validate_peer_record(record: &PeerRecord) -> Result<(), PeeringError> {
    if record.schema != PEER_RECORD_SCHEMA_V1
        || record.node_id != record.identity.node_id
        || record.lifecycle.len() > MAX_PEER_LIFECYCLE_RECORDS
        || record.authority != "none"
        || !valid_timestamp(&record.updated_at)
        || record.partition_snapshot.as_deref().is_some_and(|value| !crate::wire::is_sha256_ref(value))
    { return Err(PeeringError("peer_record_corrupt".into())); }
    let rebuilt = rebuild_peer_identity(&record.identity, &record.lifecycle)?;
    if rebuilt.sequence != record.lifecycle_sequence || identity_fingerprint(&record.identity, &record.lifecycle)? != record.identity_fingerprint {
        return Err(PeeringError("peer_record_identity_drift".into()));
    }
    if let Some(advertisement) = &record.capability_advertisement { verify_capability_advertisement_signature(advertisement, &rebuilt)?; }
    Ok(())
}

fn transition_allowed(from: PeerLifecycleState, to: PeerLifecycleState) -> bool {
    if from == to { return true; }
    match from {
        PeerLifecycleState::Introduced => matches!(to, PeerLifecycleState::Admitted | PeerLifecycleState::Quarantined | PeerLifecycleState::Revoked | PeerLifecycleState::Disconnected),
        PeerLifecycleState::Admitted => matches!(to, PeerLifecycleState::Quarantined | PeerLifecycleState::Revoked | PeerLifecycleState::Disconnected),
        PeerLifecycleState::Quarantined => matches!(to, PeerLifecycleState::Admitted | PeerLifecycleState::Revoked | PeerLifecycleState::Disconnected),
        PeerLifecycleState::Revoked | PeerLifecycleState::Disconnected => false,
    }
}

fn valid_timestamp(value: &str) -> bool { is_wire_timestamp(value) && DateTime::parse_from_rfc3339(value).is_ok() }
fn parse_timestamp(value: &str) -> Result<i64, PeeringError> {
    if !valid_timestamp(value) { return Err(PeeringError("peer_timestamp_invalid".into())); }
    DateTime::parse_from_rfc3339(value).map(|value| value.timestamp()).map_err(|_| PeeringError("peer_timestamp_invalid".into()))
}
fn canonical_struct<T: Serialize>(value: &T) -> Result<Vec<u8>, PeeringError> {
    canonicalize(&serde_json::to_vec(value).map_err(|error| PeeringError(format!("peer_encode:{error}")))?).map_err(|error| PeeringError(error.0))
}
fn require_exact_canonical(raw: &[u8]) -> Result<(), PeeringError> {
    if canonicalize(raw).map_err(|error| PeeringError(error.0))? == raw { Ok(()) } else { Err(PeeringError("peer_registry_bytes_not_canonical".into())) }
}
fn peer_path(root: &Path, node_id: &str) -> Result<PathBuf, PeeringError> {
    if !is_node_id(node_id) { return Err(PeeringError("peer_node_id_invalid".into())); }
    Ok(root.join("peers").join(format!("{}.json", &node_id[9..])))
}
fn write_peer(root: &Path, record: &PeerRecord) -> Result<(), PeeringError> {
    validate_peer_record(record)?;
    atomic_replace(&peer_path(root, &record.node_id)?, &canonical_struct(record)?)
}
fn prepare_file_path(path: &Path) -> Result<PathBuf, PeeringError> {
    let parent = path.parent().filter(|value| !value.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| PeeringError(format!("registry_parent_create:{error}")))?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| PeeringError(format!("registry_parent_canonicalize:{error}")))?;
    let name = path.file_name().ok_or_else(|| PeeringError("registry_filename_missing".into()))?;
    Ok(canonical_parent.join(name))
}
fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), PeeringError> {
    let name = path.file_name().and_then(|value| value.to_str()).ok_or_else(|| PeeringError("registry_filename_invalid".into()))?;
    let temporary = path.with_file_name(format!(".{name}.tmp"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new().create_new(true).write(true).open(&temporary).map_err(|error| PeeringError(format!("registry_temp_open:{error}")))?;
    file.write_all(bytes).map_err(|error| PeeringError(format!("registry_write:{error}")))?;
    file.flush().map_err(|error| PeeringError(format!("registry_flush:{error}")))?;
    file.sync_all().map_err(|error| PeeringError(format!("registry_fsync:{error}")))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| PeeringError(format!("registry_rename:{error}")))?;
    sync_parent(path)
}
#[cfg(unix)] fn sync_parent(path: &Path) -> Result<(), PeeringError> {
    File::open(path.parent().unwrap_or_else(|| Path::new("."))).map_err(|error| PeeringError(format!("registry_parent_open:{error}")))?.sync_all().map_err(|error| PeeringError(format!("registry_parent_fsync:{error}")))
}
#[cfg(not(unix))] fn sync_parent(_path: &Path) -> Result<(), PeeringError> { Err(PeeringError("registry_parent_fsync_unsupported_platform".into())) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_identity_document, KeyStatusKind, KeyStatusReason};
    use std::time::{SystemTime, UNIX_EPOCH};

    const ROOT: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const OP: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const NEXT: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("qsol-fed-peer-{label}-{}-{nonce}", std::process::id()))
    }
    fn identity() -> (LocalSigningKey, LocalSigningKey, NodeIdentityDocument, IdentityState) {
        let root = LocalSigningKey::from_seed_hex(ROOT).unwrap();
        let op = LocalSigningKey::from_seed_hex(OP).unwrap();
        let doc = create_identity_document(&root, &op, "2026-08-23T00:00:00Z").unwrap();
        let state = IdentityState::from_document(&doc).unwrap();
        (root, op, doc, state)
    }

    #[test]
    fn peer_lifecycle_and_trust_are_separate_and_durable() {
        let root = temp_root("separate");
        let peers = PeerRegistry::open(root.join("peer-registry")).unwrap();
        let mut trust = TrustRegistry::open(root.join("trust.json")).unwrap();
        let (_, _, doc, _) = identity();
        peers.introduce(doc.clone(), vec![], None, "2026-08-23T00:00:01Z").unwrap();
        peers.transition(&doc.node_id, PeerLifecycleState::Admitted, "2026-08-23T00:00:02Z").unwrap();
        assert_eq!(peers.state(&doc.node_id).unwrap(), PeerStateView::Admitted);
        assert_eq!(trust.get(&doc.node_id), LocalTrustLevel::Unknown);
        trust.set(&doc.node_id, LocalTrustLevel::Trusted).unwrap();
        assert_eq!(TrustRegistry::open(root.join("trust.json")).unwrap().get(&doc.node_id), LocalTrustLevel::Trusted);
        assert_eq!(PeerRegistry::open(root.join("peer-registry")).unwrap().state(&doc.node_id).unwrap(), PeerStateView::Admitted);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn capability_advertisement_does_not_override_local_policy() {
        let root = temp_root("capability");
        let peers = PeerRegistry::open(root.join("peers")).unwrap();
        let mut policy = LocalCapabilityPolicy::open(root.join("policy.json")).unwrap();
        let (_, op, doc, state) = identity();
        peers.introduce(doc.clone(), vec![], None, "2026-08-23T00:00:01Z").unwrap();
        let ad = create_capability_advertisement(&state, &op, 1, "2026-08-23T00:00:00Z", "2026-08-23T01:00:00Z", vec!["evidence.exchange/1".into()]).unwrap();
        peers.record_capability_advertisement(ad, 1_787_443_320, "2026-08-23T00:00:02Z").unwrap();
        let peer = peers.get(&doc.node_id).unwrap().unwrap();
        assert!(!policy.advertised_and_allowed(&peer, "evidence.exchange/1", 1_787_443_320));
        policy.set(&doc.node_id, "evidence.exchange/1", CapabilityDecision::Allow).unwrap();
        assert!(policy.advertised_and_allowed(&peer, "evidence.exchange/1", 1_787_443_320));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn partition_rejoin_never_silently_reconciles() {
        let root = temp_root("partition");
        let peers = PeerRegistry::open(&root).unwrap();
        let (_, _, doc, _) = identity();
        peers.introduce(doc.clone(), vec![], None, "2026-08-23T00:00:01Z").unwrap();
        peers.transition(&doc.node_id, PeerLifecycleState::Admitted, "2026-08-23T00:00:02Z").unwrap();
        let old = format!("sha256:{}", "1".repeat(64));
        let changed = format!("sha256:{}", "2".repeat(64));
        peers.disconnect(&doc.node_id, &old, "2026-08-23T00:01:00Z").unwrap();
        assert_eq!(peers.propose_rejoin(&doc.node_id, &changed).unwrap(), RejoinDisposition::ExplicitReconciliationRequired);
        assert!(peers.confirm_rejoin(&doc.node_id, &changed, false, "2026-08-23T00:02:00Z").is_err());
        peers.confirm_rejoin(&doc.node_id, &changed, true, "2026-08-23T00:02:00Z").unwrap();
        assert_eq!(peers.state(&doc.node_id).unwrap(), PeerStateView::Admitted);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_replay_and_rollback_fail_across_restart() {
        let root = temp_root("rollback");
        let peers = PeerRegistry::open(&root).unwrap();
        let (root_key, op, doc, mut state) = identity();
        peers.introduce(doc.clone(), vec![], None, "2026-08-23T00:00:01Z").unwrap();
        let status = state.create_key_status_record(&root_key, &op.key_id(), KeyStatusKind::Compromised, "2026-08-23T00:10:00Z", KeyStatusReason::ConfirmedCompromise).unwrap();
        state.apply_key_status(&status).unwrap();
        let next = LocalSigningKey::from_seed_hex(NEXT).unwrap();
        let recovery = state.create_recovery_rotation(&root_key, &next, "2026-08-23T00:11:00Z").unwrap();
        peers.introduce(doc.clone(), vec![PeerLifecycleRecord::Status(status), PeerLifecycleRecord::Rotation(recovery)], None, "2026-08-23T00:12:00Z").unwrap();
        drop(peers);
        let reopened = PeerRegistry::open(&root).unwrap();
        assert!(reopened.introduce(doc, vec![], None, "2026-08-23T00:13:00Z").is_err());
        let _ = fs::remove_dir_all(root);
    }
}
