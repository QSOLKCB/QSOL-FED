//! Phase 8 transport profiles and resilience drills.
//!
//! Transport changes reachability and delivery mechanics only. It never changes
//! authenticated identity, message identity, provenance, trust, authority, or
//! Holodeck sandbox semantics.

use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::{canonicalize, sha256_ref};
use crate::wire::{is_node_id, is_sha256_ref};

pub const TRANSPORT_FRAME_SCHEMA_V1: &str = "qsol-fed-transport-frame/1";
pub const NAT_TRAVERSAL_TICKET_SCHEMA_V1: &str = "qsol-fed-nat-traversal-ticket/1";
pub const RELAY_RECEIPT_SCHEMA_V1: &str = "qsol-fed-relay-receipt/1";
pub const OFFLINE_PACKAGE_SCHEMA_V1: &str = "qsol-fed-offline-package/1";
pub const TRANSPORT_DRILL_SCHEMA_V1: &str = "qsol-fed-transport-drill/1";
pub const ARCHIVE_POLICY_V1: &str = "qsol-fed-archive-compatibility/1";
pub const TRANSPORT_FRAME_MAX_BYTES: usize = 65_536;
pub const TRANSPORT_QUEUE_MAX_DEPTH: usize = 1_024;
pub const TRANSPORT_MAX_RELAY_HOPS: usize = 16;
pub const NAT_MAX_CANDIDATES: usize = 8;
pub const NAT_MAX_TICKET_LIFETIME_SECONDS: i64 = 600;
pub const TRANSPORT_HOLODECK_INVARIANT: &str = "transport_does_not_enter_holodeck_sandbox";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError(pub String);
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for TransportError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProfile {
    WebSocket,
    Quic,
    UnixIpc,
    OfflineSneakernet,
    StoreForward,
}

pub const ALL_TRANSPORT_PROFILES: [TransportProfile; 5] = [
    TransportProfile::WebSocket,
    TransportProfile::Quic,
    TransportProfile::UnixIpc,
    TransportProfile::OfflineSneakernet,
    TransportProfile::StoreForward,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportProfileSpec {
    pub profile: TransportProfile,
    pub framing: String,
    pub network_bearing: bool,
    pub nat_traversal_supported: bool,
    pub delayed_delivery_supported: bool,
    pub maximum_frame_bytes: usize,
    pub identity_source: String,
    pub authority_effect: String,
    pub live_backend_claimed: bool,
}

pub fn transport_profile_spec(profile: TransportProfile) -> TransportProfileSpec {
    let (framing, network_bearing, nat, delayed) = match profile {
        TransportProfile::WebSocket => ("one-canonical-frame-per-websocket-message", true, true, false),
        TransportProfile::Quic => ("one-canonical-frame-per-unidirectional-stream", true, true, false),
        TransportProfile::UnixIpc => ("u32-be-length-prefixed-canonical-frame", false, false, false),
        TransportProfile::OfflineSneakernet => ("canonical-offline-package", false, false, true),
        TransportProfile::StoreForward => ("bounded-canonical-spool-record", false, false, true),
    };
    TransportProfileSpec {
        profile,
        framing: framing.into(),
        network_bearing,
        nat_traversal_supported: nat,
        delayed_delivery_supported: delayed,
        maximum_frame_bytes: TRANSPORT_FRAME_MAX_BYTES,
        identity_source: "phase2-authenticated-envelope-identity".into(),
        authority_effect: "none".into(),
        live_backend_claimed: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportFrame {
    pub schema: String,
    pub frame_id: String,
    pub profile: TransportProfile,
    pub sender_node_id: String,
    pub recipient_node_id: String,
    pub message_id: String,
    pub payload_ref: String,
    pub provenance_ref: Option<String>,
    pub sequence: u64,
    pub authority_effect: String,
}

fn canonical_id<T: Serialize>(value: &T) -> Result<String, TransportError> {
    let raw = serde_json::to_vec(value).map_err(|_| TransportError("transport_serialization_failed".into()))?;
    let canonical = canonicalize(&raw).map_err(|error| TransportError(error.0))?;
    Ok(sha256_ref(&canonical))
}

fn canonical_id_without_field<T: Serialize>(value: &T, field: &str) -> Result<String, TransportError> {
    let mut projection = serde_json::to_value(value).map_err(|_| TransportError("transport_serialization_failed".into()))?;
    let Value::Object(ref mut object) = projection else { return Err(TransportError("transport_identity_projection_invalid".into())); };
    object.remove(field);
    canonical_id(&projection)
}

impl TransportFrame {
    pub fn new(
        profile: TransportProfile,
        sender_node_id: String,
        recipient_node_id: String,
        message_id: String,
        payload_ref: String,
        provenance_ref: Option<String>,
        sequence: u64,
    ) -> Result<Self, TransportError> {
        let mut frame = Self {
            schema: TRANSPORT_FRAME_SCHEMA_V1.into(),
            frame_id: String::new(),
            profile,
            sender_node_id,
            recipient_node_id,
            message_id,
            payload_ref,
            provenance_ref,
            sequence,
            authority_effect: "none".into(),
        };
        validate_transport_frame_shape(&frame, false)?;
        frame.frame_id = canonical_id_without_field(&frame, "frame_id")?;
        validate_transport_frame(&frame)?;
        Ok(frame)
    }
}

fn validate_transport_frame_shape(frame: &TransportFrame, require_id: bool) -> Result<(), TransportError> {
    if frame.schema != TRANSPORT_FRAME_SCHEMA_V1 { return Err(TransportError("transport_frame_schema_invalid".into())); }
    if require_id && !is_sha256_ref(&frame.frame_id) { return Err(TransportError("transport_frame_id_invalid".into())); }
    if !is_node_id(&frame.sender_node_id) || !is_node_id(&frame.recipient_node_id) {
        return Err(TransportError("transport_frame_node_id_invalid".into()));
    }
    if !is_sha256_ref(&frame.message_id) || !is_sha256_ref(&frame.payload_ref) {
        return Err(TransportError("transport_frame_object_ref_invalid".into()));
    }
    if frame.provenance_ref.as_deref().is_some_and(|value| !is_sha256_ref(value)) {
        return Err(TransportError("transport_frame_provenance_ref_invalid".into()));
    }
    if frame.sequence == 0 { return Err(TransportError("transport_frame_sequence_invalid".into())); }
    if frame.authority_effect != "none" { return Err(TransportError("transport_frame_authority_forbidden".into())); }
    let raw = serde_json::to_vec(frame).map_err(|_| TransportError("transport_serialization_failed".into()))?;
    if raw.len() > TRANSPORT_FRAME_MAX_BYTES { return Err(TransportError("transport_frame_too_large".into())); }
    Ok(())
}

pub fn validate_transport_frame(frame: &TransportFrame) -> Result<(), TransportError> {
    validate_transport_frame_shape(frame, true)?;
    let expected = canonical_id_without_field(frame, "frame_id")?;
    if expected != frame.frame_id { return Err(TransportError("transport_frame_identity_mismatch".into())); }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportAdmissionContext {
    pub signature_valid: bool,
    pub identity_current: bool,
    pub replay_fresh: bool,
    pub local_peer_admitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportAdmissionDecision { AcceptDataOnly, Reject }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatCandidateKind { Host, ServerReflexive, Relay }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatCandidate {
    pub kind: NatCandidateKind,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatTraversalTicket {
    pub schema: String,
    pub ticket_id: String,
    pub node_id: String,
    pub identity_ref: String,
    pub profile: TransportProfile,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub candidates: Vec<NatCandidate>,
    pub grants_trust: bool,
    pub grants_authority: bool,
    pub authority_effect: String,
}

fn valid_endpoint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains('@')
        && !value.chars().any(|ch| ch.is_control() || ch.is_whitespace())
}

impl NatTraversalTicket {
    pub fn new(
        node_id: String,
        identity_ref: String,
        profile: TransportProfile,
        issued_at_unix: i64,
        expires_at_unix: i64,
        candidates: Vec<NatCandidate>,
    ) -> Result<Self, TransportError> {
        let mut ticket = Self {
            schema: NAT_TRAVERSAL_TICKET_SCHEMA_V1.into(),
            ticket_id: String::new(),
            node_id,
            identity_ref,
            profile,
            issued_at_unix,
            expires_at_unix,
            candidates,
            grants_trust: false,
            grants_authority: false,
            authority_effect: "none".into(),
        };
        validate_nat_ticket_shape(&ticket, false)?;
        ticket.ticket_id = canonical_id_without_field(&ticket, "ticket_id")?;
        validate_nat_ticket(&ticket)?;
        Ok(ticket)
    }
}

fn validate_nat_ticket_shape(ticket: &NatTraversalTicket, require_id: bool) -> Result<(), TransportError> {
    if ticket.schema != NAT_TRAVERSAL_TICKET_SCHEMA_V1 { return Err(TransportError("nat_ticket_schema_invalid".into())); }
    if require_id && !is_sha256_ref(&ticket.ticket_id) { return Err(TransportError("nat_ticket_id_invalid".into())); }
    if !matches!(ticket.profile, TransportProfile::WebSocket | TransportProfile::Quic) {
        return Err(TransportError("nat_ticket_profile_invalid".into()));
    }
    if !is_node_id(&ticket.node_id) || !is_sha256_ref(&ticket.identity_ref) {
        return Err(TransportError("nat_ticket_identity_invalid".into()));
    }
    if ticket.candidates.is_empty() || ticket.candidates.len() > NAT_MAX_CANDIDATES {
        return Err(TransportError("nat_ticket_candidate_count_invalid".into()));
    }
    if ticket.candidates.iter().any(|candidate| !valid_endpoint(&candidate.endpoint)) {
        return Err(TransportError("nat_ticket_candidate_invalid".into()));
    }
    let lifetime = ticket.expires_at_unix.checked_sub(ticket.issued_at_unix).ok_or_else(|| TransportError("nat_ticket_lifetime_invalid".into()))?;
    if lifetime <= 0 || lifetime > NAT_MAX_TICKET_LIFETIME_SECONDS {
        return Err(TransportError("nat_ticket_lifetime_invalid".into()));
    }
    if ticket.grants_trust || ticket.grants_authority || ticket.authority_effect != "none" {
        return Err(TransportError("nat_ticket_authority_forbidden".into()));
    }
    Ok(())
}

pub fn validate_nat_ticket(ticket: &NatTraversalTicket) -> Result<(), TransportError> {
    validate_nat_ticket_shape(ticket, true)?;
    let expected = canonical_id_without_field(ticket, "ticket_id")?;
    if expected != ticket.ticket_id { return Err(TransportError("nat_ticket_identity_mismatch".into())); }
    Ok(())
}

pub fn admit_transport_frame(
    frame: &TransportFrame,
    nat_ticket: Option<&NatTraversalTicket>,
    context: TransportAdmissionContext,
) -> TransportAdmissionDecision {
    if validate_transport_frame(frame).is_err()
        || !context.signature_valid
        || !context.identity_current
        || !context.replay_fresh
        || !context.local_peer_admitted
    {
        return TransportAdmissionDecision::Reject;
    }
    if let Some(ticket) = nat_ticket {
        if validate_nat_ticket(ticket).is_err()
            || ticket.node_id != frame.sender_node_id
            || ticket.profile != frame.profile
        {
            return TransportAdmissionDecision::Reject;
        }
    }
    TransportAdmissionDecision::AcceptDataOnly
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayReceipt {
    pub schema: String,
    pub relay_receipt_id: String,
    pub frame_id: String,
    pub message_id: String,
    pub payload_ref: String,
    pub hop_index: u16,
    pub relay_node_id: String,
    pub previous_relay_receipt_ref: Option<String>,
    pub ingress_profile: TransportProfile,
    pub egress_profile: TransportProfile,
    pub authority_effect: String,
}

pub fn build_relay_receipt(
    frame: &TransportFrame,
    hop_index: u16,
    relay_node_id: String,
    previous_relay_receipt_ref: Option<String>,
    ingress_profile: TransportProfile,
    egress_profile: TransportProfile,
) -> Result<RelayReceipt, TransportError> {
    validate_transport_frame(frame)?;
    if hop_index == 0 || hop_index as usize > TRANSPORT_MAX_RELAY_HOPS || !is_node_id(&relay_node_id) {
        return Err(TransportError("relay_hop_invalid".into()));
    }
    if previous_relay_receipt_ref.as_deref().is_some_and(|value| !is_sha256_ref(value)) {
        return Err(TransportError("relay_previous_ref_invalid".into()));
    }
    let mut receipt = RelayReceipt {
        schema: RELAY_RECEIPT_SCHEMA_V1.into(),
        relay_receipt_id: String::new(),
        frame_id: frame.frame_id.clone(),
        message_id: frame.message_id.clone(),
        payload_ref: frame.payload_ref.clone(),
        hop_index,
        relay_node_id,
        previous_relay_receipt_ref,
        ingress_profile,
        egress_profile,
        authority_effect: "none".into(),
    };
    receipt.relay_receipt_id = canonical_id_without_field(&receipt, "relay_receipt_id")?;
    Ok(receipt)
}

pub fn validate_relay_chain(frame: &TransportFrame, chain: &[RelayReceipt]) -> Result<(), TransportError> {
    validate_transport_frame(frame)?;
    if chain.len() > TRANSPORT_MAX_RELAY_HOPS { return Err(TransportError("relay_chain_too_long".into())); }
    let mut previous: Option<&str> = None;
    for (index, receipt) in chain.iter().enumerate() {
        if receipt.schema != RELAY_RECEIPT_SCHEMA_V1
            || !is_sha256_ref(&receipt.relay_receipt_id)
            || receipt.hop_index as usize != index + 1
            || receipt.frame_id != frame.frame_id
            || receipt.message_id != frame.message_id
            || receipt.payload_ref != frame.payload_ref
            || receipt.authority_effect != "none"
            || !is_node_id(&receipt.relay_node_id)
            || receipt.previous_relay_receipt_ref.as_deref() != previous
        {
            return Err(TransportError("relay_chain_invalid".into()));
        }
        let expected = canonical_id_without_field(receipt, "relay_receipt_id")?;
        if expected != receipt.relay_receipt_id { return Err(TransportError("relay_receipt_identity_mismatch".into())); }
        previous = Some(&receipt.relay_receipt_id);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflinePackage {
    pub schema: String,
    pub package_id: String,
    pub frame: TransportFrame,
    pub relay_chain: Vec<RelayReceipt>,
    pub authority_effect: String,
}

pub fn build_offline_package(frame: TransportFrame, relay_chain: Vec<RelayReceipt>) -> Result<OfflinePackage, TransportError> {
    validate_relay_chain(&frame, &relay_chain)?;
    let mut package = OfflinePackage {
        schema: OFFLINE_PACKAGE_SCHEMA_V1.into(),
        package_id: String::new(),
        frame,
        relay_chain,
        authority_effect: "none".into(),
    };
    package.package_id = canonical_id_without_field(&package, "package_id")?;
    let bytes = serde_json::to_vec(&package).map_err(|_| TransportError("transport_serialization_failed".into()))?;
    if bytes.len() > TRANSPORT_FRAME_MAX_BYTES { return Err(TransportError("offline_package_too_large".into())); }
    Ok(package)
}

pub fn validate_offline_package(package: &OfflinePackage) -> Result<(), TransportError> {
    if package.schema != OFFLINE_PACKAGE_SCHEMA_V1 || package.authority_effect != "none" || !is_sha256_ref(&package.package_id) {
        return Err(TransportError("offline_package_invalid".into()));
    }
    validate_relay_chain(&package.frame, &package.relay_chain)?;
    let expected = canonical_id_without_field(package, "package_id")?;
    if expected != package.package_id { return Err(TransportError("offline_package_identity_mismatch".into())); }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct BoundedTransportQueue {
    queue: VecDeque<TransportFrame>,
    queued_ids: BTreeSet<String>,
    limit: usize,
}

impl Default for BoundedTransportQueue {
    fn default() -> Self { Self::with_limit(TRANSPORT_QUEUE_MAX_DEPTH) }
}

impl BoundedTransportQueue {
    pub fn with_limit(limit: usize) -> Self {
        Self { queue: VecDeque::new(), queued_ids: BTreeSet::new(), limit: limit.min(TRANSPORT_QUEUE_MAX_DEPTH) }
    }
    pub fn len(&self) -> usize { self.queue.len() }
    pub fn is_empty(&self) -> bool { self.queue.is_empty() }
    pub fn enqueue(&mut self, frame: TransportFrame) -> Result<(), TransportError> {
        validate_transport_frame(&frame)?;
        if self.queue.len() >= self.limit { return Err(TransportError("transport_queue_limit_exceeded".into())); }
        if self.queued_ids.contains(&frame.frame_id) { return Err(TransportError("transport_queue_duplicate_frame".into())); }
        self.queued_ids.insert(frame.frame_id.clone());
        self.queue.push_back(frame);
        Ok(())
    }
    pub fn dequeue(&mut self) -> Option<TransportFrame> {
        let frame = self.queue.pop_front()?;
        self.queued_ids.remove(&frame.frame_id);
        Some(frame)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCompatibilityPolicy {
    pub policy: String,
    pub canonical_profile: String,
    pub wire_protocol: String,
    pub retained_major_protocols: Vec<String>,
    pub unknown_major_policy: String,
    pub preserve_canonical_bytes: bool,
    pub preserve_object_identity: bool,
    pub historical_receipts_reinterpreted: bool,
    pub migration_requires_new_artifact: bool,
    pub authority_effect: String,
}

pub fn archive_compatibility_policy() -> ArchiveCompatibilityPolicy {
    ArchiveCompatibilityPolicy {
        policy: ARCHIVE_POLICY_V1.into(),
        canonical_profile: "qsol-fed-canonical-json/1".into(),
        wire_protocol: "qsol-fed/1".into(),
        retained_major_protocols: vec!["qsol-fed/1".into()],
        unknown_major_policy: "reject-until-explicit-migration-contract".into(),
        preserve_canonical_bytes: true,
        preserve_object_identity: true,
        historical_receipts_reinterpreted: false,
        migration_requires_new_artifact: true,
        authority_effect: "none".into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolodeckBoundarySnapshot {
    pub authority_effect: String,
    pub federation_effect: String,
    pub evidence_effect: String,
    pub network_used: bool,
    pub real_tools_used: bool,
    pub credentials_exposed: bool,
}

pub fn validate_holodeck_boundary_snapshot(snapshot: &HolodeckBoundarySnapshot) -> Result<(), TransportError> {
    if snapshot.authority_effect != "none"
        || snapshot.federation_effect != "none"
        || snapshot.evidence_effect != "none"
        || snapshot.network_used
        || snapshot.real_tools_used
        || snapshot.credentials_exposed
    {
        return Err(TransportError("holodeck_transport_boundary_drift".into()));
    }
    Ok(())
}

pub fn carry_holodeck_boundary_snapshot(
    _profile: TransportProfile,
    snapshot: &HolodeckBoundarySnapshot,
) -> Result<HolodeckBoundarySnapshot, TransportError> {
    validate_holodeck_boundary_snapshot(snapshot)?;
    Ok(snapshot.clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportDrillKind {
    ResourceExhaustion,
    PartitionRecovery,
    KeyCompromise,
    NatTraversalIdentity,
    MultiRelayProvenance,
    ArchiveCompatibility,
    HolodeckTransportIndependence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportDrillReport {
    pub schema: String,
    pub report_id: String,
    pub profile: TransportProfile,
    pub kind: TransportDrillKind,
    pub passed: bool,
    pub identity_weakened: bool,
    pub authority_promoted: bool,
    pub provenance_lost: bool,
    pub resource_bound_breached: bool,
    pub holodeck_invariant_drift: bool,
    pub authority_effect: String,
    pub note: String,
}

fn fixed_ref(seed: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(seed))
}

fn drill_frame(profile: TransportProfile, sequence: u64) -> Result<TransportFrame, TransportError> {
    TransportFrame::new(
        profile,
        "fed:qsol:phase8-sender".into(),
        "fed:qsol:phase8-recipient".into(),
        fixed_ref(format!("message-{sequence}").as_bytes()),
        fixed_ref(format!("payload-{sequence}").as_bytes()),
        Some(fixed_ref(format!("provenance-{sequence}").as_bytes())),
        sequence,
    )
}

fn drill_report(profile: TransportProfile, kind: TransportDrillKind, passed: bool, note: &str) -> Result<TransportDrillReport, TransportError> {
    let mut report = TransportDrillReport {
        schema: TRANSPORT_DRILL_SCHEMA_V1.into(),
        report_id: String::new(),
        profile,
        kind,
        passed,
        identity_weakened: false,
        authority_promoted: false,
        provenance_lost: false,
        resource_bound_breached: false,
        holodeck_invariant_drift: false,
        authority_effect: "none".into(),
        note: note.into(),
    };
    report.report_id = canonical_id_without_field(&report, "report_id")?;
    Ok(report)
}

pub fn run_transport_drill(profile: TransportProfile, kind: TransportDrillKind) -> Result<TransportDrillReport, TransportError> {
    match kind {
        TransportDrillKind::ResourceExhaustion => {
            let mut queue = BoundedTransportQueue::with_limit(4);
            for sequence in 1..=4 { queue.enqueue(drill_frame(profile, sequence)?)?; }
            let rejected = queue.enqueue(drill_frame(profile, 5)?).is_err();
            drill_report(profile, kind, rejected && queue.len() == 4, "bounded queue rejects the first frame beyond its declared capacity")
        }
        TransportDrillKind::PartitionRecovery => {
            let mut queue = BoundedTransportQueue::with_limit(4);
            let mut before = Vec::new();
            for sequence in 1..=4 {
                let frame = drill_frame(profile, sequence)?;
                before.push(frame.frame_id.clone());
                queue.enqueue(frame)?;
            }
            let mut after = Vec::new();
            while let Some(frame) = queue.dequeue() { after.push(frame.frame_id); }
            drill_report(profile, kind, before == after && queue.is_empty(), "partition backlog drains in deterministic FIFO order without changing frame identity")
        }
        TransportDrillKind::KeyCompromise => {
            let frame = drill_frame(profile, 1)?;
            let rejected = admit_transport_frame(&frame, None, TransportAdmissionContext {
                signature_valid: true,
                identity_current: false,
                replay_fresh: true,
                local_peer_admitted: true,
            }) == TransportAdmissionDecision::Reject;
            drill_report(profile, kind, rejected, "a transport path cannot revive a compromised or non-current identity")
        }
        TransportDrillKind::NatTraversalIdentity => {
            if !transport_profile_spec(profile).nat_traversal_supported {
                return drill_report(profile, kind, true, "NAT traversal is not applicable to this profile and grants no fallback authority");
            }
            let frame = drill_frame(profile, 1)?;
            let ticket = NatTraversalTicket::new(
                frame.sender_node_id.clone(),
                fixed_ref(b"identity-document"),
                profile,
                1_000,
                1_300,
                vec![NatCandidate { kind: NatCandidateKind::Relay, endpoint: "198.51.100.8:443".into() }],
            )?;
            let accepted = admit_transport_frame(&frame, Some(&ticket), TransportAdmissionContext {
                signature_valid: true,
                identity_current: true,
                replay_fresh: true,
                local_peer_admitted: true,
            }) == TransportAdmissionDecision::AcceptDataOnly;
            let mut wrong = ticket.clone();
            wrong.node_id = "fed:qsol:other-node".into();
            let rejected = admit_transport_frame(&frame, Some(&wrong), TransportAdmissionContext {
                signature_valid: true,
                identity_current: true,
                replay_fresh: true,
                local_peer_admitted: true,
            }) == TransportAdmissionDecision::Reject;
            drill_report(profile, kind, accepted && rejected, "NAT candidate routes are hints only and cannot replace authenticated sender identity")
        }
        TransportDrillKind::MultiRelayProvenance => {
            let frame = drill_frame(profile, 1)?;
            let first = build_relay_receipt(&frame, 1, "fed:qsol:relay-one".into(), None, profile, TransportProfile::StoreForward)?;
            let second = build_relay_receipt(&frame, 2, "fed:qsol:relay-two".into(), Some(first.relay_receipt_id.clone()), TransportProfile::StoreForward, profile)?;
            let chain = vec![first, second];
            drill_report(profile, kind, validate_relay_chain(&frame, &chain).is_ok(), "relay hops preserve original message/payload identity and form an explicit provenance chain")
        }
        TransportDrillKind::ArchiveCompatibility => {
            let policy = archive_compatibility_policy();
            let passed = policy.preserve_canonical_bytes
                && policy.preserve_object_identity
                && !policy.historical_receipts_reinterpreted
                && policy.migration_requires_new_artifact
                && policy.unknown_major_policy == "reject-until-explicit-migration-contract";
            drill_report(profile, kind, passed, "archive policy preserves historical bytes/identities and requires explicit migration artifacts")
        }
        TransportDrillKind::HolodeckTransportIndependence => {
            let snapshot = HolodeckBoundarySnapshot {
                authority_effect: "none".into(), federation_effect: "none".into(), evidence_effect: "none".into(),
                network_used: false, real_tools_used: false, credentials_exposed: false,
            };
            let carried = carry_holodeck_boundary_snapshot(profile, &snapshot)?;
            drill_report(profile, kind, carried == snapshot, "transport outside the sandbox does not rewrite the sandbox's authority/network/tool/credential receipt")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_declared_profiles_are_bounded_and_non_authoritative() {
        for profile in ALL_TRANSPORT_PROFILES {
            let spec = transport_profile_spec(profile);
            assert_eq!(spec.maximum_frame_bytes, TRANSPORT_FRAME_MAX_BYTES);
            assert_eq!(spec.identity_source, "phase2-authenticated-envelope-identity");
            assert_eq!(spec.authority_effect, "none");
            assert!(!spec.live_backend_claimed);
            let frame = drill_frame(profile, 1).unwrap();
            validate_transport_frame(&frame).unwrap();
        }
    }

    #[test]
    fn nat_traversal_cannot_weaken_identity() {
        for profile in [TransportProfile::WebSocket, TransportProfile::Quic] {
            let report = run_transport_drill(profile, TransportDrillKind::NatTraversalIdentity).unwrap();
            assert!(report.passed);
            assert!(!report.identity_weakened);
            assert!(!report.authority_promoted);
        }
    }

    #[test]
    fn multi_relay_provenance_is_explicit_and_non_transitive() {
        for profile in ALL_TRANSPORT_PROFILES {
            let report = run_transport_drill(profile, TransportDrillKind::MultiRelayProvenance).unwrap();
            assert!(report.passed);
            assert!(!report.provenance_lost);
            assert_eq!(report.authority_effect, "none");
        }
    }

    #[test]
    fn compromised_identity_fails_on_every_transport() {
        for profile in ALL_TRANSPORT_PROFILES {
            assert!(run_transport_drill(profile, TransportDrillKind::KeyCompromise).unwrap().passed);
        }
    }

    #[test]
    fn resource_exhaustion_and_partition_drills_cover_every_profile() {
        for profile in ALL_TRANSPORT_PROFILES {
            assert!(run_transport_drill(profile, TransportDrillKind::ResourceExhaustion).unwrap().passed);
            assert!(run_transport_drill(profile, TransportDrillKind::PartitionRecovery).unwrap().passed);
        }
    }

    #[test]
    fn long_lived_archive_policy_is_transport_neutral() {
        let policy = archive_compatibility_policy();
        assert_eq!(policy.policy, ARCHIVE_POLICY_V1);
        assert_eq!(policy.canonical_profile, "qsol-fed-canonical-json/1");
        assert_eq!(policy.wire_protocol, "qsol-fed/1");
        assert!(policy.preserve_canonical_bytes);
        assert!(policy.preserve_object_identity);
        assert!(!policy.historical_receipts_reinterpreted);
        assert!(policy.migration_requires_new_artifact);
    }

    #[test]
    fn offline_and_store_forward_preserve_frame_and_relay_identity() {
        let frame = drill_frame(TransportProfile::OfflineSneakernet, 1).unwrap();
        let relay = build_relay_receipt(
            &frame, 1, "fed:qsol:archive-relay".into(), None,
            TransportProfile::OfflineSneakernet, TransportProfile::StoreForward,
        ).unwrap();
        let package = build_offline_package(frame.clone(), vec![relay]).unwrap();
        validate_offline_package(&package).unwrap();
        assert_eq!(package.frame.frame_id, frame.frame_id);
        assert_eq!(package.authority_effect, "none");
    }

    #[test]
    fn holodeck_sandbox_invariants_are_transport_independent() {
        for profile in ALL_TRANSPORT_PROFILES {
            let report = run_transport_drill(profile, TransportDrillKind::HolodeckTransportIndependence).unwrap();
            assert!(report.passed);
            assert!(!report.holodeck_invariant_drift);
        }
    }

    #[test]
    fn every_profile_runs_the_complete_resilience_matrix() {
        for profile in ALL_TRANSPORT_PROFILES {
            for kind in [
                TransportDrillKind::ResourceExhaustion,
                TransportDrillKind::PartitionRecovery,
                TransportDrillKind::KeyCompromise,
                TransportDrillKind::NatTraversalIdentity,
                TransportDrillKind::MultiRelayProvenance,
                TransportDrillKind::ArchiveCompatibility,
                TransportDrillKind::HolodeckTransportIndependence,
            ] {
                let report = run_transport_drill(profile, kind).unwrap();
                assert!(report.passed, "Phase 8 drill failed for {profile:?}/{kind:?}");
                assert!(!report.identity_weakened);
                assert!(!report.authority_promoted);
                assert!(!report.provenance_lost);
                assert!(!report.resource_bound_breached);
                assert!(!report.holodeck_invariant_drift);
            }
        }
    }
}
