#![forbid(unsafe_code)]

//! QSOL-FED constitutional, canonical wire, cryptographic identity, opt-in HTTP,
//! and durable Phase 4 federation-state core.
//!
//! Persistence, import, peering, trust, and capability policy remain separate
//! from truth, evidence, authority, and constitutional admission.

pub mod api;
pub mod bundle;
pub mod canonical;
pub mod claims;
mod crypto;
pub mod envelope;
pub mod invariants;
pub mod peering;
pub mod replay;
pub mod store;
pub mod wire;

pub use api::{
    build_router, ApiBuildError, ApiState, AuditRecord, PeerHello,
    PeerLifecycleRecord as ApiPeerLifecycleRecord, API_MAX_BODY_BYTES, API_MAX_CAPABILITIES,
    API_MAX_EXPORT_OBJECTS, API_MAX_LIFECYCLE_RECORDS, API_POSTS_PER_MINUTE,
    API_REQUESTS_PER_MINUTE, PEER_HELLO_SCHEMA_V1, RATE_LIMIT_CLIENT_IP_HEADER,
};
pub use bundle::{
    export_bundle, import_bundle, verify_bundle, BundleError, BundleImportReceipt, BundleObject,
    BundlePeer, BundleVerificationReport, PortableFederationBundle, FEDERATION_BUNDLE_SCHEMA_V1,
    MAX_BUNDLE_BYTES, MAX_BUNDLE_OBJECTS, MAX_BUNDLE_PEERS,
};
pub use canonical::{
    canonicalize, derive_message_id, object_id, parse_canonical_value, serialize_canonical,
    sha256_ref, CanonicalError, CanonicalValue, CANONICAL_PROFILE,
};
pub use claims::{
    is_established, CurrentClaims, Phase0Claims, ReleaseClaim, CURRENT_CLAIMS, PHASE0_CLAIMS,
    PHASE0_GATE_ID, PHASE2_GATE_ID, PHASE3_GATE_ID, PHASE4_GATE_ID,
};
pub use crypto::{
    create_identity_document, derive_key_id, derive_node_id, sign_envelope,
    verify_identity_document, AuthenticationAssessment, AuthorityDisposition, CryptoError,
    IdentityState, KeyRotationRecord, KeyStatusKind, KeyStatusReason, KeyStatusRecord,
    LocalSigningKey, NodeIdentityDocument, OperationalKeyState, OperationalKeyStatus, RotationMode,
    SignatureValidity, SignedEnvelope, SigningAlgorithm, TrustDisposition, ENVELOPE_SIGNATURE_DOMAIN,
    KEY_ROTATION_SCHEMA_V1, KEY_STATUS_SCHEMA_V1, MAX_CLOCK_SKEW_SECONDS,
    MAX_ROTATION_OVERLAP_SECONDS, MAX_SIGNED_MESSAGE_LIFETIME_SECONDS, NODE_IDENTITY_SCHEMA_V1,
    SIGNED_ENVELOPE_SCHEMA_V1,
};
pub use envelope::{AuthorityClaim, FederationEnvelope, MessageClass, NodeManifest};
pub use invariants::{
    admit_effect, AdmissionDecision, FederationEffect, HardInvariant, CHARTER_ID,
    HARD_INVARIANTS, PRIME_DIRECTIVE_ID, PROTOCOL_ID,
};
pub use peering::{
    create_capability_advertisement, rebuild_peer_identity, verify_capability_advertisement,
    verify_capability_advertisement_signature, CapabilityAdvertisement, CapabilityDecision,
    LocalCapabilityPolicy, LocalTrustLevel, PeerLifecycleState, PeerRecord, PeerRegistry,
    PeerStateView, PeeringError, RegistryWriteDisposition, RejoinDisposition, TrustRegistry,
    CAPABILITY_ADVERTISEMENT_SCHEMA_V1, CAPABILITY_POLICY_SCHEMA_V1,
    MAX_CAPABILITY_ADVERTISEMENT_LIFETIME_SECONDS, MAX_PEER_LIFECYCLE_RECORDS,
    PEER_RECORD_SCHEMA_V1, TRUST_REGISTRY_SCHEMA_V1,
};
pub use replay::{
    DurableReplayStore, ReplayDecision, ReplayError, MAX_REPLAY_LOG_BYTES,
    REPLAY_COMPACTION_THRESHOLD_BYTES, REPLAY_RETENTION_SECONDS,
};
pub use store::{
    FederationObjectStore, ForeignNamespace, ForeignObjectRecord, LocalDescendantRecord,
    StoreError, FOREIGN_RECORD_SCHEMA_V1, LOCAL_DESCENDANT_SCHEMA_V1,
};
pub use wire::{
    classify_protocol, is_capability_id, is_node_id, is_sha256_ref, is_wire_timestamp,
    ProtocolDisposition, ProtocolErrorCode, ProtocolErrorEnvelope, ProvenanceObject,
    ProvenanceRelation, ERROR_SCHEMA_V1, PROTOCOL_V1, PROVENANCE_SCHEMA_V1,
};

/// Verify a Phase 2 signed envelope using the frozen constitutional clock maxima.
///
/// External callers cannot widen the 300-second skew or 3,600-second signed-message
/// lifetime. Stricter local policy may reject the authenticated result afterward,
/// but cryptographic verification never accepts a looser clock window.
pub fn verify_signed_envelope(
    signed: &SignedEnvelope,
    identity: &IdentityState,
    now_unix: i64,
) -> Result<AuthenticationAssessment, CryptoError> {
    crypto::verify_signed_envelope(signed, identity, now_unix, crypto::DEFAULT_CLOCK_POLICY)
}
