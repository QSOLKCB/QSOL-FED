#![forbid(unsafe_code)]

//! QSOL-FED constitutional, canonical wire, cryptographic identity, and opt-in HTTP API core.
//!
//! The reference listener is opt-in and remains separate from production-networking claims.
//! Cryptographic validity remains separate from trust, authority, evidence, and admission.

pub mod api;
pub mod canonical;
pub mod claims;
mod crypto;
pub mod envelope;
pub mod invariants;
pub mod replay;
pub mod wire;

pub use api::{
    build_router, ApiBuildError, ApiState, AuditRecord, PeerHello, API_MAX_BODY_BYTES,
    API_MAX_CAPABILITIES, API_MAX_EXPORT_OBJECTS, API_POSTS_PER_MINUTE,
    API_REQUESTS_PER_MINUTE, PEER_HELLO_SCHEMA_V1,
};
pub use canonical::{
    canonicalize, derive_message_id, object_id, parse_canonical_value, serialize_canonical,
    sha256_ref, CanonicalError, CanonicalValue, CANONICAL_PROFILE,
};
pub use claims::{
    is_established, CurrentClaims, Phase0Claims, ReleaseClaim, CURRENT_CLAIMS, PHASE0_CLAIMS,
    PHASE0_GATE_ID, PHASE2_GATE_ID, PHASE3_GATE_ID,
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
pub use replay::{DurableReplayStore, ReplayDecision, ReplayError, MAX_REPLAY_LOG_BYTES};
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
