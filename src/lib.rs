#![forbid(unsafe_code)]

//! QSOL-FED constitutional, canonical wire, and Phase 2 cryptographic identity core.
//!
//! This crate still exposes no production network listener or remote execution.
//! Cryptographic validity remains separate from trust, authority, and admission.

pub mod canonical;
pub mod claims;
pub mod crypto;
pub mod envelope;
pub mod invariants;
pub mod replay;
pub mod wire;

pub use canonical::{
    canonicalize, derive_message_id, object_id, parse_canonical_value, serialize_canonical,
    sha256_ref, CanonicalError, CanonicalValue, CANONICAL_PROFILE,
};
pub use claims::{
    is_established, CurrentClaims, Phase0Claims, ReleaseClaim, CURRENT_CLAIMS, PHASE0_CLAIMS,
    PHASE0_GATE_ID, PHASE2_GATE_ID,
};
pub use crypto::{
    create_identity_document, derive_key_id, derive_node_id, sign_envelope,
    verify_identity_document, verify_signed_envelope, AuthenticationAssessment,
    AuthorityDisposition, ClockPolicy, CryptoError, IdentityState, KeyRotationRecord,
    KeyStatusKind, KeyStatusReason, KeyStatusRecord, LocalSigningKey, NodeIdentityDocument,
    OperationalKeyState, OperationalKeyStatus, RotationMode, SignatureValidity, SignedEnvelope,
    SigningAlgorithm, TrustDisposition, DEFAULT_CLOCK_POLICY, ENVELOPE_SIGNATURE_DOMAIN,
    KEY_ROTATION_SCHEMA_V1, KEY_STATUS_SCHEMA_V1, MAX_CLOCK_SKEW_SECONDS,
    MAX_ROTATION_OVERLAP_SECONDS, MAX_SIGNED_MESSAGE_LIFETIME_SECONDS,
    NODE_IDENTITY_SCHEMA_V1, SIGNED_ENVELOPE_SCHEMA_V1,
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
