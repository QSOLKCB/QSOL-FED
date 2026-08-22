#![forbid(unsafe_code)]

//! QSOL-FED constitutional core and Phase 1 canonical wire contract.
//!
//! This crate still exposes no production network listener, cryptographic node
//! identity, or remote execution. Phase 1 freezes deterministic wire bytes only.

pub mod canonical;
pub mod claims;
pub mod envelope;
pub mod invariants;
pub mod wire;

pub use canonical::{
    canonicalize, derive_message_id, object_id, parse_canonical_value, serialize_canonical,
    sha256_ref, CanonicalError, CanonicalValue, CANONICAL_PROFILE,
};
pub use claims::{is_established, Phase0Claims, ReleaseClaim, PHASE0_CLAIMS, PHASE0_GATE_ID};
pub use envelope::{AuthorityClaim, FederationEnvelope, MessageClass, NodeManifest};
pub use invariants::{
    admit_effect, AdmissionDecision, FederationEffect, HardInvariant, CHARTER_ID,
    HARD_INVARIANTS, PRIME_DIRECTIVE_ID, PROTOCOL_ID,
};
pub use wire::{
    classify_protocol, is_capability_id, is_node_id, is_sha256_ref, is_wire_timestamp,
    ProtocolDisposition, ProtocolErrorCode, ProtocolErrorEnvelope, ProvenanceObject,
    ProvenanceRelation, ERROR_SCHEMA_V1, PROTOCOL_V1, PROVENANCE_SCHEMA_V1,
};
