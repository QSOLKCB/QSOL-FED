#![forbid(unsafe_code)]

//! QSOL-FED bootstrap constitutional core.
//!
//! This crate intentionally does not expose a network listener. PR #1 establishes
//! fail-closed federation admission semantics and protocol data structures only.

pub mod envelope;
pub mod invariants;

pub use envelope::{AuthorityClaim, FederationEnvelope, MessageClass, NodeManifest};
pub use invariants::{
    admit_effect, AdmissionDecision, FederationEffect, HardInvariant, CHARTER_ID,
    HARD_INVARIANTS, PRIME_DIRECTIVE_ID, PROTOCOL_ID,
};
