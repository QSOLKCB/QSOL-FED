#![forbid(unsafe_code)]

//! QSOL-FED bootstrap constitutional core.
//!
//! This crate intentionally does not expose a network listener. The current
//! repository establishes fail-closed federation admission semantics, protocol
//! data structures, and an executable Phase 0 release-claim gate only.

pub mod claims;
pub mod envelope;
pub mod invariants;

pub use claims::{is_established, Phase0Claims, ReleaseClaim, PHASE0_CLAIMS, PHASE0_GATE_ID};
pub use envelope::{AuthorityClaim, FederationEnvelope, MessageClass, NodeManifest};
pub use invariants::{
    admit_effect, AdmissionDecision, FederationEffect, HardInvariant, CHARTER_ID,
    HARD_INVARIANTS, PRIME_DIRECTIVE_ID, PROTOCOL_ID,
};
