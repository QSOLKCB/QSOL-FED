# Threat Model

## Assets

QSOL-FED must protect:

- local sovereignty and governance;
- evidence labels and provenance;
- Council integrity;
- local history;
- node identity keys and credentials;
- capability boundaries;
- execution environment;
- availability;
- protocol-version integrity.

## Adversaries

Assume a peer may be malicious, compromised, buggy, stale, spoofed, replaying old traffic, correctly authenticated but unauthorized, or attempting to exploit parser/resource limits.

Also assume local adapters and AI models can be wrong. Model confidence is not a security primitive.

## Primary threats

### T1. Authority injection

A peer submits a message that attempts to create local governance/evidence/voting authority.

**Mitigation:** hard-coded Prime Directive admission rejection; foreign material remains data-only by default.

### T2. Remote code/tool execution

A peer disguises executable instructions as a capability, payload, tool request or imported object.

**Mitigation:** arbitrary remote execution is absent/forbidden in v1; local adapters must not execute semantic payload content.

### T3. State laundering

Foreign state is imported and relabelled as locally authoritative merely because it is signed or content-addressed.

**Mitigation:** foreign state identity is preserved; import is not authority; local descendants require explicit local processes.

### T4. Consensus laundering

A remote Council majority is treated as evidence or a local vote.

**Mitigation:** remote Council reports are attributed artifacts only; consensus is not truth; vote injection is forbidden.

### T5. Capability confusion

Advertisement is mistaken for authorization, or version negotiation enables unknown behavior.

**Mitigation:** capability != entitlement; explicit version negotiation; unknown authority semantics reject.

### T6. Signature confusion

A valid signature is interpreted as truth, identity semantics or authorization.

**Mitigation:** signature/authentication and local admission are separate stages.

### T7. Replay

Captured valid envelopes are resent to produce duplicate effects.

**Mitigation:** future message identity, expiry and replay store; v1 does not claim production networking before this exists.

### T8. Downgrade

A peer forces an older protocol/capability mode that weakens constitutional protections.

**Mitigation:** unsupported majors reject; no downgrade may disable constitutional invariants.

### T9. Resource exhaustion

Oversized/deep JSON, decompression bombs, object floods or expensive verification consume resources.

**Mitigation:** bounded framing, depth, size, rate and cache policies before production listener exposure.

### T10. SSRF / confused deputy

A peer causes the node to fetch arbitrary URLs or access local/cloud metadata services.

**Mitigation:** no arbitrary peer-directed fetch; reviewed fixed/disclosed retrieval mechanisms only.

### T11. Secret exfiltration

Credentials leak into payloads, logs, prompts or exported provenance.

**Mitigation:** separate operational secret state; semantic state prohibition; secret-aware logging and adapters.

### T12. Parser ambiguity / canonicalization split

Different implementations sign or hash semantically equivalent but byte-different structures.

**Mitigation:** freeze canonicalization with cross-language vectors before claiming wire interoperability.

### T13. Sybil / peer swarm

Many identities attempt to manufacture apparent consensus or exhaust resources.

**Mitigation:** Federation does not equate peer count with truth or authority; local peering/rate policies remain sovereign.

### T14. Compromised trusted peer

A previously trusted key behaves maliciously.

**Mitigation:** trust never bypasses Prime Directive invariants; future revocation/rotation mechanisms; local quarantine.

### T15. Local adapter privilege escalation

A NEXUS/ORACLE/ARK adapter accidentally maps foreign data into local authority-bearing operations.

**Mitigation:** adapter calls occur after Prime Directive admission and must preserve the same invariant IDs in conformance tests.

## Out of scope for bootstrap

PR #1 does not claim mitigation by implementation for network attacks that require a live listener, cryptographic identity stack, durable replay database or production key management. Those remain roadmap gates.

## Security invariant

The most important threat-model rule is intentionally boring:

> No amount of remote agreement is itself permission to cross a local authority boundary.
