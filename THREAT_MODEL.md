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

Phase 9 additionally assumes that a repository-aware adversarial operator may deliberately search across phase boundaries for contradictions, authority laundering, parser splits, unsafe restart behavior, transport confusion, Assembly capture, or Holodeck escape paths. The operator is untrusted input to the review process, not an execution or authority principal.

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

**Mitigation:** durable message identity, expiry and replay state; replay freshness remains separate from authority and local admission.

### T8. Downgrade

A peer forces an older protocol/capability mode that weakens constitutional protections.

**Mitigation:** unsupported majors reject; no downgrade may disable constitutional invariants.

### T9. Resource exhaustion

Oversized/deep JSON, decompression bombs, object floods or expensive verification consume resources.

**Mitigation:** bounded framing, depth, size, rate, queue and cache policies; deterministic exhaustion drills cover API, Holodeck and transport surfaces.

### T10. SSRF / confused deputy

A peer causes the node to fetch arbitrary URLs or access local/cloud metadata services.

**Mitigation:** no arbitrary peer-directed fetch; reviewed fixed/disclosed retrieval mechanisms only.

### T11. Secret exfiltration

Credentials leak into payloads, logs, prompts or exported provenance.

**Mitigation:** separate operational secret state; semantic state prohibition; secret-aware logging and adapters.

### T12. Parser ambiguity / canonicalization split

Different implementations sign or hash semantically equivalent but byte-different structures.

**Mitigation:** frozen canonicalization, hostile fixtures and cross-language golden vectors.

### T13. Sybil / peer swarm

Many identities attempt to manufacture apparent consensus or exhaust resources.

**Mitigation:** Federation does not equate peer count with truth or authority; local peering/rate policies remain sovereign. Assembly registry uniqueness is not overclaimed as proof of real-world principal uniqueness.

### T14. Compromised trusted peer

A previously trusted key behaves maliciously.

**Mitigation:** trust never bypasses Prime Directive invariants; key lifecycle, compromise/recovery/revocation and local quarantine remain authoritative across transports.

### T15. Local adapter privilege escalation

A NEXUS/ORACLE/ARK adapter accidentally maps foreign data into local authority-bearing operations.

**Mitigation:** adapter calls preserve the same invariant IDs as the core node and remain data/observation/preservation membranes rather than authority bridges.

### T16. Cross-phase contradiction

Two individually valid phase contracts compose into a path that weakens an earlier invariant, for example transport changing identity semantics, Assembly output becoming a member-local command, or archival presence changing provenance meaning.

**Mitigation:** MORIARTY/1 maps explicit cross-phase attack families to every historical phase gate plus the complete Rust regression suite. A reproducible contradiction reopens the owning phase and becomes a permanent regression.

### T17. Adversarial-operator confused deputy

A model or human reviewer proposes a command, URL, credential, target, or constitutional bypass and the security harness executes it merely because it was supplied as an adversarial test.

**Mitigation:** the Phase 9 attack corpus contains source-owned probe IDs only. The runner owns a closed fixed argv map, invokes no shell, accepts no operator-selected command/network target/credential, and binds execution to the exact checked-out commit.

### T18. Security-report overclaim

A green adversarial run is described as proof that no vulnerability or counterexample exists.

**Mitigation:** every report hard-codes `security_proof = false` and `no_counterexample_found_implies_none_exist = false`.

## Current non-claims

The repository now implements historical identity, replay, reference API, state, Holodeck, adapter, SDK, Assembly and transport-resilience gates, but it still does not claim:

- production networking;
- arbitrary remote execution;
- host-level sandbox isolation;
- deployed interoperable federation;
- Holodeck synthetic output as ORACLE evidence;
- universal security merely because MORIARTY/1 is green.

Those claims require their own explicit evidence and reviewed promotion path. Phase 9 intentionally changes none of them.

## MORIARTY/1 adversarial boundary

MORIARTY receives public repository blueprints and disposable repository fixtures only. It receives no production credentials, production targets, private infrastructure endpoints, member-local authority handles, or constitutional bypass.

Accepted findings use `moriarty-counterexample/1`. A finding remains blocking until locally reproduced, assigned to its owning phase/boundary, repaired, and preserved as a regression.

```text
COUNTEREXAMPLE != AUTHORITY
ADVERSARIAL OPERATOR != EXECUTION AUTHORITY
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
```

## Security invariant

The most important threat-model rule is intentionally boring:

> No amount of remote agreement, simulated persuasion, adversarial confidence, or green-report ceremony is itself permission to cross a local authority boundary.
