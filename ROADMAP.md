# ROADMAP

QSOL-FED is built **protocol first, parliament later**. Every completed phase keeps its historical security gate while successor claim manifests advance the current implementation boundary.

## Phase 0 — Constitutional bootstrap

**Status: complete; historical claim gate preserved in code and CI.**

Constitution, Prime Directive, machine-readable invariants, fail-closed admission, schemas, tests, and CI are complete. `claims/phase0.json` remains immutable history.

### Phase 0 gate

Phase 0 claimed only the tested constitutional model, machine contracts, and fail-closed admission skeleton. Production networking, cryptographic identity, remote execution, and interoperable federation were false.

---

## Phase 1 — Canonical wire contract

**Status: complete; two-implementation conformance gate enforced.**

Canonical JSON, NFC policy, duplicate/non-finite rejection, safe integers, exact `sha256:` identity, envelope/message-ID/provenance/error contracts, capability grammar, golden vectors, hostile fixtures, Rust/Python canonicalizers, and unsupported-major rejection are complete.

### Phase 1 gate

Two independent implementations must produce byte-identical canonical bytes and hashes for the golden fixtures before signatures are layered on top.

---

## Phase 2 — Cryptographic node identity

**Status: complete; historical cryptographic identity gate preserved.**

Ed25519 identity, root/operational key separation, detached signatures, lifecycle rotation/revocation/recovery, frozen clock limits, durable replay, algorithm-confusion tests, and compromised-peer tests are complete.

### Phase 2 gate

A valid signature must never bypass local admission. Tests must show that a correctly signed forbidden request is still rejected.

---

## Phase 3 — Reference federation API

**Status: complete; opt-in reference API gate enforced.**

The six `/fed/v1` routes, canonical/body/rate limits, lifecycle-aware introduction, replay-safe envelope admission, local-recipient routing, local-only object lookup, SSRF/redirect isolation, secret-safe audit, TLS deployment profile, trusted-proxy rate attribution, and fuzz/adversarial suite are complete.

### Phase 3 gate

Public network listening remains opt-in until replay protection, limits, identity verification and fuzz/adversarial suites are green.

The listener remains a reference service, not a production-networking claim.

---

## Phase 4 — Federation object store and peering

**Status: complete; durable federation-state gate enforced.**

Content-addressed foreign/quarantine storage, multiple source/provenance attributions, provenance-preserving descendants, durable peer lifecycle, separate trust registry, expiring capability advertisements, local allow/deny policy, partition/rejoin controls, portable bundles, offline verification, append-only lifecycle prefixes, persist-before-live local writes, and crash-recoverable namespace moves are complete.

### Phase 4 gate

Import/export round-trips must preserve foreign identity and provenance exactly. Import must not create local authority.

---

## Phase 5 — QSOL adapters and synthetic worlds

**Status: complete; historical Phase 5 and Phase 5C gates preserved.**

### Phase 5A — QSOL-NEXUS AI Holodeck sandbox

**Status: complete; historical Holodeck gate preserved.**

- [x] `qsol-fed-nexus-world-source/1` preserves NEXUS export lineage without authority.
- [x] Deterministic Holodeck program/world/event identities.
- [x] Capability-less application sandbox with hard Computer safeguards.
- [x] `Computer, end program` survives frozen state and event-ledger exhaustion.
- [x] Moriarty feature-level escape/boundary regressions.
- [x] Explicit host-level sandbox non-claim.
- [x] Live local QSOL-NEXUS adapter constructs source manifests only after native verification.
- [x] Reviewed Council actors project into synthetic Holodeck actors without authority inheritance.

### Phase 5A gate

For identical verified source manifests and seeds, the reference implementation must produce byte-identical world plans and event identities.

`Computer, end program` must terminate a frozen simulation without simulated approval.

```text
MORIARTY REPORT != SECURITY PROOF
SIMULATION != AUTHORITY
```

### Phase 5B — QSOL-NEXUS Federation adapter

- [x] Export Council and minority reports as attributed artifacts.
- [x] Import without vote injection or evidence promotion.
- [x] Preserve Council equality without inherited authority.
- [x] Independent re-deliberation.
- [x] Council-of-Councils uses reports, not a shared ballot.

### QSOL-ORACLE historical Phase 5 membrane

- [x] Preserve `known` / `conflict` / `unknown` without authority promotion.
- [x] Suggested searches remain non-evidence.
- [x] Remote evidence promotion rejected.
- [x] Historical `oracle_live_transport = false` remains frozen in `claims/phase5.json`.

### QSOL-ARK

- [x] Content-addressed offline preservation.
- [x] Archival presence remains non-authoritative.
- [x] Holodeck artifacts remain synthetic cultural/research material.

### Phase 5 gate

Every adapter must prove it cannot bypass the same Prime Directive invariant IDs enforced by the core node. NEXUS integration must additionally prove that `SIMULATION != AUTHORITY` survives the adapter boundary.

### Phase 5C — QSOL-ORACLE live transport

**Status: complete; historical attested live-local ORACLE gate preserved.**

Pinned donor commit: `043e864b3c25dfeca3ce1752b3110479479071b1`.

- [x] Attested donor release and exact schema/contract comparison.
- [x] Private staged runtime per request.
- [x] Bounded canonical local stdio JSONL.
- [x] Response identity/provenance verification.
- [x] `oracle_live_transport = true`.
- [x] `oracle_holodeck_synthetic_admission = false`.
- [x] Production networking and remote execution remain false.

### Phase 5C gate

The exact reviewed QSOL-ORACLE donor release must attest locally before process launch. FED must preserve `known` / `conflict` / `unknown` without truth or authority promotion.

```text
oracle_holodeck_synthetic_admission = false
host_level_sandbox                  = false
production_networking               = false
remote_execution                    = false
interoperable_federation            = false
```

---

## Phase 6 — Third-party federation SDKs

**Status: complete; historical third-party SDK gate preserved by `claims/phase6.json`.**

- [x] Minimal protocol SDK contract.
- [x] Rust, Python, and JavaScript/TypeScript SDKs.
- [x] Language-neutral conformance suite.
- [x] Minimal non-QSOL node.
- [x] Institutional/research integration docs.
- [x] Interop test across at least three independent implementations.

### Phase 6 gate

A non-NEXUS, non-QSOL-specific node must participate without adopting QSOL internal governance.

```text
WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP
SDK CONFORMANCE != TRUST
```

Phase 6 proves local three-implementation protocol conformance. It does not claim deployed `interoperable_federation`.

---

## Phase 7 — Federation Assembly

**Status: current; sovereignty-preserving Assembly gate enforced by `claims/phase7.json`.**

- [x] Separate Assembly membership from network membership.
- [x] Proposal/amendment lifecycle, representation and anti-Sybil assumptions.
- [x] Deterministic Charter Gate.
- [x] Preserve member-local sovereignty and NEXUS advisory status.
- [x] Transparent fork/version path and governance receipts.

### Membership and representation

Assembly membership requires explicit local opt-in and does not follow network membership. The reference model is `one-member-one-vote/1`, freezes the electorate when a proposal opens, and rejects duplicate votes rather than replacing history.

The registry enforces one active NFC-normalized representation subject, but does not claim to prove real-world principal uniqueness. That remains an explicit admission-policy assumption.

### Deterministic Charter Gate

`qsol-fed-charter-gate/1` maps declared proposal effects to existing invariant IDs. A proposal that conflicts with the sitting constitutional lineage becomes `fork_required` instead of gaining an override through majority vote.

### NEXUS advisory status

NEXUS reports may be attached as advisory artifacts with:

```text
advisory_weight = 0
vote_weight     = 0
authority_effect = none
```

Running NEXUS does not create Assembly membership.

### Fork/version path and receipts

Accepted governance creates deterministic `qsol-fed-governance-receipt/1` records. Backward-compatible amendments require explicit source change; breaking/Charter amendments require a new major; constitutional conflicts require an explicit fork path.

```text
protocol_changed_automatically = false
member_local_authority_mutated = false
```

### Phase 7 gate

No Assembly mechanism may directly mutate member-local authority.

---

## Phase 8 — Additional transports and resilience

- [ ] WebSocket, QUIC, Unix/local IPC, offline/sneakernet and store-forward profiles.
- [ ] NAT traversal without identity weakening.
- [ ] Multi-relay provenance.
- [ ] Disaster recovery/key compromise drills.
- [ ] Long-lived archive compatibility policy.
- [ ] Resource-exhaustion and partition drills across every admitted transport.
- [ ] Verify Holodeck sandbox invariants remain transport-independent.

---

## Phase 9 — MORIARTY/1 adversarial graduation

**Status: planned. This is the final executable-architecture graduation gate, not a feature dependency.**

`MORIARTY/1` is a provider-neutral, repository-aware constitutional adversary whose reference operator may be Codex. Every accepted finding must be a reproducible `moriarty-counterexample/1`; a valid finding reopens the owning phase and becomes a regression.

### Phase 9 gate

No unresolved reproducible counterexample may cross a constitutional, authority, provenance, sandbox, cryptographic, replay, storage, transport, adapter, governance, or resource-safety boundary for the exact reviewed commit.

```text
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
```

---

## Phase 10 — Lean 4 formalization

**Status: planned. Begins only after an exact commit passes MORIARTY/1.**

Bind the Lean package to the exact Moriarty-surviving commit, invariant IDs, contracts, schemas, phase gates, and adversarial report. Assembly sovereignty and Charter Gate properties are theorem targets alongside earlier invariants.

### Phase 10 gate

The theorem manifest must compile from a clean checkout of the exact Moriarty-surviving lineage on a pinned Lean toolchain.

```text
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION
```

---

## Phase 11 — Zenodo formalization and archival release

**Status: planned. Publication begins only after Phase 10 is green.**

Freeze the exact executable + adversarial + Lean artifact with Git commit/tag identity, theorem manifest, MORIARTY corpus/report, machine contracts, schemas, fixtures, reproducibility instructions, citation metadata, deterministic release manifest, and `SHA256SUMS`.

### Phase 11 gate

An offline verifier must bind Git commit, release tag, Lean proof tree, Moriarty input commit, machine-contract hashes, publication files, release metadata, and absence of secrets/private keys before DOI publication.

```text
ZENODO PRESENCE != TECHNICAL AUTHORITY
DOI != PROOF OF TRUTH
ARCHIVAL IMMUTABILITY != IMPLEMENTATION PERFECTION
```

---

## Explicitly deferred / prohibited

Generic remote shell, arbitrary peer-selected tools, shared global truth, transitive trust by default, global mutable state, automatic evidence promotion, automatic vote federation, secret-bearing semantic prompts, peer-controlled constitutional override, Assembly-to-member local authority mutation, Holodeck-to-real authority promotion, Holodeck-to-ORACLE synthetic admission without a separately reviewed non-evidence contract, simulated credential access, and protocol-derived personhood/legal sovereignty claims remain outside the current design.

## Long-term success condition

QSOL-FED succeeds when mutually distrustful systems can exchange useful, attributable knowledge while retaining local sovereignty; evolve the protocol through transparent non-executing governance; safely explore synthetic worlds without confusing simulation for reality; survive explicit adversarial graduation; and publish a traceable formal model without overstating what the proof or DOI establishes.
