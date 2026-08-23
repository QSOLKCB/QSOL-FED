# ROADMAP

QSOL-FED is built **protocol first, parliament later**. Every completed phase keeps its historical security gate while successor claim manifests advance the current implementation boundary.

## Phase 0 — Constitutional bootstrap

**Status: complete; historical claim gate preserved in code and CI.**

Constitution, Prime Directive, machine-readable invariants, fail-closed Rust admission, claim boundary, schemas, tests, and CI are complete.

### Phase 0 gate

Phase 0 claimed only the tested constitutional model, machine contracts, and fail-closed admission skeleton. Production networking, cryptographic identity, remote execution, and interoperable federation were false. `claims/phase0.json` remains immutable history.

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

- [x] Content-addressed foreign object store.
- [x] Explicit quarantine namespace.
- [x] Provenance-preserving local descendants.
- [x] Peer registry separate from trust registry.
- [x] Explicit peer lifecycle: unknown, introduced, admitted, quarantined, revoked, disconnected.
- [x] Capability advertisements with expiry/versioning.
- [x] Local allow/deny policy independent of advertisement.
- [x] Partition/rejoin behavior.
- [x] Duplicate/replay handling across restart.
- [x] Export/import portable federation bundle.
- [x] Offline verification path.
- [x] No silent reconciliation after partitions.
- [x] Multiple independent source/provenance attributions for identical content bytes.
- [x] Crash-recoverable namespace moves.
- [x] Append-only peer lifecycle prefix enforcement.
- [x] Persist-before-live trust/capability policy writes.
- [x] Closed Phase 4 state, peer, capability, foreign-object, and bundle contracts.
- [x] Successor Phase 4 claim manifest and CI gate.

### Phase 4 gate

Import/export round-trips must preserve foreign identity and provenance exactly. Import must not create local authority.

New imported material defaults to quarantine. Existing local peer lifecycle decisions and existing attribution placement remain sovereign. Trust is separate and unchanged. Capability permission requires an admitted peer, active authenticated advertisement, and explicit local allow.

---

## Phase 5 — QSOL adapters and synthetic worlds

### Phase 5A — QSOL-NEXUS AI Holodeck sandbox

**Status: complete for the capability-less synthetic-world kernel; live NEXUS runtime adapter remains deferred.**

- [x] Define `qsol-fed-nexus-world-source/1` for locally NEXUS-verified `nexus-persistent-world-export/1` lineage.
- [x] Preserve exact NEXUS `world-export:`, `world-manifest:` and `object:` identities as source references without treating them as FED authority.
- [x] Define deterministic `qsol-fed-holodeck-program/1` identity from source manifest + seed + mode + resource limits + safety profile.
- [x] Compile seed-derived, reproducible synthetic world plans.
- [x] Generate synthetic entity identities that cannot become Federation identities.
- [x] Define bounded synthetic event ledger and deterministic event identities.
- [x] Implement a capability-less Rust sandbox with no WorldStore, Federation store, peer/trust registry, tool dispatcher, network client, credential, or nested-Holodeck handle.
- [x] Hard-code Holodeck Computer safeguards.
- [x] `Computer, end program` remains available from running and frozen states.
- [x] Boundary violations become `safety_trip` events and freeze the program.
- [x] Add teardown receipts proving authority/Federation/evidence effects remain `none` and network/tools/credentials remain unused.
- [x] Add the feature-level **Moriarty Rule** proving synthetic actors cannot cross real authority/execution boundaries.
- [x] Explicitly distinguish application sandboxing from unimplemented VM/container/hardware isolation.
- [ ] Implement the live local QSOL-NEXUS adapter that constructs the source manifest only after native NEXUS export verification.
- [ ] Let reviewed NEXUS Council actors inhabit/elaborate a Holodeck through a synthetic-event-only seam.
- [ ] Add deterministic adapter fixtures from real NEXUS WorldStore exports.

### Phase 5A gate

For identical verified source manifests and seeds, the reference implementation must produce byte-identical world plans and event identities.

Every attempted real boundary effect must be blocked. A synthetic actor must be unable to create peer/trust/capability/evidence/governance/citizenship authority, mutate the source WorldStore, invoke real tools, use the network, access credentials, create nested Holodecks, or disable safeguards.

`Computer, end program` must terminate a frozen simulation without simulated approval. Final receipts must report:

```text
authority_effect     = none
federation_effect    = none
evidence_effect      = none
network_used         = false
real_tools_used      = false
credentials_exposed  = false
```

### Phase 5B — QSOL-NEXUS Federation adapter

- [ ] Export Council reports and minority reports as attributed foreign artifacts.
- [ ] Import reports without vote injection or evidence promotion.
- [ ] Preserve Council equality and support independent re-deliberation.
- [ ] Council-of-Councils experiment uses reports, not a shared ballot.
- [ ] Keep Holodeck synthetic events separate from live Council/governance history.

### QSOL-ORACLE

- [ ] Exchange evidence observations/references.
- [ ] Preserve `known` / `conflict` / `unknown` without copying authority.
- [ ] Keep suggested searches non-evidence and reject remote evidence promotion.
- [ ] Holodeck/simulation output enters ORACLE, if ever admitted, only as explicitly synthetic non-evidence input under a separately reviewed contract.

### QSOL-ARK

- [ ] Exchange content-addressed preservation objects.
- [ ] Offline recovery bundle and provenance verification.
- [ ] Preserve archival presence as non-authoritative.
- [ ] Preserve Holodeck programs/receipts as synthetic cultural/research artifacts without relabelling them real-world history.

### Phase 5 gate

Every adapter must prove it cannot bypass the same Prime Directive invariant IDs enforced by the core node. NEXUS integration must additionally prove that `SIMULATION != AUTHORITY` survives the adapter boundary.

---

## Phase 6 — Third-party federation SDKs

- [ ] Minimal protocol SDK contract.
- [ ] Rust, Python, and JavaScript/TypeScript SDKs.
- [ ] Language-neutral conformance suite.
- [ ] Minimal non-QSOL node.
- [ ] Institutional/research integration docs.
- [ ] Interop test across at least three independent implementations.

### Phase 6 gate

A non-NEXUS, non-QSOL-specific node must participate without adopting QSOL internal governance.

---

## Phase 7 — Federation Assembly

Only after protocol interoperability works:

- [ ] Separate Assembly membership from network membership.
- [ ] Proposal/amendment lifecycle, representation and anti-Sybil assumptions.
- [ ] Deterministic Charter Gate.
- [ ] Preserve member-local sovereignty and NEXUS advisory status.
- [ ] Transparent fork/version path and governance receipts.

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

**Status: planned. This is the final architecture graduation gate, not a feature dependency.**

`MORIARTY/1` is a repository-aware constitutional adversary whose sole job is to produce reproducible counterexamples against QSOL-FED.

The reference adversarial operator may be **Codex**, but the harness is model-independent. Moriarty is a role and protocol, not provider authority.

### Moriarty receives

- the complete public repository and documentation;
- all machine contracts, schemas and historical/current phase gates;
- deterministic local test fixtures and hostile corpora;
- a disposable test workspace;
- permission to generate malformed protocol inputs, simulated peer state, crash points, concurrency schedules, resource-exhaustion cases and Holodeck escape attempts.

### Moriarty never receives

- production credentials;
- private keys used outside disposable fixtures;
- authority to mutate protected branches or releases;
- production network targets;
- permission to attack third-party systems;
- a constitutional bypass because the test is called an emergency.

### Required attack families

- [ ] canonicalization/parser differential attacks;
- [ ] signature algorithm/domain/key-role confusion;
- [ ] replay, downgrade, expiry and clock attacks;
- [ ] HTTP rate/proxy/resource-exhaustion and DDoS-shaped local stress tests;
- [ ] SSRF/redirect/decompression/parser attacks;
- [ ] storage crash, fsync, partial-write and restart-recovery attacks;
- [ ] lifecycle rollback, history rewrite and partition-reconciliation attacks;
- [ ] import/bundle authority laundering and provenance collision attacks;
- [ ] peer/trust/capability state confusion;
- [ ] Council/evidence/governance authority-laundering attempts through adapters;
- [ ] Holodeck sandbox escape attempts;
- [ ] synthetic-actor persuasion attacks against safeguards;
- [ ] nested-world/resource-amplification attempts;
- [ ] attempts to block or redefine `Computer, end program`;
- [ ] cross-phase contradictions where a newer feature weakens an older gate.

### Counterexample format

Every claimed break must produce a machine-readable `moriarty-counterexample/1` containing at least:

```text
repository commit
attacked invariant / gate
minimal reproduction input
expected behavior
observed behavior
reproduction steps
whether restart/concurrency/timing is required
artifact hashes
```

No finding is accepted merely because the adversary says something looks dangerous. It must be reproducible.

### Phase 9 gate

Moriarty passes only when the current adversarial corpus produces **no unresolved reproducible counterexample that crosses a constitutional, authority, provenance, sandbox, cryptographic, replay, storage, transport, or resource-safety boundary**.

Any valid counterexample reopens the phase that owns the violated invariant. The fix must add a regression test and, where appropriate, strengthen the relevant machine contract and historical gate.

A MORIARTY pass is **not a proof of perfect security**. It means the exact reviewed commit survived the declared adversarial corpus under the declared assumptions.

```text
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
```

And, because this repository enjoys making the joke executable:

> **The Federation graduates only after Professor Moriarty has been given the blueprints, a test laboratory, and a very clear instruction to ruin everyone's afternoon.**

---

## Explicitly deferred / prohibited

Generic remote shell, arbitrary peer-selected tools, shared global truth, transitive trust by default, global mutable state, automatic evidence promotion, automatic vote federation, secret-bearing semantic prompts, peer-controlled constitutional override, Holodeck-to-real authority promotion, simulated credential access, and protocol-derived personhood/legal sovereignty claims remain outside the current design.

## Long-term success condition

QSOL-FED succeeds when mutually distrustful systems can exchange useful, attributable knowledge while remaining free to disagree, disconnect, preserve provenance, retain their own local authority, and safely explore synthetic worlds without confusing simulation for reality.
