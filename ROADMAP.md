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
- [x] Closed Phase 4 state, peer, capability, foreign-object, and bundle contracts.
- [x] Successor Phase 4 claim manifest and CI gate.

### Phase 4 gate

Import/export round-trips must preserve foreign identity and provenance exactly. Import must not create local authority.

The reference implementation also preserves exact canonical foreign object bytes, lifecycle bytes, and capability-advertisement bytes in portable bundles. Bundle import always places peers and objects into quarantine, returns `authority = none`, and does not alter local trust. Bundle verification is offline and requires no network access.

Peer lifecycle survives restart and rejects lifecycle rollback or divergent same-sequence state. Trust is a separate local registry. Capability advertisement is authenticated and expiring, while local policy defaults to deny and remains independent of advertisement.

Partitions record a snapshot. If a returning peer presents a changed snapshot, rejoin requires explicit reconciliation; no silent merge path exists.

---

## Phase 5 — QSOL adapters

### QSOL-NEXUS
- [ ] Export Council reports and minority reports as attributed foreign artifacts.
- [ ] Import reports without vote injection or evidence promotion.
- [ ] Preserve Council equality and support independent re-deliberation.
- [ ] Council-of-Councils experiment uses reports, not a shared ballot.

### QSOL-ORACLE
- [ ] Exchange evidence observations/references.
- [ ] Preserve `known` / `conflict` / `unknown` without copying authority.
- [ ] Keep suggested searches non-evidence and reject remote evidence promotion.

### QSOL-ARK
- [ ] Exchange content-addressed preservation objects.
- [ ] Offline recovery bundle and provenance verification.
- [ ] Preserve archival presence as non-authoritative.

### Phase 5 gate

Every adapter must prove it cannot bypass the same Prime Directive invariant IDs enforced by the core node.

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

## Explicitly deferred / prohibited

Generic remote shell, arbitrary peer-selected tools, shared global truth, transitive trust by default, global mutable state, automatic evidence promotion, automatic vote federation, secret-bearing semantic prompts, peer-controlled constitutional override, and protocol-derived personhood/legal sovereignty claims remain outside the current design.

## Long-term success condition

QSOL-FED succeeds when mutually distrustful systems can exchange useful, attributable knowledge while remaining free to disagree, disconnect, preserve provenance, and retain their own local authority.
