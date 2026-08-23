# ROADMAP

QSOL-FED is being built **protocol first, parliament later**. Each phase has an explicit claim boundary and security gate.

## Phase 0 — Constitutional bootstrap

**Status: complete; historical claim gate preserved in code and CI.**

- [x] Define QSOL-FED as a sovereign federation protocol, not a NEXUS mode.
- [x] Preserve QSOL-NEXUS as the Council of Minds.
- [x] Write Federation Charter.
- [x] Write Federation Prime Directive.
- [x] Define architecture, protocol, API, governance, security and threat model.
- [x] Add strict `README4AI.md` and `AGENTS.md` machine contracts.
- [x] Add machine-readable v1 invariant registry.
- [x] Hard-code Prime Directive admission invariants in Rust.
- [x] Add deterministic constitutional admission tests.
- [x] Add constitution drift validator and CI.
- [x] Add bootstrap envelope/node-manifest schemas.
- [x] Explicitly forbid arbitrary remote execution in v1.
- [x] Add canonical Phase 0 release-claim manifest.
- [x] Hard-code Phase 0 capability claims in Rust.
- [x] Add release-claim drift validator and CI gate.
- [x] Make production networking, cryptographic identity, remote execution and interoperable federation hard-false claims for Phase 0.

### Phase 0 gate

At Phase 0 there was no production networking claim, cryptographic identity claim, remote execution claim, or interoperable federation claim. The repository could claim only that the constitutional model, machine contracts and executable fail-closed admission skeleton existed and were tested.

That historical baseline remains executable and immutable in `claims/phase0.json`, `PHASE0_CLAIMS`, and `tools/validate_phase0_gate.py`. Later phases promote capabilities through successor claim manifests rather than rewriting Phase 0 history.

---

## Phase 1 — Canonical wire contract

**Status: complete; two-implementation conformance gate enforced.**

- [x] Freeze canonical JSON serialization rules.
- [x] Forbid duplicate keys and non-finite numbers.
- [x] Define Unicode/string normalization policy.
- [x] Freeze `sha256:` object identity rules.
- [x] Freeze exact Federation envelope schema v1.
- [x] Define message ID derivation.
- [x] Define provenance object schema.
- [x] Define protocol error envelope.
- [x] Define capability identifier/version grammar.
- [x] Add positive and adversarial canonicalization fixtures.
- [x] Add language-neutral golden vectors.
- [x] Add malformed, ambiguous and oversized fixture corpus.
- [x] Prove unsupported major versions fail closed.
- [x] Add independent Rust and Python canonicalizers.
- [x] Add executable Phase 1 wire-contract validator and CI gate.

### Phase 1 gate

Two independent implementations must produce byte-identical canonical bytes and hashes for the golden fixtures before signatures are layered on top.

The two implementations are `src/canonical.rs` and `tools/qsol_canonical.py`. Both consume `fixtures/phase1/golden-vectors.json`; Rust verifies them in `cargo test`, Python verifies them in `tools/validate_phase1_gate.py`, and CI requires both. The gate also rejects the shared malformed/ambiguous corpus, generated oversized cases, unsupported wire protocol majors, and any attempt to make the Phase 1 embedded `signature` field non-null.

Phase 1 freezes deterministic bytes only. Its exact envelope remains unchanged by Phase 2; signatures are carried by a detached wrapper.

---

## Phase 2 — Cryptographic node identity

**Status: complete; cryptographic identity gate enforced.**

- [x] Select reviewed signing suite and key format.
- [x] Define `fed:qsol:<node-id>` derivation.
- [x] Define signed envelope bytes.
- [x] Add signature verification vectors.
- [x] Separate signature validity from trust and authority in API types.
- [x] Implement key rotation.
- [x] Implement revocation/compromise records.
- [x] Define multi-key transition rules.
- [x] Define clock/expiry/skew policy.
- [x] Implement durable replay protection.
- [x] Add downgrade and algorithm-confusion tests.
- [x] Add compromised-peer tests showing Prime Directive still holds.
- [x] Add successor current release-claim manifest without rewriting Phase 0 history.
- [x] Add executable Phase 2 crypto validator and CI gate.

### Phase 2 gate

A valid signature must never bypass local admission. Tests must show that a correctly signed forbidden request is still rejected.

The Phase 2 reference profile is defined by `crypto/phase2.json` and `CRYPTOGRAPHY.md`. It uses Ed25519 with an offline root identity key and rotatable operational envelope-signing keys. The root key derives the stable node ID and authorizes lifecycle records but cannot sign Federation envelopes. Normal rotation requires root, outgoing-key, and incoming proof-of-possession signatures. Recovery after an operational-key compromise requires the root and replacement key; root compromise is terminal for that node ID.

Signed messages require bounded lifetime and clock skew. Durable replay state is append-only, fsynced before a message is reported fresh, and fails closed on partial or corrupt logs. The replay store is single-process and makes no Phase 3 server-concurrency claim.

`SignatureValidity`, `TrustDisposition`, and `AuthorityDisposition` remain separate API dimensions. Cryptographic verification always yields `authority = none`; ordinary Prime Directive admission still decides whether an effect is permitted.

Phase 2 establishes local cryptographic identity, signed-envelope verification, key lifecycle, and durable replay protection. It does **not** establish production networking, remote execution, or deployed interoperable federation.

---

## Phase 3 — Reference federation API

- [ ] Implement Rust HTTP service.
- [ ] `GET /fed/v1/node`.
- [ ] `GET /fed/v1/capabilities`.
- [ ] `POST /fed/v1/peer/hello`.
- [ ] `POST /fed/v1/envelopes`.
- [ ] `GET /fed/v1/objects/{sha256}`.
- [ ] `GET /fed/v1/provenance/{sha256}`.
- [ ] Strict body, depth, string and rate limits.
- [ ] TLS deployment profile.
- [ ] No arbitrary redirect/fetch behavior.
- [ ] SSRF defenses.
- [ ] Structured secret-safe audit log.
- [ ] Conformance tests for rejected pseudo-admin fields (`force`, `trusted`, `override`, etc.).
- [ ] Fuzz protocol parser and admission boundary.

### Phase 3 gate

Public network listening remains opt-in until replay protection, limits, identity verification and fuzz/adversarial suites are green.

---

## Phase 4 — Federation object store and peering

- [ ] Content-addressed foreign object store.
- [ ] Explicit quarantine namespace.
- [ ] Provenance-preserving local descendants.
- [ ] Peer registry separate from trust registry.
- [ ] Explicit peer lifecycle: unknown, introduced, admitted, quarantined, revoked, disconnected.
- [ ] Capability advertisements with expiry/versioning.
- [ ] Local allow/deny policy independent of advertisement.
- [ ] Partition/rejoin behavior.
- [ ] Duplicate/replay handling across restart.
- [ ] Export/import portable federation bundle.
- [ ] Offline verification path.
- [ ] No silent reconciliation after partitions.

### Phase 4 gate

Import/export round-trips must preserve foreign identity and provenance exactly. Import must not create local authority.

---

## Phase 5 — QSOL adapters

### QSOL-NEXUS

- [ ] Export Council reports as attributed foreign artifacts.
- [ ] Export minority reports.
- [ ] Import foreign reports without vote injection.
- [ ] Preserve local Council equality and evidence boundaries.
- [ ] Add independent re-deliberation flow.
- [ ] Build Council-of-Councils experiment as reports, not a giant shared ballot.

### QSOL-ORACLE

- [ ] Exchange evidence observations and references.
- [ ] Preserve `known` / `conflict` / `unknown` semantics without copying authority.
- [ ] Keep suggested searches non-evidence.
- [ ] Reject remote evidence promotion.

### QSOL-ARK

- [ ] Exchange content-addressed preservation objects.
- [ ] Offline federation recovery bundle.
- [ ] Preserve archival presence as non-authoritative.
- [ ] Add recovery provenance and integrity verification.

### Phase 5 gate

Every adapter must have conformance tests proving it cannot bypass the same Prime Directive invariant IDs enforced by the core node.

---

## Phase 6 — Third-party federation SDKs

- [ ] Publish minimal protocol SDK contract.
- [ ] Rust client SDK.
- [ ] Python client SDK.
- [ ] JavaScript/TypeScript client SDK.
- [ ] Language-neutral conformance suite.
- [ ] Reference minimal node that does not depend on any QSOL repository.
- [ ] Document institutional/research-node integration.
- [ ] Interop test between at least three independent implementations.

### Phase 6 gate

QSOL-FED must demonstrate that a non-NEXUS, non-QSOL-specific node can participate without adopting QSOL internal governance.

---

## Phase 7 — Federation Assembly

Only after the protocol actually works:

- [ ] Define Assembly membership separately from network membership.
- [ ] Define proposal and amendment lifecycle.
- [ ] Define representation and anti-Sybil assumptions.
- [ ] Define constitutional vs ordinary protocol amendments.
- [ ] Define deterministic Charter Gate interaction.
- [ ] Preserve member-local sovereignty regardless of Assembly outcomes.
- [ ] Preserve QSOL-NEXUS as advisory/deliberative Council, not sovereign chamber.
- [ ] Define transparent fork/version path for incompatible constitutional changes.
- [ ] Add machine-readable governance receipts.

### Phase 7 gate

No Assembly mechanism may introduce a Federation message that directly mutates member-local authority. Protocol governance and member governance remain distinct.

---

## Phase 8 — Additional transports and resilience

- [ ] WebSocket transport profile where useful.
- [ ] QUIC transport profile where useful.
- [ ] Unix-domain/local IPC profile.
- [ ] Offline/sneakernet signed bundle profile.
- [ ] Store-and-forward relay profile that cannot impersonate origin.
- [ ] NAT traversal research without weakening identity/admission.
- [ ] Multi-relay provenance.
- [ ] Disaster recovery and key-compromise drills.
- [ ] Long-lived archive compatibility policy.

---

## Explicitly deferred / prohibited until separately designed

- generic remote shell;
- arbitrary peer-selected tools;
- shared global truth score;
- transitive trust by default;
- global mutable state;
- automatic local evidence promotion;
- automatic vote federation;
- secret-bearing semantic prompts;
- peer-controlled constitutional override;
- claims of legal sovereignty, personhood or consciousness from protocol membership.

## Long-term success condition

QSOL-FED succeeds when two mutually distrustful systems can safely exchange useful, attributable knowledge while remaining free to disagree, disconnect and preserve their own local authority.
