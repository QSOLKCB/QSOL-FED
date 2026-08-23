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

Content-addressed foreign/quarantine storage, multiple source/provenance attributions, provenance-preserving descendants, durable peer lifecycle, separate trust registry, expiring capability advertisements, local allow/deny policy, partition/rejoin controls, replay across restart, portable bundles, offline verification, append-only lifecycle prefixes, persist-before-live local policy writes, and crash-recoverable namespace moves are complete.

### Phase 4 gate

Import/export round-trips must preserve foreign identity and provenance exactly. Import must not create local authority.

New imported material defaults to quarantine. Existing local lifecycle/namespace decisions remain sovereign. Trust stays separate and capability permission requires admitted lifecycle state + active authenticated advertisement + explicit local allow.

---

## Phase 5 — QSOL adapters and synthetic worlds

**Status: complete; historical Phase 5 adapter gate preserved by `claims/phase5.json`. Phase 5C is current.**

### Phase 5A — QSOL-NEXUS AI Holodeck sandbox

**Status: complete; historical Holodeck gate preserved.**

- [x] `qsol-fed-nexus-world-source/1` preserves NEXUS export lineage without authority.
- [x] Deterministic Holodeck program/world/event identities.
- [x] Capability-less application sandbox with hard Computer safeguards.
- [x] `Computer, end program` survives frozen state and event-ledger exhaustion.
- [x] Moriarty feature-level escape/boundary regressions.
- [x] Explicit host-level sandbox non-claim.
- [x] Live local QSOL-NEXUS adapter constructs a source manifest only **after native NEXUS export verification**.
- [x] Reviewed NEXUS Council members project into synthetic Holodeck actors through a synthetic-event-only seam.
- [x] Deterministic fixtures are generated from native NEXUS `WorldStore` + `PersistentWorldService.export_bundle()` and reproduced in CI from pinned commit `24cb0ce246d12ac99e7d190a8890ef2ddd598321`.

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

- [x] Export verified Council sessions and minority reports as attributed `qsol-fed-nexus-council-report/1` artifacts.
- [x] Import reports without vote injection or evidence promotion.
- [x] Preserve observed Council equality while inheriting no vote weight, epistemic privilege, citizenship, or governance authority.
- [x] Support independent local re-deliberation.
- [x] Council-of-Councils consumes report identities, not a shared ballot or shared vote weight.
- [x] Holodeck synthetic actors/events remain outside live Council/governance history.

No QSOL-NEXUS follow-up PR is required for this slice because the native WorldStore/export/verifier primitives already exist. Add a NEXUS-side PR only if later integration identifies an actual missing donor primitive.

### QSOL-ORACLE historical Phase 5 membrane

- [x] Implement FED-side typed evidence observations/references.
- [x] Preserve `known` / `conflict` / `unknown` without copying authority.
- [x] Keep suggested searches `discovery-only`, non-evidence, and inadmissible without observation.
- [x] Reject evidence promotion through the FED adapter.
- [x] Reject Holodeck/simulation admission until a separately reviewed synthetic non-evidence contract exists.
- [x] Preserve the historical Phase 5 non-claim `oracle_live_transport = false` in `claims/phase5.json`.

The donor-side follow-up was implemented and hardened in `QSOLKCB/QSOL-ORACLE` PR #5. Phase 5C below is the successor that earns the live-local transport claim without rewriting Phase 5 history.

### QSOL-ARK

- [x] Content-addressed SHA-256 preservation objects.
- [x] Offline verification path requiring no network.
- [x] Archival presence explicitly non-authoritative.
- [x] Holodeck programs/receipts preserved as `synthetic_cultural_research`, never relabelled real-world history.

No QSOL-ARK PR is required for the current offline FED-side preservation contract. Add one only if future live integration reveals a missing native recovery/preservation primitive.

### Phase 5 gate

Every adapter must prove it cannot bypass the same Prime Directive invariant IDs enforced by the core node. NEXUS integration must additionally prove that `SIMULATION != AUTHORITY` survives the adapter boundary.

The historical Phase 5 gate pins the NEXUS donor commit, reproduces native WorldStore export fixtures, requires report-only Council federation, preserves the then-false ORACLE live-transport claim, and verifies ARK preservation offline.

### Phase 5C — QSOL-ORACLE live transport

**Status: current; attested live-local ORACLE gate enforced by `claims/phase5c.json`.**

- [x] Pin merged QSOL-ORACLE donor commit `043e864b3c25dfeca3ce1752b3110479479071b1`.
- [x] Pin donor release fingerprint `7b0eff4dfa9b0caa84f14920d21f6a5446114535d82706cb62e34773c39818d2`.
- [x] Byte-compare donor membrane, request schema, response schema, and FED observation schema in cross-repository CI.
- [x] Verify every donor release-fingerprint file byte length and SHA-256 before local process launch.
- [x] Use the fixed donor entrypoint `python3 tools/fed_transport.py serve`; do not expose a generic command runner.
- [x] Remove `PYTHONPATH` and `PYTHONHOME` from the donor process environment.
- [x] Send bounded canonical JSONL requests and accept exactly one bounded canonical response.
- [x] Verify donor response canonical bytes and `response_sha256` in FED.
- [x] Preserve `oracle-event:<sha256>` evidence-reference grammar.
- [x] Run a real live process probe against the historical ORACLE timelock witness.
- [x] Tamper the donor transport file in CI and prove runtime release attestation rejects it.
- [x] Promote `oracle_live_transport = true`.
- [x] Keep `oracle_holodeck_synthetic_admission = false`.
- [x] Keep production networking and remote execution false.

### Phase 5C gate

The exact reviewed QSOL-ORACLE donor release must attest locally before process launch. FED must produce bounded canonical requests, accept one bounded canonical response, verify donor response identity/provenance semantics, and preserve `known` / `conflict` / `unknown` without truth or authority promotion.

The Phase 5C capability delta is exactly:

```text
oracle_live_transport: false -> true
```

No other Phase 5 capability bit may change. In particular:

```text
oracle_holodeck_synthetic_admission = false
host_level_sandbox                  = false
production_networking               = false
remote_execution                    = false
interoperable_federation            = false
```

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

**Status: planned. This is the final executable-architecture graduation gate, not a feature dependency.**

`MORIARTY/1` is a provider-neutral, repository-aware constitutional adversary whose reference operator may be Codex. It receives public blueprints and disposable test fixtures, never production credentials/targets or constitutional bypasses.

Attack families include canonical/parser differentials; signature/domain/key-role confusion; replay/downgrade/clock attacks; HTTP rate/proxy/DDoS-shaped stress; SSRF/decompression; crash/fsync/restart; lifecycle/partition/history attacks; import/provenance authority laundering; adapter confusion; Holodeck escapes; safeguard persuasion; nested-world amplification; and cross-phase contradictions.

Every accepted finding must be a reproducible `moriarty-counterexample/1`. A valid finding reopens the phase owning the invariant and becomes a regression.

### Phase 9 gate

No unresolved reproducible counterexample may cross a constitutional, authority, provenance, sandbox, cryptographic, replay, storage, transport, adapter, or resource-safety boundary for the exact reviewed commit.

```text
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
```

---

## Phase 10 — Lean 4 formalization

**Status: planned. Begins only after an exact commit passes MORIARTY/1.**

Bind the Lean package to the exact Moriarty-surviving commit, invariant IDs, contracts, schemas, phase gates, and adversarial report. Initial theorem targets include Prime Directive admission, signature/trust/authority separation, peering/capability separation, import non-authority, lifecycle monotonicity, partition sovereignty, provenance preservation, canonical identity determinism, Holodeck separation/safeguards, adapter non-authority, and Assembly sovereignty.

No unresolved `sorry`/`admit` is permitted in the graduation theorem set; assumptions must be named and theorem-to-contract traceability complete.

### Phase 10 gate

The theorem manifest must compile from a clean checkout of the exact Moriarty-surviving lineage on a pinned Lean toolchain.

```text
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION
```

---

## Phase 11 — Zenodo formalization and archival release

**Status: planned. Publication begins only after Phase 10 is green.**

Freeze the exact executable + adversarial + Lean artifact with Git commit/tag identity, theorem manifest, MORIARTY corpus/report, machine contracts, schemas, golden/hostile fixtures, reproducibility instructions, SBOM/dependency metadata where available, citation metadata, deterministic release manifest, and `SHA256SUMS`.

Record immutable version/concept DOI relationships without repointing historical releases.

### Phase 11 gate

An offline verifier must bind Git commit, release tag, Lean proof tree, Moriarty input commit, machine-contract hashes, publication files, `SHA256SUMS`, release metadata, and absence of secrets/private keys before DOI publication.

```text
ZENODO PRESENCE != TECHNICAL AUTHORITY
DOI != PROOF OF TRUTH
ARCHIVAL IMMUTABILITY != IMPLEMENTATION PERFECTION
```

---

## Explicitly deferred / prohibited

Generic remote shell, arbitrary peer-selected tools, shared global truth, transitive trust by default, global mutable state, automatic evidence promotion, automatic vote federation, secret-bearing semantic prompts, peer-controlled constitutional override, Holodeck-to-real authority promotion, Holodeck-to-ORACLE synthetic admission without a separately reviewed non-evidence contract, simulated credential access, and protocol-derived personhood/legal sovereignty claims remain outside the current design.

## Long-term success condition

QSOL-FED succeeds when mutually distrustful systems can exchange useful, attributable knowledge while retaining local sovereignty; safely explore synthetic worlds without confusing simulation for reality; survive explicit adversarial graduation; and publish a traceable formal model without overstating what the proof or DOI establishes.
