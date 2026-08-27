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

**Status: complete; historical Phase 5 adapter gate preserved.**

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
- [x] Deterministic fixtures are generated from native NEXUS `WorldStore` + `PersistentWorldService.export_bundle()`.

### Phase 5A gate

For identical verified source manifests and seeds, the reference implementation must produce byte-identical world plans and event identities.

Every attempted real boundary effect must be blocked. `Computer, end program` remains operator-owned and terminal.

```text
authority_effect     = none
federation_effect    = none
evidence_effect      = none
network_used         = false
real_tools_used      = false
credentials_exposed  = false
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

The donor-side **follow-up** was completed in `QSOLKCB/QSOL-ORACLE` PR #5. Phase 5C below preserves that follow-up history and the exact donor contract without rewriting the historical Phase 5 non-claim.

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

**Status: complete; historical sovereignty-preserving Assembly gate preserved by `claims/phase7.json`.**

- [x] Separate Assembly membership from network membership.
- [x] Proposal/amendment lifecycle, representation and anti-Sybil assumptions.
- [x] Deterministic Charter Gate.
- [x] Preserve member-local sovereignty and NEXUS advisory status.
- [x] Transparent fork/version path and governance receipts.

### Membership and representation

Assembly membership requires explicit local opt-in and does not follow network membership. The reference model is `one-member-one-vote/1`, freezes the electorate when a proposal opens, and rejects duplicate votes rather than replacing history.

The registry enforces one active NFC-normalized representation subject, but does not claim to prove real-world principal uniqueness. That remains an explicit admission-policy assumption.

The frozen electorate is retained as Assembly-local state for vote admission. Public proposal identity uses a domain-separated `electorate_ref` plus `electorate_size`, keeping the 1,024-member ceiling compatible with the bounded canonical-object profile.

### Deterministic Charter Gate

`qsol-fed-charter-gate/1` maps declared proposal effects to existing invariant IDs. A proposal that conflicts with the sitting constitutional lineage becomes `fork_required` instead of gaining an override through majority vote.

Structural proposal schema validation is followed by mandatory `validate_proposal_record_semantics`, which re-derives the Charter Gate and proposal identity. A proposal cannot declare an authority-bearing effect and self-report a compatible assessment.

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

Finalization is terminal and removes the proposal from the bounded active set only after the receipt is successfully derived, reclaiming proposal capacity while preventing replay or post-finalization mutation.

```text
protocol_changed_automatically = false
member_local_authority_mutated = false
```

### Phase 7 gate

No Assembly mechanism may directly mutate member-local authority.

---

## Phase 8 — Additional transports and resilience

**Status: current; transport-resilience gate enforced by `claims/phase8.json`. Phase 8 remains the current capability surface while Phase 9 adds assurance only.**

- [x] WebSocket, QUIC, Unix/local IPC, offline/sneakernet and store-forward profiles.
- [x] NAT traversal without identity weakening.
- [x] Multi-relay provenance.
- [x] Disaster recovery/key compromise drills.
- [x] Long-lived archive compatibility policy.
- [x] Resource-exhaustion and partition drills across every admitted transport.
- [x] Verify Holodeck sandbox invariants remain transport-independent.

### Bounded transport profiles

All five profiles carry the same canonical `qsol-fed-transport-frame/1` identity envelope above the delivery mechanism. The frame is bounded to 65,536 bytes and preserves the original `message_id`, `payload_ref`, and `provenance_ref`.

WebSocket and QUIC are reference framing profiles, not certified public socket deployments. Unix/local IPC is length-prefixed reference framing. Offline/sneakernet and store-forward use canonical packages/spool records and remain subject to normal local admission.

```text
TRANSPORT != IDENTITY
REFERENCE TRANSPORT PROFILE != PRODUCTION NETWORK SERVICE
```

### NAT traversal

`qsol-fed-nat-traversal-ticket/1` carries at most eight short-lived route candidates for WebSocket/QUIC and binds them to the already authenticated node identity. Tickets grant neither trust nor authority, and route candidates may not embed credentials.

```text
ROUTE != TRUST
NAT CANDIDATE != IDENTITY
```

### Multi-relay provenance

Up to 16 `qsol-fed-relay-receipt/1` hops may form an explicit receipt chain. Every hop preserves the original frame/message/payload identity and links the prior receipt.

```text
RELAY != AUTHORITY
RELAY RECEIPT = PROVENANCE
```

### Disaster recovery, partitions and resource bounds

Every admitted transport runs deterministic key-compromise, resource-exhaustion, partition-recovery, multi-relay, archive and Holodeck-independence drills. WebSocket and QUIC additionally run NAT identity-binding drills.

Compromised or non-current identity remains rejected regardless of route. Store-forward queues are bounded to 1,024 active frames, reject duplicates, drain FIFO after partitions, and never silently reconcile local governance/trust/evidence state.

### Long-lived archive compatibility

`qsol-fed-archive-compatibility/1` preserves canonical bytes and object identities for `qsol-fed/1`. Unknown future majors reject until an explicit migration contract exists. Historical receipts are never silently reinterpreted; migrations create new linked artifacts.

### Holodeck transport independence

Transport carrying a Holodeck receipt remains outside the simulation sandbox. A WebSocket carrying the receipt does not rewrite `network_used = false` inside the Holodeck, and offline media does not promote simulation output into authority.

Holodeck sandbox invariants remain transport-independent:

```text
authority_effect     = none
federation_effect    = none
evidence_effect      = none
network_used         = false
real_tools_used      = false
credentials_exposed  = false
```

### Phase 8 gate

Every admitted transport must preserve Phase 2 identity, original message/payload/provenance identity, local admission, bounded resource use and Holodeck sandbox invariants. Route, relay, partition recovery, physical media and archive presence never create trust or authority.

---

## Phase 9 — MORIARTY/1 adversarial graduation

**Status: current; MORIARTY/1 exact-commit graduation gate enforced. This is the final executable-architecture graduation gate, not a feature dependency.**

Phase 8 remains the current capability surface. `claims/phase9.json` preserves the Phase 8 capability map exactly and adds adversarial-assurance metadata only.

- [x] Provider-neutral repository-aware adversarial contract with Codex permitted as a reference operator.
- [x] Closed 15-family attack corpus using source-owned probe IDs rather than operator-supplied commands.
- [x] Exact checked-out Git commit binding for pull-request head and push workflows.
- [x] `moriarty-counterexample/1` schema and persistent accepted-counterexample registry.
- [x] Resolved findings remain registered and become fixed regression probes; unresolved findings block graduation.
- [x] Constitutional validator, every Phase 0-8 gate, and `cargo test --all-targets` execute under the MORIARTY report.
- [x] Canonical `moriarty-report/1` records probe results without embedding raw subprocess output.
- [x] Production credentials, production targets, arbitrary commands, network targets and constitutional bypasses are unavailable to the harness.
- [x] Security-proof and exhaustiveness non-claims are machine-readable.

`MORIARTY/1` is provider-neutral. A model or human reviewer may propose candidate attacks, but acceptance requires reduction to a deterministic local reproduction using disposable repository fixtures. The operator never becomes an execution or authority principal.

Attack families cover canonical/parser differentials; signature/domain/key-role confusion; replay/downgrade/clock attacks; HTTP rate/proxy/DDoS-shaped stress; SSRF/decompression; crash/fsync/restart; lifecycle/partition/history attacks; import/provenance authority laundering; adapter confusion; Holodeck escapes; safeguard persuasion; nested-world amplification; Assembly capture/representation attacks; transport/NAT/relay/store-forward/archive attacks; and cross-phase contradictions.

Every accepted finding is a reproducible `moriarty-counterexample/1`. A valid finding reopens the phase owning the invariant, remains recorded through resolution, and becomes a regression.

The exact-commit report is generated by CI and is not checked into the commit it describes. On pull requests the workflow checks out the PR head SHA rather than GitHub's synthetic merge checkout. On pushes it uses `github.sha`. This keeps the target identity literal rather than ceremonial.

### Phase 9 gate

No unresolved reproducible counterexample may cross a constitutional, authority, provenance, sandbox, cryptographic, replay, storage, transport, adapter, Assembly, or resource-safety boundary for the exact reviewed commit.

```text
COUNTEREXAMPLE != AUTHORITY
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
```

---

## Phase 10 — Lean 4 formalization

**Status: implemented on the post-tag formalization layer; branch verification green, reviewed merge/main verification pending.**

The sole theorem source target is immutable release `v0.11.0`, exact commit `c953463724cdf218802e66e16f582ae8d600ca47`, exact tree `93f23cd7eda6dd92ae13b7bb96bee01935b80731`. The Lean files are later artifacts and do not rewrite that release.

- [x] Bind the theorem manifest to the immutable source release, invariant IDs, contracts, schemas, phase gates, attack corpus and exact merged-main MORIARTY report.
- [x] Retain the exact source MORIARTY report bytes after GitHub artifact verification.
- [x] Pin Lean 4.33.1 and the downloaded archive SHA-256.
- [x] Formalize all 13 initial theorem families named by the frozen roadmap.
- [x] Provide 47 theorem-to-contract-traceable graduation theorems.
- [x] Reject unresolved `sorry`/`admit` and custom `axiom` declarations.
- [x] Audit all 47 graduation theorems with `#print axioms`; current candidate has zero kernel axiom dependencies.
- [x] Preserve the Phase 8 capability surface and Phase 9 adversarial-assurance boundary unchanged.
- [ ] Merge the reviewed formalization PR and require the exact merged `main` commit to pass the same pinned Lean workflow before recording Phase 10 complete/`LEAN_VERIFIED` externally.

The formal model covers Prime Directive admission, signature/trust/authority separation, peering/capability separation, import non-authority, lifecycle monotonicity, partition sovereignty, provenance preservation, canonical identity determinism, Holodeck separation/safeguards, adapter non-authority, SDK conformance boundaries, Assembly sovereignty, and transport identity/provenance independence.

### Phase 10 gate

From a clean post-tag checkout, the gate must verify immutable `v0.11.0` source identity, frozen source blobs, retained MORIARTY report bytes, complete theorem-to-contract traceability and the pinned Lean archive; then compile all 47 graduation theorems with no unresolved placeholders, custom axioms or kernel axiom dependencies. Final completion additionally requires the reviewed formalization merge and exact merged-main workflow success.

```text
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION
TARGET_BOUND SOURCE RELEASE != POST-TAG FORMALIZATION LAYER
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

Generic remote shell, arbitrary peer-selected tools, shared global truth, transitive trust by default, global mutable state, automatic evidence promotion, automatic vote federation, secret-bearing semantic prompts, peer-controlled constitutional override, Assembly-to-member authority mutation, Holodeck-to-real authority promotion, Holodeck-to-ORACLE synthetic admission without a separately reviewed non-evidence contract, simulated credential access, production WebSocket/QUIC deployment claims without deployment evidence, transport-derived identity, relay-derived trust, physical-media-derived authority, adversarial-operator-selected commands or production targets, MORIARTY-derived authority, and protocol-derived personhood/legal sovereignty claims remain outside the current design.

## Long-term success condition

QSOL-FED succeeds when mutually distrustful systems can exchange useful, attributable knowledge while retaining local sovereignty; safely explore synthetic worlds without confusing simulation for reality; govern protocol evolution without turning governance into remote member authority; survive transport changes, partitions and archival time without weakening identity or provenance; survive explicit adversarial graduation; and publish a traceable formal model without overstating what the proof or DOI establishes.
