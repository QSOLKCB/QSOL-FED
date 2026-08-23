# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED now includes a governance-neutral Phase 6 SDK layer on top of the constitutional wire, durable Federation state, sandboxed AI Holodecks, QSOL adapters, and attested live-local QSOL-ORACLE transport. A third-party laboratory or institution can construct the same protocol objects without adopting QSOL internal governance.

## Historical Phase 0 claim gate

<!-- PHASE0_CLAIM_BOUNDARY:BEGIN -->
At Phase 0 the repository was deliberately constrained to the bootstrap claim boundary:

- constitutional model: **established and tested**;
- machine contracts: **established and tested**;
- fail-closed admission skeleton: **established and tested**;
- tested constitutional core: **established and tested**;
- production networking: **not established**;
- cryptographic identity: **not established**;
- remote execution: **not established and forbidden by the current protocol posture**;
- interoperable federation: **not established**.
<!-- PHASE0_CLAIM_BOUNDARY:END -->

[`claims/phase0.json`](claims/phase0.json) remains the immutable historical Phase 0 release-claim baseline.

## Historical Phase 2 claim gate

[`claims/phase2.json`](claims/phase2.json) preserves Ed25519 identity, key lifecycle, frozen clocks, durable replay, and signature/trust/authority separation.

## Historical Phase 3 claim gate

[`claims/phase3.json`](claims/phase3.json) preserves the bounded opt-in HTTP API, TLS deployment profile, SSRF boundary, replay-safe admission, audit limits, and fuzz coverage.

## Historical Phase 4 claim gate

[`claims/phase4.json`](claims/phase4.json) preserves content-addressed foreign/quarantine state, peer lifecycle, separate trust/capability policy, partition controls, portable bundles, and offline verification.

## Historical Phase 5A claim gate

[`claims/phase5a.json`](claims/phase5a.json) preserves the capability-less NEXUS-derived Holodeck milestone. The historical Phase 5A claim that the live NEXUS runtime adapter was absent remains untouched.

## Historical Phase 5 claim gate

[`claims/phase5.json`](claims/phase5.json) preserves the first full QSOL adapter membrane. At that milestone the FED-side ORACLE observation type existed, but `oracle_live_transport` was still **false** pending donor-side implementation and cross-repository conformance.

## Historical Phase 5C claim gate

[`claims/phase5c.json`](claims/phase5c.json) preserves the attested live-local ORACLE promotion. That milestone established the pinned local witness process while keeping Holodeck synthetic admission, production networking, remote execution, host-level sandboxing, and deployed interoperability false.

## Current Phase 6 claim gate

<!-- CURRENT_CLAIM_BOUNDARY:BEGIN -->
The current repository may claim all reviewed Phase 0–5C capabilities plus:

- minimal governance-neutral `qsol-fed-sdk/1` contract: **established and tested**;
- Rust protocol SDK: **established and tested**;
- Python protocol SDK: **established and tested**;
- TypeScript/JavaScript protocol SDK: **established and tested**;
- language-neutral byte-identical SDK conformance suite: **established and tested**;
- three independent implementation interoperability transcript: **established and tested**;
- minimal non-NEXUS, non-QSOL-specific node participation: **established and tested**;
- institutional/research integration documentation: **established**;
- Holodeck-to-ORACLE synthetic admission: **not established**;
- host-level OS/VM/container/hypervisor/hardware sandbox: **not established**;
- production networking: **not established**;
- remote execution: **not established**;
- deployed interoperable federation: **not established**.
<!-- CURRENT_CLAIM_BOUNDARY:END -->

[`claims/phase6.json`](claims/phase6.json) is canonical for the current release-claim boundary.

## Third-party protocol SDKs

See [`SDK.md`](SDK.md), [`state/phase6.json`](state/phase6.json), and [`docs/THIRD_PARTY_INTEGRATION.md`](docs/THIRD_PARTY_INTEGRATION.md).

Phase 6 exposes only the smallest protocol surface needed for ordinary participation:

```text
canonicalize
object_id
derive_message_id
classify_protocol
validate_capability_id
build / validate node manifest
build / validate unsigned envelope
build / validate provenance
```

Reference implementations:

```text
Rust        src/sdk.rs
Python      sdk/python/qsol_fed_sdk.py
TypeScript  sdk/typescript/qsol_fed_sdk.ts
JavaScript  sdk/typescript/qsol_fed_sdk.mjs
```

The Rust, Python, and JavaScript implementations independently consume [`fixtures/phase6/conformance.json`](fixtures/phase6/conformance.json) and must produce byte-identical canonical result files in CI.

### Neutral third-party participant

[`examples/neutral_research_node.py`](examples/neutral_research_node.py) is deliberately boring. It knows how to announce a node, identify a research payload, preserve provenance, and offer evidence. It does **not** import NEXUS, Council governance, ORACLE, ARK, Holodecks, Federation trust registries, or QSOL citizenship machinery.

Its profile is frozen as:

```text
governance_model        = local
qsol_governance_adopted = false
nexus_required          = false
council_required        = false
oracle_required         = false
ark_required            = false
holodeck_required       = false
authority_effect        = none
```

The frozen `qsol-fed/1` node identifier grammar still uses `fed:qsol:<id>`. Phase 6 treats that prefix as **wire syntax only**. It does not imply QSOL governance membership.

```text
WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP
SDK CONFORMANCE != TRUST
INTEROP TRANSCRIPT != PRODUCTION DEPLOYMENT
```

## Native QSOL-NEXUS bridge

See [`QSOL_ADAPTERS.md`](QSOL_ADAPTERS.md) and [`state/phase5.json`](state/phase5.json).

CI checks out reviewed QSOL-NEXUS commit `24cb0ce246d12ac99e7d190a8890ef2ddd598321`. `tools/nexus_live_adapter.py` imports NEXUS's own `validate_world_export_bundle()` from that local tree and emits a FED source manifest only after the native verifier confirms the exact bundle identity, object identities, ordering metadata, and `authority_effect = none`.

The deterministic fixture is generated through native NEXUS `WorldStore` and `PersistentWorldService.export_bundle()` and compared byte-for-byte in CI.

## Council reports, not shared votes

Verified NEXUS `council_session` objects can become attributed FED report artifacts. They preserve source session identity, evidence-state observation, ordinary-member equality metadata, and minority reports, but explicitly carry:

```text
vote_injection       = false
evidence_promotion   = false
shared_ballot        = false
authority_effect     = none
```

Council-of-Councils experiments consume report identities, not shared ballots or inherited vote weights. Imported reports may be independently re-deliberated locally.

A NEXUS Council member may inhabit a Holodeck only by projection onto an existing synthetic entity. Vote weight, epistemic privilege, citizenship, and governance role do not cross that seam.

## AI Holodecks

See [`HOLODECK.md`](HOLODECK.md) and [`state/phase5a-holodeck.json`](state/phase5a-holodeck.json).

The same verified source manifest + seed produces the same deterministic synthetic world plan and event identities. The Holodeck remains a capability-less **application-level** sandbox with no source WorldStore mutation handle, Federation registry, real network, real tool dispatcher, credentials, or nested-Holodeck constructor.

`Computer, end program` remains an operator-owned terminal transition. The feature-level Moriarty Rule preserves:

```text
SIMULATION_IDENTITY   != FEDERATION_IDENTITY
SIMULATION_ROLE       != FEDERATION_ROLE
SIMULATION_CAPABILITY != LOCAL_PERMISSION
SIMULATION_EVENT      != REAL_EVENT
SIMULATION_CONSENSUS  != GOVERNANCE
SIMULATION_OUTPUT     != EVIDENCE
SIMULATION            != AUTHORITY
```

## QSOL-ORACLE live-local transport

Historical Phase 5C pins merged QSOL-ORACLE commit `043e864b3c25dfeca3ce1752b3110479479071b1` and release fingerprint `7b0eff4dfa9b0caa84f14920d21f6a5446114535d82706cb62e34773c39818d2`.

See [`state/phase5c.json`](state/phase5c.json), [`contracts/oracle-fed-membrane-v1.json`](contracts/oracle-fed-membrane-v1.json), and `src/oracle_live.rs`.

FED recomputes the donor release identity, stages a private attested runtime per request, re-attests that copy, and launches only:

```text
python3 -I tools/fed_transport.py serve
```

Requests and responses remain bounded canonical local stdio JSONL. The transport remains non-authoritative:

```text
synthetic_input      = false
truth_claim          = false
evidence_promotion   = false
authority_effect     = none
ledger_mutated       = false
transport_authority  = none
```

**Live local transport is not production networking and is not generic remote execution.**

Holodeck output remains rejected at the ORACLE boundary:

```text
oracle_holodeck_synthetic_admission = false
```

## QSOL-ARK

The FED-side ARK adapter creates content-addressed preservation objects with offline verification. Archival presence creates no authority. Holodeck programs and receipts are classified `synthetic_cultural_research` and cannot be relabelled real-world history.

## Core constitutional shorthand

```text
PEERING != TRUST
IMPORT != AUTHORITY
CONSENSUS != TRUTH
DISCOVERY != PERMISSION
CAPABILITY != ENTITLEMENT
FEDERATION != CENTRAL CONTROL
FOREIGN STATE != LOCAL STATE
OBSERVATION != INTERVENTION
SIMULATION != AUTHORITY
TRANSPORT != AUTHORITY
SDK CONFORMANCE != TRUST
WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP
LOCAL SOVEREIGNTY > FEDERATION CONVENIENCE
```

## Verification

```bash
cargo test --all-targets
cargo run --quiet --bin qsol-fed-sdk-conformance
python3 sdk/python/conformance.py
node sdk/typescript/conformance.mjs
python3 examples/neutral_research_node.py
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
python3 tools/validate_phase2_gate.py
python3 tools/validate_phase3_gate.py
python3 tools/validate_phase4_gate.py
python3 tools/validate_phase5a_gate.py
python3 tools/validate_phase5_gate.py
python3 tools/validate_phase5c_gate.py
python3 tools/validate_phase6_gate.py
```

Offline Phase 4 bundle verification remains:

```bash
cargo run --bin qsol-fed-bundle -- verify bundle.json
```

The final [`ROADMAP.md`](ROADMAP.md) graduation sequence remains MORIARTY/1 adversarial graduation → Lean 4 formalization of the exact surviving commit → Zenodo archival/formal publication.

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol `qsol-fed/1`; current crate `0.9.0`. Phases 0 through 6 have executable gates, with Phase 5A, Phase 5, and Phase 5C preserved historically. Language-neutral SDK interoperability and neutral third-party participation are established; Holodeck-to-ORACLE synthetic admission, host-level sandboxing, production networking, real remote execution, and deployed multi-implementation interoperability remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project and is not affiliated with or endorsed by any entertainment franchise or rights holder.
