# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED now includes a Phase 5 QSOL adapter membrane around the durable Federation core and sandboxed AI Holodecks. Reports, evidence observations, archives, and simulations can cross typed boundaries without carrying their source system's authority with them.

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

## Current Phase 5 claim gate

<!-- CURRENT_CLAIM_BOUNDARY:BEGIN -->
The current repository may claim all reviewed Phase 0–5A capabilities plus:

- live local native-verified QSOL-NEXUS adapter: **established and tested**;
- NEXUS Council/minority report adapter: **established and tested**;
- NEXUS Council actor synthetic-only Holodeck seam: **established and tested**;
- independent re-deliberation and report-only Council-of-Councils: **established and tested**;
- FED-side QSOL-ORACLE evidence membrane: **established and tested**;
- QSOL-ARK offline preservation adapter: **established and tested**;
- live QSOL-ORACLE transport: **not established**;
- Holodeck-to-ORACLE synthetic admission: **not established**;
- host-level OS/VM/container/hypervisor/hardware sandbox: **not established**;
- production networking: **not established**;
- remote execution: **not established**;
- interoperable federation: **not established**.
<!-- CURRENT_CLAIM_BOUNDARY:END -->

[`claims/phase5.json`](claims/phase5.json) is canonical for the current release-claim boundary.

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

## QSOL-ORACLE

The FED-side membrane preserves `known`, `conflict`, and `unknown`; suggested searches remain `discovery-only` non-evidence; evidence promotion and authority effects remain disabled.

**Live ORACLE transport is deferred.** The planned next repository PR is in `QSOLKCB/QSOL-ORACLE` to implement and gate its donor-side transport/export contract. QSOL-FED will not promote `oracle_live_transport` until that follow-up exists and cross-repository conformance is green.

Holodeck output is rejected at the ORACLE adapter until a separately reviewed synthetic non-evidence contract exists.

## QSOL-ARK

The FED-side ARK adapter creates content-addressed preservation objects with offline verification. Archival presence creates no authority. Holodeck programs and receipts are classified `synthetic_cultural_research` and cannot be relabelled real-world history.

No NEXUS or ARK repository change is required by this Phase 5 PR because the required native primitives already exist. Future repo PRs are justified only by an identified missing donor-side primitive.

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
LOCAL SOVEREIGNTY > FEDERATION CONVENIENCE
```

## Verification

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
python3 tools/validate_phase2_gate.py
python3 tools/validate_phase3_gate.py
python3 tools/validate_phase4_gate.py
python3 tools/validate_phase5a_gate.py
python3 tools/validate_phase5_gate.py
```

Offline Phase 4 bundle verification remains:

```bash
cargo run --bin qsol-fed-bundle -- verify bundle.json
```

The final [`ROADMAP.md`](ROADMAP.md) graduation sequence remains MORIARTY/1 adversarial graduation → Lean 4 formalization of the exact surviving commit → Zenodo archival/formal publication.

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol `qsol-fed/1`; current crate `0.7.0`. Phases 0 through 5 have executable gates, with Phase 5A preserved historically. ORACLE live transport, Holodeck-to-ORACLE synthetic admission, host-level sandboxing, production networking, real remote execution, and deployed multi-implementation interoperability remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project and is not affiliated with or endorsed by any entertainment franchise or rights holder.
