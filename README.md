# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED has completed its Phase 9 MORIARTY/1 adversarial graduation and Phase 10 Lean 4 selected-invariant formalization on top of the Phase 8 runtime/protocol capability surface. The post-tag Lean layer is merged to `main`, exact merged-main verification is green, and the formalization has been published on Zenodo as Version 1.0.0 under DOI [`10.5281/zenodo.22149263`](https://doi.org/10.5281/zenodo.22149263).

## Current project state

QSOL-FED now has three deliberately separate layers of maturity:

| Layer | Current state | Meaning |
| --- | --- | --- |
| **Runtime/protocol capability** | **Phase 8 complete** | Transport/resilience, Assembly, SDK, adapters, Holodecks and prior executable protocol capabilities are established and tested within their bounded claim surface. |
| **Adversarial assurance** | **Phase 9 complete** | MORIARTY/1 graduated the exact immutable v0.11.0 source commit through provider-neutral, fixed-probe adversarial testing. |
| **Formal assurance** | **Phase 10 complete** | 47 selected constitutional and protocol separation propositions are formalized in Lean 4.33.1 with no `sorry`/`admit`, no custom axioms, and no graduation-theorem kernel-axiom dependencies. |

The identities are intentionally distinct:

```text
SOFTWARE RELEASE              = QSOL-FED v0.11.0
IMMUTABLE SOURCE COMMIT       = c953463724cdf218802e66e16f582ae8d600ca47
IMMUTABLE SOURCE TREE         = 93f23cd7eda6dd92ae13b7bb96bee01935b80731
POST-TAG FORMALIZATION MERGE  = 9bc0e33fc30ed14b5ca1a3bfbd2e7ecc5059452b
FORMALIZATION MERGE TREE      = 062ca7fd78c5ada08f0f54f7c822337e2fa081e0
ZENODO RECORD VERSION         = 1.0.0
ZENODO DOI                    = 10.5281/zenodo.22149263
```

`v0.11.0` remains immutable and is still the exact theorem source target. The later Lean merge and Zenodo publication do not rewrite or repoint that release.

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

[`claims/phase5a.json`](claims/phase5a.json) preserves the capability-less NEXUS-derived Holodeck milestone, the Moriarty Rule, and `Computer, end program` safeguards.

## Historical Phase 5 claim gate

[`claims/phase5.json`](claims/phase5.json) preserves the first full QSOL adapter membrane, including report-only Council federation, ORACLE non-authority observations, and ARK offline preservation.

## Historical Phase 5C claim gate

[`claims/phase5c.json`](claims/phase5c.json) preserves the attested live-local QSOL-ORACLE stdio transport and its non-authority boundary.

## Historical Phase 6 claim gate

[`claims/phase6.json`](claims/phase6.json) preserves governance-neutral Rust/Python/TypeScript SDKs, byte-identical three-implementation conformance, hostile parser regressions, and a neutral third-party node that adopts no QSOL internal governance.

## Historical Phase 7 claim gate

[`claims/phase7.json`](claims/phase7.json) preserves the Federation Assembly, explicit opt-in membership, one-member-one-vote representation, deterministic Charter Gate, fork/version path, advisory-only NEXUS integration, terminal finalization, and member-local sovereignty.

## Runtime capability claim gate — Phase 8

Phase 8 remains the **current runtime/protocol capability map**. Phases 9 and 10 add assurance over this surface; they do not silently add product capabilities.

<!-- CURRENT_CLAIM_BOUNDARY:BEGIN -->
The current repository may claim all reviewed Phase 0–7 capabilities plus:

- bounded transport-frame contract shared by all Phase 8 profiles: **established and tested**;
- WebSocket reference framing profile: **established and tested**;
- QUIC reference framing profile: **established and tested**;
- Unix/local IPC reference framing profile: **established and tested**;
- offline/sneakernet canonical package profile: **established and tested**;
- bounded store-forward profile: **established and tested**;
- NAT traversal route-hint identity binding without trust/authority promotion: **established and tested**;
- explicit multi-relay provenance chain: **established and tested**;
- key-compromise/disaster-recovery drills across every transport: **established and tested**;
- long-lived archive compatibility policy: **established and tested**;
- resource-exhaustion and partition drills across every admitted transport: **established and tested**;
- Holodeck transport-independence invariant: **established and tested**;
- Holodeck-to-ORACLE synthetic admission: **not established**;
- host-level OS/VM/container/hypervisor/hardware sandbox: **not established**;
- production networking: **not established**;
- remote execution: **not established**;
- deployed interoperable federation: **not established**.
<!-- CURRENT_CLAIM_BOUNDARY:END -->

[`claims/phase8.json`](claims/phase8.json) remains canonical for the runtime/protocol capability boundary.

## Phase 9 — MORIARTY/1 adversarial graduation

See [`MORIARTY.md`](MORIARTY.md), [`state/phase9.json`](state/phase9.json) and [`claims/phase9.json`](claims/phase9.json).

Phase 9 adds **assurance, not capability**. MORIARTY/1 uses a fixed, provider-neutral attack corpus and fixed probes against an exact isolated commit. The immutable v0.11.0 source commit graduated this adversarial gate before being used as the Phase 10 theorem target.

```text
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
CLAIMED EXECUTION != EXECUTED
PHASE 9 ASSURANCE != NEW PRODUCT CAPABILITY
```

The Phase 9 reference surface contains 15 attack families and 13 fixed probes. Production credentials, arbitrary operator commands, production targets, network targets, and constitutional bypasses are forbidden by the graduation protocol.

## Phase 10 — Lean 4 formalization

See [`FORMALIZATION.md`](FORMALIZATION.md), [`state/phase10.json`](state/phase10.json), [`claims/phase10.json`](claims/phase10.json), and [`machine/lean-phase10-manifest.json`](machine/lean-phase10-manifest.json).

Phase 10 formalizes **47 selected constitutional and protocol separation propositions** against the immutable QSOL-FED v0.11.0 source target. The reviewed post-tag formalization merged at commit `9bc0e33fc30ed14b5ca1a3bfbd2e7ecc5059452b`.

The archival theorem set is built with **Lean 4.33.1** and records:

- 47 named graduation theorems;
- theorem-to-contract traceability;
- elaborated theorem type auditing;
- no unresolved `sorry` or `admit`;
- no custom `axiom` or `constant` declarations;
- no external Lean dependencies;
- no kernel-axiom dependencies in the graduation theorem set.

The formalization covers selected invariants including Prime Directive admission, signature/trust/authority separation, peering/capability separation, import non-authority, peer lifecycle monotonicity, partition sovereignty, provenance preservation, Holodeck isolation, adapter/SDK non-authority, Assembly sovereignty, transport admission, authenticated sender binding, NAT identity binding, and relay non-authority.

It does **not** prove the whole Rust implementation, deployed security, operating-system or hardware isolation, real-world principal uniqueness, SHA-256 collision resistance, or unstated real-world assumptions.

```text
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
FORMAL MODEL != WHOLE IMPLEMENTATION VERIFICATION
FORMAL PROOF != EMPIRICAL VALIDATION
TAGGED RELEASE IDENTITY != POST-TAG FORMALIZATION
```

### Merged-main verification

The exact Phase 10 merge commit passed both of the relevant merged-main gates:

- Phase 10 Lean workflow #128 / run `33198458502`: **success**;
- inherited constitutional/MORIARTY CI #471 / run `33198458525`: **success**.

## Formalization publication

The human-facing formalization report, exact Phase 10 source/evidence archive, and release notes are published on Zenodo:

> Slade, T. (2026). *QSOL-FED Lean 4 Formalization: Machine-Checked Constitutional and Protocol Separation Invariants* (Version 1.0.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.22149263

The Zenodo record uses **Creative Commons Attribution 4.0 International (CC BY 4.0)** at the record/publication level. The QSOL-FED repository source retains its existing **Apache License 2.0** unchanged.

## Transport profiles and resilience

See [`TRANSPORTS.md`](TRANSPORTS.md) and [`state/phase8.json`](state/phase8.json).

Phase 8 defines one bounded canonical framing boundary above five delivery profiles:

```text
web_socket
quic
unix_ipc
offline_sneakernet
store_forward
```

The profiles preserve original authenticated and content identities:

```text
TRANSPORT != IDENTITY
ROUTE != TRUST
RELAY != AUTHORITY
PHYSICAL PRESENCE != ADMISSION
PARTITION RECOVERY != SILENT RECONCILIATION
REFERENCE TRANSPORT PROFILE != PRODUCTION NETWORK SERVICE
```

WebSocket/QUIC NAT tickets are short-lived route hints only. They cannot replace the already authenticated sender and grant no trust or authority. Relay receipts preserve original frame/message/payload identity and link each prior hop without making relays trusted. Offline and store-forward delivery remain subject to normal local admission.

Every admitted profile runs deterministic resource-exhaustion, partition-recovery, key-compromise, multi-relay, archive, and Holodeck-independence drills. WebSocket and QUIC additionally run NAT identity-binding drills.

### Holodeck transport independence

A transport carrying a Holodeck receipt remains outside the sandbox. Network delivery does not retroactively mean the simulation itself used the network, and offline media does not make simulation output authoritative:

```text
authority_effect     = none
federation_effect    = none
evidence_effect      = none
network_used         = false
real_tools_used      = false
credentials_exposed  = false
```

## Federation Assembly

See [`ASSEMBLY.md`](ASSEMBLY.md) and [`state/phase7.json`](state/phase7.json).

The Assembly remains a protocol-evolution governance plane, not a member control plane:

```text
ASSEMBLY MEMBERSHIP != NETWORK MEMBERSHIP
ASSEMBLY CONSENSUS != TRUTH
ASSEMBLY VOTE != MEMBER-LOCAL COMMAND
ASSEMBLY ACCEPTANCE != SOURCE MERGE
ASSEMBLY ACCEPTANCE != DEPLOYMENT
NEXUS ADVICE != VOTE WEIGHT
```

Assembly membership requires an explicit local Assembly admission step. The deterministic Charter Gate routes constitutional conflicts to an explicit fork path instead of allowing a majority to weaken member-local sovereignty. Finalized proposals produce governance receipts, not automatic execution.

## Third-party SDKs

See [`SDK.md`](SDK.md) and [`docs/THIRD_PARTY_INTEGRATION.md`](docs/THIRD_PARTY_INTEGRATION.md).

Rust, Python, and TypeScript/JavaScript independently reproduce the same canonical Phase 6 conformance transcript. The frozen `fed:qsol:` v1 node namespace is wire syntax, not QSOL governance membership.

```text
WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP
SDK CONFORMANCE != TRUST
```

## AI Holodecks

See [`HOLODECK.md`](HOLODECK.md). The Holodeck remains a capability-less application-level sandbox. `SIMULATION != AUTHORITY` and `Computer, end program` remain enforced.

## QSOL adapters

See [`QSOL_ADAPTERS.md`](QSOL_ADAPTERS.md). NEXUS reports do not inject votes, ORACLE observations do not become truth authority, and ARK preservation does not make archived material authoritative or real-world history.

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
TRANSPORT != IDENTITY
TRANSPORT != AUTHORITY
RELAY != TRUST
LOCAL SOVEREIGNTY > FEDERATION CONVENIENCE
```

## Verification

Runtime/protocol and adversarial gates:

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
python3 tools/validate_phase5c_gate.py
python3 tools/validate_phase6_gate.py
python3 tools/validate_phase7_gate.py
python3 tools/validate_phase8_gate.py
python3 tools/validate_phase9_gate.py
```

Phase 10 formalization:

```bash
python3 tools/validate_phase10_gate.py
lake build
lake env lean QSOLFed/TypeAudit.lean
lake env lean QSOLFed/AxiomAudit.lean
```

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol `qsol-fed/1`; software release `v0.11.0` / crate `0.11.0`.

- Phases 0 through 8: executable runtime/protocol capability gates complete within their stated claim boundaries.
- Phase 9: MORIARTY/1 exact-commit adversarial graduation complete.
- Phase 10: selected-invariant Lean 4 formalization complete, merged, exact-main verified, and published on Zenodo.

Production networking, real remote execution, host-level sandboxing, Holodeck-to-ORACLE synthetic admission, and deployed interoperable federation remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project and is not affiliated with or endorsed by any entertainment franchise or rights holder.
