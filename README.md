# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED now includes Phase 8 bounded transport/resilience reference profiles on top of the constitutional wire, durable Federation state, sandboxed AI Holodecks, QSOL adapters, attested live-local QSOL-ORACLE transport, governance-neutral third-party SDKs, and the sovereignty-preserving Federation Assembly. Transport changes delivery mechanics without becoming identity, trust, authority, evidence, governance, or execution.

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

## Current Phase 8 claim gate

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

[`claims/phase8.json`](claims/phase8.json) is canonical for the current release-claim boundary.

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
```

The final [`ROADMAP.md`](ROADMAP.md) graduation sequence remains MORIARTY/1 adversarial graduation → Lean 4 formalization of the exact surviving commit → Zenodo archival/formal publication.

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol `qsol-fed/1`; current crate `0.11.0`. Phases 0 through 8 have executable gates with historical claims preserved by successor manifests. Production networking, real remote execution, host-level sandboxing, Holodeck-to-ORACLE synthetic admission, and deployed interoperable federation remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project and is not affiliated with or endorsed by any entertainment franchise or rights holder.
