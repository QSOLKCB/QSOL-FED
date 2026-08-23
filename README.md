# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED now includes a Phase 7 Federation Assembly reference model on top of the constitutional wire, durable Federation state, sandboxed AI Holodecks, QSOL adapters, attested live-local QSOL-ORACLE transport, and governance-neutral third-party SDKs. The Assembly can deliberate about protocol evolution without acquiring member-local authority.

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

## Current Phase 7 claim gate

<!-- CURRENT_CLAIM_BOUNDARY:BEGIN -->
The current repository may claim all reviewed Phase 0–6 capabilities plus:

- Assembly membership separate from network membership: **established and tested**;
- explicit one-member-one-vote representation with frozen proposal electorates: **established and tested**;
- explicit anti-Sybil admission assumptions without overclaiming real-world identity proof: **established and tested**;
- deterministic Charter Gate using existing constitutional invariant IDs: **established and tested**;
- explicit `fork_required` path for incompatible current-lineage proposals: **established and tested**;
- NEXUS advisory-only Assembly integration with zero vote weight: **established and tested**;
- deterministic governance receipts with source/version/fork outcomes: **established and tested**;
- member-local authority mutation by Assembly: **forbidden and absent**;
- Holodeck-to-ORACLE synthetic admission: **not established**;
- host-level OS/VM/container/hypervisor/hardware sandbox: **not established**;
- production networking: **not established**;
- remote execution: **not established**;
- deployed interoperable federation: **not established**.
<!-- CURRENT_CLAIM_BOUNDARY:END -->

[`claims/phase7.json`](claims/phase7.json) is canonical for the current release-claim boundary.

## Federation Assembly

See [`ASSEMBLY.md`](ASSEMBLY.md) and [`state/phase7.json`](state/phase7.json).

The Assembly is a protocol-evolution governance plane, not a member control plane:

```text
ASSEMBLY MEMBERSHIP != NETWORK MEMBERSHIP
ASSEMBLY CONSENSUS != TRUTH
ASSEMBLY VOTE != MEMBER-LOCAL COMMAND
ASSEMBLY ACCEPTANCE != SOURCE MERGE
ASSEMBLY ACCEPTANCE != DEPLOYMENT
NEXUS ADVICE != VOTE WEIGHT
```

Assembly membership requires an explicit local Assembly admission step. A member may optionally reference a Federation node, but network membership is neither necessary nor sufficient for voting rights.

The reference representation model is `one-member-one-vote/1`. Proposal electorates are frozen when a proposal opens so later joins or withdrawals cannot move quorum or voting eligibility. Duplicate votes are rejected rather than replacing history.

The anti-Sybil model is explicit about its limit: the registry rejects duplicate NFC-normalized representation subjects while active, but the protocol does **not** claim to prove that two different real-world identities are controlled by different principals.

### Deterministic Charter Gate

Every proposal is assessed by `qsol-fed-charter-gate/1` against existing invariant IDs in `invariants/fed-v1.json`.

A proposal that would weaken current constitutional protections does not acquire an override through majority vote. It becomes:

```text
disposition              = fork_required
current_lineage_eligible = false
member_local_authority_effect = none
```

An explicit fork proposal may be endorsed as an incompatible direction, but endorsement does not rewrite the current lineage.

### NEXUS remains advisory

A NEXUS Council report can be attached as an advisory artifact with:

```text
advisory_weight  = 0
vote_weight      = 0
authority_effect = none
```

Running NEXUS does not grant Assembly membership. A NEXUS node must join through the same explicit membership process as anyone else if it wants a vote.

### Governance receipts, not automatic execution

Finalized proposals produce `qsol-fed-governance-receipt/1`, recording the electorate, tally, Charter Gate result, and source/version/fork path.

Every receipt preserves:

```text
protocol_changed_automatically = false
member_local_authority_mutated = false
nexus_advisory_vote_weight     = 0
authority_effect               = none
```

An accepted amendment can require source work or a new major version. It does not merge a branch, create a release, upgrade a node, or mutate a member.

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
TRANSPORT != AUTHORITY
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
```

The final [`ROADMAP.md`](ROADMAP.md) graduation sequence remains MORIARTY/1 adversarial graduation → Lean 4 formalization of the exact surviving commit → Zenodo archival/formal publication.

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol `qsol-fed/1`; current crate `0.10.0`. Phases 0 through 7 have executable gates with historical claims preserved by successor manifests. Production networking, real remote execution, host-level sandboxing, Holodeck-to-ORACLE synthetic admission, and deployed interoperable federation remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project and is not affiliated with or endorsed by any entertainment franchise or rights holder.
