# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED now includes a durable Phase 4 federation-state layer around the frozen wire, cryptographic identity, and opt-in HTTP reference API. It remains intentionally non-centralized: persistence, peering, import, trust labels, and capability advertisements do not create local authority.

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

[`claims/phase2.json`](claims/phase2.json) preserves the cryptographic-identity milestone. Phase 2 established Ed25519 identity, signed-envelope verification, key lifecycle, frozen clock policy, and durable replay while keeping signature validity separate from trust and authority.

## Historical Phase 3 claim gate

[`claims/phase3.json`](claims/phase3.json) preserves the bounded opt-in reference API milestone: six `/fed/v1` routes, strict limits, replay, TLS deployment profile, SSRF isolation, secret-safe audit, and fuzz/adversarial coverage. Production networking remained false.

## Current Phase 4 claim gate

<!-- CURRENT_CLAIM_BOUNDARY:BEGIN -->
The current repository may claim:

- constitutional model: **established and tested**;
- machine contracts: **established and tested**;
- fail-closed admission skeleton: **established and tested**;
- tested constitutional core: **established and tested**;
- canonical wire contract: **established and tested**;
- cryptographic identity: **established and tested**;
- signed envelope verification: **established and tested**;
- key lifecycle: **established and tested**;
- durable replay protection: **established and tested**;
- reference HTTP service: **established and tested**;
- opt-in network listener: **established and tested**;
- bounded API limits: **established and tested**;
- TLS deployment profile: **established and tested**;
- secret-safe audit log: **established and tested**;
- API fuzz/adversarial suite: **established and tested**;
- foreign object store: **established and tested**;
- quarantine namespace: **established and tested**;
- provenance-preserving descendants: **established and tested**;
- durable peer registry: **established and tested**;
- separate trust registry: **established and tested**;
- expiring capability advertisements: **established and tested**;
- local capability policy: **established and tested**;
- partition/rejoin control: **established and tested**;
- portable federation bundle: **established and tested**;
- offline bundle verification: **established and tested**;
- production networking: **not established**;
- remote execution: **not established**;
- interoperable federation: **not established**.
<!-- CURRENT_CLAIM_BOUNDARY:END -->

[`claims/phase4.json`](claims/phase4.json) is canonical for the current release-claim boundary.

## Phase 4 federation state

See [`FEDERATION_STATE.md`](FEDERATION_STATE.md) and [`state/phase4.json`](state/phase4.json).

The durable object store keeps exact canonical foreign bytes under `sha256:` identity and separates `foreign/` from `quarantine/`. Imported objects and peers land in quarantine. Local descendants are new local objects with explicit `derived` provenance back to the foreign parent.

Peer lifecycle is durable and explicit:

```text
unknown → introduced → admitted / quarantined / revoked / disconnected
```

Trust is stored separately. A peer may be admitted while local trust remains `unknown`. Capability advertisement is separately authenticated and expiring; local capability policy defaults to `deny` and must explicitly allow an advertised capability.

Partitions do not silently reconcile. A changed snapshot requires an explicit reconciliation decision before rejoin.

Portable `qsol-fed-bundle/1` files preserve exact foreign identity, lifecycle, object, capability-advertisement, and provenance bytes. Offline verification requires no network, and import yields:

```text
peer state       = quarantined
object namespace = quarantine
authority        = none
trust change     = false
```

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
```

Offline bundle verification:

```bash
cargo run --bin qsol-fed-bundle -- verify bundle.json
```

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol `qsol-fed/1`; current crate `0.5.0`. Phases 0 through 4 have executable gates. Production networking, remote execution, automatic global reconciliation, and deployed multi-implementation interoperability remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project and is not affiliated with or endorsed by any entertainment franchise or rights holder.
