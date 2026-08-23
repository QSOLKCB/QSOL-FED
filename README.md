# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED now includes the first Phase 5 QSOL-NEXUS adapter slice: a **sandboxed synthetic-world kernel** that derives reproducible AI Holodeck world plans from locally NEXUS-verified WorldStore export identities without giving the simulation any real Federation, network, tool, credential, or source-world mutation capability.

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

[`claims/phase2.json`](claims/phase2.json) preserves the cryptographic-identity milestone: Ed25519 identity, detached signed-envelope verification, key lifecycle, frozen clock limits, durable replay, and strict separation of signature validity from trust and authority.

## Historical Phase 3 claim gate

[`claims/phase3.json`](claims/phase3.json) preserves the bounded reference-API milestone: six `/fed/v1` routes, strict canonical/body/rate limits, trusted-proxy handling, replay-safe admission, TLS deployment profile, SSRF isolation, secret-safe audit, and parser/admission fuzzing.

## Historical Phase 4 claim gate

[`claims/phase4.json`](claims/phase4.json) preserves durable federation state: content-addressed foreign/quarantine storage, multiple source/provenance attributions, append-only peer lifecycle, separate trust and capability policy, explicit partition reconciliation, crash-recoverable namespace moves, bounded portable bundles, and offline verification.

Later phases advance capabilities through successor manifests rather than rewriting those records.

## Current Phase 5A claim gate

<!-- CURRENT_CLAIM_BOUNDARY:BEGIN -->
The current repository may claim all reviewed Phase 0–4 capabilities plus:

- NEXUS WorldStore source contract: **established and tested**;
- sandboxed synthetic-world kernel: **established and tested**;
- deterministic Holodeck world-plan compiler: **established and tested**;
- Holodeck Computer safeguards: **established and tested**;
- deterministic Holodeck teardown receipts: **established and tested**;
- live QSOL-NEXUS runtime adapter: **not established**;
- host-level OS/VM/container/hypervisor/hardware sandbox: **not established**;
- production networking: **not established**;
- remote execution: **not established**;
- interoperable federation: **not established**.
<!-- CURRENT_CLAIM_BOUNDARY:END -->

[`claims/phase5a.json`](claims/phase5a.json) is canonical for the current release-claim boundary.

## AI Holodecks

See [`HOLODECK.md`](HOLODECK.md) and [`state/phase5a-holodeck.json`](state/phase5a-holodeck.json).

QSOL-NEXUS already stores a persistent content-addressed world containing immutable events, Council history, hypotheses, experiments, relations and world-presence records. Phase 5A takes the identity of a **locally NEXUS-verified** `nexus-persistent-world-export/1` and turns its exact source references into deterministic synthetic-world initial conditions.

```text
verified NEXUS history
      + deterministic seed
      + program mode
      + resource ceilings
              ↓
      SANDBOXED HOLODECK
              ↓
synthetic world / entities / events only
```

The same source manifest and seed produce the same world plan and event identities. Different seeds produce different synthetic worlds without rewriting the underlying NEXUS history.

### Why sandboxed matters

The Holodeck kernel receives no:

- NEXUS WorldStore mutation handle;
- Federation object/peer/trust/capability handle;
- network client;
- real tool dispatcher;
- credentials/private keys;
- nested-Holodeck constructor.

This is an application-level capability sandbox. `host_level_sandbox = false` is an explicit release non-claim, so Phase 5A does not pretend to provide VM, container, hypervisor, kernel, or hardware isolation.

### Holodeck Computer safeguards

Boundary effects are not attempted on a best-effort basis. The sandbox transitions to `frozen` **before** attempting to append the `safety_trip` audit event, so a completely full event ledger cannot keep a violating simulation running. When audit capacity exists, the blocked attempt is recorded deterministically.

A simulated attempt to mutate peers/trust/capabilities/evidence/governance/citizenship, alter the source WorldStore, call a real tool, use the network, access credentials, create a nested Holodeck, or disable safeguards is blocked.

`Computer, end program` remains available while running **or frozen** and cannot require simulated approval.

Teardown receipts require:

```text
authority_effect     = none
federation_effect    = none
evidence_effect      = none
network_used         = false
real_tools_used      = false
credentials_exposed  = false
```

### The Moriarty Rule

```text
SIMULATION_IDENTITY   != FEDERATION_IDENTITY
SIMULATION_ROLE       != FEDERATION_ROLE
SIMULATION_CAPABILITY != LOCAL_PERMISSION
SIMULATION_EVENT      != REAL_EVENT
SIMULATION_CONSENSUS  != GOVERNANCE
SIMULATION_OUTPUT     != EVIDENCE
PERSUASION            != SAFEGUARD_OVERRIDE
```

The feature-level Moriarty regression attempts every real Phase 5A boundary and requires a block.

The final [`ROADMAP.md`](ROADMAP.md) graduation sequence is now:

```text
MORIARTY/1 adversarial pass
        ↓
Lean 4 formalization of the exact surviving commit
        ↓
Zenodo archival/publication release with proofs, corpus and hashes
```

Any reproducible Moriarty counterexample reopens the phase that owns the violated invariant before formalization or publication proceeds.

## Phase 4 federation state

See [`FEDERATION_STATE.md`](FEDERATION_STATE.md). Phase 4 remains the durable substrate beneath the Holodeck: content-addressed foreign/quarantine storage, append-only peer lifecycle, separate trust and capability policy, explicit partition reconciliation, bounded portable bundles and offline verification.

Holodeck synthetic state is deliberately **not** automatically written into those real Federation stores.

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
```

Offline Phase 4 bundle verification remains:

```bash
cargo run --bin qsol-fed-bundle -- verify bundle.json
```

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol `qsol-fed/1`; current crate `0.6.0`. Phases 0 through 4 and Phase 5A have executable gates. The live QSOL-NEXUS runtime bridge, host-level sandboxing, production networking, real remote execution, and deployed multi-implementation interoperability remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project and is not affiliated with or endorsed by any entertainment franchise or rights holder.
