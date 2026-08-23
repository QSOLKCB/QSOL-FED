# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED now includes the first Phase 5 QSOL-NEXUS adapter slice: a **sandboxed synthetic-world kernel** that derives reproducible AI Holodeck world plans from locally NEXUS-verified WorldStore export identities without giving the simulation any real Federation, network, tool, credential, or source-world mutation capability.

## Historical claim gates

Historical release-claim baselines remain immutable:

```text
claims/phase0.json   constitutional bootstrap
claims/phase2.json   cryptographic identity
claims/phase3.json   bounded reference API
claims/phase4.json   durable federation state
```

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

This is an application-level capability sandbox, not a claim of VM/container/hardware isolation.

### Holodeck Computer safeguards

Boundary effects are not attempted on a best-effort basis. A simulated attempt to mutate peers/trust/capabilities/evidence/governance/citizenship, alter the source WorldStore, call a real tool, use the network, access credentials, create a nested Holodeck, or disable safeguards becomes a deterministic `safety_trip` and freezes the program.

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

The final [`ROADMAP.md`](ROADMAP.md) phase now defines **MORIARTY/1**, a repository-wide adversarial graduation harness whose reference operator may be Codex. Any reproducible counterexample reopens the phase that owns the violated invariant.

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

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol `qsol-fed/1`; current crate `0.6.0`. Phases 0 through 4 and Phase 5A have executable gates. The live QSOL-NEXUS runtime bridge, production networking, real remote execution, and deployed multi-implementation interoperability remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project and is not affiliated with or endorsed by any entertainment franchise or rights holder.
