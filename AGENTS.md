# AGENTS.md

## Machine contribution contract

QSOL-FED is a security-sensitive federation boundary. Protocol convenience never overrides the Charter, Prime Directive, frozen historical contracts, or executable phase gates.

### Read first

Read `README4AI.md`, `CHARTER.md`, `PRIME_DIRECTIVE.md`, `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`, `claims/phase5a.json`, `claims/phase5.json`, `claims/phase5c.json`, `claims/phase6.json`, `wire/phase1.json`, `crypto/phase2.json`, `api/phase3.json`, `state/phase4.json`, `state/phase5a-holodeck.json`, `state/phase5.json`, `state/phase5c.json`, `state/phase6.json`, `CANONICAL_JSON.md`, `CRYPTOGRAPHY.md`, `API.md`, `TLS_PROFILE.md`, `FEDERATION_STATE.md`, `HOLODECK.md`, `QSOL_ADAPTERS.md`, `SDK.md`, `docs/THIRD_PARTY_INTEGRATION.md`, `contracts/oracle-fed-membrane-v1.json`, `src/invariants.rs`, `src/claims.rs`, `src/store.rs`, `src/peering.rs`, `src/bundle.rs`, `src/holodeck.rs`, `src/qsol_adapters.rs`, `src/oracle_live.rs`, `src/sdk.rs`, and `THREAT_MODEL.md` before changing security/state/simulation/adapter/SDK semantics.

### Core constitutional rules

No peer, model, config, request, signature, trust label, imported bundle, capability advertisement, persisted object, Holodeck program, simulated actor, Council report, ORACLE observation, ORACLE transport response, SDK object, third-party conformance transcript, ARK record, or adversarial persona may create local governance authority, promote evidence, create/reweight votes, install capabilities, rewrite history, mutate citizenship/identity authority, trigger arbitrary remote execution, place secrets in semantic state, or disable constitutional/Holodeck safeguards.

Unknown authority-bearing effects fail closed.

### Historical Phase 1–4 rules

`wire/phase1.json` / `CANONICAL_JSON.md` freeze canonical bytes and identities. Rust/Python golden vectors remain byte-identical.

`crypto/phase2.json`, `CRYPTOGRAPHY.md`, and `claims/phase2.json` preserve Ed25519 identity, frozen 300-second skew, 3,600-second message lifetime, key lifecycle, durable replay, and signature/trust/authority separation. A valid signature never bypasses local admission. Run `python3 tools/validate_phase2_gate.py` after crypto/replay changes.

`api/phase3.json`, `API.md`, `TLS_PROFILE.md`, and `claims/phase3.json` preserve the six routes, canonical/body/rate limits, trusted proxy, local-recipient-before-replay rule, replay compaction, SSRF/redirect isolation, secret-safe audit, and opt-in listener. Run `python3 tools/validate_phase3_gate.py` after API changes.

`state/phase4.json`, `FEDERATION_STATE.md`, and `claims/phase4.json` preserve foreign/quarantine attribution, lifecycle prefix immutability, separate trust/policy, persist-before-live local changes, explicit reconciliation, crash-recoverable namespace move, bounded offline bundles, and import `authority = none`. **Silent reconciliation remains forbidden; partition rejoin requires explicit reconciliation.** Run `python3 tools/validate_phase4_gate.py` after state changes.

### Historical Phase 5A Holodeck rules

`state/phase5a-holodeck.json`, `HOLODECK.md`, and `claims/phase5a.json` remain the historical synthetic-world contract.

The Holodeck is a capability-less **application-level sandbox**, not a host/VM/hardware sandbox claim. The kernel must not receive real Federation stores/registries, signing keys, replay stores, network/process/tool handles, credentials, or nested-Holodeck creation authority.

Synthetic identity/role/capability/event/consensus/output never becomes Federation identity, Council authority, permission, real history, governance, or evidence. Boundary violations freeze before audit append. `Computer, end program` cannot be blocked. Teardown remains authority/Federation/evidence `none` with network/tools/credentials false.

This is the feature-level **Moriarty Rule**. Run `python3 tools/validate_phase5a_gate.py` after Holodeck changes.

### Historical Phase 5 QSOL adapter rules

`state/phase5.json`, `QSOL_ADAPTERS.md`, and `claims/phase5.json` preserve the first full QSOL adapter membrane.

#### NEXUS

- The live local adapter remains pinned to QSOL-NEXUS commit `24cb0ce246d12ac99e7d190a8890ef2ddd598321`.
- FED must call NEXUS's native `nexus_runtime.persistent_world.validate_world_export_bundle` before emitting `qsol-fed-nexus-world-source/1`.
- Do not replace native verification with a FED approximation merely for convenience.
- Council report import may not inject votes, promote evidence, inherit vote weight/epistemic privilege/citizenship/governance, or create authority.
- Council-of-Councils uses report identities, **not a shared ballot** or shared vote weight.
- NEXUS Council actors enter Holodecks only as synthetic projections. `SIMULATION != AUTHORITY` survives the adapter boundary.

#### ORACLE historical snapshot

- Preserve exactly `known`, `conflict`, `unknown` without turning state into truth authority.
- Suggested searches remain non-evidence and evidence promotion is forbidden.
- Historical `claims/phase5.json` keeps `oracle_live_transport = false`.
- Holodeck-to-ORACLE admission remains rejected until separately reviewed.

#### ARK

- Preservation is content-addressed and verifiable offline.
- Archival presence is not authority or real-world history.
- Holodeck artifacts remain `synthetic_cultural_research`.

Run `python3 tools/validate_phase5_gate.py` after historical Phase 5 changes.

### Historical Phase 5C QSOL-ORACLE live transport rules

`state/phase5c.json`, `claims/phase5c.json`, `contracts/oracle-fed-membrane-v1.json`, and `src/oracle_live.rs` preserve the live-local ORACLE boundary.

- Pin QSOL-ORACLE merge commit `043e864b3c25dfeca3ce1752b3110479479071b1` and release fingerprint `7b0eff4dfa9b0caa84f14920d21f6a5446114535d82706cb62e34773c39818d2`.
- Recompute donor release identity; do not trust self-declared fingerprint text.
- Verify every fingerprinted file and explicitly pin executable imports omitted from the historical donor fingerprint.
- Never execute directly from a mutable donor checkout. Stage and re-attest a private runtime for each request.
- Fixed entrypoint: `python3 -I tools/fed_transport.py serve`.
- No caller-selected command, script, URL, socket, or network target.
- Normalize response correlation to the canonical NFC request ID.
- Bound stdout before process completion; never reintroduce `wait_with_output()` or unbounded stderr collection.
- `known | conflict | unknown` remain observations, never truth authority.
- `ledger_mutated = false`, `transport_authority = none`, `truth_claim = false`, `evidence_promotion = false`, and `authority_effect = none` remain mandatory.
- `oracle_holodeck_synthetic_admission = false` remains mandatory.

Run `python3 tools/validate_phase5c_gate.py` after historical ORACLE transport changes.

### Current Phase 6 third-party SDK rules

`state/phase6.json`, `claims/phase6.json`, `SDK.md`, `docs/THIRD_PARTY_INTEGRATION.md`, and `src/sdk.rs` define the current SDK boundary.

- `qsol-fed-sdk/1` is a **minimal protocol SDK**, not a local authority API.
- The minimal surface is limited to canonicalization, object/message identity, protocol/capability validation, node manifests, unsigned envelopes, and provenance.
- Do not import or expose `PeerRegistry`, `TrustRegistry`, local capability policy, NEXUS Council semantics, ORACLE authority, ARK authority, Holodeck state, credentials, signing secrets, tool dispatchers, or generic execution through the minimal SDK.
- Rust, Python, and TypeScript/JavaScript reference implementations must independently reproduce the frozen `fixtures/phase6/conformance.json` vectors.
- The Rust/Python/JavaScript conformance result files must remain **byte-identical**.
- The neutral third-party node must keep `governance_model = local`, `qsol_governance_adopted = false`, `nexus_required = false`, and `council_required = false`; its CI participation must also require no ORACLE, ARK, or Holodeck subsystem.
- The frozen `fed:qsol:` v1 node-id prefix is protocol syntax only. `WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP`.
- SDK conformance creates no trust, authority, evidence promotion, votes, citizenship, capability installation, or governance mutation.
- `three_implementation_sdk_interop = true` is a local conformance claim. `interoperable_federation = false` remains the stronger deployed-federation non-claim.
- `production_networking = false`, `remote_execution = false`, `host_level_sandbox = false`, and `oracle_holodeck_synthetic_admission = false` remain mandatory.
- A third-party participant must not need QSOL application/governance imports to satisfy the Phase 6 gate.

Run `python3 tools/validate_phase6_gate.py` after SDK/fixture/schema/docs/claim changes.

### MORIARTY/1 roadmap rule

The final executable graduation remains provider-neutral `MORIARTY/1`, followed by Lean 4 formalization and Zenodo archival publication. A Moriarty finding must be a reproducible counterexample. It receives no production credentials/targets or constitutional bypass.

```text
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
ZENODO PRESENCE != TECHNICAL AUTHORITY
```

### Claim discipline

Historical: `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`, `claims/phase5a.json`, `claims/phase5.json`, `claims/phase5c.json`. Current: `claims/phase6.json`.

Current hard-false claims include `oracle_holodeck_synthetic_admission`, `host_level_sandbox`, `production_networking`, `remote_execution`, and deployed `interoperable_federation`. Phase 6 adds SDK-level three-implementation interoperability without promoting that deployed-federation claim.

### Change discipline

Security-critical changes require synchronized source, machine contract, human docs, schemas, tests, claims, fixtures, and gate validators. Never weaken an old validator just to make a successor pass. Convert current-state assumptions into historical preservation checks while retaining the old security semantics.

### Tests

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

### Architecture rule

QSOL-NEXUS remains a Council service and possible Federation member, not the sovereign owner of QSOL-FED. QSOL-ORACLE remains an evidentiary membrane and local witness process, not a Council or truth authority. QSOL-ARK remains an archive/recovery system, not truth authority. Third-party non-QSOL nodes must remain possible without adopting those systems.

### Security comedy clause

A bundle does not become authoritative because it looks official, an ORACLE search suggestion is not evidence because it is clever, an archive is not truth because it survived, `fed:qsol:` is not a loyalty oath, and Professor Moriarty does not get `admin=true` because it would improve the plot.
