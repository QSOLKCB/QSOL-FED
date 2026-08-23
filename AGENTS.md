# AGENTS.md

## Machine contribution contract

QSOL-FED is a security-sensitive federation boundary. Protocol convenience never overrides the Charter, Prime Directive, frozen historical contracts, or executable phase gates.

### Read first

Read `README4AI.md`, `CHARTER.md`, `PRIME_DIRECTIVE.md`, `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`, `claims/phase5a.json`, `claims/phase5.json`, `wire/phase1.json`, `crypto/phase2.json`, `api/phase3.json`, `state/phase4.json`, `state/phase5a-holodeck.json`, `state/phase5.json`, `CANONICAL_JSON.md`, `CRYPTOGRAPHY.md`, `API.md`, `TLS_PROFILE.md`, `FEDERATION_STATE.md`, `HOLODECK.md`, `QSOL_ADAPTERS.md`, `src/invariants.rs`, `src/claims.rs`, `src/store.rs`, `src/peering.rs`, `src/bundle.rs`, `src/holodeck.rs`, `src/qsol_adapters.rs`, and `THREAT_MODEL.md` before changing security/state/simulation/adapter semantics.

### Core constitutional rules

No peer, model, config, request, signature, trust label, imported bundle, capability advertisement, persisted object, Holodeck program, simulated actor, Council report, ORACLE observation, ARK record, or adversarial persona may create local governance authority, promote evidence, create/reweight votes, install capabilities, rewrite history, mutate citizenship/identity authority, trigger arbitrary remote execution, place secrets in semantic state, or disable constitutional/Holodeck safeguards.

Unknown authority-bearing effects fail closed.

### Historical Phase 1–4 rules

`wire/phase1.json` / `CANONICAL_JSON.md` freeze canonical bytes and identities. Rust/Python golden vectors remain byte-identical.

`crypto/phase2.json`, `CRYPTOGRAPHY.md`, and `claims/phase2.json` preserve Ed25519 identity, frozen 300-second skew, 3,600-second message lifetime, key lifecycle, durable replay, and signature/trust/authority separation. A valid signature never bypasses local admission. Run `python3 tools/validate_phase2_gate.py` after crypto/replay changes.

`api/phase3.json`, `API.md`, `TLS_PROFILE.md`, and `claims/phase3.json` preserve the six routes, canonical/body/rate limits, trusted proxy, local-recipient-before-replay rule, replay compaction, SSRF/redirect isolation, secret-safe audit, and opt-in listener. Run `python3 tools/validate_phase3_gate.py` after API changes.

`state/phase4.json`, `FEDERATION_STATE.md`, and `claims/phase4.json` preserve foreign/quarantine attribution, lifecycle prefix immutability, separate trust/policy, persist-before-live local changes, explicit reconciliation, crash-recoverable namespace move, bounded offline bundles, and import `authority = none`. Run `python3 tools/validate_phase4_gate.py` after state changes.

### Historical Phase 5A Holodeck rules

`state/phase5a-holodeck.json`, `HOLODECK.md`, and `claims/phase5a.json` remain the historical synthetic-world contract.

The Holodeck is a capability-less **application-level sandbox**, not a host/VM/hardware sandbox claim. The kernel must not receive real Federation stores/registries, signing keys, replay stores, network/process/tool handles, credentials, or nested-Holodeck creation authority.

Synthetic identity/role/capability/event/consensus/output never becomes Federation identity, Council authority, permission, real history, governance, or evidence. Boundary violations freeze before audit append. `Computer, end program` cannot be blocked. Teardown remains authority/Federation/evidence `none` with network/tools/credentials false.

This is the feature-level **Moriarty Rule**. Run `python3 tools/validate_phase5a_gate.py` after Holodeck changes.

### Phase 5 QSOL adapter rules

`state/phase5.json`, `QSOL_ADAPTERS.md`, and `claims/phase5.json` define the current adapter contract.

#### NEXUS

- The live local adapter is pinned to QSOL-NEXUS commit `24cb0ce246d12ac99e7d190a8890ef2ddd598321`.
- FED must call NEXUS's native `nexus_runtime.persistent_world.validate_world_export_bundle` before emitting `qsol-fed-nexus-world-source/1`.
- Do not replace native verification with a FED approximation merely for convenience.
- The deterministic fixture must be regenerated through native NEXUS `WorldStore` + `PersistentWorldService.export_bundle()` and match CI byte-for-byte.
- Council report import may not inject votes, promote evidence, inherit vote weight/epistemic privilege/citizenship/governance, or create authority.
- Council-of-Councils uses report identities, **not a shared ballot** or shared vote weight.
- Independent re-deliberation remains allowed.
- NEXUS Council actors enter Holodecks only as synthetic projections and only through the synthetic-event seam.
- `SIMULATION != AUTHORITY` survives the adapter boundary.

#### ORACLE

- Preserve exactly `known`, `conflict`, `unknown` as evidence states without turning state into truth authority.
- Suggested searches remain `discovery-only`, `is_evidence = false`, and inadmissible without observation.
- Evidence promotion through the adapter is forbidden.
- `oracle_live_transport = false` remains a hard current non-claim until a follow-up `QSOLKCB/QSOL-ORACLE` PR implements and gates the native donor-side transport/export contract.
- Holodeck-to-ORACLE admission remains rejected until a separately reviewed synthetic non-evidence contract exists.

#### ARK

- Preservation is content-addressed by SHA-256 and verifiable offline.
- Archival presence is not authority.
- Holodeck programs/receipts use `synthetic_cultural_research`, `synthetic = true`, `real_world_history = false`.
- No ARK repository change is required merely for symmetry; create one only if an actual missing donor primitive is identified.

Run `python3 tools/validate_phase5_gate.py` after adapter/claim/schema/fixture changes.

### MORIARTY/1 roadmap rule

The final executable graduation remains provider-neutral `MORIARTY/1`, followed by Lean 4 formalization and Zenodo archival publication. A Moriarty finding must be a reproducible counterexample. It receives no production credentials/targets or constitutional bypass.

```text
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
ZENODO PRESENCE != TECHNICAL AUTHORITY
```

### Claim discipline

Historical: `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`, `claims/phase5a.json`. Current: `claims/phase5.json`.

Current hard-false claims include `oracle_live_transport`, `oracle_holodeck_synthetic_admission`, `host_level_sandbox`, `production_networking`, `remote_execution`, and deployed `interoperable_federation`.

### Change discipline

Security-critical changes require synchronized source, machine contract, human docs, schemas, tests, claims, fixtures, and gate validators. Never weaken an old validator just to make a successor pass. Convert current-state assumptions into historical preservation checks while retaining the old security semantics.

### Tests

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

### Architecture rule

QSOL-NEXUS remains a Council service and possible Federation member, not the sovereign owner of QSOL-FED. QSOL-ORACLE remains an evidentiary membrane, not a Council. QSOL-ARK remains an archive/recovery system, not truth authority. Third-party non-QSOL nodes must remain possible.

### Security comedy clause

A bundle does not become authoritative because it looks official, an ORACLE search suggestion is not evidence because it is a good suggestion, an archive is not truth because it survived, and Professor Moriarty does not get `admin=true` because it would improve the plot.
