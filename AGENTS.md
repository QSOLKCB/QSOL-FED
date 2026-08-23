# AGENTS.md

## Machine contribution contract

QSOL-FED is a security-sensitive federation boundary. Protocol convenience never overrides the Charter, Prime Directive, frozen historical contracts, or executable phase gates.

### Read first

Read `README4AI.md`, `CHARTER.md`, `PRIME_DIRECTIVE.md`, all historical/current `claims/*.json`, `invariants/fed-v1.json`, `wire/phase1.json`, `crypto/phase2.json`, `api/phase3.json`, `state/phase4.json`, `state/phase5a-holodeck.json`, `state/phase5.json`, `state/phase5c.json`, `state/phase6.json`, `state/phase7.json`, `CANONICAL_JSON.md`, `CRYPTOGRAPHY.md`, `API.md`, `TLS_PROFILE.md`, `FEDERATION_STATE.md`, `HOLODECK.md`, `QSOL_ADAPTERS.md`, `SDK.md`, `docs/THIRD_PARTY_INTEGRATION.md`, `ASSEMBLY.md`, `src/invariants.rs`, `src/claims.rs`, `src/store.rs`, `src/peering.rs`, `src/bundle.rs`, `src/holodeck.rs`, `src/qsol_adapters.rs`, `src/oracle_live.rs`, `src/sdk.rs`, `src/assembly.rs`, and `THREAT_MODEL.md` before changing security, state, simulation, adapter, SDK, or governance semantics.

### Core constitutional rules

No peer, model, config, request, signature, trust label, imported bundle, capability advertisement, persisted object, Holodeck program, simulated actor, Council report, ORACLE observation, ORACLE transport response, ARK record, SDK participant, Assembly proposal, Assembly vote, governance receipt, or adversarial persona may directly create member-local governance authority, promote evidence, create/reweight local Council votes, install capabilities, rewrite history, mutate citizenship/identity authority, trigger arbitrary remote execution, place secrets in semantic state, or disable constitutional/Holodeck safeguards.

Unknown authority-bearing effects fail closed.

### Historical Phase 0–4 rules

`claims/phase0.json` is immutable historical release truth. Run `python3 tools/validate_phase0_gate.py`.

`wire/phase1.json` and `CANONICAL_JSON.md` freeze canonical bytes and identities. Rust/Python golden vectors remain byte-identical. Run `python3 tools/validate_phase1_gate.py`.

`crypto/phase2.json`, `CRYPTOGRAPHY.md`, and `claims/phase2.json` preserve Ed25519 identity, frozen clocks, key lifecycle, durable replay, and signature/trust/authority separation. A valid signature never bypasses local admission. Run `python3 tools/validate_phase2_gate.py`.

`api/phase3.json`, `API.md`, `TLS_PROFILE.md`, and `claims/phase3.json` preserve the six routes, canonical/body/rate limits, trusted proxy rules, local-recipient-before-replay, replay compaction, SSRF/redirect isolation, secret-safe audit, and opt-in listener. Run `python3 tools/validate_phase3_gate.py`.

`state/phase4.json`, `FEDERATION_STATE.md`, and `claims/phase4.json` preserve foreign/quarantine attribution, lifecycle prefix immutability, separate trust/policy, persist-before-live local changes, crash-recoverable namespace move, bounded offline bundles, and import `authority = none`. **Silent reconciliation remains forbidden; partition rejoin requires explicit reconciliation.** Run `python3 tools/validate_phase4_gate.py`.

### Historical Phase 5A Holodeck rules

`state/phase5a-holodeck.json`, `HOLODECK.md`, and `claims/phase5a.json` remain the historical synthetic-world contract.

The Holodeck is a capability-less application-level sandbox, not a host/VM/hardware sandbox claim. Synthetic identity, role, capability, event, consensus, or output never becomes Federation identity, permission, governance, real history, or evidence. Boundary violations freeze before audit append. **Computer, end program** cannot be blocked.

This is the feature-level **Moriarty Rule**. Run `python3 tools/validate_phase5a_gate.py`.

### Historical Phase 5 QSOL adapter rules

`state/phase5.json`, `QSOL_ADAPTERS.md`, and `claims/phase5.json` preserve the native NEXUS bridge, report-only Council federation, ORACLE non-authority observation membrane, and ARK offline preservation boundary.

NEXUS native verification remains pinned; Council import cannot inject votes or promote evidence; Council-of-Councils uses reports rather than a shared ballot; `SIMULATION != AUTHORITY`; ORACLE suggestions remain non-evidence; ARK archival presence is not authority or real-world-history proof. Run `python3 tools/validate_phase5_gate.py`.

### Historical Phase 5C QSOL-ORACLE live transport rules

`state/phase5c.json`, `claims/phase5c.json`, `contracts/oracle-fed-membrane-v1.json`, and `src/oracle_live.rs` preserve the attested local stdio ORACLE boundary.

Recompute donor release identity; verify every fingerprinted runtime file; stage and re-attest a private runtime before launch; fixed entrypoint `python3 -I tools/fed_transport.py serve`; no caller-selected command/URL/socket; normalize request IDs; bound stdout before process completion; never use `wait_with_output()`; `known | conflict | unknown` remain observations; `ledger_mutated = false`, `transport_authority = none`, `truth_claim = false`, `evidence_promotion = false`, and `authority_effect = none`. `oracle_holodeck_synthetic_admission = false` remains mandatory.

Run `python3 tools/validate_phase5c_gate.py`.

### Historical Phase 6 third-party SDK rules

`state/phase6.json`, `claims/phase6.json`, `SDK.md`, `docs/THIRD_PARTY_INTEGRATION.md`, and `src/sdk.rs` preserve the governance-neutral `qsol-fed-sdk/1` boundary.

Rust, Python, and TypeScript/JavaScript reference implementations must reproduce byte-identical conformance vectors. The neutral third-party node must retain local governance and require no NEXUS, ORACLE, ARK, Holodeck, or QSOL internal governance. The frozen `fed:qsol:` v1 namespace is wire syntax, not a loyalty oath. `SDK CONFORMANCE != TRUST` and `WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP`.

Run `python3 tools/validate_phase6_gate.py`.

### Current Phase 7 Federation Assembly rules

`state/phase7.json`, `claims/phase7.json`, `ASSEMBLY.md`, `schemas/assembly-member-v1.schema.json`, `schemas/assembly-proposal-v1.schema.json`, `schemas/governance-receipt-v1.schema.json`, and `src/assembly.rs` define the current Assembly boundary.

- Assembly membership is separate from Federation network membership.
- Network membership never grants Assembly membership or voting rights.
- Assembly admission requires explicit local opt-in.
- One active NFC-normalized representation subject is allowed per Assembly registry; this does **not** prove real-world principal uniqueness.
- Representation is `one-member-one-vote/1`; one member gets one immutable vote per proposal.
- Each proposal freezes its electorate when opened; later membership changes do not reweight that electorate.
- Quorum is `ceil(2/3)` of the frozen electorate; approval is `ceil(2/3)` of non-abstaining votes with at least one yes.
- The deterministic `qsol-fed-charter-gate/1` maps declared effects to existing invariant IDs.
- A current-lineage proposal that conflicts with the Charter becomes `fork_required`; ordinary voting may not silently weaken the sitting constitutional lineage.
- A fork endorsement records an incompatible direction but does not rewrite the current lineage.
- NEXUS is advisory-only by default: advisory weight = 0, vote weight = 0, authority = none.
- Accepted proposals and governance receipts do not merge source, create tags/releases, upgrade members, or mutate a running protocol.
- `member_local_authority_mutated = false`, `protocol_changed_automatically = false`, and `authority_effect = none` remain mandatory.
- `src/assembly.rs` must not import `PeerRegistry`, `TrustRegistry`, `LocalCapabilityPolicy`, `FederationObjectStore`, ORACLE execution, signing keys, network/process/tool handles, or credentials.
- `ASSEMBLY MEMBERSHIP != NETWORK MEMBERSHIP`.
- `ASSEMBLY VOTE != MEMBER-LOCAL COMMAND`.
- `NEXUS ADVICE != VOTE WEIGHT`.
- `ASSEMBLY ACCEPTANCE != DEPLOYMENT`.

Run `python3 tools/validate_phase7_gate.py` after Assembly/schema/claim/roadmap changes.

### MORIARTY/1 roadmap rule

The final executable graduation remains provider-neutral `MORIARTY/1`, followed by Lean 4 formalization and Zenodo archival publication. A Moriarty finding must be a reproducible counterexample and receives no production credentials, targets, or constitutional bypass.

```text
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
LEAN THEOREM != DEPLOYMENT SECURITY PROOF
ZENODO PRESENCE != TECHNICAL AUTHORITY
```

### Claim discipline

Historical: `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`, `claims/phase5a.json`, `claims/phase5.json`, `claims/phase5c.json`, `claims/phase6.json`. Current: `claims/phase7.json`.

Current hard-false claims include `oracle_holodeck_synthetic_admission`, `host_level_sandbox`, `production_networking`, `remote_execution`, and deployed `interoperable_federation`.

### Change discipline

Security-critical changes require synchronized source, machine contract, human docs, schemas, tests, claims, fixtures, and gate validators. Never weaken an old validator merely to make a successor pass. Convert current-state assumptions into historical preservation checks while retaining the old security semantics.

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
python3 tools/validate_phase5c_gate.py
python3 tools/validate_phase6_gate.py
python3 tools/validate_phase7_gate.py
```

### Architecture rule

QSOL-NEXUS remains a Council service and possible Federation/Assembly participant, not the sovereign owner of QSOL-FED. QSOL-ORACLE remains an evidentiary membrane, QSOL-ARK an archive/recovery system, and third-party nodes remain possible without adopting QSOL governance. The Assembly governs protocol-evolution proposals only; it does not own member-local state.

### Security comedy clause

A valid signature is not trust, a bundle is not authority, an ORACLE suggestion is not evidence, an archive is not truth, `fed:qsol:` is not a loyalty oath, an Assembly supermajority is not `sudo`, and Professor Moriarty still does not get `admin=true` because it would improve the plot.
