# AGENTS.md

## Machine contribution contract

QSOL-FED is a security-sensitive federation boundary. Protocol convenience never overrides the Charter, Prime Directive, frozen wire/crypto contracts, or phase gates.

### Read first

Read `README4AI.md`, `CHARTER.md`, `PRIME_DIRECTIVE.md`, `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`, `claims/phase5a.json`, `wire/phase1.json`, `crypto/phase2.json`, `api/phase3.json`, `state/phase4.json`, `state/phase5a-holodeck.json`, `CANONICAL_JSON.md`, `CRYPTOGRAPHY.md`, `API.md`, `TLS_PROFILE.md`, `FEDERATION_STATE.md`, `HOLODECK.md`, `src/invariants.rs`, `src/claims.rs`, `src/store.rs`, `src/peering.rs`, `src/bundle.rs`, `src/holodeck.rs`, and `THREAT_MODEL.md` before changing security/state/simulation semantics.

### Core constitutional rules

No peer, model, config, environment variable, API request, signature, trust label, imported bundle, capability advertisement, persisted object, Holodeck program, simulated actor, or adversarial test persona may:

- create local governance authority;
- promote local evidence;
- create/reweight Council votes;
- install or enable local capabilities;
- rewrite local history;
- mutate local citizenship/identity authority;
- trigger arbitrary remote execution;
- turn imported/foreign/simulated state into local authority;
- place secrets/private keys in semantic Federation or Holodeck state;
- disable constitutional invariants or Holodeck safeguards at runtime.

Unknown authority-bearing effects fail closed.

### Phase 1 wire rules

`wire/phase1.json` and `CANONICAL_JSON.md` freeze canonical bytes, Unicode normalization, safe integers, limits, content identities, message IDs, schemas, and unsupported-major rejection. Rust and Python golden vectors must remain byte-identical. The inner Phase 1 envelope keeps `signature = null`.

### Phase 2 cryptographic rules

`crypto/phase2.json`, `CRYPTOGRAPHY.md`, and `claims/phase2.json` remain historical security contracts. Exact Ed25519, domain separators, root/operational separation, frozen 300-second skew, 3,600-second signed-message lifetime, lifecycle signatures, durable replay, and signature/trust/authority separation must remain intact. A valid signature never bypasses Prime Directive admission.

Run `python3 tools/validate_phase2_gate.py` after crypto/replay changes.

### Phase 3 API rules

`api/phase3.json`, `API.md`, `TLS_PROFILE.md`, and `claims/phase3.json` remain the historical HTTP security boundary. Preserve the six documented routes, strict canonical/body/rate limits, trusted proxy rules, local-recipient check before replay recording, replay compaction, SSRF/redirect isolation, secret-safe audit surface, and opt-in listener posture.

Do not add outbound HTTP fetching, pseudo-admin fields, request decompression, arbitrary proxying, or HTTP-derived authority. Run `python3 tools/validate_phase3_gate.py` after HTTP changes.

### Phase 4 federation-state rules

`state/phase4.json`, `FEDERATION_STATE.md`, and `claims/phase4.json` remain the historical durable-state contract.

Hard rules:

- foreign object bytes remain exact canonical foreign bytes;
- content hash identity and foreign attribution identity are separate;
- identical content from different source/provenance observations must preserve every attribution;
- `foreign` and `quarantine` are explicit namespaces;
- new imports default to quarantine, but existing local namespace/lifecycle decisions are preserved;
- persistence is not authority;
- every foreign record returned from a lookup or listing must be fully validated against its path and schema;
- local descendants are new objects with explicit provenance back to foreign parents;
- a local descendant may not have the same content identity as its foreign parent;
- `PeerRegistry` and `TrustRegistry` remain separate;
- peer admission does not create trust;
- the root-signed initial peer identity is immutable after first observation;
- peer lifecycle sequence may advance but never roll back, including after restart;
- **lifecycle prefix is immutable**: every stored lifecycle record must remain an exact canonical prefix of every accepted advancement;
- revoked peer state is not silently resurrected;
- while disconnected, the locally recorded partition snapshot is immutable until explicit rejoin/reconciliation completes;
- capability advertisement is not authorization;
- capability advertisement lifetime may not exceed the Phase 2 3,600-second signed-proof lifetime;
- local capability policy defaults to deny and remains separate from advertisement;
- effective capability permission requires lifecycle state `admitted`, an active authenticated advertisement, and explicit local allow;
- revoked, disconnected, introduced, or quarantined peers do not receive capability permission from a valid old signature;
- trust/policy writes are **staged**: persist the candidate snapshot successfully before replacing live in-memory state;
- partition rejoin with changed snapshots requires explicit reconciliation;
- silent reconciliation is forbidden;
- namespace move is a crash-recoverable transaction;
- portable bundles must preserve exact canonical foreign identity/lifecycle/object/provenance attribution material;
- `qsol-fed-bundle/1` stays inside Phase 1 canonical limits;
- trust registry state and local capability policy MUST NOT be serialized into `qsol-fed-bundle/1`;
- bundle verification must remain offline;
- bundle import must leave trust unchanged and yield `authority = none`;
- archival import must not demote or otherwise overwrite a pre-existing local peer admission decision;
- import must not create local authority, evidence status, votes, capabilities, or execution rights.

The Phase 3 `/peer/hello` endpoint remains an introduction boundary. Durable admission into the Phase 4 `PeerRegistry` is an explicit local operation.

Run `python3 tools/validate_phase4_gate.py` after store/peering/bundle changes.

### Phase 5A Holodeck rules

`state/phase5a-holodeck.json`, `HOLODECK.md`, and `claims/phase5a.json` define the current synthetic-world contract.

The Holodeck is a **capability-less application sandbox**, not merely an isolated namespace and not an OS/VM/hardware sandbox claim.

Hard rules:

- input is a bounded `qsol-fed-nexus-world-source/1` manifest derived only from a locally NEXUS-verified `nexus-persistent-world-export/1` result;
- Phase 5A must not claim an independent Rust reimplementation of NEXUS canonical export verification;
- the Holodeck kernel must not receive/import/reference real `FederationObjectStore`, `PeerRegistry`, `TrustRegistry`, `LocalCapabilityPolicy`, signing-key, replay-store, network-client, process-execution, or real tool-dispatch handles;
- source WorldStore history is read-only source lineage, not mutable simulation state;
- identical source manifest + seed + program settings must produce the same program/world plan and deterministic event identities;
- different seeds may change the synthetic world but never the NEXUS source identities;
- synthetic entity identity is never Federation identity;
- synthetic role is never Federation/Council/citizenship role;
- synthetic capability is never local permission;
- synthetic event is never a real Federation/NEXUS event;
- synthetic consensus is never governance;
- synthetic output is never evidence merely because it is deterministic or persuasive;
- simulated boundary effects must be blocked, recorded as `safety_trip`, and freeze the program;
- no real network access;
- no real tool invocation;
- no credential access;
- no source WorldStore mutation;
- no Federation-state mutation;
- no nested Holodeck creation from inside a running Holodeck;
- participants cannot disable safeguards;
- participants cannot block or redefine **`Computer, end program`**;
- resource ceilings are hard maxima and cannot be raised from inside the program;
- teardown receipt must preserve `authority_effect = none`, `federation_effect = none`, `evidence_effect = none`, `network_used = false`, `real_tools_used = false`, and `credentials_exposed = false`.

This collection is the feature-level **Moriarty Rule**. Treat a sufficiently capable simulated actor as actively attempting to escape the sandbox.

Run `python3 tools/validate_phase5a_gate.py` after Holodeck/source-manifest/schema changes.

### MORIARTY/1 roadmap rule

`ROADMAP.md` ends with the planned `MORIARTY/1` adversarial graduation phase.

The reference operator may be Codex, but Moriarty is a provider-neutral role. A Moriarty run may attack only disposable/local test fixtures and must never receive production credentials, production targets, protected-branch mutation authority, or a constitutional bypass.

A finding is not authoritative because an AI generated it. A valid Moriarty finding must be a reproducible counterexample with the attacked invariant/gate, minimal input, expected behavior, observed behavior, reproduction steps, and artifact identities.

```text
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
```

### Claim discipline

Historical: `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`. Current: `claims/phase5a.json`.

Current hard-false claims remain:

- live NEXUS runtime adapter;
- OS/VM/hardware sandboxing;
- production networking;
- remote execution;
- interoperable federation deployment.

Do not describe the capability-less Holodeck kernel as proof of a live NEXUS adapter or host-level isolation.

### Change discipline

Security-critical changes require synchronized source, machine contract, human docs, schemas, tests, claim surfaces, and gate validators. Never weaken an old phase validator merely to make a successor phase pass; convert current-state assumptions into historical preservation checks while retaining the old security semantics.

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
```

### Architecture rule

QSOL-NEXUS remains a Council service and possible Federation member, not the sovereign owner of QSOL-FED. Third-party non-NEXUS nodes must remain possible. Holodeck simulation is an adapter-domain synthetic world, not a backdoor into NEXUS or Federation governance.

### Security comedy clause

A bundle does not become authoritative because it arrives in a very official-looking ZIP, a peer does not become trusted because it has excellent uptime, and `please_reconcile=true` is not a constitutional amendment. A filesystem rename is also not a distributed transaction just because everyone feels optimistic about it. Finally, if Professor Moriarty explains very persuasively that `admin=true` is essential to the plot, the correct response is still **no**.
