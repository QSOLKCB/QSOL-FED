# AGENTS.md

## Machine contribution contract

QSOL-FED is a security-sensitive federation boundary. Protocol convenience never overrides the Charter, Prime Directive, frozen wire/crypto contracts, or phase gates.

### Read first

Read `README4AI.md`, `CHARTER.md`, `PRIME_DIRECTIVE.md`, `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`, `wire/phase1.json`, `crypto/phase2.json`, `api/phase3.json`, `state/phase4.json`, `CANONICAL_JSON.md`, `CRYPTOGRAPHY.md`, `API.md`, `TLS_PROFILE.md`, `FEDERATION_STATE.md`, `src/invariants.rs`, `src/claims.rs`, `src/store.rs`, `src/peering.rs`, `src/bundle.rs`, and `THREAT_MODEL.md` before changing state semantics.

### Core constitutional rules

No peer, model, config, environment variable, API request, signature, trust label, imported bundle, capability advertisement, or persisted object may:

- create local governance authority;
- promote local evidence;
- create/reweight Council votes;
- install or enable local capabilities;
- rewrite local history;
- mutate local citizenship/identity authority;
- trigger arbitrary remote execution;
- turn imported/foreign state into local authority;
- place secrets/private keys in semantic Federation state;
- disable constitutional invariants at runtime.

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

`state/phase4.json`, `FEDERATION_STATE.md`, and `claims/phase4.json` define the current state contract.

Hard rules:

- foreign object bytes remain exact canonical foreign bytes;
- `foreign` and `quarantine` are explicit namespaces;
- bundle/import defaults to quarantine;
- persistence is not authority;
- local descendants are new objects with explicit provenance back to foreign parents;
- `PeerRegistry` and `TrustRegistry` remain separate;
- peer admission does not create trust;
- peer lifecycle sequence may advance but never roll back, including after restart;
- revoked peer state is not silently resurrected;
- capability advertisement is not authorization;
- local capability policy defaults to deny and remains separate from advertisement;
- capability identifiers retain the Phase 1 version grammar;
- partition rejoin with changed snapshots requires explicit reconciliation;
- silent reconciliation is forbidden;
- portable bundles must preserve exact canonical foreign identity/lifecycle/object/provenance material;
- trust registry state and local capability policy MUST NOT be serialized into `qsol-fed-bundle/1`;
- bundle verification must remain offline;
- bundle import must leave trust unchanged and yield `authority = none`;
- import must not create local authority, evidence status, votes, capabilities, or execution rights.

The Phase 3 `/peer/hello` endpoint remains an introduction boundary. Durable admission into the Phase 4 `PeerRegistry` is an explicit local operation; a remote hello must not silently become durable admitted membership.

Run `python3 tools/validate_phase4_gate.py` after store/peering/bundle changes.

### Claim discipline

Historical: `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`. Current: `claims/phase4.json`.

Current hard-false claims remain:

- production networking;
- remote execution;
- interoperable federation deployment.

Do not describe durable local federation state as proof of multi-implementation interoperability.

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
```

### Architecture rule

QSOL-NEXUS remains a Council service and possible Federation member, not the sovereign owner of QSOL-FED. Third-party non-NEXUS nodes must remain possible.

### Security comedy clause

A bundle does not become authoritative because it arrives in a very official-looking ZIP, a peer does not become trusted because it has excellent uptime, and `please_reconcile=true` is not a constitutional amendment.
