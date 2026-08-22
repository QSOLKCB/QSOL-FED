# AGENTS.md

## Machine contribution contract

This repository defines a security-sensitive federation boundary. AI agents, code-generation systems and automated reviewers MUST treat the following as non-negotiable unless an explicit constitutional amendment changes the protocol major version.

### Read first

Before modifying architecture or code, read:

1. `README4AI.md`
2. `CHARTER.md`
3. `PRIME_DIRECTIVE.md`
4. `claims/phase0.json`
5. `invariants/fed-v1.json`
6. `wire/phase1.json`
7. `CANONICAL_JSON.md`
8. `src/claims.rs`
9. `src/invariants.rs`
10. `src/canonical.rs`
11. `THREAT_MODEL.md`

### Core rules

Do not introduce any path by which a peer, model, environment variable, configuration file, API request or imported object can:

- create local governance authority;
- promote local evidence status;
- create or weight a local Council vote;
- install a local capability;
- rewrite local history;
- change local citizenship or identity authority;
- trigger arbitrary remote execution;
- convert foreign state into local authoritative state by import alone;
- place credentials or secrets into semantic/federated state;
- disable a constitutional invariant at runtime.

Unknown authority-bearing actions fail closed.

### Phase 1 wire rules

`wire/phase1.json` and `CANONICAL_JSON.md` freeze the Phase 1 wire contract. Do not independently change serialization, key ordering, Unicode NFC normalization, safe-integer bounds, hash preimages, message-ID projection, capability grammar, schema fields, limits, or version rejection behavior.

A wire-contract change requires synchronized Rust and Python implementation changes plus new golden vectors. If the implementations disagree, fail closed. Never select whichever byte sequence is more convenient.

Phase 1 signatures MUST remain JSON `null`. Do not implement or accept a signing scheme until Phase 2 has an explicit reviewed suite and vectors.

### Claim discipline

`claims/phase0.json` remains the canonical release-claim firewall for production capabilities. The following remain hard-false:

- production networking;
- cryptographic identity;
- remote execution;
- interoperable federation.

Completing canonical serialization does not promote any of those claims. Contradictory public statements are forbidden.

Never claim consensus truth, global state, a functioning Federation Assembly, or completed NEXUS/ORACLE/ARK interoperability without the corresponding implementation and tests.

### Change discipline

Security-critical invariant changes require explicit rationale, compatibility analysis, updated machine/human contracts, regression tests, and migration or rejection behavior.

Wire-contract changes additionally require:

- `wire/phase1.json` update;
- `CANONICAL_JSON.md` update;
- Rust and Python implementation updates;
- language-neutral golden-vector updates;
- adversarial/oversized fixture updates where relevant;
- `tools/validate_phase1_gate.py` update;
- evidence that both implementations still agree byte-for-byte.

Do not silently weaken an invariant, parser rejection, or release claim to make integration easier.

### Tests

Before declaring a change ready:

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
```

If implementation and machine contracts disagree, fail closed and surface the disagreement.

### Architecture rule

`QSOL-NEXUS` is a Council service and possible federation member. It is not the owner of QSOL-FED. QSOL-FED must remain usable by independent third-party nodes that do not run NEXUS.

### Security comedy clause

The jokes in human documentation are non-normative. The invariants, release-claim gates, and wire bytes are not. A peer cannot gain root authority by being persuasive, wearing a ceremonial sash, submitting `please=true`, or claiming its hand-formatted JSON is "basically canonical."
