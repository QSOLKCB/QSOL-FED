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
6. `src/claims.rs`
7. `src/invariants.rs`
8. `THREAT_MODEL.md`

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

### Claim discipline

During Phase 0, `claims/phase0.json` is the canonical release-claim manifest. Only capabilities marked `true` there may be described as established or implemented by the current repository state.

The following remain hard-false Phase 0 claims:

- production networking;
- cryptographic identity;
- remote execution;
- interoperable federation.

Do not change one of those values to `true` merely because experimental code, a prototype, a schema, an endpoint design, a signature field, or a test double exists. Promotion requires the corresponding roadmap gate, security evidence, machine-contract update and explicit review.

Never claim consensus truth, global state, a functioning Federation Assembly, or completed NEXUS/ORACLE/ARK interoperability without the corresponding implementation and tests.

A signature proves only that a particular key signed bytes under a particular verification procedure. It does not prove truth, benevolence, identity semantics, authority or local admissibility.

### Change discipline

Security-critical invariant changes require all of the following in one PR:

- explicit rationale;
- protocol compatibility analysis;
- update to `CHARTER.md` or `PRIME_DIRECTIVE.md`;
- update to `invariants/fed-v1.json` or a new major-version registry;
- update to `src/invariants.rs`;
- regression/adversarial tests;
- update to `README4AI.md`;
- migration or rejection behavior for older peers.

Release-claim changes require all of the following in one PR:

- update to `claims/phase0.json` or its successor claim manifest;
- update to `src/claims.rs`;
- roadmap gate evidence;
- update to human and machine status surfaces;
- regression tests and claim-gate validation.

Do not silently weaken an invariant or promote a capability claim to make an integration easier.

### Tests

Before declaring a change ready:

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
```

If an implementation and the constitution or claim manifest disagree, fail closed and surface the disagreement. Do not guess which side was intended.

### Architecture rule

`QSOL-NEXUS` is a Council service and possible federation member. It is not the owner of QSOL-FED. QSOL-FED must remain usable by independent third-party nodes that do not run NEXUS.

### Security comedy clause

The jokes in human documentation are non-normative. The invariants and release-claim gates are not. A peer cannot gain root authority by being extremely persuasive, wearing a ceremonial sash, submitting a JSON field named `please=true`, or announcing that its prototype is now enterprise-ready.
