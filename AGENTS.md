# AGENTS.md

## Machine contribution contract

This repository defines a security-sensitive federation boundary. AI agents, code-generation systems and automated reviewers MUST treat the following as non-negotiable unless an explicit constitutional amendment changes the relevant protocol contract.

### Read first

Before modifying architecture or code, read:

1. `README4AI.md`
2. `CHARTER.md`
3. `PRIME_DIRECTIVE.md`
4. `claims/phase0.json`
5. `claims/phase2.json`
6. `invariants/fed-v1.json`
7. `wire/phase1.json`
8. `CANONICAL_JSON.md`
9. `crypto/phase2.json`
10. `CRYPTOGRAPHY.md`
11. `src/claims.rs`
12. `src/invariants.rs`
13. `src/canonical.rs`
14. `src/crypto.rs`
15. `src/replay.rs`
16. `THREAT_MODEL.md`

### Core constitutional rules

Do not introduce any path by which a peer, model, environment variable, configuration file, API request, signature, trust label, or imported object can:

- create local governance authority;
- promote local evidence status;
- create or weight a local Council vote;
- install a local capability;
- rewrite local history;
- change local citizenship or identity authority;
- trigger arbitrary remote execution;
- convert foreign state into local authoritative state by import alone;
- place credentials or private keys into semantic/federated state;
- disable a constitutional invariant at runtime.

Unknown authority-bearing actions fail closed.

### Phase 1 wire rules

`wire/phase1.json` and `CANONICAL_JSON.md` freeze the Phase 1 wire contract. Do not independently change serialization, key ordering, Unicode NFC normalization, safe-integer bounds, hash preimages, message-ID projection, capability grammar, schema fields, limits, or version rejection behavior.

The exact inner Federation envelope remains a Phase 1 object and its embedded `signature` field remains JSON `null`. Phase 2 signatures are detached in `qsol-fed-signed-envelope/1`.

A wire-contract change requires synchronized Rust and Python implementation changes plus new golden vectors. If the implementations disagree, fail closed.

### Phase 2 cryptographic rules

`crypto/phase2.json` and `CRYPTOGRAPHY.md` are the reviewed Phase 2 crypto contract.

Do not:

- substitute an algorithm for exact Ed25519;
- accept aliases such as `Ed25519`, `ed25519ph`, or `ed25519ctx`;
- change any domain separator silently;
- serialize a private seed into Federation state;
- permit a root identity key to sign Federation envelopes;
- treat signature validity as trust, evidence, authority, or admission;
- bypass Prime Directive admission because a signature is valid;
- rotate an operational key without the required root and proof-of-possession signatures;
- use recovery mode unless the outgoing operational key is already revoked or compromised;
- invent root-key rotation under the existing node ID;
- weaken the 300-second skew, 3600-second signed-message lifetime, or 86400-second transition overlap without synchronized contract review;
- report a replay as fresh before the replay record is durably fsynced;
- ignore replay-log corruption or partial tails.

Root compromise is terminal for that node ID in this profile.

### Claim discipline

`claims/phase0.json` is an immutable historical baseline. `claims/phase2.json` is the canonical **current** release-claim manifest.

Phase 2 may now claim:

- canonical wire contract;
- cryptographic identity;
- signed-envelope verification;
- key lifecycle;
- durable single-process replay protection.

The following remain hard-false current claims:

- production networking;
- remote execution;
- interoperable federation deployment.

Do not describe local crypto/replay machinery as a production-safe network node. Contradictory public statements are forbidden.

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

Crypto-contract changes additionally require:

- `crypto/phase2.json` update;
- `CRYPTOGRAPHY.md` update;
- schema updates;
- signature-vector updates;
- Rust cryptographic/lifecycle/replay regression tests;
- `tools/validate_phase2_gate.py` update;
- explicit analysis of downgrade, algorithm confusion, key compromise, replay, and Prime Directive interaction.

Release-claim changes require updating the canonical successor claim manifest, Rust claim mirror, public/machine status surfaces, roadmap evidence, and claim-gate validation.

Do not silently weaken an invariant, parser rejection, key-lifecycle rule, replay rule, or release claim to make integration easier.

### Tests

Before declaring a change ready:

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
python3 tools/validate_phase2_gate.py
```

If implementation and machine contracts disagree, fail closed and surface the disagreement.

### Architecture rule

`QSOL-NEXUS` is a Council service and possible federation member. It is not the owner of QSOL-FED. QSOL-FED must remain usable by independent third-party nodes that do not run NEXUS.

### Security comedy clause

The jokes in human documentation are non-normative. The invariants, claim gates, canonical bytes, key roles, and replay decisions are not. A peer cannot gain root authority by being persuasive, wearing a ceremonial sash, presenting a valid signature, or adding `trust_me_bro=true` beside it.
