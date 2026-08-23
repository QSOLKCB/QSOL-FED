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
6. `claims/phase3.json`
7. `invariants/fed-v1.json`
8. `wire/phase1.json`
9. `CANONICAL_JSON.md`
10. `crypto/phase2.json`
11. `CRYPTOGRAPHY.md`
12. `api/phase3.json`
13. `API.md`
14. `TLS_PROFILE.md`
15. `src/claims.rs`
16. `src/invariants.rs`
17. `src/canonical.rs`
18. `src/crypto.rs`
19. `src/replay.rs`
20. `src/api.rs`
21. `THREAT_MODEL.md`

### Core constitutional rules

Do not introduce any path by which a peer, model, environment variable, configuration file, API request, signature, trust label, HTTP header, listener option, or imported object can:

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

### Phase 3 API rules

`api/phase3.json`, `API.md`, and `TLS_PROFILE.md` define the reviewed Phase 3 reference service.

The six admitted routes are exactly:

```text
GET  /fed/v1/node
GET  /fed/v1/capabilities
POST /fed/v1/peer/hello
POST /fed/v1/envelopes
GET  /fed/v1/objects/{sha256}
GET  /fed/v1/provenance/{sha256}
```

Do not add any network path that:

- fetches a peer-supplied URL;
- follows redirects;
- proxies arbitrary HTTP;
- contacts cloud metadata services;
- treats a forwarding header as Federation identity or authority;
- decompresses Federation request bodies;
- accepts non-canonical JSON on POST;
- accepts pseudo-admin fields such as `force`, `trusted`, `override`, `admin`, `fetch_url`, or `redirect`;
- converts a successful HTTP status into semantic authority;
- accepts an envelope for a recipient other than the local node;
- executes or interprets envelope payloads as tools/commands;
- turns a peer hello into trust, persistence, membership, or governance authority.

Peer hello lifecycle is monotonic. A hello may carry up to 128 ordered, authenticated Phase 2 key-rotation/key-status records. Reconstruct the peer from the root-signed identity and apply those records in sequence. If a peer is already introduced in this process, a later hello may advance that locally retained lifecycle state but MUST NOT roll it back or replace the same sequence with a different state.

The reference crate MUST NOT gain an outbound HTTP client dependency during Phase 3. Missing object/provenance IDs return `404`; they do not trigger network retrieval.

Frozen Phase 3 limits are:

```text
HTTP body                         65536 bytes
capabilities / hello              64
lifecycle records / hello         128
requests / client / minute        120
POSTs / client / minute           30
local export registry entries     4096 per object class
```

Phase 1 JSON depth/string/array/object limits remain in force.

The binary MUST bind loopback by default. A non-loopback bind requires `--allow-public-listen`, `--tls-terminated-upstream`, and `--trusted-proxy IP`. When the direct socket peer equals that trusted proxy, `x-qsol-client-ip` is required and may be used only for per-client rate limiting and audit metadata. A forwarded client IP from any other socket peer is rejected. It never becomes Federation identity, trust, authority, or admission.

Replay compaction MUST preserve the entire active replay window. Phase 3 retains replay IDs for 4200 seconds, derived from the 3600-second signed-message lifetime plus both 300-second skew margins. Once the append log reaches the compaction threshold, expired records may be pruned and the retained set must be atomically rewritten and fsynced. Do not solve replay exhaustion by dropping still-active IDs.

Replay and audit paths MUST resolve to distinct files. The production audit logger must not retain an unbounded in-memory copy; any in-memory audit mirror is test-only.

Public exposure follows `TLS_PROFILE.md`; do not describe this as native TLS or production networking.

Audit logging must remain metadata-only. Do not intentionally log request bodies, arbitrary headers, bearer tokens, private seeds, signatures, or payload contents.

### Claim discipline

`claims/phase0.json` and `claims/phase2.json` are immutable historical baselines. `claims/phase3.json` is the canonical **current** release-claim manifest.

Phase 3 may now claim:

- canonical wire contract;
- cryptographic identity;
- signed-envelope verification;
- key lifecycle;
- durable replay protection;
- bounded reference HTTP service;
- opt-in network listener;
- bounded API limits;
- TLS deployment profile;
- secret-safe audit log;
- API fuzz/adversarial suite.

The following remain hard-false current claims:

- production networking;
- remote execution;
- interoperable federation deployment.

Do not describe an opt-in reference listener as a production-safe network service. Contradictory public or machine-readable statements are forbidden.

Never claim consensus truth, global state, a functioning Federation Assembly, or completed NEXUS/ORACLE/ARK interoperability without the corresponding implementation and tests.

### Change discipline

Security-critical invariant changes require explicit rationale, compatibility analysis, updated machine/human contracts, regression tests, and migration or rejection behavior.

Wire-contract changes require synchronized `wire/phase1.json`, `CANONICAL_JSON.md`, Rust/Python implementations, golden/adversarial vectors, and `tools/validate_phase1_gate.py` updates.

Crypto-contract changes require synchronized `crypto/phase2.json`, `CRYPTOGRAPHY.md`, schemas/vectors, Rust lifecycle/replay tests, and `tools/validate_phase2_gate.py` updates.

API-contract changes require synchronized `api/phase3.json`, `API.md`, `TLS_PROFILE.md`, strict route/body/rate-limit tests, lifecycle/recipient/replay tests, pseudo-admin/SSRF adversarial tests, audit-field review, fuzz-smoke review, and `tools/validate_phase3_gate.py` updates.

Release-claim changes require updating the canonical successor claim manifest, Rust claim mirror, public/machine status surfaces, roadmap evidence, and claim-gate validation.

Do not silently weaken an invariant, parser rejection, key-lifecycle rule, replay rule, HTTP limit, SSRF boundary, listener posture, trusted proxy rule, audit boundary, or release claim to make integration easier.

### Tests

Before declaring a change ready:

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
python3 tools/validate_phase2_gate.py
python3 tools/validate_phase3_gate.py
```

If implementation and machine contracts disagree, fail closed and surface the disagreement.

### Architecture rule

`QSOL-NEXUS` is a Council service and possible federation member. It is not the owner of QSOL-FED. QSOL-FED must remain usable by independent third-party nodes that do not run NEXUS.

### Security comedy clause

The jokes in human documentation are non-normative. The invariants, claim gates, canonical bytes, key roles, replay decisions, and HTTP boundaries are not. A peer cannot gain root authority by being persuasive, wearing a ceremonial sash, presenting a valid signature, setting `trusted=true`, or asking the server to just quickly fetch `http://169.254.169.254/` as a favour.
