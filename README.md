# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED lets independent systems exchange attributable, provenance-preserving objects without surrendering local sovereignty. Phase 3 now adds a bounded, opt-in Rust reference HTTP service around the frozen Phase 1 wire and Phase 2 cryptographic boundaries.

It is intentionally **not** a global brain, blockchain, truth oracle, remote administration plane, or central government.

## Historical Phase 0 claim gate

<!-- PHASE0_CLAIM_BOUNDARY:BEGIN -->
At Phase 0 the repository was deliberately constrained to the bootstrap claim boundary:

- constitutional model: **established and tested**;
- machine contracts: **established and tested**;
- fail-closed admission skeleton: **established and tested**;
- tested constitutional core: **established and tested**;
- production networking: **not established**;
- cryptographic identity: **not established**;
- remote execution: **not established and forbidden by the current protocol posture**;
- interoperable federation: **not established**.
<!-- PHASE0_CLAIM_BOUNDARY:END -->

[`claims/phase0.json`](claims/phase0.json) remains the immutable historical Phase 0 release-claim baseline. Later phases promote capabilities with successor manifests instead of rewriting that record.

## Historical Phase 2 claim gate

[`claims/phase2.json`](claims/phase2.json) preserves the point where QSOL-FED first established local Ed25519 identity, signed-envelope verification, operational-key lifecycle, bounded clock policy, and durable single-process replay protection while production networking remained false.

## Current Phase 3 claim gate

<!-- CURRENT_CLAIM_BOUNDARY:BEGIN -->
The current repository may claim:

- constitutional model: **established and tested**;
- machine contracts: **established and tested**;
- fail-closed admission skeleton: **established and tested**;
- tested constitutional core: **established and tested**;
- canonical wire contract: **established and tested**;
- cryptographic identity: **established and tested**;
- signed envelope verification: **established and tested**;
- key lifecycle: **established and tested**;
- durable replay protection: **established and tested**;
- reference HTTP service: **established and tested**;
- opt-in network listener: **established and tested**;
- bounded API limits: **established and tested**;
- TLS deployment profile: **established and tested**;
- secret-safe audit log: **established and tested**;
- API fuzz/adversarial suite: **established and tested**;
- production networking: **not established**;
- remote execution: **not established**;
- interoperable federation: **not established**.
<!-- CURRENT_CLAIM_BOUNDARY:END -->

[`claims/phase3.json`](claims/phase3.json) is canonical for the current release-claim boundary. The distinction is deliberate: **a tested opt-in reference listener is not the same claim as production networking**.

## Phase 1 canonical wire contract

Phase 1 provides the frozen wire protocol **`qsol-fed/1`** and canonical profile [`qsol-fed-canonical-json/1`](CANONICAL_JSON.md): UTF-8, NFC normalization, duplicate-key rejection, safe integers only, deterministic escaping and ordering, bounded depth/string/collection sizes, `sha256:` object identity, and domain-separated message IDs.

The exact Phase 1 envelope remains unchanged. Its embedded `signature` field is still JSON `null`; Phase 2 signatures are detached.

Two independent canonicalizers remain gated in CI:

```text
Rust    src/canonical.rs
Python  tools/qsol_canonical.py
```

## Phase 2 cryptographic node identity

Phase 2 is defined by [`crypto/phase2.json`](crypto/phase2.json) and [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md).

Each node has an offline root identity key and a distinct rotatable Ed25519 operational key. The root derives the stable `fed:qsol:<node-id>` and authorizes lifecycle records, but cannot sign Federation envelopes.

Signed wrappers authenticate exact canonical Phase 1 envelope bytes. `SignatureValidity`, `TrustDisposition`, and `AuthorityDisposition` remain separate, and cryptographic verification always yields `authority = none`.

Normal operational-key rotation requires root, outgoing-key, and incoming proof-of-possession signatures. Root-signed status records support revocation/compromise handling. Root compromise is terminal for the node identity.

Signed messages use the frozen Phase 2 clock limits:

```text
maximum clock skew               300 seconds
maximum signed-message lifetime 3600 seconds
maximum rotation overlap       86400 seconds
```

`DurableReplayStore` is append-only, crash-durable for creation and fresh records, calendar-validates timestamps, fails closed on corruption, and permits at most one live handle per canonical path within a process.

## Phase 3 reference federation API

Phase 3 is defined by [`api/phase3.json`](api/phase3.json), [`API.md`](API.md), and [`TLS_PROFILE.md`](TLS_PROFILE.md).

Implemented routes:

```text
GET  /fed/v1/node
GET  /fed/v1/capabilities
POST /fed/v1/peer/hello
POST /fed/v1/envelopes
GET  /fed/v1/objects/{sha256}
GET  /fed/v1/provenance/{sha256}
```

### Listener posture

The `qsol-fed` binary binds loopback by default:

```text
127.0.0.1:8787
```

A non-loopback bind requires both:

```text
--allow-public-listen
--tls-terminated-upstream
```

Public exposure is therefore explicit and must follow the TLS 1.3 deployment profile. The reference binary does not claim native TLS termination or production networking.

### HTTP admission boundary

POST requests require canonical JSON, exact `application/json`, no compression, no query parameters, and a maximum body of `65536` bytes. Phase 1 depth/string/collection limits remain in force.

Rate limits are fixed at:

```text
120 requests / IP / minute
30 POSTs / IP / minute
```

The `/peer/hello` endpoint verifies a Phase 2 node identity and stores it only as an **introduced, in-memory, non-trusted peer**. Peering still does not create trust or authority.

`/envelopes` performs:

```text
HTTP limits
→ canonical signed wrapper
→ introduced peer lookup
→ Ed25519 verification
→ frozen clock checks
→ durable replay record
→ local-recipient check
→ Prime Directive admission
→ data-only or reject
```

Known message classes are admitted only as data. The HTTP service does not execute payloads.

### Local-only retrieval and SSRF boundary

Object and provenance GET routes serve only explicitly registered local canonical bytes. Missing objects return `404`.

The crate intentionally contains no outbound HTTP client, no fetch URL route, no redirect-following behavior, and no fallback retrieval from peers or cloud metadata services. Fields such as `force`, `trusted`, `override`, `admin`, `fetch_url`, and `redirect` are rejected by closed request schemas.

### Secret-safe audit log

The JSON Lines audit surface records only bounded metadata such as timestamp, request ID, stable route label, status, remote IP, node ID, message ID, and decision. It does not intentionally record request bodies, arbitrary headers, private keys, signatures, or payload contents.

### Fuzz and adversarial coverage

Phase 3 adds a libFuzzer target at:

```text
fuzz/fuzz_targets/wire_and_admission.rs
```

Ordinary CI also runs deterministic mutation smoke coverage over canonicalization, signed-envelope parsing, and the constitutional admission boundary, plus pseudo-admin, SSRF-like, body-limit, compression, query, rate-limit, object-retrieval, identity, replay, and signature tests.

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
LOCAL SOVEREIGNTY > FEDERATION CONVENIENCE
```

The security-critical rules live in `CHARTER.md`, `PRIME_DIRECTIVE.md`, `invariants/fed-v1.json`, `src/invariants.rs`, tests, and CI.

## Relationship to QSOL-NEXUS

QSOL-NEXUS remains the **Council of Minds**. QSOL-FED defines the boundary around systems like NEXUS; a foreign Council report remains foreign data and does not inject votes, evidence labels, or authority into a receiving Council.

## Current security posture

Remote arbitrary execution, remote authority claims, remote evidence promotion, remote governance mutation, remote history rewrite, remote capability installation, and remote citizenship mutation remain forbidden. Foreign state does not become local authority merely by import. Unknown authority-bearing actions reject.

HTTP transport and cryptographic authentication strengthen delivery and attribution. Neither weakens those rules.

## Build and test

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
python3 tools/validate_phase2_gate.py
python3 tools/validate_phase3_gate.py
```

Run the local reference service with a public identity document:

```bash
cargo run --bin qsol-fed -- --identity node-identity.json
```

Non-loopback listening additionally requires the explicit public/TLS flags described above.

## Documentation map

- [`README4AI.md`](README4AI.md) — strict machine-readable repository map.
- [`AGENTS.md`](AGENTS.md) — mandatory instructions for AI/agent contributors.
- [`CHARTER.md`](CHARTER.md) — Federation constitution.
- [`PRIME_DIRECTIVE.md`](PRIME_DIRECTIVE.md) — non-interference rules.
- [`PROTOCOL.md`](PROTOCOL.md) — protocol semantics.
- [`CANONICAL_JSON.md`](CANONICAL_JSON.md) — exact canonical-byte profile.
- [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) — Phase 2 identity/signature/lifecycle profile.
- [`API.md`](API.md) — implemented Phase 3 HTTP surface.
- [`TLS_PROFILE.md`](TLS_PROFILE.md) — Phase 3 public-exposure profile.
- [`ROADMAP.md`](ROADMAP.md) — staged implementation plan.
- [`claims/phase0.json`](claims/phase0.json) — immutable historical Phase 0 claims.
- [`claims/phase2.json`](claims/phase2.json) — immutable Phase 2 claim baseline.
- [`claims/phase3.json`](claims/phase3.json) — canonical current claims.
- [`wire/phase1.json`](wire/phase1.json) — machine-readable Phase 1 wire contract.
- [`crypto/phase2.json`](crypto/phase2.json) — machine-readable Phase 2 crypto contract.
- [`api/phase3.json`](api/phase3.json) — machine-readable Phase 3 API contract.

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol **`qsol-fed/1`**. Phase 0 through Phase 3 gates are enforced. Deterministic wire bytes, cryptographic node identity, detached Ed25519 verification, key lifecycle, durable replay protection, and the bounded opt-in Rust reference HTTP service are established and tested.

**Production networking remains intentionally unclaimed**, along with remote execution, deployed interoperable federation, durable Phase 4 peer registries/object stores, and production adapters.

Licensed under Apache-2.0. QSOL-FED is an original technical project inspired by the general idea of federated cooperation; it is not affiliated with or endorsed by any entertainment franchise or rights holder.
