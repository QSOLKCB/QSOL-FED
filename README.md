# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED is being designed to let independent systems exchange attributable, provenance-preserving objects without surrendering local sovereignty. Phase 2 now establishes local cryptographic node identity and signed-envelope verification, while production networking remains a later phase.

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

## Current Phase 2 claim gate

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
- production networking: **not established**;
- remote execution: **not established**;
- interoperable federation: **not established**.
<!-- CURRENT_CLAIM_BOUNDARY:END -->

[`claims/phase2.json`](claims/phase2.json) is canonical for the current release-claim boundary. Cryptographic identity here means tested local identity, signature, lifecycle, clock, and replay machinery. It does **not** mean a production-safe network node exists.

## Phase 1 canonical wire contract

Phase 1 is complete and provides the first frozen wire protocol, **`qsol-fed/1`**.

The canonical profile [`qsol-fed-canonical-json/1`](CANONICAL_JSON.md) freezes:

- UTF-8 with no BOM;
- Unicode NFC normalization for keys and string values;
- rejection of raw duplicate keys and post-NFC key collisions;
- safe integers only (`±9007199254740991`), with floating-point/decimal numbers excluded from v1;
- deterministic string escaping and normalized key ordering;
- fixed input/depth/string/collection limits;
- `sha256:` object identity over canonical bytes;
- domain-separated message IDs excluding `message_id` and `signature` from the preimage.

The exact Phase 1 envelope remains unchanged in Phase 2. Its embedded `signature` field is still JSON `null`.

### Two-implementation gate

Phase 1 has independent implementations:

```text
Rust    src/canonical.rs
Python  tools/qsol_canonical.py
```

Both consume [`fixtures/phase1/golden-vectors.json`](fixtures/phase1/golden-vectors.json), and CI requires byte-identical canonical output and hashes.

## Phase 2 cryptographic node identity

Phase 2 is defined by [`crypto/phase2.json`](crypto/phase2.json) and [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md).

### Key architecture

Each node has:

```text
offline root identity key
        |
        +--> stable fed:qsol:<node-id>
        +--> identity/lifecycle records
        |
        X    cannot sign Federation envelopes

rotatable operational Ed25519 key
        |
        +--> detached signed-envelope wrapper
```

The node ID is SHA-256 domain-separated from the root public key. Operational key IDs are separately domain-separated. Public keys and signatures use exact lowercase-hex encodings.

The root identity key is intentionally not rotatable under the same node ID. Root compromise is terminal for that identity; a replacement root creates a new node ID.

### Detached signatures preserve Phase 1

Phase 2 adds `qsol-fed-signed-envelope/1` around the exact Phase 1 envelope rather than changing it.

The operational key signs:

```text
UTF8("qsol-fed-envelope-signature/1") || 0x00 || canonical_phase1_envelope_bytes
```

Because signing is detached, the Phase 1 `message_id` does not change.

### Signature validity is not authority

The reference API represents three different dimensions:

```text
SignatureValidity
TrustDisposition
AuthorityDisposition
```

A valid signature proves only that an admitted operational key signed the exact domain-separated bytes. Cryptographic verification returns `AuthorityDisposition::None`.

A valid signature does not create truth, evidence, a Council vote, trust, or permission to execute an effect. Prime Directive admission remains separate.

### Rotation and compromise recovery

Normal operational-key rotation requires:

- root signature;
- outgoing operational-key signature;
- incoming operational-key proof-of-possession signature.

The new key has an explicit activation time, with an overlap window bounded to 24 hours.

Root-signed key-status records can mark an operational key revoked or compromised. Recovery after compromise requires the root plus proof of possession from the replacement key and does not allow the compromised key to remain in overlap.

### Clock and replay

Signed envelopes require expiry and use:

```text
maximum clock skew               300 seconds
maximum signed-message lifetime 3600 seconds
maximum rotation overlap       86400 seconds
```

`DurableReplayStore` records message IDs in an append-only local log and fsyncs a fresh record before reporting it accepted as fresh. Partial, duplicate, malformed, or corrupt replay logs fail closed on restart.

The replay implementation is single-process. Multi-process server coordination remains Phase 3 work.

### Verification vectors

[`fixtures/phase2/signature-vectors.json`](fixtures/phase2/signature-vectors.json) contains:

- RFC 8032 Ed25519 baseline vector;
- QSOL node/key derivation vector;
- signed-envelope vector;
- three-signature operational-key transition vector.

Tests also cover algorithm confusion, signature tampering, key compromise, recovery, clock rejection, and root-key envelope-signing rejection.

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

Cryptographic authentication strengthens attribution. It does not weaken any of those rules.

## Planned reference API

```text
GET  /fed/v1/node
GET  /fed/v1/capabilities
POST /fed/v1/peer/hello
POST /fed/v1/envelopes
GET  /fed/v1/objects/{sha256}
GET  /fed/v1/provenance/{sha256}
```

These remain planned transport surfaces. There is no production network listener and no current `remote-exec` endpoint.

## Build and test

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
python3 tools/validate_phase2_gate.py
```

## Documentation map

- [`README4AI.md`](README4AI.md) — strict machine-readable repository map.
- [`AGENTS.md`](AGENTS.md) — mandatory instructions for AI/agent contributors.
- [`CHARTER.md`](CHARTER.md) — Federation constitution.
- [`PRIME_DIRECTIVE.md`](PRIME_DIRECTIVE.md) — non-interference rules.
- [`PROTOCOL.md`](PROTOCOL.md) — protocol semantics.
- [`CANONICAL_JSON.md`](CANONICAL_JSON.md) — exact canonical-byte profile.
- [`CRYPTOGRAPHY.md`](CRYPTOGRAPHY.md) — Phase 2 identity/signature/lifecycle profile.
- [`ROADMAP.md`](ROADMAP.md) — staged implementation plan.
- [`claims/phase0.json`](claims/phase0.json) — immutable historical Phase 0 claims.
- [`claims/phase2.json`](claims/phase2.json) — canonical current claims.
- [`wire/phase1.json`](wire/phase1.json) — machine-readable Phase 1 wire contract.
- [`crypto/phase2.json`](crypto/phase2.json) — machine-readable Phase 2 crypto contract.

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol **`qsol-fed/1`**. Phase 0, Phase 1, and Phase 2 gates are enforced. Deterministic wire bytes, cryptographic node identity, detached Ed25519 verification, operational-key lifecycle, bounded clock policy, and durable single-process replay protection are established and tested.

Production networking, remote execution, deployed interoperable federation, durable peer registries, and production adapters remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project inspired by the general idea of federated cooperation; it is not affiliated with or endorsed by any entertainment franchise or rights holder.
