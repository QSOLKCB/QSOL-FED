# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED is being designed to let independent systems exchange attributable, provenance-preserving objects without surrendering local sovereignty. Cryptographic identity and production networking remain later roadmap phases.

It is intentionally **not** a global brain, blockchain, truth oracle, remote administration plane, or central government.

## Phase 0 claim gate

<!-- PHASE0_CLAIM_BOUNDARY:BEGIN -->
The current repository is deliberately constrained to the bootstrap claim boundary:

- constitutional model: **established and tested**;
- machine contracts: **established and tested**;
- fail-closed admission skeleton: **established and tested**;
- tested constitutional core: **established and tested**;
- production networking: **not established**;
- cryptographic identity: **not established**;
- remote execution: **not established and forbidden by the current protocol posture**;
- interoperable federation: **not established**.
<!-- PHASE0_CLAIM_BOUNDARY:END -->

These claims are machine-enforced by [`claims/phase0.json`](claims/phase0.json), [`src/claims.rs`](src/claims.rs), tests, and [`tools/validate_phase0_gate.py`](tools/validate_phase0_gate.py). `claims/phase0.json` is canonical for the Phase 0 release-claim boundary; disagreement with a mirror or status surface fails closed. They are not runtime configuration.

## Phase 1 canonical wire contract

Phase 1 is complete and adds the first frozen wire protocol, **`qsol-fed/1`**, without changing the Phase 0 production-capability boundary.

The canonical profile [`qsol-fed-canonical-json/1`](CANONICAL_JSON.md) freezes:

- UTF-8 with no BOM;
- Unicode NFC normalization for keys and string values;
- rejection of raw duplicate keys and post-NFC key collisions;
- safe integers only (`±9007199254740991`), with floating-point/decimal numbers excluded from v1;
- deterministic string escaping and normalized key ordering;
- fixed input/depth/string/collection limits;
- `sha256:` object identity over canonical bytes;
- domain-separated message IDs excluding `message_id` and `signature` from the preimage.

The exact Phase 1 schemas are:

- [`schemas/federation-envelope-v1.schema.json`](schemas/federation-envelope-v1.schema.json);
- [`schemas/provenance-v1.schema.json`](schemas/provenance-v1.schema.json);
- [`schemas/protocol-error-v1.schema.json`](schemas/protocol-error-v1.schema.json).

`signature` is required to be JSON `null`. Phase 1 does not invent cryptography ahead of Phase 2.

### Two-implementation gate

Phase 1 has independent implementations:

```text
Rust    src/canonical.rs
Python  tools/qsol_canonical.py
```

Both consume [`fixtures/phase1/golden-vectors.json`](fixtures/phase1/golden-vectors.json). The shared adversarial corpus rejects duplicate/NFC-colliding keys, decimal and exponent numbers, NaN/Infinity extensions, out-of-range integers, BOM input, lone surrogates, JSON extensions, malformed documents, and generated oversized cases.

The gate is enforced by Rust tests plus [`tools/validate_phase1_gate.py`](tools/validate_phase1_gate.py). Signatures cannot be layered on until both implementations reproduce byte-identical canonical bytes and hashes.

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

The frozen wire contract is deterministic data machinery, not a network-safe node claim.

## Planned reference API

```text
GET  /fed/v1/node
GET  /fed/v1/capabilities
POST /fed/v1/peer/hello
POST /fed/v1/envelopes
GET  /fed/v1/objects/{sha256}
GET  /fed/v1/provenance/{sha256}
```

These remain planned transport surfaces. There is no current `remote-exec` endpoint.

## Build and test

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
```

## Documentation map

- [`README4AI.md`](README4AI.md) — strict machine-readable repository map.
- [`AGENTS.md`](AGENTS.md) — mandatory instructions for AI/agent contributors.
- [`CHARTER.md`](CHARTER.md) — Federation constitution.
- [`PRIME_DIRECTIVE.md`](PRIME_DIRECTIVE.md) — non-interference rules.
- [`PROTOCOL.md`](PROTOCOL.md) — frozen Phase 1 wire semantics.
- [`CANONICAL_JSON.md`](CANONICAL_JSON.md) — exact canonical-byte profile.
- [`ROADMAP.md`](ROADMAP.md) — staged implementation plan.
- [`claims/phase0.json`](claims/phase0.json) — production-capability claim firewall.
- [`wire/phase1.json`](wire/phase1.json) — machine-readable Phase 1 wire contract.

## Status

Constitutional bootstrap lineage `qsol-fed/0`; frozen wire protocol **`qsol-fed/1`**. Phase 0 and Phase 1 gates are enforced. Deterministic wire bytes and hashes are established and tested. Production networking, cryptographic identity, remote execution, deployed interoperable federation, durable peering, and production adapters remain intentionally unclaimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project inspired by the general idea of federated cooperation; it is not affiliated with or endorsed by any entertainment franchise or rights holder.
