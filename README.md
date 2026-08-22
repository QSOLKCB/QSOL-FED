# QSOL-FED

**Sovereign federation protocol for independent computational worlds, AI councils, research systems, humans and deterministic services.**

> **Protocol is the law. API is the port. NEXUS is the Council.**

QSOL-FED defines how independent systems can discover one another, exchange signed and provenance-preserving objects, negotiate bounded capabilities, disagree safely, and leave the federation without surrendering local sovereignty.

It is intentionally **not** a global brain, blockchain, truth oracle, remote administration plane, or central government.

## Core idea

A Federation member may offer information, evidence, hypotheses, challenges, receipts and Council reports to another member. A remote member may **not** silently alter the receiver's governance, evidence state, history, identity, citizenship, capabilities, execution environment or local authority.

The v1 constitutional shorthand is:

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

These are not just slogans. PR #1 places the security-critical rules in:

- [`CHARTER.md`](CHARTER.md) and [`PRIME_DIRECTIVE.md`](PRIME_DIRECTIVE.md), for humans;
- [`invariants/fed-v1.json`](invariants/fed-v1.json), for machines;
- [`src/invariants.rs`](src/invariants.rs), as non-configurable fail-closed code;
- CI and tests, as constitutional tripwires.

Changing a constitutional invariant therefore requires an explicit source change and review. No environment variable, API parameter, peer message, model output or runtime configuration may switch one off.

## Relationship to QSOL-NEXUS

QSOL-NEXUS remains the **Council of Minds**. It deliberates, preserves minority reports and operates a local shared world. QSOL-FED wraps around systems like NEXUS without owning their internal state.

```text
                      QSOL-FED
             charter + protocol + API
                         |
          +--------------+--------------+
          |              |              |
      FED Node A      FED Node B     FED Node C
          |              |              |
     QSOL-NEXUS      QSOL-NEXUS     other system
       Council          Council      or service
```

A foreign NEXUS Council report remains a **foreign council report**. The receiving node does not inherit its votes, consensus, evidence labels or authority.

## Architecture

QSOL-FED is layered deliberately:

1. **Federation Charter** — sovereignty, rights, obligations and amendment rules.
2. **Prime Directive** — enforceable non-interference boundary.
3. **Protocol** — identities, envelopes, provenance, capability negotiation and versioning.
4. **API** — HTTP/JSON reference surface for the protocol.
5. **Reference Node** — Rust implementation with fail-closed admission rules.
6. **Adapters** — NEXUS, ORACLE, ARK and future third-party integrations.

HTTP is a transport, not the protocol. Canonical Federation envelopes are transport-independent so future implementations can use HTTP, WebSocket, QUIC, local IPC or offline bundles without changing federation semantics.

## v1 security posture

PR #1 intentionally starts boring and strict:

- remote arbitrary execution: **forbidden**;
- remote authority claims: **forbidden**;
- remote evidence promotion: **forbidden**;
- remote governance mutation: **forbidden**;
- remote history rewrite: **forbidden**;
- remote capability installation: **forbidden**;
- remote citizenship mutation: **forbidden**;
- secrets in semantic/federated state: **forbidden**;
- foreign state becoming local state merely by import: **forbidden**;
- unknown authority-bearing actions: **reject**;
- accepted foreign semantic material: **data only**, subject to local admission.

Cryptographic signature verification and production networking are roadmap items. This bootstrap does **not** claim that a network-safe production node exists yet.

## Reference API shape

The planned HTTP reference surface begins with discovery and bounded exchange:

```text
GET  /fed/v1/node
GET  /fed/v1/capabilities
POST /fed/v1/peer/hello
POST /fed/v1/envelopes
GET  /fed/v1/objects/{sha256}
GET  /fed/v1/provenance/{sha256}
```

There is deliberately no v1 `remote-exec` endpoint.

See [`API.md`](API.md) and [`PROTOCOL.md`](PROTOCOL.md).

## Build and test

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
```

The reference crate currently implements constitutional admission logic and envelope data structures, not production transport or cryptography.

## Documentation map

- [`README4AI.md`](README4AI.md) — strict machine-readable repository map.
- [`AGENTS.md`](AGENTS.md) — mandatory instructions for AI/agent contributors.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — system boundaries and trust model.
- [`CHARTER.md`](CHARTER.md) — Federation constitution.
- [`PRIME_DIRECTIVE.md`](PRIME_DIRECTIVE.md) — non-interference rules.
- [`PROTOCOL.md`](PROTOCOL.md) — protocol semantics.
- [`API.md`](API.md) — reference API contract.
- [`SECURITY.md`](SECURITY.md) — security posture and reporting.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — attacker model and mitigations.
- [`GOVERNANCE.md`](GOVERNANCE.md) — protocol governance and amendment process.
- [`ROADMAP.md`](ROADMAP.md) — staged implementation plan.

## Status

`qsol-fed/0` bootstrap. The architecture and constitutional boundary are established; interoperable networking, cryptographic identity, durable storage and production adapters are intentionally not yet claimed.

Licensed under Apache-2.0. QSOL-FED is an original technical project inspired by the general idea of federated cooperation; it is not affiliated with or endorsed by any entertainment franchise or rights holder.
