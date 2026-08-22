# Protocol

**Protocol family:** `qsol-fed/0`

This document defines the bootstrap semantics that later wire-compatible implementations must preserve.

## 1. Design goals

QSOL-FED aims for:

- sovereign nodes;
- transport-independent canonical messages;
- explicit provenance;
- cryptographic identity without conflating identity with authority;
- capability negotiation;
- fail-closed versioning;
- bounded message classes;
- independent local evidence and governance;
- support for disagreement and partition;
- offline-verifiable exchange where practical.

## 2. Node identity

A future cryptographic profile will bind a stable Federation node identifier to one or more keys. The conceptual identifier form is:

```text
fed:qsol:<node-id>
```

PR #1 does not freeze a key algorithm or identity derivation scheme. Those choices require cryptographic review and test vectors.

## 3. Envelope

The conceptual v1 envelope is represented by `FederationEnvelope` in `src/envelope.rs` and by `schemas/federation-envelope.schema.json`.

Core fields:

- `protocol` — exact protocol identifier;
- `message_id` — content identity once canonicalization is frozen;
- `sender` — attributed sender identifier;
- `recipient` — intended recipient or explicit broadcast scope;
- `message_class` — bounded semantic class;
- `payload_ref` — content-addressed payload reference;
- `provenance_ref` — optional provenance object reference;
- `issued_at` — sender timestamp;
- `expires_at` — optional expiry;
- `authority_claim` — MUST be `none` in the bootstrap contract;
- `signature` — future signature object/string representation.

A valid envelope is not automatically admissible. Parsing, authentication and admission are separate steps.

## 4. Planned message classes

The initial protocol vocabulary is intentionally narrow:

```text
hello
capabilities
evidence.offer
evidence.request
hypothesis
challenge
response
council.report
minority.report
experiment.receipt
citation
publication
```

Unknown classes must not be interpreted as authority-bearing actions. Implementations should reject or quarantine them according to negotiated extension rules.

## 5. Capability negotiation

A node advertises capabilities. A receiver separately decides whether a capability is locally allowed.

```text
advertised capability != permission to invoke
```

Capabilities should be versioned independently where useful, for example:

```text
evidence.exchange/1
council.report/1
experiment.receipt/1
```

The v1 contract does not include arbitrary remote execution.

## 6. Provenance

Foreign data must remain attributable to its source. A receiving node may create a new local descendant, but it must not silently rewrite the foreign object to appear locally originated.

A provenance chain should distinguish:

- source node;
- source object identity;
- transport receipt;
- local admission event;
- locally derived descendants.

## 7. Content addressing

Payload and provenance references are planned as SHA-256 content references:

```text
sha256:<64 lowercase hex characters>
```

Exact canonical JSON rules, duplicate-key handling, number normalization, Unicode normalization and signature bytes are protocol-freezing tasks on the roadmap. Implementations must not independently invent incompatible canonicalization while claiming conformance.

## 8. Replay protection

Production nodes will require bounded replay protection using message identity, expiry and durable/local replay state as appropriate.

A replayed valid signature is still a replayed message.

## 9. Version negotiation

- unsupported major protocol versions: reject;
- additive known-compatible capability versions: negotiate explicitly;
- unknown authority semantics: reject;
- no silent downgrade that weakens constitutional invariants.

## 10. Error semantics

Errors should be structured and should not leak secrets. Planned broad classes:

```text
malformed
unsupported_protocol
unsupported_capability
authentication_failed
expired
replay
prime_directive_rejected
quarantined
local_policy_rejected
not_found
rate_limited
```

A rejection reason may identify the violated invariant by stable ID.

## 11. Transport requirements

A conforming transport must preserve message bytes/semantics and must not grant additional authority. HTTPS is expected for the first network reference implementation, but transport encryption does not replace envelope-level provenance, identity and admission.

## 12. Non-goals

QSOL-FED is not designed to provide:

- one global database;
- global consensus truth;
- distributed superuser access;
- remote shell semantics;
- automatic trust transitivity;
- proof that a model is conscious, correct or benevolent.
