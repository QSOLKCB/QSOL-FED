# Protocol

**Constitutional bootstrap lineage:** `qsol-fed/0`  
**Frozen wire protocol:** `qsol-fed/1`

Phase 1 freezes deterministic wire semantics while preserving every Phase 0 sovereignty and non-interference invariant. It does not add production networking or cryptographic identity.

## 1. Canonical wire representation

Every Phase 1 wire object uses [`qsol-fed-canonical-json/1`](CANONICAL_JSON.md).

The profile is UTF-8, NFC-normalized, whitespace-free canonical JSON with sorted normalized keys, duplicate-key rejection, safe integers only, deterministic escaping, and fixed resource limits. Floating-point/decimal JSON numbers, NaN/Infinity extensions, duplicate keys, NFC key collisions, unsupported JSON extensions, BOM input, and oversized inputs are rejected.

Object identity is:

```text
sha256:<lowercase SHA-256 of canonical UTF-8 bytes>
```

## 2. Exact Federation envelope v1

The exact schema is frozen at:

- `schemas/federation-envelope.schema.json`;
- `schemas/federation-envelope-v1.schema.json`;
- Rust type `FederationEnvelope` in `src/envelope.rs`.

Required fields are:

```text
protocol
message_id
sender
recipient
message_class
payload_ref
provenance_ref
issued_at
expires_at
authority_claim
signature
```

`protocol` MUST be `qsol-fed/1`. `authority_claim` MUST be `none`. `signature` MUST be JSON `null` in Phase 1. A non-null signature is rejected until Phase 2 defines a reviewed cryptographic profile.

## 3. Message ID derivation

For envelope `E`, remove exactly the top-level `message_id` and `signature` fields to form `P(E)`.

```text
preimage = UTF8("qsol-fed-message-id/1") || 0x00 || canonical_bytes(P(E))
message_id = "sha256:" + lowercase_hex(SHA-256(preimage))
```

The domain separator prevents confusion with ordinary object identity. Excluding `signature` prevents Phase 2 signing from changing message identity.

## 4. Node identifiers

Phase 1 envelope attribution uses the bounded syntax:

```text
^fed:qsol:[a-z0-9][a-z0-9._-]{0,127}$
```

This is an attributed protocol identifier only. It is **not yet cryptographically bound to a key**.

## 5. Message classes

The exact Phase 1 vocabulary is:

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

Unknown classes fail closed.

## 6. Capability identifiers

Capabilities use:

```text
^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*/[1-9][0-9]*$
```

Examples:

```text
evidence.exchange/1
council.report/1
experiment.receipt/2
```

Advertisement remains distinct from permission or authority.

## 7. Provenance

The exact provenance object schema is `qsol-fed-provenance/1` in `schemas/provenance-v1.schema.json`.

It binds:

- source node;
- source object identity;
- relation (`observed`, `derived`, `quoted`, `transported`);
- zero or more parent object references;
- creation timestamp.

Import still does not create local authority.

## 8. Protocol errors

The exact structured error envelope is `qsol-fed-error/1` in `schemas/protocol-error-v1.schema.json`.

Stable error codes include malformed input, unsupported protocol/capability, authentication failure, expiry, replay, Prime Directive rejection, quarantine, local policy rejection, not-found, and rate limiting. Error messages are bounded and must not intentionally contain secrets.

## 9. Version handling

Phase 1 accepts exactly wire major `qsol-fed/1`.

```text
qsol-fed/0 -> reject as unsupported wire major
qsol-fed/1 -> supported
qsol-fed/2 -> reject as unsupported wire major
unknown     -> reject
```

There is no silent downgrade.

## 10. Language-neutral conformance

Golden vectors live in `fixtures/phase1/golden-vectors.json`. The malformed, ambiguous, and oversized corpus is defined in `fixtures/phase1/adversarial.json`.

Two independent implementations must agree:

- Rust: `src/canonical.rs`;
- Python: `tools/qsol_canonical.py`.

`cargo test --all-targets` verifies the Rust implementation. `python3 tools/validate_phase1_gate.py` independently verifies the Python implementation and the machine contract.

## 11. Phase 1 claim boundary

Phase 1 establishes deterministic canonical bytes, hashes, message IDs, exact schemas, and conformance fixtures. It does **not** establish:

- production networking;
- cryptographic node identity;
- signatures;
- replay-safe live peering;
- remote execution;
- deployed interoperable federation.

Those claims remain gated by later phases.
