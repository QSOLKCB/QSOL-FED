# Protocol

**Constitutional bootstrap lineage:** `qsol-fed/0`  
**Frozen wire protocol:** `qsol-fed/1`  
**Cryptographic profile:** `qsol-fed-phase2-crypto-contract`

Phase 1 freezes deterministic wire semantics. Phase 2 adds cryptographic attribution around those bytes without changing the exact Phase 1 envelope or any sovereignty/non-interference invariant.

## 1. Canonical wire representation

Every Phase 1 wire object uses [`qsol-fed-canonical-json/1`](CANONICAL_JSON.md).

The profile is UTF-8, NFC-normalized, whitespace-free canonical JSON with sorted normalized keys, duplicate-key rejection, safe integers only, deterministic escaping, and fixed resource limits. Floating-point/decimal JSON numbers, NaN/Infinity extensions, duplicate keys, NFC key collisions, unsupported JSON extensions, BOM input, and oversized inputs are rejected.

Object identity is:

```text
sha256:<lowercase SHA-256 of canonical UTF-8 bytes>
```

## 2. Exact Federation envelope v1

The exact inner envelope schema remains frozen at `schemas/federation-envelope-v1.schema.json` and Rust type `FederationEnvelope`.

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

`protocol` MUST be `qsol-fed/1`. `authority_claim` MUST be `none`. The embedded `signature` field remains JSON `null` even after Phase 2.

Phase 2 does **not** mutate this schema. It wraps the exact Phase 1 envelope in `qsol-fed-signed-envelope/1`.

## 3. Message ID derivation

For envelope `E`, remove exactly the top-level `message_id` and `signature` fields to form `P(E)`.

```text
preimage = UTF8("qsol-fed-message-id/1") || 0x00 || canonical_bytes(P(E))
message_id = "sha256:" + lowercase_hex(SHA-256(preimage))
```

Detached Phase 2 signing does not change `message_id`.

## 4. Phase 2 cryptographic node identifiers

Phase 2 freezes one identity profile: Ed25519 under exact algorithm identifier `ed25519`.

For root public key bytes `R`:

```text
node_id = "fed:qsol:" + lowercase_hex(
    SHA-256(UTF8("qsol-fed-node-id/1") || 0x00 || R)
)
```

For any Ed25519 public key bytes `K`:

```text
key_id = "ed25519:" + lowercase_hex(
    SHA-256(UTF8("qsol-fed-key-id/1") || 0x00 || K)
)
```

Phase 2 node IDs therefore use exact `fed:qsol:<64 lowercase hex>` form. The root key anchors the node ID. Root-key compromise is terminal for that identity; a new root means a new node ID.

## 5. Node identity document

`qsol-fed-node-identity/1` binds:

- node ID;
- root key ID/public key;
- initial operational key ID/public key;
- exact algorithm `ed25519`;
- creation timestamp;
- root signature.

The root signature covers the canonical document projection excluding `root_signature`, under domain:

```text
UTF8("qsol-fed-node-identity/1") || 0x00
```

The verifier recomputes node and key IDs before accepting the document.

## 6. Detached signed envelope

`qsol-fed-signed-envelope/1` contains:

```text
schema
algorithm
node_id
key_id
envelope
signature
```

The operational key signs:

```text
UTF8("qsol-fed-envelope-signature/1") || 0x00 || canonical_phase1_envelope_bytes
```

The wrapper itself MUST be canonical JSON. Only exact `ed25519` is accepted. Root identity keys are not operational envelope-signing keys.

## 7. Signature validity, trust, and authority

The API keeps these dimensions separate:

```text
SignatureValidity
TrustDisposition
AuthorityDisposition
```

Cryptographic verification returns `AuthorityDisposition::None`.

A valid signature authenticates bytes to an admitted operational key. It does not establish truth, evidence, trust, governance rights, capability permission, or local admission.

## 8. Operational-key lifecycle

### Normal transition

`qsol-fed-key-rotation/1` in `transition` mode requires three signatures over the same canonical rotation payload:

1. root identity key;
2. outgoing operational key;
3. incoming operational key as proof of possession.

The replacement activates at `not_before`. The outgoing key may remain valid only through `overlap_until`, with overlap bounded to 86,400 seconds.

### Revocation and compromise

`qsol-fed-key-status/1` is root-signed and can mark an operational key `revoked` or `compromised`.

The status mechanism cannot revoke or replace the root identity key.

### Recovery transition

Recovery mode is available only after the current operational key is revoked or compromised. It requires:

- root signature;
- incoming-key proof-of-possession signature;
- `previous_signature = null`;
- zero overlap with the revoked/compromised key.

A normal healthy transition cannot use recovery semantics.

## 9. Clock policy

Signed envelopes require `expires_at`.

```text
maximum clock skew               300 seconds
maximum signed-message lifetime 3600 seconds
maximum key overlap            86400 seconds
```

Timestamps retain the Phase 1 UTC second-resolution syntax and must also parse as real calendar timestamps.

Signed verification rejects absent expiry, non-increasing expiry, excessive lifetime, excessive future skew, or messages expired beyond the allowed skew.

## 10. Durable replay protection

Replay identity is the exact Phase 1 `message_id`.

`DurableReplayStore` records accepted IDs in an append-only local file. A fresh record is written, flushed, and fsynced before `FreshRecorded` is returned.

On restart, malformed IDs/timestamps, invalid UTF-8, duplicate persisted IDs, partial trailing records, or oversized logs fail closed.

The Phase 2 replay store is explicitly single-process. Multi-process coordination belongs to Phase 3.

## 11. Message classes

The exact Phase 1 vocabulary remains:

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

Unknown classes fail closed. Signing does not expand the message vocabulary.

## 12. Capability identifiers

Capabilities remain:

```text
^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*/[1-9][0-9]*$
```

Advertisement remains distinct from permission or authority.

## 13. Provenance and protocol errors

The exact Phase 1 provenance and error contracts remain:

- `qsol-fed-provenance/1`;
- `qsol-fed-error/1`.

Import does not create authority. Signature validity does not promote evidence.

## 14. Version and algorithm handling

Wire protocol handling remains exact:

```text
qsol-fed/0 -> reject as unsupported wire major
qsol-fed/1 -> supported
qsol-fed/2 -> reject as unsupported wire major
unknown     -> reject
```

Crypto handling is likewise exact:

```text
ed25519    -> supported Phase 2 algorithm
Ed25519    -> reject
ed25519ph  -> reject
ed25519ctx -> reject
other      -> reject
```

There is no silent protocol, algorithm, domain-separator, or key-ID downgrade.

## 15. Conformance vectors

Phase 1 canonical vectors remain in `fixtures/phase1/`.

Phase 2 signature vectors live in `fixtures/phase2/signature-vectors.json` and include:

- RFC 8032 baseline signature;
- node/key derivation;
- detached signed envelope;
- three-signature key transition.

Rust tests verify the cryptographic vectors and lifecycle behavior. `tools/validate_phase2_gate.py` enforces the machine-readable Phase 2 contract, schema set, claim boundary, CI wiring, and required negative-security markers.

## 16. Phase 2 gate

A valid signature must never bypass local admission.

The gate explicitly tests a correctly signed envelope and then attempts a forbidden local governance effect. The signature remains valid while ordinary `admit_effect` still returns a constitutional rejection.

The same separation remains true if a signature is locally trusted: trust does not create authority.

## 17. Current claim boundary

Phase 2 establishes:

- deterministic canonical bytes and hashes;
- cryptographic node identity;
- detached Ed25519 signed-envelope verification;
- operational-key rotation/recovery/revocation/compromise handling;
- bounded clock/expiry policy;
- durable single-process replay protection.

Phase 2 does **not** establish:

- production networking;
- TLS deployment;
- live peering;
- remote execution;
- deployed interoperable federation;
- transitive trust;
- truth or evidence authority from signatures.
