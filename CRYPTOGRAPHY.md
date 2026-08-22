# QSOL-FED Cryptographic Identity / Phase 2

**Crypto contract:** `crypto/phase2.json`  
**Signing suite:** Ed25519, RFC 8032  
**Wire protocol carried:** `qsol-fed/1`

Phase 2 authenticates origin and key continuity. It does **not** create truth, trust, authority, evidence status, governance rights, or production networking.

## 1. Key roles

Each node has two Ed25519 roles:

- **root identity key** — offline identity anchor and lifecycle authority;
- **operational signing key** — signs Federation envelopes and normal key transitions.

The root key MUST NOT sign Federation envelopes. A key accepted as a root is intentionally absent from the operational-key registry used by envelope verification.

Private keys are 32-byte Ed25519 seeds held only in local secret state. Federation objects contain only public keys, key IDs, signatures, and lifecycle records.

## 2. Encodings

- public key: 32 raw bytes encoded as exactly 64 lowercase hexadecimal characters;
- signature: 64 raw bytes encoded as exactly 128 lowercase hexadecimal characters;
- key ID: `ed25519:` followed by 64 lowercase hexadecimal characters;
- node ID: `fed:qsol:` followed by 64 lowercase hexadecimal characters.

No alternate base64, uppercase hex, Ed25519ph, Ed25519ctx, or algorithm alias is accepted by this profile.

## 3. Node ID derivation

For root public key bytes `R`:

```text
node_id = "fed:qsol:" + lowercase_hex(
    SHA-256(UTF8("qsol-fed-node-id/1") || 0x00 || R)
)
```

The node ID is therefore stable across operational-key rotation. Root-key rotation is deliberately not defined in this profile.

**Root compromise is terminal for the node identity.** A new root key means a new node ID. The protocol does not pretend a compromised identity anchor can certify its own trustworthy replacement.

## 4. Key ID derivation

For Ed25519 public key bytes `K`:

```text
key_id = "ed25519:" + lowercase_hex(
    SHA-256(UTF8("qsol-fed-key-id/1") || 0x00 || K)
)
```

A key ID is an identifier, not an authority label.

## 5. Identity document

`qsol-fed-node-identity/1` binds:

- node ID;
- root public key and key ID;
- initial operational public key and key ID;
- creation timestamp;
- exact algorithm identifier `ed25519`.

The root key signs the canonical document projection excluding `root_signature` using:

```text
UTF8("qsol-fed-node-identity/1") || 0x00 || canonical_payload
```

The verifier independently recomputes node ID and both key IDs before accepting the document.

## 6. Signed envelope wrapper

Phase 1's exact envelope is not modified. Its embedded `signature` field remains JSON `null`.

Phase 2 adds `qsol-fed-signed-envelope/1` around that frozen object:

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

The Phase 1 `message_id` therefore remains unchanged by signing.

A signed wrapper must itself be canonical JSON on the wire.

## 7. Validity, trust, and authority are separate

The Rust API exposes separate dimensions:

```text
SignatureValidity
TrustDisposition
AuthorityDisposition
```

A valid signature means only that an admitted operational public key verified the exact domain-separated bytes under Ed25519.

It does not imply:

- the claim is true;
- the peer is trusted;
- the payload is evidence;
- the requested effect is allowed;
- the sender receives a Council vote;
- the Prime Directive may be bypassed.

`AuthorityDisposition` produced by cryptographic verification is always `None`.

## 8. Normal key rotation

`qsol-fed-key-rotation/1` normal transition requires three signatures over one canonical rotation payload:

1. root signature;
2. outgoing operational-key signature;
3. incoming operational-key proof-of-possession signature.

The new key activates at `not_before`. The outgoing key remains valid only until `overlap_until`.

The overlap window is bounded to 86,400 seconds. A transition cannot nominate an unknown replacement key without proving possession of that key.

## 9. Revocation, compromise, and recovery

`qsol-fed-key-status/1` is root-signed and can mark an operational key:

- `revoked`;
- `compromised`.

The root key itself cannot be revoked by this mechanism.

After the current operational key is revoked or compromised, a recovery rotation may omit the outgoing key signature. Recovery requires:

- valid root signature;
- valid incoming-key proof of possession;
- exact `recovery` mode;
- `previous_signature = null`;
- no overlap with the compromised key.

Normal transitions cannot use this shortcut.

## 10. Clock and expiry policy

Signed envelopes require `expires_at`.

```text
maximum clock skew:               300 seconds
maximum signed-message lifetime: 3600 seconds
maximum rotation overlap:       86400 seconds
```

The timestamp syntax remains Phase 1 UTC second-resolution `YYYY-MM-DDTHH:MM:SSZ` and is additionally validated as a real calendar timestamp.

A signed message is rejected when:

- expiry is absent;
- expiry is not after issue time;
- lifetime exceeds 3600 seconds;
- issue time is more than 300 seconds in the future;
- expiry is more than 300 seconds in the past.

## 11. Durable replay protection

`DurableReplayStore` records accepted `message_id` values in an append-only local log:

```text
<message_id>\t<seen_at>\n
```

A fresh record is flushed and fsynced before `FreshRecorded` is returned. On restart the complete log is reloaded.

Malformed lines, duplicate records already present in the log, invalid IDs/timestamps, partial trailing writes, invalid UTF-8, or oversized replay logs fail closed.

The Phase 2 implementation is explicitly **single-process**. It does not claim multi-process locking or production server concurrency; that belongs to the Phase 3 network service.

## 12. Downgrade and algorithm confusion

The implementation rejects:

- any algorithm identifier other than exact `ed25519`;
- malformed public keys, signatures, node IDs, and key IDs;
- wrong domain separators;
- key-ID/public-key mismatch;
- unsupported crypto schema versions;
- unsupported wire protocol majors;
- root-key attempts to sign envelopes;
- signatures from revoked, compromised, not-yet-valid, or retired operational keys.

## 13. Phase 2 gate

The gate is not merely "a signature verified."

A correctly signed envelope is authenticated first and then remains subject to ordinary constitutional admission. Tests explicitly show:

```text
signature_validity = valid
trust              = unknown or locally_trusted
authority          = none
Prime Directive    = still enforced
```

A correctly signed request corresponding to a forbidden governance effect remains rejected by `admit_effect`.

## 14. Explicit non-claims

Phase 2 does not establish:

- production networking;
- TLS deployment;
- live peering;
- distributed trust;
- transitive trust;
- remote execution;
- interoperable federation deployment;
- consciousness, personhood, truth, or legal identity.
