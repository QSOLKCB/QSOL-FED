# QSOL-FED Federation State / Phase 4

**Machine contract:** `state/phase4.json`  
**Current claim manifest:** `claims/phase4.json`

Phase 4 adds durable Federation state. It does not turn persistence into truth, trust, evidence, governance authority, or execution permission.

## Storage

`FederationObjectStore` uses exact Phase 1 canonical JSON bytes and `sha256:` identities. Payload and provenance bytes are content-addressed. Foreign metadata lives in an explicit `foreign/` or `quarantine/` namespace.

Imported material always lands in quarantine. Merely possessing an object does not admit it, trust its origin, or create local authority.

Local descendants are new local objects. Their generated `qsol-fed-provenance/1` record uses `relation = derived` and names the foreign object as a parent. The foreign parent is never relabelled as local.

## Peers and trust

`PeerRegistry` and `TrustRegistry` are separate durable stores.

Peer lifecycle states are:

```text
unknown
introduced
admitted
quarantined
revoked
disconnected
```

`unknown` is a query result for an absent durable record. Admission does not imply trust. Trust does not imply capability permission. Revocation is terminal for that peer record unless a separately designed future migration says otherwise.

Identity/lifecycle updates are monotonic across restart. Lower sequence numbers reject, and divergent content at the same lifecycle sequence rejects.

## Capability advertisements

`qsol-fed-capability-advertisement/1` is versioned, sequenced, expiring, and authenticated using the already-reviewed Phase 2 signed-envelope machinery. Advertisement is not authorization.

`LocalCapabilityPolicy` is separate and defaults to `deny`. A capability is locally usable only when the peer has an active authenticated advertisement **and** local policy explicitly says `allow`.

## Partitions and rejoin

Disconnect records a content snapshot. Rejoin compares the remote snapshot with that stored partition point.

- same snapshot: a clean rejoin may be explicitly confirmed;
- changed snapshot: `explicit_reconciliation_required`;
- changed snapshot without explicit reconciliation: reject.

There is no automatic last-writer-wins, silent merge, or trust-the-peer reconciliation path.

## Portable bundle

`qsol-fed-bundle/1` carries exact canonical foreign object, provenance, identity, lifecycle, and capability-advertisement bytes as lowercase hexadecimal strings.

The offline verifier:

```bash
cargo run --bin qsol-fed-bundle -- verify bundle.json
```

requires no network access. It checks canonical bytes, hashes, identity/lifecycle cryptography, capability proof bindings, provenance identity, limits, and the bundle's `authority = none` boundary.

Bundle import always:

```text
peer state       -> quarantined
foreign objects  -> quarantine namespace
local authority  -> none
local trust       -> unchanged
```

Trust state and local capability policy are deliberately absent from the bundle schema.

## Phase 4 gate

Export/import round-trips must preserve the exact foreign identity, lifecycle, object, capability-advertisement, and provenance bytes represented in the bundle. Import must create neither local authority nor trust.

The round-trip test exports from one store, verifies offline, imports into fresh stores, re-exports, and compares the encoded foreign identity/provenance material byte-for-byte.

## Non-claims

Phase 4 still does not claim production networking, remote execution, automatic global reconciliation, transitive trust, or deployed multi-implementation interoperability.
