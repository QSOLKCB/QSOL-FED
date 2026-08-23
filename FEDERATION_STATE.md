# QSOL-FED Federation State / Phase 4

**Machine contract:** `state/phase4.json`  
**Current claim manifest:** `claims/phase4.json`

Phase 4 adds durable Federation state. **Persistence is not authority.** Peering, trust, capability advertisement, local permission, object presence, and bundle import remain separate decisions.

## Content identity and foreign attribution

`FederationObjectStore` stores exact Phase 1 canonical JSON payload bytes once by `sha256:` content identity. Foreign attribution is deliberately keyed separately because two independent peers may provide the same bytes with different valid provenance.

```text
objects/<content-hash>.json
provenance/<provenance-hash>.json
foreign/<content-hash>/<attribution-hash>.record.json
quarantine/<content-hash>/<attribution-hash>.record.json
```

An attribution binds `source_node` plus `provenance_id`. Identical content may therefore preserve multiple independent source/provenance observations without duplicating payload bytes or allowing one observation to overwrite another.

Every record returned by a single lookup or namespace listing is revalidated against its path, object identity, attribution identity, namespace, authority boundary, source node, timestamp, and provenance reference. Corruption fails closed.

### Quarantine and namespace moves

New imported foreign material defaults to `quarantine`. Existing local placement is preserved rather than silently demoted or promoted by an archival import.

Namespace moves use a durable transaction marker under `transactions/`. The target attribution records are fsynced before source records are removed. If the process or machine stops between those steps, `FederationObjectStore::open` detects the marker and deterministically completes the move before exposing the store.

## Provenance-preserving local descendants

A local descendant is a new local content identity with `relation = derived` provenance pointing to the foreign parent. The foreign parent is never relabelled local.

A descendant whose content hash equals its foreign parent is rejected because that would create a self-referential provenance cycle.

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

`unknown` is a query result for an absent record. Admission does not imply trust, and trust does not imply capability permission.

The root-signed initial identity is immutable after first observation. Lifecycle advancement is append-only: every previously stored lifecycle record must remain an **exact canonical prefix** of any later sequence. A higher sequence cannot rewrite an earlier key-status or rotation record. This remains true across restart.

## Transactional local trust and capability policy

Trust and local capability policy updates are staged in memory, encoded, durably atomically replaced on disk, and only then installed as live state. If persistence fails, the method returns an error and the running process continues to observe the previous trust/policy decision.

This prevents a failed disk write from briefly granting a capability or changing trust until restart.

## Capability advertisements

`qsol-fed-capability-advertisement/1` is sequenced, expiring, and authenticated through the already-reviewed Phase 2 signed-envelope machinery.

Because the proof is a Phase 2 signed envelope, the advertisement lifetime is also capped at **3,600 seconds**. There is no separate 24-hour claim layered on top of a one-hour cryptographic proof.

Advertisement is not authorization. Effective capability permission requires all three:

```text
peer lifecycle state = admitted
active authenticated advertisement
explicit local allow
```

`LocalCapabilityPolicy` defaults to `deny`. A revoked, disconnected, introduced, or quarantined peer cannot gain permission merely because an older signature remains cryptographically valid.

## Partitions and rejoin

Disconnect records a local partition snapshot. That snapshot is immutable while the peer is disconnected, including when authenticated key-lifecycle updates arrive during the partition.

- same snapshot: a clean rejoin may be explicitly confirmed;
- changed snapshot: `explicit_reconciliation_required`;
- changed snapshot without explicit reconciliation: reject.

Only the explicit rejoin path may replace the stored partition point. There is no automatic last-writer-wins or peer-supplied snapshot overwrite.

## Portable bundle

`qsol-fed-bundle/1` remains inside the frozen Phase 1 canonical JSON profile rather than inventing impossible larger JSON claims.

Frozen Phase 4 bundle bounds are:

```text
total canonical bundle bytes       65,536
embedded lowercase-hex string       8,192 characters (4,096 decoded bytes)
peer entries                           256
object-attribution entries           1,024
```

A selected content hash expands to every preserved source/provenance attribution. The bundle can therefore carry identical object bytes from multiple foreign observations while preserving each provenance identity exactly.

The offline verifier:

```bash
cargo run --bin qsol-fed-bundle -- verify bundle.json
```

requires no network access. It verifies canonical bytes, hashes, identity/lifecycle cryptography, capability proof bindings, attribution uniqueness, provenance identity, bounds, and `authority = none`.

## Non-destructive bundle import

For material not already present locally:

```text
new peer state       -> quarantined
new foreign objects  -> quarantine namespace
local authority      -> none
local trust          -> unchanged
```

For a peer or exact object attribution that already has local state, import preserves that existing lifecycle/namespace decision rather than demoting it. An archival bundle cannot turn an admitted peer into a quarantined peer merely by being imported.

Trust state and local capability policy are absent from the bundle schema and cannot be imported as foreign authority.

## Phase 4 gate

Export/import round-trips must preserve exact foreign identity, lifecycle, capability-advertisement, object bytes, and **every independent provenance attribution** represented in the bundle. Import must create neither local authority nor trust and must not overwrite pre-existing local lifecycle decisions.

## Non-claims

Phase 4 still does not claim production networking, remote execution, automatic global reconciliation, transitive trust, or deployed multi-implementation interoperability.
