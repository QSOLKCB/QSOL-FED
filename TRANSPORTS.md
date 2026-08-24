# Phase 8 transport profiles and resilience

**Contract:** `qsol-fed-transport/1`  
**Current claim manifest:** `claims/phase8.json`  
**Reference implementation:** `src/transport.rs`

Phase 8 adds transport and resilience profiles without allowing transport mechanics to change constitutional meaning.

```text
TRANSPORT != IDENTITY
ROUTE != TRUST
RELAY != AUTHORITY
PHYSICAL PRESENCE != ADMISSION
PARTITION RECOVERY != SILENT RECONCILIATION
ARCHIVE PRESENCE != CURRENT AUTHORITY
NETWORK OUTSIDE HOLODECK != NETWORK INSIDE HOLODECK
```

## Reference profiles

The reference layer implements a common bounded `qsol-fed-transport-frame/1` above five delivery profiles:

| Profile | Reference framing | Network-bearing | NAT route hints | Delayed delivery |
| --- | --- | ---: | ---: | ---: |
| WebSocket | one canonical frame per WebSocket message | yes | yes | no |
| QUIC | one canonical frame per unidirectional stream | yes | yes | no |
| Unix/local IPC | u32-be length-prefixed canonical frame | no | no | no |
| offline/sneakernet | canonical offline package | no | no | yes |
| store-forward | bounded canonical spool record | no | no | yes |

These are **reference framing and resilience profiles**. Phase 8 does not claim that a hardened public WebSocket or QUIC service has been deployed.

```text
REFERENCE TRANSPORT PROFILE != PRODUCTION NETWORK SERVICE
```

## Common frame boundary

Every profile carries the same bounded frame fields:

```text
frame_id
profile
sender_node_id
recipient_node_id
message_id
payload_ref
provenance_ref
sequence
authority_effect = none
```

`message_id`, `payload_ref`, and `provenance_ref` are protocol identities that already existed before the transport was selected. A transport may not mint replacements merely because delivery changed.

The maximum canonical transport frame is 65,536 bytes.

## Identity and admission

Transport admission is downstream of Phase 2 authentication and local peer admission.

A frame is accepted as data only when all of the following remain true:

```text
signature_valid       = true
identity_current      = true
replay_fresh          = true
local_peer_admitted   = true
```

Changing WebSocket to QUIC, QUIC to a relay, or a network route to offline media does not relax these conditions.

A compromised/revoked/non-current identity therefore stays rejected on every transport.

## NAT traversal

`qsol-fed-nat-traversal-ticket/1` is a short-lived **route-hint object** for WebSocket and QUIC.

It binds:

- the already authenticated node ID;
- an identity-document reference;
- a transport profile;
- at most eight route candidates;
- a maximum lifetime of 600 seconds.

It hard-codes:

```text
grants_trust     = false
grants_authority = false
authority_effect = none
```

The ticket node must equal the authenticated frame sender. A NAT candidate is never a replacement identity.

Candidate strings are bounded and reject embedded user-info/credential syntax, whitespace, and control characters.

## Multi-relay provenance

A relay does not rewrite the original message. Each `qsol-fed-relay-receipt/1` records:

- original `frame_id`;
- original `message_id`;
- original `payload_ref`;
- relay node ID;
- hop index;
- ingress and egress transport profile;
- previous relay receipt reference;
- `authority_effect = none`.

A chain may contain at most 16 hops. Each receipt after hop 1 must point to the exact prior receipt.

```text
RELAY RECEIPT = PROVENANCE
RELAY RECEIPT != TRUST
RELAY COUNT != AUTHORITY
```

## Offline and sneakernet

`qsol-fed-offline-package/1` packages one validated transport frame and an optional validated relay chain.

Physical media does not bypass local admission. Copying a file onto a USB device, optical disc, archive object, air-gapped transfer medium, or preservation system does not promote its authority.

```text
PHYSICAL POSSESSION != LOCAL ADMISSION
ARCHIVAL PRESENCE != REAL-TIME TRUST
```

## Store-forward and partitions

The reference store-forward queue is bounded to 1,024 frames.

It rejects:

- the first frame beyond the configured bound;
- duplicate frame IDs within the active queue.

Partition recovery drains in deterministic FIFO order and preserves every frame identity.

No rejoin path may silently reconcile governance, trust, lifecycle, evidence, or authority state merely because connectivity returned.

## Disaster recovery and key compromise

Phase 8 exercises each transport with a key-compromise drill. A route that remains reachable while identity is no longer current must still reject the frame.

Phase 2 lifecycle remains authoritative for key rotation, compromise, recovery, and revocation. Transport failover cannot revive a compromised key and cannot skip replay or local-admission checks.

## Long-lived archive compatibility

`qsol-fed-archive-compatibility/1` freezes these rules:

```text
canonical_profile              = qsol-fed-canonical-json/1
wire_protocol                  = qsol-fed/1
preserve_canonical_bytes       = true
preserve_object_identity       = true
historical_receipts_reinterpreted = false
unknown_major_policy           = reject-until-explicit-migration-contract
migration_requires_new_artifact = true
```

A future migration may create a new explicitly linked artifact. It may not silently reinterpret historical bytes under a new protocol meaning.

## Resource-exhaustion and partition matrix

Every admitted profile runs deterministic drills for:

- bounded resource exhaustion;
- partition buffering and recovery;
- key compromise;
- NAT identity binding where applicable;
- multi-relay provenance;
- archive compatibility;
- Holodeck transport independence.

A successful `qsol-fed-transport-drill/1` report hard-codes:

```text
identity_weakened        = false
authority_promoted       = false
provenance_lost          = false
resource_bound_breached  = false
holodeck_invariant_drift = false
authority_effect         = none
```

## Holodeck transport independence

A Holodeck may be discussed, archived, or have its receipts carried by any Phase 8 transport. The transport remains **outside** the simulation sandbox.

The sandbox receipt must continue to mean:

```text
authority_effect     = none
federation_effect    = none
evidence_effect      = none
network_used         = false
real_tools_used      = false
credentials_exposed  = false
```

Sending that receipt over WebSocket does not retroactively make `network_used = true` inside the simulation. Likewise, using offline media does not make the simulation more authoritative.

The Phase 8 gate therefore preserves:

> **Transport may change delivery, never identity, authority, provenance, admission, or sandbox law.**
