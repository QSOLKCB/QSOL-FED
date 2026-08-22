# Reference API

The QSOL-FED API is a **reference transport surface** for the Federation protocol. The protocol remains authoritative; endpoints are replaceable.

## Planned v1 base

```text
/fed/v1
```

## Discovery

### `GET /fed/v1/node`

Returns a non-secret node manifest suitable for protocol discovery.

Planned fields include:

```json
{
  "protocol": "qsol-fed/1",
  "node_id": "fed:qsol:<id>",
  "capabilities": ["evidence.exchange/1", "council.report/1"],
  "authority_claim": "none"
}
```

### `GET /fed/v1/capabilities`

Returns versioned capabilities the node is willing to advertise. Advertisement is not authorization.

## Peering

### `POST /fed/v1/peer/hello`

Performs bounded protocol/capability introduction. It must not create broad trust, install capabilities, grant voting rights or modify local governance.

## Envelope exchange

### `POST /fed/v1/envelopes`

Accepts one bounded Federation envelope for validation and local admission.

Conceptual response classes:

```text
accepted_as_data
quarantined
rejected
```

An HTTP success code must not be interpreted as semantic truth or local authority.

## Content retrieval

### `GET /fed/v1/objects/{sha256}`

Retrieves a locally exportable object by exact content identity, subject to local disclosure policy.

### `GET /fed/v1/provenance/{sha256}`

Retrieves exportable provenance for an object or receipt.

## Explicitly absent from v1

There is no generic endpoint equivalent to:

```text
POST /remote-exec
POST /shell
POST /tools/{arbitrary}
POST /governance/override
POST /evidence/promote
POST /council/inject-vote
POST /capabilities/install
```

Adding an endpoint with equivalent semantics under a cute new name does not make it constitutional.

## Authentication and authorization

The production design will distinguish:

1. transport security;
2. envelope authentication;
3. peer identity;
4. capability advertisement;
5. local authorization;
6. Prime Directive admission.

Passing one layer does not imply passing the next.

## Limits

Production endpoints must define and test limits for:

- body size;
- nesting depth;
- object count;
- string length;
- request rate;
- clock skew/expiry;
- replay cache size;
- decompression behavior, if compression is admitted.

Unbounded JSON is not a federation protocol. It is an invitation written in curly braces.

## Errors

Structured errors should expose stable machine codes and optional violated invariant IDs without leaking credentials, local private policy or unnecessary internal state.

## Implementation status

PR #1 documents this surface and supplies schemas/data structures. It does not expose a network listener and therefore does not claim operational API interoperability yet.
