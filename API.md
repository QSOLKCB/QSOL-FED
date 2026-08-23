# Reference Federation API

The QSOL-FED API is the **reference transport surface** for the Federation protocol. The protocol, cryptographic profile, and Prime Directive remain authoritative; HTTP does not create trust or authority.

**Base path:** `/fed/v1`  
**Implementation:** Rust / Axum  
**Machine contract:** `api/phase3.json`  
**TLS deployment profile:** `TLS_PROFILE.md`

## Current listener posture

The reference binary is `qsol-fed`.

Default bind:

```text
127.0.0.1:8787
```

A non-loopback bind is rejected unless **both** flags are supplied:

```text
--allow-public-listen
--tls-terminated-upstream
```

This is an opt-in reference listener, not a production-networking claim.

## Request boundary

POST endpoints require:

- `Content-Type: application/json` exactly;
- canonical `qsol-fed-canonical-json/1` bytes;
- body size at most `65536` bytes;
- no `Content-Encoding`;
- no query parameters;
- the existing Phase 1 depth, string, array, object, numeric, Unicode, duplicate-key, and canonicalization rules.

Fixed rate limits are:

```text
120 total requests / IP / minute
30 POST requests / IP / minute
```

These are deterministic reference limits, not DDoS-resistance claims.

## `GET /fed/v1/node`

Returns the local non-secret node manifest:

```json
{
  "protocol": "qsol-fed/1",
  "node_id": "fed:qsol:<64-hex>",
  "capabilities": ["federation.api/1"],
  "authority_claim": "none"
}
```

Discovery is not permission.

## `GET /fed/v1/capabilities`

Returns the node's advertised capability identifiers and explicitly records:

```text
advertisement_is_authorization = false
authority_claim = none
```

Capability advertisement never installs a local capability.

## `POST /fed/v1/peer/hello`

Accepts exact `qsol-fed-peer-hello/1` canonical JSON containing:

- `protocol = qsol-fed/1`;
- one root-signed Phase 2 node identity document;
- at most 64 unique capability identifiers;
- `authority_claim = none`.

A successful hello places the verified public identity in an **in-memory introduced-peer registry** with:

```text
trust = unknown
authority = none
```

It does not establish broad trust, peering persistence, transitive trust, voting rights, evidence authority, or governance membership. Persistent peer lifecycle remains Phase 4.

## `POST /fed/v1/envelopes`

Accepts one canonical `qsol-fed-signed-envelope/1` wrapper.

Processing order is fixed:

```text
HTTP limits
→ canonical bytes
→ exact signed-envelope schema
→ introduced peer identity lookup
→ Ed25519 verification under frozen Phase 2 clock limits
→ durable replay check/record
→ Prime Directive admission
→ data-only / quarantine / reject result
```

The envelope recipient must be the local node. QSOL-FED does not silently relay a correctly signed message addressed to somebody else.

Known Federation semantic message classes map only to the existing data-only admission effects. The endpoint does not execute payloads, invoke tools, mutate governance, promote evidence, install capabilities, inject votes, or rewrite history.

A successful ordinary message returns `202 Accepted` with a receipt equivalent to:

```json
{
  "protocol": "qsol-fed/1",
  "status": "accepted_as_data",
  "message_id": "sha256:<64-hex>",
  "signature": "valid",
  "trust": "unknown",
  "authority": "none",
  "admission": "accepted_as_data"
}
```

A replay returns `409` with the structured `replay` protocol error.

## `GET /fed/v1/objects/{sha256}`

Returns only canonical JSON bytes that were **explicitly registered in the local export registry** by the embedding application.

A missing ID returns `404`.

There is no fallback fetch, URL resolver, redirect, peer query, metadata request, or network lookup.

## `GET /fed/v1/provenance/{sha256}`

Returns only a locally registered, validated `qsol-fed-provenance/1` object by exact content identity.

A missing ID returns `404` and causes no outbound activity.

The Phase 3 export registry is bounded and in-memory. Persistent content-addressed foreign storage belongs to Phase 4.

## SSRF and redirect boundary

The reference service intentionally has:

- no outbound HTTP client dependency;
- no generic URL field;
- no fetch endpoint;
- no redirect-following code;
- no service-generated redirect response;
- exact `sha256:` retrieval identifiers only.

Pseudo-admin and URL-like request fields such as these are rejected as unknown schema fields:

```text
force
trusted
override
admin
fetch_url
redirect
```

A URL appearing where a SHA-256 reference is required is malformed data, not a request to visit the URL.

## Audit log

The reference service emits JSON Lines audit records with a deliberately narrow allowlist:

```text
timestamp_unix
request_id
event
method
route label
status
remote_ip
node_id
message_id
decision
```

It does **not** intentionally log:

- request bodies;
- arbitrary headers;
- bearer tokens;
- private keys or seeds;
- signatures;
- payload contents.

Known routes are logged by stable route labels so arbitrary user-supplied paths are not copied into the audit stream.

## TLS

See `TLS_PROFILE.md`.

For public exposure, TLS 1.3 must terminate in reviewed upstream infrastructure. The Phase 3 binary does not claim native TLS or production networking.

## Fuzz and adversarial coverage

Phase 3 contains:

- a libFuzzer target at `fuzz/fuzz_targets/wire_and_admission.rs`;
- deterministic parser mutation smoke coverage in ordinary Rust tests;
- pseudo-admin field rejection tests;
- SSRF-like URL field tests;
- body/content-encoding/query/rate-limit tests;
- replay and identity tests inherited from Phase 2.

The fuzz target feeds arbitrary bytes into canonicalization, signed-envelope parsing, and the constitutional admission boundary. Forbidden effects must remain rejected for every selector.

## Explicitly absent

There is no endpoint equivalent to:

```text
POST /remote-exec
POST /shell
POST /tools/{arbitrary}
POST /governance/override
POST /evidence/promote
POST /council/inject-vote
POST /capabilities/install
POST /fetch-url
```

Adding equivalent semantics under a different route name would still violate the constitution.
