# Reference Federation API

The QSOL-FED API is the **reference transport surface** for the Federation protocol. The protocol, cryptographic profile, and Prime Directive remain authoritative; HTTP does not create trust or authority.

**Base path:** `/fed/v1`  
**Implementation:** Rust / Axum  
**Machine contract:** `api/phase3.json`  
**TLS deployment profile:** `TLS_PROFILE.md`

## Listener posture

Default bind:

```text
127.0.0.1:8787
```

A non-loopback bind requires all three:

```text
--allow-public-listen
--tls-terminated-upstream
--trusted-proxy <IP>
```

The trusted proxy IP is used only to authorize the dedicated `x-qsol-client-ip` rate-attribution header. That header selects a per-client rate bucket and may appear in audit metadata. It is never Federation identity, trust, authority, evidence, or admission.

## Request boundary

POST endpoints require canonical `application/json`, at most `65536` bytes, no `Content-Encoding`, no query parameters, and all frozen Phase 1 JSON limits.

Rate limits are:

```text
120 total requests / client / minute
30 POST requests / client / minute
```

Direct connections use the socket peer IP. In configured proxy mode, the direct socket peer must equal `--trusted-proxy`, and the proxy must supply exactly one parseable `x-qsol-client-ip`. Forwarded client IP supplied by any other socket peer is rejected.

## Discovery

`GET /fed/v1/node` returns the local non-secret node manifest. `GET /fed/v1/capabilities` returns advertised capability identifiers and explicitly states that advertisement is not authorization.

## `POST /fed/v1/peer/hello`

`qsol-fed-peer-hello/1` contains:

- the root-signed Phase 2 identity document;
- up to 128 ordered authenticated lifecycle records (`qsol-fed-key-rotation/1` or `qsol-fed-key-status/1`);
- up to 64 unique capabilities;
- `authority_claim = none`.

The service rebuilds the peer from sequence zero and applies every lifecycle record through the existing Phase 2 signature/sequence rules. If that node is already introduced in the current process, a later hello may advance the locally retained lifecycle state but may not roll it back or replace the same sequence with a different state.

A successful hello still means only:

```text
trust = unknown
authority = none
```

The registry remains in-memory. Persistent peer state is Phase 4 work.

## `POST /fed/v1/envelopes`

Processing order is:

```text
HTTP limits
→ canonical signed wrapper
→ lifecycle-aware introduced peer lookup
→ Ed25519 verification under frozen clock limits
→ recipient == local node check
→ durable replay check/record
→ Prime Directive admission
→ data-only / reject response
```

A correctly signed envelope addressed to another node is rejected **before** replay recording. The service does not become an accidental relay and foreign traffic cannot consume local replay state.

The endpoint never executes payloads, invokes tools, mutates governance, promotes evidence, installs capabilities, injects votes, or rewrites history.

## Replay retention and compaction

Replay IDs are retained for `4200` seconds:

```text
3600 second maximum signed-message lifetime
+ 300 second future skew margin
+ 300 second expiry skew margin
= 4200 seconds
```

That is the complete interval in which a previously accepted message could still pass the Phase 2 clock gate. Older records may therefore be pruned safely.

At 1 MiB the append log is compacted: expired records are removed, the retained set is written to a same-directory temporary file, fsynced, atomically renamed, and the parent directory is fsynced. The 64 MiB bound remains a hard fail-closed ceiling for an unexpectedly enormous **active** replay window, rather than a permanent exhaustion point caused by historical entries.

## Local object and provenance retrieval

`GET /fed/v1/objects/{sha256}` and `GET /fed/v1/provenance/{sha256}` serve only explicitly registered local canonical bytes. Missing IDs return `404` and never trigger peer retrieval, redirects, URL resolution, cloud metadata access, or any other outbound request.

The reference crate has no outbound HTTP client dependency.

## SSRF and pseudo-admin boundary

Unknown fields such as these fail closed:

```text
force
trusted
override
admin
fetch_url
redirect
```

There is no `/fetch-url`, redirect-following client, generic proxy endpoint, or remote-execution route.

## Audit log

Production audit logging is JSON Lines to the configured audit file with a narrow metadata allowlist. The service does **not** keep a production in-memory clone of every audit record. The in-memory mirror exists only under `cfg(test)`.

Replay and audit paths are canonicalized before opening and must resolve to distinct files, preventing audit JSON from corrupting the replay log.

The audit record intentionally excludes request bodies, arbitrary headers, bearer material, private seeds, signatures, and payload contents.

## TLS

See `TLS_PROFILE.md`. Public exposure requires TLS 1.3 upstream termination and the explicit trusted-proxy configuration described above. This remains a reference listener, not a production-networking claim.

## Fuzz and adversarial coverage

Phase 3 includes the libFuzzer target `fuzz/fuzz_targets/wire_and_admission.rs` plus deterministic parser/admission mutation smoke tests in ordinary CI. Regression tests cover lifecycle rollback, wrong-recipient envelopes, replay compaction, trusted-proxy rate separation, shared log paths, pseudo-admin fields, SSRF-like inputs, body limits, compression rejection, and local-only retrieval.
