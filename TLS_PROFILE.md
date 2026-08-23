# QSOL-FED Phase 3 TLS Deployment Profile

Phase 3 implements an opt-in HTTP reference service. It does **not** claim a native production TLS stack or production networking. Public exposure is permitted only under this deployment profile and remains an operator decision.

## Required public-exposure pattern

```text
Internet / private WAN
        |
    TLS 1.3
        |
reviewed TLS terminator
        |
protected transport
        |
qsol-fed reference service
```

The Rust reference binary binds `127.0.0.1:8787` by default.

A non-loopback bind is rejected unless the operator supplies all three:

```text
--allow-public-listen
--tls-terminated-upstream
--trusted-proxy <IP>
```

The direct socket IP of the terminator must equal the configured `--trusted-proxy` value. Requests received from that exact socket peer must carry one `x-qsol-client-ip` header containing a single parseable IP address. That value is used only to select the per-client rate-limit bucket and to record rate-source audit metadata. It does **not** create Federation identity, trust, authority, evidence status, or admission.

A forwarded client-IP header received from any socket peer other than the configured trusted proxy is rejected. This avoids collapsing all external clients into one proxy-wide rate bucket without turning generic forwarding headers into an authentication mechanism.

Those flags do not make the service production-safe. They acknowledge that TLS terminates outside this binary and that the operator has explicitly pinned the terminator used for rate attribution.

## TLS requirements

For public or cross-host deployment:

- TLS 1.3 is the minimum admitted version;
- certificates must be validated according to the deployment's explicit trust policy;
- private keys must not be placed in Federation semantic objects, request bodies, audit records, or repository configuration;
- plaintext public HTTP is not an admitted deployment profile;
- TLS termination should occur on the same host or across an authenticated, operator-controlled private transport;
- the TLS terminator's request-body limit must be no larger than the service's `65536` byte limit;
- request decompression must remain disabled before the Federation service;
- the terminator must not synthesize Federation authority, trust, capability, or identity fields;
- the terminator may set only the dedicated `x-qsol-client-ip` rate-attribution header after stripping any client-supplied copy;
- other forwarded headers are not trusted by the Phase 3 reference service for identity or authority decisions.

## No redirect dependency

QSOL-FED does not rely on an HTTP-to-HTTPS redirect to make plaintext exposure safe. Public plaintext should not be opened in the first place.

The reference service itself emits no redirect responses and contains no redirect-following client.

## SSRF boundary

The service contains no outbound HTTP client and no generic URL-fetch endpoint. Object and provenance retrieval is exact `sha256:` lookup against explicitly registered local export bytes.

A missing local object returns `404`. It does not cause the node to fetch a URL, follow a redirect, query cloud metadata, or contact a peer.

## Reverse proxy hardening

A TLS terminator or reverse proxy should:

- admit only the six documented `/fed/v1` routes;
- preserve exact request bodies;
- disable request decompression;
- enforce a body limit no larger than the service limit;
- impose connection limits appropriate to the deployment;
- strip all client-supplied copies of `x-qsol-client-ip`, then write exactly one validated client IP itself;
- strip other untrusted forwarding and pseudo-admin headers;
- avoid injecting credentials into Federation request bodies;
- avoid caching POST responses;
- avoid rewriting status codes or Federation JSON error bodies.

## Production non-claim

Phase 3 proves the bounded reference service, opt-in listener behavior, lifecycle-aware identity introduction, replay retention/compaction, per-client proxy-aware rate attribution, authentication/replay/admission pipeline, and deployment contract. It does not claim:

- native TLS termination;
- multi-process replay coordination;
- globally distributed rate limiting;
- DDoS resistance;
- production SRE maturity;
- deployed cross-node federation interoperability.

Those require later operational evidence and explicit claim promotion.
