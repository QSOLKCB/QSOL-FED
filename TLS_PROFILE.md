# QSOL-FED Phase 3 TLS Deployment Profile

Phase 3 implements an opt-in HTTP reference service. It does **not** claim a native production TLS stack or production networking. Public exposure is permitted only under this deployment profile and remains an operator decision.

## Required public-exposure pattern

The preferred deployment shape is:

```text
Internet / private WAN
        |
    TLS 1.3
        |
reviewed TLS terminator
        |
loopback / protected local transport
        |
qsol-fed reference service
```

The Rust reference binary binds `127.0.0.1:8787` by default.

A non-loopback bind is rejected unless the operator supplies **both**:

```text
--allow-public-listen
--tls-terminated-upstream
```

Those flags do not make the service production-safe. They are explicit acknowledgements that the listener is being exposed outside the default loopback posture and that TLS terminates in infrastructure outside this binary.

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
- forwarded headers are not trusted by the Phase 3 reference service for identity or authority decisions.

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
- impose connection and request-rate limits appropriate to the deployment;
- strip untrusted forwarding and pseudo-admin headers;
- avoid injecting credentials into Federation request bodies;
- avoid caching POST responses;
- avoid rewriting status codes or Federation JSON error bodies.

## Production non-claim

Phase 3 proves the bounded reference service, opt-in listener behavior, authentication/replay/admission pipeline, and deployment contract. It does not claim:

- native TLS termination;
- multi-process replay coordination;
- globally distributed rate limiting;
- DDoS resistance;
- production SRE maturity;
- deployed cross-node federation interoperability.

Those require later operational evidence and explicit claim promotion.
