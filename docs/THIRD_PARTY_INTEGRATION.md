# Third-party and institutional integration

This guide is for laboratories, universities, observatories, archives, public-interest research groups, independent developers, and deterministic services that want QSOL-FED wire compatibility **without adopting QSOL internal governance**.

## Integration model

A third-party participant keeps its own:

- governance;
- identity policy;
- evidence policy;
- trust policy;
- data-retention rules;
- internal software architecture.

QSOL-FED supplies an exchange protocol, not an institutional constitution.

The minimum integration sequence is:

1. implement or use `qsol-fed-sdk/1`;
2. choose a valid v1 node identifier;
3. advertise only capabilities the local system actually supports;
4. construct canonical protocol objects;
5. preserve source/provenance identities;
6. treat all remote authority as `none` unless a separately reviewed local policy says otherwise;
7. reject unsupported protocol majors and unknown authority-bearing effects.

## Example: independent observatory

An observatory may expose:

```text
evidence.exchange/1
federation.sdk/1
```

and exchange an attributed dataset notice. It does not need:

```text
NEXUS
Council membership
QSOL citizenship
ORACLE
ARK
Holodecks
shared ballots
shared truth
```

The Phase 6 fixture demonstrates exactly this case.

## Example: university research group

A university group can use a local ethics/governance process and still participate. The Federation envelope carries data identity and provenance, not institutional voting rights.

Recommended local policy:

- keep inbound material quarantined until admitted;
- preserve provenance exactly;
- map Federation capabilities to an explicit local allowlist;
- never infer trust from protocol conformance;
- do not expose internal credentials or tool handles through semantic payloads.

## Example: public archive

An archive may participate only as a content/provenance peer. Archival presence does not become semantic truth or governance authority.

## Security boundary

The Phase 6 SDK is deliberately narrower than the reference node. Using an SDK does not grant access to local stores, trust registries, capability policy, Council machinery, ORACLE, ARK, Holodecks, signing secrets, or executable tools.

```text
CONFORMANCE != ADMISSION
ADMISSION != TRUST
TRUST != AUTHORITY
PROVENANCE != TRUTH
INSTITUTIONAL INTEGRATION != QSOL GOVERNANCE
```

## Production note

Phase 6 proves deterministic local interoperability and third-party participation in CI. Institutions deploying across real networks must still apply the TLS, rate-limit, proxy, replay, key-management, audit, and operational controls documented by the relevant earlier phases.

Phase 6 does not claim production-network deployment or deployed multi-implementation federation merely because three SDKs agree on bytes.
