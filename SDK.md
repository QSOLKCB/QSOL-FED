# QSOL-FED minimal protocol SDK

Phase 6 defines `qsol-fed-sdk/1`: the smallest governance-neutral surface needed to construct and validate ordinary Federation protocol objects.

## Minimal surface

Every conforming SDK provides equivalent behavior for:

- canonical JSON using `qsol-fed-canonical-json/1`;
- `sha256:` content identities;
- deterministic Phase 1 message IDs;
- protocol-major classification;
- capability-ID grammar;
- node-manifest construction and validation;
- unsigned Phase 1 envelope construction and validation;
- provenance construction and validation.

The reference implementations are:

```text
Rust        src/sdk.rs
Python      sdk/python/qsol_fed_sdk.py
TypeScript  sdk/typescript/qsol_fed_sdk.ts
JavaScript  sdk/typescript/qsol_fed_sdk.mjs
```

The JavaScript runtime has no package-manager dependency. The TypeScript file is the typed public façade over that runtime.

## What the SDK does not provide

The minimal SDK does **not** create:

- trust;
- governance authority;
- Council votes;
- citizenship;
- evidence promotion;
- capability installation;
- remote execution;
- NEXUS Council semantics;
- ORACLE truth authority;
- ARK archival authority;
- Holodeck state.

```text
SDK CONFORMANCE != TRUST
WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP
NODE ID NAMESPACE != QSOL GOVERNANCE
INTEROP TEST != PRODUCTION DEPLOYMENT
```

## Frozen v1 node namespace

`qsol-fed/1` historically validates node IDs using `fed:qsol:<id>`. Phase 6 does not change that frozen grammar because doing so would be a wire-major change.

For third-party nodes, `fed:qsol:` is therefore treated strictly as the v1 wire namespace. It does **not** imply adoption of QSOL internal governance, NEXUS, a Council, ORACLE, ARK, Holodecks, citizenship, or local trust policy.

A future wire-major may generalize the namespace independently of this SDK contract.

## Language-neutral conformance

`fixtures/phase6/conformance.json` contains one neutral research participant, a node manifest, a research payload, provenance, a `hello`, and an `evidence.offer`.

CI executes three independent implementations:

```bash
cargo run --quiet --bin qsol-fed-sdk-conformance
python3 sdk/python/conformance.py
node sdk/typescript/conformance.mjs
```

All three outputs must be byte-identical.

The fixture also freezes the expected canonical objects, object IDs, and message IDs, so three implementations cannot agree with each other while jointly drifting away from the reviewed protocol.

## Third-party participation gate

`examples/neutral_research_node.py` constructs the same protocol participation without importing any QSOL application subsystem. Its local profile requires:

```text
governance_model          = local
qsol_governance_adopted   = false
nexus_required            = false
council_required          = false
oracle_required           = false
ark_required              = false
holodeck_required         = false
authority_effect          = none
```

The participant can announce itself and offer attributed research material. It does not inherit Federation trust or local authority merely because the wire objects validate.

## Scope of the Phase 6 claim

Phase 6 establishes **SDK-level and local transcript interoperability** across three independent implementations plus a non-QSOL-specific participant.

It does not yet establish a deployed, production-hardened multi-node Federation. Accordingly `interoperable_federation`, `production_networking`, and `remote_execution` remain false current claims.
