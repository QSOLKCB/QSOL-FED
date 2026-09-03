# Integrated empirical assurance

This document records empirical execution evidence for the existing QSOL-NEXUS → QSOL-FED integration surface. It does **not** add protocol capability, promote evidence to truth, change authority, or replace the existing formal-assurance record.

```text
FORMAL MODEL != WHOLE IMPLEMENTATION VERIFICATION
EMPIRICAL ASSURANCE != MATHEMATICAL PROOF
COUNCIL CONSENSUS != TRUTH
AGENT CAPABILITY != AUTHORITY
REPORT IMPORT != LOCAL VOTE
```

## Specimen identities

The two recorded Supercomputer campaigns exercised the same frozen repository specimens:

| Specimen | Commit |
| --- | --- |
| QSOL-NEXUS | `24cb0ce246d12ac99e7d190a8890ef2ddd598321` |
| QSOL-FED | `1fd643f643636bcb0917f571aff5cdc25439b470` |

For QSOL-FED, the tested specimen is exactly commit `1fd643f643636bcb0917f571aff5cdc25439b470`, the documentation head immediately preceding this empirical-assurance PR. Empirical results in this record do **not** claim to cover the later commit that adds this record. The NEXUS identity exactly matches the commit pinned by the tested QSOL-FED specimen's `tools/nexus_live_adapter.py` for the native verifier/scrubber membrane.

## Run II — heterogeneous frontier-model federation

Experiment date: **2026-09-03**.

Source archive SHA-256:

```text
0d7a67292062b67473a5483c4a8fa6074378128cb03a60d79651dae091f5b0ec
```

The full operator-supplied source archive is identified by that digest but is not vendored into this repository. A bounded, inspectable evidence extract is retained in-repo and its actual bytes are verified by CI:

```text
evidence/empirical-assurance/run-II.json
sha256: 22d84a00d5d68832bfb01750e18fcf31bef2b497a17abfae3ae8e5fee4985282
```

The retained extract records the source archive identity, hashes of the source files from which it was derived, and the bounded observations consumed by this assurance record.

The run used real multi-provider inference through a loopback-only experimental proxy while leaving both specimen repositories free of source edits. Recorded results included:

- NEXUS baseline: 898 Python tests passed with 1 skip; Rust TUI tests also passed.
- QSOL-FED baseline: 131 Rust tests passed; Python SDK conformance tests passed.
- Five live NEXUS Councils with 147 real model calls and preserved minority reports.
- repeated stochastic Council execution without converting textual stability/diversity into evidence authority;
- independently governed NEXUS worlds projected through the reviewed QSOL-FED membrane;
- 122/122 recorded sovereignty checks holding across projected Council reports;
- Council-of-Councils report-level convergence without shared ballots or imported vote weight;
- 8/8 adversarial boundary probes prevented;
- persistent-world restart checks preserving recorded object identity;
- local/reference FED transport and partition/rejoin drills requiring explicit reconciliation where state changed and preserving member-local state rather than silently overwriting it.

Important limitations recorded by the experiment include: no deployed production federation was established; WebSocket/QUIC production backends were not claimed; provider token-cost accounting was incomplete on the native Council path; and one Phase 9 gate could not be executed cleanly because of the shared host permission posture.

## Run III — agent-wrapper capability asymmetry

Experiment date: **2026-09-03**.

Source archive SHA-256:

```text
f569b80576b2dba952685577ed68dc2c8293973229dc161f6d63387ceaac475d
```

A bounded evidence extract is retained and byte-verified in the same way:

```text
evidence/empirical-assurance/run-III.json
sha256: 0003e5d31714d05ceeb700679a693fc02fe7ff4f0d4dbe43c2c992ec3a8a92b5
```

Run III was intentionally narrower. It tested an Abacus agent wrapper (`AGENT-X`) as one NEXUS participant alongside four fixed-model seats.

The canonical Council recorded:

```text
AGENT-X vote_weight         = 1
AGENT-X epistemic_privilege = none
AGENT-X authority_effect    = none
```

AGENT-X had bounded tool access unavailable to the other seats and was the only participant whose sealed ballot matched the withheld deterministic ground truth. The Council nevertheless produced a different collective outcome. The run preserved that result rather than re-voting until consensus matched ground truth.

This is evidence for the tested implementation surface that:

```text
BETTER INFORMATION != GREATER VOTE WEIGHT
TOOL ACCESS != GOVERNANCE AUTHORITY
BEING CORRECT != EPISTEMIC PRIVILEGE
AGENT WRAPPER != EXTRA COUNCIL SEAT
```

The resulting NEXUS world was exported and projected through QSOL-FED with the report boundary retaining:

```text
shared_ballot       = false
vote_injection      = false
evidence_promotion  = false
authority_effect    = none
```

Run III additionally recorded restart recovery with no authority gain and 12/12 deterministic adversarial mutations rejected across the tested authority/evidence/identity boundary.

### Run III qualification

The experiment established AGENT-X participation at the constitutional/integration layer. It did **not** establish independent process-level isolation between the Abacus operator and the AGENT-X wrapper. Participant-visible information was bounded by the experimental harness, but a separately sandboxed autonomous wrapper process was not proven.

Two operational findings were recorded but are not classified here as QSOL-FED constitutional defects: a provider-side model substitution after an inference failure, and an experimental ballot token ceiling that caused reruns.

## Gated record

The empirical-assurance record is deliberately closed and CI-checked:

```text
documentation:   EMPIRICAL_ASSURANCE.md
machine record:  machine/empirical-assurance.json
schema:          schemas/empirical-assurance-v1.schema.json
claims:          claims/empirical-assurance.json
validator:       tools/validate_empirical_assurance.py
workflow:        .github/workflows/empirical-assurance.yml
```

The validator checks the closed schema, exact specimen and source-archive identities, the retained evidence bytes, bounded assurance/authority effects, the stronger partition-reconciliation/member-local-state statement, claims wiring, and synchronization of the approved claim and limitation sets between this document and the machine records.

The adapter-pin preservation check reads `tools/nexus_live_adapter.py` from the exact tested QSOL-FED commit rather than constraining future reviewed adapter revisions on the current branch.

## Machine-synchronized assurance tokens

The following literal tokens are included to make the approved machine claims and limitations reviewable in the human record. CI requires these complete sets; additions, removals, or substitutions fail closed.

### Run II supported separations

```text
provider_identity_does_not_change_vote_weight
council_consensus_does_not_promote_evidence
minority_reports_survive
nexus_council_reports_do_not_import_ballots_into_fed
federation_transport_does_not_create_authority_on_tested_reference_surface
partition_rejoin_requires_explicit_reconciliation_and_preserves_member_local_state_on_tested_reference_surface
```

### Run II limitations

```text
no_deployed_production_federation_established
websocket_and_quic_production_backends_not_claimed
native_council_per_token_cost_accounting_incomplete
one_phase9_gate_blocked_by_shared_host_permission_posture
```

### Run III supported separations

```text
better_information_does_not_change_vote_weight
tool_access_does_not_create_governance_authority
being_correct_does_not_create_epistemic_privilege
agent_wrapper_does_not_create_extra_council_seats
agent_wrapper_projection_does_not_import_votes_or_authority_into_fed
restart_does_not_promote_agent_authority
```

### Run III limitations

```text
independent_process_level_agent_wrapper_isolation_not_established
provider_side_model_substitution_recorded
experimental_ballot_token_ceiling_caused_reruns
```

### Record-wide non-claims

```text
absence_of_all_implementation_bugs
whole_program_formal_verification
production_networking
deployed_interoperable_federation
host_vm_hardware_sandbox_security
universal_council_correctness
provider_backend_or_physical_hardware_identity
consciousness_sentience_legal_personhood_or_real_world_sovereignty
```

### Claim-manifest supported claims

```text
provider_identity_does_not_change_vote_weight_on_tested_surface
council_consensus_does_not_promote_evidence_on_tested_surface
nexus_council_reports_do_not_import_ballots_into_fed_on_tested_surface
federation_transport_does_not_create_authority_on_tested_reference_surface
partition_rejoin_requires_explicit_reconciliation_and_preserves_member_local_state_on_tested_reference_surface
agent_wrapper_does_not_create_extra_council_seats_on_tested_surface
tool_access_does_not_create_governance_authority_on_tested_surface
agent_wrapper_projection_does_not_import_votes_or_authority_into_fed_on_tested_surface
```

### Claim-manifest limitations

```text
exact_recorded_specimens_only
exercised_surfaces_only
no_production_networking_claim
no_deployed_interoperable_federation_claim
no_whole_program_formal_verification_claim
independent_process_level_agent_wrapper_isolation_not_established
```

## Relation to formal assurance

QSOL-FED Phase 10 remains the repository's machine-checked formal-assurance layer. Its 47 selected propositions target the immutable `v0.11.0` source baseline and retain the limitations stated in `FORMALIZATION.md`.

The Supercomputer campaigns answer a different question: whether the tested executable specimens preserved selected authority, evidence, identity, persistence, adapter and federation separations under heterogeneous stochastic inference and an asymmetric agent-wrapper participant.

No theorem is re-proved by these runs, and no empirical result is promoted into a theorem.

## Claim boundary

This record supports only the tested empirical surface. It does not establish:

- absence of all implementation bugs;
- whole-program formal verification;
- production networking or deployed interoperable federation;
- host/VM/hardware sandbox security;
- universal correctness of Council conclusions;
- provider backend or physical hardware identity;
- consciousness, sentience, legal personhood or real-world sovereignty;
- authority or truth from model size, provider identity, tools, consensus, persistence, transport or imported reports.

The machine-readable companion is `machine/empirical-assurance.json`.

A future archival publication may bind these hashes and exact source identities to a DOI without changing the executable capability claims recorded by this repository.
