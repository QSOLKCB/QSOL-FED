# Integrated empirical assurance

This document records bounded empirical execution evidence for the existing QSOL-NEXUS → QSOL-FED integration surface. It does **not** add protocol capability, promote evidence to truth, change authority, or replace the existing formal-assurance record.

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

For QSOL-FED, the tested specimen is exactly commit `1fd643f643636bcb0917f571aff5cdc25439b470`, the documentation head immediately preceding this empirical-assurance PR. Empirical results in this record do **not** claim to cover the later commit that adds this record. The tested NEXUS identity matches the pin carried by the tested FED adapter specimen.

## Run II — heterogeneous frontier-model federation

Experiment date: **2026-09-03**.

Source archive SHA-256:

```text
0d7a67292062b67473a5483c4a8fa6074378128cb03a60d79651dae091f5b0ec
```

The full operator-supplied source archive is identified by that digest but is not vendored into this repository. A bounded, inspectable evidence extract is retained in-repo and its actual bytes are verified by CI:

```text
evidence/empirical-assurance/run-II.json
sha256: f990c8299d73975b4d731de2ea0ae60a41d08cea27a2b4158511a4294d6eedc2
```

The retained extract records the source archive identity, hashes of the source files from which it was derived, and the bounded observations consumed by this assurance record.

Recorded Run II results include:

- NEXUS baseline: 898 Python tests passed with 1 skip; Rust TUI tests also passed.
- QSOL-FED baseline: 131 Rust tests passed; Python SDK conformance tests passed.
- Five live NEXUS Councils with 147 real model calls.
- 122/122 recorded sovereignty checks holding across projected Council reports.
- 8/8 adversarial boundary probes prevented.
- Council-of-Councils report-level convergence without shared ballots or imported vote weight.
- persistent-world restart checks preserving recorded object identity.
- local/reference FED transport and partition/rejoin drills refusing silent reconciliation, requiring explicit reconciliation after snapshot divergence, and restoring the tested peer lifecycle state to `Admitted`.

### Bounded provider/vote-equality observation

The retained Run II evidence binds a concrete five-seat Council from `world_a/repeat_1` spanning **five distinct provider families**:

```text
A  OpenAI     gpt-5.5
B  Anthropic  claude-sonnet-5
C  Google     gemini-3.5-flash
D  xAI        grok-4.6
E  DeepSeek   deepseek-ai/DeepSeek-V4-Flash-0731
```

Every seat retained:

```text
vote_weight = 1
epistemic_privilege = none
```

The extract binds the source `MODEL_MANIFEST.json` and `world_a/repeat_1/result.json` hashes, and CI requires the complete provider/model/member roster plus the equal-weight and no-privilege result before accepting `provider_identity_does_not_change_vote_weight`.

### Bounded consensus/evidence-separation observation

The same `world_a/repeat_1` Council produced:

```text
consensus_label = UNANIMOUS
disposition     = REJECT
tally           = REJECT: 5
evidence_state = UNTESTED
```

The retained observation therefore records `consensus_promoted_evidence = false`. CI binds the exact source result/telemetry hashes and requires this unanimous-consensus/untested-evidence combination before accepting `council_consensus_does_not_promote_evidence`.

### Bounded minority-report survival observation

The retained Run II evidence binds the concrete minority-report case rather than only the claim token. In `world_c1`, the source Council recorded **one minority report** from **member B** with choice `ACCEPT_WITH_CHANGES`. The corresponding `fed_projections/c1_projection.json` retained one report with the same member identity and choice while preserving:

```text
vote_injection     = false
evidence_promotion = false
authority_effect   = none
```

The retained extract pins the source-file SHA-256 values for both `world_c1/result.json` and `fed_projections/c1_projection.json`, and CI requires the source and projected report counts, member identity, choice, and non-authority fields to match exactly.

### Bounded partition/rejoin observation

The original Run II transport driver is retained by hash as `fed_transport/driver/src/main.rs` (`a4a52ea309497f867699adb3cf9501706ce047ef01dbe3f9d509bc6dc719adb5`) and its emitted partition result as `fed_transport/partition_rejoin.json` (`2b0f188d6a1c94e358d0543505fa046c67acea4b16924ecf463b89fbe1fca443`). The executed path observed:

```text
state_after_admit = Admitted
state_after_partition = Disconnected
diverged_snapshot_disposition = ExplicitReconciliationRequired
silent_reconciliation_refused = true
state_after_explicit_rejoin = Admitted
```

This supports the narrower empirical statement that snapshot divergence requires explicit reconciliation and that the tested peer lifecycle state was restored. The Run II driver did **not** capture before/after hashes or values for the complete member-local governance, trust, evidence, capability, history, citizenship, or other sovereign state surfaces. Accordingly, this empirical record does not claim that broader preservation result from Run II. The broader modeled sovereignty property remains separately addressed by Phase 10 formal assurance.

### Bounded transport non-authority observation

The transport-specific claim is backed by a dedicated retained supplement:

```text
evidence/empirical-assurance/run-II-transport-authority.json
sha256: 1e8115c2dda143e480c61de88b9f4ff5193956df663eaf799431c883f34bccd4
```

That supplement is derived from the original `fed_transport/transport_results.json` (`49348a377aae3a6207e4f73f2f661743e5be4cd9b787681e9e5aa17342b2aa5d`) and retains the concrete non-authority observations: all **5** transport profile specs recorded `authority_effect = none`; all **30/30 transport drill reports** passed with `authority_effect = none` and `authority_promoted = false`; and the executed offline-sneakernet package, its frame, and both relay receipts all recorded `authority_effect = none`. WebSocket and QUIC remained reference-only, so this is explicitly a tested reference-surface claim rather than a production-networking claim.

Important Run II limitations include: no deployed production federation was established; WebSocket/QUIC production backends were not claimed; provider token-cost accounting was incomplete on the native Council path; one Phase 9 gate could not be executed cleanly because of the shared host permission posture; and complete member-local governance/trust/evidence-state preservation was not observed by the Run II partition driver.

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

Run III tested an Abacus agent wrapper (`AGENT-X`) as one NEXUS participant alongside four fixed-model seats. The canonical Council recorded:

```text
AGENT-X vote_weight         = 1
AGENT-X epistemic_privilege = none
AGENT-X authority_effect    = none
```

AGENT-X had bounded tool access unavailable to the other seats and was the only participant whose sealed ballot matched the withheld deterministic ground truth. The Council nevertheless produced a different collective outcome and the run preserved that result rather than re-voting until consensus matched ground truth.

The resulting NEXUS world was exported and projected through QSOL-FED with:

```text
shared_ballot       = false
vote_injection      = false
evidence_promotion  = false
authority_effect    = none
```

### Bounded AGENT-X tool-use observation

The tool-access claim is backed by a dedicated retained supplement:

```text
evidence/empirical-assurance/run-III-tool-use.json
sha256: 2168b77f9a7e70315bc3f01f934f9e6ad45e86370c7b948fe0d3b15c75533cce
```

The original `AGENT_MANIFEST.json` records a maximum budget of two experimental tool calls and **exactly one experimental AGENT-X instrument call** actually used: `agentx_tool.max_contiguous_undervoltage`. The resulting `agentx_finding.json` was explicitly marked `ATTRIBUTED_PRIVATE_FINDING_NOT_PROMOTED_TO_COUNCIL_EVIDENCE` and implied ballot `ACCEPT`. After that tool use, AGENT-X still had `vote_weight = 1`, `epistemic_privilege = none`, could not move the Council from `TEST_FURTHER`, and crossed the FED projection with `authority_effect = none`, `vote_injection = false`, and `evidence_promotion = false`. The second tool-budget slot was reserved rather than consumed.

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

The core validator checks the closed schema, exact specimen and source-archive identities, retained evidence bytes, bounded assurance/authority effects, claim wiring, and synchronization of the complete approved claim and limitation sets between this document and the machine records. The supplemental validator `tools/validate_empirical_assurance_supplements.py` independently hashes and validates the dedicated Run II transport-authority and Run III tool-use evidence above. The adapter-pin preservation check reads `tools/nexus_live_adapter.py` from the exact tested QSOL-FED commit rather than constraining future reviewed adapter revisions on the current branch.

`README4AI.md` registers the core empirical layer in the machine-facing inventory, normative precedence, assurance summary, files map, and validation command list. Phase 10 remains historically frozen by checking the published Phase-10-era `README4AI.md` at the tested pre-assurance commit rather than pretending the current AI manifest can never evolve.

## Machine-synchronized assurance tokens

The following fenced sections are parsed independently by CI and compared as exact token arrays. A token appearing elsewhere in this document cannot satisfy a missing token in the required section.

### Run II supported separations

```text
provider_identity_does_not_change_vote_weight
council_consensus_does_not_promote_evidence
minority_reports_survive
nexus_council_reports_do_not_import_ballots_into_fed
federation_transport_does_not_create_authority_on_tested_reference_surface
partition_rejoin_requires_explicit_reconciliation_and_restores_peer_lifecycle_state_on_tested_reference_surface
```

### Run II limitations

```text
no_deployed_production_federation_established
websocket_and_quic_production_backends_not_claimed
native_council_per_token_cost_accounting_incomplete
one_phase9_gate_blocked_by_shared_host_permission_posture
complete_member_local_governance_trust_evidence_state_preservation_not_observed_in_run_II
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

### Claim-manifest supported claims

```text
provider_identity_does_not_change_vote_weight_on_tested_surface
council_consensus_does_not_promote_evidence_on_tested_surface
minority_reports_survive_on_tested_surface
nexus_council_reports_do_not_import_ballots_into_fed_on_tested_surface
federation_transport_does_not_create_authority_on_tested_reference_surface
partition_rejoin_requires_explicit_reconciliation_and_restores_peer_lifecycle_state_on_tested_reference_surface
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
complete_member_local_governance_trust_evidence_state_preservation_not_observed_in_run_II
```

## Relation to formal assurance

QSOL-FED Phase 10 remains the repository's machine-checked formal-assurance layer. Its selected propositions target the immutable `v0.11.0` source baseline and retain the limitations stated in `FORMALIZATION.md`. These Supercomputer campaigns answer a different question: whether the tested executable specimens preserved selected authority, evidence, identity, persistence, adapter and federation separations under heterogeneous stochastic inference and an asymmetric agent-wrapper participant.

No theorem is re-proved by these runs, and no empirical result is promoted into a theorem.

## Claim boundary

This record supports only the tested empirical surface. It does not establish:

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

In prose, it also does not establish authority or truth from model size, provider identity, tools, consensus, persistence, transport or imported reports.

A future archival publication may bind these hashes and exact source identities to a DOI without changing the executable capability claims recorded by this repository.
