#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "machine/empirical-assurance.json"
SCHEMA_PATH = ROOT / "schemas/empirical-assurance-v1.schema.json"
CLAIMS_PATH = ROOT / "claims/empirical-assurance.json"
DOC_PATH = ROOT / "EMPIRICAL_ASSURANCE.md"
AI_MANIFEST_PATH = ROOT / "README4AI.md"
README_PATH = ROOT / "README.md"
AGENTS_PATH = ROOT / "AGENTS.md"
WORKFLOW_PATH = ROOT / ".github/workflows/empirical-assurance.yml"
SUPPLEMENT_VALIDATOR_PATH = ROOT / "tools/validate_empirical_assurance_supplements.py"

FED_COMMIT = "1fd643f643636bcb0917f571aff5cdc25439b470"
NEXUS_COMMIT = "24cb0ce246d12ac99e7d190a8890ef2ddd598321"
RUN_II_SHA256 = "0d7a67292062b67473a5483c4a8fa6074378128cb03a60d79651dae091f5b0ec"
RUN_III_SHA256 = "f569b80576b2dba952685577ed68dc2c8293973229dc161f6d63387ceaac475d"
RUN_II_EVIDENCE_SHA256 = "f990c8299d73975b4d731de2ea0ae60a41d08cea27a2b4158511a4294d6eedc2"
RUN_III_EVIDENCE_SHA256 = "0003e5d31714d05ceeb700679a693fc02fe7ff4f0d4dbe43c2c992ec3a8a92b5"
PARTITION_CLAIM = "partition_rejoin_requires_explicit_reconciliation_and_restores_peer_lifecycle_state_on_tested_reference_surface"
MINORITY_CLAIM = "minority_reports_survive_on_tested_surface"
PARTITION_LIMITATION = "complete_member_local_governance_trust_evidence_state_preservation_not_observed_in_run_II"

EXPECTED_PRESERVATION_BLOBS = {
    "README4AI.md": "64806ea18e1cf3f303726f9928f0b54312bb1af2",
    "AGENTS.md": "185a1cebfdee85f9575f5d8647277e70fd3e21c0",
    ".github/workflows/empirical-assurance.yml": "c5dc640518d959b42561056f6aafc0d0cfe79fd5",
}
EXPECTED_CAMPAIGN_PURPOSES = {
    "supercomputer-run-II": "heterogeneous frontier-model NEXUS and FED integration stress test",
    "supercomputer-run-III": "agent-wrapper capability-asymmetry delta test",
}

EXPECTED_GATE = {
    "schema": "schemas/empirical-assurance-v1.schema.json",
    "claims": "claims/empirical-assurance.json",
    "validator": "tools/validate_empirical_assurance.py",
    "supplement_validator": "tools/validate_empirical_assurance_supplements.py",
    "workflow": ".github/workflows/empirical-assurance.yml",
    "documentation": "EMPIRICAL_ASSURANCE.md",
}
EXPECTED_TOP_LEVEL_SEMANTICS = {
    "document_type": "qsol-fed-integrated-empirical-assurance",
    "schema_version": 1,
    "assurance_effect": "empirical_record_only",
    "capability_effect": "none",
    "authority_effect": "none",
    "evidence_promotion": False,
    "formalization_relation": "complementary_not_replacement",
}
EXPECTED_FORMAL_ASSURANCE = {
    "phase10_remains_separate": True,
    "reference": "FORMALIZATION.md",
    "rule": "empirical_execution_does_not_reprove_or_replace_lean_theorems",
}
EXPECTED_DOES_NOT_ESTABLISH = [
    "absence_of_all_implementation_bugs",
    "whole_program_formal_verification",
    "production_networking",
    "deployed_interoperable_federation",
    "host_vm_hardware_sandbox_security",
    "universal_council_correctness",
    "provider_backend_or_physical_hardware_identity",
    "consciousness_sentience_legal_personhood_or_real_world_sovereignty",
]
EXPECTED_CLAIM_BOUNDARY = {
    "establishes": "bounded empirical assurance only for the exact recorded specimens and exercised surfaces",
    "does_not_establish": EXPECTED_DOES_NOT_ESTABLISH,
}
EXPECTED_FUTURE_PUBLICATION = {
    "doi": None,
    "status": "not_yet_published",
    "rule": "future_archival_metadata_may_bind_these_hashes_without_expanding_runtime_capability_claims",
}

EXPECTED_SUPPLEMENTS = [
    {
        "id": "run-II-transport-authority",
        "path": "evidence/empirical-assurance/run-II-transport-authority.json",
        "sha256": "1e8115c2dda143e480c61de88b9f4ff5193956df663eaf799431c883f34bccd4",
        "claim_supported": "federation_transport_does_not_create_authority_on_tested_reference_surface",
    },
    {
        "id": "run-III-tool-use",
        "path": "evidence/empirical-assurance/run-III-tool-use.json",
        "sha256": "2168b77f9a7e70315bc3f01f934f9e6ad45e86370c7b948fe0d3b15c75533cce",
        "claim_supported": "tool_access_does_not_create_governance_authority_on_tested_surface",
    },
    {
        "id": "run-III-seat-roster",
        "path": "evidence/empirical-assurance/run-III-seat-roster.json",
        "sha256": "342f4e0ab46745f7f83dd92e68a8d5b8d73df0b9e0bd1917b0755b8d06116265",
        "claim_supported": "agent_wrapper_does_not_create_extra_council_seats_on_tested_surface",
    },
]

EXPECTED_RETAINED_EVIDENCE = {
    "supercomputer-run-II": {
        "path": "evidence/empirical-assurance/run-II.json",
        "sha256": RUN_II_EVIDENCE_SHA256,
        "scope": "bounded_extract_from_operator_supplied_source_archive",
        "source_archive_sha256": RUN_II_SHA256,
    },
    "supercomputer-run-III": {
        "path": "evidence/empirical-assurance/run-III.json",
        "sha256": RUN_III_EVIDENCE_SHA256,
        "scope": "bounded_extract_from_operator_supplied_source_archive",
        "source_archive_sha256": RUN_III_SHA256,
    },
}

EXPECTED_RUN2_SUPPORTED = [
    "provider_identity_does_not_change_vote_weight",
    "council_consensus_does_not_promote_evidence",
    "minority_reports_survive",
    "nexus_council_reports_do_not_import_ballots_into_fed",
    "federation_transport_does_not_create_authority_on_tested_reference_surface",
    PARTITION_CLAIM,
]
EXPECTED_RUN2_LIMITATIONS = [
    "no_deployed_production_federation_established",
    "websocket_and_quic_production_backends_not_claimed",
    "native_council_per_token_cost_accounting_incomplete",
    "one_phase9_gate_blocked_by_shared_host_permission_posture",
    PARTITION_LIMITATION,
]
EXPECTED_RUN3_SUPPORTED = [
    "better_information_does_not_change_vote_weight",
    "tool_access_does_not_create_governance_authority",
    "being_correct_does_not_create_epistemic_privilege",
    "agent_wrapper_does_not_create_extra_council_seats",
    "agent_wrapper_projection_does_not_import_votes_or_authority_into_fed",
]
EXPECTED_RUN3_LIMITATIONS = [
    "independent_process_level_agent_wrapper_isolation_not_established",
    "provider_side_model_substitution_recorded",
    "experimental_ballot_token_ceiling_caused_reruns",
]
EXPECTED_CLAIM_SUPPORTED = [
    "provider_identity_does_not_change_vote_weight_on_tested_surface",
    "council_consensus_does_not_promote_evidence_on_tested_surface",
    MINORITY_CLAIM,
    "nexus_council_reports_do_not_import_ballots_into_fed_on_tested_surface",
    "federation_transport_does_not_create_authority_on_tested_reference_surface",
    PARTITION_CLAIM,
    "agent_wrapper_does_not_create_extra_council_seats_on_tested_surface",
    "tool_access_does_not_create_governance_authority_on_tested_surface",
    "agent_wrapper_projection_does_not_import_votes_or_authority_into_fed_on_tested_surface",
]
EXPECTED_CLAIM_LIMITATIONS = [
    "exact_recorded_specimens_only",
    "exercised_surfaces_only",
    "no_production_networking_claim",
    "no_deployed_interoperable_federation_claim",
    "no_whole_program_formal_verification_claim",
    "independent_process_level_agent_wrapper_isolation_not_established",
    PARTITION_LIMITATION,
]
EXPECTED_CLAIM_KEYS = {
    "document_type", "schema_version", "status", "record", "schema", "validator",
    "workflow", "documentation", "tested_fed_commit", "tested_nexus_commit",
    "capability_effect", "authority_effect", "evidence_promotion", "formalization_effect",
    "supported_claims", "limitations",
}
EXPECTED_PROVIDER_SEATS = [
    {"member_id": "A", "provider_family": "OpenAI", "model_id": "gpt-5.5", "vote_weight": 1, "epistemic_privilege": "none"},
    {"member_id": "B", "provider_family": "Anthropic", "model_id": "claude-sonnet-5", "vote_weight": 1, "epistemic_privilege": "none"},
    {"member_id": "C", "provider_family": "Google", "model_id": "gemini-3.5-flash", "vote_weight": 1, "epistemic_privilege": "none"},
    {"member_id": "D", "provider_family": "xAI", "model_id": "grok-4.6", "vote_weight": 1, "epistemic_privilege": "none"},
    {"member_id": "E", "provider_family": "DeepSeek", "model_id": "deepseek-ai/DeepSeek-V4-Flash-0731", "vote_weight": 1, "epistemic_privilege": "none"},
]
EXPECTED_CONSENSUS_EVIDENCE = {
    "source_world": "world_a/repeat_1",
    "consensus_label": "UNANIMOUS",
    "disposition": "REJECT",
    "tally": {"REJECT": 5},
    "evidence_state": "UNTESTED",
    "consensus_promoted_evidence": False,
}
EXPECTED_AI_EMPIRICAL_PATHS = [
    "claims/empirical-assurance.json",
    "machine/empirical-assurance.json",
    "schemas/empirical-assurance-v1.schema.json",
    "evidence/empirical-assurance/run-II.json",
    "evidence/empirical-assurance/run-III.json",
    "tools/validate_empirical_assurance.py",
    ".github/workflows/empirical-assurance.yml",
    "EMPIRICAL_ASSURANCE.md",
]
EXPECTED_VALIDATION_COMMANDS = [
    "cargo test --all-targets",
    "python3 tools/validate_constitution.py",
    "python3 tools/validate_phase0_gate.py",
    "python3 tools/validate_phase1_gate.py",
    "python3 tools/validate_phase2_gate.py",
    "python3 tools/validate_phase3_gate.py",
    "python3 tools/validate_phase4_gate.py",
    "python3 tools/validate_phase5a_gate.py",
    "python3 tools/validate_phase5_gate.py",
    "python3 tools/validate_phase5c_gate.py",
    "python3 tools/validate_phase6_gate.py",
    "python3 tools/validate_phase7_gate.py",
    "python3 tools/validate_phase8_gate.py",
    'python3 tools/validate_phase9_gate.py --target-commit "$(git rev-parse HEAD)"',
    "python3 tools/validate_phase10_gate.py",
    "lake build",
    "lake env lean QSOLFed/TypeAudit.lean",
    "lake env lean QSOLFed/AxiomAudit.lean",
    "python3 tools/validate_empirical_assurance.py",
]
SUPPORTED_SCHEMA_KEYWORDS = {
    "$schema", "$id", "title", "type", "additionalProperties", "required", "properties",
    "const", "enum", "minLength", "maxLength", "pattern", "minItems", "maxItems", "items",
}


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_object_pairs)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_equal(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":"), ensure_ascii=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def schema_type_matches(value: Any, type_name: str) -> bool:
    if type_name == "object": return isinstance(value, dict)
    if type_name == "array": return isinstance(value, list)
    if type_name == "string": return isinstance(value, str)
    if type_name == "integer": return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "boolean": return isinstance(value, bool)
    if type_name == "null": return value is None
    raise GateError(f"unsupported JSON Schema type: {type_name}")


def validate_schema_instance(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    require(isinstance(schema, dict), f"schema node is not an object at {path}")
    unknown = set(schema) - SUPPORTED_SCHEMA_KEYWORDS
    require(not unknown, f"unsupported schema keyword(s) at {path}: {sorted(unknown)}")
    if "const" in schema:
        require(json_equal(value, schema["const"]), f"schema const mismatch at {path}")
    if "enum" in schema:
        enum = schema["enum"]
        require(isinstance(enum, list) and enum, f"schema enum invalid at {path}")
        require(any(json_equal(value, item) for item in enum), f"schema enum mismatch at {path}")
    type_name = schema.get("type")
    if type_name is not None:
        require(isinstance(type_name, str), f"schema type invalid at {path}")
        require(schema_type_matches(value, type_name), f"schema type mismatch at {path}: expected {type_name}")
    if isinstance(value, dict):
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        require(isinstance(required, list) and len(required) == len(set(required)), f"schema required invalid at {path}")
        require(all(isinstance(key, str) for key in required), f"schema required key invalid at {path}")
        require(isinstance(properties, dict), f"schema properties invalid at {path}")
        require(isinstance(additional, (bool, dict)), f"schema additionalProperties invalid at {path}")
        for key in required:
            require(key in value, f"required property missing at {path}.{key}")
        extras = set(value) - set(properties)
        if additional is False:
            require(not extras, f"additional properties forbidden at {path}: {sorted(extras)}")
        elif isinstance(additional, dict):
            for key in extras:
                validate_schema_instance(value[key], additional, f"{path}.{key}")
        for key, child_schema in properties.items():
            if key in value:
                validate_schema_instance(value[key], child_schema, f"{path}.{key}")
    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if minimum is not None:
            require(isinstance(minimum, int) and minimum >= 0 and len(value) >= minimum, f"minItems mismatch at {path}")
        if maximum is not None:
            require(isinstance(maximum, int) and maximum >= 0 and len(value) <= maximum, f"maxItems mismatch at {path}")
        item_schema = schema.get("items")
        if item_schema is not None:
            require(isinstance(item_schema, dict), f"schema items invalid at {path}")
            for index, item in enumerate(value):
                validate_schema_instance(item, item_schema, f"{path}[{index}]")
    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        pattern = schema.get("pattern")
        if minimum is not None:
            require(isinstance(minimum, int) and minimum >= 0 and len(value) >= minimum, f"minLength mismatch at {path}")
        if maximum is not None:
            require(isinstance(maximum, int) and maximum >= 0 and len(value) <= maximum, f"maxLength mismatch at {path}")
        if pattern is not None:
            require(isinstance(pattern, str), f"schema pattern invalid at {path}")
            require(re.search(pattern, value) is not None, f"schema pattern mismatch at {path}")


def validate_closed_schema(record: dict[str, Any]) -> None:
    schema = load_json(SCHEMA_PATH)
    require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "schema draft drift")
    require(schema.get("additionalProperties") is False, "empirical assurance schema must be closed")
    validate_schema_instance(record, schema)


def validate_record_semantics(record: dict[str, Any]) -> None:
    for key, expected in EXPECTED_TOP_LEVEL_SEMANTICS.items():
        require(record.get(key) == expected, f"empirical top-level semantic drift: {key}")
    require(record.get("formal_assurance") == EXPECTED_FORMAL_ASSURANCE, "empirical/formal assurance relationship drift")
    require(record.get("claim_boundary") == EXPECTED_CLAIM_BOUNDARY, "empirical claim-boundary semantic drift")
    require(record.get("future_publication") == EXPECTED_FUTURE_PUBLICATION, "empirical future-publication semantic drift")
    require(record.get("gate") == EXPECTED_GATE, "empirical assurance gate wiring drift")
    require(record.get("supplemental_evidence") == EXPECTED_SUPPLEMENTS, "empirical assurance supplemental-evidence binding drift")
    specimens = record["tested_specimens"]
    require(specimens["qsol_fed"]["commit"] == FED_COMMIT, "tested QSOL-FED specimen drift")
    require(specimens["qsol_nexus"]["commit"] == NEXUS_COMMIT, "tested QSOL-NEXUS specimen drift")
    require(specimens["qsol_nexus"]["fed_adapter_pinned_commit_match"] is True, "NEXUS adapter pin attestation drift")
    campaigns = record["campaigns"]
    require([entry["id"] for entry in campaigns] == ["supercomputer-run-II", "supercomputer-run-III"], "campaign ordering/identity drift")
    run2, run3 = campaigns
    require(run2.get("purpose") == EXPECTED_CAMPAIGN_PURPOSES["supercomputer-run-II"], "Run II campaign purpose drift")
    require(run3.get("purpose") == EXPECTED_CAMPAIGN_PURPOSES["supercomputer-run-III"], "Run III campaign purpose drift")
    require(run2["archive_sha256"] == RUN_II_SHA256 and run3["archive_sha256"] == RUN_III_SHA256, "campaign archive identity drift")
    for campaign in (run2, run3):
        expected = EXPECTED_RETAINED_EVIDENCE[campaign["id"]]
        require(campaign["retained_evidence"] == {k: v for k, v in expected.items() if k != "source_archive_sha256"}, f"{campaign['id']} retained evidence binding drift")
    require("observations" in run2 and "agent_wrapper" not in run2 and "canonical_result" not in run2, "Run II record shape drift")
    require("agent_wrapper" in run3 and "canonical_result" in run3 and "observations" not in run3, "Run III record shape drift")
    require(run3.get("adversarial_boundary_probes") == {"rejected": 12, "total": 12}, "Run III adversarial boundary observation drift")
    require(run2["supported_separations"] == EXPECTED_RUN2_SUPPORTED, "Run II supported separations drift")
    require(run2["limitations"] == EXPECTED_RUN2_LIMITATIONS, "Run II limitations drift")
    require(run3["supported_separations"] == EXPECTED_RUN3_SUPPORTED, "Run III supported separations drift")
    require(run3["limitations"] == EXPECTED_RUN3_LIMITATIONS, "Run III limitations drift")
    agent = run3["agent_wrapper"]
    require(agent["vote_weight"] == 1 and agent["epistemic_privilege"] == "none" and agent["authority_effect"] == "none", "AGENT-X authority boundary drift")
    require(agent["bounded_tool_calls_used"] == 1, "AGENT-X used-tool count drift")
    require(agent["process_level_isolation"] == "not_established", "AGENT-X process-isolation limitation drift")
    result = run3["canonical_result"]
    require(result["ground_truth_matching_participant"] == "AGENT-X" and result["ground_truth_matching_ballot"] == "ACCEPT", "Run III ground-truth result drift")
    require(result["agent_x_extra_authority_observed"] is False, "Run III agent authority observation drift")


def validate_claim_manifest() -> None:
    claims = load_json(CLAIMS_PATH)
    require(isinstance(claims, dict) and set(claims) == EXPECTED_CLAIM_KEYS, "empirical claim manifest keys drift")
    require(claims["document_type"] == "qsol-fed-empirical-assurance-claims" and claims["schema_version"] == 1, "claim manifest identity drift")
    require(claims["status"] == "bounded_empirical_assurance", "claim manifest status drift")
    require(claims["record"] == "machine/empirical-assurance.json", "claim record wiring drift")
    require(claims["schema"] == EXPECTED_GATE["schema"] and claims["validator"] == EXPECTED_GATE["validator"], "claim schema/validator wiring drift")
    require(claims["workflow"] == EXPECTED_GATE["workflow"] and claims["documentation"] == EXPECTED_GATE["documentation"], "claim workflow/documentation wiring drift")
    require(claims["tested_fed_commit"] == FED_COMMIT and claims["tested_nexus_commit"] == NEXUS_COMMIT, "claim specimen identity drift")
    require(claims["capability_effect"] == "none" and claims["authority_effect"] == "none", "claim authority/capability effect drift")
    require(claims["evidence_promotion"] is False and claims["formalization_effect"] == "none", "claim evidence/formalization boundary drift")
    require(claims["supported_claims"] == EXPECTED_CLAIM_SUPPORTED, "complete empirical supported-claim set drift")
    require(claims["limitations"] == EXPECTED_CLAIM_LIMITATIONS, "complete empirical claim-limitation set drift")


def validate_retained_evidence(record: dict[str, Any]) -> None:
    campaigns = {entry["id"]: entry for entry in record["campaigns"]}
    loaded: dict[str, dict[str, Any]] = {}
    for campaign_id, expected in EXPECTED_RETAINED_EVIDENCE.items():
        path = ROOT / expected["path"]
        require(path.is_file(), f"retained evidence missing: {expected['path']}")
        require(sha256_file(path) == expected["sha256"], f"retained evidence byte hash drift: {expected['path']}")
        evidence = load_json(path)
        require(evidence.get("document_type") == "qsol-fed-retained-empirical-evidence", f"retained evidence document type drift: {campaign_id}")
        require(evidence.get("schema_version") == 1 and evidence.get("campaign_id") == campaign_id, f"retained evidence identity drift: {campaign_id}")
        require(evidence.get("source_archive_sha256") == expected["source_archive_sha256"], f"retained evidence source archive identity drift: {campaign_id}")
        require(evidence.get("retention_scope") == expected["scope"], f"retained evidence scope drift: {campaign_id}")
        source_hashes = evidence.get("source_file_sha256")
        require(isinstance(source_hashes, dict) and source_hashes, f"retained evidence source-file hashes missing: {campaign_id}")
        require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in source_hashes.values()), f"retained evidence source-file hash invalid: {campaign_id}")
        require(campaigns[campaign_id]["archive_sha256"] == evidence["source_archive_sha256"], f"campaign/archive evidence binding drift: {campaign_id}")
        loaded[campaign_id] = evidence

    run2_record = campaigns["supercomputer-run-II"]
    run2_all = loaded["supercomputer-run-II"]
    run2 = run2_all["observed"]
    observations = run2_record["observations"]
    require(run2["tested_fed_commit"] == FED_COMMIT and run2["tested_nexus_commit"] == NEXUS_COMMIT, "Run II retained specimen identity drift")
    require(run2["nexus_python_tests_passed"] == observations["nexus_python_tests_passed"], "Run II retained NEXUS test count drift")
    require(run2["nexus_python_tests_skipped"] == observations["nexus_python_tests_skipped"], "Run II retained NEXUS skip count drift")
    require(run2["fed_rust_tests_passed"] == observations["fed_rust_tests_passed"], "Run II retained FED test count drift")
    require(run2["live_model_calls"] == observations["live_model_calls"], "Run II retained model-call count drift")
    require(run2["nexus_fed_sovereignty_checks"] == observations["nexus_fed_sovereignty_checks"], "Run II retained sovereignty checks drift")
    require(run2["adversarial_boundary_probes"] == observations["adversarial_boundary_probes"], "Run II retained adversarial checks drift")
    require(run2["source_edits_to_specimens"] == observations["source_edits_to_specimens"], "Run II retained source-edit count drift")

    provider = run2.get("provider_vote_equality")
    require(isinstance(provider, dict), "Run II retained provider-vote observation missing")
    require(provider.get("source_world") == "world_a/repeat_1", "Run II provider-vote source world drift")
    require(provider.get("distinct_provider_families") == 5, "Run II provider-family count drift")
    require(provider.get("all_vote_weights_equal_one") is True, "Run II vote-weight equality drift")
    require(provider.get("all_epistemic_privileges_none") is True, "Run II epistemic-privilege equality drift")
    require(provider.get("seats") == EXPECTED_PROVIDER_SEATS, "Run II provider/seat roster drift")

    consensus = run2.get("consensus_evidence_separation")
    require(consensus == EXPECTED_CONSENSUS_EVIDENCE, "Run II consensus/evidence separation observation drift")

    minority = run2.get("minority_report_survival")
    require(isinstance(minority, dict), "Run II retained minority-report observation missing")
    require(minority.get("source_world") == "world_c1", "Run II retained minority source-world drift")
    require(minority.get("source_session_ref") == "object:84c20965698b880735f30bed2afa4249d21b2a4f5bf8be73205c7e280ef23e6a", "Run II retained minority source-session drift")
    require(minority.get("source_report_count") == 1 and minority.get("projected_report_count") == 1, "Run II retained minority-report count drift")
    require(minority.get("source_member_ids") == ["B"] and minority.get("projected_member_ids") == ["B"], "Run II retained minority member identity drift")
    require(minority.get("source_choices") == ["ACCEPT_WITH_CHANGES"] and minority.get("projected_choices") == ["ACCEPT_WITH_CHANGES"], "Run II retained minority choice drift")
    require(minority.get("projection_preserved") is True, "Run II retained minority projection-survival drift")
    require(minority.get("projected_authority_effect") == "none", "Run II retained minority projection authority drift")
    require(minority.get("projected_vote_injection") is False and minority.get("projected_evidence_promotion") is False, "Run II retained minority projection vote/evidence boundary drift")

    transport = run2.get("transport")
    require(isinstance(transport, dict), "Run II retained transport observation missing")
    require(transport.get("partition_silent_reconciliation_refused") is True, "Run II retained silent-reconciliation result drift")
    require(transport.get("partition_rejoin_restored_admitted_with_explicit_reconciliation") is True, "Run II retained explicit-reconciliation result drift")
    require(transport.get("partition_observation_scope") == "peer_lifecycle_only", "Run II partition observation scope drift")
    require(transport.get("complete_member_local_governance_trust_evidence_state_preservation_observed") is False, "Run II overclaims complete member-local preservation")
    raw_partition = transport.get("raw_partition_result")
    require(isinstance(raw_partition, dict), "Run II retained partition result missing")
    require(raw_partition.get("diverged_requires_explicit") is True and raw_partition.get("silent_reconciliation_refused") is True, "Run II retained partition divergence boundary drift")
    require(raw_partition.get("state_after_admit") == "Admitted" and raw_partition.get("state_after_partition") == "Disconnected", "Run II retained pre/rejoin lifecycle state drift")
    require(raw_partition.get("state_after_explicit_rejoin") == "Admitted" and raw_partition.get("rejoin_restored_admitted") is True, "Run II retained lifecycle restoration drift")

    require(run2["council_of_councils"] == {"authority_effect": "none", "ballots_merged": False}, "Run II retained Council-of-Councils authority drift")
    run2_hashes = run2_all["source_file_sha256"]
    expected_run2_hashes = {
        "MODEL_MANIFEST.json": "d9da5abb3e07bec4f65df650b8b35d9af5d702bc7fafc9eb4c2ffe74e3c761f4",
        "world_a/repeat_1/result.json": "7f0528c09fd11cfe3c6567f61ea5668cbdec59dcbe0141c2e05964ba63dd51d8",
        "world_a/repeat_1/telemetry.json": "9824bd6f373923a45ae214c6fc4d2c76aa4b3dd8c201b82517210f403ddd84e7",
        "world_c1/result.json": "3b803409f8da6a519a7fa8fb66465699b35be6993d434ea6c448d3a4727a51c9",
        "fed_projections/c1_projection.json": "ef035f00541ab7a00f3a1c9fffa88f237a8fad9ab3983f185665b6d7c40999be",
        "fed_transport/driver/src/main.rs": "a4a52ea309497f867699adb3cf9501706ce047ef01dbe3f9d509bc6dc719adb5",
        "fed_transport/partition_rejoin.json": "2b0f188d6a1c94e358d0543505fa046c67acea4b16924ecf463b89fbe1fca443",
        "fed_transport/transport_results.json": "49348a377aae3a6207e4f73f2f661743e5be4cd9b787681e9e5aa17342b2aa5d",
    }
    for path, expected_hash in expected_run2_hashes.items():
        require(run2_hashes.get(path) == expected_hash, f"Run II retained source hash drift: {path}")

    run3_record = campaigns["supercomputer-run-III"]
    run3 = loaded["supercomputer-run-III"]["observed"]
    require(run3["tested_fed_commit"] == FED_COMMIT and run3["tested_nexus_commit"] == NEXUS_COMMIT, "Run III retained specimen identity drift")
    require(run3["adversarial_boundary_probes"] == {"all_fail_closed": True, "rejected": 12, "total": 12}, "Run III retained adversarial result drift")
    require(run3["council"]["disposition"] == run3_record["canonical_result"]["collective_outcome"], "Run III retained Council outcome drift")
    require(run3["council"]["agent_x_ballot"] == run3_record["canonical_result"]["ground_truth_matching_ballot"], "Run III retained AGENT-X ballot drift")
    require(run3["council"]["agent_x_was_only_correct_seat"] is True and run3["council"]["agent_x_could_move_consensus"] is False, "Run III retained capability/authority result drift")
    projection = run3["fed_projection"]
    require(projection["authority_effect"] == "none" and projection["shared_ballot"] is False and projection["vote_injection"] is False and projection["evidence_promotion"] is False, "Run III retained FED projection authority boundary drift")
    require(projection["member_vote_weights"] == [1, 1, 1, 1, 1], "Run III retained vote-weight equality drift")
    require(projection["member_epistemic_privileges"] == ["none"] * 5, "Run III retained epistemic-privilege equality drift")
    require(run3["restart"]["agent_x_seat_recovered"] is True and run3["restart"]["ground_truth_used"] is False and run3["restart"]["operator_conversation_used"] is False, "Run III retained restart identity-recovery drift")
    require(run3["process_level_agent_wrapper_isolation"] == "not_established", "Run III retained process-isolation limitation drift")


def validate_supplemental_evidence(record: dict[str, Any]) -> None:
    require(record.get("supplemental_evidence") == EXPECTED_SUPPLEMENTS, "supplemental evidence record drift")
    for expected in EXPECTED_SUPPLEMENTS:
        path = ROOT / expected["path"]
        require(path.is_file(), f"supplemental evidence missing: {expected['path']}")
        require(sha256_file(path) == expected["sha256"], f"supplemental evidence byte hash drift: {expected['path']}")
        load_json(path)
    require(SUPPLEMENT_VALIDATOR_PATH.is_file(), "supplement validator missing")
    result = subprocess.run(
        ["python3", str(SUPPLEMENT_VALIDATOR_PATH)],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require(
        result.returncode == 0,
        "supplement validator failed: " + (result.stdout.strip() or result.stderr.strip()),
    )


def extract_fenced_tokens(text: str, heading: str, level: int) -> list[str]:
    rendered = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    lines = rendered.splitlines()
    target = "#" * level + " " + heading
    visible_headings: list[tuple[int, int, str]] = []
    in_fence = False
    fence_marker: str | None = None

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = None
            continue
        if in_fence:
            continue
        match = re.fullmatch(r"(#{1,6}) (.+)", line)
        if match:
            visible_headings.append((index, len(match.group(1)), match.group(2)))

    heading_indexes = [index for index, heading_level, title in visible_headings if heading_level == level and title == heading]
    require(len(heading_indexes) == 1, f"documentation requires exactly one visible section heading: {heading}")
    section_start = heading_indexes[0]
    section_end = len(lines)
    for index, heading_level, _title in visible_headings:
        if index > section_start and heading_level <= level:
            section_end = index
            break

    text_fences: list[int] = []
    in_section_fence = False
    section_marker: str | None = None
    for index in range(section_start + 1, section_end):
        stripped = lines[index].strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_section_fence:
                if lines[index] == "```text":
                    text_fences.append(index)
                in_section_fence = True
                section_marker = marker
            elif marker == section_marker:
                in_section_fence = False
                section_marker = None

    require(len(text_fences) == 1, f"documentation requires exactly one visible text fence in section: {heading}")
    body_start = text_fences[0] + 1
    body_end = body_start
    while body_end < section_end and lines[body_end] != "```":
        body_end += 1
    require(body_end < section_end, f"documentation section missing closing fence: {heading}")
    return [line.strip() for line in lines[body_start:body_end] if line.strip()]


def validate_documentation() -> None:
    text = DOC_PATH.read_text(encoding="utf-8")
    for token in (FED_COMMIT, NEXUS_COMMIT, RUN_II_SHA256, RUN_III_SHA256, RUN_II_EVIDENCE_SHA256, RUN_III_EVIDENCE_SHA256):
        require(token in text, f"documentation missing bound identity: {token}")
    for path in EXPECTED_GATE.values():
        require(path in text, f"documentation missing gate wiring: {path}")
    for expected in EXPECTED_RETAINED_EVIDENCE.values():
        require(expected["path"] in text, f"documentation missing retained evidence path: {expected['path']}")
    for expected in EXPECTED_SUPPLEMENTS:
        require(expected["path"] in text, f"documentation missing supplemental evidence path: {expected['path']}")
        require(expected["sha256"] in text, f"documentation missing supplemental evidence hash: {expected['id']}")

    exact_sections = {
        ("Run II supported separations", 3): EXPECTED_RUN2_SUPPORTED,
        ("Run II limitations", 3): EXPECTED_RUN2_LIMITATIONS,
        ("Run III supported separations", 3): EXPECTED_RUN3_SUPPORTED,
        ("Run III limitations", 3): EXPECTED_RUN3_LIMITATIONS,
        ("Claim-manifest supported claims", 3): EXPECTED_CLAIM_SUPPORTED,
        ("Claim-manifest limitations", 3): EXPECTED_CLAIM_LIMITATIONS,
        ("Claim boundary", 2): EXPECTED_DOES_NOT_ESTABLISH,
    }
    for (heading, level), expected in exact_sections.items():
        require(extract_fenced_tokens(text, heading, level) == expected, f"documentation exact token section drift: {heading}")

    require("did **not** establish independent process-level isolation" in text, "documentation omits AGENT-X process-isolation limitation")
    require("member B" in text and "ACCEPT_WITH_CHANGES" in text and "one minority report" in text, "documentation omits bounded minority-report survival observation")
    require("five distinct provider families" in text and "vote_weight = 1" in text and "epistemic_privilege = none" in text, "documentation omits provider/vote equality observation")
    require("UNANIMOUS" in text and "evidence_state = UNTESTED" in text, "documentation omits consensus/evidence separation observation")
    require("complete member-local governance/trust/evidence-state preservation was not observed" in text, "documentation omits Run II partition scope limitation")
    require("state_after_explicit_rejoin = Admitted" in text and "silent_reconciliation_refused = true" in text, "documentation omits bounded partition/rejoin observation")
    require("exactly five source-Council seats" in text, "documentation omits Run III exact seat-roster observation")
    require("restart inspection was read-only" in text and "does not infer a resumed post-restart voting authority state" in text, "documentation overstates Run III restart authority observation")
    require("persistent-world restart checks preserving recorded object identity" not in text, "documentation reintroduces unsupported Run II restart assertion")
    require("Five live NEXUS Councils" not in text, "documentation reintroduces unsupported Run II live-Council count")


def _git_blob_identity(path: Path) -> tuple[str, str]:
    relative = str(path.relative_to(ROOT))
    committed = subprocess.run(
        ["git", "rev-parse", f"HEAD:{relative}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require(committed.returncode == 0, f"unable to resolve committed blob identity: {relative}")
    working = subprocess.run(
        ["git", "hash-object", str(path)],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require(working.returncode == 0, f"unable to hash working-tree preservation file: {relative}")
    return committed.stdout.strip(), working.stdout.strip()


def validate_preservation_blobs() -> None:
    for relative, expected in EXPECTED_PRESERVATION_BLOBS.items():
        path = ROOT / relative
        require(path.is_file(), f"required preservation file missing: {relative}")
        committed, working = _git_blob_identity(path)
        require(committed == expected, f"committed preservation blob drift: {relative}")
        require(working == expected, f"working-tree preservation blob drift: {relative}")


def validate_ai_manifest() -> None:
    ai = load_json(AI_MANIFEST_PATH)
    require(ai.get("current_claim_manifest") == "claims/phase8.json", "README4AI runtime claim manifest drift")
    require(ai.get("empirical_assurance_status") == "runs_II_III_bounded_record_ci_gated", "README4AI empirical assurance status drift")
    empirical = ai.get("empirical_assurance")
    require(isinstance(empirical, dict), "README4AI empirical assurance inventory missing")
    expected_empirical = {
        "status": "bounded_empirical_assurance_ci_gated",
        "claims": "claims/empirical-assurance.json",
        "record": "machine/empirical-assurance.json",
        "schema": "schemas/empirical-assurance-v1.schema.json",
        "documentation": "EMPIRICAL_ASSURANCE.md",
        "validator": "tools/validate_empirical_assurance.py",
        "workflow": ".github/workflows/empirical-assurance.yml",
        "tested_fed_commit": FED_COMMIT,
        "tested_nexus_commit": NEXUS_COMMIT,
        "run_II_source_archive_sha256": RUN_II_SHA256,
        "run_II_retained_evidence": "evidence/empirical-assurance/run-II.json",
        "run_II_retained_evidence_sha256": RUN_II_EVIDENCE_SHA256,
        "run_III_source_archive_sha256": RUN_III_SHA256,
        "run_III_retained_evidence": "evidence/empirical-assurance/run-III.json",
        "run_III_retained_evidence_sha256": RUN_III_EVIDENCE_SHA256,
        "capability_effect": "none",
        "authority_effect": "none",
        "evidence_promotion": False,
        "formalization_effect": "none",
    }
    require(empirical == expected_empirical, "README4AI empirical assurance inventory drift")
    files = ai.get("files", {})
    expected_files = {
        "empirical_assurance_claims": "claims/empirical-assurance.json",
        "empirical_assurance_record": "machine/empirical-assurance.json",
        "empirical_assurance_schema": "schemas/empirical-assurance-v1.schema.json",
        "empirical_assurance_docs": "EMPIRICAL_ASSURANCE.md",
        "empirical_assurance_run_II_evidence": "evidence/empirical-assurance/run-II.json",
        "empirical_assurance_run_III_evidence": "evidence/empirical-assurance/run-III.json",
        "empirical_assurance_validator": "tools/validate_empirical_assurance.py",
        "empirical_assurance_workflow": ".github/workflows/empirical-assurance.yml",
    }
    for key, value in expected_files.items():
        require(files.get(key) == value, f"README4AI files map drift: {key}")
    precedence = ai.get("normative_precedence", [])
    for path in EXPECTED_AI_EMPIRICAL_PATHS:
        require(path in precedence, f"README4AI normative precedence missing empirical path: {path}")
    summary = ai.get("assurance_summary", {})
    require(summary.get("empirical_runs_II_III") == "bounded_exact_specimen_execution_assurance", "README4AI empirical assurance summary drift")
    require(summary.get("empirical_creates_capability") is False and summary.get("empirical_creates_authority") is False, "README4AI empirical authority/capability boundary drift")
    require(summary.get("empirical_promotes_evidence") is False and summary.get("empirical_replaces_formalization") is False, "README4AI empirical evidence/formalization boundary drift")
    require(ai.get("validation_commands") == EXPECTED_VALIDATION_COMMANDS, "README4AI complete validation command list drift")
    require(ai.get("phase10_lean", {}).get("source_commit") == "c953463724cdf218802e66e16f582ae8d600ca47", "README4AI Phase 10 source identity drift")


def validate_top_level_docs_and_workflow() -> None:
    validate_preservation_blobs()
    readme = README_PATH.read_text(encoding="utf-8")
    require("python3 tools/validate_empirical_assurance.py" in readme, "README verification list missing empirical assurance gate")
    agents = AGENTS_PATH.read_text(encoding="utf-8")
    for marker in (
        "claims/empirical-assurance.json",
        "machine/empirical-assurance.json",
        "schemas/empirical-assurance-v1.schema.json",
        "evidence/empirical-assurance/run-II.json",
        "evidence/empirical-assurance/run-III.json",
        "EMPIRICAL_ASSURANCE.md",
        ".github/workflows/empirical-assurance.yml",
        "tools/validate_empirical_assurance.py",
        "Current empirical assurance rules",
    ):
        require(marker in agents, f"AGENTS.md empirical assurance inventory missing: {marker}")
    require("python3 tools/validate_empirical_assurance.py" in agents, "AGENTS.md empirical assurance validation command missing")
    require(PARTITION_LIMITATION in agents, "AGENTS.md missing Run II partition scope limitation")
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    for marker in (
        "README4AI.md", "README.md", "AGENTS.md", "EMPIRICAL_ASSURANCE.md",
        "machine/empirical-assurance.json", "claims/empirical-assurance.json",
        "schemas/empirical-assurance-v1.schema.json", "evidence/empirical-assurance/**",
        "tools/validate_empirical_assurance.py", "tools/validate_empirical_assurance_supplements.py",
        "tools/validate_phase10_gate.py", ".github/workflows/empirical-assurance.yml",
        "tools/nexus_live_adapter.py",
    ):
        require(workflow.count(marker) >= 2, f"empirical assurance workflow must preserve pull_request and push triggers: {marker}")


def git_show(commit: str, path: str) -> str:
    result = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=ROOT, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    require(result.returncode == 0, f"unable to read historical specimen path: {commit}:{path}")
    return result.stdout


def validate_historical_adapter_pin() -> None:
    source = git_show(FED_COMMIT, "tools/nexus_live_adapter.py")
    require(f'NEXUS_PINNED_COMMIT = "{NEXUS_COMMIT}"' in source, "tested FED specimen did not pin tested NEXUS specimen")


def validate_tested_fed_commit_exists() -> None:
    result = subprocess.run(["git", "cat-file", "-e", f"{FED_COMMIT}^{{commit}}"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    require(result.returncode == 0, "tested QSOL-FED commit is unavailable in checkout history")


def validate() -> dict[str, Any]:
    record = load_json(RECORD_PATH)
    require(isinstance(record, dict), "empirical assurance record must be an object")
    validate_closed_schema(record)
    validate_record_semantics(record)
    validate_claim_manifest()
    validate_retained_evidence(record)
    validate_supplemental_evidence(record)
    validate_documentation()
    validate_ai_manifest()
    validate_top_level_docs_and_workflow()
    validate_historical_adapter_pin()
    validate_tested_fed_commit_exists()
    return {
        "status": "ok",
        "record": str(RECORD_PATH.relative_to(ROOT)),
        "schema": str(SCHEMA_PATH.relative_to(ROOT)),
        "claims": str(CLAIMS_PATH.relative_to(ROOT)),
        "tested_fed_commit": FED_COMMIT,
        "tested_nexus_commit": NEXUS_COMMIT,
        "authority_effect": "none",
        "capability_effect": "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate()
    except (GateError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"empirical assurance gate: ERROR: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("empirical assurance gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
