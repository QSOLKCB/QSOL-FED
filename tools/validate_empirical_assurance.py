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

FED_COMMIT = "1fd643f643636bcb0917f571aff5cdc25439b470"
NEXUS_COMMIT = "24cb0ce246d12ac99e7d190a8890ef2ddd598321"
RUN_II_SHA256 = "0d7a67292062b67473a5483c4a8fa6074378128cb03a60d79651dae091f5b0ec"
RUN_III_SHA256 = "f569b80576b2dba952685577ed68dc2c8293973229dc161f6d63387ceaac475d"
RUN_II_EVIDENCE_SHA256 = "796d1ac580228812d36e41e4b41211a857449151e7cd3181ebac5b66c312940f"
RUN_III_EVIDENCE_SHA256 = "0003e5d31714d05ceeb700679a693fc02fe7ff4f0d4dbe43c2c992ec3a8a92b5"
PARTITION_CLAIM = "partition_rejoin_requires_explicit_reconciliation_and_preserves_member_local_state_on_tested_reference_surface"
MINORITY_CLAIM = "minority_reports_survive_on_tested_surface"

EXPECTED_GATE = {
    "schema": "schemas/empirical-assurance-v1.schema.json",
    "claims": "claims/empirical-assurance.json",
    "validator": "tools/validate_empirical_assurance.py",
    "workflow": ".github/workflows/empirical-assurance.yml",
    "documentation": "EMPIRICAL_ASSURANCE.md",
}

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
]
EXPECTED_RUN3_SUPPORTED = [
    "better_information_does_not_change_vote_weight",
    "tool_access_does_not_create_governance_authority",
    "being_correct_does_not_create_epistemic_privilege",
    "agent_wrapper_does_not_create_extra_council_seats",
    "agent_wrapper_projection_does_not_import_votes_or_authority_into_fed",
    "restart_does_not_promote_agent_authority",
]
EXPECTED_RUN3_LIMITATIONS = [
    "independent_process_level_agent_wrapper_isolation_not_established",
    "provider_side_model_substitution_recorded",
    "experimental_ballot_token_ceiling_caused_reruns",
]
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
]
EXPECTED_CLAIM_KEYS = {
    "document_type", "schema_version", "status", "record", "schema", "validator",
    "workflow", "documentation", "tested_fed_commit", "tested_nexus_commit",
    "capability_effect", "authority_effect", "evidence_promotion", "formalization_effect",
    "supported_claims", "limitations",
}
SUPPORTED_SCHEMA_KEYWORDS = {
    "$schema", "$id", "title", "type", "additionalProperties", "required", "properties",
    "const", "enum", "minLength", "maxLength", "pattern", "minItems", "maxItems", "items",
}


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_equal(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":"), ensure_ascii=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def schema_type_matches(value: Any, type_name: str) -> bool:
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "null":
        return value is None
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
    require(record.get("gate") == EXPECTED_GATE, "empirical assurance gate wiring drift")
    specimens = record["tested_specimens"]
    require(specimens["qsol_fed"]["commit"] == FED_COMMIT, "tested QSOL-FED specimen drift")
    require(specimens["qsol_nexus"]["commit"] == NEXUS_COMMIT, "tested QSOL-NEXUS specimen drift")
    require(specimens["qsol_nexus"]["fed_adapter_pinned_commit_match"] is True, "NEXUS adapter pin attestation drift")
    campaigns = record["campaigns"]
    require([entry["id"] for entry in campaigns] == ["supercomputer-run-II", "supercomputer-run-III"], "campaign ordering/identity drift")
    run2, run3 = campaigns
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
    require(record["claim_boundary"]["does_not_establish"] == EXPECTED_DOES_NOT_ESTABLISH, "claim-boundary limitation list drift")
    agent = run3["agent_wrapper"]
    require(agent["vote_weight"] == 1 and agent["epistemic_privilege"] == "none" and agent["authority_effect"] == "none", "AGENT-X authority boundary drift")
    require(agent["process_level_isolation"] == "not_established", "AGENT-X process-isolation limitation drift")
    result = run3["canonical_result"]
    require(result["ground_truth_matching_participant"] == "AGENT-X" and result["ground_truth_matching_ballot"] == "ACCEPT", "Run III ground-truth result drift")
    require(result["agent_x_extra_authority_observed"] is False, "Run III agent authority observation drift")
    require(record["capability_effect"] == "none" and record["authority_effect"] == "none", "empirical record authority/capability effect drift")
    require(record["evidence_promotion"] is False, "empirical record must not promote evidence")
    require(record["formal_assurance"]["phase10_remains_separate"] is True, "Phase 10 separation drift")


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
    run2 = loaded["supercomputer-run-II"]["observed"]
    observations = run2_record["observations"]
    require(run2["tested_fed_commit"] == FED_COMMIT and run2["tested_nexus_commit"] == NEXUS_COMMIT, "Run II retained specimen identity drift")
    require(run2["nexus_python_tests_passed"] == observations["nexus_python_tests_passed"], "Run II retained NEXUS test count drift")
    require(run2["nexus_python_tests_skipped"] == observations["nexus_python_tests_skipped"], "Run II retained NEXUS skip count drift")
    require(run2["fed_rust_tests_passed"] == observations["fed_rust_tests_passed"], "Run II retained FED test count drift")
    require(run2["live_model_calls"] == observations["live_model_calls"], "Run II retained model-call count drift")
    require(run2["nexus_fed_sovereignty_checks"] == observations["nexus_fed_sovereignty_checks"], "Run II retained sovereignty checks drift")
    require(run2["adversarial_boundary_probes"] == observations["adversarial_boundary_probes"], "Run II retained adversarial checks drift")
    require(run2["source_edits_to_specimens"] == observations["source_edits_to_specimens"], "Run II retained source-edit count drift")
    require(run2["transport"]["partition_silent_reconciliation_refused"] is True, "Run II retained silent-reconciliation result drift")
    require(run2["transport"]["partition_rejoin_restored_admitted_with_explicit_reconciliation"] is True, "Run II retained explicit-reconciliation result drift")
    require(run2["transport"]["raw_partition_result"]["diverged_requires_explicit"] is True, "Run II retained partition divergence boundary drift")
    require(run2["council_of_councils"] == {"authority_effect": "none", "ballots_merged": False}, "Run II retained Council-of-Councils authority drift")

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
    run2_hashes = loaded["supercomputer-run-II"]["source_file_sha256"]
    require(run2_hashes.get("world_c1/result.json") == "3b803409f8da6a519a7fa8fb66465699b35be6993d434ea6c448d3a4727a51c9", "Run II minority source file hash drift")
    require(run2_hashes.get("fed_projections/c1_projection.json") == "ef035f00541ab7a00f3a1c9fffa88f237a8fad9ab3983f185665b6d7c40999be", "Run II minority projection file hash drift")

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
    require(run3["restart"]["agent_x_seat_recovered"] is True and run3["restart"]["ground_truth_used"] is False and run3["restart"]["operator_conversation_used"] is False, "Run III retained restart boundary drift")
    require(run3["process_level_agent_wrapper_isolation"] == "not_established", "Run III retained process-isolation limitation drift")


def validate_documentation() -> None:
    text = DOC_PATH.read_text(encoding="utf-8")
    for token in (FED_COMMIT, NEXUS_COMMIT, RUN_II_SHA256, RUN_III_SHA256, RUN_II_EVIDENCE_SHA256, RUN_III_EVIDENCE_SHA256):
        require(token in text, f"documentation missing bound identity: {token}")
    for path in EXPECTED_GATE.values():
        require(path in text, f"documentation missing gate wiring: {path}")
    for expected in EXPECTED_RETAINED_EVIDENCE.values():
        require(expected["path"] in text, f"documentation missing retained evidence path: {expected['path']}")
    sync_tokens = (
        EXPECTED_RUN2_SUPPORTED + EXPECTED_RUN2_LIMITATIONS + EXPECTED_RUN3_SUPPORTED + EXPECTED_RUN3_LIMITATIONS +
        EXPECTED_DOES_NOT_ESTABLISH + EXPECTED_CLAIM_SUPPORTED + EXPECTED_CLAIM_LIMITATIONS
    )
    for token in sync_tokens:
        require(token in text, f"documentation missing synchronized assurance token: {token}")
    require("current post-Phase-10 documentation head" not in text, "documentation incorrectly describes tested specimen as current head")
    require("requiring explicit reconciliation where state changed and preserving member-local state" in text, "documentation weakens partition reconciliation/member-local-state result")
    require("did **not** establish independent process-level isolation" in text, "documentation omits AGENT-X process-isolation limitation")
    require("member B" in text and "ACCEPT_WITH_CHANGES" in text and "one minority report" in text, "documentation omits bounded minority-report survival observation")


def git_show(commit: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"], cwd=ROOT, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    require(result.returncode == 0, f"unable to read historical specimen path: {commit}:{path}")
    return result.stdout


def validate_historical_adapter_pin() -> None:
    source = git_show(FED_COMMIT, "tools/nexus_live_adapter.py")
    require(f'NEXUS_PINNED_COMMIT = "{NEXUS_COMMIT}"' in source, "tested FED specimen did not pin tested NEXUS specimen")


def validate_tested_fed_commit_exists() -> None:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{FED_COMMIT}^{{commit}}"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    require(result.returncode == 0, "tested QSOL-FED commit is unavailable in checkout history")


def validate() -> dict[str, Any]:
    record = load_json(RECORD_PATH)
    require(isinstance(record, dict), "empirical assurance record must be an object")
    validate_closed_schema(record)
    validate_record_semantics(record)
    validate_claim_manifest()
    validate_retained_evidence(record)
    validate_documentation()
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
