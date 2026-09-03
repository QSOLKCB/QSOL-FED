#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
PARTITION_CLAIM = "partition_rejoin_requires_explicit_reconciliation_and_preserves_member_local_state_on_tested_reference_surface"

EXPECTED_GATE = {
    "schema": "schemas/empirical-assurance-v1.schema.json",
    "claims": "claims/empirical-assurance.json",
    "validator": "tools/validate_empirical_assurance.py",
    "workflow": ".github/workflows/empirical-assurance.yml",
    "documentation": "EMPIRICAL_ASSURANCE.md",
}

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
    require(run2["archive_sha256"] == RUN_II_SHA256, "Run II archive identity drift")
    require(run3["archive_sha256"] == RUN_III_SHA256, "Run III archive identity drift")
    require("observations" in run2 and "agent_wrapper" not in run2 and "canonical_result" not in run2, "Run II record shape drift")
    require("agent_wrapper" in run3 and "canonical_result" in run3 and "observations" not in run3, "Run III record shape drift")
    require(PARTITION_CLAIM in run2["supported_separations"], "partition reconciliation/member-local preservation claim missing")

    agent = run3["agent_wrapper"]
    require(agent["vote_weight"] == 1 and agent["epistemic_privilege"] == "none" and agent["authority_effect"] == "none", "AGENT-X authority boundary drift")
    require(agent["process_level_isolation"] == "not_established", "AGENT-X process-isolation limitation drift")
    result = run3["canonical_result"]
    require(result["ground_truth_matching_participant"] == "AGENT-X", "Run III ground-truth participant drift")
    require(result["agent_x_extra_authority_observed"] is False, "Run III agent authority observation drift")

    require(record["capability_effect"] == "none", "empirical record must not create capability")
    require(record["authority_effect"] == "none", "empirical record must not create authority")
    require(record["evidence_promotion"] is False, "empirical record must not promote evidence")
    require(record["formal_assurance"]["phase10_remains_separate"] is True, "Phase 10 separation drift")


def validate_claim_manifest(record: dict[str, Any]) -> None:
    claims = load_json(CLAIMS_PATH)
    require(isinstance(claims, dict) and set(claims) == EXPECTED_CLAIM_KEYS, "empirical claim manifest keys drift")
    require(claims["document_type"] == "qsol-fed-empirical-assurance-claims" and claims["schema_version"] == 1, "claim manifest identity drift")
    require(claims["status"] == "bounded_empirical_assurance", "claim manifest status drift")
    require(claims["record"] == EXPECTED_GATE["claims"].replace("claims/empirical-assurance.json", "machine/empirical-assurance.json"), "claim record wiring drift")
    require(claims["schema"] == EXPECTED_GATE["schema"], "claim schema wiring drift")
    require(claims["validator"] == EXPECTED_GATE["validator"], "claim validator wiring drift")
    require(claims["workflow"] == EXPECTED_GATE["workflow"], "claim workflow wiring drift")
    require(claims["documentation"] == EXPECTED_GATE["documentation"], "claim documentation wiring drift")
    require(claims["tested_fed_commit"] == FED_COMMIT and claims["tested_nexus_commit"] == NEXUS_COMMIT, "claim specimen identity drift")
    require(claims["capability_effect"] == "none" and claims["authority_effect"] == "none", "claim authority/capability effect drift")
    require(claims["evidence_promotion"] is False and claims["formalization_effect"] == "none", "claim evidence/formalization boundary drift")
    require(PARTITION_CLAIM in claims["supported_claims"], "claim manifest weakens partition reconciliation boundary")
    require("independent_process_level_agent_wrapper_isolation_not_established" in claims["limitations"], "AGENT-X isolation limitation missing from claims")


def validate_documentation(record: dict[str, Any]) -> None:
    text = DOC_PATH.read_text(encoding="utf-8")
    for token in (FED_COMMIT, NEXUS_COMMIT, RUN_II_SHA256, RUN_III_SHA256):
        require(token in text, f"documentation missing bound identity: {token}")
    for path in EXPECTED_GATE.values():
        require(path in text, f"documentation missing gate wiring: {path}")
    require("current post-Phase-10 documentation head" not in text, "documentation incorrectly describes tested specimen as current head")
    require("requiring explicit reconciliation where state changed and preserving member-local state" in text, "documentation weakens partition reconciliation/member-local-state result")
    require("did **not** establish independent process-level isolation" in text, "documentation omits AGENT-X process-isolation limitation")
    require(str(record["campaigns"][0]["observations"]["live_model_calls"]) in text, "documentation/model-call count drift")


def validate_adapter_pin() -> None:
    source = (ROOT / "tools/nexus_live_adapter.py").read_text(encoding="utf-8")
    require(f'NEXUS_PINNED_COMMIT = "{NEXUS_COMMIT}"' in source, "current FED adapter no longer pins the tested NEXUS specimen")


def validate_tested_fed_commit_exists() -> None:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{FED_COMMIT}^{{commit}}"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    require(result.returncode == 0, "tested QSOL-FED commit is unavailable in checkout history")


def validate() -> dict[str, Any]:
    record = load_json(RECORD_PATH)
    require(isinstance(record, dict), "empirical assurance record must be an object")
    validate_closed_schema(record)
    validate_record_semantics(record)
    validate_claim_manifest(record)
    validate_documentation(record)
    validate_adapter_pin()
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
    except (GateError, OSError, json.JSONDecodeError) as exc:
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
