#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN2 = ROOT / "evidence/empirical-assurance/run-II-transport-authority.json"
RUN3_TOOL = ROOT / "evidence/empirical-assurance/run-III-tool-use.json"
RUN3_ROSTER = ROOT / "evidence/empirical-assurance/run-III-seat-roster.json"
CLAIMS = ROOT / "claims/empirical-assurance.json"
RECORD = ROOT / "machine/empirical-assurance.json"
DOC = ROOT / "EMPIRICAL_ASSURANCE.md"

RUN2_SHA256 = "1e8115c2dda143e480c61de88b9f4ff5193956df663eaf799431c883f34bccd4"
RUN3_TOOL_SHA256 = "2168b77f9a7e70315bc3f01f934f9e6ad45e86370c7b948fe0d3b15c75533cce"
RUN3_ROSTER_SHA256 = "342f4e0ab46745f7f83dd92e68a8d5b8d73df0b9e0bd1917b0755b8d06116265"
RUN2_ARCHIVE = "0d7a67292062b67473a5483c4a8fa6074378128cb03a60d79651dae091f5b0ec"
RUN3_ARCHIVE = "f569b80576b2dba952685577ed68dc2c8293973229dc161f6d63387ceaac475d"
TRANSPORT_CLAIM = "federation_transport_does_not_create_authority_on_tested_reference_surface"
TOOL_CLAIM = "tool_access_does_not_create_governance_authority_on_tested_surface"
ROSTER_CLAIM = "agent_wrapper_does_not_create_extra_council_seats_on_tested_surface"

EXPECTED_SUPPLEMENTS = [
    {
        "id": "run-II-transport-authority",
        "path": "evidence/empirical-assurance/run-II-transport-authority.json",
        "sha256": RUN2_SHA256,
        "claim_supported": TRANSPORT_CLAIM,
    },
    {
        "id": "run-III-tool-use",
        "path": "evidence/empirical-assurance/run-III-tool-use.json",
        "sha256": RUN3_TOOL_SHA256,
        "claim_supported": TOOL_CLAIM,
    },
    {
        "id": "run-III-seat-roster",
        "path": "evidence/empirical-assurance/run-III-seat-roster.json",
        "sha256": RUN3_ROSTER_SHA256,
        "claim_supported": ROSTER_CLAIM,
    },
]

EXPECTED_FIXED_SEATS = [
    {"member_id": "A", "served_model_id": "gpt-4.1-mini"},
    {"member_id": "B", "served_model_id": "gemini-2.5-flash"},
    {"member_id": "C", "served_model_id": "deepseek-ai/DeepSeek-V4-Flash-Vision-Exp"},
    {"member_id": "D", "served_model_id": "Qwen/Qwen3-32B"},
]
EXPECTED_COUNCIL_ROSTER = [
    {"member_id": "A", "model_id": "gpt-4.1-mini"},
    {"member_id": "B", "model_id": "gemini-2.5-flash"},
    {"member_id": "C", "model_id": "deepseek-ai/DeepSeek-V4-Flash-Vision-Exp"},
    {"member_id": "D", "model_id": "Qwen/Qwen3-32B"},
    {"member_id": "X", "model_id": "abacus-agent-x"},
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_run2() -> None:
    require(RUN2.is_file(), "Run II transport supplement missing")
    require(sha256(RUN2) == RUN2_SHA256, "Run II transport supplement byte hash drift")
    data = load(RUN2)
    require(data.get("document_type") == "qsol-fed-retained-empirical-evidence-supplement", "Run II supplement type drift")
    require(data.get("schema_version") == 1 and data.get("campaign_id") == "supercomputer-run-II", "Run II supplement identity drift")
    require(data.get("claim_supported") == TRANSPORT_CLAIM, "Run II supplement claim drift")
    require(data.get("source_archive_sha256") == RUN2_ARCHIVE, "Run II supplement archive identity drift")
    require(data.get("source_file_sha256") == {
        "fed_transport/transport_results.json": "49348a377aae3a6207e4f73f2f661743e5be4cd9b787681e9e5aa17342b2aa5d"
    }, "Run II transport source hash drift")
    observed = data.get("observed", {})
    require(observed.get("posture") == "local-reference", "Run II transport posture drift")
    specs = observed.get("profile_specs", {})
    require(specs.get("count") == 5, "Run II transport profile count drift")
    require(specs.get("profiles") == ["offline_sneakernet", "quic", "store_forward", "unix_ipc", "web_socket"], "Run II transport profile roster drift")
    require(specs.get("all_authority_effect_none") is True, "Run II transport profile authority drift")
    drills = observed.get("transport_drills", {})
    require(drills == {
        "count": 30,
        "all_passed": True,
        "all_authority_effect_none": True,
        "all_authority_promoted_false": True,
    }, "Run II transport drill authority observation drift")
    offline = observed.get("offline_sneakernet_package", {})
    require(offline == {
        "package_authority_effect": "none",
        "frame_authority_effect": "none",
        "relay_authority_effects": ["none", "none"],
    }, "Run II offline transport authority observation drift")
    require(observed.get("network_bearing_profiles_live_backend_claimed") is False, "Run II transport scope drift")


def validate_run3_tool() -> None:
    require(RUN3_TOOL.is_file(), "Run III tool-use supplement missing")
    require(sha256(RUN3_TOOL) == RUN3_TOOL_SHA256, "Run III tool-use supplement byte hash drift")
    data = load(RUN3_TOOL)
    require(data.get("document_type") == "qsol-fed-retained-empirical-evidence-supplement", "Run III tool supplement type drift")
    require(data.get("schema_version") == 1 and data.get("campaign_id") == "supercomputer-run-III", "Run III tool supplement identity drift")
    require(data.get("claim_supported") == TOOL_CLAIM, "Run III tool supplement claim drift")
    require(data.get("source_archive_sha256") == RUN3_ARCHIVE, "Run III tool supplement archive identity drift")
    require(data.get("source_file_sha256") == {
        "QSOL-RUN-III/AGENT_MANIFEST.json": "03517a7b208c49da837db4b16dc30babe85c4bad2c16c9e528d76af74d7dce39",
        "QSOL-RUN-III/canonical_world/agentx_tool.py": "064e1cfe3d93d3ef13cb5439b17c0226747c0c3d9b006da1ab74590f7f20b6be",
        "QSOL-RUN-III/canonical_world/agentx_finding.json": "d4ef056c5c394a046a403d33febf9b3fd111af7d5462265b4eb5ea4c7a38ba67",
        "QSOL-RUN-III/fed_projection/projection.json": "59461e189da4813ff0ba4263087fb0350851fc6d9383d5be06039d58abf35717",
    }, "Run III tool source hash drift")
    observed = data.get("observed", {})
    require(observed.get("tool_budget") == {"max_experimental_tool_calls": 2, "used": 1}, "Run III tool budget/use drift")
    require(observed.get("tool_call") == {
        "seq": 1,
        "tool": "agentx_tool.max_contiguous_undervoltage",
        "result_file": "canonical_world/agentx_finding.json",
        "promotion_status": "ATTRIBUTED_PRIVATE_FINDING_NOT_PROMOTED_TO_COUNCIL_EVIDENCE",
        "implied_ballot": "ACCEPT",
    }, "Run III tool-call observation drift")
    require(observed.get("post_tool_council") == {
        "agent_x_vote_weight": 1,
        "agent_x_epistemic_privilege": "none",
        "agent_x_could_move_consensus": False,
        "collective_outcome": "TEST_FURTHER",
    }, "Run III post-tool Council authority drift")
    require(observed.get("fed_projection") == {
        "authority_effect": "none",
        "vote_injection": False,
        "evidence_promotion": False,
    }, "Run III post-tool FED authority drift")


def validate_run3_roster() -> None:
    require(RUN3_ROSTER.is_file(), "Run III seat-roster supplement missing")
    require(sha256(RUN3_ROSTER) == RUN3_ROSTER_SHA256, "Run III seat-roster supplement byte hash drift")
    data = load(RUN3_ROSTER)
    require(data.get("document_type") == "qsol-fed-retained-empirical-evidence-supplement", "Run III roster supplement type drift")
    require(data.get("schema_version") == 1 and data.get("campaign_id") == "supercomputer-run-III", "Run III roster supplement identity drift")
    require(data.get("claim_supported") == ROSTER_CLAIM, "Run III roster supplement claim drift")
    require(data.get("source_archive_sha256") == RUN3_ARCHIVE, "Run III roster supplement archive identity drift")
    require(data.get("source_file_sha256") == {
        "QSOL-RUN-III/MODEL_MANIFEST.json": "ed9303cd1fb2bba47f8d1c1f7ba771f7ac6189c316d53ffa795523ed7d3f3adb",
        "QSOL-RUN-III/AGENT_MANIFEST.json": "03517a7b208c49da837db4b16dc30babe85c4bad2c16c9e528d76af74d7dce39",
        "QSOL-RUN-III/agent_x/council_roster.json": "b05b7036bff30f30c103f48e0b30107a4f740ec4a78552033937540459568eaf",
        "QSOL-RUN-III/agent_x/council_result.json": "ab8ce62100ba8d3f88763814f342cc50aa2ea206b39bed98978508ba255ef72c",
    }, "Run III roster source hash drift")
    observed = data.get("observed", {})
    require(observed.get("configured_fixed_seats") == EXPECTED_FIXED_SEATS, "Run III configured fixed-seat roster drift")
    require(observed.get("configured_agent_seat") == {"member_id": "X", "model_id": "abacus-agent-x"}, "Run III configured AGENT-X seat drift")
    require(observed.get("configured_total_seats") == 5, "Run III configured Council size drift")
    require(observed.get("observed_council_roster") == EXPECTED_COUNCIL_ROSTER, "Run III observed Council roster drift")
    require(observed.get("observed_total_seats") == 5, "Run III observed Council size drift")
    require(observed.get("observed_member_ids_unique") is True, "Run III observed Council member uniqueness drift")
    require(observed.get("council_result_member_count") == 5, "Run III Council result member-count drift")
    require(observed.get("wrapper_created_extra_seats_observed") is False, "Run III wrapper extra-seat observation drift")


def validate_bindings() -> None:
    claims = load(CLAIMS)
    for claim in (TRANSPORT_CLAIM, TOOL_CLAIM, ROSTER_CLAIM):
        require(claim in claims.get("supported_claims", []), f"supplement claim missing from claim manifest: {claim}")
    record = load(RECORD)
    require(record.get("supplemental_evidence") == EXPECTED_SUPPLEMENTS, "machine record supplemental-evidence binding drift")
    require(record.get("gate", {}).get("supplement_validator") == "tools/validate_empirical_assurance_supplements.py", "machine record supplement-validator wiring drift")
    run3 = next(c for c in record["campaigns"] if c["id"] == "supercomputer-run-III")
    require(run3["agent_wrapper"].get("bounded_tool_calls_used") == 1, "machine record tool-call count must match AGENT_MANIFEST used=1")
    text = DOC.read_text(encoding="utf-8")
    for marker in (
        "evidence/empirical-assurance/run-II-transport-authority.json",
        RUN2_SHA256,
        "evidence/empirical-assurance/run-III-tool-use.json",
        RUN3_TOOL_SHA256,
        "evidence/empirical-assurance/run-III-seat-roster.json",
        RUN3_ROSTER_SHA256,
        "30/30 transport drill reports",
        "exactly one experimental AGENT-X instrument call",
        "exactly five source-Council seats",
    ):
        require(marker in text, f"documentation missing supplement marker: {marker}")


def validate() -> None:
    validate_run2()
    validate_run3_tool()
    validate_run3_roster()
    validate_bindings()


def main() -> int:
    try:
        validate()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"empirical assurance supplements: ERROR: {exc}")
        return 1
    print("empirical assurance supplements: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
