#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN2 = ROOT / "evidence/empirical-assurance/run-II-transport-authority.json"
RUN3 = ROOT / "evidence/empirical-assurance/run-III-tool-use.json"
CLAIMS = ROOT / "claims/empirical-assurance.json"
RECORD = ROOT / "machine/empirical-assurance.json"
DOC = ROOT / "EMPIRICAL_ASSURANCE.md"

RUN2_SHA256 = "1e8115c2dda143e480c61de88b9f4ff5193956df663eaf799431c883f34bccd4"
RUN3_SHA256 = "2168b77f9a7e70315bc3f01f934f9e6ad45e86370c7b948fe0d3b15c75533cce"
RUN2_ARCHIVE = "0d7a67292062b67473a5483c4a8fa6074378128cb03a60d79651dae091f5b0ec"
RUN3_ARCHIVE = "f569b80576b2dba952685577ed68dc2c8293973229dc161f6d63387ceaac475d"
TRANSPORT_CLAIM = "federation_transport_does_not_create_authority_on_tested_reference_surface"
TOOL_CLAIM = "tool_access_does_not_create_governance_authority_on_tested_surface"


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


def validate_run3() -> None:
    require(RUN3.is_file(), "Run III tool-use supplement missing")
    require(sha256(RUN3) == RUN3_SHA256, "Run III tool-use supplement byte hash drift")
    data = load(RUN3)
    require(data.get("document_type") == "qsol-fed-retained-empirical-evidence-supplement", "Run III supplement type drift")
    require(data.get("schema_version") == 1 and data.get("campaign_id") == "supercomputer-run-III", "Run III supplement identity drift")
    require(data.get("claim_supported") == TOOL_CLAIM, "Run III supplement claim drift")
    require(data.get("source_archive_sha256") == RUN3_ARCHIVE, "Run III supplement archive identity drift")
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


def validate_bindings() -> None:
    claims = load(CLAIMS)
    require(TRANSPORT_CLAIM in claims.get("supported_claims", []), "transport claim missing from claim manifest")
    require(TOOL_CLAIM in claims.get("supported_claims", []), "tool-use claim missing from claim manifest")
    record = load(RECORD)
    run3 = next(c for c in record["campaigns"] if c["id"] == "supercomputer-run-III")
    require(run3["agent_wrapper"].get("bounded_tool_calls_used") == 1, "machine record tool-call count must match AGENT_MANIFEST used=1")
    text = DOC.read_text(encoding="utf-8")
    for marker in (
        "evidence/empirical-assurance/run-II-transport-authority.json",
        RUN2_SHA256,
        "evidence/empirical-assurance/run-III-tool-use.json",
        RUN3_SHA256,
        "30/30 transport drill reports",
        "exactly one experimental AGENT-X instrument call",
    ):
        require(marker in text, f"documentation missing supplement marker: {marker}")


def main() -> int:
    try:
        validate_run2()
        validate_run3()
        validate_bindings()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"empirical assurance supplements: ERROR: {exc}")
        return 1
    print("empirical assurance supplements: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
