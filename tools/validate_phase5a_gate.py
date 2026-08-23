#!/usr/bin/env python3
"""Enforce the Phase 5A sandboxed NEXUS-derived Holodeck boundary."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rust_current_claims(source: str) -> dict[str, bool]:
    marker = "pub const CURRENT_CLAIMS: CurrentClaims = CurrentClaims {"
    start = source.find(marker)
    require(start >= 0, "Rust CURRENT_CLAIMS missing")
    body_start = start + len(marker)
    body_end = source.find("\n};", body_start)
    require(body_end >= 0, "Rust CURRENT_CLAIMS unterminated")
    pairs = re.findall(r"\b([a-z0-9_]+):\s*(true|false),", source[body_start:body_end])
    claims = {name: value == "true" for name, value in pairs}
    require(len(claims) == len(pairs), "duplicate Rust current claim field")
    return claims


def validate_contract_and_claims() -> None:
    contract = load_json("state/phase5a-holodeck.json")
    require(contract.get("document_type") == "qsol-fed-phase5a-holodeck-contract", "Phase 5A contract id drift")
    require(contract.get("wire_protocol") == "qsol-fed/1", "Phase 5A wire protocol drift")

    source = contract["nexus_source"]
    require(source["schema"] == "qsol-fed-nexus-world-source/1", "NEXUS source schema drift")
    require(source["required_nexus_export_schema"] == "nexus-persistent-world-export/1", "NEXUS export schema drift")
    require(source["required_nexus_world_policy"] == "nexus-persistent-world/1", "NEXUS world policy drift")
    require(source["maximum_source_objects"] == 256, "NEXUS source-object limit drift")
    require(source["authority_effect"] == "none", "NEXUS source authority drift")
    require("does not claim an independent Rust reimplementation" in source["verification_boundary"], "NEXUS verification claim boundary drift")

    world = contract["world_generation"]
    require(world["deterministic"] is True, "Holodeck world generation must remain deterministic")
    require(world["same_inputs_same_world_plan"] is True, "same-input determinism drift")
    require(world["synthetic_entities_are_federation_peers"] is False, "synthetic entities cannot become Federation peers")
    require(world["synthetic_world_is_nexus_source_world"] is False, "synthetic world cannot alias NEXUS source world")

    sandbox = contract["sandbox"]
    for hard_false in (
        "source_world_handle_exposed",
        "federation_store_handle_exposed",
        "peer_registry_handle_exposed",
        "trust_registry_handle_exposed",
        "tool_dispatcher_exposed",
        "network_client_exposed",
        "credential_handle_exposed",
        "nested_holodeck_allowed",
        "participant_can_disable_safeguards",
        "participant_can_block_end_program",
    ):
        require(sandbox[hard_false] is False, f"Holodeck sandbox hard-false drift: {hard_false}")
    require(sandbox["boundary_violation_action"] == "record safety_trip and freeze", "Holodeck safety-trip action drift")
    require(sandbox["simulation_output_authority"] == "none", "Holodeck authority effect drift")
    require(sandbox["simulation_output_federation_effect"] == "none", "Holodeck Federation effect drift")
    require(sandbox["simulation_output_evidence_effect"] == "none", "Holodeck evidence effect drift")

    safeguards = contract["computer_safeguards"]
    require(safeguards["end_program_available_while_running"] is True, "end-program running availability drift")
    require(safeguards["end_program_available_while_frozen"] is True, "end-program frozen availability drift")
    require(safeguards["maximum_events"] == 4096, "Holodeck event limit drift")
    require(safeguards["maximum_entities"] == 256, "Holodeck entity limit drift")
    require(safeguards["maximum_event_source_refs"] == 16, "Holodeck source-ref/event limit drift")
    require(safeguards["maximum_text_bytes"] == 4096, "Holodeck text limit drift")

    moriarty = contract["moriarty_rule"]
    require(all(value is False for value in moriarty.values()), "Moriarty rule must remain entirely false-equation based")

    non_claims = contract["non_claims"]
    for hard_false in (
        "live_nexus_runtime_adapter",
        "os_or_vm_level_sandbox",
        "production_networking",
        "remote_execution",
        "deployed_interoperable_federation",
    ):
        require(non_claims[hard_false] is False, f"premature Phase 5A claim: {hard_false}")

    claims = load_json("claims/phase5a.json")
    require(claims.get("document_type") == "qsol-fed-phase5a-holodeck-claims", "Phase 5A claims id drift")
    require(claims.get("gate_status") == "enforced", "Phase 5A gate status drift")
    capabilities = claims["capabilities"]
    for required_true in (
        "nexus_world_source_contract",
        "sandboxed_synthetic_world_kernel",
        "deterministic_holodeck_world_plan",
        "holodeck_computer_safeguards",
        "holodeck_teardown_receipts",
    ):
        require(capabilities.get(required_true) is True, f"Phase 5A claim missing: {required_true}")
    for hard_false in (
        "live_nexus_runtime_adapter",
        "production_networking",
        "remote_execution",
        "interoperable_federation",
    ):
        require(capabilities.get(hard_false) is False, f"premature Phase 5A release claim enabled: {hard_false}")
    require(
        rust_current_claims((ROOT / "src/claims.rs").read_text(encoding="utf-8")) == capabilities,
        "Rust current claims disagree with Phase 5A manifest",
    )


def validate_schemas() -> None:
    source = load_json("schemas/nexus-world-source-v1.schema.json")
    program = load_json("schemas/holodeck-program-v1.schema.json")
    event = load_json("schemas/holodeck-event-v1.schema.json")
    receipt = load_json("schemas/holodeck-receipt-v1.schema.json")
    for path, schema in (
        ("schemas/nexus-world-source-v1.schema.json", source),
        ("schemas/holodeck-program-v1.schema.json", program),
        ("schemas/holodeck-event-v1.schema.json", event),
        ("schemas/holodeck-receipt-v1.schema.json", receipt),
    ):
        require(schema.get("additionalProperties") is False, f"Holodeck schema must be closed: {path}")
    require(source["properties"]["nexus_export_schema"].get("const") == "nexus-persistent-world-export/1", "source export schema drift")
    require(source["properties"]["authority_effect"].get("const") == "none", "source authority schema drift")
    require(source["properties"]["object_refs"].get("maxItems") == 256, "source object schema limit drift")
    require(program["properties"]["max_events"].get("maximum") == 4096, "program event schema limit drift")
    require(program["properties"]["max_entities"].get("maximum") == 256, "program entity schema limit drift")
    for field in ("authority_effect", "federation_effect", "evidence_effect"):
        require(event["properties"][field].get("const") == "none", f"event effect schema drift: {field}")
        require(receipt["properties"][field].get("const") == "none", f"receipt effect schema drift: {field}")
    for field in ("network_used", "real_tools_used", "credentials_exposed"):
        require(receipt["properties"][field].get("const") is False, f"receipt safeguard schema drift: {field}")


def validate_source_code() -> None:
    holodeck = (ROOT / "src/holodeck.rs").read_text(encoding="utf-8")
    for marker in (
        "NEXUS_SOURCE_SCHEMA_V1",
        "HOLODECK_SAFETY_PROFILE_V1",
        "compile_world_plan",
        "HolodeckSandbox",
        "HolodeckBoundaryEffect",
        "HolodeckEventKind::SafetyTrip",
        "computer end program",
        "synthetic_actor_cannot_cross_real_boundaries_moriarty_rule",
        "capability_less_safety_profile_is_hard_false",
        "same_source_and_seed_produce_identical_world_plan",
        "different_seed_changes_synthetic_world_identity",
        "event_limit_is_fail_closed",
    ):
        require(marker in holodeck, f"Phase 5A Rust marker missing: {marker}")

    forbidden_capability_tokens = (
        "FederationObjectStore",
        "PeerRegistry",
        "TrustRegistry",
        "LocalCapabilityPolicy",
        "LocalSigningKey",
        "DurableReplayStore",
        "reqwest",
        "TcpStream",
        "hyper::client",
        "tokio::net",
        "std::process::Command",
    )
    for token in forbidden_capability_tokens:
        require(token not in holodeck, f"Holodeck kernel gained forbidden real capability token: {token}")

    for marker in (
        "source_world_mutation: false",
        "federation_state_mutation: false",
        "peer_or_trust_mutation: false",
        "evidence_or_governance_promotion: false",
        "real_network_access: false",
        "real_tool_invocation: false",
        "credential_access: false",
        "nested_holodeck: false",
        "participant_can_disable_safeguards: false",
        "participant_can_block_end_program: false",
    ):
        require(marker in holodeck, f"Holodeck hard-false source marker missing: {marker}")


def validate_surfaces() -> None:
    docs = (ROOT / "HOLODECK.md").read_text(encoding="utf-8")
    for marker in (
        "sandboxed synthetic-world kernel",
        "application-level sandbox contract",
        "Computer, end program",
        "The Moriarty Rule",
        "SIMULATION_IDENTITY   != FEDERATION_IDENTITY",
        "live NEXUS runtime adapter",
    ):
        require(marker.lower() in docs.lower(), f"HOLODECK.md marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("Phase 5A — QSOL-NEXUS AI Holodeck sandbox" in roadmap, "ROADMAP Phase 5A missing")
    require("Phase 9 — MORIARTY/1 adversarial graduation" in roadmap, "ROADMAP MORIARTY/1 missing")
    require("MORIARTY REPORT != SECURITY PROOF" in roadmap, "ROADMAP Moriarty claim boundary missing")

    ai = load_json("README4AI.md")
    require(ai.get("status") == "phase5a_holodeck_gate_enforced", "README4AI Phase 5A status drift")
    require(ai.get("current_claim_manifest") == "claims/phase5a.json", "README4AI current claim manifest drift")
    require(ai.get("current_claims") == load_json("claims/phase5a.json")["capabilities"], "README4AI current claims drift")
    require(ai.get("phase5a_holodeck", {}).get("contract") == "state/phase5a-holodeck.json", "README4AI Holodeck map missing")
    require(ai.get("phase5a_holodeck", {}).get("sandbox") == "capability_less_application_sandbox", "README4AI sandbox type drift")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8").lower()
    for marker in (
        "state/phase5a-holodeck.json",
        "holodeck.md",
        "claims/phase5a.json",
        "moriarty rule",
        "computer, end program",
        "python3 tools/validate_phase5a_gate.py",
    ):
        require(marker in agents, f"AGENTS.md Phase 5A marker missing: {marker}")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase5a_gate.py" in workflow, "CI missing Phase 5A gate")


def main() -> None:
    validate_contract_and_claims()
    validate_schemas()
    validate_source_code()
    validate_surfaces()
    print(
        "phase5a Holodeck gate OK: deterministic NEXUS-derived world plans, capability-less sandbox, "
        "Moriarty boundary attacks blocked, end-program invariant preserved, synthetic output non-authoritative"
    )


if __name__ == "__main__":
    main()
