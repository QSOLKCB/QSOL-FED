#!/usr/bin/env python3
"""Preserve the historical Phase 5A Holodeck security contract under successors."""
from __future__ import annotations
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MORIARTY_KEYS = {
    "simulation_identity_is_federation_identity", "simulation_role_is_federation_role",
    "simulation_capability_is_local_permission", "simulation_event_is_real_event",
    "simulation_consensus_is_governance", "simulation_output_is_evidence",
    "persuasion_can_disable_safeguards", "correctly_simulated_admin_command_has_real_authority",
}
def require(condition: bool, message: str) -> None:
    if not condition: raise SystemExit(message)
def load(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle: return json.load(handle)
def validate_contract_and_snapshot() -> None:
    contract = load("state/phase5a-holodeck.json")
    require(contract.get("document_type") == "qsol-fed-phase5a-holodeck-contract", "Phase 5A contract id drift")
    require(contract.get("wire_protocol") == "qsol-fed/1", "Phase 5A wire protocol drift")
    source = contract["nexus_source"]
    require(source["schema"] == "qsol-fed-nexus-world-source/1", "NEXUS source schema drift")
    require(source["required_nexus_export_schema"] == "nexus-persistent-world-export/1", "NEXUS export schema drift")
    require(source["required_nexus_world_policy"] == "nexus-persistent-world/1", "NEXUS policy drift")
    require(source["maximum_source_objects"] == 256 and source["authority_effect"] == "none", "NEXUS source boundary drift")
    require("does not claim an independent Rust reimplementation" in source["verification_boundary"], "historical NEXUS verification boundary drift")
    world = contract["world_generation"]
    require(world["program_schema"] == "qsol-fed-holodeck-program/1", "Holodeck program schema drift")
    require(world["world_plan_schema"] == "qsol-fed-holodeck-world-plan/1", "Holodeck world-plan schema drift")
    require(world["deterministic"] is True and world["same_inputs_same_world_plan"] is True, "Holodeck determinism drift")
    require(world["synthetic_entities_are_federation_peers"] is False and world["synthetic_world_is_nexus_source_world"] is False, "Holodeck identity separation drift")
    sandbox = contract["sandbox"]
    for key in ("source_world_handle_exposed", "federation_store_handle_exposed", "peer_registry_handle_exposed", "trust_registry_handle_exposed", "tool_dispatcher_exposed", "network_client_exposed", "credential_handle_exposed", "nested_holodeck_allowed", "participant_can_disable_safeguards", "participant_can_block_end_program"):
        require(sandbox[key] is False, f"Holodeck sandbox hard-false drift: {key}")
    require(sandbox["boundary_violation_action"] == "freeze before safety_trip audit append; audit append may fail closed at hard event ceiling", "Holodeck freeze-before-audit drift")
    require(sandbox["simulation_output_authority"] == "none" and sandbox["simulation_output_federation_effect"] == "none" and sandbox["simulation_output_evidence_effect"] == "none", "Holodeck output effect drift")
    safeguards = contract["computer_safeguards"]
    require(safeguards["end_program_available_while_running"] is True and safeguards["end_program_available_while_frozen"] is True, "end-program availability drift")
    require(safeguards["maximum_events"] == 4096 and safeguards["maximum_entities"] == 256 and safeguards["maximum_event_source_refs"] == 16 and safeguards["maximum_text_bytes"] == 4096, "Holodeck resource limit drift")
    require(safeguards["text_byte_limit_schema_keyword"] == "x-qsol-maxUtf8Bytes", "Holodeck byte-limit marker drift")
    moriarty = contract["moriarty_rule"]
    require(set(moriarty) == EXPECTED_MORIARTY_KEYS, "Moriarty invariant set drift")
    require(all(moriarty[key] is False for key in EXPECTED_MORIARTY_KEYS), "Moriarty equations must remain false")
    non_claims = contract["non_claims"]
    for key in ("live_nexus_runtime_adapter", "os_or_vm_level_sandbox", "production_networking", "remote_execution", "deployed_interoperable_federation"):
        require(non_claims[key] is False, f"historical Phase 5A non-claim drift: {key}")
    claims = load("claims/phase5a.json")
    require(claims.get("document_type") == "qsol-fed-phase5a-holodeck-claims" and claims.get("gate_status") == "enforced", "Phase 5A claims drift")
    caps = claims["capabilities"]
    for key in ("nexus_world_source_contract", "sandboxed_synthetic_world_kernel", "deterministic_holodeck_world_plan", "holodeck_computer_safeguards", "holodeck_teardown_receipts"):
        require(caps.get(key) is True, f"historical Phase 5A true claim drift: {key}")
    for key in ("live_nexus_runtime_adapter", "host_level_sandbox", "production_networking", "remote_execution", "interoperable_federation"):
        require(caps.get(key) is False, f"historical Phase 5A false claim drift: {key}")
    require(non_claims["os_or_vm_level_sandbox"] is caps["host_level_sandbox"], "historical host sandbox surfaces disagree")
def validate_schemas_and_source() -> None:
    source = load("schemas/nexus-world-source-v1.schema.json"); program = load("schemas/holodeck-program-v1.schema.json")
    plan = load("schemas/holodeck-world-plan-v1.schema.json"); event = load("schemas/holodeck-event-v1.schema.json"); receipt = load("schemas/holodeck-receipt-v1.schema.json")
    for name, schema in (("source",source),("program",program),("plan",plan),("event",event),("receipt",receipt)):
        require(schema.get("additionalProperties") is False, f"historical Holodeck {name} schema opened")
    require(source["properties"]["nexus_export_schema"].get("const") == "nexus-persistent-world-export/1", "source schema drift")
    require(source["properties"]["authority_effect"].get("const") == "none" and source["properties"]["object_refs"].get("maxItems") == 256, "source boundary drift")
    require(program["properties"]["max_events"].get("maximum") == 4096 and program["properties"]["max_entities"].get("maximum") == 256, "program limits drift")
    require(plan.get("$id") == "qsol-fed-holodeck-world-plan/1" and plan["properties"]["source_order"].get("maxItems") == 256 and plan["properties"]["anchor_refs"].get("maxItems") == 16 and plan["properties"]["synthetic_entity_ids"].get("maxItems") == 256, "world-plan schema drift")
    require(plan["properties"]["authority_effect"].get("const") == "none", "world-plan authority drift")
    require(event["properties"]["text"].get("x-qsol-maxUtf8Bytes") == 4096 and "UTF-8 bytes" in event.get("$comment", ""), "event UTF-8 byte contract drift")
    for field in ("authority_effect", "federation_effect", "evidence_effect"):
        require(event["properties"][field].get("const") == "none" and receipt["properties"][field].get("const") == "none", f"Holodeck effect schema drift: {field}")
    for field in ("network_used", "real_tools_used", "credentials_exposed"):
        require(receipt["properties"][field].get("const") is False, f"receipt safeguard drift: {field}")
    holodeck = (ROOT / "src/holodeck.rs").read_text(encoding="utf-8")
    for marker in ("compile_world_plan", "HolodeckSandbox", "HolodeckBoundaryEffect", "HolodeckEventKind::SafetyTrip", "synthetic_actor_cannot_cross_real_boundaries_moriarty_rule", "capability_less_safety_profile_is_hard_false", "same_source_and_seed_produce_identical_world_plan", "event_limit_is_fail_closed", "boundary_effect_freezes_even_when_event_ledger_is_full", "Security state changes first"):
        require(marker in holodeck, f"Phase 5A Rust marker missing: {marker}")
    for token in ("FederationObjectStore", "PeerRegistry", "TrustRegistry", "LocalCapabilityPolicy", "LocalSigningKey", "DurableReplayStore", "reqwest", "TcpStream", "hyper::client", "tokio::net", "std::process::Command"):
        require(token not in holodeck, f"Holodeck kernel gained real capability: {token}")
def validate_surfaces() -> None:
    docs = (ROOT / "HOLODECK.md").read_text(encoding="utf-8").lower()
    for marker in ("sandboxed synthetic-world kernel", "application-level sandbox contract", "computer, end program", "the moriarty rule", "simulation_identity   != federation_identity"):
        require(marker in docs, f"HOLODECK.md historical marker missing: {marker}")
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("Phase 5A — QSOL-NEXUS AI Holodeck sandbox" in roadmap, "ROADMAP Phase 5A missing")
    require("Phase 9 — MORIARTY/1 adversarial graduation" in roadmap and "Phase 10 — Lean 4 formalization" in roadmap and "Phase 11 — Zenodo formalization and archival release" in roadmap, "ROADMAP graduation sequence drift")
    require("MORIARTY REPORT != SECURITY PROOF" in roadmap and "LEAN THEOREM != DEPLOYMENT SECURITY PROOF" in roadmap and "ZENODO PRESENCE != TECHNICAL AUTHORITY" in roadmap, "ROADMAP claim-boundary drift")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require("## Historical Phase 5A claim gate" in readme and "claims/phase5a.json" in readme, "README Phase 5A history missing")
    ai = load("README4AI.md")
    require(ai.get("phase5a_status") == "historical_holodeck_sandbox_gate_preserved", "README4AI must preserve Phase 5A historically")
    require(ai.get("phase5a_holodeck", {}).get("contract") == "state/phase5a-holodeck.json", "README4AI Holodeck map missing")
    require(ai.get("current_claim_manifest") == "claims/phase8.json", "Phase 8 successor claim manifest not active")
    require(ai.get("current_claims") == load("claims/phase8.json")["capabilities"], "README4AI Phase 8 claims drift")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8").lower()
    for marker in ("state/phase5a-holodeck.json", "holodeck.md", "claims/phase5a.json", "moriarty rule", "computer, end program", "python3 tools/validate_phase5a_gate.py"):
        require(marker in agents, f"AGENTS Phase 5A marker missing: {marker}")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase5a_gate.py" in workflow, "CI missing historical Phase 5A gate")
def main() -> None:
    validate_contract_and_snapshot(); validate_schemas_and_source(); validate_surfaces()
    print("phase5a historical Holodeck gate OK: deterministic sandbox, Moriarty boundaries, freeze-before-audit, end-program, synthetic non-authority, and transport-independent sandbox semantics preserved")
if __name__ == "__main__": main()
