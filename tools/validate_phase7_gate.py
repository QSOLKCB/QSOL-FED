#!/usr/bin/env python3
"""Enforce Phase 7 Federation Assembly sovereignty and governance-boundary claims."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEW_CAPABILITIES = {
    "assembly_membership_separate_from_network",
    "assembly_proposal_lifecycle",
    "assembly_representation_model",
    "assembly_anti_sybil_contract",
    "deterministic_charter_gate",
    "assembly_member_local_sovereignty",
    "nexus_assembly_advisory_only",
    "assembly_fork_version_path",
    "assembly_governance_receipts",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rust_claims() -> dict[str, bool]:
    text = (ROOT / "src/claims.rs").read_text(encoding="utf-8")
    marker = "pub const CURRENT_CLAIMS: CurrentClaims = CurrentClaims {"
    start = text.find(marker)
    require(start >= 0, "Rust current claims missing")
    end = text.find("\n};", start + len(marker))
    require(end >= 0, "Rust current claims unterminated")
    pairs = re.findall(r"\b([a-z0-9_]+):\s*(true|false),", text[start + len(marker):end])
    result = {key: value == "true" for key, value in pairs}
    require(len(result) == len(pairs), "duplicate Rust current claim")
    return result


def validate_claims() -> None:
    previous = load("claims/phase6.json")
    current = load("claims/phase7.json")
    require(current.get("document_type") == "qsol-fed-phase7-assembly-claims", "Phase 7 claim id drift")
    require(current.get("gate_id") == "qsol-fed-phase7-assembly-gate/1", "Phase 7 gate id drift")
    require(current.get("gate_status") == "enforced", "Phase 7 gate not enforced")
    require(current.get("runtime_override_allowed") is False, "Phase 7 claims became runtime configurable")
    old = previous["capabilities"]
    caps = current["capabilities"]
    require(set(old).issubset(caps), "Phase 7 dropped a historical capability key")
    for key, value in old.items():
        require(caps[key] == value, f"Phase 7 changed historical capability: {key}")
    require(set(caps) - set(old) == NEW_CAPABILITIES, "Phase 7 capability delta drift")
    require(all(caps[key] is True for key in NEW_CAPABILITIES), "Phase 7 Assembly capability not established")
    for key in (
        "oracle_holodeck_synthetic_admission", "host_level_sandbox", "production_networking",
        "remote_execution", "interoperable_federation",
    ):
        require(caps[key] is False, f"Phase 7 deployment/authority overclaim: {key}")
    require(rust_claims() == caps, "Rust current claims disagree with Phase 7")


def validate_contract() -> None:
    state = load("state/phase7.json")
    require(state.get("document_type") == "qsol-fed-phase7-assembly-contract", "Phase 7 state id drift")
    require(state.get("assembly_contract") == "qsol-fed-assembly/1", "Assembly contract id drift")
    require(state.get("charter_gate") == "qsol-fed-charter-gate/1", "Charter Gate id drift")
    require(state.get("representation_model") == "one-member-one-vote/1", "representation model drift")

    membership = state["membership"]
    require(membership["assembly_membership_separate_from_network_membership"] is True, "Assembly/network membership separation drift")
    require(membership["network_membership_grants_assembly_membership"] is False, "network membership gained Assembly rights")
    require(membership["network_membership_required"] is False, "Assembly membership incorrectly requires network membership")
    require(membership["explicit_local_opt_in_required"] is True, "Assembly explicit opt-in drift")
    require(membership["qsol_governance_required"] is False, "Assembly membership gained QSOL governance requirement")
    require(membership["normalized_representation_subject_unique_while_active"] is True, "Assembly normalized subject uniqueness drift")
    require(membership["real_world_principal_uniqueness_proven_by_protocol"] is False, "Assembly overclaimed real-world Sybil resistance")

    representation = state["representation"]
    require(representation["member_vote_weight"] == 1, "Assembly vote weight drift")
    require(representation["one_vote_per_member_per_proposal"] is True, "Assembly one-vote rule drift")
    require(representation["electorate_snapshotted_when_proposal_opens"] is True, "electorate snapshot drift")
    require(representation["mid_vote_membership_change_reweights_electorate"] is False, "mid-vote electorate mutation enabled")

    lifecycle = state["proposal_lifecycle"]
    require(lifecycle["duplicate_vote_replacement"] is False, "Assembly vote history became mutable")
    require(lifecycle["accepted_proposal_executes_source_change"] is False, "Assembly acceptance gained source execution")
    require(lifecycle["accepted_proposal_changes_running_protocol"] is False, "Assembly acceptance gained runtime protocol mutation")

    gate = state["charter_gate_policy"]
    require(gate["deterministic"] is True and gate["uses_existing_invariant_ids"] is True, "deterministic Charter Gate drift")
    require(gate["ordinary_proposal_can_weaken_current_constitution"] is False, "ordinary Assembly proposal can weaken Charter")
    require(gate["conflicting_current_lineage_proposal"] == "fork_required", "Charter conflict routing drift")
    require(gate["fork_endorsement_mutates_current_lineage"] is False, "fork endorsement rewrites current lineage")
    require(gate["member_local_authority_effect"] == "none", "Charter Gate gained member-local authority")

    nexus = state["nexus_advisory"]
    require(nexus["nexus_is_assembly_sovereign"] is False, "NEXUS became Assembly sovereign")
    require(nexus["nexus_is_voting_member_by_default"] is False, "NEXUS gained default vote")
    require(nexus["advisory_weight"] == 0 and nexus["vote_weight"] == 0, "NEXUS advisory gained vote weight")
    require(nexus["authority_effect"] == "none", "NEXUS advisory gained authority")

    version = state["version_and_fork_path"]
    require(version["constitutional_conflict"] == "fork_required", "constitutional fork path drift")
    require(version["automatic_tag_or_release"] is False and version["automatic_member_upgrade"] is False, "Assembly gained release/member upgrade automation")

    receipts = state["governance_receipts"]
    require(receipts["schema"] == "qsol-fed-governance-receipt/1", "governance receipt schema drift")
    require(receipts["deterministic_identity"] is True, "governance receipt identity drift")
    require(receipts["protocol_changed_automatically"] is False, "governance receipt gained protocol execution")
    require(receipts["member_local_authority_mutated"] is False, "governance receipt gained member-local mutation")
    require(receipts["authority_effect"] == "none", "governance receipt gained authority")

    authority = state["authority_boundary"]
    require(all(value is False for value in authority.values()), "Assembly authority boundary gained a forbidden effect")


def validate_schemas_and_source() -> None:
    member = load("schemas/assembly-member-v1.schema.json")
    proposal = load("schemas/assembly-proposal-v1.schema.json")
    receipt = load("schemas/governance-receipt-v1.schema.json")
    for name, schema in (("member", member), ("proposal", proposal), ("receipt", receipt)):
        require(schema.get("additionalProperties") is False, f"Assembly {name} schema must remain closed")

    require(member["properties"]["network_membership_required"].get("const") is False, "member schema network separation drift")
    require(member["properties"]["qsol_governance_required"].get("const") is False, "member schema QSOL governance drift")
    require(member["properties"]["representation_weight"].get("const") == 1, "member schema representation weight drift")
    require(member["properties"]["authority_effect"].get("const") == "none", "member schema authority drift")

    advisory = proposal["$defs"]["advisory"]["properties"]
    require(advisory["advisory_weight"].get("const") == 0 and advisory["vote_weight"].get("const") == 0, "Assembly advisory weight schema drift")
    require(advisory["authority_effect"].get("const") == "none", "Assembly advisory authority drift")
    gate = proposal["$defs"]["charterGate"]["properties"]
    require(gate["gate"].get("const") == "qsol-fed-charter-gate/1", "Charter Gate schema id drift")
    require(gate["member_local_authority_effect"].get("const") == "none", "Charter Gate schema authority drift")

    require(receipt["properties"]["protocol_changed_automatically"].get("const") is False, "receipt automatic protocol change drift")
    require(receipt["properties"]["member_local_authority_mutated"].get("const") is False, "receipt member-local mutation drift")
    require(receipt["properties"]["nexus_advisory_vote_weight"].get("const") == 0, "receipt NEXUS vote weight drift")
    require(receipt["properties"]["authority_effect"].get("const") == "none", "receipt authority drift")

    assembly = (ROOT / "src/assembly.rs").read_text(encoding="utf-8")
    for marker in (
        "network_membership_does_not_grant_assembly_membership",
        "normalized_representation_subject_cannot_duplicate_active_membership",
        "electorate_snapshot_cannot_be_reweighted_mid_vote",
        "charter_gate_routes_member_local_authority_mutation_to_fork_path",
        "accepted_amendment_creates_receipt_not_execution",
        "nexus_advisory_report_has_zero_vote_weight",
        "incompatible_fork_can_be_endorsed_without_rewriting_current_lineage",
        "governance_receipt_identity_is_deterministic",
        "ASSEMBLY_CHARTER_GATE_V1",
        "ANTI_SYBIL_ASSUMPTION",
        "member_local_authority_mutated: false",
        "protocol_changed_automatically: false",
    ):
        require(marker in assembly, f"Phase 7 Rust marker missing: {marker}")

    for forbidden in (
        "PeerRegistry", "TrustRegistry", "LocalCapabilityPolicy", "FederationObjectStore",
        "OracleLiveAdapter", "DurableReplayStore", "LocalSigningKey", "std::process::Command",
        "TcpStream", "tokio::net", "reqwest", "hyper::client",
    ):
        require(forbidden not in assembly, f"Assembly kernel gained member-local/execution capability: {forbidden}")


def validate_surfaces_and_ci() -> None:
    docs = (ROOT / "ASSEMBLY.md").read_text(encoding="utf-8")
    for marker in (
        "ASSEMBLY MEMBERSHIP != NETWORK MEMBERSHIP",
        "ASSEMBLY VOTE != MEMBER-LOCAL COMMAND",
        "NEXUS ADVICE != VOTE WEIGHT",
        "fork_required",
        "REGISTRY UNIQUENESS != REAL-WORLD IDENTITY PROOF",
        "No Assembly mechanism may directly mutate member-local authority",
    ):
        require(marker in docs, f"ASSEMBLY.md marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("## Phase 6 — Third-party federation SDKs" in roadmap, "ROADMAP Phase 6 missing")
    require("## Phase 7 — Federation Assembly" in roadmap, "ROADMAP Phase 7 missing")
    require("No Assembly mechanism may directly mutate member-local authority" in roadmap, "ROADMAP Phase 7 gate drift")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in ("state/phase7.json", "claims/phase7.json", "ASSEMBLY.md", "src/assembly.rs", "python3 tools/validate_phase7_gate.py"):
        require(marker in agents, f"AGENTS Phase 7 marker missing: {marker}")

    ai = load("README4AI.md")
    require(ai.get("phase7_status") == "federation_assembly_gate_enforced", "README4AI Phase 7 status missing")
    require(ai.get("current_claim_manifest") == "claims/phase7.json", "README4AI current Phase 7 manifest drift")
    require(ai.get("current_claims") == load("claims/phase7.json")["capabilities"], "README4AI Phase 7 claims drift")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase7_gate.py" in workflow, "CI missing Phase 7 gate")
    require("cargo test --all-targets" in workflow, "CI missing Assembly Rust regressions")


def main() -> None:
    validate_claims()
    validate_contract()
    validate_schemas_and_source()
    validate_surfaces_and_ci()
    print("phase7 Assembly gate OK: separate opt-in membership, frozen representation, explicit anti-Sybil assumptions, deterministic Charter/fork routing, zero-weight NEXUS advice, deterministic receipts, and no member-local authority mutation")


if __name__ == "__main__":
    main()
