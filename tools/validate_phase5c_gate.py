#!/usr/bin/env python3
"""Preserve the Phase 5C attested live-local QSOL-ORACLE transport boundary."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORACLE_COMMIT = "043e864b3c25dfeca3ce1752b3110479479071b1"
ORACLE_RELEASE = "7b0eff4dfa9b0caa84f14920d21f6a5446114535d82706cb62e34773c39818d2"
PHASE6_KEYS = {
    "minimal_protocol_sdk_contract", "rust_protocol_sdk", "python_protocol_sdk",
    "typescript_protocol_sdk", "language_neutral_sdk_conformance",
    "third_party_node_conformance", "three_implementation_sdk_interop",
    "institutional_integration_docs",
}
PHASE7_KEYS = {
    "assembly_membership_separate_from_network", "assembly_proposal_lifecycle",
    "assembly_representation_model", "assembly_anti_sybil_contract",
    "deterministic_charter_gate", "assembly_member_local_sovereignty",
    "nexus_assembly_advisory_only", "assembly_fork_version_path",
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


def validate_claim_delta() -> None:
    previous = load("claims/phase5.json")
    historical = load("claims/phase5c.json")
    require(historical.get("document_type") == "qsol-fed-phase5c-oracle-live-claims", "Phase 5C claim id drift")
    require(historical.get("gate_id") == "qsol-fed-phase5c-oracle-live-gate/1", "Phase 5C gate id drift")
    require(historical.get("gate_status") == "enforced", "Phase 5C gate not enforced")
    require(historical.get("runtime_override_allowed") is False, "Phase 5C claim became runtime-configurable")
    old_caps = previous["capabilities"]
    caps = historical["capabilities"]
    require(set(old_caps) == set(caps), "Phase 5C capability key set drift")
    changed = {key for key in caps if caps[key] != old_caps[key]}
    require(changed == {"oracle_live_transport"}, f"Phase 5C changed unexpected claims: {sorted(changed)}")
    require(old_caps["oracle_live_transport"] is False and caps["oracle_live_transport"] is True, "ORACLE live transport promotion drift")
    for key in ("oracle_holodeck_synthetic_admission", "host_level_sandbox", "production_networking", "remote_execution", "interoperable_federation"):
        require(caps[key] is False, f"Phase 5C premature claim enabled: {key}")

    phase6 = load("claims/phase6.json")["capabilities"]
    require(set(caps).issubset(phase6), "Phase 6 dropped Phase 5C capability keys")
    require(all(phase6[key] == value for key, value in caps.items()), "Phase 6 changed a historical Phase 5C capability")
    require(set(phase6) - set(caps) == PHASE6_KEYS, "Phase 6 successor capability key drift")
    require(all(phase6[key] is True for key in PHASE6_KEYS), "Phase 6 SDK capability missing")

    phase7 = load("claims/phase7.json")["capabilities"]
    require(set(phase6).issubset(phase7), "Phase 7 dropped Phase 6 capability keys")
    require(all(phase7[key] == value for key, value in phase6.items()), "Phase 7 changed a historical Phase 6 capability")
    require(set(phase7) - set(phase6) == PHASE7_KEYS, "Phase 7 successor capability key drift")
    require(all(phase7[key] is True for key in PHASE7_KEYS), "Phase 7 Assembly capability missing")
    require(rust_claims() == phase7, "Rust current claims disagree with Phase 7 successor")


def validate_contract_and_snapshots() -> None:
    state = load("state/phase5c.json")
    require(state.get("document_type") == "qsol-fed-phase5c-oracle-live-contract", "Phase 5C state id drift")
    oracle = state["oracle"]
    require(oracle["repository"] == "QSOLKCB/QSOL-ORACLE", "ORACLE repository pin drift")
    require(oracle["pinned_merge_commit"] == ORACLE_COMMIT, "ORACLE merge commit pin drift")
    require(oracle["release_fingerprint_sha256"] == ORACLE_RELEASE, "ORACLE release fingerprint pin drift")
    require(oracle["transport_protocol"] == "QSOL-ORACLE-FED/1", "ORACLE transport protocol drift")
    require(oracle["transport_profile"] == "local-stdio-jsonl", "ORACLE transport profile drift")
    for key in (
        "runtime_release_fingerprint_attestation", "release_fingerprint_digest_recomputed",
        "release_files_digest_recomputed", "all_fingerprinted_files_verified",
        "unfingerprinted_runtime_helper_explicitly_pinned", "private_runtime_staged_per_request",
        "staged_runtime_reattested_before_launch", "ci_exact_commit_checkout", "python_isolated_mode",
        "stdout_read_is_bounded_before_process_completion",
    ):
        require(oracle[key] is True, f"ORACLE hardened runtime requirement missing: {key}")
    require(oracle["mutable_checkout_executed_directly"] is False, "mutable ORACLE checkout execution drift")
    require(oracle["stderr_buffered_in_memory"] is False, "ORACLE stderr buffering drift")
    require(oracle["fixed_python_entrypoint"] == "python3 -I tools/fed_transport.py serve", "ORACLE process entrypoint drift")
    for key in ("caller_supplied_command", "caller_supplied_url", "caller_supplied_socket", "pythonpath_inherited", "pythonhome_inherited"):
        require(oracle[key] is False, f"ORACLE live process boundary drift: {key}")
    require(oracle["maximum_line_bytes"] == 65536, "ORACLE line limit drift")
    require(oracle["request_id_correlation"] == "NFC-normalized canonical request_id", "ORACLE request-id correlation drift")
    require(oracle["states"] == ["known", "conflict", "unknown"], "ORACLE state set drift")
    require(oracle["evidence_reference_prefix"] == "oracle-event:", "ORACLE provenance prefix drift")
    require(oracle["response_digest_verified"] is True and oracle["response_canonical_bytes_required"] is True, "ORACLE response validation drift")
    require(oracle["ledger_mutated"] is False and oracle["transport_authority"] == "none", "ORACLE transport gained state/authority")
    require(oracle["synthetic_input"] is False and oracle["truth_claim"] is False and oracle["evidence_promotion"] is False and oracle["authority_effect"] == "none", "ORACLE observation boundary drift")
    require(oracle["holodeck_synthetic_admission"] is False, "Holodeck-to-ORACLE admission enabled")
    require(oracle["network_transport_claimed"] is False and oracle["remote_execution_claimed"] is False, "ORACLE local process transport overclaimed")
    require(all(value is False for value in state["prime_directive"].values()), "Phase 5C transport gained forbidden Prime Directive effect")

    donor = load("contracts/oracle-fed-membrane-v1.json")
    require(donor["protocol"] == "QSOL-ORACLE-FED/1", "local ORACLE donor contract protocol drift")
    require(donor["consumer_pin"]["commit"] == "407d0ed75c7d8a76bd49b3c30e74a0ae2c59f1e6", "ORACLE donor consumer pin drift")
    transport = donor["transport"]
    require(transport["profile"] == "local-stdio-jsonl" and transport["maximum_line_bytes"] == 65536, "ORACLE donor transport profile/bounds drift")
    require(transport["canonical_input_required"] is True and transport["deterministic_output"] is True, "ORACLE donor canonical/deterministic drift")
    require(transport["response_budget_policy"] == "truncate-discovery-searches-before-response-limit", "ORACLE donor response-budget policy drift")
    require(transport["request_kind"] == "evidence.export" and transport["response_kind"] == "evidence.export.result", "ORACLE donor message-kind drift")
    observation_contract = donor["observation"]
    require(observation_contract["ledger_membership_required_when_validating_live_response"] is True, "ORACLE donor ledger-membership rule drift")
    require(observation_contract["research_missing_evidence_forces_unknown"] is True, "ORACLE donor unknown-precedence drift")
    require(observation_contract["conflict_supporting_reference_policy"] == "evidence.state=conflict only", "ORACLE donor conflict provenance drift")
    require(observation_contract["suggested_search_is_evidence"] is False, "ORACLE donor suggested-search evidence drift")
    require(observation_contract["synthetic_input"] is False and observation_contract["truth_claim"] is False and observation_contract["evidence_promotion"] is False and observation_contract["authority_effect"] == "none", "ORACLE donor observation authority drift")
    require(all(value is False for value in donor["authority_firewall"].values()), "ORACLE donor authority firewall drift")

    request = load("schemas/oracle-transport-request-v1.schema.json")
    response = load("schemas/oracle-transport-response-v1.schema.json")
    observation = load("schemas/oracle-observation-v1.schema.json")
    for name, schema in (("request", request), ("response", response), ("observation", observation)):
        require(schema.get("additionalProperties") is False, f"ORACLE {name} schema must remain closed")
    require(request["properties"]["synthetic_input"].get("const") is False, "ORACLE request synthetic input drift")
    require(request["properties"]["evidence_promotion_requested"].get("const") is False, "ORACLE request promotion drift")
    require(request["properties"]["authority_requested"].get("const") is False, "ORACLE request authority drift")
    require(request["properties"]["remote_execution_requested"].get("const") is False, "ORACLE request execution drift")
    require(response["properties"]["ledger_mutated"].get("const") is False and response["properties"]["transport_authority"].get("const") == "none", "ORACLE response authority drift")


def validate_rust_and_ci() -> None:
    source = (ROOT / "src/oracle_live.rs").read_text(encoding="utf-8")
    for marker in (
        ORACLE_COMMIT, ORACLE_RELEASE, "ORACLE_NEXUS_MEMBRANE_COMMON_SHA256",
        "stage_attested_runtime", "StagedOracleRuntime", "oracle_release_files_digest_mismatch",
        "oracle_release_fingerprint_digest_mismatch", "oracle_runtime_helper_mismatch",
        "Command::new(\"python3\")", ".arg(\"-I\")", ".arg(\"serve\")",
        "env_remove(\"PYTHONPATH\")", "env_remove(\"PYTHONHOME\")",
        "oracle_transport_stdout_limit_exceeded", "canonical_request_id",
        "oracle-event:", "response_sha256", "oracle_transport_noncanonical_response",
    ):
        require(marker in source, f"Phase 5C Rust marker missing: {marker}")
    for forbidden in ("Command::new(request", "TcpStream", "reqwest", "hyper::client", "wait_with_output"):
        require(forbidden not in source, f"Phase 5C live adapter gained forbidden generic/network/unbounded process capability: {forbidden}")
    binary = (ROOT / "src/bin/qsol-fed-oracle.rs").read_text(encoding="utf-8")
    for marker in ("OracleLiveAdapter::open", "phase5c-conformance", "ORACLE_PINNED_COMMIT", "ORACLE_RELEASE_FINGERPRINT_SHA256"):
        require(marker in binary, f"ORACLE live probe marker missing: {marker}")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for marker in ("QSOLKCB/QSOL-ORACLE", ORACLE_COMMIT, ".deps/QSOL-ORACLE", "oracle-fed-membrane-v1.json", "oracle-transport-request-v1.schema.json", "oracle-transport-response-v1.schema.json", "qsol-fed-oracle", "forged fingerprint self-claim", "validate_phase5c_gate.py"):
        require(marker.lower() in workflow.lower(), f"CI Phase 5C marker missing: {marker}")


def validate_surfaces() -> None:
    ai = load("README4AI.md")
    require(ai.get("phase5_status") == "historical_qsol_adapter_gate_preserved", "README4AI Phase 5 historical status drift")
    require(ai.get("phase5c_status") == "historical_oracle_live_transport_gate_preserved", "README4AI Phase 5C historical status missing")
    require(ai.get("current_claim_manifest") == "claims/phase7.json", "README4AI Phase 7 current manifest drift")
    require(ai.get("current_claims") == load("claims/phase7.json")["capabilities"], "README4AI Phase 7 claim drift")
    live = ai.get("phase5c_oracle_live", {})
    require(live.get("historical") is True, "README4AI Phase 5C history marker missing")
    require(live.get("oracle_pinned_commit") == ORACLE_COMMIT and live.get("oracle_release_fingerprint_sha256") == ORACLE_RELEASE, "README4AI ORACLE pin drift")
    require(live.get("oracle_holodeck_synthetic_admission") is False, "README4AI Holodeck admission drift")
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("Phase 5C — QSOL-ORACLE live transport" in roadmap, "ROADMAP Phase 5C missing")
    require("oracle_live_transport" in roadmap and ORACLE_COMMIT in roadmap, "ROADMAP ORACLE promotion/pin missing")
    require("oracle_holodeck_synthetic_admission" in roadmap and "false" in roadmap.lower(), "ROADMAP Holodeck deferral missing")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in ("state/phase5c.json", "claims/phase5c.json", "src/oracle_live.rs", "python3 tools/validate_phase5c_gate.py"):
        require(marker in agents, f"AGENTS Phase 5C marker missing: {marker}")


def main() -> None:
    validate_claim_delta()
    validate_contract_and_snapshots()
    validate_rust_and_ci()
    validate_surfaces()
    print("phase5c historical ORACLE live gate OK: donor fingerprint recomputed, staged runtime re-attested, bounded isolated local JSONL process verified, oracle-event provenance preserved, and the non-authority transport survives the Phase 7 successor unchanged")


if __name__ == "__main__":
    main()
