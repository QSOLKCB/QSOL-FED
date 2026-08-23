#!/usr/bin/env python3
"""Enforce Phase 5 QSOL adapter authority boundaries and explicit deferrals."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINNED_NEXUS_COMMIT = "24cb0ce246d12ac99e7d190a8890ef2ddd598321"


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


def validate_claims_and_contract() -> None:
    claims = load("claims/phase5.json")
    require(claims.get("document_type") == "qsol-fed-phase5-adapter-claims", "Phase 5 claim id drift")
    require(claims.get("gate_status") == "enforced", "Phase 5 claim gate not enforced")
    caps = claims["capabilities"]
    require(rust_claims() == caps, "Rust claims disagree with claims/phase5.json")
    for key in (
        "live_nexus_runtime_adapter", "nexus_council_report_adapter", "nexus_synthetic_actor_seam",
        "nexus_independent_redeliberation", "council_of_councils_reports_only",
        "oracle_evidence_membrane", "ark_offline_preservation_adapter",
    ):
        require(caps.get(key) is True, f"reviewed Phase 5 capability missing: {key}")
    for key in (
        "oracle_live_transport", "oracle_holodeck_synthetic_admission", "host_level_sandbox",
        "production_networking", "remote_execution", "interoperable_federation",
    ):
        require(caps.get(key) is False, f"premature Phase 5 claim enabled: {key}")

    contract = load("state/phase5.json")
    require(contract.get("document_type") == "qsol-fed-phase5-adapter-contract", "Phase 5 contract id drift")
    nexus = contract["nexus"]
    require(nexus["pinned_commit"] == PINNED_NEXUS_COMMIT, "NEXUS adapter commit pin drift")
    require(nexus["native_verifier"] == "nexus_runtime.persistent_world.validate_world_export_bundle", "native NEXUS verifier drift")
    require(nexus["manifest_only_after_native_verification"] is True, "manifest must require native verification")
    require(nexus["vote_injection"] is False and nexus["evidence_promotion"] is False, "NEXUS import authority drift")
    require(nexus["source_vote_weight_observed"] == 1 and nexus["source_epistemic_privilege_observed"] == "none", "Council equality observation drift")
    require(nexus["vote_weight_inherited"] is False and nexus["epistemic_privilege_inherited"] is False, "Council equality inheritance drift")
    require(nexus["council_of_councils_shared_ballot"] is False, "Council-of-Councils shared ballot forbidden")
    require(nexus["holodeck_projection_inherits_governance"] is False, "Holodeck projection gained governance")

    oracle = contract["oracle"]
    require(oracle["states"] == ["known", "conflict", "unknown"], "ORACLE state set drift")
    require(oracle["suggested_search_is_evidence"] is False, "ORACLE suggested search became evidence")
    require(oracle["remote_evidence_promotion"] is False, "ORACLE evidence promotion enabled")
    require(oracle["live_transport"] is False, "ORACLE live transport prematurely claimed")
    require(oracle["holodeck_synthetic_admission"] is False, "Holodeck-to-ORACLE admission prematurely claimed")
    require(oracle["deferred_pr"] == "QSOLKCB/QSOL-ORACLE", "ORACLE follow-up target drift")

    ark = contract["ark"]
    require(ark["content_addressed_sha256"] is True and ark["offline_verification"] is True, "ARK offline preservation drift")
    require(ark["archival_presence_is_authority"] is False, "ARK archival presence became authority")
    require(ark["holodeck_artifact_class"] == "synthetic_cultural_research", "Holodeck ARK classification drift")
    require(ark["holodeck_relabelled_real_world_history"] is False, "Holodeck artifact relabelled real history")

    prime = contract["prime_directive"]
    require(all(value is False for key, value in prime.items() if key.startswith("adapter_may_")), "adapter gained forbidden Prime Directive effect")
    require(prime["simulation_is_authority"] is False, "SIMULATION != AUTHORITY drift")


def validate_schemas_and_source() -> None:
    report = load("schemas/nexus-council-report-v1.schema.json")
    oracle = load("schemas/oracle-observation-v1.schema.json")
    ark = load("schemas/ark-preservation-v1.schema.json")
    for name, schema in (("NEXUS report", report), ("ORACLE observation", oracle), ("ARK preservation", ark)):
        require(schema.get("additionalProperties") is False, f"{name} schema must be closed")
    require(report["properties"]["shared_ballot"].get("const") is False, "NEXUS report shared ballot drift")
    require(report["properties"]["vote_injection"].get("const") is False, "NEXUS vote injection drift")
    require(report["properties"]["evidence_promotion"].get("const") is False, "NEXUS evidence promotion drift")
    require(oracle["properties"]["state"].get("enum") == ["known", "conflict", "unknown"], "ORACLE schema state drift")
    suggestion = oracle["properties"]["suggested_searches"]["items"]["properties"]
    require(suggestion["is_evidence"].get("const") is False, "ORACLE search schema evidence drift")
    require(oracle["properties"]["evidence_promotion"].get("const") is False, "ORACLE promotion schema drift")
    require(ark["properties"]["archival_presence_is_authority"].get("const") is False, "ARK authority schema drift")

    live = (ROOT / "tools/nexus_live_adapter.py").read_text(encoding="utf-8")
    for marker in (
        PINNED_NEXUS_COMMIT, "validate_world_export_bundle", "native_verification_required",
        "nexus_native_verification_not_verified", "vote_weight_inherited", "shared_ballot",
    ):
        require(marker in live, f"live NEXUS adapter marker missing: {marker}")
    for forbidden in ("requests", "urllib.request", "http.client", "subprocess"):
        require(forbidden not in live, f"live NEXUS adapter gained forbidden external execution/network token: {forbidden}")

    fixture = (ROOT / "tools/generate_nexus_phase5_fixture.py").read_text(encoding="utf-8")
    for marker in ("WorldStore", "PersistentWorldService", "validate_world_export_bundle", "council_session"):
        require(marker in fixture, f"native fixture generator marker missing: {marker}")

    adapters = (ROOT / "src/qsol_adapters.rs").read_text(encoding="utf-8")
    for marker in (
        "nexus_import_cannot_inject_votes_or_promote_evidence",
        "council_of_councils_uses_reports_not_shared_ballot",
        "nexus_council_actor_projection_inherits_zero_authority",
        "oracle_preserves_unknown_conflict_and_search_non_evidence",
        "ark_preserves_holodeck_as_synthetic_not_real_history",
        "oracle_holodeck_synthetic_admission_contract_not_reviewed",
    ):
        require(marker in adapters, f"Phase 5 Rust regression marker missing: {marker}")


def validate_fixtures_and_surfaces() -> None:
    bundle = load("fixtures/phase5/nexus-world-export.json")
    source = load("fixtures/phase5/nexus-source-manifest.json")
    reports = load("fixtures/phase5/nexus-council-reports.json")
    require(bundle["schema"] == "nexus-persistent-world-export/1", "NEXUS fixture schema drift")
    require(bundle["authority_effect"] == "none", "NEXUS fixture authority drift")
    require(source["bundle_ref"] == bundle["bundle_ref"], "source fixture bundle binding drift")
    require(source["object_refs"] == [item["object_id"] for item in bundle["objects"]], "source fixture refs drift")
    require(reports["count"] == 1 and reports["authority_effect"] == "none", "Council fixture drift")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for marker in (
        PINNED_NEXUS_COMMIT,
        "generate_nexus_phase5_fixture.py",
        "nexus_live_adapter.py",
        "validate_phase5_gate.py",
    ):
        require(marker in workflow, f"CI Phase 5 marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("Phase 5 — QSOL adapters" in roadmap, "ROADMAP Phase 5 missing")
    require("QSOLKCB/QSOL-ORACLE" in roadmap and "follow-up" in roadmap.lower(), "ROADMAP ORACLE follow-up missing")
    docs = (ROOT / "QSOL_ADAPTERS.md").read_text(encoding="utf-8")
    for marker in ("native NEXUS verification", "SIMULATION != AUTHORITY", "ORACLE", "ARK", "deferred"):
        require(marker.lower() in docs.lower(), f"QSOL_ADAPTERS.md marker missing: {marker}")


def main() -> None:
    validate_claims_and_contract()
    validate_schemas_and_source()
    validate_fixtures_and_surfaces()
    print("phase5 adapter gate OK: native-verified NEXUS bridge, report-only Council federation, ORACLE non-authority membrane with live transport deferred, ARK offline preservation, and SIMULATION != AUTHORITY preserved")


if __name__ == "__main__":
    main()
