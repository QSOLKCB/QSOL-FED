#!/usr/bin/env python3
"""Preserve the historical Phase 5 QSOL adapter authority boundary under successors."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINNED_NEXUS_COMMIT = "24cb0ce246d12ac99e7d190a8890ef2ddd598321"
PHASE6_KEYS = {
    "minimal_protocol_sdk_contract", "rust_protocol_sdk", "python_protocol_sdk",
    "typescript_protocol_sdk", "language_neutral_sdk_conformance",
    "third_party_node_conformance", "three_implementation_sdk_interop",
    "institutional_integration_docs",
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


def validate_claims_and_contract() -> None:
    claims = load("claims/phase5.json")
    require(claims.get("document_type") == "qsol-fed-phase5-adapter-claims", "Phase 5 claim id drift")
    require(claims.get("gate_status") == "enforced", "Phase 5 claim gate not enforced")
    require(claims.get("runtime_override_allowed") is False, "historical Phase 5 claims became runtime configurable")
    caps = claims["capabilities"]
    for key in (
        "live_nexus_runtime_adapter", "nexus_council_report_adapter", "nexus_synthetic_actor_seam",
        "nexus_independent_redeliberation", "council_of_councils_reports_only",
        "oracle_evidence_membrane", "ark_offline_preservation_adapter",
    ):
        require(caps.get(key) is True, f"historical Phase 5 capability missing: {key}")
    for key in (
        "oracle_live_transport", "oracle_holodeck_synthetic_admission", "host_level_sandbox",
        "production_networking", "remote_execution", "interoperable_federation",
    ):
        require(caps.get(key) is False, f"historical Phase 5 false claim drift: {key}")

    phase5c = load("claims/phase5c.json")["capabilities"]
    require(set(phase5c) == set(caps), "Phase 5C capability key set does not preserve Phase 5")
    changed = {key for key in caps if caps[key] != phase5c[key]}
    require(changed == {"oracle_live_transport"}, f"Phase 5C changed unexpected historical Phase 5 claims: {sorted(changed)}")
    require(phase5c["oracle_live_transport"] is True, "Phase 5C did not promote ORACLE live transport")

    phase6 = load("claims/phase6.json")["capabilities"]
    require(set(phase5c).issubset(phase6), "Phase 6 dropped Phase 5C capability keys")
    require(all(phase6[key] == value for key, value in phase5c.items()), "Phase 6 changed a Phase 5C historical capability")
    require(set(phase6) - set(phase5c) == PHASE6_KEYS, "Phase 6 successor capability key drift")
    require(all(phase6[key] is True for key in PHASE6_KEYS), "Phase 6 SDK capability missing")
    require(rust_claims() == phase6, "Rust current claims disagree with Phase 6 successor")

    contract = load("state/phase5.json")
    require(contract.get("document_type") == "qsol-fed-phase5-adapter-contract", "Phase 5 contract id drift")
    nexus = contract["nexus"]
    require(nexus["pinned_commit"] == PINNED_NEXUS_COMMIT, "NEXUS adapter commit pin drift")
    require(nexus["native_verifier"] == "nexus_runtime.persistent_world.validate_world_export_bundle", "native NEXUS verifier drift")
    require(nexus["checkout_head_verified"] is True, "NEXUS checkout HEAD attestation drift")
    require(nexus["verifier_dependency_git_blobs_verified"] is True, "NEXUS verifier blob attestation drift")
    require(nexus["package_initializer_executed"] is False, "NEXUS package initializer execution boundary drift")
    require(nexus["manifest_only_after_native_verification"] is True, "manifest must require native verification")
    require(nexus["fed_canonical_output_profile"] == "qsol-fed-canonical-json/1", "FED adapter canonical profile drift")
    require(nexus["native_secret_scrubber_required"] is True, "native NEXUS secret scrub requirement drift")
    require(nexus["secret_scrub_attestation_field"] == "secret_scrubbed", "secret scrub attestation field drift")
    require(nexus["council_member_uniqueness"] == "NFC-normalized member_id", "Council NFC uniqueness drift")
    require(nexus["minority_member_must_be_roster_member"] is True, "minority roster attribution drift")
    require(nexus["vote_injection"] is False and nexus["evidence_promotion"] is False, "NEXUS import authority drift")
    require(nexus["source_vote_weight_observed"] == 1 and nexus["source_epistemic_privilege_observed"] == "none", "Council equality observation drift")
    require(nexus["vote_weight_inherited"] is False and nexus["epistemic_privilege_inherited"] is False, "Council equality inheritance drift")
    require(nexus["council_of_councils_shared_ballot"] is False, "Council-of-Councils shared ballot forbidden")
    require(nexus["holodeck_projection_requires_valid_world_plan"] is True, "Holodeck world-plan validation drift")
    require(nexus["holodeck_projection_requires_source_session_membership"] is True, "Holodeck source-session binding drift")
    require(nexus["holodeck_projection_inherits_governance"] is False, "Holodeck projection gained governance")

    oracle = contract["oracle"]
    require(oracle["states"] == ["known", "conflict", "unknown"], "ORACLE state set drift")
    require(oracle["distinct_evidence_refs_required"] is True, "ORACLE distinct-evidence rule drift")
    require(oracle["evidence_reference_uniqueness"] == "NFC-normalized reference", "ORACLE NFC uniqueness drift")
    require(oracle["suggested_search_is_evidence"] is False, "ORACLE suggested search became evidence")
    require(oracle["remote_evidence_promotion"] is False, "ORACLE evidence promotion enabled")
    require(oracle["live_transport"] is False, "historical Phase 5 ORACLE live transport drift")
    require(oracle["holodeck_synthetic_admission"] is False, "Holodeck-to-ORACLE admission historical drift")
    require(oracle["deferred_pr"] == "QSOLKCB/QSOL-ORACLE", "ORACLE follow-up target drift")

    ark = contract["ark"]
    require(ark["content_addressed_sha256"] is True and ark["offline_verification"] is True, "ARK offline preservation drift")
    require(ark["archival_presence_is_authority"] is False, "ARK archival presence became authority")
    require(ark["archival_presence_implies_real_world_history"] is False, "ARK archival presence inferred real-world history")
    require(ark["real_world_history_field"] is False, "ARK real-world history field drift")
    require(ark["holodeck_artifact_class"] == "synthetic_cultural_research", "Holodeck ARK classification drift")
    require(ark["known_holodeck_reclassification_forbidden"] is True, "Holodeck ARK reclassification guard drift")
    require(ark["holodeck_relabelled_real_world_history"] is False, "Holodeck artifact relabelled real history")

    prime = contract["prime_directive"]
    require(all(value is False for key, value in prime.items() if key.startswith("adapter_may_")), "adapter gained forbidden Prime Directive effect")
    require(prime["simulation_is_authority"] is False, "SIMULATION != AUTHORITY drift")


def validate_schemas_and_source() -> None:
    report = load("schemas/nexus-council-report-v1.schema.json")
    report_import = load("schemas/nexus-report-import-v1.schema.json")
    council_of_councils = load("schemas/council-of-councils-v1.schema.json")
    actor = load("schemas/nexus-holodeck-actor-v1.schema.json")
    oracle = load("schemas/oracle-observation-v1.schema.json")
    ark = load("schemas/ark-preservation-v1.schema.json")
    for name, schema in (("NEXUS report", report), ("NEXUS report import", report_import), ("Council-of-Councils", council_of_councils), ("NEXUS Holodeck actor", actor), ("ORACLE observation", oracle), ("ARK preservation", ark)):
        require(schema.get("additionalProperties") is False, f"{name} schema must be closed")
    require(report["properties"]["source_commit"].get("const") == PINNED_NEXUS_COMMIT, "NEXUS report source commit drift")
    require(report["properties"]["secret_scrubbed"].get("const") is True, "NEXUS secret scrub attestation schema drift")
    require(report["properties"]["members"].get("x-qsol-uniqueByNfcField") == "member_id", "NEXUS member NFC uniqueness extension missing")
    require(report["properties"]["minority_reports"].get("x-qsol-memberFieldMustReference") == "members[].member_id", "minority roster-reference extension missing")
    require(report["properties"]["shared_ballot"].get("const") is False, "NEXUS report shared ballot drift")
    require(report["properties"]["vote_injection"].get("const") is False, "NEXUS vote injection drift")
    require(report["properties"]["evidence_promotion"].get("const") is False, "NEXUS evidence promotion drift")
    require(report_import["properties"]["vote_injection"].get("const") is False and report_import["properties"]["evidence_promotion"].get("const") is False, "report import authority drift")
    require(council_of_councils["properties"]["shared_ballot"].get("const") is False and council_of_councils["properties"]["shared_vote_weight"].get("const") is False, "Council-of-Councils ballot drift")
    require(actor["properties"]["authority_effect"].get("const") == "none", "NEXUS Holodeck actor authority drift")
    for inherited in ("vote_weight_inherited", "epistemic_privilege_inherited", "citizenship_inherited", "governance_role_inherited"):
        require(actor["properties"][inherited].get("const") is False, f"NEXUS actor inheritance drift: {inherited}")
    require(oracle["properties"]["state"].get("enum") == ["known", "conflict", "unknown"], "ORACLE schema state drift")
    evidence_refs = oracle["properties"]["evidence_refs"]
    require(evidence_refs.get("uniqueItems") is True and evidence_refs.get("x-qsol-uniqueByNfcField") == "reference", "ORACLE evidence uniqueness drift")
    require(evidence_refs["items"]["properties"]["reference"].get("minLength") == 1, "ORACLE evidence reference emptiness drift")
    require(oracle["properties"]["suggested_searches"]["items"]["properties"]["is_evidence"].get("const") is False, "ORACLE search schema evidence drift")
    require(oracle["properties"]["evidence_promotion"].get("const") is False, "ORACLE promotion schema drift")
    require(ark["properties"]["archival_presence_is_authority"].get("const") is False and ark["properties"]["real_world_history"].get("const") is False, "ARK authority/history schema drift")

    live = (ROOT / "tools/nexus_live_adapter.py").read_text(encoding="utf-8")
    for marker in (PINNED_NEXUS_COMMIT, "NEXUS_PINNED_BLOBS", "_attest_nexus_checkout", "_git_blob_sha", "validate_world_export_bundle", "SecretScrubber", "canonicalize", "fed_canonical_output_invalid", "nexus_checkout_blob_mismatch", "native_verification_required", "nexus_native_verification_not_verified", "secret_scrubbed", "nexus_council_roster_duplicate_member_after_nfc", "nexus_minority_report_nonmember"):
        require(marker in live, f"live NEXUS adapter marker missing: {marker}")
    for forbidden in ("requests", "urllib.request", "http.client", "subprocess"):
        require(forbidden not in live, f"live NEXUS adapter gained forbidden external execution/network token: {forbidden}")
    fixture = (ROOT / "tools/generate_nexus_phase5_fixture.py").read_text(encoding="utf-8")
    for marker in ("WorldStore", "PersistentWorldService", "validate_world_export_bundle", "council_session", "--minority-rationale"):
        require(marker in fixture, f"native fixture generator marker missing: {marker}")
    adapters = (ROOT / "src/qsol_adapters.rs").read_text(encoding="utf-8")
    for marker in ("nexus_import_cannot_inject_votes_or_promote_evidence", "council_of_councils_uses_reports_not_shared_ballot", "nexus_council_actor_projection_inherits_zero_authority", "forged_or_unrelated_holodeck_plan_cannot_project_real_identity", "council_report_enforces_normalized_uniqueness_lengths_and_membership", "oracle_requires_nonempty_distinct_normalized_evidence_refs", "ark_preserves_holodeck_as_synthetic_not_real_history", "ark_never_infers_real_world_history_from_preservation", "ark_holodeck_reclassification_forbidden", "oracle_holodeck_synthetic_admission_contract_not_reviewed"):
        require(marker in adapters, f"Phase 5 Rust regression marker missing: {marker}")


def validate_fixtures_and_surfaces() -> None:
    bundle = load("fixtures/phase5/nexus-world-export.json")
    source = load("fixtures/phase5/nexus-source-manifest.json")
    reports = load("fixtures/phase5/nexus-council-reports.json")
    require(bundle["schema"] == "nexus-persistent-world-export/1" and bundle["authority_effect"] == "none", "NEXUS fixture drift")
    require(source["bundle_ref"] == bundle["bundle_ref"], "source fixture bundle binding drift")
    require(source["object_refs"] == [item["object_id"] for item in bundle["objects"]], "source fixture refs drift")
    require(reports["count"] == 1 and reports["authority_effect"] == "none", "Council fixture drift")
    require(reports["reports"][0]["secret_scrubbed"] is True and reports["reports"][0]["source_commit"] == PINNED_NEXUS_COMMIT, "Council fixture source/scrub drift")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for marker in (PINNED_NEXUS_COMMIT, "generate_nexus_phase5_fixture.py", "nexus_live_adapter.py", "QSOL-NEXUS-tampered", "nexus-secret-world-export.json", "validate_phase5_gate.py"):
        require(marker in workflow, f"CI Phase 5 marker missing: {marker}")
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("Phase 5 — QSOL adapters" in roadmap, "ROADMAP Phase 5 missing")
    require("QSOLKCB/QSOL-ORACLE" in roadmap and "follow-up" in roadmap.lower(), "ROADMAP ORACLE follow-up history missing")
    docs = (ROOT / "QSOL_ADAPTERS.md").read_text(encoding="utf-8")
    for marker in ("native NEXUS verification", "Git blob", "SecretScrubber", "canonical", "SIMULATION != AUTHORITY", "distinct evidence", "real-world history", "ORACLE", "ARK", "deferred"):
        require(marker.lower() in docs.lower(), f"QSOL_ADAPTERS.md historical marker missing: {marker}")
    ai = load("README4AI.md")
    require(ai.get("phase5_status") == "historical_qsol_adapter_gate_preserved", "README4AI Phase 5 historical status missing")
    require(ai.get("phase5_adapters", {}).get("oracle_live_transport") is False, "README4AI historical Phase 5 ORACLE non-claim drift")
    require(ai.get("current_claim_manifest") == "claims/phase6.json", "Phase 6 successor claim manifest not active")
    require(ai.get("current_claims") == load("claims/phase6.json")["capabilities"], "README4AI current Phase 6 claims drift")


def main() -> None:
    validate_claims_and_contract()
    validate_schemas_and_source()
    validate_fixtures_and_surfaces()
    print("phase5 historical adapter gate OK: attested native NEXUS bridge, canonical secret-safe report projection, report-only Council federation, source-bound synthetic actors, ORACLE distinct non-authority evidence, ARK preservation without history inference, historical ORACLE live-transport non-claim preserved, and SIMULATION != AUTHORITY preserved")


if __name__ == "__main__":
    main()
