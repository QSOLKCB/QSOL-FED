#!/usr/bin/env python3
"""Enforce Phase 4 durable federation state and portable bundle boundaries."""

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
    pairs = re.findall(r"\b([a-z0-9_]+):\s*(true|false),", source[body_start:body_end])
    return {name: value == "true" for name, value in pairs}


def validate_contract_and_claims() -> None:
    contract = load_json("state/phase4.json")
    require(contract.get("document_type") == "qsol-fed-phase4-state-contract", "Phase 4 state contract id drift")
    require(contract.get("wire_protocol") == "qsol-fed/1", "Phase 4 wire protocol drift")
    require(contract["foreign_store"]["import_default_namespace"] == "quarantine", "imports must default to quarantine")
    require(contract["foreign_store"]["authority_from_presence"] is False, "foreign presence cannot create authority")
    require(contract["trust_registry"]["separate_from_peer_registry"] is True, "trust must remain separate from peers")
    require(contract["trust_registry"]["import_changes_trust"] is False, "import must not change trust")
    require(contract["local_capability_policy"]["default"] == "deny", "local capability policy must default deny")
    require(contract["partition_rejoin"]["silent_reconciliation"] is False, "silent reconciliation must remain disabled")
    bundle = contract["portable_bundle"]
    require(bundle["offline_verification"] is True and bundle["network_required_for_verification"] is False, "offline bundle verification drift")
    require(bundle["import_peer_state"] == "quarantined", "bundle peers must import quarantined")
    require(bundle["import_object_namespace"] == "quarantine", "bundle objects must import quarantined")
    require(bundle["import_authority"] == "none", "bundle import authority drift")
    require(bundle["import_trust_change"] is False, "bundle import trust drift")

    claims = load_json("claims/phase4.json")
    require(claims.get("document_type") == "qsol-fed-phase4-claims", "Phase 4 claims id drift")
    require(claims.get("gate_status") == "enforced", "Phase 4 gate status drift")
    capabilities = claims["capabilities"]
    for required_true in (
        "foreign_object_store", "quarantine_namespace", "provenance_preserving_descendants",
        "durable_peer_registry", "separate_trust_registry", "expiring_capability_advertisements",
        "local_capability_policy", "partition_rejoin_control", "portable_federation_bundle",
        "offline_bundle_verification",
    ):
        require(capabilities.get(required_true) is True, f"Phase 4 claim missing: {required_true}")
    for hard_false in ("production_networking", "remote_execution", "interoperable_federation"):
        require(capabilities.get(hard_false) is False, f"premature Phase 4 claim enabled: {hard_false}")
    require(rust_current_claims((ROOT / "src/claims.rs").read_text(encoding="utf-8")) == capabilities, "Rust current claims disagree with Phase 4 manifest")


def validate_schemas() -> None:
    for path in (
        "schemas/capability-advertisement-v1.schema.json",
        "schemas/peer-record-v1.schema.json",
        "schemas/foreign-object-record-v1.schema.json",
        "schemas/federation-bundle-v1.schema.json",
    ):
        schema = load_json(path)
        require(schema.get("additionalProperties") is False, f"schema must be closed: {path}")
    require(load_json("schemas/foreign-object-record-v1.schema.json")["properties"]["authority"].get("const") == "none", "foreign record authority drift")
    bundle = load_json("schemas/federation-bundle-v1.schema.json")
    require(bundle["properties"]["authority"].get("const") == "none", "bundle authority drift")
    text = json.dumps(bundle, sort_keys=True)
    require("trust" not in text.lower(), "bundle schema must not carry trust state")
    require("capability_policy" not in text.lower(), "bundle schema must not carry local capability policy")


def validate_source() -> None:
    store = (ROOT / "src/store.rs").read_text(encoding="utf-8")
    for marker in (
        "ForeignNamespace", "Quarantine", "foreign_provenance_identity_mismatch",
        "create_local_descendant", "content_address_collision_or_metadata_conflict",
        "foreign_bytes_and_provenance_are_preserved_exactly", "local_descendant_points_back_to_foreign_parent",
    ):
        require(marker in store, f"Phase 4 store marker missing: {marker}")

    peering = (ROOT / "src/peering.rs").read_text(encoding="utf-8")
    for marker in (
        "PeerStateView", "Unknown", "Introduced", "Admitted", "Quarantined", "Revoked", "Disconnected",
        "TrustRegistry", "LocalCapabilityPolicy", "CapabilityDecision::Deny",
        "peer_lifecycle_rollback_forbidden", "capability_advertisement_rollback",
        "silent_reconciliation_forbidden", "SignedEnvelope",
        "peer_lifecycle_and_trust_are_separate_and_durable",
        "capability_advertisement_does_not_override_local_policy",
        "partition_rejoin_never_silently_reconciles", "lifecycle_replay_and_rollback_fail_across_restart",
    ):
        require(marker in peering, f"Phase 4 peering marker missing: {marker}")

    bundle = (ROOT / "src/bundle.rs").read_text(encoding="utf-8")
    for marker in (
        "FEDERATION_BUNDLE_SCHEMA_V1", "verify_bundle", "ForeignNamespace::Quarantine",
        'authority: "none"', "trust_changed: false", "network_required: false",
        "round_trip_preserves_foreign_identity_and_provenance_exactly",
        "identity_hex", "provenance_hex",
    ):
        require(marker in bundle, f"Phase 4 bundle marker missing: {marker}")

    offline = (ROOT / "src/bin/qsol-fed-bundle.rs").read_text(encoding="utf-8")
    require("verify_bundle" in offline and "No network access" in offline, "offline verifier boundary missing")
    for forbidden in ("reqwest", "TcpStream", "hyper::client", "ureq"):
        require(forbidden not in offline, f"offline verifier contains network client token: {forbidden}")


def validate_surfaces() -> None:
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; durable federation-state gate enforced.**" in roadmap, "ROADMAP Phase 4 status missing")
    require("Import/export round-trips must preserve foreign identity and provenance exactly" in roadmap, "ROADMAP Phase 4 gate wording missing")
    docs = (ROOT / "FEDERATION_STATE.md").read_text(encoding="utf-8")
    for marker in ("Persistence", "quarantine", "TrustRegistry", "explicit_reconciliation_required", "qsol-fed-bundle/1", "authority = none"):
        require(marker.lower() in docs.lower(), f"FEDERATION_STATE.md marker missing: {marker}")

    ai = load_json("README4AI.md")
    require(ai.get("status") == "phase4_gate_enforced", "README4AI Phase 4 status drift")
    require(ai.get("phase4_status") == "federation_state_gate_enforced", "README4AI Phase 4 gate marker missing")
    require(ai.get("current_claim_manifest") == "claims/phase4.json", "README4AI Phase 4 current claim manifest drift")
    require(ai.get("current_claims") == load_json("claims/phase4.json")["capabilities"], "README4AI Phase 4 current claims drift")
    require(ai.get("phase4_state", {}).get("contract") == "state/phase4.json", "README4AI Phase 4 state map missing")
    require(ai.get("claim_disagreement_policy") == "fail_closed", "claim disagreement policy drift")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8").lower()
    for marker in ("state/phase4.json", "federation_state.md", "claims/phase4.json", "silent reconciliation", "import", "python3 tools/validate_phase4_gate.py"):
        require(marker in agents, f"AGENTS.md Phase 4 marker missing: {marker}")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase4_gate.py" in workflow, "CI missing Phase 4 gate")


def main() -> None:
    validate_contract_and_claims()
    validate_schemas()
    validate_source()
    validate_surfaces()
    print("phase4 federation-state gate OK: foreign bytes/provenance preserved, peers/trust separated, partition reconciliation explicit, portable bundles offline-verifiable, imports quarantined and non-authoritative")


if __name__ == "__main__":
    main()
