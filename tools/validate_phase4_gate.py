#!/usr/bin/env python3
"""Preserve the historical Phase 4 federation-state security contract."""
from __future__ import annotations
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def require(condition: bool, message: str) -> None:
    if not condition: raise SystemExit(message)
def load(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle: return json.load(handle)
def validate_contract_and_claims() -> None:
    contract = load("state/phase4.json")
    require(contract.get("document_type") == "qsol-fed-phase4-state-contract", "Phase 4 state contract id drift")
    require(contract.get("wire_protocol") == "qsol-fed/1", "Phase 4 wire protocol drift")
    foreign = contract["foreign_store"]
    require(foreign["authority_from_presence"] is False, "foreign presence cannot create authority")
    require(foreign["multiple_attributions_per_content"] is True and "<attribution-hash>" in foreign["attribution_layout"], "foreign attribution model drift")
    require(foreign["record_listing_validation"] == "fail_closed" and "transaction" in foreign["namespace_move_recovery"].lower(), "foreign durability/listing drift")
    descendants = contract["local_descendants"]
    require(descendants["must_reference_foreign_parent"] is True and descendants["descendant_must_differ_from_parent_content_id"] is True, "descendant provenance drift")
    peers = contract["peer_registry"]
    require(peers["initial_identity_immutable"] is True and peers["identity_lifecycle_monotonic"] is True and peers["existing_lifecycle_must_be_exact_prefix"] is True, "peer lifecycle drift")
    require(peers["bundle_import_preserves_existing_local_state"] is True, "bundle import local-state drift")
    trust = contract["trust_registry"]
    require(trust["separate_from_peer_registry"] is True and trust["import_changes_trust"] is False and "persist" in trust["write_visibility"].lower(), "trust registry drift")
    capability = contract["capability_advertisement"]
    require(capability["maximum_lifetime_seconds"] == 3600 and capability["advertisement_is_authorization"] is False, "capability advertisement drift")
    policy = contract["local_capability_policy"]
    require(policy["default"] == "deny" and policy["effective_allow_requires"][0] == "peer lifecycle state admitted" and "persist" in policy["write_visibility"].lower(), "capability policy drift")
    partition = contract["partition_rejoin"]
    require(partition["silent_reconciliation"] is False and partition["disconnect_snapshot_immutable_during_lifecycle_updates"] is True, "partition sovereignty drift")
    bundle = contract["portable_bundle"]
    require(bundle["maximum_bytes"] == 65536 and bundle["maximum_embedded_hex_characters"] == 8192 and bundle["maximum_peers"] == 256 and bundle["maximum_object_attributions"] == 1024, "bundle limits drift")
    require(bundle["offline_verification"] is True and bundle["network_required_for_verification"] is False, "offline verification drift")
    require(bundle["new_peer_state"] == "quarantined" and bundle["existing_peer_state"] == "preserved", "bundle peer import drift")
    require(bundle["new_object_namespace"] == "quarantine" and bundle["existing_object_namespace"] == "preserved", "bundle object import drift")
    require(bundle["import_authority"] == "none" and bundle["import_trust_change"] is False, "bundle authority/trust drift")
    claims = load("claims/phase4.json")
    require(claims.get("document_type") == "qsol-fed-phase4-claims" and claims.get("gate_status") == "enforced", "Phase 4 claim snapshot drift")
    caps = claims["capabilities"]
    for key in ("foreign_object_store", "quarantine_namespace", "provenance_preserving_descendants", "durable_peer_registry", "separate_trust_registry", "expiring_capability_advertisements", "local_capability_policy", "partition_rejoin_control", "portable_federation_bundle", "offline_bundle_verification"):
        require(caps.get(key) is True, f"historical Phase 4 claim missing: {key}")
    for key in ("production_networking", "remote_execution", "interoperable_federation"):
        require(caps.get(key) is False, f"historical Phase 4 false claim drift: {key}")
def validate_schemas_and_source() -> None:
    for path in ("schemas/capability-advertisement-v1.schema.json", "schemas/peer-record-v1.schema.json", "schemas/foreign-object-record-v1.schema.json", "schemas/federation-bundle-v1.schema.json"):
        require(load(path).get("additionalProperties") is False, f"schema must remain closed: {path}")
    capability = load("schemas/capability-advertisement-v1.schema.json")
    authority = capability.get("properties", {}).get("authority")
    require(authority is None or authority.get("const") == "none", "capability advertisement gained authority")
    foreign = load("schemas/foreign-object-record-v1.schema.json")
    require(foreign["properties"]["authority"].get("const") == "none", "foreign record authority drift")
    bundle_schema = load("schemas/federation-bundle-v1.schema.json")
    require(bundle_schema["properties"]["authority"].get("const") == "none", "bundle authority drift")
    require(bundle_schema["properties"]["peers"].get("maxItems") == 256 and bundle_schema["properties"]["objects"].get("maxItems") == 1024, "bundle schema limits drift")
    text = json.dumps(bundle_schema, sort_keys=True).lower()
    require("trust" not in text and "capability_policy" not in text, "bundle schema gained local authority state")
    store = (ROOT / "src/store.rs").read_text(encoding="utf-8")
    for marker in ("foreign_records(", "AttributionKey", "identical_bytes_preserve_multiple_foreign_attributions", "local_descendant_self_parent_forbidden", "listed_records_are_validated_fail_closed", "NAMESPACE_MOVE_SCHEMA_V1", "recover_namespace_moves", "interrupted_namespace_move_is_recovered_on_open", "foreign_record_layout_corrupt"):
        require(marker in store, f"Phase 4 store marker missing: {marker}")
    peering = (ROOT / "src/peering.rs").read_text(encoding="utf-8")
    for marker in ("MAX_CAPABILITY_ADVERTISEMENT_LIFETIME_SECONDS: i64 = MAX_SIGNED_MESSAGE_LIFETIME_SECONDS", "require_lifecycle_prefix", "peer_lifecycle_prefix_rewrite_forbidden", "peer.state != PeerLifecycleState::Admitted", "persist_trust_entries", "persist_capability_entries", "lifecycle_advancement_must_preserve_exact_prefix", "disconnected_snapshot_cannot_be_replaced_by_lifecycle_update", "import_does_not_demote_existing_admitted_peer", "failed_trust_and_policy_persistence_do_not_change_live_state", "advertisement_cannot_outlive_phase2_signed_proof"):
        require(marker in peering, f"Phase 4 peering marker missing: {marker}")
    bundle = (ROOT / "src/bundle.rs").read_text(encoding="utf-8")
    for marker in ("MAX_BUNDLE_BYTES: usize = 65_536", "MAX_BUNDLE_EMBEDDED_HEX_CHARS: usize = 8_192", "MAX_BUNDLE_OBJECTS: usize = 1_024", "attributions_seen", "new_material_quarantined_existing_state_preserved", "import_preserves_existing_admitted_peer", "round_trip_preserves_foreign_identity_and_provenance_exactly"):
        require(marker in bundle, f"Phase 4 bundle marker missing: {marker}")
    offline = (ROOT / "src/bin/qsol-fed-bundle.rs").read_text(encoding="utf-8")
    require("verify_bundle" in offline and "No network access" in offline, "offline verifier boundary drift")
def validate_surfaces() -> None:
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; durable federation-state gate enforced.**" in roadmap, "ROADMAP Phase 4 status missing")
    require("Import/export round-trips must preserve foreign identity and provenance exactly" in roadmap, "ROADMAP Phase 4 gate wording missing")
    docs = (ROOT / "FEDERATION_STATE.md").read_text(encoding="utf-8").lower()
    for marker in ("persistence", "attribution", "quarantine", "trustregistry", "explicit_reconciliation_required", "qsol-fed-bundle/1", "authority = none", "3,600", "65,536", "8,192"):
        require(marker.lower() in docs, f"FEDERATION_STATE.md marker missing: {marker}")
    ai = load("README4AI.md")
    require(ai.get("phase4_status") == "historical_federation_state_gate_preserved", "README4AI Phase 4 historical status drift")
    require(ai.get("phase4_state", {}).get("contract") == "state/phase4.json", "README4AI Phase 4 map missing")
    require(ai.get("current_claim_manifest") == "claims/phase8.json", "Phase 8 successor claim manifest not active")
    require(ai.get("claim_disagreement_policy") == "fail_closed", "claim disagreement policy drift")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8").lower()
    for marker in ("state/phase4.json", "federation_state.md", "claims/phase4.json", "lifecycle prefix", "silent reconciliation", "persist-before-live", "attribution", "namespace move", "python3 tools/validate_phase4_gate.py"):
        require(marker in agents, f"AGENTS Phase 4 marker missing: {marker}")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase4_gate.py" in workflow, "CI missing historical Phase 4 gate")
def main() -> None:
    validate_contract_and_claims(); validate_schemas_and_source(); validate_surfaces()
    print("phase4 historical federation-state gate OK: lifecycle prefixes immutable, local state transactional, foreign attributions preserved, namespace moves recoverable, capabilities admission-scoped, and bounded offline bundles import without authority")
if __name__ == "__main__": main()
