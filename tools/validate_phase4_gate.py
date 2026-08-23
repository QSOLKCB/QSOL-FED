#!/usr/bin/env python3
"""Enforce the historical Phase 4 durable federation-state boundary."""

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
    contract = load_json("state/phase4.json")
    require(contract.get("document_type") == "qsol-fed-phase4-state-contract", "Phase 4 state contract id drift")
    require(contract.get("wire_protocol") == "qsol-fed/1", "Phase 4 wire protocol drift")

    foreign = contract["foreign_store"]
    require(foreign["authority_from_presence"] is False, "foreign presence cannot create authority")
    require(foreign["multiple_attributions_per_content"] is True, "content hash must preserve multiple attributions")
    require("<attribution-hash>" in foreign["attribution_layout"], "foreign attribution layout drift")
    require(foreign["record_listing_validation"] == "fail_closed", "foreign listing validation must fail closed")
    require("transaction" in foreign["namespace_move_recovery"].lower(), "namespace move recovery contract missing")

    descendants = contract["local_descendants"]
    require(descendants["must_reference_foreign_parent"] is True, "descendant foreign-parent rule drift")
    require(descendants["descendant_must_differ_from_parent_content_id"] is True, "self-parent descendant must remain forbidden")

    peers = contract["peer_registry"]
    require(peers["initial_identity_immutable"] is True, "initial peer identity must remain immutable")
    require(peers["identity_lifecycle_monotonic"] is True, "peer lifecycle monotonicity drift")
    require(peers["existing_lifecycle_must_be_exact_prefix"] is True, "peer lifecycle prefix preservation drift")
    require(peers["bundle_import_preserves_existing_local_state"] is True, "bundle import must preserve existing local peer state")

    trust = contract["trust_registry"]
    require(trust["separate_from_peer_registry"] is True, "trust must remain separate from peers")
    require(trust["import_changes_trust"] is False, "import must not change trust")
    require("persist" in trust["write_visibility"].lower(), "trust write-before-live contract missing")

    capability = contract["capability_advertisement"]
    require(capability["maximum_lifetime_seconds"] == 3600, "capability advertisement lifetime must match Phase 2 proof lifetime")
    require(capability["advertisement_is_authorization"] is False, "capability advertisement must not authorize")

    policy = contract["local_capability_policy"]
    require(policy["default"] == "deny", "local capability policy must default deny")
    require(policy["effective_allow_requires"][0] == "peer lifecycle state admitted", "capability permission must require admitted peer")
    require("persist" in policy["write_visibility"].lower(), "policy write-before-live contract missing")

    partition = contract["partition_rejoin"]
    require(partition["silent_reconciliation"] is False, "silent reconciliation must remain disabled")
    require(partition["disconnect_snapshot_immutable_during_lifecycle_updates"] is True, "disconnect snapshot immutability drift")

    bundle = contract["portable_bundle"]
    require(bundle["maximum_bytes"] == 65536, "bundle total bound must match Phase 1 input profile")
    require(bundle["maximum_embedded_hex_characters"] == 8192, "bundle embedded string bound must match Phase 1 string profile")
    require(bundle["maximum_peers"] == 256, "bundle peer limit drift")
    require(bundle["maximum_object_attributions"] == 1024, "bundle object-attribution limit drift")
    require(bundle["offline_verification"] is True and bundle["network_required_for_verification"] is False, "offline bundle verification drift")
    require(bundle["new_peer_state"] == "quarantined", "new bundle peers must import quarantined")
    require(bundle["existing_peer_state"] == "preserved", "existing peer state must survive bundle import")
    require(bundle["new_object_namespace"] == "quarantine", "new bundle objects must import quarantined")
    require(bundle["existing_object_namespace"] == "preserved", "existing object namespace must survive bundle import")
    require(bundle["import_authority"] == "none", "bundle import authority drift")
    require(bundle["import_trust_change"] is False, "bundle import trust drift")

    historical = load_json("claims/phase4.json")
    require(historical.get("document_type") == "qsol-fed-phase4-claims", "Phase 4 claims id drift")
    require(historical.get("gate_status") == "enforced", "Phase 4 gate status drift")
    phase4_capabilities = historical["capabilities"]
    for required_true in (
        "foreign_object_store",
        "quarantine_namespace",
        "provenance_preserving_descendants",
        "durable_peer_registry",
        "separate_trust_registry",
        "expiring_capability_advertisements",
        "local_capability_policy",
        "partition_rejoin_control",
        "portable_federation_bundle",
        "offline_bundle_verification",
    ):
        require(phase4_capabilities.get(required_true) is True, f"historical Phase 4 claim missing: {required_true}")
    for hard_false in ("production_networking", "remote_execution", "interoperable_federation"):
        require(phase4_capabilities.get(hard_false) is False, f"historical Phase 4 claim drift: {hard_false}")

    successor = load_json("claims/phase5a.json")["capabilities"]
    for name, value in phase4_capabilities.items():
        require(successor.get(name) is value, f"Phase 5A changed historical Phase 4 claim: {name}")
    require(
        rust_current_claims((ROOT / "src/claims.rs").read_text(encoding="utf-8")) == successor,
        "Rust current claims disagree with Phase 5A successor manifest",
    )


def validate_schemas() -> None:
    for path in (
        "schemas/capability-advertisement-v1.schema.json",
        "schemas/peer-record-v1.schema.json",
        "schemas/foreign-object-record-v1.schema.json",
        "schemas/federation-bundle-v1.schema.json",
    ):
        schema = load_json(path)
        require(schema.get("additionalProperties") is False, f"schema must be closed: {path}")

    capability = load_json("schemas/capability-advertisement-v1.schema.json")
    capability_authority = capability.get("properties", {}).get("authority")
    require(
        capability_authority is None or capability_authority.get("const") == "none",
        "capability advertisement schema gained authority-bearing semantics",
    )

    foreign = load_json("schemas/foreign-object-record-v1.schema.json")
    require(foreign["properties"]["authority"].get("const") == "none", "foreign record authority drift")

    bundle = load_json("schemas/federation-bundle-v1.schema.json")
    require(bundle["properties"]["authority"].get("const") == "none", "bundle authority drift")
    require(bundle["properties"]["peers"].get("maxItems") == 256, "bundle peer schema limit drift")
    require(bundle["properties"]["objects"].get("maxItems") == 1024, "bundle object schema limit drift")
    peer_item = bundle["properties"]["peers"]["items"]["properties"]
    object_item = bundle["properties"]["objects"]["items"]["properties"]
    require(peer_item["identity_hex"].get("maxLength") == 8192, "bundle identity hex bound drift")
    require(peer_item["lifecycle_hex"]["items"].get("maxLength") == 8192, "bundle lifecycle hex bound drift")
    require(object_item["object_hex"].get("maxLength") == 8192, "bundle object hex bound drift")
    text = json.dumps(bundle, sort_keys=True)
    require("trust" not in text.lower(), "bundle schema must not carry trust state")
    require("capability_policy" not in text.lower(), "bundle schema must not carry local capability policy")


def validate_source() -> None:
    store = (ROOT / "src/store.rs").read_text(encoding="utf-8")
    for marker in (
        "foreign_records(",
        "AttributionKey",
        "identical_bytes_preserve_multiple_foreign_attributions",
        "local_descendant_self_parent_forbidden",
        "listed_records_are_validated_fail_closed",
        "NAMESPACE_MOVE_SCHEMA_V1",
        "recover_namespace_moves",
        "interrupted_namespace_move_is_recovered_on_open",
        "foreign_record_layout_corrupt",
    ):
        require(marker in store, f"Phase 4 store hardening marker missing: {marker}")

    peering = (ROOT / "src/peering.rs").read_text(encoding="utf-8")
    for marker in (
        "MAX_CAPABILITY_ADVERTISEMENT_LIFETIME_SECONDS: i64 = MAX_SIGNED_MESSAGE_LIFETIME_SECONDS",
        "require_lifecycle_prefix",
        "peer_lifecycle_prefix_rewrite_forbidden",
        "old.state != PeerLifecycleState::Disconnected",
        "if existed {",
        "peer.state != PeerLifecycleState::Admitted",
        "persist_trust_entries",
        "persist_capability_entries",
        "lifecycle_advancement_must_preserve_exact_prefix",
        "disconnected_snapshot_cannot_be_replaced_by_lifecycle_update",
        "import_does_not_demote_existing_admitted_peer",
        "failed_trust_and_policy_persistence_do_not_change_live_state",
        "advertisement_cannot_outlive_phase2_signed_proof",
    ):
        require(marker in peering, f"Phase 4 peering hardening marker missing: {marker}")

    bundle = (ROOT / "src/bundle.rs").read_text(encoding="utf-8")
    for marker in (
        "MAX_BUNDLE_BYTES: usize = 65_536",
        "MAX_BUNDLE_EMBEDDED_HEX_CHARS: usize = 8_192",
        "MAX_BUNDLE_OBJECTS: usize = 1_024",
        "attributions_seen",
        "new_material_quarantined_existing_state_preserved",
        "embedded_hex_and_total_bundle_bounds_match_phase1_profile",
        "import_preserves_existing_admitted_peer",
        "round_trip_preserves_foreign_identity_and_provenance_exactly",
    ):
        require(marker in bundle, f"Phase 4 bundle hardening marker missing: {marker}")

    offline = (ROOT / "src/bin/qsol-fed-bundle.rs").read_text(encoding="utf-8")
    require("verify_bundle" in offline and "No network access" in offline, "offline verifier boundary missing")
    for forbidden in ("reqwest", "TcpStream", "hyper::client", "ureq"):
        require(forbidden not in offline, f"offline verifier contains network client token: {forbidden}")


def validate_surfaces() -> None:
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; durable federation-state gate enforced.**" in roadmap, "ROADMAP Phase 4 status missing")
    require("Import/export round-trips must preserve foreign identity and provenance exactly" in roadmap, "ROADMAP Phase 4 gate wording missing")

    docs = (ROOT / "FEDERATION_STATE.md").read_text(encoding="utf-8")
    for marker in ("Persistence", "attribution", "quarantine", "TrustRegistry", "explicit_reconciliation_required", "qsol-fed-bundle/1", "authority = none", "3,600", "65,536", "8,192"):
        require(marker.lower() in docs.lower(), f"FEDERATION_STATE.md marker missing: {marker}")

    ai = load_json("README4AI.md")
    require(ai.get("phase4_status") == "historical_federation_state_gate_preserved", "README4AI Phase 4 historical status drift")
    require(ai.get("phase4_state", {}).get("contract") == "state/phase4.json", "README4AI Phase 4 state map missing")
    require(ai.get("current_claim_manifest") == "claims/phase5a.json", "README4AI successor claim manifest drift")
    require(ai.get("claim_disagreement_policy") == "fail_closed", "claim disagreement policy drift")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8").lower()
    for marker in ("state/phase4.json", "federation_state.md", "claims/phase4.json", "lifecycle prefix", "silent reconciliation", "staged", "attribution", "namespace move", "python3 tools/validate_phase4_gate.py"):
        require(marker in agents, f"AGENTS.md Phase 4 marker missing: {marker}")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase4_gate.py" in workflow, "CI missing historical Phase 4 gate")


def main() -> None:
    validate_contract_and_claims()
    validate_schemas()
    validate_source()
    validate_surfaces()
    print(
        "phase4 historical federation-state gate OK: lifecycle prefixes immutable, local state transactional, "
        "foreign attributions preserved, namespace moves recoverable, capabilities admission-scoped, "
        "and bounded offline bundles import without authority"
    )


if __name__ == "__main__":
    main()
