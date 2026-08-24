#!/usr/bin/env python3
"""Enforce Phase 8 transport/resilience identity, provenance, resource and sandbox boundaries."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEW_CAPABILITIES = {
    "bounded_transport_frame_contract",
    "websocket_transport_profile",
    "quic_transport_profile",
    "unix_local_ipc_profile",
    "offline_sneakernet_profile",
    "store_forward_profile",
    "nat_traversal_identity_binding",
    "multi_relay_provenance",
    "disaster_recovery_key_compromise_drills",
    "long_lived_archive_compatibility",
    "transport_resource_partition_drills",
    "holodeck_transport_independence",
}
EXPECTED_PROFILES = {"web_socket", "quic", "unix_ipc", "offline_sneakernet", "store_forward"}
EXPECTED_DRILLS = {
    "resource_exhaustion",
    "partition_recovery",
    "key_compromise",
    "nat_traversal_identity",
    "multi_relay_provenance",
    "archive_compatibility",
    "holodeck_transport_independence",
}
EXPECTED_AUTHORITY_KEYS = {
    "transport_may_mutate_peer_registry",
    "transport_may_mutate_trust_registry",
    "transport_may_install_capability",
    "transport_may_promote_evidence",
    "transport_may_create_assembly_vote",
    "transport_may_mutate_citizenship",
    "transport_may_rewrite_history",
    "transport_may_claim_local_authority",
    "nat_ticket_may_replace_identity",
    "relay_chain_may_create_trust",
    "offline_media_presence_may_create_authority",
    "partition_recovery_may_silently_reconcile",
    "transport_may_disable_holodeck_safeguards",
}
EXPECTED_TRANSPORT_USES = {
    "std::collections::{BTreeSet,VecDeque}",
    "std::fmt",
    "serde::{Deserialize,Serialize}",
    "serde_json::Value",
    "sha2::{Digest,Sha256}",
    "crate::canonical::{canonicalize,sha256_ref,SAFE_INTEGER_MAX,SAFE_INTEGER_MIN}",
    "crate::holodeck::HolodeckReceipt",
    "crate::wire::{is_node_id,is_sha256_ref}",
}
FORBIDDEN_PRODUCTION_PATHS = (
    "std::net::",
    "std::os::unix::net::",
    "std::process::",
    "std::fs::",
    "tokio::net::",
    "tokio::process::",
    "reqwest::",
    "hyper::client",
    "crate::crypto",
    "crate::peering",
    "crate::store",
    "crate::assembly",
    "crate::oracle_live",
    "HolodeckSandbox",
    "HolodeckProgram",
    "HolodeckBoundaryEffect",
)
SAFE_MAX = 9007199254740991
SAFE_MIN = -SAFE_MAX


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


def production_rust(source: str) -> str:
    return source.split("#[cfg(test)]", 1)[0]


def rust_use_statements(source: str) -> set[str]:
    return {
        re.sub(r"\s+", "", match)
        for match in re.findall(r"(?ms)^\s*use\s+(.+?);", source)
    }


def validate_claims() -> None:
    previous = load("claims/phase7.json")
    current = load("claims/phase8.json")
    require(current.get("document_type") == "qsol-fed-phase8-transport-resilience-claims", "Phase 8 claim id drift")
    require(current.get("gate_id") == "qsol-fed-phase8-transport-resilience-gate/1", "Phase 8 gate id drift")
    require(current.get("gate_status") == "enforced", "Phase 8 gate not enforced")
    require(current.get("runtime_override_allowed") is False, "Phase 8 claims became runtime configurable")
    old = previous["capabilities"]
    caps = current["capabilities"]
    require(set(old).issubset(caps), "Phase 8 dropped a Phase 7 capability")
    for key, value in old.items():
        require(caps[key] == value, f"Phase 8 changed historical Phase 7 capability: {key}")
    require(set(caps) - set(old) == NEW_CAPABILITIES, "Phase 8 capability delta drift")
    require(all(caps[key] is True for key in NEW_CAPABILITIES), "Phase 8 transport capability not established")
    for key in ("oracle_holodeck_synthetic_admission", "host_level_sandbox", "production_networking", "remote_execution", "interoperable_federation"):
        require(caps[key] is False, f"Phase 8 deployment/authority overclaim: {key}")
    require(rust_claims() == caps, "Rust current claims disagree with Phase 8")


def validate_contract() -> None:
    state = load("state/phase8.json")
    require(state.get("document_type") == "qsol-fed-phase8-transport-resilience-contract", "Phase 8 state id drift")
    require(state.get("transport_contract") == "qsol-fed-transport/1", "transport contract id drift")
    require(state.get("maximum_frame_bytes") == 65536, "transport frame bound drift")
    require(state.get("maximum_queue_depth") == 1024, "transport queue bound drift")
    require(state.get("maximum_relay_hops") == 16, "relay bound drift")
    profiles = state["profiles"]
    require(set(profiles) == EXPECTED_PROFILES, "transport profile set drift")
    for name, profile in profiles.items():
        require(profile["live_backend_claimed"] is False, f"Phase 8 overclaimed live backend: {name}")

    identity = state["identity_boundary"]
    require(identity["identity_source"] == "phase2-authenticated-envelope-identity", "transport identity source drift")
    for key in ("transport_profile_may_replace_sender_identity", "transport_route_may_create_trust", "transport_route_may_create_authority"):
        require(identity[key] is False, f"transport identity/authority boundary drift: {key}")
    for key in (
        "message_id_preserved_across_transports", "payload_ref_preserved_across_transports",
        "provenance_ref_preserved_across_transports", "transport_acceptance_requires_signature_valid",
        "transport_acceptance_requires_current_identity", "transport_acceptance_requires_fresh_replay_state",
        "transport_acceptance_requires_local_peer_admission", "verified_sender_node_must_match_frame_sender",
        "verified_identity_ref_bound_to_nat_ticket", "direct_profiles_require_local_recipient",
        "forwarding_profiles_require_explicit_relay_admission", "recipient_or_relay_checked_before_replay_freshness",
    ):
        require(identity[key] is True, f"transport admission/identity preservation drift: {key}")

    nat = state["nat_traversal"]
    require(set(nat["profiles"]) == {"web_socket", "quic"}, "NAT profile set drift")
    require(nat["maximum_candidates"] == 8 and nat["maximum_ticket_lifetime_seconds"] == 600, "NAT bounds drift")
    require(nat["clock_skew_seconds"] == 300, "NAT clock skew drift")
    for key in ("ticket_is_route_hint_only", "ticket_node_must_match_authenticated_sender", "ticket_identity_ref_must_match_verified_identity", "active_time_window_required"):
        require(nat[key] is True, f"NAT identity/time binding drift: {key}")
    require(nat["endpoint_syntax"] == "strict-host-or-ip-plus-port", "NAT endpoint syntax drift")
    for key in ("url_path_query_fragment_userinfo_percent_escape_allowed", "ticket_grants_trust", "ticket_grants_authority", "candidate_may_embed_credentials", "identity_weakening_allowed"):
        require(nat[key] is False, f"NAT authority/credential drift: {key}")

    relay = state["multi_relay_provenance"]
    require(relay["maximum_hops"] == 16, "relay maximum drift")
    for key in (
        "every_hop_preserves_frame_id", "every_hop_preserves_message_id", "every_hop_preserves_payload_ref",
        "every_hop_preserves_provenance_ref", "every_hop_links_previous_receipt",
        "first_ingress_matches_frame_profile", "adjacent_hops_transport_continuous",
    ):
        require(relay[key] is True, f"relay provenance drift: {key}")
    require(relay["relay_presence_is_trust"] is False and relay["relay_presence_is_authority"] is False, "relay gained trust/authority")

    sf = state["store_forward"]
    require(sf["maximum_queue_depth"] == 1024 and sf["duplicate_frame_rejected"] is True and sf["fifo_order_preserved"] is True, "store-forward bound/order drift")
    require(sf["partition_backlog_bounded"] is True and sf["dequeue_changes_frame_identity"] is False and sf["physical_or_archival_presence_is_authority"] is False, "store-forward sovereignty drift")

    recovery = state["disaster_recovery"]
    require(recovery["compromised_or_noncurrent_identity_rejected_on_every_profile"] is True, "key-compromise drill drift")
    require(recovery["transport_path_may_revive_compromised_key"] is False, "transport can revive compromised key")
    require(recovery["phase2_key_lifecycle_remains_authoritative"] is True, "Phase 2 lifecycle authority drift")
    require(recovery["transport_failover_may_skip_replay_checks"] is False and recovery["transport_failover_may_skip_local_admission"] is False, "transport failover bypass drift")

    archive = state["archive_compatibility"]
    require(archive["policy"] == "qsol-fed-archive-compatibility/1", "archive policy id drift")
    require(archive["canonical_profile"] == "qsol-fed-canonical-json/1" and archive["wire_protocol"] == "qsol-fed/1", "archive protocol/profile drift")
    require(archive["preserve_canonical_bytes"] is True and archive["preserve_object_identity"] is True, "archive identity preservation drift")
    require(archive["historical_receipts_reinterpreted"] is False and archive["migration_requires_new_artifact"] is True, "archive reinterpretation drift")
    require(archive["unknown_major_policy"] == "reject-until-explicit-migration-contract", "archive unknown-major drift")

    matrix = state["drill_matrix"]
    require(set(matrix["profiles"]) == EXPECTED_PROFILES, "drill profile matrix drift")
    require(set(matrix["drills"]) == EXPECTED_DRILLS, "drill kind matrix drift")
    for key, value in matrix.items():
        if key.startswith("every_profile_runs_"):
            require(value is True, f"cross-profile drill coverage drift: {key}")
    require(matrix["failed_reports_name_detected_boundary"] is True, "failed drill reporting drift")

    holo = state["holodeck_transport_independence"]
    require(holo["invariant"] == "transport_does_not_enter_holodeck_sandbox", "Holodeck transport invariant id drift")
    require(holo["drill_uses_real_teardown_receipt"] is True and holo["boundary_violation_exercised_before_teardown"] is True, "Holodeck real-receipt drill drift")
    require(holo["transport_outside_sandbox_may_relabel_sandbox_network_use"] is False, "transport rewrites Holodeck network receipt")
    require(holo["authority_effect"] == "none" and holo["federation_effect"] == "none" and holo["evidence_effect"] == "none", "Holodeck effect drift under transport")
    require(holo["network_used"] is False and holo["real_tools_used"] is False and holo["credentials_exposed"] is False, "Holodeck safeguard drift under transport")

    authority = state["authority_boundary"]
    require(set(authority) == EXPECTED_AUTHORITY_KEYS, "transport authority-boundary key set drift")
    require(all(authority[key] is False for key in EXPECTED_AUTHORITY_KEYS), "transport gained forbidden authority effect")
    nonclaims = state["deployment_nonclaims"]
    require(all(value is False for value in nonclaims.values()), "Phase 8 deployment non-claim drift")


def validate_schemas_and_source() -> None:
    frame = load("schemas/transport-frame-v1.schema.json")
    nat = load("schemas/nat-traversal-ticket-v1.schema.json")
    relay = load("schemas/relay-receipt-v1.schema.json")
    offline = load("schemas/offline-package-v1.schema.json")
    drill = load("schemas/transport-drill-report-v1.schema.json")
    for name, schema in (("frame", frame), ("NAT", nat), ("relay", relay), ("offline", offline), ("drill", drill)):
        require(schema.get("additionalProperties") is False, f"Phase 8 {name} schema must remain closed")
    require(frame["properties"]["sequence"].get("maximum") == SAFE_MAX, "transport frame canonical integer maximum drift")
    require(frame["properties"]["authority_effect"].get("const") == "none", "transport frame authority schema drift")
    require(nat["properties"]["issued_at_unix"].get("minimum") == SAFE_MIN and nat["properties"]["issued_at_unix"].get("maximum") == SAFE_MAX, "NAT issued timestamp safe range drift")
    require(nat["properties"]["expires_at_unix"].get("minimum") == SAFE_MIN and nat["properties"]["expires_at_unix"].get("maximum") == SAFE_MAX, "NAT expiry timestamp safe range drift")
    endpoint = nat["properties"]["candidates"]["items"]["properties"]["endpoint"]
    require("pattern" in endpoint and endpoint.get("maxLength") == 512, "NAT endpoint schema constraint drift")
    require(nat["properties"]["grants_trust"].get("const") is False and nat["properties"]["grants_authority"].get("const") is False, "NAT schema gained trust/authority")
    require("provenance_ref" in relay.get("required", []), "relay schema missing provenance binding")
    require(relay["properties"]["authority_effect"].get("const") == "none", "relay schema authority drift")
    require(offline["properties"]["authority_effect"].get("const") == "none", "offline package schema authority drift")
    for key in ("identity_weakened", "authority_promoted", "provenance_lost", "resource_bound_breached", "holodeck_invariant_drift"):
        require(drill["properties"][key].get("type") == "boolean" and "const" not in drill["properties"][key], f"drill failure indicator schema drift: {key}")

    source = (ROOT / "src/transport.rs").read_text(encoding="utf-8")
    for marker in (
        "ALL_TRANSPORT_PROFILES",
        "frame_sender_must_match_verified_signing_identity",
        "direct_recipient_and_forwarding_relay_roles_are_explicit",
        "nat_traversal_cannot_weaken_identity",
        "nat_ticket_requires_active_window_and_credential_free_endpoint",
        "canonical_integer_bounds_match_transport_schemas",
        "multi_relay_provenance_is_explicit_and_non_transitive",
        "relay_chain_requires_transport_continuity_and_original_provenance",
        "compromised_identity_fails_on_every_transport",
        "resource_exhaustion_and_partition_drills_cover_every_profile",
        "failed_drill_reports_name_the_breached_boundary",
        "long_lived_archive_policy_is_transport_neutral",
        "offline_and_store_forward_preserve_frame_and_relay_identity",
        "holodeck_sandbox_invariants_are_transport_independent",
        "every_profile_runs_the_complete_resilience_matrix",
        "run_holodeck_transport_independence_drill",
        "holodeck_receipt_required",
        "TRANSPORT_HOLODECK_INVARIANT",
        "phase2-authenticated-envelope-identity",
    ):
        require(marker in source, f"Phase 8 Rust marker missing: {marker}")
    production = production_rust(source)
    require(rust_use_statements(production) == EXPECTED_TRANSPORT_USES, "Phase 8 transport production import allowlist drift")
    for forbidden in FORBIDDEN_PRODUCTION_PATHS:
        require(forbidden not in production, f"Phase 8 transport core gained forbidden production capability: {forbidden}")


def validate_surfaces_and_ci() -> None:
    docs = (ROOT / "TRANSPORTS.md").read_text(encoding="utf-8")
    for marker in (
        "TRANSPORT != IDENTITY",
        "ROUTE != TRUST",
        "RELAY != AUTHORITY",
        "PARTITION RECOVERY != SILENT RECONCILIATION",
        "NETWORK OUTSIDE HOLODECK != NETWORK INSIDE HOLODECK",
        "REFERENCE TRANSPORT PROFILE != PRODUCTION NETWORK SERVICE",
        "Transport may change delivery, never identity, authority, provenance, admission, or sandbox law",
    ):
        require(marker in docs, f"TRANSPORTS.md marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("## Phase 8 — Additional transports and resilience" in roadmap, "ROADMAP Phase 8 missing")
    require("Status: current" in roadmap and "claims/phase8.json" in roadmap, "ROADMAP Phase 8 current status missing")
    for marker in ("WebSocket", "QUIC", "Unix/local IPC", "offline/sneakernet", "store-forward", "NAT traversal", "Multi-relay provenance", "Holodeck sandbox invariants remain transport-independent"):
        require(marker in roadmap, f"ROADMAP Phase 8 marker missing: {marker}")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in ("state/phase8.json", "claims/phase8.json", "TRANSPORTS.md", "src/transport.rs", "python3 tools/validate_phase8_gate.py"):
        require(marker in agents, f"AGENTS Phase 8 marker missing: {marker}")

    ai = load("README4AI.md")
    require(ai.get("phase8_status") == "transport_resilience_gate_enforced", "README4AI Phase 8 status missing")
    require(ai.get("current_claim_manifest") == "claims/phase8.json", "README4AI current Phase 8 manifest drift")
    require(ai.get("current_claims") == load("claims/phase8.json")["capabilities"], "README4AI Phase 8 claims drift")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase8_gate.py" in workflow, "CI missing Phase 8 gate")
    require("cargo test --all-targets" in workflow, "CI missing Phase 8 Rust drills")


def main() -> None:
    validate_claims()
    validate_contract()
    validate_schemas_and_source()
    validate_surfaces_and_ci()
    print("phase8 transport-resilience gate OK: five bounded reference profiles bind verified sender/recipient roles before replay, enforce active credential-free NAT routes, preserve continuous relay provenance, truthfully report drill failures, and prove real Holodeck teardown receipts remain transport-independent")


if __name__ == "__main__":
    main()
