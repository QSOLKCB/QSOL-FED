#!/usr/bin/env python3
"""Preserve the historical Phase 3 reference API security contract."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_ROUTES = [
    "GET /fed/v1/node",
    "GET /fed/v1/capabilities",
    "POST /fed/v1/peer/hello",
    "POST /fed/v1/envelopes",
    "GET /fed/v1/objects/{sha256}",
    "GET /fed/v1/provenance/{sha256}",
]

EXPECTED_CLAIMS = {
    "constitutional_model": True,
    "machine_contracts": True,
    "fail_closed_admission_skeleton": True,
    "tested_constitutional_core": True,
    "canonical_wire_contract": True,
    "cryptographic_identity": True,
    "signed_envelope_verification": True,
    "key_lifecycle": True,
    "durable_replay_protection": True,
    "reference_http_service": True,
    "opt_in_network_listener": True,
    "bounded_api_limits": True,
    "tls_deployment_profile": True,
    "secret_safe_audit_log": True,
    "api_fuzz_adversarial_suite": True,
    "production_networking": False,
    "remote_execution": False,
    "interoperable_federation": False,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rust_current_claims(source: str) -> dict[str, bool]:
    marker = "pub const CURRENT_CLAIMS: CurrentClaims = CurrentClaims {"
    start = source.find(marker)
    require(start >= 0, "Rust CURRENT_CLAIMS registry missing")
    body_start = start + len(marker)
    body_end = source.find("\n};", body_start)
    require(body_end >= 0, "Rust CURRENT_CLAIMS registry is not terminated")
    body = source[body_start:body_end]
    pairs = re.findall(r"\b([a-z0-9_]+):\s*(true|false),", body)
    claims = {name: value == "true" for name, value in pairs}
    require(len(claims) == len(pairs), "duplicate Rust current claim field")
    return claims


def validate_contract() -> None:
    contract = load_json("api/phase3.json")
    require(contract.get("document_type") == "qsol-fed-phase3-api-contract", "Phase 3 contract id drift")
    require(contract.get("wire_protocol") == "qsol-fed/1", "Phase 3 wire protocol drift")
    require(contract.get("routes") == EXPECTED_ROUTES, "Phase 3 route contract drift")
    limits = contract.get("limits", {})
    require(limits.get("max_http_body_bytes") == 65536, "Phase 3 body limit drift")
    require(limits.get("max_capabilities_per_hello") == 64, "Phase 3 capability limit drift")
    require(limits.get("max_lifecycle_records_per_hello") == 128, "Phase 3 lifecycle limit drift")
    require(limits.get("max_requests_per_client_per_minute") == 120, "Phase 3 request-rate drift")
    require(limits.get("max_posts_per_client_per_minute") == 30, "Phase 3 POST-rate drift")
    replay = contract.get("replay_policy", {})
    require(replay.get("retention_seconds") == 4200, "Phase 3 replay retention drift")
    require(replay.get("compaction_threshold_bytes") == 1048576, "Phase 3 replay compaction threshold drift")
    require(replay.get("hard_limit_bytes") == 67108864, "Phase 3 replay hard limit drift")
    require(contract.get("recipient_policy", "").startswith("a valid envelope is admitted only when recipient equals"), "recipient policy missing")
    require(contract.get("outbound_http_client") is False, "outbound HTTP client must remain false")
    require(contract.get("redirect_generation") is False, "redirect generation must remain false")
    audit = contract.get("audit_policy", {})
    require(audit.get("production_in_memory_copy") is False, "production audit memory copy must remain false")
    require(audit.get("replay_and_audit_paths_must_be_distinct") is True, "replay/audit path separation drift")
    listener = contract.get("listener_policy", {})
    require(listener.get("non_loopback_requires") == ["--allow-public-listen", "--tls-terminated-upstream", "--trusted-proxy IP"], "public listener requirements drift")
    require(contract.get("production_networking") is False, "production networking prematurely promoted")
    require(contract.get("remote_execution") is False, "remote execution prematurely promoted")
    require(contract.get("interoperable_federation") is False, "interop prematurely promoted")


def validate_schema_and_source() -> None:
    schema = load_json("schemas/peer-hello-v1.schema.json")
    require(schema.get("$id") == "qsol-fed-peer-hello/1", "peer hello schema id drift")
    require(schema.get("additionalProperties") is False, "peer hello schema must be closed")
    lifecycle = schema["properties"]["lifecycle"]
    require(lifecycle.get("maxItems") == 128, "peer hello lifecycle limit drift")
    require(schema["properties"]["capabilities"].get("maxItems") == 64, "peer hello capability limit drift")
    require(schema["properties"]["authority_claim"].get("const") == "none", "peer hello authority drift")

    api = (ROOT / "src/api.rs").read_text(encoding="utf-8")
    replay = (ROOT / "src/replay.rs").read_text(encoding="utf-8")
    binary = (ROOT / "src/bin/qsol-fed.rs").read_text(encoding="utf-8")
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8").lower()
    for marker in (
        "API_MAX_BODY_BYTES: usize = 65_536",
        "API_MAX_CAPABILITIES: usize = 64",
        "API_MAX_LIFECYCLE_RECORDS: usize = 128",
        "RATE_LIMIT_CLIENT_IP_HEADER",
        "peer_lifecycle_rollback_rejected",
        "envelope_not_addressed_to_local_node",
        "replay_and_audit_paths_must_be_distinct",
        "trusted_proxy_client_rate_buckets_are_separate",
        "envelope_for_another_node_is_rejected_before_replay",
        "peer_lifecycle_reintroduction_cannot_roll_back",
    ):
        require(marker in api, f"Phase 3 API source marker missing: {marker}")
    for marker in ("REPLAY_RETENTION_SECONDS", "REPLAY_COMPACTION_THRESHOLD_BYTES", "fn compact(&mut self", "replay_active_window_too_large"):
        require(marker in replay, f"Phase 3 replay marker missing: {marker}")
    for marker in ('"--allow-public-listen"', '"--tls-terminated-upstream"', '"--trusted-proxy"', "new_with_trusted_proxy"):
        require(marker in binary, f"Phase 3 listener marker missing: {marker}")
    for token in ("reqwest", "ureq", "curl", "isahc", "surf"):
        require(token not in cargo, f"outbound HTTP client dependency forbidden in Phase 3: {token}")


def validate_tls_fuzz_and_claim_snapshot() -> None:
    tls = (ROOT / "TLS_PROFILE.md").read_text(encoding="utf-8")
    for marker in ("TLS 1.3", "127.0.0.1:8787", "--trusted-proxy", "x-qsol-client-ip", "no outbound HTTP client"):
        require(marker in tls, f"TLS profile marker missing: {marker}")
    fuzz = (ROOT / "fuzz/fuzz_targets/wire_and_admission.rs").read_text(encoding="utf-8")
    for marker in ("fuzz_target!", "canonicalize(data)", "SignedEnvelope::from_wire(data)", "admit_effect(effect)"):
        require(marker in fuzz, f"fuzz target marker missing: {marker}")

    claims = load_json("claims/phase3.json")
    require(claims.get("document_type") == "qsol-fed-phase3-claims", "Phase 3 claims id drift")
    require(claims.get("gate_status") == "enforced", "Phase 3 gate status drift")
    require(claims.get("capabilities") == EXPECTED_CLAIMS, "historical Phase 3 claim capabilities drift")

    current = rust_current_claims((ROOT / "src/claims.rs").read_text(encoding="utf-8"))
    for name, historical_value in EXPECTED_CLAIMS.items():
        require(current.get(name) == historical_value, f"current claims no longer preserve Phase 3 capability {name}")

    ai = load_json("README4AI.md")
    require(ai.get("phase3_status") in {"reference_api_gate_enforced", "historical_api_gate_preserved"}, "README4AI Phase 3 preservation marker missing")
    require(ai.get("phase3_api", {}).get("contract") == "api/phase3.json", "README4AI Phase 3 API map missing")
    require(ai.get("claim_disagreement_policy") == "fail_closed", "claim disagreement policy must remain fail_closed")


def validate_repository_gate() -> None:
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; opt-in reference API gate enforced.**" in roadmap, "ROADMAP Phase 3 status drift")
    require("Public network listening remains opt-in" in roadmap, "ROADMAP Phase 3 gate wording missing")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8").lower()
    for marker in ("api/phase3.json", "tls_profile.md", "claims/phase3.json", "trusted proxy", "replay compaction"):
        require(marker in agents, f"AGENTS.md Phase 3 marker missing: {marker}")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase3_gate.py" in workflow, "CI missing historical Phase 3 gate")


def main() -> None:
    validate_contract()
    validate_schema_and_source()
    validate_tls_fuzz_and_claim_snapshot()
    validate_repository_gate()
    print("phase3 historical API gate OK: listener, routing, replay, proxy, limits, SSRF, audit, and fuzz contract preserved")


if __name__ == "__main__":
    main()
