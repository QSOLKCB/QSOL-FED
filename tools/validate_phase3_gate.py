#!/usr/bin/env python3
"""Enforce the Phase 3 reference federation API and opt-in listener boundary."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_API = {
    "document_type": "qsol-fed-phase3-api-contract",
    "schema_version": 1,
    "wire_protocol": "qsol-fed/1",
    "base_path": "/fed/v1",
    "service": "Rust axum reference HTTP/1 service",
    "routes": [
        "GET /fed/v1/node",
        "GET /fed/v1/capabilities",
        "POST /fed/v1/peer/hello",
        "POST /fed/v1/envelopes",
        "GET /fed/v1/objects/{sha256}",
        "GET /fed/v1/provenance/{sha256}",
    ],
    "limits": {
        "max_http_body_bytes": 65536,
        "max_json_depth": 32,
        "max_string_utf8_bytes": 8192,
        "max_array_items": 1024,
        "max_object_members": 1024,
        "max_capabilities_per_hello": 64,
        "max_requests_per_ip_per_minute": 120,
        "max_posts_per_ip_per_minute": 30,
        "max_local_export_objects": 4096,
    },
    "post_body_policy": {
        "content_type": "application/json only",
        "canonical_json_required": True,
        "content_encoding": "forbidden",
        "query_parameters": "forbidden",
    },
    "peer_hello": {
        "schema": "qsol-fed-peer-hello/1",
        "effect": "introduces verified public identity and capabilities into in-memory non-trust state only",
        "peering_is_trust": False,
        "peering_is_authority": False,
    },
    "envelope_pipeline": [
        "strict HTTP limits",
        "canonical signed-envelope bytes",
        "introduced peer identity lookup",
        "Ed25519 verification under frozen Phase 2 clock limits",
        "durable replay record",
        "Prime Directive admission",
        "data-only or reject response",
    ],
    "retrieval_policy": "objects and provenance are served only from explicitly registered local export bytes; missing content returns 404 and never triggers outbound retrieval",
    "outbound_http_client": False,
    "redirect_generation": False,
    "ssrf_policy": "no URL-bearing fetch field, no outbound HTTP client, no redirect-following, exact sha256 retrieval paths only",
    "audit_policy": {
        "format": "JSON Lines",
        "logs_request_body": False,
        "logs_headers": False,
        "logs_signatures": False,
        "logs_private_keys": False,
        "allowed_semantic_fields": [
            "timestamp_unix",
            "request_id",
            "event",
            "method",
            "route_label",
            "status",
            "remote_ip",
            "node_id",
            "message_id",
            "decision",
        ],
    },
    "listener_policy": {
        "default_bind": "127.0.0.1:8787",
        "non_loopback_requires": ["--allow-public-listen", "--tls-terminated-upstream"],
        "public_listen_default": False,
    },
    "tls_profile": {
        "document": "TLS_PROFILE.md",
        "minimum": "TLS 1.3",
        "reference_pattern": "loopback service behind a same-host or authenticated upstream TLS terminator",
        "native_tls_in_reference_binary": False,
    },
    "fuzz": {
        "libfuzzer_target": "fuzz/fuzz_targets/wire_and_admission.rs",
        "ci_smoke": "deterministic parser/admission mutation test in src/api.rs",
        "pseudo_admin_fields": ["force", "trusted", "override", "admin", "fetch_url", "redirect"],
    },
    "production_networking": False,
    "remote_execution": False,
    "interoperable_federation": False,
    "gate": "public network listening is opt-in and the reference service is claimable only while replay, limits, identity verification, adversarial tests, and parser/admission fuzz smoke are green",
}

EXPECTED_CLAIMS = {
    "document_type": "qsol-fed-phase3-claims",
    "schema_version": 1,
    "protocol": "qsol-fed/0",
    "wire_protocol": "qsol-fed/1",
    "phase": 3,
    "gate_id": "qsol-fed-phase3-claim-gate/1",
    "gate_status": "enforced",
    "historical_baselines": ["claims/phase0.json", "claims/phase2.json"],
    "runtime_override_allowed": False,
    "capabilities": {
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
    },
    "claim_rule": "Only capabilities with value true may be described as established by the current repository state. The Phase 3 listener is opt-in reference networking, not a production-networking claim. HTTP transport never creates trust, authority, evidence, or admission.",
    "promotion_requirements": {
        "production_networking": "requires a later production deployment profile with mature concurrency, operational hardening, deployment evidence, and explicit claim promotion",
        "remote_execution": "not admitted by the current roadmap; requires separate constitutional design and review",
        "interoperable_federation": "requires Phase 4 peer lifecycle and object-store semantics plus multi-implementation deployed interop evidence",
    },
}

CURRENT_BEGIN = "<!-- CURRENT_CLAIM_BOUNDARY:BEGIN -->"
CURRENT_END = "<!-- CURRENT_CLAIM_BOUNDARY:END -->"


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


def extract_current_claim_block(readme: str) -> str:
    require(readme.count(CURRENT_BEGIN) == 1, "README current claim begin marker drift")
    require(readme.count(CURRENT_END) == 1, "README current claim end marker drift")
    start = readme.index(CURRENT_BEGIN) + len(CURRENT_BEGIN)
    end = readme.index(CURRENT_END, start)
    return readme[start:end]


def validate_schema() -> None:
    schema = load_json("schemas/peer-hello-v1.schema.json")
    require(schema.get("$id") == "qsol-fed-peer-hello/1", "peer hello schema id drift")
    require(schema.get("additionalProperties") is False, "peer hello schema must be closed")
    require(schema["properties"]["protocol"].get("const") == "qsol-fed/1", "peer hello protocol drift")
    require(schema["properties"]["authority_claim"].get("const") == "none", "peer hello authority drift")
    require(schema["properties"]["capabilities"].get("maxItems") == 64, "peer hello capability limit drift")
    require(schema["properties"]["capabilities"].get("uniqueItems") is True, "peer hello capability uniqueness drift")


def validate_source() -> None:
    api = (ROOT / "src/api.rs").read_text(encoding="utf-8")
    binary = (ROOT / "src/bin/qsol-fed.rs").read_text(encoding="utf-8")
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")

    for marker in (
        'pub const API_MAX_BODY_BYTES: usize = 65_536;',
        'pub const API_MAX_CAPABILITIES: usize = 64;',
        'pub const API_REQUESTS_PER_MINUTE: u32 = 120;',
        'pub const API_POSTS_PER_MINUTE: u32 = 30;',
        'pub const API_MAX_EXPORT_OBJECTS: usize = 4_096;',
        '"/fed/v1/node"',
        '"/fed/v1/capabilities"',
        '"/fed/v1/peer/hello"',
        '"/fed/v1/envelopes"',
        '"/fed/v1/objects/{object_id}"',
        '"/fed/v1/provenance/{object_id}"',
        'content_encoding_not_admitted',
        'query_parameters_not_admitted',
        'request_json_not_canonical',
        'peer_not_introduced',
        'replayed_message',
        'accepted_as_data',
        'deterministic_fuzz_smoke_never_panics_parser_or_admission',
        'pseudo_admin_and_ssrf_like_fields_fail_closed',
        'object_and_provenance_routes_are_local_only_and_never_redirect',
    ):
        require(marker in api, f"Phase 3 API source marker missing: {marker}")

    for field in ("force", "trusted", "override", "admin", "fetch_url", "redirect"):
        require(f'"{field}"' in api, f"pseudo-admin/SSRF regression marker missing: {field}")

    for marker in (
        '"127.0.0.1:8787"',
        '"--allow-public-listen"',
        '"--tls-terminated-upstream"',
        'if !listen.ip().is_loopback()',
    ):
        require(marker in binary, f"listener opt-in marker missing: {marker}")

    forbidden_dependency_tokens = ("reqwest", "ureq", "curl", "isahc", "surf")
    lower_cargo = cargo.lower()
    for token in forbidden_dependency_tokens:
        require(token not in lower_cargo, f"outbound HTTP client dependency forbidden in Phase 3: {token}")
    for token in ("reqwest::", "hyper::client", "TcpStream::connect", "follow_redirect"):
        require(token not in api and token not in binary, f"outbound fetch/redirect code forbidden in Phase 3: {token}")

    audit_match = re.search(r"pub struct AuditRecord \{(?P<body>.*?)\n\}", api, flags=re.S)
    require(audit_match is not None, "AuditRecord missing")
    audit_body = audit_match.group("body").lower()
    for forbidden in ("body", "header", "signature", "private", "payload", "token", "secret"):
        require(forbidden not in audit_body, f"secret-bearing audit field forbidden: {forbidden}")


def validate_tls_and_fuzz() -> None:
    tls = (ROOT / "TLS_PROFILE.md").read_text(encoding="utf-8")
    for marker in (
        "TLS 1.3",
        "127.0.0.1:8787",
        "--allow-public-listen",
        "--tls-terminated-upstream",
        "no outbound HTTP client",
        "Production non-claim",
    ):
        require(marker in tls, f"TLS profile marker missing: {marker}")

    fuzz = (ROOT / "fuzz/fuzz_targets/wire_and_admission.rs").read_text(encoding="utf-8")
    for marker in ("fuzz_target!", "canonicalize(data)", "SignedEnvelope::from_wire(data)", "admit_effect(effect)"):
        require(marker in fuzz, f"fuzz target marker missing: {marker}")
    fuzz_manifest = (ROOT / "fuzz/Cargo.toml").read_text(encoding="utf-8")
    require("libfuzzer-sys" in fuzz_manifest, "libFuzzer dependency missing")
    require('name = "wire_and_admission"' in fuzz_manifest, "wire/admission fuzz binary missing")


def validate_contracts_and_claims() -> None:
    contract = load_json("api/phase3.json")
    require(contract == EXPECTED_API, "Phase 3 API machine contract drift")
    claims = load_json("claims/phase3.json")
    require(claims == EXPECTED_CLAIMS, "Phase 3 current claim manifest drift")

    phase2 = load_json("claims/phase2.json")
    require(phase2.get("document_type") == "qsol-fed-phase2-claims", "Phase 2 historical claim baseline missing")
    require(phase2["capabilities"]["production_networking"] is False, "Phase 2 historical networking claim rewritten")

    rust_claims = rust_current_claims((ROOT / "src/claims.rs").read_text(encoding="utf-8"))
    require(rust_claims == claims["capabilities"], "Rust CURRENT_CLAIMS disagree with Phase 3 manifest")

    ai = load_json("README4AI.md")
    require(ai.get("status") == "phase3_gate_enforced", "README4AI Phase 3 status drift")
    require(ai.get("current_claim_manifest") == "claims/phase3.json", "README4AI current claim manifest drift")
    require(ai.get("current_claims") == claims["capabilities"], "README4AI current claims disagree with Phase 3 manifest")
    require(ai.get("phase3_api", {}).get("contract") == "api/phase3.json", "README4AI Phase 3 API map missing")
    require(ai.get("phase3_api", {}).get("outbound_http_client") is False, "README4AI outbound HTTP client drift")
    require(ai.get("claim_disagreement_policy") == "fail_closed", "claim disagreement policy must remain fail_closed")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    current = extract_current_claim_block(readme)
    for marker in (
        "reference HTTP service: **established and tested**",
        "opt-in network listener: **established and tested**",
        "bounded API limits: **established and tested**",
        "TLS deployment profile: **established and tested**",
        "secret-safe audit log: **established and tested**",
        "API fuzz/adversarial suite: **established and tested**",
        "production networking: **not established**",
        "remote execution: **not established**",
        "interoperable federation: **not established**",
    ):
        require(marker in current, f"README current Phase 3 claim missing: {marker}")


def validate_repository_gate() -> None:
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; opt-in reference API gate enforced.**" in roadmap, "ROADMAP Phase 3 status drift")
    require("Public network listening remains opt-in" in roadmap, "ROADMAP Phase 3 gate wording missing")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in ("api/phase3.json", "TLS_PROFILE.md", "claims/phase3.json", "python3 tools/validate_phase3_gate.py"):
        require(marker in agents, f"AGENTS.md Phase 3 marker missing: {marker}")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("cargo test --all-targets" in workflow, "CI missing Rust API/adversarial tests")
    require("python3 tools/validate_phase2_gate.py" in workflow, "CI missing historical Phase 2 gate")
    require("python3 tools/validate_phase3_gate.py" in workflow, "CI missing Phase 3 API gate")


def main() -> None:
    validate_schema()
    validate_source()
    validate_tls_and_fuzz()
    validate_contracts_and_claims()
    validate_repository_gate()
    print(
        "phase3 api gate OK: six bounded routes, opt-in listener, local-only retrieval, "
        "SSRF/redirect denial, secret-safe audit surface, and fuzz/adversarial coverage enforced"
    )


if __name__ == "__main__":
    main()
