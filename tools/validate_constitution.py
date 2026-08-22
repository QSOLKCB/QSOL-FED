#!/usr/bin/env python3
"""Fail closed when the constitutional surfaces drift."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_FALSE_FLAGS = {
    "remote_arbitrary_execution_enabled",
    "remote_governance_mutation_enabled",
    "remote_evidence_promotion_enabled",
    "remote_vote_creation_enabled",
    "remote_capability_installation_enabled",
    "remote_history_rewrite_enabled",
    "remote_citizenship_mutation_enabled",
    "remote_local_authority_claim_enabled",
    "foreign_import_becomes_local_authority",
    "secrets_in_semantic_state_allowed",
    "runtime_constitution_override_allowed",
}


def load_json(path: str) -> dict:
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected top-level JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def rust_hard_invariant_ids(source: str) -> list[str]:
    marker = "pub const HARD_INVARIANTS: &[HardInvariant] = &["
    start = source.find(marker)
    require(start >= 0, "Rust HARD_INVARIANTS registry missing")
    body_start = start + len(marker)
    body_end = source.find("\n];", body_start)
    require(body_end >= 0, "Rust HARD_INVARIANTS registry is not terminated")
    body = source[body_start:body_end]
    return re.findall(r'\bid:\s*"([a-z0-9_]+)"', body)


def main() -> None:
    registry = load_json("invariants/fed-v1.json")
    ai_manifest = load_json("README4AI.md")
    envelope_schema = load_json("schemas/federation-envelope.schema.json")
    node_schema = load_json("schemas/node-manifest.schema.json")

    require(registry.get("registry") == "qsol-fed-invariants/1", "wrong invariant registry id")
    require(registry.get("protocol") == "qsol-fed/0", "wrong constitutional registry protocol")
    require(ai_manifest.get("protocol") == "qsol-fed/0", "README4AI constitutional protocol drift")

    flags = registry.get("constitutional_flags")
    require(isinstance(flags, dict), "missing constitutional_flags")
    require(set(flags) == EXPECTED_FALSE_FLAGS, "constitutional flag set drift")
    for name in sorted(EXPECTED_FALSE_FLAGS):
        require(flags[name] is False, f"constitutional flag must remain false: {name}")

    overrides = registry.get("runtime_override_sources")
    require(isinstance(overrides, dict) and overrides, "missing runtime_override_sources")
    for source, allowed in overrides.items():
        require(allowed is False, f"runtime constitutional override unexpectedly enabled: {source}")

    policies = registry.get("default_policies")
    require(policies == {
        "unknown_authority_action": "reject",
        "foreign_semantic_material": "accept_as_data_only",
        "foreign_state_import": "quarantine",
        "unsupported_major_protocol": "reject",
        "unknown_message_class": "reject",
    }, "default policy drift")

    invariants = registry.get("invariants")
    require(isinstance(invariants, list) and invariants, "missing invariants")
    invariant_ids = [item.get("id") for item in invariants if isinstance(item, dict)]
    require(len(invariant_ids) == len(invariants), "malformed invariant entry")
    require(len(set(invariant_ids)) == len(invariant_ids), "duplicate invariant id")

    rust_source = (ROOT / "src/invariants.rs").read_text(encoding="utf-8")
    rust_registry_ids = rust_hard_invariant_ids(rust_source)
    require(len(set(rust_registry_ids)) == len(rust_registry_ids), "duplicate Rust HARD_INVARIANTS id")
    require(set(rust_registry_ids) == set(invariant_ids), "Rust HARD_INVARIANTS registry drift")
    require(len(rust_registry_ids) == len(invariant_ids), "Rust HARD_INVARIANTS cardinality drift")

    ai_invariants = ai_manifest.get("authority_invariants")
    require(isinstance(ai_invariants, list), "README4AI authority_invariants missing")
    require(not (set(ai_invariants) - set(invariant_ids)), "README4AI references unknown invariants")

    hardening = ai_manifest.get("hardening")
    require(isinstance(hardening, dict), "README4AI hardening missing")
    for key in (
        "runtime_override_of_constitution",
        "environment_override_of_constitution",
        "peer_override_of_constitution",
        "model_override_of_constitution",
    ):
        require(hardening.get(key) is False, f"README4AI hardening drift: {key}")

    envelope_properties = envelope_schema.get("properties", {})
    require(envelope_properties.get("protocol", {}).get("const") == "qsol-fed/1", "frozen wire envelope protocol drift")
    require(envelope_properties.get("authority_claim", {}).get("const") == "none", "envelope authority claim drift")
    require(envelope_schema.get("additionalProperties") is False, "envelope must reject unknown fields")

    node_properties = node_schema.get("properties", {})
    require(node_properties.get("protocol", {}).get("const") == "qsol-fed/0", "bootstrap node-manifest protocol drift")
    require(node_properties.get("authority_claim", {}).get("const") == "none", "node manifest authority claim drift")
    require(node_schema.get("additionalProperties") is False, "node manifest must reject unknown fields")

    envelope_required = set(envelope_schema.get("required", []))
    for field in ("provenance_ref", "expires_at", "signature"):
        require(field in envelope_required, f"envelope required field drift: {field}")

    prime_directive = (ROOT / "PRIME_DIRECTIVE.md").read_text(encoding="utf-8")
    require("No emergency backdoor" in prime_directive, "Prime Directive emergency-backdoor section missing")
    require("runtime" in prime_directive.lower(), "Prime Directive runtime boundary missing")

    print(f"constitutional contract OK: {len(invariant_ids)} invariant ids, {len(EXPECTED_FALSE_FLAGS)} hard false flags")


if __name__ == "__main__":
    main()
