#!/usr/bin/env python3
"""Enforce the immutable Phase 2 cryptographic identity and replay baseline."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_CRYPTO = {
    "document_type": "qsol-fed-phase2-crypto-contract",
    "schema_version": 1,
    "wire_protocol": "qsol-fed/1",
    "suite": "ed25519-rfc8032",
    "algorithm_id": "ed25519",
    "public_key_encoding": "32 raw bytes encoded as exactly 64 lowercase hexadecimal characters",
    "private_key_encoding": "32-byte Ed25519 seed; local secret only; never serialized into Federation state",
    "signature_encoding": "64 raw bytes encoded as exactly 128 lowercase hexadecimal characters",
    "node_id_domain": "qsol-fed-node-id/1\\x00",
    "node_id_derivation": "fed:qsol: + lowercase_hex(SHA-256(domain || root_public_key_bytes))",
    "key_id_domain": "qsol-fed-key-id/1\\x00",
    "key_id_derivation": "ed25519: + lowercase_hex(SHA-256(domain || public_key_bytes))",
    "root_key_use": "identity lifecycle only; MUST NOT sign Federation envelopes",
    "operational_key_use": "Federation envelope signatures only plus transition authorization",
    "signed_envelope_schema": "qsol-fed-signed-envelope/1",
    "signed_envelope_signature_domain": "qsol-fed-envelope-signature/1\\x00",
    "signed_envelope_payload": "domain || canonical Phase 1 envelope bytes with the embedded Phase 1 signature field still null",
    "identity_schema": "qsol-fed-node-identity/1",
    "identity_signature_domain": "qsol-fed-node-identity/1\\x00",
    "rotation_schema": "qsol-fed-key-rotation/1",
    "rotation_signature_domain": "qsol-fed-key-rotation/1\\x00",
    "rotation_transition": "root + outgoing operational + incoming proof-of-possession signatures required",
    "rotation_recovery": "root + incoming proof-of-possession signatures required after outgoing key is revoked or compromised; outgoing signature MUST be null",
    "key_status_schema": "qsol-fed-key-status/1",
    "key_status_signature_domain": "qsol-fed-key-status/1\\x00",
    "root_compromise_policy": "terminal for the node identity; create a new node ID",
    "clock_policy": {
        "timestamp_format": "UTC second-resolution YYYY-MM-DDTHH:MM:SSZ",
        "max_clock_skew_seconds": 300,
        "max_signed_message_lifetime_seconds": 3600,
        "signed_envelope_expiry_required": True,
        "max_rotation_overlap_seconds": 86400,
        "public_verifier_policy": "frozen maxima are enforced internally and cannot be widened by callers",
    },
    "replay_policy": {
        "store": "durable append-only local replay log",
        "key": "message_id",
        "write_order": "validate signature and clock, fsync replay record, then expose fresh decision",
        "creation_durability": "fsync the parent directory entry when creating a replay log before any FreshRecorded decision",
        "timestamp_validation": "UTC second-resolution syntax plus real Gregorian calendar validation",
        "single_process_handle_policy": "at most one live replay-store handle per canonical path within a process",
        "corruption_policy": "fail_closed",
        "multi_process_claim": False,
    },
    "signature_validity_is_trust": False,
    "signature_validity_is_authority": False,
    "signature_validity_is_evidence": False,
    "algorithm_confusion_policy": "reject every algorithm identifier except exact ed25519",
    "downgrade_policy": "reject unsupported wire protocol, crypto schema, domain, key-id, and algorithm substitutions",
    "gate": "a valid signature never bypasses Prime Directive admission; correctly signed forbidden effects remain rejected",
}

EXPECTED_PHASE2_CLAIMS = {
    "document_type": "qsol-fed-phase2-claims",
    "schema_version": 1,
    "protocol": "qsol-fed/0",
    "wire_protocol": "qsol-fed/1",
    "phase": 2,
    "gate_id": "qsol-fed-phase2-claim-gate/1",
    "gate_status": "enforced",
    "historical_baseline": "claims/phase0.json",
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
        "production_networking": False,
        "remote_execution": False,
        "interoperable_federation": False,
    },
    "claim_rule": "Only capabilities with value true may be described as established by the current repository state. Cryptographic validity remains distinct from trust, authority, evidence, and admission.",
    "promotion_requirements": {
        "production_networking": "requires Phase 3 reference API security gate and explicit opt-in listener posture",
        "remote_execution": "not admitted by the current roadmap; requires separate constitutional design and review",
        "interoperable_federation": "requires deployed networking, peer lifecycle, replay-safe transport, and multi-implementation interop evidence",
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_schemas() -> None:
    signed = load_json("schemas/signed-envelope-v1.schema.json")
    require(signed.get("additionalProperties") is False, "signed-envelope schema must be closed")
    require(signed["properties"]["schema"].get("const") == "qsol-fed-signed-envelope/1", "signed-envelope schema id drift")
    require(signed["properties"]["algorithm"].get("const") == "ed25519", "signed-envelope algorithm drift")
    require(signed["properties"]["envelope"].get("$ref") == "federation-envelope-v1.schema.json", "signed envelope must wrap exact Phase 1 envelope")

    identity = load_json("schemas/node-identity-v1.schema.json")
    require(identity.get("additionalProperties") is False, "identity schema must be closed")
    require(identity["properties"]["algorithm"].get("const") == "ed25519", "identity algorithm drift")

    rotation = load_json("schemas/key-rotation-v1.schema.json")
    require(rotation.get("additionalProperties") is False, "rotation schema must be closed")
    require(rotation["properties"]["mode"].get("enum") == ["transition", "recovery"], "rotation modes drift")
    require("previous_signature" in rotation.get("required", []), "rotation previous_signature must remain required-nullable")

    status = load_json("schemas/key-status-v1.schema.json")
    require(status.get("additionalProperties") is False, "key-status schema must be closed")
    require(status["properties"]["status"].get("enum") == ["revoked", "compromised"], "key status values drift")


def validate_vectors() -> None:
    vectors = load_json("fixtures/phase2/signature-vectors.json")
    require(vectors.get("suite") == "ed25519-rfc8032", "signature vector suite drift")
    entries = vectors.get("vectors")
    require(isinstance(entries, list) and len(entries) == 4, "signature vector set drift")
    by_id = {entry["id"]: entry for entry in entries}
    require(set(by_id) == {"rfc8032-empty-message", "qsol-node-identity", "qsol-signed-envelope", "qsol-transition-rotation"}, "signature vector IDs drift")
    rfc = by_id["rfc8032-empty-message"]
    require(rfc["public_key_hex"] == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "RFC 8032 public key vector drift")
    require(rfc["signature_hex"] == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", "RFC 8032 signature vector drift")
    for entry in entries:
        for key, value in entry.items():
            if key.endswith("signature_hex"):
                require(re.fullmatch(r"[0-9a-f]{128}", value) is not None, f"bad signature vector encoding: {entry['id']}:{key}")


def validate_repository_surface() -> None:
    require(load_json("crypto/phase2.json") == EXPECTED_CRYPTO, "Phase 2 crypto machine contract drift")
    require(load_json("claims/phase2.json") == EXPECTED_PHASE2_CLAIMS, "Phase 2 historical claim manifest drift")

    phase0 = load_json("claims/phase0.json")["capabilities"]
    require(phase0["cryptographic_identity"] is False, "historical Phase 0 cryptographic claim was rewritten")
    require(phase0["production_networking"] is False, "historical Phase 0 network claim was rewritten")

    crypto_source = (ROOT / "src/crypto.rs").read_text(encoding="utf-8")
    for marker in (
        "qsol-fed-envelope-signature/1\\0",
        "qsol-fed-node-id/1\\0",
        "qsol-fed-key-id/1\\0",
        "root_or_unregistered_key_cannot_sign_envelope",
        "AuthorityDisposition::None",
        "RotationMode::Transition",
        "RotationMode::Recovery",
        "SignatureValidity::Compromised",
        "root_and_operational_keys_must_be_distinct",
        "rotation_next_key_role_invalid",
        "MAX_CLOCK_SKEW_SECONDS: i64 = 300",
        "MAX_SIGNED_MESSAGE_LIFETIME_SECONDS: i64 = 3600",
        "MAX_ROTATION_OVERLAP_SECONDS: i64 = 86_400",
    ):
        require(marker in crypto_source, f"Rust crypto contract marker missing: {marker}")

    lib_source = (ROOT / "src/lib.rs").read_text(encoding="utf-8")
    require("mod crypto;" in lib_source, "crypto implementation module must remain private")
    require("crypto::DEFAULT_CLOCK_POLICY" in lib_source, "public verifier must use frozen default clock policy")
    export_block = lib_source.split("pub use crypto::{", 1)[1].split("};", 1)[0]
    require("ClockPolicy" not in export_block, "caller-configurable ClockPolicy must not be publicly re-exported")
    require("DEFAULT_CLOCK_POLICY" not in export_block, "caller-configurable default clock policy must remain internal")

    replay_source = (ROOT / "src/replay.rs").read_text(encoding="utf-8")
    for marker in (
        "sync_all()",
        "sync_parent_directory",
        "OPEN_REPLAY_PATHS",
        "valid_replay_timestamp",
        "replay_store_already_open",
        "replay_log_partial_tail",
        "ReplayDecision::Replay",
        "multi-process",
    ):
        require(marker in replay_source, f"replay contract marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; historical cryptographic identity gate preserved.**" in roadmap, "ROADMAP Phase 2 historical status drift")
    require("A valid signature must never bypass local admission" in roadmap, "ROADMAP Phase 2 gate wording missing")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require("## Historical Phase 2 claim gate" in readme, "README historical Phase 2 claim section missing")
    require("claims/phase2.json" in readme, "README must preserve Phase 2 claim baseline reference")

    ai = load_json("README4AI.md")
    require(ai.get("phase2_status") in {"cryptographic_identity_gate_enforced", "historical_crypto_gate_preserved"}, "README4AI Phase 2 status drift")
    require(ai.get("phase2_crypto", {}).get("contract") == "crypto/phase2.json", "README4AI Phase 2 crypto map missing")
    require(ai.get("claim_disagreement_policy") == "fail_closed", "claim disagreement must remain fail closed")
    if (ROOT / "claims/phase3.json").exists():
        require(ai.get("phase2_status") == "historical_crypto_gate_preserved", "Phase 3 must preserve Phase 2 as historical")
        require(ai.get("current_claim_manifest") == "claims/phase3.json", "Phase 3 successor claim manifest not active")
    else:
        require(ai.get("current_claim_manifest") == "claims/phase2.json", "Phase 2 current claim manifest drift")
        require(ai.get("current_claims") == EXPECTED_PHASE2_CLAIMS["capabilities"], "README4AI current claims disagree with Phase 2 manifest")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("cargo test --all-targets" in workflow, "CI missing Rust cryptographic tests")
    require("python3 tools/validate_phase2_gate.py" in workflow, "CI missing Phase 2 gate")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in ("crypto/phase2.json", "CRYPTOGRAPHY.md", "claims/phase2.json", "python3 tools/validate_phase2_gate.py"):
        require(marker in agents, f"AGENTS.md Phase 2 rule missing: {marker}")


def main() -> None:
    validate_schemas()
    validate_vectors()
    validate_repository_surface()
    print("phase2 historical crypto gate OK: Ed25519 identity, detached signatures, key lifecycle, frozen clock policy, durable replay, and Prime Directive separation preserved")


if __name__ == "__main__":
    main()
