#!/usr/bin/env python3
"""Enforce the immutable Phase 2 cryptographic identity and replay baseline."""
from __future__ import annotations
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PHASE2_CAPABILITIES = {
    "constitutional_model": True, "machine_contracts": True,
    "fail_closed_admission_skeleton": True, "tested_constitutional_core": True,
    "canonical_wire_contract": True, "cryptographic_identity": True,
    "signed_envelope_verification": True, "key_lifecycle": True,
    "durable_replay_protection": True, "production_networking": False,
    "remote_execution": False, "interoperable_federation": False,
}
def require(condition: bool, message: str) -> None:
    if not condition: raise SystemExit(message)
def load_json(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle: return json.load(handle)
def validate_contract() -> None:
    crypto = load_json("crypto/phase2.json")
    require(crypto.get("document_type") == "qsol-fed-phase2-crypto-contract", "Phase 2 crypto contract id drift")
    require(crypto.get("wire_protocol") == "qsol-fed/1", "Phase 2 wire protocol drift")
    require(crypto.get("suite") == "ed25519-rfc8032" and crypto.get("algorithm_id") == "ed25519", "Phase 2 signing suite drift")
    require(crypto.get("root_key_use") == "identity lifecycle only; MUST NOT sign Federation envelopes", "root-key role drift")
    clock = crypto.get("clock_policy", {})
    require(clock.get("max_clock_skew_seconds") == 300, "Phase 2 clock skew drift")
    require(clock.get("max_signed_message_lifetime_seconds") == 3600, "Phase 2 signed lifetime drift")
    require(clock.get("max_rotation_overlap_seconds") == 86400, "Phase 2 rotation overlap drift")
    replay = crypto.get("replay_policy", {})
    require(replay.get("corruption_policy") == "fail_closed" and replay.get("multi_process_claim") is False, "Phase 2 replay policy drift")
    require(crypto.get("signature_validity_is_trust") is False, "signature/trust separation drift")
    require(crypto.get("signature_validity_is_authority") is False, "signature/authority separation drift")
    require(crypto.get("signature_validity_is_evidence") is False, "signature/evidence separation drift")
    require("valid signature never bypasses Prime Directive" in crypto.get("gate", ""), "Phase 2 gate wording drift")
def validate_schemas_and_vectors() -> None:
    signed = load_json("schemas/signed-envelope-v1.schema.json")
    require(signed.get("additionalProperties") is False and signed["properties"]["algorithm"].get("const") == "ed25519", "signed-envelope schema drift")
    require(signed["properties"]["envelope"].get("$ref") == "federation-envelope-v1.schema.json", "signed envelope must wrap Phase 1 envelope")
    identity = load_json("schemas/node-identity-v1.schema.json")
    require(identity.get("additionalProperties") is False and identity["properties"]["algorithm"].get("const") == "ed25519", "identity schema drift")
    rotation = load_json("schemas/key-rotation-v1.schema.json")
    require(rotation.get("additionalProperties") is False and rotation["properties"]["mode"].get("enum") == ["transition", "recovery"], "rotation mode drift")
    require("previous_signature" in rotation.get("required", []), "rotation previous_signature required-nullable drift")
    status = load_json("schemas/key-status-v1.schema.json")
    require(status.get("additionalProperties") is False and status["properties"]["status"].get("enum") == ["revoked", "compromised"], "key status drift")
    vectors = load_json("fixtures/phase2/signature-vectors.json"); entries = vectors.get("vectors")
    require(vectors.get("suite") == "ed25519-rfc8032" and isinstance(entries, list) and len(entries) == 4, "Phase 2 vector set drift")
    by_id = {entry["id"]: entry for entry in entries}
    require(set(by_id) == {"rfc8032-empty-message", "qsol-node-identity", "qsol-signed-envelope", "qsol-transition-rotation"}, "Phase 2 vector IDs drift")
    require(by_id["rfc8032-empty-message"]["signature_hex"] == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", "RFC 8032 vector drift")
def validate_claim_snapshot_and_source() -> None:
    claims = load_json("claims/phase2.json")
    require(claims.get("document_type") == "qsol-fed-phase2-claims" and claims.get("gate_status") == "enforced", "Phase 2 claims drift")
    require(claims.get("capabilities") == EXPECTED_PHASE2_CAPABILITIES, "Phase 2 capability snapshot drift")
    source = (ROOT / "src/crypto.rs").read_text(encoding="utf-8")
    for marker in ("qsol-fed-envelope-signature/1\\0", "qsol-fed-node-id/1\\0", "qsol-fed-key-id/1\\0", "root_or_unregistered_key_cannot_sign_envelope", "AuthorityDisposition::None", "RotationMode::Transition", "RotationMode::Recovery", "SignatureValidity::Compromised", "root_and_operational_keys_must_be_distinct", "rotation_next_key_role_invalid", "MAX_CLOCK_SKEW_SECONDS: i64 = 300", "MAX_SIGNED_MESSAGE_LIFETIME_SECONDS: i64 = 3600", "MAX_ROTATION_OVERLAP_SECONDS: i64 = 86_400"):
        require(marker in source, f"Phase 2 Rust marker missing: {marker}")
    lib = (ROOT / "src/lib.rs").read_text(encoding="utf-8")
    require("mod crypto;" in lib and "crypto::DEFAULT_CLOCK_POLICY" in lib, "Phase 2 public crypto boundary drift")
    export_block = lib.split("pub use crypto::{", 1)[1].split("};", 1)[0]
    require("ClockPolicy" not in export_block and "DEFAULT_CLOCK_POLICY" not in export_block, "clock policy became caller-configurable")
    replay = (ROOT / "src/replay.rs").read_text(encoding="utf-8")
    for marker in ("sync_all()", "sync_parent_directory", "OPEN_REPLAY_PATHS", "valid_replay_timestamp", "replay_store_already_open", "replay_log_partial_tail", "ReplayDecision::Replay", "multi-process"):
        require(marker in replay, f"Phase 2 replay marker missing: {marker}")
def validate_surfaces() -> None:
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; historical cryptographic identity gate preserved.**" in roadmap, "ROADMAP Phase 2 status drift")
    require("A valid signature must never bypass local admission" in roadmap, "ROADMAP Phase 2 gate wording missing")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require("## Historical Phase 2 claim gate" in readme and "claims/phase2.json" in readme, "README Phase 2 history missing")
    ai = load_json("README4AI.md")
    require(ai.get("phase2_status") == "historical_crypto_gate_preserved", "README4AI must preserve Phase 2 historically")
    require(ai.get("phase2_crypto", {}).get("contract") == "crypto/phase2.json", "README4AI Phase 2 crypto map missing")
    require(ai.get("claim_disagreement_policy") == "fail_closed", "claim disagreement policy drift")
    for path, expected in (
        ("claims/phase8.json", "claims/phase8.json"),
        ("claims/phase7.json", "claims/phase7.json"),
        ("claims/phase6.json", "claims/phase6.json"),
        ("claims/phase5c.json", "claims/phase5c.json"),
        ("claims/phase5.json", "claims/phase5.json"),
        ("claims/phase5a.json", "claims/phase5a.json"),
        ("claims/phase4.json", "claims/phase4.json"),
    ):
        if (ROOT / path).exists():
            require(ai.get("current_claim_manifest") == expected, f"{expected} successor claim manifest not active")
            break
    else:
        require(ai.get("current_claim_manifest") == "claims/phase2.json", "Phase 2 current claim manifest drift")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("cargo test --all-targets" in workflow and "python3 tools/validate_phase2_gate.py" in workflow, "CI missing Phase 2 gate")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in ("crypto/phase2.json", "CRYPTOGRAPHY.md", "claims/phase2.json", "python3 tools/validate_phase2_gate.py"):
        require(marker in agents, f"AGENTS.md Phase 2 marker missing: {marker}")
def main() -> None:
    validate_contract(); validate_schemas_and_vectors(); validate_claim_snapshot_and_source(); validate_surfaces()
    print("phase2 historical crypto gate OK: Ed25519 identity, lifecycle, frozen clocks, replay, and Prime Directive separation preserved")
if __name__ == "__main__": main()
