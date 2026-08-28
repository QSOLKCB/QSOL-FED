#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PREIMPORT_BLOBS = {
    "tools/validate_phase10_gate_round11.py": "c9c86f38540077581cfa0aa4d80d899d271252ee",
    "tools/validate_phase10_gate_round10.py": "d40d56c9686821ce5379ecc45b75b65f7f5ffd68",
    "tools/validate_phase10_gate_round9.py": "a441500abae06b628e98b374a4181a294d6d5f56",
    "tools/validate_phase10_gate_base.py": "ced7c981daf3a71ba6d7736755e0154bd7414ade",
    "machine/lean-phase10-manifest.json": "178d2c21a236ee81048db866e230aaddb6c92497",
    "schemas/lean-phase10-manifest-v1.schema.json": "ce0fb2c46184c5323ca898d8a90517ea67537809",
    "state/phase10.json": "d167a8123cb0124fdd92e77dc4e8476b5de999af",
    "claims/phase10.json": "7e72230c93fc5ca27500fc41ed3f4523e734d52a",
    "README4AI.md": "e44ccc1e280a6ed69482ff661a0879edd57e02c8",
    "FORMALIZATION.md": "2c5418755af2124f7547b08fd85539d558bd0139",
    "QSOLFed/Model.lean": "809918669c6fd41b2d72cd58ba4c00680eb62471",
    "QSOLFed/Theorems.lean": "2928e4c11eddcfcdc06822ac51a106e1afd5f6f7",
    "QSOLFed/TypeAudit.lean": "9f5993ea7e8f9799df26b0c55d3fdb6dbb340c8c",
}

EXPECTED_CLAIM_RULE = 'Phase 10 adds a post-tag Lean 4 formal model of selected v0.11.0 constitutional and protocol separation invariants. The Phase 8 capability map remains the runtime/protocol capability surface, Phase 9 remains the adversarial-assurance baseline, and Lean adds formalization assurance only. A compiled theorem proves its stated abstract model proposition under named assumptions; it is not a deployment security proof, whole-Rust verification, proof of SHA-256 collision resistance, or proof of unstated real-world assumptions.'
EXPECTED_PROMOTION_REQUIREMENTS = {
    'phase10_complete': 'requires the formalization PR to be reviewed/merged and the exact merged main commit to pass the pinned Phase 10 Lean workflow with manifest, immutable-release, retained-MORIARTY-report, no-placeholder, and zero-kernel-axiom checks',
    'phase11_archival_publication': 'requires a later deterministic archival bundle and offline verifier that bind source release, formalization tree, theorem manifest, retained MORIARTY evidence, machine contracts, schemas, hashes, release metadata and secret absence',
}
EXPECTED_FORMALIZATION_ASSURANCE = {
    "lean_version": "4.33.1",
    "pinned_toolchain": True,
    "lean_archive_sha256_verified": True,
    "external_lean_dependencies": False,
    "theorem_manifest": "machine/lean-phase10-manifest.json",
    "theorem_manifest_schema": "schemas/lean-phase10-manifest-v1.schema.json",
    "theorem_count": 47,
    "theorem_to_contract_traceability": True,
    "named_assumptions": True,
    "unresolved_sorry_or_admit": False,
    "custom_axioms": False,
    "graduation_theorem_kernel_axiom_dependencies": False,
    "whole_implementation_verified": False,
    "deployment_security_proof": False,
    "source_release_rewritten": False,
    "formalization_creates_authority": False,
}


def _raw_git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_NO_REPLACE_OBJECTS": "1"},
    )
    return result.stdout.strip()


def _preflight() -> None:
    for relative, expected in PREIMPORT_BLOBS.items():
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"required exact-byte Phase 10 input missing: {relative}")
        committed = _raw_git("rev-parse", f"HEAD:{relative}")
        if committed != expected:
            raise RuntimeError(f"committed exact-byte Phase 10 input drift for {relative}: expected {expected}, observed {committed}")
        working = _raw_git("hash-object", str(path))
        if working != expected:
            raise RuntimeError(f"working-tree exact-byte Phase 10 input drift for {relative}: expected {expected}, observed {working}")


_preflight()
prev = importlib.import_module("validate_phase10_gate_round11")
base = prev.base
round9 = prev.prev.prev
prev.EXPECTED_MANIFEST_BLOB = PREIMPORT_BLOBS["machine/lean-phase10-manifest.json"]
prev.EXPECTED_MANIFEST_SCHEMA_BLOB = PREIMPORT_BLOBS["schemas/lean-phase10-manifest-v1.schema.json"]
round9.EXPECTED_TYPE_AUDIT_SHA256 = round9.hashlib.sha256((ROOT / "QSOLFed/TypeAudit.lean").read_bytes()).hexdigest()
round9.EXPECTED_THEOREM_TYPE_SHA256.update({
    "capability_requires_explicit_local_allow": "e60c688ec6f332d14731dc6c90b4e4a6f24e85a097e36b84ccf0794c2a684e90",
    "capability_requires_peer_admission": "3b0fa920a70f8d10d5e369f0dc0158bbf23176573b7f25863daf8f9c04e9d868",
    "capability_requires_authenticated_advertisement": "042695784603eca2d2e15948c04ba33ef6934363340d57235c2725f0abd51b69",
    "lifecycle_prefix_is_transitive": "5d2113da5b36a302a7384ab7006ab3a239a7aa53008080c5306f26257610f89e",
    "partition_rejoin_preserves_local_state": "109fa052bd16e7c585a149b6cf25ea3130ecfafc4b6c550384b7c72995f2595d",
    "changed_partition_snapshot_requires_reconciliation": "24889d6a84b6db02530d38093ec120984e3d551692c68437c05fd1155f53d3d9",
    "unchanged_partition_snapshot_needs_no_reconciliation": "46c929b18e9af25d88aad75db1dfd5b27aa0a68d1fb9c3d6baf146d6befd4c1a",
    "holodeck_transport_does_not_relabel_network_use": "35559f0ad94dea763a58444412f66ab246a1cb0f391b67f980c756d1b5e64698",
    "adapter_output_has_no_authority": "ce1cc5f6082375c4db24533a6309ffe9c5c6cd72bdad1cc95294bb82674deb82",
    "transport_preserves_authenticated_identity": "7c295b2039570fe5bdeda3a79b6637f3a4d8377fb3adcc5e86bd629e379ae57a",
    "nat_route_does_not_create_trust": "907cb09baa56dca84f018f8e88c04d6163efe535ec225b36b1010fe1bec1a2c9",
    "nat_route_does_not_replace_identity": "2ac27a4039d888a1f37626f942b1b255d6ff1eebccc3eff7f3f81de85cfb6f72",
})

base.SOURCE_BOUND_CONTRACT_REGISTRY.update({
    "capability_advertisement_maximum_lifetime_seconds=3600": ("state/phase4.json", "/capability_advertisement/maximum_lifetime_seconds", "equals", 3600),
    "revoked_reintroduction=reject": ("state/phase4.json", "/peer_registry/revoked_reintroduction", "equals", "reject"),
    "adapter_may_rewrite_history=false": ("state/phase5.json", "/prime_directive/adapter_may_rewrite_history", "equals", False),
    "adapter_may_mutate_citizenship=false": ("state/phase5.json", "/prime_directive/adapter_may_mutate_citizenship", "equals", False),
    "adapter_may_trigger_remote_execution=false": ("state/phase5.json", "/prime_directive/adapter_may_trigger_remote_execution", "equals", False),
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise base.GateError(message)


def verify_exact_bytes_still_hold() -> None:
    for relative, expected in PREIMPORT_BLOBS.items():
        require(_raw_git("rev-parse", f"HEAD:{relative}") == expected, f"committed exact-byte Phase 10 input drift for {relative}")
        require(_raw_git("hash-object", str(ROOT / relative)) == expected, f"working-tree exact-byte Phase 10 input drift for {relative}")


def verify_claims_and_docs() -> None:
    claims = base.load_json(base.CLAIMS_PATH)
    require(claims.get("claim_rule") == EXPECTED_CLAIM_RULE, "Phase 10 claim rule drift")
    require(claims.get("promotion_requirements") == EXPECTED_PROMOTION_REQUIREMENTS, "Phase 10 promotion requirements drift")
    require(claims.get("formalization_assurance") == EXPECTED_FORMALIZATION_ASSURANCE, "complete Phase 10 formalization_assurance claim drift")


def verify_round12_13_boundaries() -> None:
    phase4 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase4.json"))
    require(phase4["peer_registry"]["revoked_reintroduction"] == "reject", "frozen Phase 4 revoked-reintroduction boundary drift")
    require(phase4["capability_advertisement"]["maximum_lifetime_seconds"] == 3600, "frozen Phase 4 capability lifetime drift")
    require("active authenticated advertisement" in phase4["local_capability_policy"]["effective_allow_requires"], "frozen Phase 4 active advertisement boundary drift")
    phase5 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase5.json"))
    prime = phase5["prime_directive"]
    for key in ("adapter_may_create_local_governance_authority", "adapter_may_install_capabilities", "adapter_may_rewrite_history", "adapter_may_mutate_citizenship", "adapter_may_trigger_remote_execution"):
        require(prime.get(key) is False, f"frozen Phase 5 adapter boundary drift: {key}")
    phase8 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase8.json"))
    identity = phase8["identity_boundary"]
    require(identity["verified_sender_node_must_match_frame_sender"] is True, "frozen Phase 8 sender binding drift")
    require(identity["transport_profile_may_replace_sender_identity"] is False, "frozen Phase 8 transport identity replacement drift")
    holodeck = phase8["holodeck_transport_independence"]
    require(holodeck["authority_effect"] == "none" and holodeck["federation_effect"] == "none" and holodeck["evidence_effect"] == "none" and holodeck["network_used"] is False and holodeck["real_tools_used"] is False and holodeck["credentials_exposed"] is False, "frozen Phase 8 Holodeck transport boundary drift")


def verify_round14_boundaries() -> None:
    phase4 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase4.json"))
    peer = phase4["peer_registry"]
    bundle = phase4["portable_bundle"]
    partition = phase4["partition_rejoin"]
    require(peer["bundle_import_preserves_existing_local_state"] is True and "peer lifecycle bytes" in bundle["preserves"] and bundle["existing_peer_state"] == "preserved", "frozen Phase 4 bundle/peer lifecycle preservation drift")
    require(partition["disconnect_records_snapshot"] is True and partition["disconnect_snapshot_immutable_during_lifecycle_updates"] is True and partition["same_snapshot_rejoin"] == "clean only after explicit confirm call" and partition["changed_snapshot_rejoin"] == "explicit_reconciliation_required" and partition["silent_reconciliation"] is False, "frozen Phase 4 partition snapshot boundary drift")
    peering_source = base.git("show", f"{base.TARGET_TAG}:src/peering.rs")
    require("pub expires_at: String" in peering_source and "expires - issued > MAX_CAPABILITY_ADVERTISEMENT_LIFETIME_SECONDS" in peering_source and "if now_unix < issued || now_unix > expires" in peering_source, "frozen declared capability expiry semantics drift")

    phase7 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase7.json"))
    assembly = phase7["authority_boundary"]
    for key in ("assembly_may_mutate_peer_registry", "assembly_may_mutate_trust_registry", "assembly_may_install_capability", "assembly_may_promote_evidence", "assembly_may_rewrite_history", "assembly_may_mutate_citizenship", "assembly_may_execute_tools", "assembly_may_access_credentials", "assembly_may_use_network", "assembly_may_open_files", "assembly_may_spawn_processes", "assembly_may_mutate_member_local_governance"):
        require(assembly.get(key) is False, f"frozen Phase 7 Assembly boundary drift: {key}")

    phase8 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase8.json"))
    identity = phase8["identity_boundary"]
    for key in ("transport_acceptance_requires_signature_valid", "transport_acceptance_requires_current_identity", "transport_acceptance_requires_fresh_replay_state", "transport_acceptance_requires_local_peer_admission", "verified_sender_node_must_match_frame_sender", "direct_profiles_require_local_recipient", "forwarding_profiles_require_explicit_relay_admission", "recipient_or_relay_checked_before_replay_freshness"):
        require(identity.get(key) is True, f"frozen Phase 8 transport prerequisite drift: {key}")
    nat = phase8["nat_traversal"]
    require(nat["ticket_node_must_match_authenticated_sender"] is True and nat["ticket_identity_ref_must_match_verified_identity"] is True and identity["verified_identity_ref_bound_to_nat_ticket"] is True, "frozen Phase 8 NAT identity binding drift")
    transport_source = base.git("show", f"{base.TARGET_TAG}:src/transport.rs")
    require(all(token in transport_source for token in ("pub signature_valid: bool", "pub identity_current: bool", "pub replay_fresh: bool", "pub local_peer_admitted: bool", "pub verified_identity_ref: String", "ticket.identity_ref != context.verified_identity_ref")), "frozen Phase 8 transport/NAT implementation semantics drift")


def verify_ai_inventory() -> None:
    ai = json.loads((ROOT / "README4AI.md").read_text(encoding="utf-8"))
    require(ai.get("phase10_lean", {}).get("type_audit") == "QSOLFed/TypeAudit.lean", "README4AI Phase 10 TypeAudit inventory drift")


def validate() -> dict:
    verify_exact_bytes_still_hold()
    result = prev.validate()
    verify_claims_and_docs()
    verify_round12_13_boundaries()
    verify_round14_boundaries()
    verify_ai_inventory()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate()
    except (base.GateError, RuntimeError, subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"Phase 10 gate: ERROR: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"Phase 10 gate: OK ({result['theorem_count']} theorem declarations/source-types + elaborated environment types + exact contract/model/document bytes bound to {result['target_tag']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())