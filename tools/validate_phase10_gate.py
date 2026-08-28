#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Round 14 preserves every inherited validator layer and exact-locks the complete
# formal-model/claim/document inputs strengthened by this review. Every listed input
# must match BOTH committed HEAD bytes and the working-tree bytes actually used before
# any inherited validator is imported.
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
    "QSOLFed/Model.lean": "dbaf27c024a5f8a70e7f45b572de48c5aac166ae",
    "QSOLFed/Theorems.lean": "92f5928adccc14f163ad71841769fcf7e1c47498",
    "QSOLFed/TypeAudit.lean": "f3f68fc57d4a73536a61d14dbf1a3c517655bba7",
}

EXPECTED_MANIFEST_BLOB = PREIMPORT_BLOBS["machine/lean-phase10-manifest.json"]
EXPECTED_MANIFEST_SCHEMA_BLOB = PREIMPORT_BLOBS["schemas/lean-phase10-manifest-v1.schema.json"]
EXPECTED_CLAIM_RULE = 'Phase 10 adds a post-tag Lean 4 formal model of selected v0.11.0 constitutional and protocol separation invariants. The Phase 8 capability map remains the runtime/protocol capability surface, Phase 9 remains the adversarial-assurance baseline, and Lean adds formalization assurance only. A compiled theorem proves its stated abstract model proposition under named assumptions; it is not a deployment security proof, whole-Rust verification, proof of SHA-256 collision resistance, or proof of unstated real-world assumptions.'
EXPECTED_PROMOTION_REQUIREMENTS = {'phase10_complete': 'requires the formalization PR to be reviewed/merged and the exact merged main commit to pass the pinned Phase 10 Lean workflow with manifest, immutable-release, retained-MORIARTY-report, no-placeholder, and zero-kernel-axiom checks', 'phase11_archival_publication': 'requires a later deterministic archival bundle and offline verifier that bind source release, formalization tree, theorem manifest, retained MORIARTY evidence, machine contracts, schemas, hashes, release metadata and secret absence'}
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
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
    )
    return result.stdout.strip()


def _preflight_exact_bytes() -> None:
    for relative, expected in PREIMPORT_BLOBS.items():
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"required exact-byte Phase 10 input missing: {relative}")
        committed = _raw_git("rev-parse", f"HEAD:{relative}")
        if committed != expected:
            raise RuntimeError(
                f"committed exact-byte Phase 10 input drift for {relative}: "
                f"expected {expected}, observed {committed}"
            )
        working = _raw_git("hash-object", str(path))
        if working != expected:
            raise RuntimeError(
                f"working-tree exact-byte Phase 10 input drift for {relative}: "
                f"expected {expected}, observed {working}"
            )


_preflight_exact_bytes()
prev = importlib.import_module("validate_phase10_gate_round11")
base = prev.base

# The verified round-11 snapshot expected its then-current manifest. Later rounds
# intentionally strengthen theorem/model surfaces while preserving that reviewed layer.
prev.EXPECTED_MANIFEST_BLOB = EXPECTED_MANIFEST_BLOB
prev.EXPECTED_MANIFEST_SCHEMA_BLOB = EXPECTED_MANIFEST_SCHEMA_BLOB

# Strengthened theorem declarations and exact elaborated type audit.
round9 = prev.prev.prev
round9.EXPECTED_TYPE_AUDIT_SHA256 = "ea405f8ee457a80d74dab81ca462d8c6b800039cd56a5b256ee0925f8b911aec"
round9.EXPECTED_THEOREM_TYPE_SHA256.update({
    "capability_requires_explicit_local_allow": "e60c688ec6f332d14731dc6c90b4e4a6f24e85a097e36b84ccf0794c2a684e90",
    "capability_requires_peer_admission": "3b0fa920a70f8d10d5e369f0dc0158bbf23176573b7f25863daf8f9c04e9d868",
    "capability_requires_authenticated_advertisement": "042695784603eca2d2e15948c04ba33ef6934363340d57235c2725f0abd51b69",
    "lifecycle_prefix_is_transitive": "5d2113da5b36a302a7384ab7006ab3a239a7aa53008080c5306f26257610f89e",
    "holodeck_transport_does_not_relabel_network_use": "35559f0ad94dea763a58444412f66ab246a1cb0f391b67f980c756d1b5e64698",
    "adapter_output_has_no_authority": "ce1cc5f6082375c4db24533a6309ffe9c5c6cd72bdad1cc95294bb82674deb82",
    "partition_rejoin_preserves_local_state": "109fa052bd16e7c585a149b6cf25ea3130ecfafc4b6c550384b7c72995f2595d",
    "changed_partition_snapshot_requires_reconciliation": "24889d6a84b6db02530d38093ec120984e3d551692c68437c05fd1155f53d3d9",
    "unchanged_partition_snapshot_needs_no_reconciliation": "46c929b18e9af25d88aad75db1dfd5b27aa0a68d1fb9c3d6baf146d6befd4c1a",
    "transport_preserves_authenticated_identity": "ab397879ca995ca93639615b6659f63f4fd85f6bba0849ecfe687f0ccc3729db",
    "nat_route_does_not_create_trust": "907cb09baa56dca84f018f8e88c04d6163efe535ec225b36b1010fe1bec1a2c9",
    "nat_route_does_not_replace_identity": "2ac27a4039d888a1f37626f942b1b255d6ff1eebccc3eff7f3f81de85cfb6f72",
})

# Existing theorem-facing boundaries remain source-resolved only to immutable v0.11.0
# contracts. Round 14 does not invent a new semantic contract vocabulary.
base.SOURCE_BOUND_CONTRACT_REGISTRY.update({
    "capability_advertisement_maximum_lifetime_seconds=3600": (
        "state/phase4.json",
        "/capability_advertisement/maximum_lifetime_seconds",
        "equals",
        3600,
    ),
    "revoked_reintroduction=reject": (
        "state/phase4.json",
        "/peer_registry/revoked_reintroduction",
        "equals",
        "reject",
    ),
    "adapter_may_rewrite_history=false": (
        "state/phase5.json",
        "/prime_directive/adapter_may_rewrite_history",
        "equals",
        False,
    ),
    "adapter_may_mutate_citizenship=false": (
        "state/phase5.json",
        "/prime_directive/adapter_may_mutate_citizenship",
        "equals",
        False,
    ),
    "adapter_may_trigger_remote_execution=false": (
        "state/phase5.json",
        "/prime_directive/adapter_may_trigger_remote_execution",
        "equals",
        False,
    ),
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise base.GateError(message)


def verify_working_tree_blob_locks_still_hold() -> None:
    # Re-check immediately before inherited validators read/import assurance inputs.
    for relative, expected in PREIMPORT_BLOBS.items():
        require(
            _raw_git("rev-parse", f"HEAD:{relative}") == expected,
            f"committed exact-byte Phase 10 input drift for {relative}",
        )
        require(
            _raw_git("hash-object", str(ROOT / relative)) == expected,
            f"working-tree exact-byte Phase 10 input drift for {relative}",
        )


def verify_claim_language_and_promotion_locked() -> None:
    claims = base.load_json(base.CLAIMS_PATH)
    require(
        claims.get("claim_rule") == EXPECTED_CLAIM_RULE,
        "Phase 10 claim rule may not overstate formalization assurance",
    )
    require(
        claims.get("promotion_requirements") == EXPECTED_PROMOTION_REQUIREMENTS,
        "Phase 10 promotion requirements drift from reviewed merged-main completion gate",
    )


def verify_complete_formalization_assurance_locked() -> None:
    claims = base.load_json(base.CLAIMS_PATH)
    require(
        claims.get("formalization_assurance") == EXPECTED_FORMALIZATION_ASSURANCE,
        "complete Phase 10 formalization_assurance claim drift",
    )


def verify_round12_source_boundaries() -> None:
    phase4 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase4.json"))
    require(
        phase4.get("peer_registry", {}).get("revoked_reintroduction") == "reject",
        "frozen Phase 4 revoked-reintroduction boundary drift",
    )
    require(
        phase4.get("capability_advertisement", {}).get("maximum_lifetime_seconds") == 3600,
        "frozen Phase 4 capability advertisement lifetime boundary drift",
    )
    require(
        "active authenticated advertisement"
        in phase4.get("local_capability_policy", {}).get("effective_allow_requires", []),
        "frozen Phase 4 active authenticated advertisement boundary drift",
    )

    phase5 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase5.json"))
    prime = phase5.get("prime_directive", {})
    expected = {
        "adapter_may_create_local_governance_authority": False,
        "adapter_may_install_capabilities": False,
        "adapter_may_rewrite_history": False,
        "adapter_may_mutate_citizenship": False,
        "adapter_may_trigger_remote_execution": False,
    }
    require(
        {key: prime.get(key) for key in expected} == expected,
        "frozen Phase 5 adapter authority-bearing effect boundary drift",
    )


def verify_round13_source_boundaries() -> None:
    phase8 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase8.json"))
    identity = phase8.get("identity_boundary", {})
    require(
        identity.get("verified_sender_node_must_match_frame_sender") is True,
        "frozen Phase 8 verified-sender/frame-sender binding drift",
    )
    require(
        identity.get("transport_profile_may_replace_sender_identity") is False,
        "frozen Phase 8 transport sender-replacement boundary drift",
    )

    holodeck = phase8.get("holodeck_transport_independence", {})
    expected_holodeck = {
        "authority_effect": "none",
        "federation_effect": "none",
        "evidence_effect": "none",
        "network_used": False,
        "real_tools_used": False,
        "credentials_exposed": False,
    }
    require(
        {key: holodeck.get(key) for key in expected_holodeck} == expected_holodeck,
        "frozen Phase 8 Holodeck transport-isolation boundary drift",
    )


def verify_round14_source_boundaries() -> None:
    phase4 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase4.json"))
    peer = phase4.get("peer_registry", {})
    bundle = phase4.get("portable_bundle", {})
    partition = phase4.get("partition_rejoin", {})
    require(
        peer.get("bundle_import_preserves_existing_local_state") is True
        and "peer lifecycle bytes" in bundle.get("preserves", [])
        and bundle.get("existing_peer_state") == "preserved",
        "frozen Phase 4 bundle import must preserve pre-existing peer lifecycle state",
    )
    require(
        partition.get("disconnect_records_snapshot") is True
        and partition.get("disconnect_snapshot_immutable_during_lifecycle_updates") is True
        and partition.get("same_snapshot_rejoin") == "clean only after explicit confirm call"
        and partition.get("changed_snapshot_rejoin") == "explicit_reconciliation_required"
        and partition.get("silent_reconciliation") is False,
        "frozen Phase 4 partition snapshot/rejoin boundary drift",
    )

    # Bind the abstract activity predicate to the frozen implementation semantics:
    # declared expires_at is part of the signed advertisement and now must lie inside it.
    peering_source = base.git("show", f"{base.TARGET_TAG}:src/peering.rs")
    require(
        "pub expires_at: String" in peering_source
        and "expires - issued > MAX_CAPABILITY_ADVERTISEMENT_LIFETIME_SECONDS" in peering_source
        and "if now_unix < issued || now_unix > expires" in peering_source,
        "frozen capability advertisement declared-expiry semantics drift",
    )

    phase7 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase7.json"))
    assembly = phase7.get("authority_boundary", {})
    expected_assembly = {
        "assembly_may_mutate_peer_registry": False,
        "assembly_may_mutate_trust_registry": False,
        "assembly_may_install_capability": False,
        "assembly_may_promote_evidence": False,
        "assembly_may_rewrite_history": False,
        "assembly_may_mutate_citizenship": False,
        "assembly_may_execute_tools": False,
        "assembly_may_access_credentials": False,
        "assembly_may_use_network": False,
        "assembly_may_open_files": False,
        "assembly_may_spawn_processes": False,
        "assembly_may_mutate_member_local_governance": False,
    }
    require(
        {key: assembly.get(key) for key in expected_assembly} == expected_assembly,
        "frozen Phase 7 complete Assembly member-state authority boundary drift",
    )

    phase8 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase8.json"))
    identity = phase8.get("identity_boundary", {})
    expected_transport = {
        "transport_acceptance_requires_signature_valid": True,
        "transport_acceptance_requires_current_identity": True,
        "transport_acceptance_requires_fresh_replay_state": True,
        "transport_acceptance_requires_local_peer_admission": True,
        "verified_sender_node_must_match_frame_sender": True,
        "direct_profiles_require_local_recipient": True,
        "forwarding_profiles_require_explicit_relay_admission": True,
        "recipient_or_relay_checked_before_replay_freshness": True,
    }
    require(
        {key: identity.get(key) for key in expected_transport} == expected_transport,
        "frozen Phase 8 complete transport admission prerequisite boundary drift",
    )
    nat = phase8.get("nat_traversal", {})
    require(
        nat.get("ticket_node_must_match_authenticated_sender") is True
        and nat.get("ticket_identity_ref_must_match_verified_identity") is True
        and identity.get("verified_identity_ref_bound_to_nat_ticket") is True,
        "frozen Phase 8 NAT node/identity-reference binding drift",
    )

    transport_source = base.git("show", f"{base.TARGET_TAG}:src/transport.rs")
    require(
        "pub signature_valid: bool" in transport_source
        and "pub identity_current: bool" in transport_source
        and "pub replay_fresh: bool" in transport_source
        and "pub local_peer_admitted: bool" in transport_source
        and "pub verified_identity_ref: String" in transport_source
        and "ticket.identity_ref != context.verified_identity_ref" in transport_source,
        "frozen Phase 8 transport/NAT implementation prerequisite semantics drift",
    )


def verify_ai_inventory_type_audit() -> None:
    ai_manifest = json.loads((ROOT / "README4AI.md").read_text(encoding="utf-8"))
    require(
        ai_manifest.get("phase10_lean", {}).get("type_audit") == "QSOLFed/TypeAudit.lean",
        "README4AI Phase 10 inventory must include the elaborated TypeAudit",
    )


def validate() -> dict:
    verify_working_tree_blob_locks_still_hold()
    result = prev.validate()
    verify_claim_language_and_promotion_locked()
    verify_complete_formalization_assurance_locked()
    verify_round12_source_boundaries()
    verify_round13_source_boundaries()
    verify_round14_source_boundaries()
    verify_ai_inventory_type_audit()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate()
    except (
        base.GateError,
        RuntimeError,
        subprocess.CalledProcessError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"Phase 10 gate: ERROR: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"Phase 10 gate: OK ({result['theorem_count']} theorem declarations/source-types + "
            f"elaborated environment types + exact working-tree contract/model/document bytes bound to "
            f"{result['target_tag']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
