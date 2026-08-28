#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Round 13 preserves the round-12 exact-byte preflight and additionally locks the
# complete Phase 10 state contract before inherited validators read it. Every listed
# input must match BOTH committed HEAD bytes and the working-tree bytes actually used.
# No inherited validator is imported until this check has succeeded.
PREIMPORT_BLOBS = {
    "tools/validate_phase10_gate_round11.py": "c9c86f38540077581cfa0aa4d80d899d271252ee",
    "tools/validate_phase10_gate_round10.py": "d40d56c9686821ce5379ecc45b75b65f7f5ffd68",
    "tools/validate_phase10_gate_round9.py": "a441500abae06b628e98b374a4181a294d6d5f56",
    "tools/validate_phase10_gate_base.py": "ced7c981daf3a71ba6d7736755e0154bd7414ade",
    "machine/lean-phase10-manifest.json": "178d2c21a236ee81048db866e230aaddb6c92497",
    "schemas/lean-phase10-manifest-v1.schema.json": "ce0fb2c46184c5323ca898d8a90517ea67537809",
    "state/phase10.json": "d167a8123cb0124fdd92e77dc4e8476b5de999af",
    "README4AI.md": "e44ccc1e280a6ed69482ff661a0879edd57e02c8",
}

EXPECTED_MANIFEST_BLOB = PREIMPORT_BLOBS["machine/lean-phase10-manifest.json"]
EXPECTED_MANIFEST_SCHEMA_BLOB = PREIMPORT_BLOBS["schemas/lean-phase10-manifest-v1.schema.json"]
EXPECTED_CLAIM_RULE = 'Phase 10 adds a post-tag Lean 4 formal model of selected v0.11.0 constitutional and protocol separation invariants. The Phase 8 capability map remains the runtime/protocol capability surface, Phase 9 remains the adversarial-assurance baseline, and Lean adds formalization assurance only. A compiled theorem proves its stated abstract model proposition under named assumptions; it is not a deployment security proof, whole-Rust verification, proof of SHA-256 collision resistance, or proof of unstated real-world assumptions.'
EXPECTED_PROMOTION_REQUIREMENTS = {'phase10_complete': 'requires the formalization PR to be reviewed/merged and the exact merged main commit to pass the pinned Phase 10 Lean workflow with manifest, immutable-release, retained-MORIARTY-report, no-placeholder, and zero-kernel-axiom checks', 'phase11_archival_publication': 'requires a later deterministic archival bundle and offline verifier that bind source release, formalization tree, theorem manifest, retained MORIARTY evidence, machine contracts, schemas, hashes, release metadata and secret absence'}


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

# The verified round-11 snapshot expected its then-current manifest. Round 12
# intentionally strengthens that manifest and therefore updates the in-memory
# expected identity only after the snapshot itself has been byte-verified.
prev.EXPECTED_MANIFEST_BLOB = EXPECTED_MANIFEST_BLOB
prev.EXPECTED_MANIFEST_SCHEMA_BLOB = EXPECTED_MANIFEST_SCHEMA_BLOB

# Strengthened theorem declarations and exact elaborated type audit.
round9 = prev.prev.prev
round9.EXPECTED_TYPE_AUDIT_SHA256 = "10d6238597c11a9552a98810dc42f7da4d690a88d245ac5310e03529c01b5707"
round9.EXPECTED_THEOREM_TYPE_SHA256.update({
    "capability_requires_explicit_local_allow": "72d7fef1779f58a53339641dcee6251ca32a1abbeef3e1eedc73ee38ddc9319f",
    "capability_requires_peer_admission": "21dfe36ea5ec6bc101fc0fad5f4b23674d0dedd379bb1320cbb906dc5d68a88d",
    "capability_requires_authenticated_advertisement": "7ff9f36ffd7e4e9554c9e14b76d00d7e39dd147036bbd3593b1719ba4bdcc023",
    "lifecycle_prefix_is_transitive": "5d2113da5b36a302a7384ab7006ab3a239a7aa53008080c5306f26257610f89e",
    "holodeck_transport_does_not_relabel_network_use": "35559f0ad94dea763a58444412f66ab246a1cb0f391b67f980c756d1b5e64698",
    "adapter_output_has_no_authority": "ce1cc5f6082375c4db24533a6309ffe9c5c6cd72bdad1cc95294bb82674deb82",
    "transport_preserves_authenticated_identity": "abc234c34bec2f5e2c84c37b2afaed4bdf0a0920b3555d8732efcf2b725b2c80",
})

# New theorem-facing boundaries resolve only to immutable v0.11.0 fields.
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
    # Re-check immediately before the inherited validator reads/imports these
    # contracts. This makes the documented local gate fail closed on dirty files.
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
    verify_round12_source_boundaries()
    verify_round13_source_boundaries()
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
            f"elaborated environment types + exact working-tree contract bytes bound to "
            f"{result['target_tag']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
