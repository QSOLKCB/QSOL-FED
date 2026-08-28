#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess

import validate_phase10_gate_round10 as prev

base = prev.base

# Round 11 composes on the exact round-10 validator snapshot. The reviewed
# round-6/9/10 checks therefore remain immutable underneath this layer.
ROUND10_GATE_PATH = prev.prev.ROOT / "tools/validate_phase10_gate_round10.py"
ROUND10_GATE_BLOB = "d40d56c9686821ce5379ecc45b75b65f7f5ffd68"
EXPECTED_MANIFEST_BLOB = "11eec24b99dce7f7e89c770fe61963f6421bcb7a"
EXPECTED_MANIFEST_SCHEMA_BLOB = "ce0fb2c46184c5323ca898d8a90517ea67537809"
EXPECTED_FORMALIZATION_SCOPE = (
    "selected constitutional and protocol separation invariants from immutable "
    "QSOL-FED v0.11.0; not whole-software verification"
)

# Strengthened theorem declarations and their exact elaborated type audit.
prev.prev.EXPECTED_TYPE_AUDIT_SHA256 = "9f2f789395b297c9d2925479a4257d05fb1d4973262218951ef34198e28a5082"
prev.prev.EXPECTED_THEOREM_TYPE_SHA256.update({
    "peering_does_not_create_trust": "0d3b49f3cb09c32c9a10830342f75a6d010dd49f0a2a9b62483f56ca2d47060b",
    "import_does_not_change_trust": "5aa4ca1087527ac3a7f578315e8d4f349e414096e17703997e9090415b060172",
    "sdk_conformance_does_not_create_authority": "cfb6e8c75f8b615304b7a289ff1d79f827d18bd72d5c325e100e7b5213f0498a",
})

# New round-11 theorem-facing aliases remain resolved only against exact frozen
# v0.11.0 source fields, and each theorem's source_refs must contain that source.
base.SOURCE_BOUND_CONTRACT_REGISTRY.update({
    "peer_admission_creates_trust=false": (
        "state/phase4.json",
        "/trust_registry/peer_admission_creates_trust",
        "equals",
        False,
    ),
    "bundle_import_trust_change=false": (
        "state/phase4.json",
        "/portable_bundle/import_trust_change",
        "equals",
        False,
    ),
    "sdk_promotes_evidence=false": (
        "state/phase6.json",
        "/authority_boundary/sdk_promotes_evidence",
        "equals",
        False,
    ),
    "sdk_installs_capabilities=false": (
        "state/phase6.json",
        "/authority_boundary/sdk_installs_capabilities",
        "equals",
        False,
    ),
    "sdk_creates_votes=false": (
        "state/phase6.json",
        "/authority_boundary/sdk_creates_votes",
        "equals",
        False,
    ),
    "sdk_mutates_governance=false": (
        "state/phase6.json",
        "/authority_boundary/sdk_mutates_governance",
        "equals",
        False,
    ),
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise base.GateError(message)


def verify_round10_gate_snapshot() -> None:
    require(ROUND10_GATE_PATH.is_file(), "frozen round-10 validator snapshot missing")
    require(
        base.git("rev-parse", "HEAD:tools/validate_phase10_gate_round10.py") == ROUND10_GATE_BLOB,
        "frozen round-10 validator snapshot blob drift",
    )


def verify_manifest_contract_locked() -> None:
    require(
        base.git("rev-parse", "HEAD:machine/lean-phase10-manifest.json") == EXPECTED_MANIFEST_BLOB,
        "Phase 10 theorem/source/contract manifest byte identity drift",
    )
    require(
        base.git("rev-parse", "HEAD:schemas/lean-phase10-manifest-v1.schema.json")
        == EXPECTED_MANIFEST_SCHEMA_BLOB,
        "Phase 10 manifest schema byte identity drift",
    )
    manifest = base.load_json(base.MANIFEST_PATH)
    require(
        manifest.get("formalization_scope") == EXPECTED_FORMALIZATION_SCOPE,
        "Phase 10 formalization scope drift",
    )


def verify_state_claim_surface_locked() -> None:
    state = base.load_json(base.STATE_PATH)
    require(
        state.get("claim_surface_changed") is False,
        "Phase 10 state may not claim a changed runtime/capability surface",
    )


def verify_round11_source_boundaries() -> None:
    phase4 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase4.json"))
    require(
        phase4.get("trust_registry", {}).get("peer_admission_creates_trust") is False,
        "frozen Phase 4 peer-admission trust boundary drift",
    )
    require(
        phase4.get("portable_bundle", {}).get("import_trust_change") is False,
        "frozen Phase 4 portable-bundle trust boundary drift",
    )

    phase6 = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase6.json"))
    authority = phase6.get("authority_boundary", {})
    expected = {
        "sdk_creates_authority": False,
        "sdk_promotes_evidence": False,
        "sdk_installs_capabilities": False,
        "sdk_creates_votes": False,
        "sdk_mutates_governance": False,
    }
    require(
        {key: authority.get(key) for key in expected} == expected,
        "frozen Phase 6 SDK authority-bearing effect boundary drift",
    )


def validate() -> dict:
    verify_round10_gate_snapshot()
    result = prev.validate()
    verify_manifest_contract_locked()
    verify_state_claim_surface_locked()
    verify_round11_source_boundaries()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate()
    except (base.GateError, subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
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
            f"elaborated environment types + exact theorem/contract mapping bound to {result['target_tag']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
