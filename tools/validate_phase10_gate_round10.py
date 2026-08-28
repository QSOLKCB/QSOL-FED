#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess

import validate_phase10_gate_round9 as prev

base = prev.base

# Round 10 composes on the exact round-9 validator snapshot rather than rewriting
# previously reviewed checks.
prev.EXPECTED_TYPE_AUDIT_SHA256 = "19b57a5dc8126195c783cc51e20c7a77698195bba57e626b8b54079c4935a74f"
prev.EXPECTED_FORMALIZATION_LAYER = {
    **prev.EXPECTED_FORMALIZATION_LAYER,
    "type_audit": "QSOLFed/TypeAudit.lean",
}
prev.EXPECTED_THEOREM_TYPE_SHA256.update({
    "prime_directive_accepts_data_only": "fcc4124e0c3b88900b8db2e0a5063173986408601cca553180b27dffb56ceac2",
    "valid_signature_does_not_bypass_local_rejection": "d28a41822558488c3c9b883bb983143ce33ee5888a47b75f99a8a48d8509c18a",
    "import_does_not_create_local_authority": "23ba0fe094ffb68037c1f4c36c243b77e33e7071c877369dbe90e39601ec10ed",
})

ROUND9_GATE_PATH = prev.ROOT / "tools/validate_phase10_gate_round9.py"
ROUND9_GATE_BLOB = "a441500abae06b628e98b374a4181a294d6d5f56"
EXPECTED_CLAIMS_GATE_STATUS = "implemented_pending_merge_verification"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise base.GateError(message)


def verify_round9_gate_snapshot() -> None:
    require(ROUND9_GATE_PATH.is_file(), "frozen round-9 validator snapshot missing")
    require(
        base.git("rev-parse", "HEAD:tools/validate_phase10_gate_round9.py") == ROUND9_GATE_BLOB,
        "frozen round-9 validator snapshot blob drift",
    )


def verify_claims_gate_status_locked() -> None:
    claims = base.load_json(base.CLAIMS_PATH)
    require(
        claims.get("gate_status") == EXPECTED_CLAIMS_GATE_STATUS,
        "Phase 10 claims gate status may not promote before exact merged-main verification",
    )


def verify_bundle_import_authority_source_binding() -> None:
    manifest = base.load_json(base.MANIFEST_PATH)
    theorems = {
        item.get("id"): item
        for item in manifest.get("theorems", [])
        if isinstance(item, dict)
    }
    theorem = theorems.get("FED-LEAN-017")
    require(theorem is not None, "FED-LEAN-017 missing from theorem manifest")
    require(
        theorem.get("declaration") == "import_does_not_create_local_authority",
        "FED-LEAN-017 declaration drift",
    )
    require(
        "state/phase4.json" in theorem.get("source_refs", []),
        "FED-LEAN-017 must remain source-bound to frozen Phase 4",
    )
    require(
        "import_is_not_authority" in theorem.get("contract_ids", []),
        "FED-LEAN-017 import non-authority contract mapping drift",
    )
    frozen = json.loads(base.git("show", f"{base.TARGET_TAG}:state/phase4.json"))
    require(
        frozen.get("portable_bundle", {}).get("import_authority") == "none",
        "frozen Phase 4 portable-bundle import authority boundary drift",
    )


def validate() -> dict:
    verify_round9_gate_snapshot()
    result = prev.validate()
    verify_claims_gate_status_locked()
    verify_bundle_import_authority_source_binding()
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
            f"elaborated environment types bound to {result['target_tag']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
