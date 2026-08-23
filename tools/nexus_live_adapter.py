#!/usr/bin/env python3
"""Live local QSOL-NEXUS -> QSOL-FED adapter.

This adapter never reimplements NEXUS world-export verification. It imports the
native NEXUS verifier from an explicitly supplied local source tree, verifies the
complete export first, and only then emits closed FED adapter artifacts.
"""

from __future__ import annotations

import argparse
import copy
import importlib
import json
from pathlib import Path
import re
import sys
from typing import Any

NEXUS_PINNED_COMMIT = "24cb0ce246d12ac99e7d190a8890ef2ddd598321"
FED_SOURCE_SCHEMA = "qsol-fed-nexus-world-source/1"
FED_REPORT_SCHEMA = "qsol-fed-nexus-council-report/1"
NEXUS_EXPORT_SCHEMA = "nexus-persistent-world-export/1"
NEXUS_WORLD_POLICY = "nexus-persistent-world/1"
MAX_REPORTS = 64
MAX_MEMBERS = 32
MAX_MINORITIES = 64

_OBJECT_REF = re.compile(r"^object:[0-9a-f]{64}$")
_WORLD_EXPORT_REF = re.compile(r"^world-export:[0-9a-f]{64}$")
_WORLD_MANIFEST_REF = re.compile(r"^world-manifest:[0-9a-f]{64}$")


def fail(code: str) -> "NoReturn":
    raise SystemExit(code)


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(value: Any, path: Path | None) -> None:
    rendered = canonical(value) + "\n"
    if path is None:
        sys.stdout.write(rendered)
    else:
        path.write_text(rendered, encoding="utf-8")


def _load_native_verifier(nexus_src: Path):
    nexus_src = nexus_src.resolve()
    package = nexus_src / "nexus_runtime"
    verifier_file = package / "persistent_world.py"
    if not verifier_file.is_file():
        fail("nexus_source_tree_missing_native_verifier")
    sys.path.insert(0, str(nexus_src))
    module = importlib.import_module("nexus_runtime.persistent_world")
    loaded = Path(module.__file__).resolve()
    if loaded != verifier_file.resolve():
        fail("nexus_native_verifier_import_path_mismatch")
    verifier = getattr(module, "validate_world_export_bundle", None)
    if not callable(verifier):
        fail("nexus_native_verifier_missing")
    return verifier


def verify_native(bundle: Any, nexus_src: Path) -> dict[str, Any]:
    verifier = _load_native_verifier(nexus_src)
    result = verifier(bundle)
    if not isinstance(result, dict):
        fail("nexus_native_verifier_result_invalid")
    if result.get("status") != "verified" or result.get("authority_effect") != "none":
        fail("nexus_native_verification_not_verified")
    if result.get("bundle_ref") != bundle.get("bundle_ref"):
        fail("nexus_native_verification_bundle_ref_mismatch")
    if result.get("object_count") != bundle.get("object_count"):
        fail("nexus_native_verification_object_count_mismatch")
    expected_refs = [entry.get("object_id") for entry in bundle.get("objects", [])]
    if result.get("object_refs") != expected_refs:
        fail("nexus_native_verification_object_refs_mismatch")
    return result


def build_source_manifest(bundle: dict[str, Any], verification: dict[str, Any]) -> dict[str, Any]:
    if bundle.get("schema") != NEXUS_EXPORT_SCHEMA or bundle.get("world_policy") != NEXUS_WORLD_POLICY:
        fail("nexus_export_contract_mismatch")
    bundle_ref = verification["bundle_ref"]
    if not isinstance(bundle_ref, str) or _WORLD_EXPORT_REF.fullmatch(bundle_ref) is None:
        fail("nexus_export_bundle_ref_invalid")
    source_head_ref = bundle.get("source_head_ref")
    if source_head_ref is not None and (
        not isinstance(source_head_ref, str) or _WORLD_MANIFEST_REF.fullmatch(source_head_ref) is None
    ):
        fail("nexus_export_head_ref_invalid")
    object_refs = list(verification["object_refs"])
    if not object_refs or any(not isinstance(ref, str) or _OBJECT_REF.fullmatch(ref) is None for ref in object_refs):
        fail("nexus_export_object_refs_invalid")
    return {
        "schema": FED_SOURCE_SCHEMA,
        "nexus_export_schema": NEXUS_EXPORT_SCHEMA,
        "nexus_world_policy": NEXUS_WORLD_POLICY,
        "bundle_ref": bundle_ref,
        "source_head_ref": source_head_ref,
        "order_basis": bundle["order_basis"],
        "object_refs": object_refs,
        "authority_effect": "none",
    }


def _validate_member(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        fail("nexus_council_member_invalid")
    member_id = raw.get("member_id")
    if not isinstance(member_id, str) or not member_id or len(member_id.encode("utf-8")) > 256:
        fail("nexus_council_member_id_invalid")
    if raw.get("vote_weight") != 1 or raw.get("epistemic_privilege") != "none":
        fail("nexus_council_equality_boundary_invalid")
    return {
        "member_id": member_id,
        "vote_weight_observed": 1,
        "epistemic_privilege_observed": "none",
        "vote_weight_inherited": False,
        "epistemic_privilege_inherited": False,
        "citizenship_inherited": False,
        "authority_effect": "none",
    }


def _minority_reports(result: Any) -> list[dict[str, Any]]:
    if not isinstance(result, dict):
        return []
    raw_reports = result.get("minority_reports", [])
    if raw_reports is None:
        return []
    if not isinstance(raw_reports, list) or len(raw_reports) > MAX_MINORITIES:
        fail("nexus_minority_reports_invalid")
    reports: list[dict[str, Any]] = []
    for raw in raw_reports:
        if not isinstance(raw, dict):
            fail("nexus_minority_report_invalid")
        member_id = raw.get("member_id")
        choice = raw.get("choice")
        rationale = raw.get("rationale")
        if not all(isinstance(value, str) for value in (member_id, choice, rationale)):
            fail("nexus_minority_report_field_invalid")
        reports.append({
            "member_id": member_id,
            "choice": choice,
            "rationale": rationale,
            "evidence_promotion": False,
            "vote_injection": False,
            "authority_effect": "none",
        })
    return reports


def build_council_reports(bundle: dict[str, Any], verification: dict[str, Any]) -> list[dict[str, Any]]:
    verified_refs = set(verification["object_refs"])
    reports: list[dict[str, Any]] = []
    for raw in bundle.get("objects", []):
        if raw.get("object_type") != "council_session":
            continue
        session_ref = raw.get("object_id")
        if session_ref not in verified_refs:
            fail("nexus_council_session_not_verified")
        payload = raw.get("payload")
        if not isinstance(payload, dict):
            fail("nexus_council_session_payload_invalid")
        roster = payload.get("roster")
        if not isinstance(roster, list) or not roster or len(roster) > MAX_MEMBERS:
            fail("nexus_council_roster_invalid")
        members = [_validate_member(entry) for entry in roster]
        if len({entry["member_id"] for entry in members}) != len(members):
            fail("nexus_council_roster_duplicate_member")
        result = payload.get("result")
        evidence_state = result.get("evidence_state") if isinstance(result, dict) else None
        if not isinstance(evidence_state, str) or not evidence_state:
            evidence_state = "UNSPECIFIED"
        session_id = payload.get("session_id")
        question_ref = payload.get("question_ref")
        if not isinstance(session_id, str) or not session_id:
            fail("nexus_council_session_id_invalid")
        if not isinstance(question_ref, str) or _OBJECT_REF.fullmatch(question_ref) is None:
            fail("nexus_council_question_ref_invalid")
        reports.append({
            "schema": FED_REPORT_SCHEMA,
            "source_repository": "QSOLKCB/QSOL-NEXUS",
            "source_commit": NEXUS_PINNED_COMMIT,
            "source_bundle_ref": verification["bundle_ref"],
            "source_session_ref": session_ref,
            "session_id": session_id,
            "question_ref": question_ref,
            "evidence_state_observed": evidence_state,
            "members": members,
            "minority_reports": _minority_reports(result),
            "shared_ballot": False,
            "vote_injection": False,
            "evidence_promotion": False,
            "authority_effect": "none",
        })
        if len(reports) > MAX_REPORTS:
            fail("nexus_council_report_limit")
    return reports


def verified_projection(bundle_path: Path, nexus_src: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    bundle = load_json(bundle_path)
    if not isinstance(bundle, dict):
        fail("nexus_bundle_must_be_object")
    verification = verify_native(copy.deepcopy(bundle), nexus_src)
    return build_source_manifest(bundle, verification), build_council_reports(bundle, verification)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nexus-src", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("command", choices=("source-manifest", "council-reports", "projection"))
    args = parser.parse_args()

    source, reports = verified_projection(args.bundle, args.nexus_src)
    if args.command == "source-manifest":
        output: Any = source
    elif args.command == "council-reports":
        output = {"reports": reports, "count": len(reports), "authority_effect": "none"}
    else:
        output = {
            "schema": "qsol-fed-nexus-live-projection/1",
            "source": source,
            "council_reports": reports,
            "native_verification_required": True,
            "authority_effect": "none",
        }
    write_json(output, args.output)


if __name__ == "__main__":
    main()
