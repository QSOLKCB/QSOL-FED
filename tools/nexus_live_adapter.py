#!/usr/bin/env python3
"""Live local QSOL-NEXUS -> QSOL-FED adapter.

This adapter never reimplements NEXUS world-export verification. It attests the
reviewed local NEXUS verifier source, imports that verifier without executing the
package initializer, verifies the complete export first, applies the reviewed
NEXUS SecretScrubber to Council semantic text, and only then emits closed FED
adapter artifacts through the frozen QSOL-FED canonical JSON profile.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys
import types
import unicodedata
from typing import Any

from qsol_canonical import CanonicalError, canonicalize

NEXUS_PINNED_COMMIT = "24cb0ce246d12ac99e7d190a8890ef2ddd598321"
# Git blob identities for the exact dependency set imported by persistent_world.py.
# Loading uses a synthetic package shell, so nexus_runtime/__init__.py is not executed.
NEXUS_PINNED_BLOBS = {
    "nexus_runtime/persistent_world.py": "c71d981b946cafdc01c4862a2c54caed91247d83",
    "nexus_runtime/canonical.py": "db6369e3f7f4ccec03ced8b3f16fd44c3eae3ad3",
    "nexus_runtime/scrub.py": "be0558280efb7e98cf10bda1f1fbd6245abdc18c",
    "nexus_runtime/world.py": "785ccad3196bbf19c0185d8d4da43e42ec552770",
    "nexus_runtime/world_continuity.py": "7bd02eb5f7e35955a708cf1ec73f597faccfda1d",
    "nexus_runtime/world_lattice.py": "7d0ae0bc2e69ce7af51343648b03584b513ecf8f",
}
FED_SOURCE_SCHEMA = "qsol-fed-nexus-world-source/1"
FED_REPORT_SCHEMA = "qsol-fed-nexus-council-report/1"
NEXUS_EXPORT_SCHEMA = "nexus-persistent-world-export/1"
NEXUS_WORLD_POLICY = "nexus-persistent-world/1"
MAX_REPORTS = 64
MAX_MEMBERS = 32
MAX_MINORITIES = 64
MAX_MEMBER_ID_CHARS = 256
MAX_SESSION_ID_CHARS = 1024
MAX_EVIDENCE_STATE_CHARS = 128
MAX_CHOICE_CHARS = 256
MAX_RATIONALE_UTF8_BYTES = 8192

_OBJECT_REF = re.compile(r"^object:[0-9a-f]{64}$")
_WORLD_EXPORT_REF = re.compile(r"^world-export:[0-9a-f]{64}$")
_WORLD_MANIFEST_REF = re.compile(r"^world-manifest:[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def fail(code: str) -> "NoReturn":
    raise SystemExit(code)


def canonical(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    try:
        return canonicalize(raw).decode("utf-8")
    except CanonicalError as exc:
        fail(f"fed_canonical_output_invalid:{exc}")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(value: Any, path: Path | None) -> None:
    rendered = canonical(value) + "\n"
    if path is None:
        sys.stdout.write(rendered)
    else:
        path.write_text(rendered, encoding="utf-8")


def _git_dir(repo_root: Path) -> Path:
    marker = repo_root / ".git"
    if marker.is_dir():
        return marker.resolve()
    if marker.is_file():
        line = marker.read_text(encoding="utf-8").strip()
        if not line.startswith("gitdir: "):
            fail("nexus_gitdir_marker_invalid")
        target = Path(line.removeprefix("gitdir: "))
        if not target.is_absolute():
            target = repo_root / target
        return target.resolve()
    fail("nexus_git_metadata_missing")


def _git_head(repo_root: Path) -> str:
    git_dir = _git_dir(repo_root)
    head_file = git_dir / "HEAD"
    if not head_file.is_file():
        fail("nexus_git_head_missing")
    head = head_file.read_text(encoding="utf-8").strip()
    if _HEX40.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        fail("nexus_git_head_invalid")
    ref = head.removeprefix("ref: ")
    ref_file = git_dir / ref
    if ref_file.is_file():
        value = ref_file.read_text(encoding="utf-8").strip()
        if _HEX40.fullmatch(value):
            return value
        fail("nexus_git_ref_invalid")
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith(("#", "^")):
                continue
            try:
                value, name = line.split(" ", 1)
            except ValueError:
                continue
            if name == ref and _HEX40.fullmatch(value):
                return value
    fail("nexus_git_ref_unresolved")


def _git_blob_sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail("nexus_attested_source_file_invalid")
    body = path.read_bytes()
    header = f"blob {len(body)}\0".encode("ascii")
    return hashlib.sha1(header + body).hexdigest()  # Git blob identity, not a security digest.


def _attest_nexus_checkout(nexus_src: Path) -> Path:
    nexus_src = nexus_src.resolve()
    repo_root = nexus_src.parent
    if _git_head(repo_root) != NEXUS_PINNED_COMMIT:
        fail("nexus_checkout_commit_mismatch")
    for relative, expected_blob in NEXUS_PINNED_BLOBS.items():
        actual = _git_blob_sha(nexus_src / relative)
        if actual != expected_blob:
            fail(f"nexus_checkout_blob_mismatch:{relative}")
    return nexus_src


def _load_native_runtime(nexus_src: Path):
    nexus_src = _attest_nexus_checkout(nexus_src)
    package = nexus_src / "nexus_runtime"
    verifier_file = package / "persistent_world.py"
    scrub_file = package / "scrub.py"

    # Do not let a previously imported runtime escape the source attestation.
    if any(name == "nexus_runtime" or name.startswith("nexus_runtime.") for name in sys.modules):
        fail("nexus_runtime_already_loaded")

    # Provide only a package shell so Python can resolve reviewed relative imports
    # without executing nexus_runtime/__init__.py and its wider runtime surface.
    package_module = types.ModuleType("nexus_runtime")
    package_module.__path__ = [str(package)]
    package_module.__package__ = "nexus_runtime"
    sys.modules["nexus_runtime"] = package_module
    sys.path.insert(0, str(nexus_src))

    module = importlib.import_module("nexus_runtime.persistent_world")
    loaded = Path(module.__file__).resolve()
    if loaded != verifier_file.resolve():
        fail("nexus_native_verifier_import_path_mismatch")
    scrub_module = importlib.import_module("nexus_runtime.scrub")
    if Path(scrub_module.__file__).resolve() != scrub_file.resolve():
        fail("nexus_native_scrubber_import_path_mismatch")

    verifier = getattr(module, "validate_world_export_bundle", None)
    scrubber_class = getattr(scrub_module, "SecretScrubber", None)
    if not callable(verifier):
        fail("nexus_native_verifier_missing")
    if scrubber_class is None:
        fail("nexus_native_secret_scrubber_missing")
    return verifier, scrubber_class()


def verify_native(bundle: Any, nexus_src: Path) -> tuple[dict[str, Any], Any]:
    verifier, scrubber = _load_native_runtime(nexus_src)
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
    return result, scrubber


def _nfc_text(
    value: Any,
    *,
    code: str,
    scrubber: Any,
    max_chars: int | None = None,
    max_utf8_bytes: int | None = None,
) -> str:
    if not isinstance(value, str) or not value:
        fail(code)
    normalized = unicodedata.normalize("NFC", value)
    if max_chars is not None and len(normalized) > max_chars:
        fail(code)
    if max_utf8_bytes is not None and len(normalized.encode("utf-8")) > max_utf8_bytes:
        fail(code)
    if scrubber.scrub(normalized).changed:
        fail(f"{code}:secret_material_rejected")
    return normalized


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


def _validate_member(raw: Any, scrubber: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        fail("nexus_council_member_invalid")
    member_id = _nfc_text(
        raw.get("member_id"),
        code="nexus_council_member_id_invalid",
        scrubber=scrubber,
        max_chars=MAX_MEMBER_ID_CHARS,
    )
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


def _minority_reports(result: Any, scrubber: Any, member_ids: set[str]) -> list[dict[str, Any]]:
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
        member_id = _nfc_text(
            raw.get("member_id"),
            code="nexus_minority_report_member_invalid",
            scrubber=scrubber,
            max_chars=MAX_MEMBER_ID_CHARS,
        )
        if member_id not in member_ids:
            fail("nexus_minority_report_nonmember")
        choice = _nfc_text(
            raw.get("choice"),
            code="nexus_minority_report_choice_invalid",
            scrubber=scrubber,
            max_chars=MAX_CHOICE_CHARS,
        )
        rationale = _nfc_text(
            raw.get("rationale"),
            code="nexus_minority_report_rationale_invalid",
            scrubber=scrubber,
            max_utf8_bytes=MAX_RATIONALE_UTF8_BYTES,
        )
        reports.append({
            "member_id": member_id,
            "choice": choice,
            "rationale": rationale,
            "evidence_promotion": False,
            "vote_injection": False,
            "authority_effect": "none",
        })
    return reports


def build_council_reports(
    bundle: dict[str, Any], verification: dict[str, Any], scrubber: Any
) -> list[dict[str, Any]]:
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
        members = [_validate_member(entry, scrubber) for entry in roster]
        member_ids = {entry["member_id"] for entry in members}
        if len(member_ids) != len(members):
            fail("nexus_council_roster_duplicate_member_after_nfc")
        result = payload.get("result")
        evidence_state = result.get("evidence_state") if isinstance(result, dict) else None
        if not isinstance(evidence_state, str) or not evidence_state:
            evidence_state = "UNSPECIFIED"
        evidence_state = _nfc_text(
            evidence_state,
            code="nexus_council_evidence_state_invalid",
            scrubber=scrubber,
            max_chars=MAX_EVIDENCE_STATE_CHARS,
        )
        session_id = _nfc_text(
            payload.get("session_id"),
            code="nexus_council_session_id_invalid",
            scrubber=scrubber,
            max_chars=MAX_SESSION_ID_CHARS,
        )
        question_ref = payload.get("question_ref")
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
            "minority_reports": _minority_reports(result, scrubber, member_ids),
            "secret_scrubbed": True,
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
    verification, scrubber = verify_native(copy.deepcopy(bundle), nexus_src)
    return build_source_manifest(bundle, verification), build_council_reports(bundle, verification, scrubber)


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
