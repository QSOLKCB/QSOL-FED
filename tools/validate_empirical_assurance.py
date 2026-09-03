#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import validate_empirical_assurance_core as core

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_FROZEN_BLOBS = {
    "tools/validate_empirical_assurance_core.py": "2add32386ef5e435bb9e4bde0684ea6b2eefcb3e",
    "machine/empirical-assurance.json": "e3d55db78c358dab5a28dc9018b7fd7aa37117b6",
    "schemas/empirical-assurance-v1.schema.json": "4dc82d0f704c62fce7d7aa4aaaa7f84e7871882b",
    "EMPIRICAL_ASSURANCE.md": "7bf43bf806ae0f91945b5dc13dddcd6f63b19056",
    "README4AI.md": "64806ea18e1cf3f303726f9928f0b54312bb1af2",
    "AGENTS.md": "185a1cebfdee85f9575f5d8647277e70fd3e21c0",
    ".github/workflows/empirical-assurance.yml": "18f90533f3354165f938dabca7ce78b3561af295",
}
EXPECTED_RECORD_KEYS = {
    "document_type",
    "schema_version",
    "assurance_effect",
    "capability_effect",
    "authority_effect",
    "evidence_promotion",
    "formalization_relation",
    "gate",
    "supplemental_evidence",
    "tested_specimens",
    "campaigns",
    "claim_boundary",
    "formal_assurance",
    "future_publication",
}
EXPECTED_DOCUMENT_BOUNDARY = (
    "This document records bounded empirical execution evidence for the existing "
    "QSOL-NEXUS → QSOL-FED integration surface. It does **not** add protocol capability, "
    "promote evidence to truth, change authority, or replace the existing formal-assurance record."
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise core.GateError(message)


def _git_blob_identity(relative: str) -> tuple[str, str]:
    path = ROOT / relative
    require(path.is_file(), f"required frozen assurance input missing: {relative}")
    committed = subprocess.run(
        ["git", "rev-parse", f"HEAD:{relative}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require(committed.returncode == 0, f"unable to resolve committed assurance blob: {relative}")
    working = subprocess.run(
        ["git", "hash-object", str(path)],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require(working.returncode == 0, f"unable to hash working-tree assurance input: {relative}")
    return committed.stdout.strip(), working.stdout.strip()


def validate_front_door_contract() -> None:
    for relative, expected in EXPECTED_FROZEN_BLOBS.items():
        committed, working = _git_blob_identity(relative)
        require(committed == expected, f"committed frozen assurance blob drift: {relative}")
        require(working == expected, f"working-tree frozen assurance blob drift: {relative}")

    record = core.load_json(ROOT / "machine/empirical-assurance.json")
    require(isinstance(record, dict), "empirical assurance record must be an object")
    require(set(record) == EXPECTED_RECORD_KEYS, "complete empirical assurance top-level shape drift")

    document = (ROOT / "EMPIRICAL_ASSURANCE.md").read_text(encoding="utf-8")
    paragraphs = [part.strip() for part in document.split("\n\n") if part.strip()]
    require(len(paragraphs) >= 2 and paragraphs[1] == EXPECTED_DOCUMENT_BOUNDARY, "human assurance authority boundary drift")


def validate() -> dict:
    validate_front_door_contract()
    core.EXPECTED_PRESERVATION_BLOBS.update(EXPECTED_FROZEN_BLOBS)
    return core.validate()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate()
    except (core.GateError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"empirical assurance gate: ERROR: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("empirical assurance gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
