#!/usr/bin/env python3
"""Generate the deterministic Phase 5 fixture using native QSOL-NEXUS WorldStore code."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import sys


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def load_native(nexus_src: Path):
    nexus_src = nexus_src.resolve()
    sys.path.insert(0, str(nexus_src))
    world_mod = importlib.import_module("nexus_runtime.world")
    persistent_mod = importlib.import_module("nexus_runtime.persistent_world")
    if Path(world_mod.__file__).resolve() != (nexus_src / "nexus_runtime/world.py").resolve():
        raise SystemExit("nexus_fixture_world_import_path_mismatch")
    if Path(persistent_mod.__file__).resolve() != (nexus_src / "nexus_runtime/persistent_world.py").resolve():
        raise SystemExit("nexus_fixture_persistent_import_path_mismatch")
    return world_mod.WorldStore, persistent_mod.PersistentWorldService, persistent_mod.validate_world_export_bundle


def build_fixture(nexus_src: Path):
    WorldStore, PersistentWorldService, validate_world_export_bundle = load_native(nexus_src)
    world = WorldStore()
    question = world.create_object(
        "question",
        {"text": "Should a synthetic world inherit Council authority?", "secret_scrubbed": False, "scrubbed_types": []},
        {"actor": "human_operator"},
    )
    session = world.create_object(
        "council_session",
        {
            "session_id": "phase5-fixture-session",
            "question_ref": question.object_id,
            "roster": [
                {
                    "member_id": "alpha",
                    "adapter_id": "mock",
                    "model_id": "fixture-alpha",
                    "deployment_metadata": {},
                    "capability_metadata": {},
                    "vote_weight": 1,
                    "epistemic_privilege": "none",
                    "actor_metadata": {},
                    "failsafe_state_ref": None,
                },
                {
                    "member_id": "beta",
                    "adapter_id": "mock",
                    "model_id": "fixture-beta",
                    "deployment_metadata": {},
                    "capability_metadata": {},
                    "vote_weight": 1,
                    "epistemic_privilege": "none",
                    "actor_metadata": {},
                    "failsafe_state_ref": None,
                },
            ],
            "result": {
                "status": "CONSENSUS",
                "choice": "NO",
                "evidence_state": "UNTESTED",
                "minority_reports": [
                    {
                        "member_id": "beta",
                        "choice": "ABSTAIN",
                        "rationale": "Synthetic exploration may be useful, but usefulness does not create authority.",
                    }
                ],
            },
            "revealed_ballots": [
                {"member_id": "alpha", "choice": "NO", "rationale": "Simulation is not authority.", "commitment": "fixture-alpha"},
                {"member_id": "beta", "choice": "ABSTAIN", "rationale": "Preserve the distinction explicitly.", "commitment": "fixture-beta"},
            ],
        },
        {"actor": "nexus"},
    )
    receipt = world.create_object(
        "receipt",
        {
            "operation": "fixture.phase5",
            "input_refs": [question.object_id],
            "result_ref": session.object_id,
            "replayable": True,
            "protocol": "nexus/0.15",
        },
        {"actor": "nexus"},
    )
    service = PersistentWorldService(world)
    bundle = service.export_bundle(object_refs=[question.object_id, session.object_id, receipt.object_id])
    verification = validate_world_export_bundle(bundle)
    if verification.get("status") != "verified" or verification.get("authority_effect") != "none":
        raise SystemExit("nexus_fixture_native_verification_failed")
    return bundle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nexus-src", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(canonical(build_fixture(args.nexus_src)) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
