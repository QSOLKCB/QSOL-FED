#!/usr/bin/env python3
"""Enforce the Phase 0 release-claim boundary.

Phase 0 may claim only the constitutional model, machine contracts,
fail-closed admission skeleton, and their tests. Networking, cryptographic
identity, remote execution, and interoperable federation remain unestablished.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_CAPABILITIES = {
    "constitutional_model": True,
    "machine_contracts": True,
    "fail_closed_admission_skeleton": True,
    "tested_constitutional_core": True,
    "production_networking": False,
    "cryptographic_identity": False,
    "remote_execution": False,
    "interoperable_federation": False,
}

FORBIDDEN_ESTABLISHED = {
    "production_networking",
    "cryptographic_identity",
    "remote_execution",
    "interoperable_federation",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: str) -> dict:
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    require(isinstance(value, dict), f"{path}: expected top-level JSON object")
    return value


def rust_phase0_claims(source: str) -> dict[str, bool]:
    marker = "pub const PHASE0_CLAIMS: Phase0Claims = Phase0Claims {"
    start = source.find(marker)
    require(start >= 0, "Rust PHASE0_CLAIMS registry missing")
    body_start = start + len(marker)
    body_end = source.find("\n};", body_start)
    require(body_end >= 0, "Rust PHASE0_CLAIMS registry is not terminated")
    body = source[body_start:body_end]
    pairs = re.findall(r"\b([a-z0-9_]+):\s*(true|false),", body)
    claims = {name: value == "true" for name, value in pairs}
    require(len(claims) == len(pairs), "duplicate Rust Phase 0 claim field")
    return claims


def main() -> None:
    claims = load_json("claims/phase0.json")
    ai_manifest = load_json("README4AI.md")

    require(claims.get("document_type") == "qsol-fed-phase0-claims", "wrong Phase 0 claim document type")
    require(claims.get("protocol") == "qsol-fed/0", "Phase 0 claim protocol drift")
    require(claims.get("phase") == 0, "Phase 0 claim phase drift")
    require(claims.get("gate_id") == "qsol-fed-phase0-claim-gate/1", "Phase 0 gate id drift")
    require(claims.get("gate_status") == "enforced", "Phase 0 claim gate must remain enforced")
    require(claims.get("runtime_override_allowed") is False, "Phase 0 claim gate became runtime configurable")

    capabilities = claims.get("capabilities")
    require(capabilities == EXPECTED_CAPABILITIES, f"Phase 0 capability claim drift: {capabilities!r}")
    for name in FORBIDDEN_ESTABLISHED:
        require(capabilities[name] is False, f"premature capability claim enabled: {name}")

    ai_claims = ai_manifest.get("phase0_claims")
    require(ai_claims == EXPECTED_CAPABILITIES, "README4AI Phase 0 claim set drift")
    require(ai_manifest.get("status") == "phase0_gate_enforced", "README4AI status must declare Phase 0 gate")

    rust_source = (ROOT / "src/claims.rs").read_text(encoding="utf-8")
    rust_claims = rust_phase0_claims(rust_source)
    require(rust_claims == EXPECTED_CAPABILITIES, f"Rust Phase 0 claim registry drift: {rust_claims!r}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    required_readme_lines = (
        "constitutional model: **established and tested**",
        "machine contracts: **established and tested**",
        "fail-closed admission skeleton: **established and tested**",
        "production networking: **not established**",
        "cryptographic identity: **not established**",
        "remote execution: **not established and forbidden by the current protocol posture**",
        "interoperable federation: **not established**",
    )
    for line in required_readme_lines:
        require(line in readme, f"README Phase 0 claim boundary missing: {line}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; claim gate enforced in code and CI.**" in roadmap, "ROADMAP Phase 0 gate status drift")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    require("claims/phase0.json" in agents, "AGENTS.md must require the Phase 0 claim manifest")
    require("python3 tools/validate_phase0_gate.py" in agents, "AGENTS.md must require the Phase 0 gate validator")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase0_gate.py" in workflow, "CI does not enforce the Phase 0 claim gate")

    print("phase0 claim gate OK: 4 established bootstrap claims, 4 hard-false capability claims")


if __name__ == "__main__":
    main()
