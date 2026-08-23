#!/usr/bin/env python3
"""Enforce the immutable historical Phase 0 release-claim baseline.

Later phases may promote capabilities through successor claim manifests, but
must not rewrite what Phase 0 actually established.
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

EXPECTED_CLAIM_RULE = (
    "Only capabilities with value true may be described as established or implemented by the current "
    "repository state. False capabilities may be described only as absent, deferred, planned, prohibited, "
    "or not yet established."
)

EXPECTED_PROMOTION_REQUIREMENTS = {
    "production_networking": "requires later networking phases and their explicit security gates",
    "cryptographic_identity": "requires Phase 2 cryptographic node identity gate",
    "remote_execution": "not admitted by the current roadmap; requires separate constitutional design and review",
    "interoperable_federation": (
        "requires implemented networking, identity, replay protection, limits and interop evidence"
    ),
}

EXPECTED_MANIFEST = {
    "document_type": "qsol-fed-phase0-claims",
    "schema_version": 1,
    "protocol": "qsol-fed/0",
    "phase": 0,
    "gate_id": "qsol-fed-phase0-claim-gate/1",
    "gate_status": "enforced",
    "runtime_override_allowed": False,
    "capabilities": EXPECTED_CAPABILITIES,
    "claim_rule": EXPECTED_CLAIM_RULE,
    "promotion_requirements": EXPECTED_PROMOTION_REQUIREMENTS,
}

EXPECTED_CLAIM_PRECEDENCE = [
    "claims/phase0.json",
    "src/claims.rs",
    "README4AI.md.phase0_claims",
    "README.md.phase0_claim_gate",
]

EXPECTED_README_CLAIMS = [
    "- constitutional model: **established and tested**;",
    "- machine contracts: **established and tested**;",
    "- fail-closed admission skeleton: **established and tested**;",
    "- tested constitutional core: **established and tested**;",
    "- production networking: **not established**;",
    "- cryptographic identity: **not established**;",
    "- remote execution: **not established and forbidden by the current protocol posture**;",
    "- interoperable federation: **not established**.",
]

# These remain false even after Phase 2. Cryptographic identity is intentionally
# absent from this list because a successor Phase 2 claim manifest now promotes it.
FORBIDDEN_CURRENT_PUBLIC_CAPABILITIES = {
    "production_networking": "production networking",
    "remote_execution": "remote execution",
    "interoperable_federation": "interoperable federation",
}

POSITIVE_STATUS_WORDS = (
    "established",
    "implemented",
    "available",
    "enabled",
    "operational",
    "ready",
    "supported",
    "complete",
    "working",
)

README_CLAIM_BEGIN = "<!-- PHASE0_CLAIM_BOUNDARY:BEGIN -->"
README_CLAIM_END = "<!-- PHASE0_CLAIM_BOUNDARY:END -->"


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


def extract_readme_claim_block(readme: str) -> tuple[str, str]:
    require(readme.count(README_CLAIM_BEGIN) == 1, "README must contain exactly one Phase 0 claim begin marker")
    require(readme.count(README_CLAIM_END) == 1, "README must contain exactly one Phase 0 claim end marker")
    start = readme.index(README_CLAIM_BEGIN)
    end = readme.index(README_CLAIM_END, start)
    require(end > start, "README Phase 0 claim markers are reversed")
    block_start = start + len(README_CLAIM_BEGIN)
    block = readme[block_start:end]
    outside = readme[:start] + readme[end + len(README_CLAIM_END):]
    return block, outside


def normalized_public_line(line: str) -> str:
    line = re.sub(r"[`*_\[\]()#>]", " ", line.lower())
    return re.sub(r"\s+", " ", line).strip()


def positive_claim_patterns(phrase: str) -> list[re.Pattern[str]]:
    positive = "|".join(POSITIVE_STATUS_WORDS)
    escaped = re.escape(phrase)
    return [
        re.compile(rf"\b{escaped}\b\s*(?::|is|are|has been)?\s*(?:now\s+)?\b(?:{positive})\b"),
        re.compile(rf"\b(?:provides?|supports?|implements?|enables?|offers?)\b\s+(?:full\s+)?\b{escaped}\b"),
        re.compile(rf"\b(?:{positive})\b\s+\b{escaped}\b"),
    ]


def contradicted_by_positive_public_claim(text: str) -> list[str]:
    contradictions: list[str] = []
    for raw_line in text.splitlines():
        line = normalized_public_line(raw_line)
        if not line:
            continue
        for claim_id, phrase in FORBIDDEN_CURRENT_PUBLIC_CAPABILITIES.items():
            if phrase not in line:
                continue
            for pattern in positive_claim_patterns(phrase):
                match = pattern.search(line)
                if match is None:
                    continue
                prefix = line[max(0, match.start() - 16):match.start()]
                matched = match.group(0)
                if re.search(r"\b(?:not|no|never|without)\s*$", prefix):
                    continue
                if re.search(rf"\b{re.escape(phrase)}\b\s+(?:is\s+|are\s+)?not\s+", matched):
                    continue
                contradictions.append(f"{claim_id}: {raw_line.strip()}")
                break
    return contradictions


def self_test_public_claim_detector() -> None:
    hostile = [
        "Production networking is established.",
        "This node supports remote execution.",
        "Interoperable federation is ready.",
    ]
    safe = [
        "Production networking is not established.",
        "Cryptographic identity is established and tested.",
        "Remote execution is forbidden.",
        "Interoperable federation is not claimed.",
    ]
    for sample in hostile:
        require(
            contradicted_by_positive_public_claim(sample),
            f"public-claim contradiction detector failed hostile self-test: {sample}",
        )
    for sample in safe:
        require(
            not contradicted_by_positive_public_claim(sample),
            f"public-claim contradiction detector rejected safe self-test: {sample}",
        )


def main() -> None:
    claims = load_json("claims/phase0.json")
    ai_manifest = load_json("README4AI.md")

    require(
        claims == EXPECTED_MANIFEST,
        "historical Phase 0 manifest drift; later phases must use successor manifests rather than rewrite Phase 0",
    )

    capabilities = claims["capabilities"]
    require(capabilities == EXPECTED_CAPABILITIES, "historical Phase 0 capability set drift")

    ai_claims = ai_manifest.get("phase0_claims")
    require(ai_claims == EXPECTED_CAPABILITIES, "README4AI historical Phase 0 claim set drift")
    require(ai_manifest.get("phase0_status") == "historical_gate_preserved", "README4AI must preserve historical Phase 0 status")
    require(
        ai_manifest.get("claim_precedence") == EXPECTED_CLAIM_PRECEDENCE,
        "README4AI historical Phase 0 claim precedence drift",
    )
    require(ai_manifest.get("claim_disagreement_policy") == "fail_closed", "claim disagreement policy must remain fail_closed")

    normative_precedence = ai_manifest.get("normative_precedence")
    require(isinstance(normative_precedence, list), "README4AI normative_precedence missing")
    require("claims/phase0.json" in normative_precedence, "historical Phase 0 claim manifest missing from precedence")
    require("src/claims.rs" in normative_precedence, "Rust claim mirror missing from precedence")
    require(
        normative_precedence.index("claims/phase0.json") < normative_precedence.index("src/claims.rs"),
        "historical Phase 0 manifest must precede Rust mirror",
    )

    rust_source = (ROOT / "src/claims.rs").read_text(encoding="utf-8")
    rust_claims = rust_phase0_claims(rust_source)
    require(rust_claims == EXPECTED_CAPABILITIES, f"Rust historical Phase 0 claim registry drift: {rust_claims!r}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    claim_block, readme_outside_claim_block = extract_readme_claim_block(readme)
    claim_lines = [line.strip() for line in claim_block.splitlines() if line.strip().startswith("-")]
    require(claim_lines == EXPECTED_README_CLAIMS, f"README historical Phase 0 claim block drift: {claim_lines!r}")
    require("immutable historical Phase 0 release-claim baseline" in readme, "README must describe Phase 0 as immutable historical baseline")

    self_test_public_claim_detector()
    contradictions = contradicted_by_positive_public_claim(readme_outside_claim_block)
    require(
        not contradictions,
        "contradictory current hard-false capability claim outside historical Phase 0 block: " + " | ".join(contradictions),
    )

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; historical claim gate preserved in code and CI.**" in roadmap, "ROADMAP Phase 0 historical status drift")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    require("claims/phase0.json" in agents, "AGENTS.md must preserve the Phase 0 claim manifest")
    require("python3 tools/validate_phase0_gate.py" in agents, "AGENTS.md must require the Phase 0 gate validator")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("python3 tools/validate_phase0_gate.py" in workflow, "CI does not preserve the Phase 0 gate")

    print("phase0 historical claim gate OK: immutable baseline preserved; successor phases may promote only through new manifests")


if __name__ == "__main__":
    main()
