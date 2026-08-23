#!/usr/bin/env python3
"""Enforce Phase 6 governance-neutral SDK and third-party interoperability claims."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEW_CAPABILITIES = {
    "minimal_protocol_sdk_contract",
    "rust_protocol_sdk",
    "python_protocol_sdk",
    "typescript_protocol_sdk",
    "language_neutral_sdk_conformance",
    "third_party_node_conformance",
    "three_implementation_sdk_interop",
    "institutional_integration_docs",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rust_claims() -> dict[str, bool]:
    text = (ROOT / "src/claims.rs").read_text(encoding="utf-8")
    marker = "pub const CURRENT_CLAIMS: CurrentClaims = CurrentClaims {"
    start = text.find(marker)
    require(start >= 0, "Rust current claims missing")
    end = text.find("\n};", start + len(marker))
    require(end >= 0, "Rust current claims unterminated")
    pairs = re.findall(r"\b([a-z0-9_]+):\s*(true|false),", text[start + len(marker):end])
    result = {key: value == "true" for key, value in pairs}
    require(len(result) == len(pairs), "duplicate Rust current claim")
    return result


def validate_claims() -> None:
    previous = load("claims/phase5c.json")
    current = load("claims/phase6.json")
    require(current.get("document_type") == "qsol-fed-phase6-sdk-claims", "Phase 6 claim id drift")
    require(current.get("gate_id") == "qsol-fed-phase6-sdk-gate/1", "Phase 6 gate id drift")
    require(current.get("gate_status") == "enforced", "Phase 6 gate not enforced")
    require(current.get("runtime_override_allowed") is False, "Phase 6 claims became runtime configurable")
    old = previous["capabilities"]
    caps = current["capabilities"]
    require(set(old).issubset(caps), "Phase 6 dropped a historical capability key")
    for key, value in old.items():
        require(caps[key] == value, f"Phase 6 changed historical capability: {key}")
    require(set(caps) - set(old) == NEW_CAPABILITIES, "Phase 6 capability delta drift")
    require(all(caps[key] is True for key in NEW_CAPABILITIES), "Phase 6 SDK capability not established")
    for key in ("oracle_holodeck_synthetic_admission", "host_level_sandbox", "production_networking", "remote_execution", "interoperable_federation"):
        require(caps[key] is False, f"Phase 6 deployment/authority overclaim: {key}")
    require(rust_claims() == caps, "Rust current claims disagree with Phase 6")


def validate_contract_and_fixture() -> None:
    state = load("state/phase6.json")
    require(state.get("document_type") == "qsol-fed-phase6-sdk-contract", "Phase 6 state id drift")
    require(state.get("sdk_contract") == "qsol-fed-sdk/1", "SDK contract id drift")
    require(state.get("wire_protocol") == "qsol-fed/1", "SDK wire protocol drift")
    require(state.get("canonical_profile") == "qsol-fed-canonical-json/1", "SDK canonical profile drift")
    surface = state["minimal_surface"]
    required_surface = {
        "canonicalize", "object_id", "derive_message_id", "classify_protocol",
        "validate_capability_id", "build_node_manifest", "validate_node_manifest",
        "build_unsigned_envelope", "validate_unsigned_envelope", "build_provenance", "validate_provenance",
    }
    require(set(surface) == required_surface, "minimal SDK surface drift")
    implementations = state["implementations"]
    require(set(implementations) == {"rust", "python", "typescript", "javascript_runtime"}, "SDK implementation set drift")
    require(state["conformance"]["required_implementations"] == 3, "three-implementation conformance requirement drift")
    require(state["conformance"]["byte_identical_results"] is True, "byte-identical interop requirement drift")
    third = state["third_party_node"]
    for key in ("qsol_governance_adopted", "nexus_required", "council_required", "oracle_required", "ark_required", "holodeck_required", "wire_namespace_implies_governance"):
        require(third[key] is False, f"third-party independence drift: {key}")
    authority = state["authority_boundary"]
    require(all(value is False for value in authority.values()), "minimal SDK gained authority/application dependency")
    deployment = state["deployment_claims"]
    require(deployment["language_neutral_sdk_interop"] is True and deployment["third_party_node_conformance"] is True, "Phase 6 interop evidence missing")
    require(deployment["deployed_interoperable_federation"] is False and deployment["production_networking"] is False and deployment["remote_execution"] is False, "Phase 6 deployment overclaim")

    fixture = load("fixtures/phase6/conformance.json")
    require(fixture["schema"] == "qsol-fed-sdk-conformance/1", "Phase 6 fixture schema drift")
    profile = fixture["third_party_profile"]
    require(profile == {
        "schema": "third-party-node-profile/1",
        "implementation": "neutral-research-node",
        "governance_model": "local",
        "qsol_governance_adopted": False,
        "nexus_required": False,
        "council_required": False,
    }, "neutral third-party profile drift")
    expected = fixture["expected"]
    require(expected["node_manifest_object_id"] == "sha256:1c33ecd73cbf0730659079c66ea67ef4d126c4e0d6f3e38d16be6b805ca8b012", "node manifest vector drift")
    require(expected["payload_object_id"] == "sha256:76c341cf34445d25d16c8eeea43a64b8744cae6d18081c07a904f94324957bcd", "payload vector drift")
    require(expected["provenance_object_id"] == "sha256:4804a87605a0bbe276abaeade2eb29793863eb41cedc91df4804aaac4ff2f4b8", "provenance vector drift")
    require(expected["hello_message_id"] == "sha256:dc7527b2ba5551a0d6462f583161e1d55d565552698a1771740fe6978c2206cb", "hello vector drift")
    require(expected["evidence_message_id"] == "sha256:b3d2de3605bf001f945ff1fc9b14127fca321cbb5cac2edde6c79f659390d7f1", "evidence vector drift")


def validate_schemas_and_implementations() -> None:
    profile = load("schemas/third-party-node-profile-v1.schema.json")
    result = load("schemas/sdk-conformance-result-v1.schema.json")
    require(profile.get("additionalProperties") is False, "third-party profile schema must be closed")
    require(profile["properties"]["qsol_governance_adopted"].get("const") is False, "profile governance adoption drift")
    require(profile["properties"]["nexus_required"].get("const") is False and profile["properties"]["council_required"].get("const") is False, "profile QSOL dependency drift")
    require(result.get("additionalProperties") is False, "conformance result schema must be closed")
    require(result["properties"]["authority_effect"].get("const") == "none", "conformance result authority drift")

    rust = (ROOT / "src/sdk.rs").read_text(encoding="utf-8")
    python = (ROOT / "sdk/python/qsol_fed_sdk.py").read_text(encoding="utf-8")
    javascript = (ROOT / "sdk/typescript/qsol_fed_sdk.mjs").read_text(encoding="utf-8")
    typescript = (ROOT / "sdk/typescript/qsol_fed_sdk.ts").read_text(encoding="utf-8")
    for name, text, markers in (
        ("Rust", rust, ("SDK_CONTRACT_V1", "sdk_build_unsigned_envelope", "phase6_conformance_from_fixture")),
        ("Python", python, ("SDK_CONTRACT", "build_unsigned_envelope", "conformance_result")),
        ("JavaScript", javascript, ("SDK_CONTRACT", "buildUnsignedEnvelope", "conformanceResult", "normalized_duplicate_key")),
        ("TypeScript", typescript, ("ThirdPartyNodeProfile", "buildUnsignedEnvelope", "conformanceResult")),
    ):
        for marker in markers:
            require(marker in text, f"{name} SDK marker missing: {marker}")

    for forbidden in ("qsol_adapters", "holodeck", "oracle_live", "PeerRegistry", "TrustRegistry", "CouncilOfCouncils"):
        require(forbidden not in rust, f"Rust minimal SDK imported application subsystem: {forbidden}")
    third_party = (ROOT / "examples/neutral_research_node.py").read_text(encoding="utf-8")
    for forbidden in ("nexus_runtime", "qsol_adapters", "oracle_live", "holodeck", "PeerRegistry", "TrustRegistry"):
        require(forbidden not in third_party, f"third-party node imported QSOL subsystem: {forbidden}")


def validate_surfaces_and_ci() -> None:
    sdk_doc = (ROOT / "SDK.md").read_text(encoding="utf-8")
    integration = (ROOT / "docs/THIRD_PARTY_INTEGRATION.md").read_text(encoding="utf-8")
    for marker in ("qsol-fed-sdk/1", "WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP", "byte-identical", "third-party"):
        require(marker.lower() in sdk_doc.lower(), f"SDK.md marker missing: {marker}")
    for marker in ("universities", "observatories", "INSTITUTIONAL INTEGRATION != QSOL GOVERNANCE", "local ethics"):
        require(marker.lower() in integration.lower(), f"integration doc marker missing: {marker}")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for marker in (
        "qsol-fed-sdk-conformance", "sdk/python/conformance.py", "sdk/typescript/conformance.mjs",
        "neutral_research_node.py", "validate_phase6_gate.py", "cmp /tmp/phase6-rust.json /tmp/phase6-python.json",
        "cmp /tmp/phase6-rust.json /tmp/phase6-js.json",
    ):
        require(marker in workflow, f"CI Phase 6 marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("Phase 6 — Third-party federation SDKs" in roadmap, "ROADMAP Phase 6 missing")
    require("non-NEXUS, non-QSOL-specific node" in roadmap, "ROADMAP third-party gate drift")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in ("state/phase6.json", "claims/phase6.json", "SDK.md", "python3 tools/validate_phase6_gate.py"):
        require(marker in agents, f"AGENTS Phase 6 marker missing: {marker}")

    ai = load("README4AI.md")
    require(ai.get("phase6_status") == "third_party_sdk_gate_enforced", "README4AI Phase 6 status missing")
    require(ai.get("current_claim_manifest") == "claims/phase6.json", "README4AI current Phase 6 manifest drift")
    require(ai.get("current_claims") == load("claims/phase6.json")["capabilities"], "README4AI Phase 6 claims drift")


def main() -> None:
    validate_claims()
    validate_contract_and_fixture()
    validate_schemas_and_implementations()
    validate_surfaces_and_ci()
    print("phase6 SDK gate OK: Rust/Python/TypeScript references, byte-identical three-implementation conformance, neutral third-party participation, and governance independence preserved without deployment overclaim")


if __name__ == "__main__":
    main()
