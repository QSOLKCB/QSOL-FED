#!/usr/bin/env python3
"""Preserve Phase 6 governance-neutral SDK and third-party interoperability under successors."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE6_CAPABILITIES = {
    "minimal_protocol_sdk_contract",
    "rust_protocol_sdk",
    "python_protocol_sdk",
    "typescript_protocol_sdk",
    "language_neutral_sdk_conformance",
    "third_party_node_conformance",
    "three_implementation_sdk_interop",
    "institutional_integration_docs",
}
PHASE7_CAPABILITIES = {
    "assembly_membership_separate_from_network",
    "assembly_proposal_lifecycle",
    "assembly_representation_model",
    "assembly_anti_sybil_contract",
    "deterministic_charter_gate",
    "assembly_member_local_sovereignty",
    "nexus_assembly_advisory_only",
    "assembly_fork_version_path",
    "assembly_governance_receipts",
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
    previous = load("claims/phase5c.json")["capabilities"]
    historical_doc = load("claims/phase6.json")
    require(historical_doc.get("document_type") == "qsol-fed-phase6-sdk-claims", "Phase 6 claim id drift")
    require(historical_doc.get("gate_id") == "qsol-fed-phase6-sdk-gate/1", "Phase 6 gate id drift")
    require(historical_doc.get("gate_status") == "enforced", "Phase 6 gate not enforced")
    require(historical_doc.get("runtime_override_allowed") is False, "Phase 6 claims became runtime configurable")
    historical = historical_doc["capabilities"]
    require(set(previous).issubset(historical), "Phase 6 dropped a Phase 5C capability key")
    require(all(historical[key] == value for key, value in previous.items()), "Phase 6 changed a Phase 5C capability")
    require(set(historical) - set(previous) == PHASE6_CAPABILITIES, "Phase 6 capability delta drift")
    require(all(historical[key] is True for key in PHASE6_CAPABILITIES), "Phase 6 SDK capability not established")
    for key in ("oracle_holodeck_synthetic_admission", "host_level_sandbox", "production_networking", "remote_execution", "interoperable_federation"):
        require(historical[key] is False, f"historical Phase 6 overclaim drift: {key}")

    current = load("claims/phase7.json")["capabilities"]
    require(set(historical).issubset(current), "Phase 7 dropped a Phase 6 capability key")
    require(all(current[key] == value for key, value in historical.items()), "Phase 7 changed a historical Phase 6 capability")
    require(set(current) - set(historical) == PHASE7_CAPABILITIES, "Phase 7 successor capability delta drift")
    require(all(current[key] is True for key in PHASE7_CAPABILITIES), "Phase 7 Assembly capability missing")
    require(rust_claims() == current, "Rust current claims disagree with Phase 7 successor")


def validate_contract_and_fixture() -> None:
    state = load("state/phase6.json")
    require(state.get("document_type") == "qsol-fed-phase6-sdk-contract", "Phase 6 state id drift")
    require(state.get("sdk_contract") == "qsol-fed-sdk/1", "SDK contract id drift")
    require(state.get("wire_protocol") == "qsol-fed/1", "SDK wire protocol drift")
    require(state.get("canonical_profile") == "qsol-fed-canonical-json/1", "SDK canonical profile drift")
    required_surface = {
        "canonicalize", "object_id", "derive_message_id", "classify_protocol",
        "validate_capability_id", "build_node_manifest", "validate_node_manifest",
        "build_unsigned_envelope", "validate_unsigned_envelope", "build_provenance", "validate_provenance",
    }
    require(set(state["minimal_surface"]) == required_surface, "minimal SDK surface drift")
    require(set(state["implementations"]) == {"rust", "python", "typescript", "javascript_runtime"}, "SDK implementation set drift")
    require(state["conformance"]["required_implementations"] == 3, "three-implementation conformance requirement drift")
    require(state["conformance"]["byte_identical_results"] is True, "byte-identical interop requirement drift")
    third = state["third_party_node"]
    for key in ("qsol_governance_adopted", "nexus_required", "council_required", "oracle_required", "ark_required", "holodeck_required", "wire_namespace_implies_governance"):
        require(third[key] is False, f"third-party independence drift: {key}")
    require(all(value is False for value in state["authority_boundary"].values()), "minimal SDK gained authority/application dependency")
    deployment = state["deployment_claims"]
    require(deployment["language_neutral_sdk_interop"] is True and deployment["third_party_node_conformance"] is True, "Phase 6 interop evidence missing")
    require(deployment["deployed_interoperable_federation"] is False and deployment["production_networking"] is False and deployment["remote_execution"] is False, "Phase 6 deployment overclaim")

    fixture = load("fixtures/phase6/conformance.json")
    require(fixture["schema"] == "qsol-fed-sdk-conformance/1", "Phase 6 fixture schema drift")
    require(fixture["third_party_profile"] == {
        "schema": "third-party-node-profile/1", "implementation": "neutral-research-node",
        "governance_model": "local", "qsol_governance_adopted": False,
        "nexus_required": False, "council_required": False,
    }, "neutral third-party profile drift")
    expected = fixture["expected"]
    require(expected["node_manifest_object_id"] == "sha256:1c33ecd73cbf0730659079c66ea67ef4d126c4e0d6f3e38d16be6b805ca8b012", "node manifest vector drift")
    require(expected["payload_object_id"] == "sha256:76c341cf34445d25d16c8eeea43a64b8744cae6d18081c07a904f94324957bcd", "payload vector drift")
    require(expected["provenance_object_id"] == "sha256:4804a87605a0bbe276abaeade2eb29793863eb41cedc91df4804aaac4ff2f4b8", "provenance vector drift")
    require(expected["hello_message_id"] == "sha256:dc7527b2ba5551a0d6462f583161e1d55d565552698a1771740fe6978c2206cb", "hello vector drift")
    require(expected["evidence_message_id"] == "sha256:b3d2de3605bf001f945ff1fc9b14127fca321cbb5cac2edde6c79f659390d7f1", "evidence vector drift")


def _python_imports(source: str) -> tuple[set[str], set[str]]:
    modules: set[str] = set()
    names: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            names.update(alias.name for alias in node.names)
    return modules, names


def validate_schemas_and_implementations() -> None:
    profile = load("schemas/third-party-node-profile-v1.schema.json")
    result = load("schemas/sdk-conformance-result-v1.schema.json")
    require(profile.get("additionalProperties") is False, "third-party profile schema must be closed")
    require(profile["properties"]["implementation"].get("maxLength") == 128, "third-party profile length contract drift")
    require(profile["properties"]["qsol_governance_adopted"].get("const") is False, "profile governance adoption drift")
    require(profile["properties"]["nexus_required"].get("const") is False and profile["properties"]["council_required"].get("const") is False, "profile QSOL dependency drift")
    require(result.get("additionalProperties") is False, "conformance result schema must be closed")
    require(result["properties"]["implementation"].get("const") == "language-neutral", "conformance result discriminator drift")
    require(result["properties"]["authority_effect"].get("const") == "none", "conformance result authority drift")

    rust = (ROOT / "src/sdk.rs").read_text(encoding="utf-8")
    python = (ROOT / "sdk/python/qsol_fed_sdk.py").read_text(encoding="utf-8")
    javascript = (ROOT / "sdk/typescript/qsol_fed_sdk.mjs").read_text(encoding="utf-8")
    typescript = (ROOT / "sdk/typescript/qsol_fed_sdk.ts").read_text(encoding="utf-8")
    for name, text, markers in (
        ("Rust", rust, ("SDK_CONTRACT_V1", "sdk_build_provenance", "sdk_validate_unsigned_envelope", "phase6_conformance_from_fixture", "chars().count()")),
        ("Python", python, ("SDK_CONTRACT", "build_provenance", "validate_unsigned_envelope", "output_too_large", "[0-9]{4}")),
        ("JavaScript", javascript, ("SDK_CONTRACT", "buildProvenance", "validateUnsignedEnvelope", "TextDecoder", "compareUnicodeScalars", "invalid_utf8")),
        ("TypeScript", typescript, ("ThirdPartyNodeProfile", "ProvenanceObject", "buildProvenance", "validateUnsignedEnvelope", "conformanceResult")),
    ):
        for marker in markers:
            require(marker in text, f"{name} SDK marker missing: {marker}")
    for forbidden in ("crate::qsol_adapters", "crate::holodeck", "crate::oracle_live", "PeerRegistry", "TrustRegistry", "CouncilOfCouncils"):
        require(forbidden not in rust, f"Rust minimal SDK imported application subsystem: {forbidden}")

    third_party = (ROOT / "examples/neutral_research_node.py").read_text(encoding="utf-8")
    modules, names = _python_imports(third_party)
    for module in modules:
        require(not any(module == item or module.startswith(item + ".") for item in {"nexus_runtime", "qsol_adapters", "oracle_live", "holodeck"}), f"third-party node imported QSOL subsystem: {module}")
    for forbidden_name in ("PeerRegistry", "TrustRegistry", "CouncilOfCouncils"):
        require(forbidden_name not in names, f"third-party node imported QSOL authority type: {forbidden_name}")
    require((ROOT / "sdk/python/test_sdk.py").is_file(), "Python Phase 6 adversarial regression suite missing")
    require((ROOT / "sdk/typescript/adversarial.mjs").is_file(), "JavaScript Phase 6 adversarial regression suite missing")


def validate_surfaces_and_ci() -> None:
    sdk_doc = (ROOT / "SDK.md").read_text(encoding="utf-8")
    integration = (ROOT / "docs/THIRD_PARTY_INTEGRATION.md").read_text(encoding="utf-8")
    for marker in ("qsol-fed-sdk/1", "WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP", "byte-identical", "third-party"):
        require(marker.lower() in sdk_doc.lower(), f"SDK.md marker missing: {marker}")
    for marker in ("universities", "observatories", "INSTITUTIONAL INTEGRATION != QSOL GOVERNANCE", "local ethics"):
        require(marker.lower() in integration.lower(), f"integration doc marker missing: {marker}")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for marker in ("qsol-fed-sdk-conformance", "sdk/python/conformance.py", "sdk/typescript/conformance.mjs", "sdk/python/test_sdk.py", "sdk/typescript/adversarial.mjs", "neutral_research_node.py", "validate_phase6_gate.py", "cmp /tmp/phase6-rust.json /tmp/phase6-python.json", "cmp /tmp/phase6-rust.json /tmp/phase6-js.json"):
        require(marker in workflow, f"CI Phase 6 marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("Phase 6 — Third-party federation SDKs" in roadmap, "ROADMAP Phase 6 missing")
    require("non-NEXUS, non-QSOL-specific node" in roadmap, "ROADMAP third-party gate drift")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in ("state/phase6.json", "claims/phase6.json", "SDK.md", "python3 tools/validate_phase6_gate.py"):
        require(marker in agents, f"AGENTS Phase 6 marker missing: {marker}")

    ai = load("README4AI.md")
    require(ai.get("phase6_status") in {"third_party_sdk_gate_enforced", "historical_third_party_sdk_gate_preserved"}, "README4AI Phase 6 status missing")
    require(ai.get("current_claim_manifest") == "claims/phase7.json", "README4AI Phase 7 successor manifest not active")
    require(ai.get("current_claims") == load("claims/phase7.json")["capabilities"], "README4AI current Phase 7 claims drift")


def main() -> None:
    validate_claims()
    validate_contract_and_fixture()
    validate_schemas_and_implementations()
    validate_surfaces_and_ci()
    print("phase6 historical SDK gate OK: Rust/Python/TypeScript conformance, hostile parser parity, neutral third-party participation, and governance independence preserved under Phase 7 successor")


if __name__ == "__main__":
    main()
