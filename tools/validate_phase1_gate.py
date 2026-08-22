#!/usr/bin/env python3
"""Enforce the Phase 1 canonical wire contract and independent Python vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from qsol_canonical import (
    MAX_ARRAY_ITEMS,
    MAX_DEPTH,
    MAX_INPUT_BYTES,
    MAX_OBJECT_MEMBERS,
    MAX_STRING_UTF8,
    PROTOCOL,
    CanonicalError,
    canonicalize,
    derive_message_id,
    object_id,
    supported_protocol,
)

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_WIRE_CONTRACT = {
    "document_type": "qsol-fed-phase1-wire-contract",
    "schema_version": 1,
    "protocol": "qsol-fed/1",
    "canonical_profile": "qsol-fed-canonical-json/1",
    "envelope_schema": "qsol-fed-envelope/1",
    "provenance_schema": "qsol-fed-provenance/1",
    "error_schema": "qsol-fed-error/1",
    "capability_grammar": "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*/[1-9][0-9]*$",
    "object_identity": "sha256(lowercase-hex over canonical UTF-8 bytes)",
    "message_id_domain": "qsol-fed-message-id/1\\x00",
    "message_id_projection_excludes": ["message_id", "signature"],
    "unicode_normalization": "NFC",
    "numbers": "safe integers only; no floating-point or decimal values",
    "limits": {
        "max_input_bytes": 65536,
        "max_depth": 32,
        "max_string_utf8": 8192,
        "max_array_items": 1024,
        "max_object_members": 1024,
    },
    "independent_implementations": ["src/canonical.rs", "tools/qsol_canonical.py"],
    "golden_vectors": "fixtures/phase1/golden-vectors.json",
    "adversarial_corpus": "fixtures/phase1/adversarial.json",
    "unsupported_major_policy": "reject",
    "signatures": "not_implemented_phase2_gate_required",
    "production_networking": False,
    "remote_execution": False,
    "gate": "both independent implementations must match every golden canonical byte sequence and hash before Phase 2",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: str):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_python_golden_vectors() -> int:
    manifest = load_json("fixtures/phase1/golden-vectors.json")
    require(manifest.get("profile") == "qsol-fed-canonical-json/1", "golden profile drift")
    vectors = manifest.get("vectors")
    require(isinstance(vectors, list) and vectors, "golden vectors missing")
    for vector in vectors:
        raw = vector["input"]
        canonical = canonicalize(raw)
        require(canonical.decode("utf-8") == vector["canonical"], f"canonical text mismatch: {vector['id']}")
        require(canonical.hex() == vector["canonical_utf8_hex"], f"canonical bytes mismatch: {vector['id']}")
        digest = hashlib.sha256(canonical).hexdigest()
        require(digest == vector["sha256"], f"sha256 mismatch: {vector['id']}")
        require(object_id(raw) == vector["object_id"], f"object identity mismatch: {vector['id']}")
        if "message_id" in vector:
            require(derive_message_id(raw) == vector["message_id"], f"message id mismatch: {vector['id']}")
    return len(vectors)


def validate_adversarial_corpus() -> int:
    corpus = load_json("fixtures/phase1/adversarial.json")
    cases = corpus.get("cases")
    require(isinstance(cases, list) and cases, "adversarial cases missing")
    for case in cases:
        try:
            canonicalize(case["raw"])
        except (CanonicalError, UnicodeError):
            pass
        else:
            raise SystemExit(f"adversarial case unexpectedly accepted: {case['id']}")

    generated = {
        "input_over_65536_bytes": '"' + ("a" * MAX_INPUT_BYTES) + '"',
        "depth_over_32": ("[" * MAX_DEPTH) + "0" + ("]" * MAX_DEPTH),
        "string_over_8192_utf8_bytes": '"' + ("a" * (MAX_STRING_UTF8 + 1)) + '"',
        "array_over_1024_items": "[" + ",".join(["0"] * (MAX_ARRAY_ITEMS + 1)) + "]",
        "object_over_1024_members": "{" + ",".join(
            f'"k{index}":0' for index in range(MAX_OBJECT_MEMBERS + 1)
        ) + "}",
    }
    recipes = corpus.get("oversized_generators")
    require(isinstance(recipes, list), "oversized generator corpus missing")
    require({item["id"] for item in recipes} == set(generated), "oversized corpus recipe drift")
    for case_id, raw in generated.items():
        try:
            canonicalize(raw)
        except (CanonicalError, UnicodeError):
            pass
        else:
            raise SystemExit(f"oversized case unexpectedly accepted: {case_id}")
    return len(cases) + len(generated)


def validate_schemas() -> None:
    canonical_schema = load_json("schemas/federation-envelope.schema.json")
    frozen_schema = load_json("schemas/federation-envelope-v1.schema.json")
    require(canonical_schema["properties"] == frozen_schema["properties"], "envelope schema property drift")
    require(canonical_schema["required"] == frozen_schema["required"], "envelope required-field drift")
    require(canonical_schema.get("additionalProperties") is False, "envelope must reject unknown fields")
    require(canonical_schema["properties"]["protocol"].get("const") == PROTOCOL, "envelope protocol drift")
    require(canonical_schema["properties"]["signature"] == {"type": "null"}, "Phase 1 signature must remain null")

    provenance = load_json("schemas/provenance-v1.schema.json")
    require(provenance["properties"]["schema"].get("const") == "qsol-fed-provenance/1", "provenance schema drift")
    require(provenance.get("additionalProperties") is False, "provenance schema must be closed")

    error_schema = load_json("schemas/protocol-error-v1.schema.json")
    require(error_schema["properties"]["protocol"].get("const") == PROTOCOL, "error envelope protocol drift")
    require(error_schema.get("additionalProperties") is False, "error schema must be closed")


def validate_repository_gate() -> None:
    contract = load_json("wire/phase1.json")
    require(contract == EXPECTED_WIRE_CONTRACT, "Phase 1 machine contract drift")
    require(supported_protocol("qsol-fed/1"), "wire protocol v1 must be supported")
    for protocol in ("qsol-fed/0", "qsol-fed/2", "qsol-fed/99", "garbage"):
        require(not supported_protocol(protocol), f"unsupported protocol accepted: {protocol}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("**Status: complete; two-implementation conformance gate enforced.**" in roadmap, "ROADMAP Phase 1 status drift")
    require("Two independent implementations" in roadmap, "ROADMAP Phase 1 gate text missing")

    protocol_doc = (ROOT / "PROTOCOL.md").read_text(encoding="utf-8")
    for marker in (
        "qsol-fed-canonical-json/1",
        "qsol-fed/1",
        "qsol-fed-message-id/1",
        "qsol-fed-provenance/1",
        "qsol-fed-error/1",
    ):
        require(marker in protocol_doc, f"PROTOCOL.md missing Phase 1 marker: {marker}")

    phase0_claims = load_json("claims/phase0.json")["capabilities"]
    for hard_false in ("production_networking", "cryptographic_identity", "remote_execution", "interoperable_federation"):
        require(phase0_claims[hard_false] is False, f"Phase 1 illegally promoted Phase 0 capability: {hard_false}")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("cargo test --all-targets" in workflow, "CI missing Rust implementation tests")
    require("python3 tools/validate_phase1_gate.py" in workflow, "CI missing independent Python Phase 1 gate")


def main() -> None:
    vectors = validate_python_golden_vectors()
    rejected = validate_adversarial_corpus()
    validate_schemas()
    validate_repository_gate()
    print(
        f"phase1 wire gate OK: {vectors} language-neutral golden vectors matched by Python; "
        f"{rejected} adversarial/oversized cases rejected; Rust golden-vector tests required by CI"
    )


if __name__ == "__main__":
    main()
