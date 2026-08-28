#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import validate_phase10_gate_base as base

ROOT = Path(__file__).resolve().parents[1]
LEGACY_GATE_PATH = ROOT / "tools/validate_phase10_gate_base.py"
LEGACY_GATE_BLOB = "ced7c981daf3a71ba6d7736755e0154bd7414ade"
TYPE_AUDIT_PATH = ROOT / "QSOLFed/TypeAudit.lean"
EXPECTED_TYPE_AUDIT_SHA256 = "961837fb378f0459026cd76d377ec471dcb6f3dec23f722170fdda6d3cd6f199"

# Round-7/8/9 contract additions. The legacy gate remains a frozen snapshot of the
# already-reviewed round-6 validator; this wrapper layers later fail-closed checks
# without weakening any prior gate.
base.SOURCE_BOUND_CONTRACT_REGISTRY.update({
    "nexus_advisory_authority_effect=none": (
        "state/phase7.json",
        "/nexus_advisory/authority_effect",
        "equals",
        "none",
    ),
    "ticket_grants_authority=false": (
        "state/phase8.json",
        "/nat_traversal/ticket_grants_authority",
        "equals",
        False,
    ),
    "adapter_may_install_capabilities=false": (
        "state/phase5.json",
        "/prime_directive/adapter_may_install_capabilities",
        "equals",
        False,
    ),
    "remote_vote_creation_forbidden": (
        "invariants/fed-v1.json",
        "/invariants/11/id",
        "equals",
        "remote_vote_creation_forbidden",
    ),
    "remote_capability_installation_forbidden": (
        "invariants/fed-v1.json",
        "/invariants/12/id",
        "equals",
        "remote_capability_installation_forbidden",
    ),
    "remote_history_rewrite_forbidden": (
        "invariants/fed-v1.json",
        "/invariants/13/id",
        "equals",
        "remote_history_rewrite_forbidden",
    ),
    "remote_citizenship_mutation_forbidden": (
        "invariants/fed-v1.json",
        "/invariants/14/id",
        "equals",
        "remote_citizenship_mutation_forbidden",
    ),
    "remote_local_authority_claim_forbidden": (
        "invariants/fed-v1.json",
        "/invariants/16/id",
        "equals",
        "remote_local_authority_claim_forbidden",
    ),
    "secrets_in_semantic_state_forbidden": (
        "invariants/fed-v1.json",
        "/invariants/17/id",
        "equals",
        "secrets_in_semantic_state_forbidden",
    ),
    "holodeck_network_client_exposed=false": (
        "state/phase5a-holodeck.json",
        "/sandbox/network_client_exposed",
        "equals",
        False,
    ),
    "holodeck_tool_dispatcher_exposed=false": (
        "state/phase5a-holodeck.json",
        "/sandbox/tool_dispatcher_exposed",
        "equals",
        False,
    ),
    "holodeck_credential_handle_exposed=false": (
        "state/phase5a-holodeck.json",
        "/sandbox/credential_handle_exposed",
        "equals",
        False,
    ),
    "ticket_node_must_match_authenticated_sender": (
        "state/phase8.json",
        "/nat_traversal/ticket_node_must_match_authenticated_sender",
        "equals",
        True,
    ),
})

EXPECTED_ASSUMPTIONS = [
    {
        "id": "MODEL_SCOPE",
        "statement": "Lean definitions are an abstract formalization of stated v0.11.0 contract semantics; correspondence to every implementation path remains an external verification obligation.",
    },
    {
        "id": "CANONICAL_BYTES_INPUT",
        "statement": "canonical_identity_deterministic assumes the compared canonical byte sequences are equal; it does not prove canonicalizer implementation correctness or SHA-256 collision resistance.",
    },
    {
        "id": "REAL_WORLD_PRINCIPALS",
        "statement": "real-world principal uniqueness, deployment hardening, host isolation and operational credential hygiene are outside the theorem model unless explicitly represented.",
    },
]

EXPECTED_STATE_NON_CLAIMS = {
    "deployment_security_proof": False,
    "whole_rust_implementation_verified": False,
    "canonicalizer_implementation_verified": False,
    "sha256_collision_resistance_proved": False,
    "host_or_vm_isolation_proved": False,
    "real_world_principal_uniqueness_proved": False,
    "moriarty_exhaustiveness_proved": False,
}

EXPECTED_FORMALIZATION_LAYER = {
    "post_tag": True,
    "rewrites_source_release": False,
    "lean_toolchain": "leanprover/lean4:v4.33.1",
    "lean_archive_sha256": "890afd185370f85666025b883914ab4f4b339136f8c96167b69cfb62aecaf235",
    "external_lean_dependencies": [],
    "lake_package": "qsol-fed-formal",
    "root_module": "QSOLFed",
    "model": "QSOLFed/Model.lean",
    "graduation_theorems": "QSOLFed/Theorems.lean",
    "axiom_audit": "QSOLFed/AxiomAudit.lean",
    "manifest": "machine/lean-phase10-manifest.json",
    "manifest_schema": "schemas/lean-phase10-manifest-v1.schema.json",
    "gate_validator": "tools/validate_phase10_gate.py",
    "workflow": ".github/workflows/phase10-lean.yml",
    "documentation": "FORMALIZATION.md",
}

EXPECTED_THEOREM_TYPE_SHA256 = {
    "prime_directive_accepts_data_only": "a9970c1529f1f67b91dbcb47eb18042ec4715547eb733080798b9d646ef10bbc",
    "prime_directive_quarantines_foreign_state": "228093719203b00ebfa83627b31177dc84da362ef5fab06e7b9357ccd9f41259",
    "prime_directive_rejects_governance_mutation": "51cbba7557f9c97a71a10f4a1eca068e92af1bfa84b85b61a67f8b1c4279afde",
    "prime_directive_rejects_evidence_promotion": "b88f3b90259de61f11a4601df8eb290b06161c56193a64f49ffa8ba7585fc435",
    "prime_directive_rejects_arbitrary_execution": "70d47a9252269ede3cd18fdbc85f256ab82c09af89081064d3586e548456271e",
    "prime_directive_rejects_runtime_override": "b750c3cfdfc6e65ab1b7930cf8329a2b9e084d2c8d2816225c7b3ef29d7a4032",
    "prime_directive_rejects_unknown_authority": "1638b892cca181a72643ba1a5f31c884047d04379a84d6962da562c8457595ff",
    "signature_validity_does_not_create_trust": "949df02be04afd185ec645f02ee17d96ec4cfb48f5e4ee40231ae8dd872c88a3",
    "signature_validity_does_not_create_authority": "ab1485093bf7fbcc96eb68a280c8f32f77dadcbb0eda3fc4eac24ecab3b22185",
    "valid_signature_does_not_bypass_local_rejection": "94f56a835bd8fa378bff14be25a1945581005a9a96209c274bb6be54e9e8a4c5",
    "peering_does_not_create_trust": "5c067b04486a6f626290b8ed2ef0eba38f872c784bf002c54a5b98c30426fce0",
    "peering_does_not_create_admission": "8af176b75c7b8951819b2e4f169f103f481cd715a6f941e1d97b0190891def2c",
    "capability_requires_explicit_local_allow": "ad3ebf3eeb4fa6f87069db91394acb9a2f34c51b2bf97a555a2cb3db7c1b629f",
    "capability_requires_peer_admission": "b47f6df5c0f8265e473e3390709f8650907b4df42fbe137de6cbe21c3e433fd2",
    "capability_requires_authenticated_advertisement": "063aa6627371f29c7949c7a808ba2fed9f89c16107b269f95f6ab5e5d94085a1",
    "import_preserves_foreign_identity": "4b48ed5d838ef7105a8359d092bd947b620f3b9a78895e04a96921d073a1bae7",
    "import_does_not_create_local_authority": "0dbe573a73f6d8b3fce63275bbc14d6b056cb75e185be1ab17244bec6b933942",
    "import_does_not_change_trust": "f1182fef68de866494e4c412efba68e195e8d05f47a5f9acc70bfa2a0c47d0b9",
    "lifecycle_append_is_monotone": "53cd0bcd050c55c621a172012b306d793f52ac5efc976863da5c13cedca3b8bd",
    "lifecycle_prefix_is_transitive": "2e5425dd6532fc7a804c5e8745becccb4bc021c42a156c264b14893306c0fa57",
    "partition_rejoin_preserves_local_state": "c2dd947ae15c7498ff1f67e04c851b7c0694bbfc0a570e4064c6eea063f91efe",
    "changed_partition_snapshot_requires_reconciliation": "dabe384653387ca1afa4e64d926de78594833b49e1814fb03e42e1e49cc0e607",
    "unchanged_partition_snapshot_needs_no_reconciliation": "7c8bc3cb93502c6c5f6368925f9dcb04ce11fc5f4d4b68857061da33aef17f8f",
    "canonical_identity_deterministic": "0b87fc85763a90516b385d7994a4eb40098fb92a794a3a7ffa046fa208510557",
    "holodeck_output_has_no_authority": "6df2fc2be79e0457af388476dca52a3ee6d31a52bd935fe82e2f0f5b77439ade",
    "holodeck_output_has_no_evidence_effect": "5d8256bd969477f050267388beefe1e2ee995c89367cd0ea4d9e4eee406cfeb1",
    "holodeck_output_has_no_federation_effect": "321e8487df522bbd93e14ccd5693fcae309d9985c24517fb16df393e8bfcbbab",
    "holodeck_transport_does_not_relabel_network_use": "3d0f171dbf9af4078cc0576c411e9a2a5c8a10853f426a1d5c2ba38e6814e5bc",
    "holodeck_end_program_terminal_even_when_frozen": "629ec6fe62a8776ca912a28bd0b503c7069f2c1811bd29f066d486cffbcb7840",
    "adapter_output_has_no_authority": "655e275a2887fd92439de728311344b844deb521ff9176812f0f12db70cffea0",
    "adapter_cannot_inject_vote": "3c454c34f6988268bc8659a53e42043582132beda7af4f066bb62c1fd3cc444e",
    "adapter_cannot_promote_evidence": "bd7140ad840b8a5b1a15645d125a1c949f27f481542b8924256d7615479e84a3",
    "sdk_conformance_does_not_create_trust": "27950340c947151b3ec464cd166408162ff08c3d0873a9ed6b39087a079be17f",
    "sdk_conformance_does_not_create_governance_membership": "690085239cc58005dd6dbae653a7da617a106d414a9d00b3c6e71c85f640ff2a",
    "sdk_conformance_does_not_create_authority": "0921313bddab8e978f5a1a41fcc55ef91c0c701bfaecc60856ec2c242f88eeb1",
    "assembly_acceptance_does_not_mutate_member_authority": "713434e1b482c91b8c4f2595e74c0b56a62478d4025f99ad92fa64c21742061a",
    "assembly_acceptance_does_not_change_protocol_automatically": "2f80e3ab0ec9a0c5b66e43b4ff8891d9cd3e92aed8bc10edfaaf8d0ec3736473",
    "assembly_receipt_has_no_authority_effect": "e3304ca570c2387a924b1a28fc1cf91891c55ab63742a78c0bb04cdbdc60cdcc",
    "nexus_advisory_has_zero_vote_weight": "01f356290d4269f36f757222aca85196f56e68048c67f99d15f296d10958fbae",
    "transport_preserves_authenticated_identity": "e3a5f346ab512f6ca59921372af9e952bba6c5e6fe0a08ab0b4a202c56fc52af",
    "transport_preserves_message_identity": "ee38f8f7b923341886e784239f9ee90c266e173a9081f921dec1c15db04780de",
    "transport_preserves_payload_reference": "e9b1780e95bcd259aa4bbd85081fadd4e99c738032da96886b48072d303448d9",
    "transport_preserves_provenance": "e79594378d179aa2f280f774f4a402e83bf1e7af84c5346c3c91c239a0d30cdb",
    "nat_route_does_not_create_trust": "e27cf167d39894c8827589492775173d644e644fbad7f39665643ea5d70c9392",
    "nat_route_does_not_replace_identity": "2c62cf8ff56c759b413de899b5915148fe5760f86e8b997fd37f10f72cfa2c5e",
    "relay_does_not_create_authority": "7b4099149e9bb4585f7a096566bf5e742380cfa9de9d06cc1124f175dfe185c5",
    "relay_does_not_create_trust": "2c064061b897987816f081029eca5a4e19c339ced60c2c31cd766e80a249bef9"
}

THEOREM_START_RE = re.compile(r"(?m)^[ \t]*theorem[ \t]+([a-z][a-z0-9_]*)\b")
TYPE_AUDIT_RE = re.compile(r"(?m)^#check[ \t]+\(@([a-z][a-z0-9_]*)[ \t]*:")
THEOREM_CONTEXT_RE = re.compile(r"(?m)^[ \t]*(?:section|variable|variables|include|omit)\b")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise base.GateError(message)


def verify_legacy_gate_snapshot() -> None:
    require(LEGACY_GATE_PATH.is_file(), "frozen round-6 validator snapshot missing")
    require(
        base.git("rev-parse", "HEAD:tools/validate_phase10_gate_base.py") == LEGACY_GATE_BLOB,
        "frozen round-6 validator snapshot blob drift",
    )


def verify_state_evidence_locked() -> None:
    state = base.load_json(base.STATE_PATH)
    evidence = state.get("moriarty_source_evidence")
    expected = {
        "workflow_run": 33069191846,
        "run_number": 413,
        "artifact_id": 9645064099,
        "artifact_zip_digest": "sha256:1c77cb56e83a0af19961e9f3c99d3ace02f6dd905655dc64b36aa90d46e9d9ce",
        "retained_report": "evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json",
        "retained_report_sha256": "sha256:6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c",
        "target_commit": base.TARGET_COMMIT,
        "corpus_ref": "sha256:af50e8145a72a1a583ede29687535a59c0e17ac37fdd66e1ede51c453e8fd3e6",
        "family_count": 15,
        "executed_probe_count": 13,
        "unresolved_counterexamples": 0,
        "graduated": True,
        "security_proof": False,
    }
    require(
        evidence == expected,
        "Phase 10 state MORIARTY evidence object differs from the frozen non-security-proof boundary",
    )


def verify_state_nonclaims_locked() -> None:
    state = base.load_json(base.STATE_PATH)
    require(
        state.get("non_claims") == EXPECTED_STATE_NON_CLAIMS,
        "Phase 10 state non-claim boundary drift",
    )


def verify_state_formalization_layer_locked() -> None:
    state = base.load_json(base.STATE_PATH)
    require(
        state.get("formalization_layer") == EXPECTED_FORMALIZATION_LAYER,
        "Phase 10 formalization-layer state drift",
    )


def verify_assumption_statements_locked() -> None:
    manifest = base.load_json(base.MANIFEST_PATH)
    require(
        manifest.get("assumptions") == EXPECTED_ASSUMPTIONS,
        "Phase 10 named assumption ID/statement mapping drift",
    )


def verify_namespace_syntax_fail_closed() -> None:
    path = ROOT / "QSOLFed/Theorems.lean"
    code = base._lean_code_only(path.read_text(encoding="utf-8"), path)
    require("«" not in code and "»" not in code, "quoted Lean identifiers are not admitted in QSOLFed/Theorems.lean")
    for line_number, line in enumerate(code.splitlines(), 1):
        if re.match(r"^[ \t]*namespace(?:[ \t]|$)", line):
            require(
                base.NAMESPACE_OPEN_RE.fullmatch(line) is not None,
                f"unsupported Lean namespace syntax in QSOLFed/Theorems.lean:{line_number}",
            )
        if re.match(r"^[ \t]*end(?:[ \t]|$)", line):
            require(
                base.NAMESPACE_END_RE.fullmatch(line) is not None,
                f"unsupported Lean namespace end syntax in QSOLFed/Theorems.lean:{line_number}",
            )


def verify_theorem_context_fail_closed() -> None:
    path = ROOT / "QSOLFed/Theorems.lean"
    code = base._lean_code_only(path.read_text(encoding="utf-8"), path)
    match = THEOREM_CONTEXT_RE.search(code)
    require(
        match is None,
        "section/variable/include/omit theorem context commands are not admitted in QSOLFed/Theorems.lean",
    )


def verify_type_audit_locked() -> None:
    require(TYPE_AUDIT_PATH.is_file(), "Phase 10 elaborated theorem type audit missing")
    audit_bytes = TYPE_AUDIT_PATH.read_bytes()
    require(
        hashlib.sha256(audit_bytes).hexdigest() == EXPECTED_TYPE_AUDIT_SHA256,
        "Phase 10 elaborated theorem type audit source drift",
    )
    code = base._lean_code_only(audit_bytes.decode("utf-8"), TYPE_AUDIT_PATH)
    observed = TYPE_AUDIT_RE.findall(code)
    manifest = base.load_json(base.MANIFEST_PATH)
    expected = [item["declaration"] for item in manifest.get("theorems", [])]
    require(
        observed == expected,
        "Phase 10 elaborated theorem type audit coverage/order differs from theorem manifest",
    )


def _find_top_level_proof_assign(block: str, declaration: str) -> int:
    depths = {"(": 0, "{": 0, "[": 0, "⟨": 0}
    closers = {")": "(", "}": "{", "]": "[", "⟩": "⟨"}
    i = 0
    while i < len(block) - 1:
        ch = block[i]
        if ch in depths:
            depths[ch] += 1
        elif ch in closers:
            opener = closers[ch]
            require(depths[opener] > 0, f"unbalanced theorem type delimiter in {declaration}")
            depths[opener] -= 1
        if block.startswith(":=", i) and all(depth == 0 for depth in depths.values()):
            return i
        i += 1
    raise base.GateError(f"theorem proof delimiter missing for {declaration}")


def verify_theorem_type_digests() -> None:
    manifest = base.load_json(base.MANIFEST_PATH)
    path = ROOT / "QSOLFed/Theorems.lean"
    code = base._lean_code_only(path.read_text(encoding="utf-8"), path)
    matches = list(THEOREM_START_RE.finditer(code))
    expected_declarations = [item["declaration"] for item in manifest.get("theorems", [])]
    observed_declarations = [match.group(1) for match in matches]
    require(
        observed_declarations == expected_declarations,
        "theorem source declaration order differs from manifest before type-digest verification",
    )
    require(
        set(EXPECTED_THEOREM_TYPE_SHA256) == set(expected_declarations),
        "expected theorem type-digest registry coverage drift",
    )

    for index, match in enumerate(matches):
        declaration = match.group(1)
        next_start = matches[index + 1].start() if index + 1 < len(matches) else len(code)
        block = code[match.start():next_start]
        assign = _find_top_level_proof_assign(block, declaration)
        normalized_type_source = " ".join(block[:assign].split())
        actual = hashlib.sha256(normalized_type_source.encode("utf-8")).hexdigest()
        require(
            actual == EXPECTED_THEOREM_TYPE_SHA256[declaration],
            f"theorem type/source digest drift for {declaration}",
        )


def validate() -> dict:
    verify_legacy_gate_snapshot()
    result = base.validate()
    verify_state_evidence_locked()
    verify_state_nonclaims_locked()
    verify_state_formalization_layer_locked()
    verify_assumption_statements_locked()
    verify_namespace_syntax_fail_closed()
    verify_theorem_context_fail_closed()
    verify_theorem_type_digests()
    verify_type_audit_locked()
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
            f"Phase 10 gate: OK ({result['theorem_count']} theorem declarations/source-types + elaborated environment types bound to {result['target_tag']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
