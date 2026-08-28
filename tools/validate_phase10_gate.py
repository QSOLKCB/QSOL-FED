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

# Round-7 contract additions. The legacy gate remains a frozen snapshot of the
# already-reviewed round-6 validator; this wrapper layers the new fail-closed
# checks without weakening any prior gate.
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

EXPECTED_THEOREM_TYPE_SHA256 = {
    "prime_directive_accepts_data_only": "a9970c1529f1f67b91dbcb47eb18042ec4715547eb733080798b9d646ef10bbc",
    "prime_directive_quarantines_foreign_state": "228093719203b00ebfa83627b31177dc84da362ef5fab06e7b9357ccd9f41259",
    "prime_directive_rejects_governance_mutation": "0e2c19d8b01b991ef2e9e87caf082e1fd2b74237903754da9ab7f437732be224",
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
    "holodeck_output_has_no_authority": "d604d8f847120d8b55badba238b9d5fac6b623eb394d6751c1f27c9cf27d06d7",
    "holodeck_output_has_no_evidence_effect": "5d8256bd969477f050267388beefe1e2ee995c89367cd0ea4d9e4eee406cfeb1",
    "holodeck_output_has_no_federation_effect": "321e8487df522bbd93e14ccd5693fcae309d9985c24517fb16df393e8bfcbbab",
    "holodeck_transport_does_not_relabel_network_use": "3d0f171dbf9af4078cc0576c411e9a2a5c8a10853f426a1d5c2ba38e6814e5bc",
    "holodeck_end_program_terminal_even_when_frozen": "629ec6fe62a8776ca912a28bd0b503c7069f2c1811bd29f066d486cffbcb7840",
    "adapter_output_has_no_authority": "3812ba13f8587747e4f64812be6cb0b2dd1bc9e24ae7678c23215676a7f6dfe2",
    "adapter_cannot_inject_vote": "3c454c34f6988268bc8659a53e42043582132beda7af4f066bb62c1fd3cc444e",
    "adapter_cannot_promote_evidence": "bd7140ad840b8a5b1a15645d125a1c949f27f481542b8924256d7615479e84a3",
    "sdk_conformance_does_not_create_trust": "27950340c947151b3ec464cd166408162ff08c3d0873a9ed6b39087a079be17f",
    "sdk_conformance_does_not_create_governance_membership": "690085239cc58005dd6dbae653a7da617a106d414a9d00b3c6e71c85f640ff2a",
    "sdk_conformance_does_not_create_authority": "0921313bddab8e978f5a1a41fcc55ef91c0c701bfaecc60856ec2c242f88eeb1",
    "assembly_acceptance_does_not_mutate_member_authority": "43d0dc32cf09a97e70ed0cf844b7e8083c17617f4423693de32027c75b4fdf72",
    "assembly_acceptance_does_not_change_protocol_automatically": "2f80e3ab0ec9a0c5b66e43b4ff8891d9cd3e92aed8bc10edfaaf8d0ec3736473",
    "assembly_receipt_has_no_authority_effect": "e3304ca570c2387a924b1a28fc1cf91891c55ab63742a78c0bb04cdbdc60cdcc",
    "nexus_advisory_has_zero_vote_weight": "01f356290d4269f36f757222aca85196f56e68048c67f99d15f296d10958fbae",
    "transport_preserves_authenticated_identity": "e3a5f346ab512f6ca59921372af9e952bba6c5e6fe0a08ab0b4a202c56fc52af",
    "transport_preserves_message_identity": "ee38f8f7b923341886e784239f9ee90c266e173a9081f921dec1c15db04780de",
    "transport_preserves_payload_reference": "e9b1780e95bcd259aa4bbd85081fadd4e99c738032da96886b48072d303448d9",
    "transport_preserves_provenance": "e79594378d179aa2f280f774f4a402e83bf1e7af84c5346c3c91c239a0d30cdb",
    "nat_route_does_not_create_trust": "27e4adbc44afb6ee7d72c5adc2958c8df8eb29dc3036d432d933756e4eca9aea",
    "nat_route_does_not_replace_identity": "74d127d00d89646ec340b267456e7e6290ede70ab755d95c080cc0120012fd03",
    "relay_does_not_create_authority": "7b4099149e9bb4585f7a096566bf5e742380cfa9de9d06cc1124f175dfe185c5",
    "relay_does_not_create_trust": "2c064061b897987816f081029eca5a4e19c339ced60c2c31cd766e80a249bef9"
}

THEOREM_START_RE = re.compile(r"(?m)^[ \t]*theorem[ \t]+([a-z][a-z0-9_]*)\b")


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
    verify_assumption_statements_locked()
    verify_namespace_syntax_fail_closed()
    verify_theorem_type_digests()
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
            f"Phase 10 gate: OK ({result['theorem_count']} theorem declarations/types bound to {result['target_tag']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
