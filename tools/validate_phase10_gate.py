#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "machine/lean-phase10-manifest.json"
MANIFEST_SCHEMA_PATH = ROOT / "schemas/lean-phase10-manifest-v1.schema.json"
STATE_PATH = ROOT / "state/phase10.json"
CLAIMS_PATH = ROOT / "claims/phase10.json"
AXIOM_AUDIT_PATH = ROOT / "QSOLFed/AxiomAudit.lean"
REPORT_PATH = ROOT / "evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json"
REPORT_SHA256 = "6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c"
TARGET_TAG = "v0.11.0"
TARGET_COMMIT = "c953463724cdf218802e66e16f582ae8d600ca47"
TARGET_TREE = "93f23cd7eda6dd92ae13b7bb96bee01935b80731"
LEAN_TOOLCHAIN = "leanprover/lean4:v4.33.1"
LEAN_ARCHIVE_SHA256 = "890afd185370f85666025b883914ab4f4b339136f8c96167b69cfb62aecaf235"
EXPECTED_THEOREM_COUNT = 47
EXPECTED_FROZEN_INPUTS = {
    "ROADMAP.md": "42db05b1106e11cfb116920a5f4d8a2d92d60a66",
    "PRIME_DIRECTIVE.md": "ad6b5cdae5f8ada9b48f8066e3cb0f68ac9a6c93",
    "invariants/fed-v1.json": "97b62def1fd42cdc78cb178cddc9f269c98c620b",
    "wire/phase1.json": "1d34ac72d5d07c3f6b5bd28337eb6606cf44e782",
    "crypto/phase2.json": "042a850ccef4a058be595e955a87797d5e108e47",
    "state/phase4.json": "c9d7bcfcab9cd4581dc179a56071d7da1df97b13",
    "state/phase5a-holodeck.json": "bbb030469dcd66f4af37664c732820e6b6f0d760",
    "state/phase5.json": "5d2c22c46e9059668054a1dcb64facf071334505",
    "state/phase6.json": "c4eafb645c888d97f1d38e5eb1fe600e5aa49d0e",
    "state/phase7.json": "458c28c8ac075a6b3dcc2ea7189c3c77f0170a71",
    "state/phase8.json": "b855104b4fe4c97342b5bd48b248ca915e578703",
    "state/phase9.json": "c2bd1415cc86d27873a4432adb00d2306b87dbb0",
    "claims/phase9.json": "9ee94894169b0085c7282ac6c98a51b794eb0221",
    "fixtures/phase9/attack-corpus.json": "77d1a04e0912eec98613fc496478a04e6bae6cd6",
    "schemas/moriarty-report-v1.schema.json": "2c1992a796c48265309770653923effdb65b4f79",
}
PLACEHOLDER_RE = re.compile(r"\b(?:sorry|admit)\b")
AXIOM_TOKEN_RE = re.compile(r"\baxiom\b")
DECL_RE_TEMPLATE = r"\btheorem\s+{name}\b"
AXIOM_PRINT_RE = re.compile(r"(?m)^[ \t]*#print[ \t]+axioms[ \t]+QSOLFed\.([a-z][a-z0-9_]*)[ \t]*$")

# Every theorem-facing contract label is resolved to an exact location in one of the
# theorem's immutable v0.11.0 source refs. Labels are therefore aliases only; the
# authority for the binding remains the frozen source bytes at TARGET_TAG.
SOURCE_BOUND_CONTRACT_REGISTRY = {
    "prime_directive_local_admission": ("invariants/fed-v1.json", "/default_policies/foreign_semantic_material", "equals", "accept_as_data_only"),
    "foreign_state_is_not_local_state": ("invariants/fed-v1.json", "/invariants/6/id", "equals", "foreign_state_is_not_local_state"),
    "remote_governance_mutation_forbidden": ("invariants/fed-v1.json", "/invariants/9/id", "equals", "remote_governance_mutation_forbidden"),
    "remote_evidence_promotion_forbidden": ("invariants/fed-v1.json", "/invariants/10/id", "equals", "remote_evidence_promotion_forbidden"),
    "remote_arbitrary_execution_forbidden": ("invariants/fed-v1.json", "/invariants/15/id", "equals", "remote_arbitrary_execution_forbidden"),
    "runtime_constitution_override_forbidden": ("invariants/fed-v1.json", "/invariants/18/id", "equals", "runtime_constitution_override_forbidden"),
    "unknown_authority_action_rejected": ("invariants/fed-v1.json", "/invariants/19/id", "equals", "unknown_authority_action_rejected"),
    "signature_validity_is_trust=false": ("crypto/phase2.json", "/signature_validity_is_trust", "equals", False),
    "signature_validity_is_authority=false": ("crypto/phase2.json", "/signature_validity_is_authority", "equals", False),
    "signature_is_not_authority": ("crypto/phase2.json", "/signature_validity_is_authority", "equals", False),
    "prime_directive_admission": ("crypto/phase2.json", "/gate", "contains", "valid signature never bypasses Prime Directive admission"),
    "peering_is_not_trust": ("invariants/fed-v1.json", "/invariants/0/id", "equals", "peering_is_not_trust"),
    "local_sovereignty_over_federation_convenience": ("invariants/fed-v1.json", "/invariants/8/id", "equals", "local_sovereignty_over_federation_convenience"),
    "capability_is_not_entitlement": ("invariants/fed-v1.json", "/invariants/4/id", "equals", "capability_is_not_entitlement"),
    "explicit_local_allow": ("state/phase4.json", "/local_capability_policy/effective_allow_requires", "contains", "explicit local allow"),
    "peer_lifecycle_admitted": ("state/phase4.json", "/local_capability_policy/effective_allow_requires", "contains", "peer lifecycle state admitted"),
    "authenticated_advertisement": ("state/phase4.json", "/local_capability_policy/effective_allow_requires", "contains", "active authenticated advertisement"),
    "provenance_preserved": ("state/phase4.json", "/portable_bundle/preserves", "contains", "every independent foreign provenance attribution"),
    "import_is_not_authority": ("invariants/fed-v1.json", "/invariants/1/id", "equals", "import_is_not_authority"),
    "import_changes_trust=false": ("state/phase4.json", "/trust_registry/import_changes_trust", "equals", False),
    "identity_lifecycle_monotonic": ("state/phase4.json", "/peer_registry/identity_lifecycle_monotonic", "equals", True),
    "existing_lifecycle_must_be_exact_prefix": ("state/phase4.json", "/peer_registry/existing_lifecycle_must_be_exact_prefix", "equals", True),
    "partition_sovereignty": ("state/phase4.json", "/partition_rejoin/silent_reconciliation", "equals", False),
    "bundle_import_preserves_existing_local_state": ("state/phase4.json", "/peer_registry/bundle_import_preserves_existing_local_state", "equals", True),
    "partition_requires_explicit_reconciliation": ("state/phase4.json", "/partition_rejoin/changed_snapshot_rejoin", "equals", "explicit_reconciliation_required"),
    "same_snapshot_rejoin_explicit_confirm": ("state/phase4.json", "/partition_rejoin/same_snapshot_rejoin", "equals", "clean only after explicit confirm call"),
    "canonical_json_identity": ("wire/phase1.json", "/canonical_profile", "equals", "qsol-fed-canonical-json/1"),
    "object_identity_determinism": ("wire/phase1.json", "/object_identity", "contains", "sha256"),
    "simulation_output_authority=none": ("state/phase5a-holodeck.json", "/sandbox/simulation_output_authority", "equals", "none"),
    "simulation_output_evidence_effect=none": ("state/phase5a-holodeck.json", "/sandbox/simulation_output_evidence_effect", "equals", "none"),
    "simulation_output_federation_effect=none": ("state/phase5a-holodeck.json", "/sandbox/simulation_output_federation_effect", "equals", "none"),
    "transport_does_not_enter_holodeck_sandbox": ("state/phase5a-holodeck.json", "/sandbox/network_client_exposed", "equals", False),
    "computer_end_program_terminal": ("state/phase5a-holodeck.json", "/computer_safeguards/end_program_available_while_frozen", "equals", True),
    "adapter_data_is_not_local_authority": ("state/phase5.json", "/prime_directive/adapter_may_create_local_governance_authority", "equals", False),
    "vote_injection=false": ("state/phase5.json", "/nexus/vote_injection", "equals", False),
    "evidence_promotion=false": ("state/phase5.json", "/nexus/evidence_promotion", "equals", False),
    "sdk_conformance_is_not_trust": ("state/phase6.json", "/authority_boundary/sdk_creates_trust", "equals", False),
    "wire_compatibility_is_not_governance_membership": ("state/phase6.json", "/third_party_node/wire_namespace_implies_governance", "equals", False),
    "sdk_creates_authority=false": ("state/phase6.json", "/authority_boundary/sdk_creates_authority", "equals", False),
    "assembly_vote_is_not_member_command": ("state/phase7.json", "/authority_boundary/assembly_may_mutate_member_local_governance", "equals", False),
    "member_local_authority_mutated=false": ("state/phase7.json", "/governance_receipts/member_local_authority_mutated", "equals", False),
    "assembly_acceptance_is_not_deployment": ("state/phase7.json", "/proposal_lifecycle/accepted_proposal_changes_running_protocol", "equals", False),
    "protocol_changed_automatically=false": ("state/phase7.json", "/governance_receipts/protocol_changed_automatically", "equals", False),
    "assembly_consensus_is_not_member_local_authority": ("state/phase7.json", "/authority_boundary/assembly_consensus_is_member_local_authority", "equals", False),
    "nexus_advice_is_not_vote_weight": ("state/phase7.json", "/nexus_advisory/vote_weight", "equals", 0),
    "transport_is_not_identity": ("state/phase8.json", "/identity_boundary/transport_profile_may_replace_sender_identity", "equals", False),
    "message_id_preserved_across_transports": ("state/phase8.json", "/identity_boundary/message_id_preserved_across_transports", "equals", True),
    "payload_ref_preserved_across_transports": ("state/phase8.json", "/identity_boundary/payload_ref_preserved_across_transports", "equals", True),
    "provenance_ref_preserved_across_transports": ("state/phase8.json", "/identity_boundary/provenance_ref_preserved_across_transports", "equals", True),
    "route_is_not_trust": ("state/phase8.json", "/identity_boundary/transport_route_may_create_trust", "equals", False),
    "nat_ticket_may_replace_identity=false": ("state/phase8.json", "/authority_boundary/nat_ticket_may_replace_identity", "equals", False),
    "relay_is_not_authority": ("state/phase8.json", "/multi_relay_provenance/relay_presence_is_authority", "equals", False),
    "relay_presence_is_trust=false": ("state/phase8.json", "/multi_relay_provenance/relay_presence_is_trust", "equals", False),
}

SUPPORTED_SCHEMA_KEYWORDS = {
    "$schema", "$id", "title", "type", "additionalProperties", "required", "properties",
    "const", "enum", "minLength", "maxLength", "pattern", "minItems", "maxItems", "items",
}


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_NO_REPLACE_OBJECTS": "1"},
    )
    return result.stdout.strip()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _json_equal(left, right) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":"), ensure_ascii=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _schema_type_matches(value, type_name: str) -> bool:
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "null":
        return value is None
    raise GateError(f"unsupported JSON Schema type: {type_name}")


def validate_schema_instance(value, schema: dict, path: str = "$") -> None:
    require(isinstance(schema, dict), f"schema node at {path} is not an object")
    unknown = set(schema) - SUPPORTED_SCHEMA_KEYWORDS
    require(not unknown, f"unsupported JSON Schema keyword(s) at {path}: {sorted(unknown)}")

    if "const" in schema:
        require(_json_equal(value, schema["const"]), f"schema const mismatch at {path}")
    if "enum" in schema:
        enum = schema["enum"]
        require(isinstance(enum, list) and enum, f"schema enum invalid at {path}")
        require(any(_json_equal(value, item) for item in enum), f"schema enum mismatch at {path}")

    type_name = schema.get("type")
    if type_name is not None:
        require(isinstance(type_name, str), f"schema type invalid at {path}")
        require(_schema_type_matches(value, type_name), f"schema type mismatch at {path}: expected {type_name}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        require(isinstance(required, list) and all(isinstance(item, str) for item in required), f"schema required invalid at {path}")
        require(len(required) == len(set(required)), f"schema required duplicates at {path}")
        for key in required:
            require(key in value, f"schema required property missing at {path}.{key}")
        properties = schema.get("properties", {})
        require(isinstance(properties, dict), f"schema properties invalid at {path}")
        additional = schema.get("additionalProperties", True)
        require(isinstance(additional, (bool, dict)), f"schema additionalProperties invalid at {path}")
        extras = set(value) - set(properties)
        if additional is False:
            require(not extras, f"schema additional properties forbidden at {path}: {sorted(extras)}")
        elif isinstance(additional, dict):
            for key in extras:
                validate_schema_instance(value[key], additional, f"{path}.{key}")
        for key, child_schema in properties.items():
            require(isinstance(key, str), f"schema property name invalid at {path}")
            if key in value:
                validate_schema_instance(value[key], child_schema, f"{path}.{key}")

    if isinstance(value, list):
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if min_items is not None:
            require(isinstance(min_items, int) and min_items >= 0 and len(value) >= min_items, f"schema minItems mismatch at {path}")
        if max_items is not None:
            require(isinstance(max_items, int) and max_items >= 0 and len(value) <= max_items, f"schema maxItems mismatch at {path}")
        items = schema.get("items")
        if items is not None:
            require(isinstance(items, dict), f"schema items invalid at {path}")
            for index, item in enumerate(value):
                validate_schema_instance(item, items, f"{path}[{index}]")

    if isinstance(value, str):
        min_length = schema.get("minLength")
        max_length = schema.get("maxLength")
        if min_length is not None:
            require(isinstance(min_length, int) and min_length >= 0 and len(value) >= min_length, f"schema minLength mismatch at {path}")
        if max_length is not None:
            require(isinstance(max_length, int) and max_length >= 0 and len(value) <= max_length, f"schema maxLength mismatch at {path}")
        pattern = schema.get("pattern")
        if pattern is not None:
            require(isinstance(pattern, str), f"schema pattern invalid at {path}")
            try:
                matched = re.search(pattern, value) is not None
            except re.error as exc:
                raise GateError(f"invalid schema regex at {path}: {exc}") from exc
            require(matched, f"schema pattern mismatch at {path}")


def verify_manifest_schema(manifest: dict) -> dict:
    schema = load_json(MANIFEST_SCHEMA_PATH)
    require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "Phase 10 manifest schema draft drift")
    validate_schema_instance(manifest, schema)
    return schema


def _json_pointer_get(document, pointer: str):
    require(isinstance(pointer, str) and pointer.startswith("/"), f"invalid JSON pointer: {pointer!r}")
    current = document
    for encoded in pointer.split("/")[1:]:
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            require(token in current, f"JSON pointer key missing: {pointer}")
            current = current[token]
        elif isinstance(current, list):
            require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None, f"JSON pointer list index invalid: {pointer}")
            index = int(token)
            require(index < len(current), f"JSON pointer list index out of range: {pointer}")
            current = current[index]
        else:
            raise GateError(f"JSON pointer traverses scalar: {pointer}")
    return current


def verify_contract_traceability(manifest: dict, frozen_inputs: set[str]) -> None:
    used_ids = {
        contract_id
        for theorem in manifest.get("theorems", [])
        for contract_id in theorem.get("contract_ids", [])
    }
    registry_ids = set(SOURCE_BOUND_CONTRACT_REGISTRY)
    require(used_ids == registry_ids, f"contract registry coverage drift: missing={sorted(used_ids - registry_ids)}, stale={sorted(registry_ids - used_ids)}")

    cache: dict[str, object] = {}
    for theorem in manifest["theorems"]:
        declaration = theorem["declaration"]
        theorem_refs = set(theorem["source_refs"])
        for contract_id in theorem["contract_ids"]:
            source_ref, pointer, mode, expected = SOURCE_BOUND_CONTRACT_REGISTRY[contract_id]
            require(source_ref in theorem_refs, f"theorem {declaration} contract {contract_id} resolves outside declared source_refs: {source_ref}")
            require(source_ref in frozen_inputs, f"contract registry source is not frozen: {source_ref}")
            if source_ref not in cache:
                try:
                    cache[source_ref] = json.loads(git("show", f"{TARGET_TAG}:{source_ref}"))
                except json.JSONDecodeError as exc:
                    raise GateError(f"contract registry source is not valid JSON: {source_ref}: {exc}") from exc
            actual = _json_pointer_get(cache[source_ref], pointer)
            if mode == "equals":
                require(_json_equal(actual, expected), f"contract {contract_id} source binding mismatch at {source_ref}{pointer}")
            elif mode == "contains":
                require(isinstance(actual, (str, list)), f"contract {contract_id} contains binding targets non-container at {source_ref}{pointer}")
                require(expected in actual, f"contract {contract_id} source evidence missing at {source_ref}{pointer}")
            else:
                raise GateError(f"contract registry mode invalid for {contract_id}: {mode}")


def verify_frozen_target(manifest: dict) -> None:
    require(git("cat-file", "-t", TARGET_COMMIT) == "commit", "frozen target is not a commit object")
    require(git("rev-parse", f"{TARGET_TAG}^{{commit}}") == TARGET_COMMIT, "v0.11.0 does not resolve to frozen target commit")
    require(git("cat-file", "-t", TARGET_TAG) == "commit", "v0.11.0 is not a direct commit tag ref")
    require(git("rev-parse", f"{TARGET_COMMIT}^{{tree}}") == TARGET_TREE, "frozen target tree drift")

    release = manifest.get("source_release", {})
    expected = {
        "id": 377808649,
        "tag": TARGET_TAG,
        "immutable": True,
        "commit": TARGET_COMMIT,
        "tree": TARGET_TREE,
        "published_at": "2026-08-27T12:35:21Z",
    }
    require({key: release.get(key) for key in expected} == expected, "manifest frozen release identity drift")


def verify_moriarty_binding(manifest: dict) -> None:
    binding = manifest.get("moriarty_binding", {})
    expected = {
        "protocol": "MORIARTY/1",
        "workflow_run": 33069191846,
        "run_number": 413,
        "artifact_id": 9645064099,
        "artifact_digest": "sha256:1c77cb56e83a0af19961e9f3c99d3ace02f6dd905655dc64b36aa90d46e9d9ce",
        "report_path": "evidence/phase10/moriarty-report-c953463724cdf218802e66e16f582ae8d600ca47.json",
        "report_sha256": "sha256:6c215f44a1c52aa3bfefadc4039013ea69ddbe0f2afd06f6dac27377369b185c",
        "target_commit": TARGET_COMMIT,
        "corpus_ref": "sha256:af50e8145a72a1a583ede29687535a59c0e17ac37fdd66e1ede51c453e8fd3e6",
        "family_count": 15,
        "executed_probe_count": 13,
        "unresolved_counterexamples": 0,
        "graduated": True,
        "security_proof": False,
    }
    require({key: binding.get(key) for key in expected} == expected, "MORIARTY binding drift")
    require(REPORT_PATH.is_file(), "retained MORIARTY report missing")
    report_bytes = REPORT_PATH.read_bytes()
    require(hashlib.sha256(report_bytes).hexdigest() == REPORT_SHA256, "retained MORIARTY report SHA-256 drift")
    report = json.loads(report_bytes.decode("utf-8"))
    report_expected = {
        "protocol": "MORIARTY/1",
        "schema": "moriarty-report/1",
        "target_commit": TARGET_COMMIT,
        "corpus_ref": expected["corpus_ref"],
        "family_count": 15,
        "executed_probe_count": 13,
        "unresolved_counterexamples": 0,
        "graduated": True,
        "security_proof": False,
        "no_counterexample_found_implies_none_exist": False,
        "production_credentials_used": False,
        "production_targets_used": False,
        "constitutional_bypass_used": False,
        "authority_effect": "none",
    }
    require({key: report.get(key) for key in report_expected} == report_expected, "retained MORIARTY report semantic drift")
    require(report.get("counterexamples") == [] and report.get("remediation_replays") == [], "retained MORIARTY report counterexample/replay drift")
    probes = report.get("probe_results")
    require(isinstance(probes, list) and len(probes) == 13, "retained MORIARTY probe inventory drift")
    expected_probe_ids = {"constitution", "phase0", "phase1", "phase2", "phase3", "phase4", "phase5a", "phase5", "phase5c", "phase6", "phase7", "phase8", "rust_all"}
    require({item.get("probe_id") for item in probes if isinstance(item, dict)} == expected_probe_ids, "retained MORIARTY probe ID drift")
    require(all(item.get("ok") is True and item.get("exit_code") == 0 and item.get("failure_kind") is None for item in probes), "retained MORIARTY probe failure")


def verify_frozen_inputs(manifest: dict) -> set[str]:
    items = manifest.get("frozen_inputs")
    require(isinstance(items, list), "frozen_inputs must be a list")
    require(len(items) == len(EXPECTED_FROZEN_INPUTS), "frozen input inventory count drift")
    observed: dict[str, str] = {}
    for item in items:
        require(isinstance(item, dict) and set(item) == {"path", "git_blob_sha1"}, "frozen input field set drift")
        path = item["path"]
        blob = item["git_blob_sha1"]
        require(isinstance(path, str) and path and path not in observed, f"invalid/duplicate frozen input path: {path!r}")
        require(re.fullmatch(r"[0-9a-f]{40}", blob) is not None, f"invalid frozen input blob: {path}")
        observed[path] = blob
    require(observed == EXPECTED_FROZEN_INPUTS, "frozen input inventory/path/blob drift")
    for path, blob in EXPECTED_FROZEN_INPUTS.items():
        actual = git("rev-parse", f"{TARGET_TAG}:{path}")
        require(actual == blob, f"frozen input blob drift: {path}: {actual} != {blob}")
        require(git("cat-file", "-t", actual) == "blob", f"frozen input is not a blob: {path}")
    return set(observed)


def verify_toolchain(manifest: dict) -> None:
    require((ROOT / "lean-toolchain").read_text(encoding="utf-8").strip() == LEAN_TOOLCHAIN, "lean-toolchain drift")
    toolchain = manifest.get("toolchain", {})
    require(toolchain.get("lean") == "v4.33.1", "manifest Lean version drift")
    require(toolchain.get("lean_toolchain") == LEAN_TOOLCHAIN, "manifest lean-toolchain drift")
    require(toolchain.get("archive_sha256") == LEAN_ARCHIVE_SHA256, "manifest Lean archive checksum drift")
    require(toolchain.get("external_dependencies") == [], "Phase 10 must remain dependency-free beyond Lean core")

    lakefile_path = ROOT / "lakefile.toml"
    require(lakefile_path.is_file(), "lakefile.toml missing")
    try:
        lakefile = tomllib.loads(lakefile_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise GateError(f"lakefile.toml invalid: {exc}") from exc
    expected_lakefile = {
        "name": "qsol-fed-formal",
        "version": "0.11.0",
        "defaultTargets": ["QSOLFed"],
        "lean_lib": [{"name": "QSOLFed"}],
    }
    require(_json_equal(lakefile, expected_lakefile), "lakefile dependency/configuration drift")

    resolved_path = ROOT / "lake-manifest.json"
    if resolved_path.exists():
        resolved = load_json(resolved_path)
        require(resolved.get("packages") == [], "resolved Lake dependency graph is not empty")


def verify_theorems(manifest: dict, frozen_inputs: set[str]) -> None:
    theorems = manifest.get("theorems")
    require(isinstance(theorems, list), "theorems must be a list")
    require(manifest.get("theorem_count") == EXPECTED_THEOREM_COUNT == len(theorems), "theorem count drift")

    ids: set[str] = set()
    declarations: set[str] = set()
    file_cache: dict[str, str] = {}
    for index, theorem in enumerate(theorems, 1):
        required = {"id", "declaration", "module", "path", "source_refs", "contract_ids", "proof_status"}
        require(set(theorem) == required, f"theorem {index} field set drift")
        expected_id = f"FED-LEAN-{index:03d}"
        require(theorem["id"] == expected_id and expected_id not in ids, f"theorem ID drift/duplicate at {index}")
        ids.add(expected_id)
        declaration = theorem["declaration"]
        require(re.fullmatch(r"[a-z][a-z0-9_]*", declaration) is not None, f"invalid theorem declaration: {declaration}")
        require(declaration not in declarations, f"duplicate theorem declaration: {declaration}")
        declarations.add(declaration)
        require(theorem["module"] == "QSOLFed.Theorems", f"unexpected module for {declaration}")
        path = theorem["path"]
        require(path == "QSOLFed/Theorems.lean", f"unexpected theorem path for {declaration}")
        if path not in file_cache:
            file_cache[path] = (ROOT / path).read_text(encoding="utf-8")
        source = file_cache[path]
        require(re.search(DECL_RE_TEMPLATE.format(name=re.escape(declaration)), source) is not None, f"manifest declaration missing from Lean source: {declaration}")
        refs = theorem["source_refs"]
        require(isinstance(refs, list) and refs and len(refs) == len(set(refs)), f"invalid source_refs for {declaration}")
        for ref in refs:
            require(ref in frozen_inputs, f"theorem {declaration} references unbound frozen input {ref}")
        contract_ids = theorem["contract_ids"]
        require(isinstance(contract_ids, list) and contract_ids and all(isinstance(x, str) and x for x in contract_ids), f"missing contract traceability for {declaration}")
        require(len(contract_ids) == len(set(contract_ids)), f"duplicate contract IDs for {declaration}")
        require(theorem["proof_status"] == "IMPLEMENTED", f"unexpected proof status for {declaration}")


def verify_axiom_audit_coverage(manifest: dict) -> None:
    require(AXIOM_AUDIT_PATH.is_file(), "Phase 10 axiom audit source missing")
    audit_source = AXIOM_AUDIT_PATH.read_text(encoding="utf-8")
    audited = AXIOM_PRINT_RE.findall(audit_source)
    expected = [theorem["declaration"] for theorem in manifest.get("theorems", [])]
    require(len(audited) == EXPECTED_THEOREM_COUNT, "Phase 10 axiom audit theorem count drift")
    require(len(audited) == len(set(audited)), "Phase 10 axiom audit contains duplicate theorem entries")
    require(audited == expected, "Phase 10 axiom audit coverage/order differs from theorem manifest")


def verify_no_placeholders() -> None:
    lean_files = sorted(ROOT.glob("QSOLFed/**/*.lean")) + [ROOT / "QSOLFed.lean"]
    require(lean_files, "no Lean source files found")
    for path in lean_files:
        source = path.read_text(encoding="utf-8")
        match = PLACEHOLDER_RE.search(source)
        require(match is None, f"unresolved proof placeholder in {path.relative_to(ROOT)}")


def _lean_code_only(text: str, path: Path) -> str:
    out: list[str] = []
    i = 0
    block_depth = 0
    in_string = False
    while i < len(text):
        if block_depth:
            if text.startswith("/-", i):
                block_depth += 1
                out.extend("  ")
                i += 2
            elif text.startswith("-/", i):
                block_depth -= 1
                out.extend("  ")
                i += 2
            else:
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue

        if in_string:
            if text[i] == "\\" and i + 1 < len(text):
                out.extend("  ")
                i += 2
            elif text[i] == '"':
                in_string = False
                out.append(" ")
                i += 1
            else:
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue

        if text.startswith("--", i):
            while i < len(text) and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if text.startswith("/-", i):
            block_depth = 1
            out.extend("  ")
            i += 2
            continue
        if text[i] == '"':
            in_string = True
            out.append(" ")
            i += 1
            continue

        out.append(text[i])
        i += 1

    require(block_depth == 0, f"unterminated Lean block comment while scanning {path.relative_to(ROOT)}")
    require(not in_string, f"unterminated Lean string while scanning {path.relative_to(ROOT)}")
    return "".join(out)


def verify_no_custom_axioms() -> None:
    lean_files = sorted(ROOT.glob("QSOLFed/**/*.lean")) + [ROOT / "QSOLFed.lean"]
    require(lean_files, "no Lean source files found")
    found: list[str] = []
    for path in lean_files:
        code = _lean_code_only(path.read_text(encoding="utf-8"), path)
        for match in AXIOM_TOKEN_RE.finditer(code):
            line = code.count("\n", 0, match.start()) + 1
            found.append(f"{path.relative_to(ROOT)}:{line}")
    require(not found, "custom axiom declaration/token found in Phase 10 source: " + ", ".join(found))


def verify_manifest_policy(manifest: dict) -> None:
    require(manifest.get("schema") == "qsol-fed-lean-phase10-manifest/1", "manifest schema drift")
    require(manifest.get("protocol") == "qsol-fed/0" and manifest.get("phase") == 10, "manifest protocol/phase drift")
    status = manifest.get("status")
    require(status in {"IMPLEMENTED_PENDING_CI", "LEAN_VERIFIED_ON_BRANCH", "LEAN_VERIFIED_ON_MERGED_MAIN"}, "manifest verification status drift")
    if status == "LEAN_VERIFIED_ON_MERGED_MAIN":
        require(os.environ.get("GITHUB_EVENT_NAME") == "push", "merged-main status requires GitHub push context")
        require(os.environ.get("GITHUB_REF") == "refs/heads/main", "merged-main status requires refs/heads/main")
        event_sha = os.environ.get("GITHUB_SHA", "")
        require(re.fullmatch(r"[0-9a-f]{40}", event_sha) is not None, "merged-main status requires exact GitHub SHA")
        require(git("rev-parse", "HEAD") == event_sha, "merged-main status SHA differs from checked-out commit")
    assumptions = manifest.get("assumptions")
    require(isinstance(assumptions, list) and {x.get("id") for x in assumptions} == {"MODEL_SCOPE", "CANONICAL_BYTES_INPUT", "REAL_WORLD_PRINCIPALS"}, "named assumptions drift")
    nonclaims = set(manifest.get("nonclaims", []))
    required_nonclaims = {
        "LEAN_THEOREM != DEPLOYMENT_SECURITY_PROOF",
        "FORMAL_MODEL != UNSTATED_REAL_WORLD_ASSUMPTION",
        "LEAN_MODEL != COMPLETE_RUST_IMPLEMENTATION_VERIFICATION",
        "MORIARTY_REPORT != SECURITY_PROOF",
        "TARGET_BOUND_SOURCE_RELEASE != POST_TAG_FORMALIZATION_LAYER",
    }
    require(required_nonclaims <= nonclaims, "formalization nonclaim boundary drift")
    graduation = manifest.get("graduation_requirements", {})
    require(graduation.get("no_unresolved_sorry_or_admit") is True, "placeholder prohibition missing")
    require(graduation.get("named_assumptions_required") is True, "named assumption requirement missing")
    require(graduation.get("theorem_to_contract_traceability_required") is True, "traceability requirement missing")
    require(graduation.get("clean_checkout_build_required") is True, "clean checkout build requirement missing")
    require(graduation.get("custom_axioms_allowed") == [], "custom axioms must not be admitted")


def verify_frozen_roadmap_contract() -> None:
    roadmap = git("show", f"{TARGET_TAG}:ROADMAP.md")
    required = [
        "Phase 10 — Lean 4 formalization",
        "Prime Directive admission",
        "signature/trust/authority separation",
        "transport identity/provenance independence",
        "No unresolved `sorry`/`admit` is permitted in the graduation theorem set",
        "assumptions must be named and theorem-to-contract traceability complete",
        "LEAN THEOREM != DEPLOYMENT SECURITY PROOF",
        "FORMAL MODEL != UNSTATED REAL-WORLD ASSUMPTION",
    ]
    for text in required:
        require(text in roadmap, f"frozen Phase 10 ROADMAP contract missing: {text}")


def verify_phase10_contracts(manifest: dict, schema: dict) -> None:
    state = load_json(STATE_PATH)
    claims = load_json(CLAIMS_PATH)
    phase9_claims = load_json(ROOT / "claims/phase9.json")
    phase8_claims = load_json(ROOT / "claims/phase8.json")
    try:
        frozen_phase9_claims = json.loads(git("show", f"{TARGET_TAG}:claims/phase9.json"))
    except json.JSONDecodeError as exc:
        raise GateError(f"frozen Phase 9 claims invalid JSON: {exc}") from exc

    require(state.get("document_type") == "qsol-fed-phase10-lean-contract" and state.get("phase") == "10", "Phase 10 state contract identity drift")
    source = state.get("source_release", {})
    require(source.get("tag") == TARGET_TAG and source.get("commit") == TARGET_COMMIT and source.get("tree") == TARGET_TREE and source.get("immutable") is True, "Phase 10 state source release drift")
    scope = state.get("theorem_scope", {})
    require(scope.get("theorem_count") == EXPECTED_THEOREM_COUNT, "Phase 10 state theorem count drift")
    require(scope.get("no_sorry_or_admit") is True and scope.get("custom_axioms") == [] and scope.get("kernel_axiom_dependencies") == [], "Phase 10 state proof-discipline drift")
    evidence = state.get("moriarty_source_evidence", {})
    require(evidence.get("retained_report") == str(REPORT_PATH.relative_to(ROOT)) and evidence.get("retained_report_sha256") == "sha256:" + REPORT_SHA256, "Phase 10 state MORIARTY report binding drift")

    require(claims.get("document_type") == "qsol-fed-phase10-lean-claims" and claims.get("phase") == "10", "Phase 10 claim identity drift")
    require(claims.get("claim_surface_changed") is False, "Phase 10 must not change runtime capability claims")
    frozen_capabilities = frozen_phase9_claims.get("capabilities")
    require(isinstance(frozen_capabilities, dict), "frozen Phase 9 capability baseline missing")
    require(claims.get("capabilities") == frozen_capabilities, "Phase 10 capability map differs from immutable v0.11.0 Phase 9 baseline")
    require(phase9_claims.get("capabilities") == frozen_capabilities, "working Phase 9 capability map differs from immutable v0.11.0 baseline")
    require(phase8_claims.get("capabilities") == frozen_capabilities, "working Phase 8 capability map differs from immutable v0.11.0 baseline")
    assurance = claims.get("formalization_assurance", {})
    require(assurance.get("theorem_count") == EXPECTED_THEOREM_COUNT, "Phase 10 formalization assurance theorem count drift")
    require(assurance.get("unresolved_sorry_or_admit") is False and assurance.get("custom_axioms") is False and assurance.get("graduation_theorem_kernel_axiom_dependencies") is False, "Phase 10 formalization assurance proof-discipline drift")
    require(
        assurance.get("whole_implementation_verified") is False
        and assurance.get("deployment_security_proof") is False
        and assurance.get("source_release_rewritten") is False
        and assurance.get("formalization_creates_authority") is False,
        "Phase 10 formalization assurance overclaim",
    )

    require(schema.get("$id") == "https://qsol.example/schemas/lean-phase10-manifest-v1.schema.json", "Phase 10 manifest schema ID drift")
    properties = schema.get("properties", {})
    require(properties.get("theorem_count", {}).get("const") == EXPECTED_THEOREM_COUNT, "Phase 10 manifest schema theorem count drift")
    require(manifest.get("status") in properties.get("status", {}).get("enum", []), "Phase 10 manifest status not admitted by schema")
    report_const = properties.get("moriarty_binding", {}).get("properties", {}).get("report_sha256", {}).get("const")
    require(report_const == "sha256:" + REPORT_SHA256, "Phase 10 manifest schema report digest drift")

    docs = (ROOT / "FORMALIZATION.md").read_text(encoding="utf-8")
    for text in (TARGET_TAG, TARGET_COMMIT, TARGET_TREE, "LEAN THEOREM != DEPLOYMENT SECURITY PROOF", "TARGET_BOUND SOURCE RELEASE != POST-TAG FORMALIZATION LAYER"):
        require(text in docs, f"FORMALIZATION.md missing boundary/source text: {text}")


def validate() -> dict:
    manifest = load_json(MANIFEST_PATH)
    schema = verify_manifest_schema(manifest)
    verify_manifest_policy(manifest)
    verify_frozen_target(manifest)
    verify_moriarty_binding(manifest)
    verify_phase10_contracts(manifest, schema)
    frozen_inputs = verify_frozen_inputs(manifest)
    verify_toolchain(manifest)
    verify_theorems(manifest, frozen_inputs)
    verify_contract_traceability(manifest, frozen_inputs)
    verify_axiom_audit_coverage(manifest)
    verify_no_placeholders()
    verify_no_custom_axioms()
    verify_frozen_roadmap_contract()
    return {
        "status": "ok",
        "target_tag": TARGET_TAG,
        "target_commit": TARGET_COMMIT,
        "target_tree": TARGET_TREE,
        "theorem_count": EXPECTED_THEOREM_COUNT,
        "manifest_status": manifest["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate()
    except (GateError, subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        else:
            print(f"Phase 10 gate: ERROR: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"Phase 10 gate: OK ({result['theorem_count']} theorem declarations bound to {TARGET_TAG})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
