#!/usr/bin/env python3
"""Enforce the MORIARTY/1 exact-commit adversarial graduation boundary."""
from __future__ import annotations

import argparse
import copy
import os
import hashlib
import builtins
import types
import json
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.dont_write_bytecode = True
_BOOTSTRAP_GIT = Path("/usr/bin/git")
_BOOTSTRAP_TARGET_RE = re.compile(r"^[0-9a-f]{40}$")


def _bootstrap_git_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": "/dev/null",
        "GIT_CONFIG_KEY_2": "core.attributesFile",
        "GIT_CONFIG_VALUE_2": "/dev/null",
    }


def _bootstrap_git(*args: str) -> subprocess.CompletedProcess[bytes]:
    if not _BOOTSTRAP_GIT.is_file():
        raise SystemExit("moriarty_bootstrap_system_git_unavailable")
    return subprocess.run(
        [str(_BOOTSTRAP_GIT), *args],
        cwd=ROOT,
        env=_bootstrap_git_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        close_fds=True,
    )


def _bootstrap_target() -> str:
    target: str | None = None
    if "--target-commit" in sys.argv:
        index = sys.argv.index("--target-commit")
        if index + 1 < len(sys.argv):
            target = sys.argv[index + 1]
    if target is None:
        completed = _bootstrap_git("rev-parse", "HEAD")
        if completed.returncode != 0:
            raise SystemExit("moriarty_bootstrap_target_unavailable")
        try:
            target = completed.stdout.decode("ascii", errors="strict").strip()
        except UnicodeError:
            raise SystemExit("moriarty_bootstrap_target_invalid")
    if _BOOTSTRAP_TARGET_RE.fullmatch(target) is None:
        raise SystemExit("moriarty_bootstrap_target_invalid")
    return target


def _bootstrap_git_object(kind: str, object_id: str) -> bytes:
    if _BOOTSTRAP_TARGET_RE.fullmatch(object_id) is None:
        raise SystemExit("moriarty_bootstrap_object_id_invalid")
    completed = _bootstrap_git("cat-file", kind, object_id)
    if completed.returncode != 0:
        raise SystemExit(f"moriarty_bootstrap_{kind}_read_failed")
    payload = completed.stdout
    actual = hashlib.sha1(f"{kind} {len(payload)}".encode("ascii") + b"\x00" + payload).hexdigest()
    if actual != object_id:
        raise SystemExit(f"moriarty_bootstrap_{kind}_hash_mismatch")
    return payload


def _bootstrap_tree_entry(tree_payload: bytes, wanted: str) -> tuple[str, str]:
    cursor = 0
    while cursor < len(tree_payload):
        space = tree_payload.find(b" ", cursor)
        nul = tree_payload.find(b"\x00", space + 1 if space >= 0 else cursor)
        if space <= cursor or nul <= space or nul + 21 > len(tree_payload):
            raise SystemExit("moriarty_bootstrap_tree_malformed")
        mode = tree_payload[cursor:space].decode("ascii", errors="strict")
        name = tree_payload[space + 1:nul].decode("utf-8", errors="strict")
        object_id = tree_payload[nul + 1:nul + 21].hex()
        cursor = nul + 21
        if name == wanted:
            return mode, object_id
    raise SystemExit(f"moriarty_bootstrap_path_missing:{wanted}")


def _bootstrap_verified_blob(target: str, relative: str) -> bytes:
    commit_payload = _bootstrap_git_object("commit", target)
    first_line = commit_payload.split(b"\n", 1)[0]
    if not first_line.startswith(b"tree "):
        raise SystemExit("moriarty_bootstrap_commit_tree_missing")
    tree_id = first_line[5:].decode("ascii", errors="strict")
    parts = relative.split("/")
    for index, part in enumerate(parts):
        tree_payload = _bootstrap_git_object("tree", tree_id)
        mode, object_id = _bootstrap_tree_entry(tree_payload, part)
        if index + 1 < len(parts):
            if mode != "40000":
                raise SystemExit("moriarty_bootstrap_path_not_tree")
            tree_id = object_id
            continue
        if mode not in {"100644", "100755"}:
            raise SystemExit("moriarty_bootstrap_source_not_regular")
        return _bootstrap_git_object("blob", object_id)
    raise SystemExit("moriarty_bootstrap_path_invalid")


def _load_verified_source_module(name: str, target: str):
    relative = f"tools/{name}.py"
    path = ROOT / relative
    expected = _bootstrap_verified_blob(target, relative)
    try:
        actual = path.read_bytes()
    except OSError:
        raise SystemExit(f"moriarty_bootstrap_source_unavailable:{name}")
    if actual != expected:
        raise SystemExit(f"moriarty_bootstrap_source_mismatch:{name}")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    module.__loader__ = None
    module.__spec__ = None
    sys.modules[name] = module
    try:
        code = compile(expected, str(path), "exec", dont_inherit=True, optimize=0)
        getattr(builtins, "exec")(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module

_BOOTSTRAP_TARGET = _bootstrap_target()
_qsol_canonical = _load_verified_source_module("qsol_canonical", _BOOTSTRAP_TARGET)
moriarty = _load_verified_source_module("run_moriarty", _BOOTSTRAP_TARGET)
serialize = _qsol_canonical.serialize

EXPECTED_FAMILIES = set(moriarty.EXPECTED_FAMILIES)
EXPECTED_PROBES = {
    "constitution": ("tools/validate_constitution.py",),
    "phase0": ("tools/validate_phase0_gate.py",),
    "phase1": ("tools/validate_phase1_gate.py",),
    "phase2": ("tools/validate_phase2_gate.py",),
    "phase3": ("tools/validate_phase3_gate.py",),
    "phase4": ("tools/validate_phase4_gate.py",),
    "phase5a": ("tools/validate_phase5a_gate.py",),
    "phase5": ("tools/validate_phase5_gate.py",),
    "phase5c": ("tools/validate_phase5c_gate.py",),
    "phase6": ("tools/validate_phase6_gate.py",),
    "phase7": ("tools/validate_phase7_gate.py",),
    "phase8": ("tools/validate_phase8_gate.py",),
    "rust_all": ("test", "--all-targets", "--frozen"),
}
HARD_FALSE_CLAIMS = {
    "oracle_holodeck_synthetic_admission",
    "host_level_sandbox",
    "production_networking",
    "remote_execution",
    "interoperable_federation",
}
TARGET_RE = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load(path: str) -> dict[str, Any]:
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    require(isinstance(value, dict), f"{path}: top-level object required")
    return value


def canonical_ref(value: Any) -> str:
    return "sha256:" + hashlib.sha256(serialize(value).encode("utf-8")).hexdigest()


def git_head() -> str:
    completed = moriarty.git("rev-parse", "HEAD")
    require(completed.returncode == 0, "Phase 9 cannot resolve Git HEAD")
    head = completed.stdout.decode("ascii", errors="strict").strip()
    require(bool(TARGET_RE.fullmatch(head)), "Phase 9 Git HEAD is not a lowercase 40-hex commit")
    return head


PHASE9_CLAIM_RULE = "Phase 9 adds adversarial graduation assurance, not a new runtime or protocol capability. The Phase 8 capability map remains unchanged. A MORIARTY report is evidence about execution of the exact reviewed regression surface, not a security proof, authority grant, production-deployment certification, or proof that no counterexample exists."


def _validate_claim_document(previous: dict[str, Any], current: dict[str, Any]) -> None:
    expected_top = {
        "document_type", "schema_version", "protocol", "wire_protocol", "phase", "gate_id",
        "gate_status", "historical_baseline", "runtime_override_allowed", "claim_surface_changed",
        "capabilities", "assurance", "claim_rule", "promotion_requirements",
    }
    expected_assurance = {
        "moriarty_protocol", "provider_neutral", "exact_commit_binding",
        "reproducible_counterexample_contract", "accepted_counterexample_registry",
        "fixed_repository_probe_map", "cross_phase_regression_sweep",
        "isolated_source_export", "committed_cargo_lock", "opened_executable_binding",
        "cache_only_cargo_home", "exclusive_external_report_output",
        "remediation_transition_verified", "network_syscalls_denied", "probe_proc_read_isolated",
        "per_probe_cargo_home", "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",
        "production_credentials_used", "production_targets_used", "constitutional_bypass_used",
        "report_is_security_proof", "no_counterexample_found_means_none_exist", "authority_effect",
    }
    require(set(current) == expected_top, "Phase 9 claim manifest field set is not closed")
    require(current.get("document_type") == "qsol-fed-phase9-moriarty-claims", "Phase 9 claim id drift")
    require(current.get("gate_id") == "qsol-fed-phase9-moriarty-gate/1", "Phase 9 gate id drift")
    require(current.get("gate_status") == "enforced", "Phase 9 gate not enforced")
    require(current.get("historical_baseline") == "claims/phase8.json", "Phase 9 claim baseline drift")
    require(current.get("runtime_override_allowed") is False, "Phase 9 claims became runtime configurable")
    require(current.get("claim_surface_changed") is False, "MORIARTY incorrectly promoted runtime capability surface")
    require(current.get("capabilities") == previous.get("capabilities"), "Phase 9 changed the Phase 8 capability map")
    for key in HARD_FALSE_CLAIMS:
        require(current["capabilities"].get(key) is False, f"Phase 9 overclaim enabled: {key}")
    assurance = current.get("assurance")
    require(isinstance(assurance, dict) and set(assurance) == expected_assurance, "Phase 9 assurance field set is not closed")
    for key in (
        "provider_neutral", "exact_commit_binding", "reproducible_counterexample_contract",
        "accepted_counterexample_registry", "fixed_repository_probe_map", "cross_phase_regression_sweep",
        "isolated_source_export", "committed_cargo_lock", "opened_executable_binding",
        "cache_only_cargo_home", "exclusive_external_report_output", "remediation_transition_verified",
        "network_syscalls_denied", "probe_proc_read_isolated", "per_probe_cargo_home",
        "verified_cargo_registry_archives", "staged_rust_toolchain_runtime",
    ):
        require(assurance.get(key) is True, f"Phase 9 assurance drift: {key}")
    for key in (
        "production_credentials_used", "production_targets_used", "constitutional_bypass_used",
        "report_is_security_proof", "no_counterexample_found_means_none_exist",
    ):
        require(assurance.get(key) is False, f"Phase 9 assurance overclaim/bypass: {key}")
    require(assurance.get("authority_effect") == "none", "MORIARTY assurance gained authority")
    require(current.get("claim_rule") == PHASE9_CLAIM_RULE, "Phase 9 claim rule drift")
    require(
        current.get("promotion_requirements") == previous.get("promotion_requirements"),
        "Phase 9 promotion requirements changed the preserved Phase 8 requirements",
    )


def validate_claims() -> None:
    previous = load("claims/phase8.json")
    current = load("claims/phase9.json")
    _validate_claim_document(previous, current)
    malicious = copy.deepcopy(current)
    malicious["assurance"]["security_proof"] = True
    _expect_reject(lambda: _validate_claim_document(previous, malicious), "undeclared assurance claim")
    promotion_drift = copy.deepcopy(current)
    promotion_drift["promotion_requirements"]["remote_execution"] = "already admitted"
    _expect_reject(lambda: _validate_claim_document(previous, promotion_drift), "promotion requirement value drift")
    claim_drift = copy.deepcopy(current)
    claim_drift["claim_rule"] = "Phase 9 grants authority"
    _expect_reject(lambda: _validate_claim_document(previous, claim_drift), "claim rule drift")


def validate_contract() -> None:
    state = load("state/phase9.json")
    expected_top = {
        "document_type", "schema_version", "protocol", "wire_protocol", "moriarty_protocol", "purpose",
        "feature_dependency", "claim_surface_changed", "capability_baseline", "assurance_manifest",
        "attack_corpus", "accepted_counterexample_registry", "counterexample_schema", "report_schema",
        "attack_corpus_schema", "reference_runner", "gate_validator", "operator_model",
        "execution_boundary", "attack_families", "probe_policy", "counterexample_policy",
        "report_policy", "phase9_gate",
    }
    require(set(state) == expected_top, "Phase 9 contract top-level field set is not closed")
    require(state.get("document_type") == "qsol-fed-phase9-moriarty-contract", "Phase 9 state id drift")
    require(state.get("moriarty_protocol") == "MORIARTY/1", "MORIARTY protocol drift")
    require(state.get("feature_dependency") is False, "MORIARTY became a feature dependency")
    require(state.get("claim_surface_changed") is False, "MORIARTY changed capability claim surface")
    require(state.get("capability_baseline") == "claims/phase8.json", "MORIARTY capability baseline drift")
    require(set(state.get("attack_families", [])) == EXPECTED_FAMILIES, "MORIARTY attack-family set drift")

    operator = state["operator_model"]
    require(set(operator) == {
        "provider_neutral", "reference_operator_may_be_codex", "operator_output_is_authority",
        "operator_output_is_security_proof", "operator_may_supply_commands",
        "operator_may_supply_repository_targets", "operator_may_supply_network_targets",
        "operator_may_supply_credentials", "operator_may_disable_constitution",
        "candidate_findings_require_local_reproduction",
    }, "MORIARTY operator field set is not closed")
    for key in ("provider_neutral", "reference_operator_may_be_codex", "candidate_findings_require_local_reproduction"):
        require(operator[key] is True, f"MORIARTY operator rule drift: {key}")
    for key in (
        "operator_output_is_authority", "operator_output_is_security_proof", "operator_may_supply_commands",
        "operator_may_supply_repository_targets", "operator_may_supply_network_targets",
        "operator_may_supply_credentials", "operator_may_disable_constitution",
    ):
        require(operator[key] is False, f"MORIARTY operator boundary weakened: {key}")

    execution = state["execution_boundary"]
    expected_execution_fields = {'fixed_repository_probe_map', 'production_credentials_allowed', 'probe_output_bounded', 'production_targets_allowed', 'target_is_exact_git_commit', 'report_output_external_private_exclusive', 'semantic_payload_execution_allowed', 'untracked_inputs_excluded', 'tracked_worktree_must_be_clean', 'cargo_target_outside_source', 'authority_effect', 'probe_process_group_isolated', 'arbitrary_command_execution', 'outbound_network_targeting_allowed', 'checked_out_head_must_equal_target', 'cargo_home_cache_only', 'exact_source_export', 'constitutional_bypass_allowed', 'target_commit_format', 'shell_execution', 'source_export_read_only', 'tool_exec_via_open_descriptor', 'probe_environment_allowlisted', 'probe_network_syscalls_denied', 'probe_proc_read_isolated', 'rust_toolchain_runtime_staged'}
    require(set(execution) == expected_execution_fields, "MORIARTY execution boundary field set is not closed")
    required_true = {
        "target_is_exact_git_commit", "checked_out_head_must_equal_target", "tracked_worktree_must_be_clean",
        "fixed_repository_probe_map", "probe_environment_allowlisted", "probe_process_group_isolated",
        "probe_output_bounded", "exact_source_export", "source_export_read_only",
        "untracked_inputs_excluded", "tool_exec_via_open_descriptor", "cargo_home_cache_only",
        "cargo_target_outside_source", "report_output_external_private_exclusive",
        "probe_network_syscalls_denied", "probe_proc_read_isolated", "rust_toolchain_runtime_staged",
    }
    for key in required_true:
        require(execution[key] is True, f"MORIARTY exact/fixed execution boundary drift: {key}")
    for key in (
        "shell_execution", "arbitrary_command_execution", "production_credentials_allowed",
        "production_targets_allowed", "outbound_network_targeting_allowed",
        "constitutional_bypass_allowed", "semantic_payload_execution_allowed",
    ):
        require(execution[key] is False, f"MORIARTY execution boundary weakened: {key}")
    require(execution["authority_effect"] == "none", "MORIARTY execution gained authority")

    probes = state["probe_policy"]
    expected_probe_fields = {'probe_ids_are_source_allowlisted', 'failure_output_is_recorded_by_digest_and_size_only', 'probe_output_semantic_content_in_report', 'historical_phase_gates_are_regressions', 'rust_all_targets_is_regression', 'shared_probe_failure_implies_specific_attack', 'cargo_mode', 'cargo_lockfile_committed', 'maximum_output_bytes_per_stream', 'timeout_seconds', 'cargo_network_access', 'constitutional_gate_is_regression', 'unknown_probe_id', 'cargo_user_config_inherited', 'cargo_home_per_probe', 'cargo_registry_archives_verified_against_lock'}
    require(set(probes) == expected_probe_fields, "MORIARTY probe policy field set is not closed")
    require(probes["cargo_network_access"] is False, "MORIARTY Cargo probe regained network access")
    require(probes["cargo_mode"] == "frozen", "MORIARTY Cargo mode is not frozen")
    require(probes["cargo_lockfile_committed"] is True, "MORIARTY Cargo lockfile is not committed")
    require(probes["cargo_user_config_inherited"] is False, "MORIARTY Cargo user config became ambient")
    require(probes["cargo_home_per_probe"] is True, "MORIARTY Cargo home is shared across probes")
    require(probes["cargo_registry_archives_verified_against_lock"] is True, "MORIARTY Cargo archives are not lock-authenticated")
    require(probes["shared_probe_failure_implies_specific_attack"] is False, "shared probe can fabricate specific counterexample")
    require(probes["maximum_output_bytes_per_stream"] == moriarty.MAX_PROBE_OUTPUT_BYTES, "MORIARTY output bound drift")

    counterexamples = state["counterexample_policy"]
    expected_counterexample_fields = {'resolved_finding_remains_in_registry', 'accepted_findings_bind_to_attack_corpus', 'finding_may_create_authority', 'candidate_can_enter_accepted_registry_without_local_reproduction', 'accepted_findings_require_observed_local_failure', 'resolution_commit_is_fix_commit', 'external_findings_are_candidates_only', 'accepted_findings_name_attack_family', 'finding_may_contain_production_credentials', 'accepted_findings_name_fixed_regression_probes', 'resolved_finding_becomes_regression', 'regression_probes_must_be_subset_of_attack_probes', 'accepted_findings_name_boundary_ids', 'resolved_requires_fail_before_pass_after', 'accepted_findings_name_owning_phases', 'counterexample_id_stable_through_resolution', 'resolution_commit_descends_from_finding_target', 'resolution_commit_is_in_reviewed_history', 'resolution_commit_must_exist', 'unresolved_accepted_finding_blocks_graduation', 'maximum_accepted_counterexamples', 'resolved_failure_metadata_must_reproduce', 'accepted_findings_are_reproducible', 'accepted_schema', 'finding_may_target_production_system', 'unresolved_regressions_execute_before_graduation_decision'}
    require(set(counterexamples) == expected_counterexample_fields, "MORIARTY counterexample policy field set is not closed")
    for key in (
        "accepted_findings_are_reproducible", "accepted_findings_require_observed_local_failure",
        "accepted_findings_bind_to_attack_corpus", "accepted_findings_name_attack_family",
        "accepted_findings_name_owning_phases", "accepted_findings_name_boundary_ids",
        "accepted_findings_name_fixed_regression_probes", "regression_probes_must_be_subset_of_attack_probes",
        "external_findings_are_candidates_only", "unresolved_accepted_finding_blocks_graduation",
        "unresolved_regressions_execute_before_graduation_decision", "resolved_finding_remains_in_registry",
        "resolved_finding_becomes_regression", "resolution_commit_is_fix_commit", "resolution_commit_must_exist",
        "resolution_commit_descends_from_finding_target", "resolution_commit_is_in_reviewed_history",
        "counterexample_id_stable_through_resolution", "resolved_requires_fail_before_pass_after",
        "resolved_failure_metadata_must_reproduce",
    ):
        require(counterexamples[key] is True, f"MORIARTY counterexample policy drift: {key}")
    for key in (
        "candidate_can_enter_accepted_registry_without_local_reproduction", "finding_may_create_authority",
        "finding_may_contain_production_credentials", "finding_may_target_production_system",
    ):
        require(counterexamples[key] is False, f"MORIARTY counterexample boundary weakened: {key}")
    require(counterexamples["maximum_accepted_counterexamples"] == moriarty.MAX_ACCEPTED_COUNTEREXAMPLES, "MORIARTY registry count bound drift")

    report = state["report_policy"]
    expected_report_fields = {'report_persisted_for_ci_artifact_upload', 'records_probe_results_without_raw_output', 'graduated_requires_all_probes_green', 'records_generated_counterexamples', 'schema', 'security_proof', 'maximum_canonical_bytes', 'no_counterexample_found_implies_none_exist', 'maximum_counterexamples', 'generated_report_nested_schema_validated', 'authority_effect', 'binds_canonical_attack_corpus_identity', 'binds_exact_target_commit', 'failed_report_metadata_exposed_before_exit', 'graduated_requires_zero_unresolved_counterexamples', 'probe_failure_kind_persisted', 'probe_output_truncation_persisted'}
    require(set(report) == expected_report_fields, "MORIARTY report policy field set is not closed")
    for key in (
        "binds_exact_target_commit", "binds_canonical_attack_corpus_identity",
        "records_probe_results_without_raw_output", "records_generated_counterexamples",
        "graduated_requires_zero_unresolved_counterexamples", "graduated_requires_all_probes_green",
        "failed_report_metadata_exposed_before_exit", "generated_report_nested_schema_validated",
        "report_persisted_for_ci_artifact_upload", "probe_failure_kind_persisted",
        "probe_output_truncation_persisted",
    ):
        require(report[key] is True, f"MORIARTY report policy drift: {key}")
    require(report["maximum_canonical_bytes"] == moriarty.MAX_REPORT_BYTES, "MORIARTY report byte bound drift")
    require(report["security_proof"] is False, "MORIARTY report overclaimed security proof")
    require(report["no_counterexample_found_implies_none_exist"] is False, "MORIARTY report overclaimed exhaustiveness")
    require(report["authority_effect"] == "none", "MORIARTY report gained authority")


def _require_closed_schema_fields(schema: dict[str, Any], expected: set[str], name: str) -> None:
    props = schema.get("properties")
    required = schema.get("required")
    require(isinstance(props, dict) and set(props) == expected, f"MORIARTY {name} schema property set drift")
    require(isinstance(required, list) and set(required) == expected and len(required) == len(expected), f"MORIARTY {name} schema required set drift")
    require(schema.get("additionalProperties") is False, f"MORIARTY {name} schema must remain closed")


def validate_schemas_and_fixtures() -> None:
    corpus_schema = load("schemas/moriarty-attack-corpus-v1.schema.json")
    counterexample_schema = load("schemas/moriarty-counterexample-v1.schema.json")
    report_schema = load("schemas/moriarty-report-v1.schema.json")

    corpus_fields = {
        "schema", "protocol", "attacks", "production_credentials_allowed",
        "production_targets_allowed", "constitutional_bypass_allowed", "authority_effect",
    }
    attack_fields = {"id", "family", "owner_phases", "boundary_ids", "probe_ids"}
    counterexample_fields = {
        "schema", "counterexample_id", "target_commit", "attack_id", "family", "owner_phases",
        "boundary_ids", "regression_probe_ids", "failure_kind", "observed_exit_code",
        "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes", "status",
        "resolution_commit", "production_credentials_used", "production_targets_used",
        "constitutional_bypass_used", "authority_effect",
    }
    report_fields = {
        "schema", "protocol", "target_commit", "corpus_ref", "operator_profile", "family_count",
        "executed_probe_count", "probe_results", "remediation_replays", "counterexamples", "unresolved_counterexamples",
        "graduated", "production_credentials_used", "production_targets_used",
        "constitutional_bypass_used", "security_proof", "no_counterexample_found_implies_none_exist",
        "authority_effect",
    }
    probe_result_fields = {
        "probe_id", "ok", "exit_code", "failure_kind", "stdout_sha256", "stderr_sha256",
        "stdout_bytes", "stderr_bytes", "stdout_truncated", "stderr_truncated",
    }
    remediation_replay_fields = {
        "counterexample_id", "status", "probe_id", "ok", "target_reproduced",
        "resolution_green", "failure_kind", "failure_result",
    }
    _require_closed_schema_fields(corpus_schema, corpus_fields, "attack corpus")
    _require_closed_schema_fields(corpus_schema["properties"]["attacks"]["items"], attack_fields, "attack record")
    _require_closed_schema_fields(counterexample_schema, counterexample_fields, "counterexample")
    _require_closed_schema_fields(report_schema, report_fields, "report")
    _require_closed_schema_fields(report_schema["properties"]["probe_results"]["items"], probe_result_fields, "probe result")
    replay_item_schema = report_schema["properties"]["remediation_replays"]["items"]
    _require_closed_schema_fields(replay_item_schema, remediation_replay_fields, "remediation replay")
    _require_closed_schema_fields(replay_item_schema["properties"]["failure_result"], probe_result_fields, "remediation failure result")

    corpus_props = corpus_schema["properties"]
    for key in ("production_credentials_allowed", "production_targets_allowed", "constitutional_bypass_allowed"):
        require(corpus_props[key].get("const") is False, f"MORIARTY corpus schema boundary drift: {key}")
    require(corpus_props["authority_effect"].get("const") == "none", "MORIARTY corpus schema gained authority")

    counter_props = counterexample_schema["properties"]
    require(set(counter_props["failure_kind"].get("enum", [])) == {"exit_nonzero", "timeout", "tool_error"}, "MORIARTY accepted failure-kind set drift")
    for key in ("production_credentials_used", "production_targets_used", "constitutional_bypass_used"):
        require(counter_props[key].get("const") is False, f"MORIARTY counterexample schema boundary drift: {key}")
    require(counter_props["authority_effect"].get("const") == "none", "MORIARTY counterexample schema gained authority")
    require(counter_props["regression_probe_ids"].get("maxItems") == 1, "MORIARTY counterexample must bind one observed regression probe")
    require(counter_props["stdout_bytes"].get("maximum") == moriarty.MAX_PROBE_OUTPUT_BYTES, "counterexample stdout bound schema drift")
    require(counter_props["stderr_bytes"].get("maximum") == moriarty.MAX_PROBE_OUTPUT_BYTES, "counterexample stderr bound schema drift")
    all_of = counterexample_schema.get("allOf")
    require(isinstance(all_of, list) and len(all_of) == 2, "MORIARTY counterexample conditional set drift")
    require(set(all_of[0].get("if", {}).get("required", [])) == {"failure_kind"}, "counterexample failure conditional drift")
    require(set(all_of[1].get("if", {}).get("required", [])) == {"status"}, "counterexample status conditional drift")
    require((ROOT / "Cargo.lock").is_file(), "MORIARTY committed Cargo.lock missing")

    report_props = report_schema["properties"]
    require(report_props["operator_profile"].get("const") == "provider-neutral-fixed-probe/1", "MORIARTY report operator profile drift")
    require(report_props["family_count"].get("const") == 15, "MORIARTY report family count drift")
    require(report_props["counterexamples"].get("maxItems") == moriarty.MAX_REPORT_COUNTEREXAMPLES, "MORIARTY report counterexample bound drift")
    require(report_props["remediation_replays"].get("maxItems") == moriarty.MAX_ACCEPTED_COUNTEREXAMPLES, "MORIARTY remediation replay count bound drift")
    replay_props = report_props["remediation_replays"]["items"]["properties"]
    require(set(replay_props["failure_kind"].get("enum", [])) == {None, "target_failure_not_reproduced", "resolution_probe_not_green", "replay_setup_error"}, "MORIARTY remediation failure-kind schema drift")
    require(report_props["unresolved_counterexamples"].get("maximum") == moriarty.MAX_REPORT_COUNTEREXAMPLES, "MORIARTY unresolved count schema drift")
    result_props = report_props["probe_results"]["items"]["properties"]
    require(result_props["stdout_bytes"].get("maximum") == moriarty.MAX_PROBE_OUTPUT_BYTES, "report stdout bound schema drift")
    require(result_props["stderr_bytes"].get("maximum") == moriarty.MAX_PROBE_OUTPUT_BYTES, "report stderr bound schema drift")
    require(set(result_props["failure_kind"].get("enum", [])) == {None, "exit_nonzero", "timeout", "tool_error"}, "report failure-kind schema drift")
    for key in (
        "production_credentials_used", "production_targets_used", "constitutional_bypass_used",
        "security_proof", "no_counterexample_found_implies_none_exist",
    ):
        require(report_props[key].get("const") is False, f"MORIARTY report schema overclaim/bypass: {key}")
    require(report_props["authority_effect"].get("const") == "none", "MORIARTY report schema gained authority")
    require(moriarty.MAX_REPORT_BYTES == 512 * 1024, "MORIARTY report byte ceiling drift")
    max_boundary_ids = [f"b{index:02d}" + "x" * 125 for index in range(moriarty.MAX_BOUNDARY_IDS)]
    max_counterexample = {
        "schema": moriarty.COUNTEREXAMPLE_SCHEMA, "counterexample_id": "sha256:" + "f" * 64,
        "target_commit": "f" * 40, "attack_id": "MOR-999", "family": max(moriarty.EXPECTED_FAMILIES, key=len),
        "owner_phases": list(sorted(moriarty.ALLOWED_OWNER_PHASES)), "boundary_ids": max_boundary_ids,
        "regression_probe_ids": ["p" * 64], "failure_kind": "exit_nonzero", "observed_exit_code": -2147483648,
        "stdout_sha256": "sha256:" + "f" * 64, "stderr_sha256": "sha256:" + "f" * 64,
        "stdout_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES, "stderr_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES,
        "status": "resolved", "resolution_commit": "e" * 40, "production_credentials_used": False,
        "production_targets_used": False, "constitutional_bypass_used": False, "authority_effect": "none",
    }
    max_result = {
        "probe_id": "p" * 64, "ok": False, "exit_code": -2147483648, "failure_kind": "exit_nonzero",
        "stdout_sha256": "sha256:" + "f" * 64, "stderr_sha256": "sha256:" + "f" * 64,
        "stdout_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES, "stderr_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES,
        "stdout_truncated": True, "stderr_truncated": True,
    }
    max_replay = {
        "counterexample_id": "sha256:" + "f" * 64, "status": "resolved", "probe_id": "p" * 64,
        "ok": False, "target_reproduced": False, "resolution_green": False,
        "failure_kind": "target_failure_not_reproduced", "failure_result": max_result,
    }
    max_report = {
        "schema": moriarty.REPORT_SCHEMA, "protocol": moriarty.PROTOCOL, "target_commit": "f" * 40,
        "corpus_ref": "sha256:" + "f" * 64, "operator_profile": moriarty.OPERATOR_PROFILE,
        "family_count": 15, "executed_probe_count": len(EXPECTED_PROBES),
        "probe_results": [max_result] * len(EXPECTED_PROBES),
        "remediation_replays": [max_replay] * moriarty.MAX_ACCEPTED_COUNTEREXAMPLES,
        "counterexamples": [max_counterexample] * moriarty.MAX_REPORT_COUNTEREXAMPLES,
        "unresolved_counterexamples": moriarty.MAX_REPORT_COUNTEREXAMPLES, "graduated": False,
        "production_credentials_used": False, "production_targets_used": False,
        "constitutional_bypass_used": False, "security_proof": False,
        "no_counterexample_found_implies_none_exist": False, "authority_effect": "none",
    }
    require(len(serialize(max_report).encode("utf-8")) <= moriarty.MAX_REPORT_BYTES, "MORIARTY schema-admitted worst-case report exceeds byte ceiling")

    corpus = load("fixtures/phase9/attack-corpus.json")
    attacks = moriarty.validate_attack_corpus(corpus)
    corpus_extra = copy.deepcopy(corpus)
    corpus_extra["command"] = "forbidden"
    _expect_reject(lambda: moriarty.validate_attack_corpus(corpus_extra), "undeclared attack-corpus field")
    attack_extra = copy.deepcopy(corpus)
    attack_extra["attacks"][0]["credential"] = "forbidden"
    _expect_reject(lambda: moriarty.validate_attack_corpus(attack_extra), "undeclared attack-record field")
    bad_owner = copy.deepcopy(corpus)
    bad_owner["attacks"][0]["owner_phases"] = ["https://evil.example"]
    _expect_reject(lambda: moriarty.validate_attack_corpus(bad_owner), "owner phase outside closed enum")
    owner_schema = corpus_schema["properties"]["attacks"]["items"]["properties"]["owner_phases"]
    require(set(owner_schema["items"].get("enum", [])) == moriarty.ALLOWED_OWNER_PHASES, "MORIARTY owner phase schema/runner enum drift")
    require(owner_schema.get("maxItems") == moriarty.MAX_OWNER_PHASES, "MORIARTY owner phase count schema drift")
    require({item["id"] for item in attacks} == {f"MOR-{index:03d}" for index in range(1, 16)}, "MORIARTY attack id set drift")
    require({item["family"] for item in attacks} == EXPECTED_FAMILIES, "MORIARTY corpus family set drift")

    registry = load("fixtures/phase9/accepted-counterexamples.json")
    values = registry.get("counterexamples")
    require(isinstance(values, list) and len(values) <= moriarty.MAX_ACCEPTED_COUNTEREXAMPLES, "MORIARTY registry counterexample count drift")
    require(all(item.get("failure_kind") != "accepted_external" for item in values if isinstance(item, dict)), "accepted_external entered accepted counterexample registry")
    unresolved = sum(1 for item in values if isinstance(item, dict) and item.get("status") == "unresolved")
    require(registry.get("unresolved_counterexamples") == unresolved, "MORIARTY registry unresolved count drift")
    registry_extra = copy.deepcopy(registry)
    registry_extra["member_local_authority"] = "root"
    _expect_reject(lambda: moriarty.validate_registry(registry_extra, attacks, git_head()), "undeclared accepted-registry wrapper field")


def validate_probe_map() -> None:
    require(set(moriarty.PROBES) == set(EXPECTED_PROBES), "MORIARTY fixed probe id set drift")
    require(set(moriarty.PROBE_EXECUTABLES) == set(EXPECTED_PROBES), "MORIARTY pinned probe executable set drift")
    for probe_id, tail in EXPECTED_PROBES.items():
        argv = moriarty.PROBES[probe_id]
        trusted = moriarty.PROBE_EXECUTABLES[probe_id]
        require(isinstance(argv, tuple) and len(argv) == len(tail) + 1, f"MORIARTY probe argv arity drift: {probe_id}")
        require(argv[0] == trusted.invocation, f"MORIARTY probe argv0/pinned executable mismatch: {probe_id}")
        require(Path(trusted.executable).is_absolute(), f"MORIARTY resolved probe executable not absolute: {probe_id}")
        require(ROOT not in Path(trusted.executable).parents and Path(trusted.executable) != ROOT, f"MORIARTY resolved probe executable came from repository: {probe_id}")
        require(tuple(argv[1:]) == tail, f"MORIARTY fixed probe argv drift: {probe_id}")
        require(moriarty.trusted_executable_matches(trusted), f"MORIARTY pinned executable revalidation failed: {probe_id}")
        if probe_id == "rust_all":
            require(trusted == moriarty.CARGO_TRUSTED, "MORIARTY Rust probe executable drift")
            require(moriarty.trusted_executable_matches(moriarty.RUSTC_TRUSTED), "MORIARTY Rustc executable revalidation failed")
        else:
            require(trusted == moriarty.PYTHON_TRUSTED, f"MORIARTY Python probe executable drift: {probe_id}")

    if moriarty.RUSTUP_DISCOVERY_USED:
        require(moriarty.RUSTUP_TRUSTED is not None, "MORIARTY Rustup discovery flag without Rustup")
        require(isinstance(moriarty.RUST_TOOLCHAIN_ID, str) and moriarty.RUST_TOOLCHAIN_ID, "MORIARTY concrete Rust toolchain id missing")
        require(not moriarty._same_trusted_inode(moriarty.CARGO_TRUSTED, moriarty.RUSTUP_TRUSTED), "MORIARTY Cargo still points at Rustup shim")
        require(not moriarty._same_trusted_inode(moriarty.RUSTC_TRUSTED, moriarty.RUSTUP_TRUSTED), "MORIARTY rustc still points at Rustup shim")
        require(Path(moriarty.CARGO_TRUSTED.executable).parent == Path(moriarty.RUSTC_TRUSTED.executable).parent, "MORIARTY concrete Cargo/rustc toolchain mismatch")
    git_env = moriarty._git_env()
    require(git_env.get("GIT_NO_REPLACE_OBJECTS") == "1", "MORIARTY Git replacement objects are not disabled")
    require(git_env.get("GIT_CONFIG_KEY_0") == "core.fsmonitor" and git_env.get("GIT_CONFIG_VALUE_0") == "false", "MORIARTY Git fsmonitor execution is not neutralized")
    require(git_env.get("GIT_CONFIG_KEY_1") == "core.hooksPath" and git_env.get("GIT_CONFIG_VALUE_1") == "/dev/null", "MORIARTY Git hooks path is not neutralized")
    require(Path("/usr") in Path(moriarty.PYTHON_TRUSTED.executable).resolve(strict=True).parents, "MORIARTY Python runtime is not system-prefixed")
    require(moriarty._index_flags_output_clean(b"H tools/run_moriarty.py\n"), "normal Git index flag parser failed")
    require(not moriarty._index_flags_output_clean(b"h tools/run_moriarty.py\n"), "assume-unchanged index flag was accepted")
    require(not moriarty._index_flags_output_clean(b"S tools/run_moriarty.py\n"), "skip-worktree index flag was accepted")
    digest = hashlib.sha256()
    bounded_count, overflow = moriarty.bounded_output_update(digest, moriarty.MAX_PROBE_OUTPUT_BYTES - 1, b"AB")
    require(bounded_count == moriarty.MAX_PROBE_OUTPUT_BYTES and overflow is True, "MORIARTY output overflow bound regression failed")
    norm_root = Path("/tmp/private-run")
    normalized_paths = moriarty._normalize_probe_output(
        b"/tmp/private-run/probe-12-rust_all-src /tmp/private-run/target-12-rust_all /tmp/private-run/home-12-rust_all /tmp/private-run/cargo-home-probe-12-rust_all /tmp/private-run/tmp-target-12-rust_all /tmp/private-run/other",
        probe_id="rust_all",
        source_root=norm_root / "probe-12-rust_all-src",
        target_dir=norm_root / "target-12-rust_all",
        home=norm_root / "home-12-rust_all",
        cargo_home=norm_root / "cargo-home-probe-12-rust_all",
        temp_dir=norm_root / "tmp-target-12-rust_all",
        workspace_root=norm_root,
    )
    require(
        normalized_paths == b"<SOURCE> <TARGET> <HOME> <CARGO_HOME> <TMP> <WORK>/other",
        "MORIARTY complete per-probe output normalization regression failed",
    )
    rust_a = moriarty._normalize_probe_output(
        b"Finished `test` profile [unoptimized + debuginfo] target(s) in 0.63s\ntest result: FAILED. 1 failed; finished in 0.02s\nthread 'main' (pid=12345)",
        probe_id="rust_all", source_root=norm_root / "src", target_dir=norm_root / "target",
        home=norm_root / "home", cargo_home=norm_root / "cargo", temp_dir=norm_root / "tmp", workspace_root=norm_root,
    )
    rust_b = moriarty._normalize_probe_output(
        b"Finished `test` profile [unoptimized + debuginfo] target(s) in 1.18s\ntest result: FAILED. 1 failed; finished in 0.91s\nthread 'main' (pid=54321)",
        probe_id="rust_all", source_root=norm_root / "src", target_dir=norm_root / "target",
        home=norm_root / "home", cargo_home=norm_root / "cargo", temp_dir=norm_root / "tmp", workspace_root=norm_root,
    )
    require(rust_a == rust_b, "MORIARTY Rust runtime-field normalization regression failed")
    require(0 < moriarty.MAX_GIT_TREE_DEPTH <= 128, "MORIARTY Git tree depth bound invalid")
    require(0 < moriarty.MAX_GIT_TREE_ENTRIES <= 65536, "MORIARTY Git tree entry bound invalid")
    require(0 < moriarty.MAX_GIT_TREE_METADATA_BYTES <= moriarty.MAX_GIT_ARCHIVE_BYTES, "MORIARTY Git tree metadata bound invalid")
    require(0 < moriarty.MAX_GIT_PATH_BYTES <= 4096, "MORIARTY Git path bound invalid")
    system_reads = moriarty._system_read_paths()
    require(Path("/etc") not in system_reads, "MORIARTY recursive /etc read access reintroduced")
    require(all(path.is_file() and not path.is_dir() for path in system_reads), "MORIARTY system read allowlist contains a directory")

    bad_exit = {
        "schema": moriarty.COUNTEREXAMPLE_SCHEMA,
        "counterexample_id": "sha256:" + "0" * 64,
        "target_commit": git_head(),
        "attack_id": "MOR-001",
        "family": next(iter(moriarty.EXPECTED_FAMILIES)),
        "owner_phases": ["0"],
        "boundary_ids": ["phase0"],
        "regression_probe_ids": ["phase0"],
        "failure_kind": "exit_nonzero",
        "observed_exit_code": 2**31,
        "stdout_sha256": "sha256:" + "0" * 64,
        "stderr_sha256": "sha256:" + "0" * 64,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "status": "unresolved",
        "resolution_commit": None,
        "production_credentials_used": False,
        "production_targets_used": False,
        "constitutional_bypass_used": False,
        "authority_effect": "none",
    }
    bad_exit["counterexample_id"] = moriarty.canonical_ref(moriarty.counterexample_identity_projection(bad_exit))
    _expect_reject(lambda: moriarty.validate_counterexample_shape(bad_exit), "counterexample signed-32-bit exit bound")

    stale = moriarty.TrustedExecutable(
        name=moriarty.PYTHON_TRUSTED.name,
        invocation=moriarty.PYTHON_TRUSTED.invocation,
        executable=moriarty.PYTHON_TRUSTED.executable,
        device=moriarty.PYTHON_TRUSTED.device,
        inode=moriarty.PYTHON_TRUSTED.inode + 1,
        size=moriarty.PYTHON_TRUSTED.size,
        mtime_ns=moriarty.PYTHON_TRUSTED.mtime_ns,
        mode=moriarty.PYTHON_TRUSTED.mode,
        fd=moriarty.PYTHON_TRUSTED.fd,
    )
    require(not moriarty.trusted_executable_matches(stale), "MORIARTY executable identity negative regression failed")


def validate_runner_source() -> None:
    source = (ROOT / "tools/run_moriarty.py").read_text(encoding="utf-8")
    validator_bootstrap = "\n".join((ROOT / "tools/validate_phase9_gate.py").read_text(encoding="utf-8").splitlines()[:180])
    require("sys.path.insert" not in validator_bootstrap, "Phase 9 validator bootstrap reintroduced checkout import search")
    require("_bootstrap_verified_blob" in validator_bootstrap and "compile(expected" in validator_bootstrap and "SourceFileLoader" not in validator_bootstrap, "Phase 9 validator bootstrap does not execute verified target bytes directly")
    for marker in (
        "provider-neutral-fixed-probe/1", "moriarty-counterexample/1", "moriarty-report/1",
        "PROBES: dict[str, tuple[str, ...]]", "PROBE_EXECUTABLES", "TrustedExecutable",
        "proc_fd_path(trusted.fd)", "pass_fds=pass_fds", "create_exact_export",
        "create_isolated_cargo_home", "create_verified_cargo_template", "probe_isolation_preexec",
        "stage_rust_toolchain_runtime", "git_archive_bytes", "trusted_capture_bounded", "index_flags_clean",
        "_verified_commit_files", "_git_object_id", "_normalize_probe_output", "stdin=subprocess.DEVNULL",
        "write_report_exclusive", "--frozen", "candidate",
        "GIT_NO_REPLACE_OBJECTS", "RUSTUP_DISCOVERY_USED", "_rustup_which", "bounded_output_update",
        "enable_child_subreaper", "_kill_probe_tree", "post_exit_deadline", "termination_deadline",
        "tracked_tree_clean", "start_new_session=True", "selectors.DefaultSelector",
        "MAX_PROBE_OUTPUT_BYTES", "git_commit_exists", "git_is_ancestor",
        "moriarty_counterexample_attack_not_in_corpus", "moriarty_resolution_commit_missing",
        "counterexample_identity_projection", "verify_accepted_counterexamples",
        "production_credentials_used", "production_targets_used", "constitutional_bypass_used",
        "security_proof", "no_counterexample_found_implies_none_exist", "stdout_truncated", "stderr_truncated",
        "_bootstrap_verified_blob", "compile(expected", "ALLOWED_OWNER_PHASES", "_RUNTIME_NORMALIZATIONS", "close_fds=True",
    ):
        require(marker in source, f"MORIARTY runner marker missing: {marker}")
    require("accepted_external" not in source, "MORIARTY runner still admits accepted_external")
    for forbidden in (
        "shell=True", "os.system(", "eval(", "requests.", "urllib.", "socket.",
        "--command", "--url", "--host", "--credential", "--token",
    ):
        require(forbidden not in source, f"MORIARTY runner gained forbidden dynamic/target capability: {forbidden}")
    require(
        re.search(r"(?<![A-Za-z0-9_])exec\s*\(", source) is None,
        "MORIARTY runner gained forbidden standalone exec call",
    )
    validate_probe_map()


def validate_docs_and_ci() -> None:
    docs = (ROOT / "MORIARTY.md").read_text(encoding="utf-8")
    threat = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
    for marker in (
        "## Residual risks", "anonymous `AF_UNIX` `socketpair()`",
        "RESIDUAL RISK ACKNOWLEDGED != RESIDUAL RISK ACCEPTED AS AUTHORITY",
        "BOUNDED EXPOSURE != ZERO EXPOSURE",
    ):
        require(marker in threat, f"THREAT_MODEL.md residual-risk marker missing: {marker}")

    for marker in (
        "MORIARTY/1", "PROVIDER NEUTRAL", "EXACT COMMIT", "COUNTEREXAMPLE != AUTHORITY",
        "MORIARTY REPORT != SECURITY PROOF", "NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS",
        "External observations are candidates only", "resolution_commit is the fix commit",
        "reopens the owning phase", "production credentials", "production targets",
        "cargo test --all-targets --frozen", "read-only exact-commit export",
        "fail-before/pass-after", "stable through resolution",
    ):
        require(marker in docs, f"MORIARTY.md marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("## Phase 9 — MORIARTY/1 adversarial graduation" in roadmap, "ROADMAP Phase 9 missing")
    require("Status: current; MORIARTY/1 exact-commit graduation gate enforced" in roadmap, "ROADMAP Phase 9 current status missing")
    require("Phase 8 remains the current capability surface" in roadmap, "ROADMAP Phase 8 capability-surface preservation missing")
    require("Begins only after an exact merged commit passes its own MORIARTY/1 workflow run" in roadmap, "ROADMAP Phase 10 exact-merge handoff missing")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in (
        "state/phase9.json", "claims/phase9.json", "MORIARTY.md", "fixtures/phase9/attack-corpus.json",
        "tools/run_moriarty.py", "python3 tools/validate_phase9_gate.py",
    ):
        require(marker in agents, f"AGENTS Phase 9 marker missing: {marker}")

    ai = load("README4AI.md")
    require(ai.get("phase9_status") == "moriarty_adversarial_graduation_gate_enforced", "README4AI Phase 9 status missing")
    require(ai.get("current_claim_manifest") == "claims/phase8.json", "MORIARTY must not replace Phase 8 capability manifest")
    require(ai.get("current_claims") == load("claims/phase8.json")["capabilities"], "README4AI Phase 8 capability surface drift")
    phase9 = ai.get("phase9_moriarty")
    require(isinstance(phase9, dict), "README4AI Phase 9 block missing")
    require(phase9.get("contract") == "state/phase9.json", "README4AI Phase 9 contract drift")
    require(phase9.get("assurance_manifest") == "claims/phase9.json", "README4AI Phase 9 assurance manifest drift")
    require(phase9.get("claim_surface_changed") is False, "README4AI says MORIARTY changed capability surface")
    require(phase9.get("production_credentials_allowed") is False, "README4AI MORIARTY credential boundary drift")
    require(phase9.get("production_targets_allowed") is False, "README4AI MORIARTY target boundary drift")
    require(phase9.get("security_proof") is False, "README4AI MORIARTY security-proof overclaim")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow, "CI does not checkout the exact PR-head/push commit")
    require("fetch-depth: 0" in workflow, "CI does not provide full Git history for remediation validation")
    require("persist-credentials: false" in workflow, "CI exact target checkout persists credentials")
    require("MORIARTY_TARGET_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow, "CI MORIARTY target commit binding missing")
    require("cargo test --all-targets --locked" in workflow, "CI Rust suite is not lockfile-bound")
    require("MORIARTY_REPORT_DIR" in workflow, "CI MORIARTY persistent report directory missing")
    require("actions/upload-artifact@v4" in workflow and "Preserve Phase 9 MORIARTY report" in workflow, "CI MORIARTY report artifact preservation missing")
    require("python3 -I tools/validate_phase9_gate.py --target-commit \"$MORIARTY_TARGET_COMMIT\" --report-dir \"$MORIARTY_REPORT_DIR\"" in workflow, "CI missing isolated exact-commit Phase 9 gate")


def _counterexample_for_test(target: str, attack: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "schema": moriarty.COUNTEREXAMPLE_SCHEMA,
        "counterexample_id": "sha256:" + "0" * 64,
        "target_commit": target,
        "attack_id": attack["id"],
        "family": attack["family"],
        "owner_phases": list(attack["owner_phases"]),
        "boundary_ids": list(attack["boundary_ids"]),
        "regression_probe_ids": [attack["probe_ids"][0]],
        "failure_kind": "exit_nonzero",
        "observed_exit_code": 1,
        "stdout_sha256": moriarty.bytes_ref(b"test stdout"),
        "stderr_sha256": moriarty.bytes_ref(b"test stderr"),
        "stdout_bytes": 11,
        "stderr_bytes": 11,
        "status": "unresolved",
        "resolution_commit": None,
        "production_credentials_used": False,
        "production_targets_used": False,
        "constitutional_bypass_used": False,
        "authority_effect": "none",
    }
    _reidentify(item)
    return item


def _reidentify(item: dict[str, Any]) -> None:
    item["counterexample_id"] = moriarty.canonical_ref(moriarty.counterexample_identity_projection(item))


def _expect_reject(action: Callable[[], Any], label: str) -> None:
    try:
        action()
    except SystemExit:
        return
    raise SystemExit(f"MORIARTY negative test unexpectedly accepted: {label}")


def validate_counterexample_negative_tests(target: str) -> None:
    attacks = moriarty.validate_attack_corpus(load("fixtures/phase9/attack-corpus.json"))
    attack = attacks[0]

    external = _counterexample_for_test(target, attack)
    external["failure_kind"] = "accepted_external"
    external["observed_exit_code"] = None
    _reidentify(external)
    _expect_reject(
        lambda: moriarty.validate_registry({
            "schema": moriarty.REGISTRY_SCHEMA, "protocol": moriarty.PROTOCOL,
            "counterexamples": [external], "unresolved_counterexamples": 1, "authority_effect": "none",
        }, attacks, target),
        "accepted_external registry entry",
    )

    mismatch = _counterexample_for_test(target, attack)
    mismatch["family"] = attacks[1]["family"]
    _reidentify(mismatch)
    _expect_reject(
        lambda: moriarty.validate_registry({
            "schema": moriarty.REGISTRY_SCHEMA, "protocol": moriarty.PROTOCOL,
            "counterexamples": [mismatch], "unresolved_counterexamples": 1, "authority_effect": "none",
        }, attacks, target),
        "counterexample/corpus semantic mismatch",
    )

    unrelated_probe = _counterexample_for_test(target, attack)
    unrelated_probe["regression_probe_ids"] = ["phase8"]
    _reidentify(unrelated_probe)
    _expect_reject(
        lambda: moriarty.validate_registry({
            "schema": moriarty.REGISTRY_SCHEMA, "protocol": moriarty.PROTOCOL,
            "counterexamples": [unrelated_probe], "unresolved_counterexamples": 1, "authority_effect": "none",
        }, attacks, target),
        "counterexample probe outside corpus attack",
    )

    nonexistent_fix = _counterexample_for_test(target, attack)
    nonexistent_fix["status"] = "resolved"
    nonexistent_fix["resolution_commit"] = "f" * 40
    _reidentify(nonexistent_fix)
    _expect_reject(
        lambda: moriarty.validate_registry({
            "schema": moriarty.REGISTRY_SCHEMA, "protocol": moriarty.PROTOCOL,
            "counterexamples": [nonexistent_fix], "unresolved_counterexamples": 0, "authority_effect": "none",
        }, attacks, target),
        "nonexistent resolution commit",
    )

    stable = _counterexample_for_test(target, attack)
    original_id = stable["counterexample_id"]
    stable["status"] = "resolved"
    stable["resolution_commit"] = target
    _reidentify(stable)
    require(stable["counterexample_id"] == original_id, "counterexample identity changed through resolution")


def validate_isolation_negative_tests(target: str) -> None:
    require(moriarty.harness_files_match_target(target, ("tools/validate_phase9_gate.py",)), "executed Phase 9 harness bytes do not match target")

    with tempfile.TemporaryDirectory(prefix="moriarty-cargo-auth-test-") as temp_dir:
        root = Path(temp_dir)
        ambient = root / "ambient"
        cache = ambient / "registry" / "cache" / "test-index"
        cache.mkdir(parents=True)
        (ambient / "registry" / "index").mkdir(parents=True)
        (ambient / "config.toml").write_text("[build]\nrustc-wrapper='evil'\n", encoding="utf-8")
        good = b"verified crate archive"
        good_sha = hashlib.sha256(good).hexdigest()
        crate = cache / "demo-1.0.0.crate"
        crate.write_bytes(b"tampered")
        lock = root / "Cargo.lock"
        lock.write_text(
            'version = 4\n\n[[package]]\nname = "demo"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + good_sha + '"\n',
            encoding="utf-8",
        )
        oversized_index = ambient / "registry" / "index" / "oversized"
        oversized_index.write_bytes(b"")
        os.truncate(oversized_index, moriarty._moriarty_isolation.MAX_CARGO_INDEX_BYTES + 1)
        traversal_lock = root / "Cargo-traversal.lock"
        traversal_lock.write_text(
            'version = 4\n\n[[package]]\nname = "../../payload"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + good_sha + '"\n',
            encoding="utf-8",
        )
        workspace_traversal = root / "workspace-traversal"
        workspace_traversal.mkdir()
        _expect_reject(
            lambda: moriarty.create_verified_cargo_template(ambient, workspace_traversal, traversal_lock),
            "Cargo.lock package path traversal",
        )
        workspace_index = root / "workspace-index"
        workspace_index.mkdir()
        _expect_reject(
            lambda: moriarty.create_verified_cargo_template(ambient, workspace_index, lock),
            "oversized Cargo registry index projection",
        )
        oversized_index.unlink()
        workspace_bad = root / "workspace-bad"
        workspace_bad.mkdir()
        _expect_reject(
            lambda: moriarty.create_verified_cargo_template(ambient, workspace_bad, lock),
            "tampered Cargo package archive",
        )
        crate.write_bytes(good)
        workspace = root / "workspace"
        workspace.mkdir()
        template = moriarty.create_verified_cargo_template(ambient, workspace, lock)
        require(not (template / "config.toml").exists(), "ambient Cargo config entered verified template")
        require(not (template / "registry" / "src").exists(), "ambient unpacked Cargo source entered verified template")
        first = moriarty.create_isolated_cargo_home(template, workspace, "first")
        second = moriarty.create_isolated_cargo_home(template, workspace, "second")
        (first / "config.toml").write_text("[build]\nrustc-wrapper='evil'\n", encoding="utf-8")
        require(not (second / "config.toml").exists(), "per-probe Cargo homes contaminated each other")

    cargo_dir = ROOT / ".cargo"
    config = cargo_dir / "config.toml"
    require(not config.exists(), "negative test requires no tracked repository Cargo config")
    cargo_dir.mkdir(exist_ok=True)
    try:
        config.write_text("[build]\nrustc-wrapper='evil'\n", encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="moriarty-export-test-") as temp_dir:
            workspace = Path(temp_dir)
            export = moriarty.create_exact_export(target, workspace, moriarty.git_archive_bytes, "negative-untracked")
            require(not (export / ".cargo/config.toml").exists(), "untracked Cargo config entered exact export")
            require((export / "Cargo.lock").read_bytes() == (ROOT / "Cargo.lock").read_bytes(), "exact export lockfile drift")
    finally:
        try:
            config.unlink()
        except FileNotFoundError:
            pass
        try:
            cargo_dir.rmdir()
        except OSError:
            pass

    _expect_reject(
        lambda: moriarty.write_report_exclusive(ROOT / "moriarty-report-negative.json", b"{}", ROOT),
        "repository-local report output",
    )
    with tempfile.TemporaryDirectory(prefix="moriarty-report-test-") as temp_dir:
        parent = Path(temp_dir)
        os.chmod(parent, 0o700)
        victim = parent / "victim"
        victim.write_bytes(b"unchanged")
        output = parent / "report.json"
        output.symlink_to(victim)
        _expect_reject(lambda: moriarty.write_report_exclusive(output, b"{}", ROOT), "symlinked report output")
        require(victim.read_bytes() == b"unchanged", "report symlink negative test modified victim")


def validate_kernel_write_denial() -> None:
    require(moriarty.landlock_abi_version() >= 3, "MORIARTY requires Linux Landlock ABI >= 3")
    with tempfile.TemporaryDirectory(prefix="moriarty-landlock-test-") as temp_dir:
        root = Path(temp_dir)
        allowed = root / "allowed"
        forbidden = root / "forbidden"
        allowed.mkdir(mode=0o700)
        forbidden.mkdir(mode=0o700)
        victim = forbidden / "victim.txt"
        victim.write_text("original", encoding="utf-8")
        os.chmod(victim, 0o400)
        program = r'''
import os
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import moriarty_isolation as isolation
allowed = Path(sys.argv[2])
victim = Path(sys.argv[3])
isolation.apply_landlock_write_policy((allowed,))
os.chmod(victim, 0o600)
try:
    victim.write_text("changed", encoding="utf-8")
except PermissionError:
    raise SystemExit(0)
raise SystemExit(2)
'''
        completed = subprocess.run(
            [sys.executable, "-I", "-c", program, str(TOOLS), str(allowed), str(victim)],
            cwd=ROOT,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(root),
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        require(
            completed.returncode == 0,
            "MORIARTY Landlock write-denial regression failed: "
            + completed.stderr.decode("utf-8", errors="replace")[:256],
        )
        require(victim.read_text(encoding="utf-8") == "original", "MORIARTY Landlock victim changed")


def validate_kernel_network_and_proc_denial() -> None:
    require(moriarty.network_seccomp_supported(), "MORIARTY requires network seccomp support")
    with tempfile.TemporaryDirectory(prefix="moriarty-net-proc-test-") as temp_dir:
        root = Path(temp_dir)
        writable = root / "writable"
        writable.mkdir(mode=0o700)
        parent_pid = os.getpid()
        program = r"""
import errno
import socket
import sys
from pathlib import Path
parent_pid = sys.argv[1]
try:
    Path(f"/proc/{parent_pid}/environ").read_bytes()
except PermissionError:
    pass
else:
    raise SystemExit(3)
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as exc:
    if exc.errno != errno.EPERM:
        raise
else:
    raise SystemExit(4)
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
except OSError as exc:
    if exc.errno != errno.EPERM:
        raise
else:
    raise SystemExit(5)
left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    try:
        left.connect("/tmp/moriarty-forbidden.sock")
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise
    else:
        raise SystemExit(6)
finally:
    left.close(); right.close()
try:
    import os, signal
    os.kill(int(parent_pid), signal.SIGCONT)
except OSError as exc:
    if exc.errno != errno.EPERM:
        raise
else:
    raise SystemExit(7)
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
machine = os.uname().machine
queue_nr, tgqueue_nr = ((129, 297) if machine == "x86_64" else (138, 240))
for number, args in (
    (queue_nr, (int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),
    (tgqueue_nr, (int(parent_pid), int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),
):
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        raise SystemExit(8)
forbidden_etc = Path("/etc/hostname")
if forbidden_etc.exists():
    try:
        forbidden_etc.read_bytes()
    except PermissionError:
        pass
    else:
        raise SystemExit(9)
ctypes.set_errno(0)
result = libc.syscall(425, 1, ctypes.c_void_p(0))
if result != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit(10)
raise SystemExit(0)
"""
        preexec = moriarty.probe_isolation_preexec(
            tuple(path for path in (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64")) if path.exists()),
            moriarty._system_read_paths(),
            tuple(path for path in (writable, Path("/dev/null")) if path.exists()),
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", program, str(parent_pid)],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "HOME": str(writable), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            preexec_fn=preexec,
        )
        require(
            completed.returncode == 0,
            "MORIARTY network/proc isolation regression failed: "
            + completed.stderr.decode("utf-8", errors="replace")[:256],
        )


def validate_report_common(report: dict[str, Any], target: str) -> None:
    expected_fields = {
        "schema", "protocol", "target_commit", "corpus_ref", "operator_profile", "family_count",
        "executed_probe_count", "probe_results", "remediation_replays", "counterexamples", "unresolved_counterexamples",
        "graduated", "production_credentials_used", "production_targets_used",
        "constitutional_bypass_used", "security_proof", "no_counterexample_found_implies_none_exist",
        "authority_effect",
    }
    require(set(report) == expected_fields, "MORIARTY generated report field-set drift")
    require(report["schema"] == "moriarty-report/1", "MORIARTY generated report schema drift")
    require(report["protocol"] == "MORIARTY/1", "MORIARTY generated report protocol drift")
    require(report["target_commit"] == target, "MORIARTY generated report target drift")
    require(report["corpus_ref"] == canonical_ref(load("fixtures/phase9/attack-corpus.json")), "MORIARTY generated report corpus reference drift")
    require(report["operator_profile"] == "provider-neutral-fixed-probe/1", "MORIARTY generated report operator drift")
    require(report["family_count"] == 15, "MORIARTY generated report family count drift")
    require(report["executed_probe_count"] == len(EXPECTED_PROBES), "MORIARTY did not execute complete fixed-probe set")

    probe_results = report["probe_results"]
    result_fields = {"probe_id", "ok", "exit_code", "failure_kind", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes", "stdout_truncated", "stderr_truncated"}
    require(isinstance(probe_results, list) and len(probe_results) == len(EXPECTED_PROBES), "MORIARTY report probe result count drift")
    require({item.get("probe_id") for item in probe_results if isinstance(item, dict)} == set(EXPECTED_PROBES), "MORIARTY report probe set drift")
    for item in probe_results:
        require(isinstance(item, dict) and set(item) == result_fields, "MORIARTY nested probe result schema drift")
        require(isinstance(item["probe_id"], str) and item["probe_id"] in EXPECTED_PROBES, "MORIARTY probe result id invalid")
        require(type(item["ok"]) is bool, "MORIARTY probe result ok must be boolean")
        exit_code = item["exit_code"]
        require(exit_code is None or (type(exit_code) is int and -2147483648 <= exit_code <= 2147483647), "MORIARTY probe exit code invalid")
        failure_kind = item["failure_kind"]
        require(failure_kind in {None, "exit_nonzero", "timeout", "tool_error"}, "MORIARTY probe failure kind invalid")
        require(type(item["stdout_truncated"]) is bool and type(item["stderr_truncated"]) is bool, "MORIARTY truncation flags must be boolean")
        if item["ok"]:
            require(exit_code == 0 and failure_kind is None, "MORIARTY successful probe exit/failure semantics invalid")
            require(not item["stdout_truncated"] and not item["stderr_truncated"], "successful probe cannot be truncated")
        elif failure_kind == "exit_nonzero":
            require(type(exit_code) is int and exit_code != 0, "exit_nonzero probe lacks nonzero exit")
        else:
            require(exit_code is None, "timeout/tool_error probe must not expose an exit code")
        for stream in ("stdout", "stderr"):
            if item[f"{stream}_truncated"]:
                # Digests/counts are over normalized bounded evidence, which can be
                # shorter than the raw 1 MiB prefix after path/timing/PID replacement.
                require(0 < item[f"{stream}_bytes"] <= moriarty.MAX_PROBE_OUTPUT_BYTES, f"truncated {stream} normalized byte count invalid")
                require(failure_kind == "tool_error", f"truncated {stream} must be a tool_error")
        for digest in ("stdout_sha256", "stderr_sha256"):
            require(isinstance(item[digest], str) and moriarty.SHA256_REF_RE.fullmatch(item[digest]) is not None, f"MORIARTY probe digest invalid: {digest}")
        for size in ("stdout_bytes", "stderr_bytes"):
            require(type(item[size]) is int and 0 <= item[size] <= moriarty.MAX_PROBE_OUTPUT_BYTES, f"MORIARTY probe byte bound invalid: {size}")

    remediation_replays = report["remediation_replays"]
    replay_fields = {
        "counterexample_id", "status", "probe_id", "ok", "target_reproduced",
        "resolution_green", "failure_kind", "failure_result",
    }
    registry_entries = load("fixtures/phase9/accepted-counterexamples.json")["counterexamples"]
    registry_by_id = {item["counterexample_id"]: item for item in registry_entries}
    require(
        isinstance(remediation_replays, list)
        and len(remediation_replays) == len(registry_entries)
        and len(remediation_replays) <= moriarty.MAX_ACCEPTED_COUNTEREXAMPLES,
        "MORIARTY remediation replay count drift",
    )
    replay_ids: set[str] = set()
    for replay in remediation_replays:
        require(isinstance(replay, dict) and set(replay) == replay_fields, "MORIARTY remediation replay field-set drift")
        counterexample_id = replay["counterexample_id"]
        require(isinstance(counterexample_id, str) and counterexample_id in registry_by_id and counterexample_id not in replay_ids, "MORIARTY remediation replay identity invalid")
        replay_ids.add(counterexample_id)
        registry_item = registry_by_id[counterexample_id]
        require(replay["status"] == registry_item["status"], "MORIARTY remediation replay status drift")
        require(replay["probe_id"] == registry_item["regression_probe_ids"][0], "MORIARTY remediation replay probe drift")
        require(type(replay["ok"]) is bool and type(replay["target_reproduced"]) is bool, "MORIARTY remediation replay booleans invalid")
        require(replay["resolution_green"] is None or type(replay["resolution_green"]) is bool, "MORIARTY remediation resolution flag invalid")
        require(replay["failure_kind"] in {None, "target_failure_not_reproduced", "resolution_probe_not_green", "replay_setup_error"}, "MORIARTY remediation replay failure kind invalid")
        failure_result = replay["failure_result"]
        if failure_result is not None:
            require(isinstance(failure_result, dict) and set(failure_result) == result_fields, "MORIARTY remediation failure result schema drift")
            require(failure_result["probe_id"] == replay["probe_id"], "MORIARTY remediation failure result probe drift")
            require(type(failure_result["ok"]) is bool, "MORIARTY remediation failure result ok invalid")
            require(failure_result["exit_code"] is None or (type(failure_result["exit_code"]) is int and -2147483648 <= failure_result["exit_code"] <= 2147483647), "MORIARTY remediation failure result exit invalid")
            require(failure_result["failure_kind"] in {None, "exit_nonzero", "timeout", "tool_error"}, "MORIARTY remediation failure result kind invalid")
            for digest in ("stdout_sha256", "stderr_sha256"):
                require(isinstance(failure_result[digest], str) and moriarty.SHA256_REF_RE.fullmatch(failure_result[digest]) is not None, "MORIARTY remediation failure digest invalid")
            for size in ("stdout_bytes", "stderr_bytes"):
                require(type(failure_result[size]) is int and 0 <= failure_result[size] <= moriarty.MAX_PROBE_OUTPUT_BYTES, "MORIARTY remediation failure byte bound invalid")
            require(type(failure_result["stdout_truncated"]) is bool and type(failure_result["stderr_truncated"]) is bool, "MORIARTY remediation failure truncation invalid")
        if replay["ok"]:
            require(replay["failure_kind"] is None and failure_result is None and replay["target_reproduced"] is True, "MORIARTY successful remediation replay semantics invalid")
            if replay["status"] == "resolved":
                require(replay["resolution_green"] is True, "MORIARTY resolved remediation replay lacks green resolution")
            else:
                require(replay["resolution_green"] is None, "MORIARTY unresolved remediation replay gained resolution state")
        else:
            require(replay["failure_kind"] is not None, "MORIARTY failed remediation replay lacks failure kind")
            if replay["failure_kind"] in {"target_failure_not_reproduced", "resolution_probe_not_green"}:
                require(failure_result is not None, "MORIARTY failed remediation replay lost subprocess metadata")
    require(replay_ids == set(registry_by_id), "MORIARTY did not replay every accepted registry entry")

    counterexamples = report["counterexamples"]
    require(isinstance(counterexamples, list) and len(counterexamples) <= moriarty.MAX_REPORT_COUNTEREXAMPLES, "MORIARTY report counterexample count drift")
    attacks = moriarty.validate_attack_corpus(load("fixtures/phase9/attack-corpus.json"))
    attack_by_id = {attack["id"]: attack for attack in attacks}
    unresolved = 0
    for item in counterexamples:
        moriarty.validate_counterexample_shape(item)
        attack = attack_by_id.get(item["attack_id"])
        require(attack is not None, "MORIARTY report counterexample attack not in corpus")
        require(item["family"] == attack["family"], "MORIARTY report counterexample family mismatch")
        require(item["owner_phases"] == attack["owner_phases"], "MORIARTY report counterexample owner mismatch")
        require(item["boundary_ids"] == attack["boundary_ids"], "MORIARTY report counterexample boundary mismatch")
        require(set(item["regression_probe_ids"]).issubset(set(attack["probe_ids"])), "MORIARTY report counterexample probe mismatch")
        unresolved += item["status"] == "unresolved"
    require(type(report["unresolved_counterexamples"]) is int and report["unresolved_counterexamples"] == unresolved, "MORIARTY report unresolved count inconsistent")

    for key in (
        "production_credentials_used", "production_targets_used", "constitutional_bypass_used",
        "security_proof", "no_counterexample_found_implies_none_exist",
    ):
        require(report[key] is False, f"MORIARTY generated report overclaim/bypass: {key}")
    require(report["authority_effect"] == "none", "MORIARTY generated report gained authority")
    all_ok = all(item["ok"] for item in probe_results)
    all_replays_ok = all(item["ok"] for item in remediation_replays)
    require(type(report["graduated"]) is bool and report["graduated"] == (all_ok and all_replays_ok and unresolved == 0), "MORIARTY graduation Boolean inconsistent with report evidence")


def validate_success_report(report: dict[str, Any], registry: dict[str, Any]) -> None:
    probe_results = report["probe_results"]
    require(all(item.get("ok") is True and item.get("exit_code") == 0 for item in probe_results), "MORIARTY report contains failed fixed probe")
    require(report["counterexamples"] == registry["counterexamples"], "MORIARTY successful report contains generated counterexample or registry drift")
    require(all(item.get("ok") is True for item in report["remediation_replays"]), "MORIARTY successful report contains failed remediation replay")
    require(report["unresolved_counterexamples"] == 0, "MORIARTY report has unresolved counterexample")
    require(report["graduated"] is True, "MORIARTY report did not graduate exact commit")


def failure_diagnostic(report: dict[str, Any]) -> str:
    failed_probes = [
        {
            "probe_id": item["probe_id"],
            "exit_code": item["exit_code"],
            "failure_kind": item["failure_kind"],
            "stdout_truncated": item["stdout_truncated"],
            "stderr_truncated": item["stderr_truncated"],
            "stdout_sha256": item["stdout_sha256"],
            "stderr_sha256": item["stderr_sha256"],
            "stdout_bytes": item["stdout_bytes"],
            "stderr_bytes": item["stderr_bytes"],
        }
        for item in report["probe_results"]
        if not item["ok"]
    ]
    counterexamples = [
        {
            "counterexample_id": item["counterexample_id"],
            "attack_id": item["attack_id"],
            "regression_probe_ids": item["regression_probe_ids"],
            "status": item["status"],
        }
        for item in report["counterexamples"]
    ]
    return json.dumps({
        "target_commit": report["target_commit"],
        "corpus_ref": report["corpus_ref"],
        "failed_probes": failed_probes,
        "counterexamples": counterexamples,
        "remediation_replay_failures": [
            {
                "counterexample_id": item["counterexample_id"],
                "probe_id": item["probe_id"],
                "failure_kind": item["failure_kind"],
                "failure_result": item["failure_result"],
            }
            for item in report["remediation_replays"]
            if not item["ok"]
        ],
        "unresolved_counterexamples": report["unresolved_counterexamples"],
        "graduated": report["graduated"],
    }, sort_keys=True, separators=(",", ":"))


def _runner_report_attestation(stdout: bytes) -> str:
    prefix = b"MORIARTY_REPORT_SHA256="
    values = [line[len(prefix):].decode("ascii", errors="strict") for line in stdout.splitlines() if line.startswith(prefix)]
    require(len(values) == 1 and re.fullmatch(r"[0-9a-f]{64}", values[0]) is not None, "MORIARTY runner report attestation missing or invalid")
    return values[0]


def _read_attested_report(path: Path, expected_sha256: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SystemExit(f"MORIARTY attested report open failed: {exc}")
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), "MORIARTY attested report is not a regular file")
        require(before.st_uid == os.getuid(), "MORIARTY attested report owner drift")
        require(before.st_nlink == 1, "MORIARTY attested report link-count drift")
        require(0 <= before.st_size <= moriarty.MAX_REPORT_BYTES, "MORIARTY report exceeds canonical byte bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, moriarty.MAX_REPORT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= moriarty.MAX_REPORT_BYTES, "MORIARTY report exceeds canonical byte bound")
        after = os.fstat(fd)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "MORIARTY attested report changed during descriptor read",
        )
        raw = b"".join(chunks)
        require(len(raw) == before.st_size, "MORIARTY attested report size drift")
        require(hashlib.sha256(raw).hexdigest() == expected_sha256, "MORIARTY report bytes do not match runner attestation")
        return raw
    finally:
        os.close(fd)


def execute_exact_commit_gate(target: str, report_dir: Path | None) -> None:
    require(git_head() == target, "Phase 9 target commit does not match checked-out HEAD")
    require(moriarty.tracked_tree_clean(), "Phase 9 target tracked tree/index flags are dirty before runner")
    require(moriarty.harness_files_match_target(target, ("tools/validate_phase9_gate.py",)), "Phase 9 executed harness bytes differ from target")
    registry = load("fixtures/phase9/accepted-counterexamples.json")
    if report_dir is None:
        report_dir = Path(tempfile.mkdtemp(prefix="qsol-fed-moriarty-report-"))
    else:
        report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(report_dir, 0o700)
    report_path = report_dir / f"moriarty-report-{target}.json"
    require(not report_path.exists(), "MORIARTY report destination already exists")

    completed = moriarty.trusted_run(
        moriarty.PYTHON_TRUSTED,
        ("-I", "tools/run_moriarty.py", "--target-commit", target, "--output", str(report_path)),
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(report_dir),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if not report_path.exists():
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        diagnostic = stderr or stdout or "no runner output"
        raise SystemExit(
            "MORIARTY runner did not emit report: "
            + diagnostic[:2048]
        )
    attested_sha256 = _runner_report_attestation(completed.stdout)
    raw = _read_attested_report(report_path, attested_sha256)
    try:
        decoded = raw.decode("utf-8", errors="strict")
        report = json.loads(decoded)
        canonical = serialize(report).encode("utf-8")
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise SystemExit(f"MORIARTY report canonical parse failed: {exc}")
    require(canonical == raw, "MORIARTY report is not exact canonical JSON")
    validate_report_common(report, target)

    injected = copy.deepcopy(report)
    injected["probe_results"][0]["raw_output"] = "forbidden"
    _expect_reject(lambda: validate_report_common(injected, target), "nested raw probe output")
    malformed = copy.deepcopy(report)
    malformed["probe_results"][0]["stdout_sha256"] = "sha256:not-a-digest"
    _expect_reject(lambda: validate_report_common(malformed, target), "malformed nested probe digest")

    if completed.returncode != 0:
        raise SystemExit("MORIARTY runner blocked exact commit: " + failure_diagnostic(report))
    validate_success_report(report, registry)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate the Phase 9 MORIARTY/1 graduation gate")
    parser.add_argument("--target-commit", help="exact checked-out commit; defaults to Git HEAD")
    parser.add_argument("--report-dir", help="private external directory for persistent MORIARTY report")
    args = parser.parse_args()
    target = args.target_commit or git_head()
    require(bool(TARGET_RE.fullmatch(target)), "Phase 9 target commit format invalid")

    validate_claims()
    validate_contract()
    validate_schemas_and_fixtures()
    validate_runner_source()
    validate_docs_and_ci()
    validate_counterexample_negative_tests(target)
    validate_isolation_negative_tests(target)
    validate_kernel_write_denial()
    validate_kernel_network_and_proc_denial()
    execute_exact_commit_gate(target, Path(args.report_dir).resolve() if args.report_dir else None)
    print(
        f"phase9 MORIARTY/1 gate OK for exact commit {target}: "
        "15 adversarial families, 13 source-allowlisted probes, zero unresolved reproducible counterexamples; "
        "accepted registry requires local reproduction and reviewed-history fix commits; report remains non-authoritative"
    )


if __name__ == "__main__":
    main()
