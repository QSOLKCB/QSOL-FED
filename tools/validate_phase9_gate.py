#!/usr/bin/env python3
"""Enforce the MORIARTY/1 exact-commit adversarial graduation boundary."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from qsol_canonical import canonicalize  # noqa: E402

EXPECTED_FAMILIES = {
    "canonical_parser_differentials",
    "signature_domain_key_role_confusion",
    "replay_downgrade_clock",
    "http_rate_proxy_ddos_shape",
    "ssrf_decompression",
    "crash_fsync_restart",
    "lifecycle_partition_history",
    "import_provenance_authority_laundering",
    "adapter_confusion",
    "holodeck_escape",
    "safeguard_persuasion",
    "nested_world_amplification",
    "assembly_capture_representation",
    "transport_nat_relay_store_forward_archive",
    "cross_phase_contradictions",
}
EXPECTED_PROBES = {
    "constitution",
    "phase0",
    "phase1",
    "phase2",
    "phase3",
    "phase4",
    "phase5a",
    "phase5",
    "phase5c",
    "phase6",
    "phase7",
    "phase8",
    "rust_all",
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


def git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(completed.returncode == 0, "Phase 9 cannot resolve Git HEAD")
    head = completed.stdout.decode("ascii", errors="strict").strip()
    require(bool(TARGET_RE.fullmatch(head)), "Phase 9 Git HEAD is not a lowercase 40-hex commit")
    return head


def validate_claims() -> None:
    previous = load("claims/phase8.json")
    current = load("claims/phase9.json")
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
    require(isinstance(assurance, dict), "Phase 9 assurance block missing")
    for key in (
        "provider_neutral",
        "exact_commit_binding",
        "reproducible_counterexample_contract",
        "accepted_counterexample_registry",
        "fixed_repository_probe_map",
        "cross_phase_regression_sweep",
    ):
        require(assurance.get(key) is True, f"Phase 9 assurance drift: {key}")
    for key in (
        "production_credentials_used",
        "production_targets_used",
        "constitutional_bypass_used",
        "report_is_security_proof",
        "no_counterexample_found_means_none_exist",
    ):
        require(assurance.get(key) is False, f"Phase 9 assurance overclaim/bypass: {key}")
    require(assurance.get("authority_effect") == "none", "MORIARTY assurance gained authority")


def validate_contract() -> None:
    state = load("state/phase9.json")
    require(state.get("document_type") == "qsol-fed-phase9-moriarty-contract", "Phase 9 state id drift")
    require(state.get("moriarty_protocol") == "MORIARTY/1", "MORIARTY protocol drift")
    require(state.get("feature_dependency") is False, "MORIARTY became a feature dependency")
    require(state.get("claim_surface_changed") is False, "MORIARTY changed capability claim surface")
    require(state.get("capability_baseline") == "claims/phase8.json", "MORIARTY capability baseline drift")
    require(set(state.get("attack_families", [])) == EXPECTED_FAMILIES, "MORIARTY attack-family set drift")

    operator = state["operator_model"]
    require(operator["provider_neutral"] is True, "MORIARTY lost provider neutrality")
    require(operator["reference_operator_may_be_codex"] is True, "MORIARTY reference-operator rule drift")
    require(operator["candidate_findings_require_local_reproduction"] is True, "MORIARTY findings no longer require reproduction")
    for key in (
        "operator_output_is_authority",
        "operator_output_is_security_proof",
        "operator_may_supply_commands",
        "operator_may_supply_repository_targets",
        "operator_may_supply_network_targets",
        "operator_may_supply_credentials",
        "operator_may_disable_constitution",
    ):
        require(operator[key] is False, f"MORIARTY operator boundary weakened: {key}")

    execution = state["execution_boundary"]
    for key in ("target_is_exact_git_commit", "checked_out_head_must_equal_target", "fixed_repository_probe_map"):
        require(execution[key] is True, f"MORIARTY exact/fixed execution boundary drift: {key}")
    for key in (
        "shell_execution",
        "arbitrary_command_execution",
        "production_credentials_allowed",
        "production_targets_allowed",
        "outbound_network_targeting_allowed",
        "constitutional_bypass_allowed",
        "semantic_payload_execution_allowed",
    ):
        require(execution[key] is False, f"MORIARTY execution boundary weakened: {key}")
    require(execution["authority_effect"] == "none", "MORIARTY execution gained authority")

    counterexamples = state["counterexample_policy"]
    for key in (
        "accepted_findings_are_reproducible",
        "accepted_findings_name_attack_family",
        "accepted_findings_name_owning_phases",
        "accepted_findings_name_boundary_ids",
        "accepted_findings_name_fixed_regression_probes",
        "unresolved_accepted_finding_blocks_graduation",
        "resolved_finding_remains_in_registry",
        "resolved_finding_becomes_regression",
    ):
        require(counterexamples[key] is True, f"MORIARTY counterexample policy drift: {key}")
    for key in (
        "finding_may_create_authority",
        "finding_may_contain_production_credentials",
        "finding_may_target_production_system",
    ):
        require(counterexamples[key] is False, f"MORIARTY counterexample boundary weakened: {key}")

    report = state["report_policy"]
    require(report["binds_exact_target_commit"] is True, "MORIARTY report lost exact commit binding")
    require(report["binds_canonical_attack_corpus_identity"] is True, "MORIARTY report lost corpus binding")
    require(report["graduated_requires_zero_unresolved_counterexamples"] is True, "MORIARTY graduation rule drift")
    require(report["security_proof"] is False, "MORIARTY report overclaimed security proof")
    require(report["no_counterexample_found_implies_none_exist"] is False, "MORIARTY report overclaimed exhaustiveness")
    require(report["authority_effect"] == "none", "MORIARTY report gained authority")


def validate_schemas_and_fixtures() -> None:
    corpus_schema = load("schemas/moriarty-attack-corpus-v1.schema.json")
    counterexample_schema = load("schemas/moriarty-counterexample-v1.schema.json")
    report_schema = load("schemas/moriarty-report-v1.schema.json")
    for name, schema in (
        ("attack corpus", corpus_schema),
        ("counterexample", counterexample_schema),
        ("report", report_schema),
    ):
        require(schema.get("additionalProperties") is False, f"MORIARTY {name} schema must remain closed")

    corpus_props = corpus_schema["properties"]
    for key in ("production_credentials_allowed", "production_targets_allowed", "constitutional_bypass_allowed"):
        require(corpus_props[key].get("const") is False, f"MORIARTY corpus schema boundary drift: {key}")
    require(corpus_props["authority_effect"].get("const") == "none", "MORIARTY corpus schema gained authority")

    counter_props = counterexample_schema["properties"]
    for key in ("production_credentials_used", "production_targets_used", "constitutional_bypass_used"):
        require(counter_props[key].get("const") is False, f"MORIARTY counterexample schema boundary drift: {key}")
    require(counter_props["authority_effect"].get("const") == "none", "MORIARTY counterexample schema gained authority")

    report_props = report_schema["properties"]
    require(report_props["operator_profile"].get("const") == "provider-neutral-fixed-probe/1", "MORIARTY report operator profile drift")
    require(report_props["family_count"].get("const") == 15, "MORIARTY report family count drift")
    for key in (
        "production_credentials_used",
        "production_targets_used",
        "constitutional_bypass_used",
        "security_proof",
        "no_counterexample_found_implies_none_exist",
    ):
        require(report_props[key].get("const") is False, f"MORIARTY report schema overclaim/bypass: {key}")
    require(report_props["authority_effect"].get("const") == "none", "MORIARTY report schema gained authority")

    corpus = load("fixtures/phase9/attack-corpus.json")
    require(corpus.get("schema") == "moriarty-attack-corpus/1", "MORIARTY corpus id drift")
    require(corpus.get("protocol") == "MORIARTY/1", "MORIARTY corpus protocol drift")
    attacks = corpus.get("attacks")
    require(isinstance(attacks, list) and len(attacks) == 15, "MORIARTY corpus must contain exactly 15 attacks")
    require({item.get("family") for item in attacks} == EXPECTED_FAMILIES, "MORIARTY corpus family set drift")
    require({item.get("id") for item in attacks} == {f"MOR-{index:03d}" for index in range(1, 16)}, "MORIARTY attack id set drift")
    for item in attacks:
        require(isinstance(item.get("probe_ids"), list) and item["probe_ids"], f"MORIARTY attack missing probes: {item.get('id')}")
        require(set(item["probe_ids"]).issubset(EXPECTED_PROBES), f"MORIARTY attack selected unknown probe: {item.get('id')}")
        require(isinstance(item.get("owner_phases"), list) and item["owner_phases"], f"MORIARTY attack missing owner phase: {item.get('id')}")
        require(isinstance(item.get("boundary_ids"), list) and item["boundary_ids"], f"MORIARTY attack missing boundary ids: {item.get('id')}")
    for key in ("production_credentials_allowed", "production_targets_allowed", "constitutional_bypass_allowed"):
        require(corpus.get(key) is False, f"MORIARTY fixture boundary drift: {key}")
    require(corpus.get("authority_effect") == "none", "MORIARTY fixture gained authority")

    registry = load("fixtures/phase9/accepted-counterexamples.json")
    require(registry.get("schema") == "moriarty-counterexample-registry/1", "MORIARTY registry id drift")
    require(registry.get("protocol") == "MORIARTY/1", "MORIARTY registry protocol drift")
    require(registry.get("authority_effect") == "none", "MORIARTY registry gained authority")
    values = registry.get("counterexamples")
    require(isinstance(values, list), "MORIARTY registry counterexamples missing")
    unresolved = sum(1 for item in values if isinstance(item, dict) and item.get("status") == "unresolved")
    require(registry.get("unresolved_counterexamples") == unresolved, "MORIARTY registry unresolved count drift")
    require(unresolved == 0, "MORIARTY accepted unresolved counterexample blocks graduation")


def validate_runner_source() -> None:
    source = (ROOT / "tools/run_moriarty.py").read_text(encoding="utf-8")
    for marker in (
        "provider-neutral-fixed-probe/1",
        "moriarty-counterexample/1",
        "moriarty-report/1",
        "git\", \"rev-parse\", \"HEAD",
        "PROBES: dict[str, tuple[str, ...]]",
        "candidate",
        "production_credentials_used",
        "production_targets_used",
        "constitutional_bypass_used",
        "security_proof",
        "no_counterexample_found_implies_none_exist",
    ):
        require(marker in source, f"MORIARTY runner marker missing: {marker}")
    for probe_id in EXPECTED_PROBES:
        require(f'"{probe_id}"' in source, f"MORIARTY fixed probe missing: {probe_id}")
    for forbidden in (
        "shell=True",
        "os.system(",
        "eval(",
        "exec(",
        "requests.",
        "urllib.",
        "socket.",
        "--command",
        "--url",
        "--host",
        "--credential",
        "--token",
    ):
        require(forbidden not in source, f"MORIARTY runner gained forbidden dynamic/target capability: {forbidden}")


def validate_docs_and_ci() -> None:
    docs = (ROOT / "MORIARTY.md").read_text(encoding="utf-8")
    for marker in (
        "MORIARTY/1",
        "PROVIDER NEUTRAL",
        "EXACT COMMIT",
        "COUNTEREXAMPLE != AUTHORITY",
        "MORIARTY REPORT != SECURITY PROOF",
        "NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS",
        "production credentials",
        "production targets",
        "reopens the owning phase",
    ):
        require(marker in docs, f"MORIARTY.md marker missing: {marker}")

    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    require("## Phase 9 — MORIARTY/1 adversarial graduation" in roadmap, "ROADMAP Phase 9 missing")
    require("Status: current; MORIARTY/1 exact-commit graduation gate enforced" in roadmap, "ROADMAP Phase 9 current status missing")
    require("Phase 8 remains the current capability surface" in roadmap, "ROADMAP Phase 8 capability-surface preservation missing")
    require("Begins only after an exact merged commit passes its own MORIARTY/1 workflow run" in roadmap, "ROADMAP Phase 10 exact-merge handoff missing")

    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for marker in (
        "state/phase9.json",
        "claims/phase9.json",
        "MORIARTY.md",
        "fixtures/phase9/attack-corpus.json",
        "tools/run_moriarty.py",
        "python3 tools/validate_phase9_gate.py",
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
    require("persist-credentials: false" in workflow, "CI exact target checkout persists credentials")
    require("MORIARTY_TARGET_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow, "CI MORIARTY target commit binding missing")
    require("python3 tools/validate_phase9_gate.py --target-commit \"$MORIARTY_TARGET_COMMIT\"" in workflow, "CI missing exact-commit Phase 9 gate")


def validate_report(report: dict[str, Any], target: str, registry: dict[str, Any]) -> None:
    expected_fields = {
        "schema",
        "protocol",
        "target_commit",
        "corpus_ref",
        "operator_profile",
        "family_count",
        "executed_probe_count",
        "probe_results",
        "counterexamples",
        "unresolved_counterexamples",
        "graduated",
        "production_credentials_used",
        "production_targets_used",
        "constitutional_bypass_used",
        "security_proof",
        "no_counterexample_found_implies_none_exist",
        "authority_effect",
    }
    require(set(report) == expected_fields, "MORIARTY generated report field-set drift")
    require(report["schema"] == "moriarty-report/1", "MORIARTY generated report schema drift")
    require(report["protocol"] == "MORIARTY/1", "MORIARTY generated report protocol drift")
    require(report["target_commit"] == target, "MORIARTY generated report target drift")
    require(report["operator_profile"] == "provider-neutral-fixed-probe/1", "MORIARTY generated report operator drift")
    require(report["family_count"] == 15, "MORIARTY generated report family count drift")
    require(report["executed_probe_count"] == len(EXPECTED_PROBES), "MORIARTY did not execute complete fixed-probe set")
    probe_results = report["probe_results"]
    require(isinstance(probe_results, list) and len(probe_results) == len(EXPECTED_PROBES), "MORIARTY report probe result count drift")
    require({item.get("probe_id") for item in probe_results} == EXPECTED_PROBES, "MORIARTY report probe set drift")
    require(all(item.get("ok") is True and item.get("exit_code") == 0 for item in probe_results), "MORIARTY report contains failed fixed probe")
    require(report["counterexamples"] == registry["counterexamples"], "MORIARTY successful report contains generated counterexample or registry drift")
    require(report["unresolved_counterexamples"] == 0, "MORIARTY report has unresolved counterexample")
    require(report["graduated"] is True, "MORIARTY report did not graduate exact commit")
    for key in (
        "production_credentials_used",
        "production_targets_used",
        "constitutional_bypass_used",
        "security_proof",
        "no_counterexample_found_implies_none_exist",
    ):
        require(report[key] is False, f"MORIARTY generated report overclaim/bypass: {key}")
    require(report["authority_effect"] == "none", "MORIARTY generated report gained authority")


def execute_exact_commit_gate(target: str) -> None:
    require(git_head() == target, "Phase 9 target commit does not match checked-out HEAD")
    registry = load("fixtures/phase9/accepted-counterexamples.json")
    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-") as temp_dir:
        report_path = Path(temp_dir) / "moriarty-report.json"
        completed = subprocess.run(
            [
                "python3",
                "tools/run_moriarty.py",
                "--target-commit",
                target,
                "--output",
                str(report_path),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(report_path.exists(), "MORIARTY runner did not emit report")
        raw = report_path.read_bytes()
        require(canonicalize(raw.decode("utf-8")) == raw, "MORIARTY report is not exact canonical JSON")
        report = json.loads(raw)
        validate_report(report, target, registry)
        if completed.returncode != 0:
            diagnostic = completed.stderr.decode("utf-8", errors="replace")[-2000:]
            raise SystemExit(f"MORIARTY runner blocked exact commit: {diagnostic}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate the Phase 9 MORIARTY/1 graduation gate")
    parser.add_argument("--target-commit", help="exact checked-out commit; defaults to Git HEAD")
    args = parser.parse_args()
    target = args.target_commit or git_head()
    require(bool(TARGET_RE.fullmatch(target)), "Phase 9 target commit format invalid")

    validate_claims()
    validate_contract()
    validate_schemas_and_fixtures()
    validate_runner_source()
    validate_docs_and_ci()
    execute_exact_commit_gate(target)
    print(
        f"phase9 MORIARTY/1 gate OK for exact commit {target}: "
        "15 adversarial families, 13 source-allowlisted probes, zero unresolved reproducible counterexamples; "
        "report remains non-authoritative and is not a security proof"
    )


if __name__ == "__main__":
    main()
