#!/usr/bin/env python3
"""Run the provider-neutral MORIARTY/1 exact-commit adversarial graduation harness."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from qsol_canonical import serialize  # noqa: E402

PROTOCOL = "MORIARTY/1"
REPORT_SCHEMA = "moriarty-report/1"
COUNTEREXAMPLE_SCHEMA = "moriarty-counterexample/1"
ATTACK_CORPUS_SCHEMA = "moriarty-attack-corpus/1"
REGISTRY_SCHEMA = "moriarty-counterexample-registry/1"
OPERATOR_PROFILE = "provider-neutral-fixed-probe/1"
TARGET_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMEOUT_SECONDS = 300

# Source-owned and closed. An external/model candidate finding must be reduced to
# one of these deterministic local probes before it is eligible for the accepted registry.
PROBES: dict[str, tuple[str, ...]] = {
    "constitution": ("python3", "tools/validate_constitution.py"),
    "phase0": ("python3", "tools/validate_phase0_gate.py"),
    "phase1": ("python3", "tools/validate_phase1_gate.py"),
    "phase2": ("python3", "tools/validate_phase2_gate.py"),
    "phase3": ("python3", "tools/validate_phase3_gate.py"),
    "phase4": ("python3", "tools/validate_phase4_gate.py"),
    "phase5a": ("python3", "tools/validate_phase5a_gate.py"),
    "phase5": ("python3", "tools/validate_phase5_gate.py"),
    "phase5c": ("python3", "tools/validate_phase5c_gate.py"),
    "phase6": ("python3", "tools/validate_phase6_gate.py"),
    "phase7": ("python3", "tools/validate_phase7_gate.py"),
    "phase8": ("python3", "tools/validate_phase8_gate.py"),
    "rust_all": ("cargo", "test", "--all-targets"),
}

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


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"moriarty_json_load_failed:{path.relative_to(ROOT)}:{exc}")
    if not isinstance(value, dict):
        fail(f"moriarty_json_object_required:{path.relative_to(ROOT)}")
    return value


def canonical_ref(value: Any) -> str:
    return "sha256:" + hashlib.sha256(serialize(value).encode("utf-8")).hexdigest()


def bytes_ref(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def git_head() -> str:
    completed = git("rev-parse", "HEAD")
    if completed.returncode != 0:
        fail("moriarty_git_head_unavailable")
    try:
        head = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        fail("moriarty_git_head_non_ascii")
    if not TARGET_RE.fullmatch(head):
        fail("moriarty_git_head_invalid")
    return head


def git_commit_exists(commit: str) -> bool:
    return bool(TARGET_RE.fullmatch(commit)) and git("cat-file", "-e", f"{commit}^{{commit}}").returncode == 0


def git_is_ancestor(ancestor: str, descendant: str) -> bool:
    return git("merge-base", "--is-ancestor", ancestor, descendant).returncode == 0


def validate_attack_corpus(corpus: dict[str, Any]) -> list[dict[str, Any]]:
    if (
        corpus.get("schema") != ATTACK_CORPUS_SCHEMA
        or corpus.get("protocol") != PROTOCOL
        or corpus.get("production_credentials_allowed") is not False
        or corpus.get("production_targets_allowed") is not False
        or corpus.get("constitutional_bypass_allowed") is not False
        or corpus.get("authority_effect") != "none"
    ):
        fail("moriarty_attack_corpus_boundary_invalid")
    attacks = corpus.get("attacks")
    if not isinstance(attacks, list) or len(attacks) != 15:
        fail("moriarty_attack_count_invalid")
    ids: set[str] = set()
    families: set[str] = set()
    for attack in attacks:
        if not isinstance(attack, dict):
            fail("moriarty_attack_record_invalid")
        attack_id = attack.get("id")
        family = attack.get("family")
        owner_phases = attack.get("owner_phases")
        boundary_ids = attack.get("boundary_ids")
        probe_ids = attack.get("probe_ids")
        if (
            not isinstance(attack_id, str)
            or not re.fullmatch(r"MOR-[0-9]{3}", attack_id)
            or attack_id in ids
            or not isinstance(family, str)
            or family not in EXPECTED_FAMILIES
            or family in families
            or not isinstance(owner_phases, list)
            or not owner_phases
            or not all(isinstance(value, str) and value for value in owner_phases)
            or len(set(owner_phases)) != len(owner_phases)
            or not isinstance(boundary_ids, list)
            or not boundary_ids
            or not all(isinstance(value, str) and re.fullmatch(r"[a-z0-9_./-]{1,128}", value) for value in boundary_ids)
            or len(set(boundary_ids)) != len(boundary_ids)
            or not isinstance(probe_ids, list)
            or not probe_ids
            or not all(isinstance(value, str) and value in PROBES for value in probe_ids)
            or len(set(probe_ids)) != len(probe_ids)
        ):
            fail(f"moriarty_attack_invalid:{attack_id!r}")
        ids.add(attack_id)
        families.add(family)
    if families != EXPECTED_FAMILIES:
        fail("moriarty_attack_family_set_drift")
    return attacks


def validate_counterexample_shape(item: Any) -> None:
    if not isinstance(item, dict):
        fail("moriarty_counterexample_not_object")
    required = {
        "schema", "counterexample_id", "target_commit", "attack_id", "family",
        "owner_phases", "boundary_ids", "regression_probe_ids", "failure_kind",
        "observed_exit_code", "stdout_sha256", "stderr_sha256", "stdout_bytes",
        "stderr_bytes", "status", "resolution_commit", "production_credentials_used",
        "production_targets_used", "constitutional_bypass_used", "authority_effect",
    }
    if set(item) != required:
        fail("moriarty_counterexample_field_set_invalid")
    if (
        item["schema"] != COUNTEREXAMPLE_SCHEMA
        or not isinstance(item["counterexample_id"], str)
        or not SHA256_REF_RE.fullmatch(item["counterexample_id"])
        or not isinstance(item["target_commit"], str)
        or not TARGET_RE.fullmatch(item["target_commit"])
        or not isinstance(item["attack_id"], str)
        or not re.fullmatch(r"MOR-[0-9]{3}", item["attack_id"])
        or item["family"] not in EXPECTED_FAMILIES
        or not isinstance(item["owner_phases"], list)
        or not item["owner_phases"]
        or len(set(item["owner_phases"])) != len(item["owner_phases"])
        or not isinstance(item["boundary_ids"], list)
        or not item["boundary_ids"]
        or len(set(item["boundary_ids"])) != len(item["boundary_ids"])
        or not isinstance(item["regression_probe_ids"], list)
        or not item["regression_probe_ids"]
        or len(set(item["regression_probe_ids"])) != len(item["regression_probe_ids"])
        or not all(probe_id in PROBES for probe_id in item["regression_probe_ids"])
        or item["failure_kind"] not in {"exit_nonzero", "timeout", "tool_error"}
        or item["status"] not in {"unresolved", "resolved"}
        or item["production_credentials_used"] is not False
        or item["production_targets_used"] is not False
        or item["constitutional_bypass_used"] is not False
        or item["authority_effect"] != "none"
        or not isinstance(item["stdout_sha256"], str)
        or not SHA256_REF_RE.fullmatch(item["stdout_sha256"])
        or not isinstance(item["stderr_sha256"], str)
        or not SHA256_REF_RE.fullmatch(item["stderr_sha256"])
        or not isinstance(item["stdout_bytes"], int)
        or not 0 <= item["stdout_bytes"] <= 9007199254740991
        or not isinstance(item["stderr_bytes"], int)
        or not 0 <= item["stderr_bytes"] <= 9007199254740991
    ):
        fail("moriarty_counterexample_boundary_invalid")

    if item["failure_kind"] == "exit_nonzero":
        if not isinstance(item["observed_exit_code"], int) or item["observed_exit_code"] == 0:
            fail("moriarty_exit_failure_requires_nonzero_exit_code")
    elif item["observed_exit_code"] is not None:
        fail("moriarty_nonexit_failure_exit_code_must_be_null")

    if item["status"] == "unresolved":
        if item["resolution_commit"] is not None:
            fail("moriarty_unresolved_counterexample_has_resolution_commit")
    elif not isinstance(item["resolution_commit"], str) or not TARGET_RE.fullmatch(item["resolution_commit"]):
        fail("moriarty_resolved_counterexample_missing_resolution_commit")

    projection = dict(item)
    projection.pop("counterexample_id")
    if item["counterexample_id"] != canonical_ref(projection):
        fail("moriarty_counterexample_identity_mismatch")


def validate_registry(
    registry: dict[str, Any],
    attacks: list[dict[str, Any]],
    reviewed_target: str,
) -> list[dict[str, Any]]:
    if (
        registry.get("schema") != REGISTRY_SCHEMA
        or registry.get("protocol") != PROTOCOL
        or registry.get("authority_effect") != "none"
    ):
        fail("moriarty_counterexample_registry_boundary_invalid")
    counterexamples = registry.get("counterexamples")
    if not isinstance(counterexamples, list) or len(counterexamples) > 1024:
        fail("moriarty_counterexample_registry_count_invalid")

    attack_by_id = {attack["id"]: attack for attack in attacks}
    unresolved = 0
    seen_ids: set[str] = set()
    for item in counterexamples:
        validate_counterexample_shape(item)
        counterexample_id = item["counterexample_id"]
        if counterexample_id in seen_ids:
            fail("moriarty_counterexample_registry_duplicate")
        seen_ids.add(counterexample_id)

        attack = attack_by_id.get(item["attack_id"])
        if attack is None:
            fail("moriarty_counterexample_attack_not_in_corpus")
        if item["family"] != attack["family"]:
            fail("moriarty_counterexample_family_mismatch")
        if item["owner_phases"] != attack["owner_phases"]:
            fail("moriarty_counterexample_owner_phase_mismatch")
        if item["boundary_ids"] != attack["boundary_ids"]:
            fail("moriarty_counterexample_boundary_set_mismatch")
        if not set(item["regression_probe_ids"]).issubset(set(attack["probe_ids"])):
            fail("moriarty_counterexample_probe_not_bound_to_attack")

        finding_target = item["target_commit"]
        if not git_commit_exists(finding_target):
            fail("moriarty_counterexample_target_commit_missing")
        if not git_is_ancestor(finding_target, reviewed_target):
            fail("moriarty_counterexample_target_not_in_reviewed_history")

        if item["status"] == "unresolved":
            unresolved += 1
            continue

        resolution = item["resolution_commit"]
        assert isinstance(resolution, str)
        if resolution == finding_target:
            fail("moriarty_resolution_commit_must_follow_finding_target")
        if not git_commit_exists(resolution):
            fail("moriarty_resolution_commit_missing")
        if not git_is_ancestor(finding_target, resolution):
            fail("moriarty_resolution_not_descendant_of_finding_target")
        if not git_is_ancestor(resolution, reviewed_target):
            fail("moriarty_resolution_not_in_reviewed_history")

    if registry.get("unresolved_counterexamples") != unresolved:
        fail("moriarty_counterexample_registry_unresolved_count_drift")
    return counterexamples


def run_probe(probe_id: str) -> dict[str, Any]:
    argv = PROBES[probe_id]
    try:
        completed = subprocess.run(
            list(argv), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=TIMEOUT_SECONDS, check=False,
        )
        return {
            "probe_id": probe_id,
            "ok": completed.returncode == 0,
            "exit_code": completed.returncode,
            "failure_kind": None if completed.returncode == 0 else "exit_nonzero",
            "stdout_sha256": bytes_ref(completed.stdout),
            "stderr_sha256": bytes_ref(completed.stderr),
            "stdout_bytes": len(completed.stdout),
            "stderr_bytes": len(completed.stderr),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        return {
            "probe_id": probe_id, "ok": False, "exit_code": None, "failure_kind": "timeout",
            "stdout_sha256": bytes_ref(stdout), "stderr_sha256": bytes_ref(stderr),
            "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
        }
    except OSError as exc:
        encoded = str(exc).encode("utf-8", errors="replace")
        return {
            "probe_id": probe_id, "ok": False, "exit_code": None, "failure_kind": "tool_error",
            "stdout_sha256": bytes_ref(b""), "stderr_sha256": bytes_ref(encoded),
            "stdout_bytes": 0, "stderr_bytes": len(encoded),
        }


def generated_counterexample(target: str, attack: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "schema": COUNTEREXAMPLE_SCHEMA,
        "counterexample_id": "sha256:" + "0" * 64,
        "target_commit": target,
        "attack_id": attack["id"],
        "family": attack["family"],
        "owner_phases": list(attack["owner_phases"]),
        "boundary_ids": list(attack["boundary_ids"]),
        "regression_probe_ids": [result["probe_id"]],
        "failure_kind": result["failure_kind"],
        "observed_exit_code": result["exit_code"],
        "stdout_sha256": result["stdout_sha256"],
        "stderr_sha256": result["stderr_sha256"],
        "stdout_bytes": result["stdout_bytes"],
        "stderr_bytes": result["stderr_bytes"],
        "status": "unresolved",
        "resolution_commit": None,
        "production_credentials_used": False,
        "production_targets_used": False,
        "constitutional_bypass_used": False,
        "authority_effect": "none",
    }
    projection = dict(item)
    projection.pop("counterexample_id")
    item["counterexample_id"] = canonical_ref(projection)
    validate_counterexample_shape(item)
    return item


def report_probe_result(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result[key] for key in (
        "probe_id", "ok", "exit_code", "stdout_sha256", "stderr_sha256",
        "stdout_bytes", "stderr_bytes",
    )}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the MORIARTY/1 exact-commit graduation harness")
    parser.add_argument("--target-commit", required=True, help="exact 40-character lowercase Git commit")
    parser.add_argument("--output", required=True, help="path for canonical moriarty-report/1 output")
    args = parser.parse_args()

    target = args.target_commit
    if not TARGET_RE.fullmatch(target):
        fail("moriarty_target_commit_invalid")
    if git_head() != target:
        fail("moriarty_target_commit_does_not_match_checkout")

    corpus = load_json(ROOT / "fixtures/phase9/attack-corpus.json")
    attacks = validate_attack_corpus(corpus)
    registry = load_json(ROOT / "fixtures/phase9/accepted-counterexamples.json")
    accepted = validate_registry(registry, attacks, target)

    requested_probe_ids: list[str] = []
    for attack in attacks:
        requested_probe_ids.extend(attack["probe_ids"])
    for item in accepted:
        requested_probe_ids.extend(item["regression_probe_ids"])

    ordered_probe_ids: list[str] = []
    seen_probes: set[str] = set()
    for probe_id in requested_probe_ids:
        if probe_id not in seen_probes:
            seen_probes.add(probe_id)
            ordered_probe_ids.append(probe_id)

    results = {probe_id: run_probe(probe_id) for probe_id in ordered_probe_ids}
    generated: list[dict[str, Any]] = []
    for attack in attacks:
        for probe_id in attack["probe_ids"]:
            result = results[probe_id]
            if not result["ok"]:
                generated.append(generated_counterexample(target, attack, result))

    unresolved_accepted = [item for item in accepted if item["status"] == "unresolved"]
    unresolved_count = len(unresolved_accepted) + len(generated)
    report = {
        "schema": REPORT_SCHEMA,
        "protocol": PROTOCOL,
        "target_commit": target,
        "corpus_ref": canonical_ref(corpus),
        "operator_profile": OPERATOR_PROFILE,
        "family_count": len(EXPECTED_FAMILIES),
        "executed_probe_count": len(ordered_probe_ids),
        "probe_results": [report_probe_result(results[probe_id]) for probe_id in ordered_probe_ids],
        "counterexamples": accepted + generated,
        "unresolved_counterexamples": unresolved_count,
        "graduated": unresolved_count == 0,
        "production_credentials_used": False,
        "production_targets_used": False,
        "constitutional_bypass_used": False,
        "security_proof": False,
        "no_counterexample_found_implies_none_exist": False,
        "authority_effect": "none",
    }

    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(serialize(report).encode("utf-8"))

    if report["graduated"]:
        print(
            f"MORIARTY/1 graduated exact commit {target}: "
            f"{len(EXPECTED_FAMILIES)} attack families, {len(ordered_probe_ids)} fixed probes, "
            "0 unresolved reproducible counterexamples"
        )
        return 0
    print(
        f"MORIARTY/1 blocked exact commit {target}: "
        f"{unresolved_count} unresolved reproducible counterexample(s); report={output}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
