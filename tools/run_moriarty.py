#!/usr/bin/env python3
"""Run the provider-neutral MORIARTY/1 exact-commit adversarial graduation harness."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
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
MAX_PROBE_OUTPUT_BYTES = 1_048_576
MAX_ACCEPTED_COUNTEREXAMPLES = 32
MAX_REPORT_COUNTEREXAMPLES = 48
MAX_REPORT_BYTES = 65_536

if os.name != "posix":
    raise SystemExit("moriarty_requires_posix_process_group_isolation")

REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def _trusted_executable(name: str, *, preferred: Path | None = None) -> str:
    candidates: list[Path] = []
    if preferred is not None:
        candidates.append(preferred)
    candidates.extend([
        Path("/usr/local/cargo/bin") / name,
        Path("/usr/local/bin") / name,
        Path("/usr/bin") / name,
        Path("/bin") / name,
        REAL_HOME / ".cargo" / "bin" / name,
    ])
    for candidate in candidates:
        invocation = candidate.absolute()
        try:
            target = invocation.resolve(strict=True)
        except OSError:
            continue
        if not target.is_file() or not os.access(invocation, os.X_OK):
            continue
        if target == ROOT or ROOT in target.parents or invocation == ROOT or ROOT in invocation.parents:
            continue
        try:
            invocation_mode = invocation.parent.stat().st_mode
            target_mode = target.parent.stat().st_mode
        except OSError:
            continue
        if invocation_mode & stat.S_IWOTH or target_mode & stat.S_IWOTH:
            continue
        # Validate the resolved target, but preserve the original trusted path for
        # invocation. Rustup-style multicall shims select Cargo/Rustc behavior from
        # argv[0], so executing the resolved `rustup` target directly would change
        # the command's semantics even though the symlink itself is trusted.
        return str(invocation)
    fail(f"moriarty_trusted_executable_unavailable:{name}")


PYTHON_EXE = _trusted_executable("python3", preferred=Path(sys.executable))
GIT_EXE = _trusted_executable("git")
CARGO_EXE = _trusted_executable("cargo")
RUSTC_EXE = _trusted_executable("rustc")

# Source-owned and closed. An external/model candidate finding must be reduced to
# one of these deterministic local probes before it is eligible for the accepted registry.
PROBES: dict[str, tuple[str, ...]] = {
    "constitution": (PYTHON_EXE, "tools/validate_constitution.py"),
    "phase0": (PYTHON_EXE, "tools/validate_phase0_gate.py"),
    "phase1": (PYTHON_EXE, "tools/validate_phase1_gate.py"),
    "phase2": (PYTHON_EXE, "tools/validate_phase2_gate.py"),
    "phase3": (PYTHON_EXE, "tools/validate_phase3_gate.py"),
    "phase4": (PYTHON_EXE, "tools/validate_phase4_gate.py"),
    "phase5a": (PYTHON_EXE, "tools/validate_phase5a_gate.py"),
    "phase5": (PYTHON_EXE, "tools/validate_phase5_gate.py"),
    "phase5c": (PYTHON_EXE, "tools/validate_phase5c_gate.py"),
    "phase6": (PYTHON_EXE, "tools/validate_phase6_gate.py"),
    "phase7": (PYTHON_EXE, "tools/validate_phase7_gate.py"),
    "phase8": (PYTHON_EXE, "tools/validate_phase8_gate.py"),
    "rust_all": (CARGO_EXE, "test", "--all-targets", "--offline"),
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


def _git_env() -> dict[str, str]:
    return {
        "PATH": os.pathsep.join(sorted({str(Path(GIT_EXE).parent), "/usr/bin", "/bin"})),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [GIT_EXE, *args],
        cwd=ROOT,
        env=_git_env(),
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


def tracked_tree_clean() -> bool:
    return (
        git("diff", "--quiet", "HEAD", "--").returncode == 0
        and git("diff", "--cached", "--quiet", "--").returncode == 0
    )


def git_commit_exists(commit: str) -> bool:
    return bool(TARGET_RE.fullmatch(commit)) and git("cat-file", "-e", f"{commit}^{{commit}}").returncode == 0


def git_is_ancestor(ancestor: str, descendant: str) -> bool:
    return git("merge-base", "--is-ancestor", ancestor, descendant).returncode == 0


def _probe_environment(home: Path) -> dict[str, str]:
    cargo_home = REAL_HOME / ".cargo"
    for credentials in (cargo_home / "credentials", cargo_home / "credentials.toml"):
        if credentials.exists():
            fail("moriarty_cargo_credentials_present")
    safe_path = os.pathsep.join(dict.fromkeys([
        str(Path(PYTHON_EXE).parent),
        str(Path(CARGO_EXE).parent),
        str(Path(RUSTC_EXE).parent),
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ]))
    return {
        "PATH": safe_path,
        "HOME": str(home),
        "CARGO_HOME": str(cargo_home),
        "RUSTUP_HOME": str(REAL_HOME / ".rustup"),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "RUSTC": RUSTC_EXE,
        "RUST_BACKTRACE": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


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
    if not isinstance(counterexamples, list) or len(counterexamples) > MAX_ACCEPTED_COUNTEREXAMPLES:
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


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _probe_failure_result(probe_id: str, kind: str, diagnostic: bytes) -> dict[str, Any]:
    return {
        "probe_id": probe_id,
        "ok": False,
        "exit_code": None,
        "failure_kind": kind,
        "stdout_sha256": bytes_ref(b""),
        "stderr_sha256": bytes_ref(diagnostic),
        "stdout_bytes": 0,
        "stderr_bytes": len(diagnostic),
    }


def run_probe(probe_id: str, home: Path) -> dict[str, Any]:
    if not tracked_tree_clean():
        return _probe_failure_result(probe_id, "tool_error", b"tracked_tree_dirty_before_probe")

    argv = PROBES[probe_id]
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=ROOT,
            env=_probe_environment(home),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as exc:
        return _probe_failure_result(probe_id, "tool_error", str(exc).encode("utf-8", errors="replace"))

    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    counts = {"stdout": 0, "stderr": 0}
    deadline = time.monotonic() + TIMEOUT_SECONDS
    failure_kind: str | None = None

    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0 and failure_kind is None:
                failure_kind = "timeout"
                _kill_process_group(process)
            events = selector.select(timeout=max(0.0, min(0.1, remaining)) if failure_kind is None else 0.1)
            for key, _ in events:
                stream_name = key.data
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                counts[stream_name] += len(chunk)
                digests[stream_name].update(chunk)
                if counts[stream_name] > MAX_PROBE_OUTPUT_BYTES and failure_kind is None:
                    failure_kind = "tool_error"
                    _kill_process_group(process)
            if process.poll() is not None and not events:
                time.sleep(0.01)
        remaining = max(0.0, deadline - time.monotonic())
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            failure_kind = failure_kind or "timeout"
            _kill_process_group(process)
            process.wait(timeout=1)
            return_code = None
    except subprocess.TimeoutExpired:
        failure_kind = failure_kind or "timeout"
        _kill_process_group(process)
        return_code = None
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass

    if not tracked_tree_clean():
        return _probe_failure_result(probe_id, "tool_error", b"tracked_tree_dirty_after_probe")
    if counts["stdout"] > MAX_PROBE_OUTPUT_BYTES or counts["stderr"] > MAX_PROBE_OUTPUT_BYTES:
        failure_kind = "tool_error"

    if failure_kind is None and return_code == 0:
        ok = True
    else:
        ok = False
        if failure_kind is None:
            failure_kind = "exit_nonzero"

    return {
        "probe_id": probe_id,
        "ok": ok,
        "exit_code": return_code if failure_kind == "exit_nonzero" or ok else None,
        "failure_kind": failure_kind,
        "stdout_sha256": "sha256:" + digests["stdout"].hexdigest(),
        "stderr_sha256": "sha256:" + digests["stderr"].hexdigest(),
        "stdout_bytes": counts["stdout"],
        "stderr_bytes": counts["stderr"],
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
    if not tracked_tree_clean():
        fail("moriarty_target_tracked_tree_dirty")

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

    probe_users: dict[str, list[dict[str, Any]]] = {probe_id: [] for probe_id in ordered_probe_ids}
    for attack in attacks:
        for probe_id in attack["probe_ids"]:
            probe_users.setdefault(probe_id, []).append(attack)

    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-home-") as home_dir:
        home = Path(home_dir)
        results = {probe_id: run_probe(probe_id, home) for probe_id in ordered_probe_ids}

    generated: list[dict[str, Any]] = []
    for probe_id, result in results.items():
        if result["ok"]:
            continue
        owners = probe_users.get(probe_id, [])
        # Shared infrastructure/regression probes block graduation through the
        # probe result, but they do not fabricate family-specific findings.
        if len(owners) == 1 and result["failure_kind"] in {"exit_nonzero", "timeout", "tool_error"}:
            generated.append(generated_counterexample(target, owners[0], result))

    unresolved_accepted = [item for item in accepted if item["status"] == "unresolved"]
    unresolved_count = len(unresolved_accepted) + len(generated)
    all_probes_ok = all(result["ok"] for result in results.values())

    if git_head() != target or not tracked_tree_clean():
        fail("moriarty_target_changed_during_probes")

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
        "graduated": unresolved_count == 0 and all_probes_ok,
        "production_credentials_used": False,
        "production_targets_used": False,
        "constitutional_bypass_used": False,
        "security_proof": False,
        "no_counterexample_found_implies_none_exist": False,
        "authority_effect": "none",
    }

    if len(report["counterexamples"]) > MAX_REPORT_COUNTEREXAMPLES:
        fail("moriarty_report_counterexample_count_exceeded")
    encoded = serialize(report).encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        fail("moriarty_report_size_exceeded")

    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encoded)

    if report["graduated"]:
        print(
            f"MORIARTY/1 graduated exact commit {target}: "
            f"{len(EXPECTED_FAMILIES)} attack families, {len(ordered_probe_ids)} fixed probes, "
            "0 unresolved reproducible counterexamples"
        )
        return 0
    print(
        f"MORIARTY/1 blocked exact commit {target}: "
        f"{unresolved_count} unresolved reproducible counterexample(s), "
        f"{sum(not result['ok'] for result in results.values())} failed probe(s); report={output}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
