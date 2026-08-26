#!/usr/bin/env python3
"""Run the provider-neutral MORIARTY/1 exact-commit adversarial graduation harness."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
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
from typing import Any, NoReturn, Sequence

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from qsol_canonical import serialize  # noqa: E402
from moriarty_isolation import (  # noqa: E402
    create_exact_export,
    create_isolated_cargo_home,
    enable_child_subreaper,
    landlock_abi_version,
    landlock_write_preexec,
    proc_fd_path,
    write_report_exclusive,
)

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

if os.name != "posix" or sys.platform != "linux":
    raise SystemExit("moriarty_requires_linux_process_and_landlock_isolation")
enable_child_subreaper()

REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


@dataclass(frozen=True)
class TrustedExecutable:
    """Bind a source-owned argv[0] label to an already-open executable inode."""

    name: str
    invocation: str
    executable: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    mode: int
    fd: int


def _directory_chain_safe(path: Path) -> bool:
    current = path.parent
    while True:
        try:
            mode = current.stat().st_mode
        except OSError:
            return False
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
        if current.parent == current:
            return True
        current = current.parent


def _trusted_executable(name: str, *, preferred: Path | None = None) -> TrustedExecutable:
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
            target_stat = target.stat()
        except OSError:
            continue
        if not target.is_file() or not os.access(invocation, os.X_OK):
            continue
        if target == ROOT or ROOT in target.parents or invocation == ROOT or ROOT in invocation.parents:
            continue
        if not _directory_chain_safe(invocation) or not _directory_chain_safe(target):
            continue
        if not stat.S_ISREG(target_stat.st_mode) or not (target_stat.st_mode & 0o111):
            continue
        try:
            fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
            pinned = os.fstat(fd)
        except OSError:
            continue
        if (
            pinned.st_dev != target_stat.st_dev
            or pinned.st_ino != target_stat.st_ino
            or pinned.st_size != target_stat.st_size
            or pinned.st_mtime_ns != target_stat.st_mtime_ns
            or stat.S_IMODE(pinned.st_mode) != stat.S_IMODE(target_stat.st_mode)
        ):
            os.close(fd)
            continue
        return TrustedExecutable(
            name=name,
            invocation=str(invocation),
            executable=str(target),
            device=pinned.st_dev,
            inode=pinned.st_ino,
            size=pinned.st_size,
            mtime_ns=pinned.st_mtime_ns,
            mode=stat.S_IMODE(pinned.st_mode),
            fd=fd,
        )
    fail(f"moriarty_trusted_executable_unavailable:{name}")


def trusted_executable_matches(trusted: TrustedExecutable) -> bool:
    """Verify that the already-open executable descriptor still names the pinned inode."""
    try:
        info = os.fstat(trusted.fd)
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and bool(info.st_mode & 0o111)
        and info.st_dev == trusted.device
        and info.st_ino == trusted.inode
        and info.st_size == trusted.size
        and info.st_mtime_ns == trusted.mtime_ns
        and stat.S_IMODE(info.st_mode) == trusted.mode
    )


def trusted_run(
    trusted: TrustedExecutable,
    args: Sequence[str],
    **kwargs: Any,
) -> subprocess.CompletedProcess[bytes]:
    if not trusted_executable_matches(trusted):
        fail(f"moriarty_trusted_executable_changed:{trusted.name}")
    inherited_fds = tuple(kwargs.pop("pass_fds", ()))
    pass_fds = tuple(dict.fromkeys((*inherited_fds, trusted.fd)))
    return subprocess.run(
        [trusted.invocation, *args],
        executable=proc_fd_path(trusted.fd),
        pass_fds=pass_fds,
        **kwargs,
    )


def _trusted_exact_path(name: str, path: Path) -> TrustedExecutable:
    invocation = path.absolute()
    try:
        target = invocation.resolve(strict=True)
        target_stat = target.stat()
    except OSError:
        fail(f"moriarty_trusted_exact_path_unavailable:{name}")
    if not target.is_file() or not os.access(invocation, os.X_OK):
        fail(f"moriarty_trusted_exact_path_not_executable:{name}")
    if target == ROOT or ROOT in target.parents or invocation == ROOT or ROOT in invocation.parents:
        fail(f"moriarty_trusted_exact_path_in_repository:{name}")
    if not _directory_chain_safe(invocation) or not _directory_chain_safe(target):
        fail(f"moriarty_trusted_exact_path_directory_unsafe:{name}")
    if not stat.S_ISREG(target_stat.st_mode) or not (target_stat.st_mode & 0o111):
        fail(f"moriarty_trusted_exact_path_type_invalid:{name}")
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    pinned = os.fstat(fd)
    if (
        pinned.st_dev != target_stat.st_dev
        or pinned.st_ino != target_stat.st_ino
        or pinned.st_size != target_stat.st_size
        or pinned.st_mtime_ns != target_stat.st_mtime_ns
        or stat.S_IMODE(pinned.st_mode) != stat.S_IMODE(target_stat.st_mode)
    ):
        os.close(fd)
        fail(f"moriarty_trusted_exact_path_changed:{name}")
    return TrustedExecutable(
        name=name,
        invocation=str(invocation),
        executable=str(target),
        device=pinned.st_dev,
        inode=pinned.st_ino,
        size=pinned.st_size,
        mtime_ns=pinned.st_mtime_ns,
        mode=stat.S_IMODE(pinned.st_mode),
        fd=fd,
    )


def _trusted_executable_optional(name: str) -> TrustedExecutable | None:
    try:
        return _trusted_executable(name)
    except SystemExit:
        return None


def _same_trusted_inode(left: TrustedExecutable, right: TrustedExecutable) -> bool:
    return left.device == right.device and left.inode == right.inode


def _rustup_discovery_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(REAL_HOME),
        "RUSTUP_HOME": str(REAL_HOME / ".rustup"),
        "CARGO_HOME": str(REAL_HOME / ".cargo"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _rustup_active_toolchain(rustup: TrustedExecutable) -> str:
    completed = trusted_run(
        rustup,
        ("show", "active-toolchain"),
        cwd=REAL_HOME,
        env=_rustup_discovery_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail("moriarty_rustup_active_toolchain_unavailable")
    try:
        toolchain = completed.stdout.decode("utf-8", errors="strict").strip().split()[0]
    except (UnicodeError, IndexError):
        fail("moriarty_rustup_active_toolchain_invalid")
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", toolchain):
        fail("moriarty_rustup_active_toolchain_invalid")
    return toolchain


def _rustup_which(rustup: TrustedExecutable, toolchain: str, component: str) -> TrustedExecutable:
    completed = trusted_run(
        rustup,
        ("which", "--toolchain", toolchain, component),
        cwd=REAL_HOME,
        env=_rustup_discovery_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"moriarty_rustup_component_unavailable:{component}")
    try:
        path = Path(completed.stdout.decode("utf-8", errors="strict").strip())
    except UnicodeError:
        fail(f"moriarty_rustup_component_path_invalid:{component}")
    toolchain_root = (REAL_HOME / ".rustup" / "toolchains").resolve(strict=True)
    resolved = path.resolve(strict=True)
    if toolchain_root not in resolved.parents:
        fail(f"moriarty_rustup_component_outside_toolchains:{component}")
    return _trusted_exact_path(component, resolved)


PYTHON_TRUSTED = _trusted_executable("python3", preferred=Path(sys.executable))
GIT_TRUSTED = _trusted_executable("git")
CARGO_ENTRY_TRUSTED = _trusted_executable("cargo")
RUSTC_ENTRY_TRUSTED = _trusted_executable("rustc")
RUSTUP_TRUSTED = _trusted_executable_optional("rustup")
RUSTUP_DISCOVERY_USED = False
RUST_TOOLCHAIN_ID: str | None = None

if RUSTUP_TRUSTED is not None and (
    _same_trusted_inode(CARGO_ENTRY_TRUSTED, RUSTUP_TRUSTED)
    or _same_trusted_inode(RUSTC_ENTRY_TRUSTED, RUSTUP_TRUSTED)
):
    if not (
        _same_trusted_inode(CARGO_ENTRY_TRUSTED, RUSTUP_TRUSTED)
        and _same_trusted_inode(RUSTC_ENTRY_TRUSTED, RUSTUP_TRUSTED)
    ):
        fail("moriarty_mixed_rustup_toolchain_entrypoints")
    RUST_TOOLCHAIN_ID = _rustup_active_toolchain(RUSTUP_TRUSTED)
    CARGO_TRUSTED = _rustup_which(RUSTUP_TRUSTED, RUST_TOOLCHAIN_ID, "cargo")
    RUSTC_TRUSTED = _rustup_which(RUSTUP_TRUSTED, RUST_TOOLCHAIN_ID, "rustc")
    if _same_trusted_inode(CARGO_TRUSTED, RUSTUP_TRUSTED) or _same_trusted_inode(RUSTC_TRUSTED, RUSTUP_TRUSTED):
        fail("moriarty_rustup_concrete_toolchain_not_pinned")
    if Path(CARGO_TRUSTED.executable).parent != Path(RUSTC_TRUSTED.executable).parent:
        fail("moriarty_rustup_toolchain_component_mismatch")
    RUSTUP_DISCOVERY_USED = True
else:
    CARGO_TRUSTED = CARGO_ENTRY_TRUSTED
    RUSTC_TRUSTED = RUSTC_ENTRY_TRUSTED

PYTHON_EXE = PYTHON_TRUSTED.invocation
GIT_EXE = GIT_TRUSTED.invocation
CARGO_EXE = CARGO_TRUSTED.invocation
RUSTC_EXE = RUSTC_TRUSTED.invocation

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
    "rust_all": (CARGO_EXE, "test", "--all-targets", "--frozen"),
}
PROBE_EXECUTABLES: dict[str, TrustedExecutable] = {
    probe_id: (CARGO_TRUSTED if probe_id == "rust_all" else PYTHON_TRUSTED)
    for probe_id in PROBES
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
        fail(f"moriarty_json_load_failed:{path}:{exc}")
    if not isinstance(value, dict):
        fail(f"moriarty_json_object_required:{path}")
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
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return trusted_run(
        GIT_TRUSTED,
        args,
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


def _probe_environment(
    home: Path,
    cargo_home: Path,
    target_dir: Path,
    temp_dir: Path,
    rustc_fd: int | None = None,
) -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "RUST_BACKTRACE": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(temp_dir),
        "TMP": str(temp_dir),
        "TEMP": str(temp_dir),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if rustc_fd is not None:
        environment["RUSTC"] = proc_fd_path(rustc_fd)
    return environment


def validate_attack_corpus(corpus: dict[str, Any]) -> list[dict[str, Any]]:
    expected_corpus_fields = {
        "schema", "protocol", "attacks", "production_credentials_allowed",
        "production_targets_allowed", "constitutional_bypass_allowed", "authority_effect",
    }
    expected_attack_fields = {"id", "family", "owner_phases", "boundary_ids", "probe_ids"}
    if set(corpus) != expected_corpus_fields:
        fail("moriarty_attack_corpus_field_set_invalid")
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
        if set(attack) != expected_attack_fields:
            fail("moriarty_attack_field_set_invalid")
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


def counterexample_identity_projection(item: dict[str, Any]) -> dict[str, Any]:
    """Hash immutable discovery/reproduction facts, not mutable resolution state."""
    return {
        key: value
        for key, value in item.items()
        if key not in {"counterexample_id", "status", "resolution_commit"}
    }


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
        or len(item["regression_probe_ids"]) != 1
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
        or isinstance(item["stdout_bytes"], bool)
        or not 0 <= item["stdout_bytes"] <= 9007199254740991
        or not isinstance(item["stderr_bytes"], int)
        or isinstance(item["stderr_bytes"], bool)
        or not 0 <= item["stderr_bytes"] <= 9007199254740991
    ):
        fail("moriarty_counterexample_boundary_invalid")

    if item["failure_kind"] == "exit_nonzero":
        if not isinstance(item["observed_exit_code"], int) or isinstance(item["observed_exit_code"], bool) or item["observed_exit_code"] == 0:
            fail("moriarty_exit_failure_requires_nonzero_exit_code")
    elif item["observed_exit_code"] is not None:
        fail("moriarty_nonexit_failure_exit_code_must_be_null")

    if item["status"] == "unresolved":
        if item["resolution_commit"] is not None:
            fail("moriarty_unresolved_counterexample_has_resolution_commit")
    elif not isinstance(item["resolution_commit"], str) or not TARGET_RE.fullmatch(item["resolution_commit"]):
        fail("moriarty_resolved_counterexample_missing_resolution_commit")

    if item["counterexample_id"] != canonical_ref(counterexample_identity_projection(item)):
        fail("moriarty_counterexample_identity_mismatch")


def validate_registry(
    registry: dict[str, Any],
    attacks: list[dict[str, Any]],
    reviewed_target: str,
) -> list[dict[str, Any]]:
    expected_registry_fields = {
        "schema", "protocol", "counterexamples", "unresolved_counterexamples", "authority_effect",
    }
    if set(registry) != expected_registry_fields:
        fail("moriarty_counterexample_registry_field_set_invalid")
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

    if type(registry.get("unresolved_counterexamples")) is not int:
        fail("moriarty_counterexample_registry_unresolved_type_invalid")
    if registry.get("unresolved_counterexamples") != unresolved:
        fail("moriarty_counterexample_registry_unresolved_count_drift")
    return counterexamples


def _process_parent_map() -> dict[int, int]:
    parents: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            continue
        for line in status.splitlines():
            if line.startswith("PPid:"):
                try:
                    parents[int(entry.name)] = int(line.split()[1])
                except (ValueError, IndexError):
                    pass
                break
    return parents


def _descendant_pids(root_pid: int) -> set[int]:
    parents = _process_parent_map()
    descendants: set[int] = set()
    frontier = {root_pid}
    while frontier:
        next_frontier: set[int] = set()
        for pid, parent in parents.items():
            if parent in frontier and pid not in descendants:
                descendants.add(pid)
                next_frontier.add(pid)
        frontier = next_frontier
    return descendants


def _kill_probe_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    # PR_SET_CHILD_SUBREAPER keeps double-fork/setsid escapees under this
    # harness. Re-scan a few times to close fork-vs-kill races.
    for _ in range(4):
        descendants = _descendant_pids(os.getpid())
        if not descendants:
            break
        for pid in sorted(descendants, reverse=True):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.01)


def _reap_adopted_children() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def bounded_output_update(digest: Any, count: int, chunk: bytes) -> tuple[int, bool]:
    remaining = max(0, MAX_PROBE_OUTPUT_BYTES - count)
    accepted = chunk[:remaining]
    if accepted:
        digest.update(accepted)
    return count + len(accepted), len(chunk) > remaining


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


def run_probe(
    probe_id: str,
    home: Path,
    source_root: Path,
    cargo_home: Path,
    target_dir: Path,
) -> dict[str, Any]:
    if not tracked_tree_clean():
        return _probe_failure_result(probe_id, "tool_error", b"tracked_tree_dirty_before_probe")
    if landlock_abi_version() < 3:
        return _probe_failure_result(probe_id, "tool_error", b"landlock_abi3_unavailable")
    home.mkdir(mode=0o700, parents=False, exist_ok=False)
    target_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    temp_dir = target_dir.parent / f"tmp-{target_dir.name}"
    temp_dir.mkdir(mode=0o700, parents=False, exist_ok=False)

    argv = PROBES[probe_id]
    trusted = PROBE_EXECUTABLES[probe_id]
    if not trusted_executable_matches(trusted):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_executable_fd_invalid_before_probe")
    rustc_fd: int | None = None
    pass_fds = (trusted.fd,)
    if probe_id == "rust_all":
        if not trusted_executable_matches(RUSTC_TRUSTED):
            return _probe_failure_result(probe_id, "tool_error", b"trusted_rustc_fd_invalid_before_probe")
        rustc_fd = RUSTC_TRUSTED.fd
        pass_fds = (trusted.fd, RUSTC_TRUSTED.fd)

    preexec = landlock_write_preexec((home, cargo_home, target_dir, temp_dir))
    try:
        process = subprocess.Popen(
            list(argv),
            executable=proc_fd_path(trusted.fd),
            pass_fds=pass_fds,
            cwd=source_root,
            env=_probe_environment(home, cargo_home, target_dir, temp_dir, rustc_fd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=preexec,
            bufsize=0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _probe_failure_result(probe_id, "tool_error", str(exc).encode("utf-8", errors="replace"))

    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    counts = {"stdout": 0, "stderr": 0}
    deadline = time.monotonic() + TIMEOUT_SECONDS
    drain_deadline: float | None = None
    failure_kind: str | None = None

    try:
        while selector.get_map():
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0 and failure_kind is None:
                failure_kind = "timeout"
                _kill_probe_tree(process)
                drain_deadline = now + 2.0
            if process.poll() is not None and failure_kind is None and selector.get_map():
                # The direct child exited but a descendant retained a pipe.
                failure_kind = "tool_error"
                _kill_probe_tree(process)
                drain_deadline = now + 2.0
            if failure_kind is not None and drain_deadline is None:
                drain_deadline = now + 2.0
            if drain_deadline is not None and now >= drain_deadline:
                for key in list(selector.get_map().values()):
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                    try:
                        key.fileobj.close()
                    except OSError:
                        pass
                break

            timeout = 0.1
            if failure_kind is None:
                timeout = max(0.0, min(0.1, remaining))
            elif drain_deadline is not None:
                timeout = max(0.0, min(0.1, drain_deadline - now))
            events = selector.select(timeout=timeout)
            for key, _ in events:
                stream_name = key.data
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                counts[stream_name], overflow = bounded_output_update(
                    digests[stream_name], counts[stream_name], chunk
                )
                if overflow and failure_kind is None:
                    failure_kind = "tool_error"
                    _kill_probe_tree(process)
                    drain_deadline = time.monotonic() + 2.0

        if process.poll() is None:
            wait_budget = 1.0 if failure_kind is not None else max(0.0, deadline - time.monotonic())
            try:
                return_code = process.wait(timeout=wait_budget)
            except subprocess.TimeoutExpired:
                failure_kind = failure_kind or "timeout"
                _kill_probe_tree(process)
                try:
                    return_code = process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    return_code = None
        else:
            return_code = process.returncode
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass

    leaked_descendants = _descendant_pids(os.getpid())
    if leaked_descendants:
        failure_kind = failure_kind or "tool_error"
        _kill_probe_tree(process)
    _reap_adopted_children()

    if not tracked_tree_clean():
        return _probe_failure_result(probe_id, "tool_error", b"tracked_tree_dirty_after_probe")
    if not trusted_executable_matches(trusted):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_executable_fd_invalid_after_probe")
    if probe_id == "rust_all" and not trusted_executable_matches(RUSTC_TRUSTED):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_rustc_fd_invalid_after_probe")

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
    item["counterexample_id"] = canonical_ref(counterexample_identity_projection(item))
    validate_counterexample_shape(item)
    return item


def counterexample_failure_matches(item: dict[str, Any], result: dict[str, Any]) -> bool:
    return (
        result["ok"] is False
        and result["failure_kind"] == item["failure_kind"]
        and result["exit_code"] == item["observed_exit_code"]
        and result["stdout_sha256"] == item["stdout_sha256"]
        and result["stderr_sha256"] == item["stderr_sha256"]
        and result["stdout_bytes"] == item["stdout_bytes"]
        and result["stderr_bytes"] == item["stderr_bytes"]
    )


def verify_resolved_counterexamples(
    accepted: list[dict[str, Any]],
    workspace: Path,
    cargo_home: Path,
) -> None:
    for index, item in enumerate(accepted):
        if item["status"] != "resolved":
            continue
        probe_id = item["regression_probe_ids"][0]
        before_source = create_exact_export(
            item["target_commit"], workspace, lambda *args: git(*args).returncode, f"resolved-{index}-before"
        )
        before = run_probe(
            probe_id,
            workspace / f"resolved-{index}-before-home",
            before_source,
            cargo_home,
            workspace / f"resolved-{index}-before-target",
        )
        if not counterexample_failure_matches(item, before):
            fail("moriarty_resolution_target_failure_not_reproduced")

        resolution = item["resolution_commit"]
        assert isinstance(resolution, str)
        after_source = create_exact_export(
            resolution, workspace, lambda *args: git(*args).returncode, f"resolved-{index}-after"
        )
        after = run_probe(
            probe_id,
            workspace / f"resolved-{index}-after-home",
            after_source,
            cargo_home,
            workspace / f"resolved-{index}-after-target",
        )
        if after["ok"] is not True or after["exit_code"] != 0:
            fail("moriarty_resolution_fix_probe_not_green")


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

    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-work-") as work_dir:
        workspace = Path(work_dir)
        cargo_home = create_isolated_cargo_home(REAL_HOME / ".cargo", workspace)
        if landlock_abi_version() < 3:
            fail("moriarty_landlock_abi3_required")
        control_source = create_exact_export(
            target, workspace, lambda *git_args: git(*git_args).returncode, "control"
        )
        if not (control_source / "Cargo.lock").is_file():
            fail("moriarty_committed_cargo_lock_missing")

        corpus = load_json(control_source / "fixtures/phase9/attack-corpus.json")
        attacks = validate_attack_corpus(corpus)
        registry = load_json(control_source / "fixtures/phase9/accepted-counterexamples.json")
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

        results: dict[str, dict[str, Any]] = {}
        for probe_index, probe_id in enumerate(ordered_probe_ids):
            probe_source = create_exact_export(
                target,
                workspace,
                lambda *git_args: git(*git_args).returncode,
                f"probe-{probe_index}-{probe_id}",
            )
            results[probe_id] = run_probe(
                probe_id,
                workspace / f"home-{probe_id}",
                probe_source,
                cargo_home,
                workspace / f"target-{probe_id}",
            )
        verify_resolved_counterexamples(accepted, workspace, cargo_home)

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
    write_report_exclusive(output, encoded, ROOT)
    if git_head() != target or not tracked_tree_clean():
        fail("moriarty_target_changed_during_report_publication")

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
