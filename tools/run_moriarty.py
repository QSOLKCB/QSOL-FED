#!/usr/bin/env python3
"""Run the provider-neutral MORIARTY/1 exact-commit adversarial graduation harness."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import builtins
import types
import json
import os
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any, NoReturn, Sequence

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.dont_write_bytecode = True
_BOOTSTRAP_GIT = Path("/usr/bin/git")
_BOOTSTRAP_TARGET_RE = re.compile(r"^[0-9a-f]{40}$")
try:
    _BOOTSTRAP_GIT_FD = os.open(_BOOTSTRAP_GIT, os.O_RDONLY | os.O_CLOEXEC)
    _BOOTSTRAP_GIT_INFO = os.fstat(_BOOTSTRAP_GIT_FD)
except OSError:
    raise SystemExit("moriarty_bootstrap_system_git_unavailable")
if not stat.S_ISREG(_BOOTSTRAP_GIT_INFO.st_mode) or not (_BOOTSTRAP_GIT_INFO.st_mode & 0o111):
    raise SystemExit("moriarty_bootstrap_system_git_invalid")


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
    try:
        current = os.fstat(_BOOTSTRAP_GIT_FD)
    except OSError:
        raise SystemExit("moriarty_bootstrap_system_git_unavailable")
    if (
        current.st_dev != _BOOTSTRAP_GIT_INFO.st_dev
        or current.st_ino != _BOOTSTRAP_GIT_INFO.st_ino
        or current.st_size != _BOOTSTRAP_GIT_INFO.st_size
        or current.st_mtime_ns != _BOOTSTRAP_GIT_INFO.st_mtime_ns
        or stat.S_IMODE(current.st_mode) != stat.S_IMODE(_BOOTSTRAP_GIT_INFO.st_mode)
    ):
        raise SystemExit("moriarty_bootstrap_system_git_changed")
    return subprocess.run(
        [str(_BOOTSTRAP_GIT), *args],
        executable=f"/proc/self/fd/{_BOOTSTRAP_GIT_FD}",
        pass_fds=(_BOOTSTRAP_GIT_FD,),
        cwd=ROOT,
        env=_bootstrap_git_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        close_fds=True,
    )


def _bootstrap_target() -> str:
    values: list[str] = []
    index = 1
    while index < len(sys.argv):
        argument = sys.argv[index]
        if argument == "--target-commit":
            if index + 1 >= len(sys.argv) or sys.argv[index + 1].startswith("--"):
                raise SystemExit("moriarty_bootstrap_target_missing")
            values.append(sys.argv[index + 1])
            index += 2
            continue
        if argument.startswith("--target-commit="):
            values.append(argument.split("=", 1)[1])
        index += 1
    if len(values) > 1:
        raise SystemExit("moriarty_bootstrap_target_duplicate")
    target: str | None = values[0] if values else None
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
if Path(__file__).read_bytes() != _bootstrap_verified_blob(_BOOTSTRAP_TARGET, "tools/run_moriarty.py"):
    raise SystemExit("moriarty_bootstrap_runner_source_mismatch")
_qsol_canonical = _load_verified_source_module("qsol_canonical", _BOOTSTRAP_TARGET)
_moriarty_isolation = _load_verified_source_module("moriarty_isolation", _BOOTSTRAP_TARGET)
serialize = _qsol_canonical.serialize
create_empty_cargo_home = _moriarty_isolation.create_empty_cargo_home
create_exact_export = _moriarty_isolation.create_exact_export
create_isolated_cargo_home = _moriarty_isolation.create_isolated_cargo_home
create_verified_cargo_template = _moriarty_isolation.create_verified_cargo_template
cargo_cache_root = _moriarty_isolation.cargo_cache_root
enable_child_subreaper = _moriarty_isolation.enable_child_subreaper
landlock_abi_version = _moriarty_isolation.landlock_abi_version
network_seccomp_supported = _moriarty_isolation.network_seccomp_supported
probe_isolation_preexec = _moriarty_isolation.probe_isolation_preexec
probe_writable_tree_within_limits = _moriarty_isolation.probe_writable_tree_within_limits
probe_quota_root = _moriarty_isolation.probe_quota_root
probe_cgroup_root = _moriarty_isolation.probe_cgroup_root
probe_cgroup_pids = _moriarty_isolation.probe_cgroup_pids
kill_probe_cgroup = _moriarty_isolation.kill_probe_cgroup
proc_fd_path = _moriarty_isolation.proc_fd_path
stage_executable_from_fd = _moriarty_isolation.stage_executable_from_fd
stage_rust_toolchain_runtime = _moriarty_isolation.stage_rust_toolchain_runtime
write_report_exclusive = _moriarty_isolation.write_report_exclusive

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
MAX_REPORT_BYTES = 512 * 1024
MAX_GIT_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_GIT_TREE_METADATA_BYTES = 16 * 1024 * 1024
MAX_GIT_TREE_ENTRIES = 32_768
MAX_GIT_TREE_DEPTH = 64
MAX_GIT_PATH_BYTES = 4096
MAX_DIAGNOSTIC_SAMPLE_BYTES = 65_536
POST_EXIT_DRAIN_SECONDS = 2.0
TERMINATION_DRAIN_SECONDS = 2.0
HARNESS_PATHS = ("tools/run_moriarty.py", "tools/moriarty_isolation.py", "tools/qsol_canonical.py")

if os.name != "posix" or sys.platform != "linux":
    raise SystemExit("moriarty_requires_linux_process_and_landlock_isolation")
enable_child_subreaper()

REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
_cache_value = os.environ.get("MORIARTY_CARGO_CACHE_ROOT")
if _cache_value:
    try:
        CARGO_CACHE_HOME = Path(_cache_value).resolve(strict=True)
    except OSError:
        raise SystemExit("moriarty_cargo_cache_root_unavailable")
    if not CARGO_CACHE_HOME.is_dir() or CARGO_CACHE_HOME == ROOT or ROOT in CARGO_CACHE_HOME.parents:
        raise SystemExit("moriarty_cargo_cache_root_invalid")
else:
    CARGO_CACHE_HOME = REAL_HOME / ".cargo"
_ACTIVE_PROBE_WRITABLE_ROOT: Path | None = None
_ACTIVE_PROBE_CGROUP: Path | None = None


def _probe_writable_root() -> Path:
    if _ACTIVE_PROBE_WRITABLE_ROOT is None:
        fail("moriarty_probe_quota_root_not_initialized")
    return _ACTIVE_PROBE_WRITABLE_ROOT


def _probe_cgroup() -> Path:
    if _ACTIVE_PROBE_CGROUP is None:
        fail("moriarty_probe_cgroup_not_initialized")
    return _ACTIVE_PROBE_CGROUP


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


def trusted_capture_bounded(
    trusted: TrustedExecutable,
    args: Sequence[str],
    *,
    limit: int,
    cwd: Path,
    env: dict[str, str],
    overflow_error: str,
    command_error: str,
) -> bytes:
    """Capture trusted stdout incrementally without exceeding `limit` bytes."""
    if limit < 0 or not trusted_executable_matches(trusted):
        fail(f"moriarty_trusted_capture_invalid:{trusted.name}")
    process = subprocess.Popen(
        [trusted.invocation, *args],
        executable=proc_fd_path(trusted.fd),
        pass_fds=(trusted.fd,),
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    assert process.stdout is not None
    output = bytearray()
    try:
        while True:
            chunk = process.stdout.read(min(65_536, limit - len(output) + 1))
            if not chunk:
                break
            if len(output) + len(chunk) > limit:
                process.kill()
                process.wait()
                fail(overflow_error)
            output.extend(chunk)
        return_code = process.wait()
    finally:
        process.stdout.close()
    if return_code != 0:
        fail(command_error)
    if not trusted_executable_matches(trusted):
        fail(f"moriarty_trusted_executable_changed:{trusted.name}")
    return bytes(output)


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



def _direct_toolchain_root(cargo: TrustedExecutable, rustc: TrustedExecutable) -> Path:
    """Accept only a genuinely self-contained direct Rust toolchain.

    Distribution layouts whose sysroot is /usr or /usr/local are deliberately
    rejected: staging those roots would copy unrelated system trees and would
    not constitute a bounded toolchain snapshot.
    """
    completed = trusted_run(
        rustc,
        ("--print", "sysroot"),
        cwd=REAL_HOME,
        env={"PATH": "/usr/bin:/bin", "HOME": str(REAL_HOME), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail("moriarty_direct_rustc_sysroot_unavailable")
    try:
        root = Path(completed.stdout.decode("utf-8", errors="strict").strip()).resolve(strict=True)
    except (UnicodeError, OSError):
        fail("moriarty_direct_rustc_sysroot_invalid")
    expected_bin = root / "bin"
    system_roots = {Path("/"), Path("/usr"), Path("/usr/local")}
    if (
        root in system_roots
        or Path(cargo.executable).parent != expected_bin
        or Path(rustc.executable).parent != expected_bin
        or not (root / "lib" / "rustlib").is_dir()
        or not (expected_bin / "rustdoc").is_file()
    ):
        fail("moriarty_direct_toolchain_not_self_contained")
    return root


_python_preferred = Path(sys.executable)
try:
    _python_preferred_resolved = _python_preferred.resolve(strict=True)
except OSError:
    _python_preferred_resolved = Path("/")
if Path("/usr") not in _python_preferred_resolved.parents:
    _python_preferred = None
PYTHON_TRUSTED = _trusted_executable("python3", preferred=_python_preferred)
if Path("/usr") not in Path(PYTHON_TRUSTED.executable).resolve(strict=True).parents:
    fail("moriarty_python_runtime_outside_system_prefix")
GIT_TRUSTED = _trusted_executable("git")
RUST_SNAPSHOT_ROOT: Path | None = None
_snapshot_value = os.environ.get("MORIARTY_RUST_TOOLCHAIN_ROOT")
if _snapshot_value:
    try:
        RUST_SNAPSHOT_ROOT = Path(_snapshot_value).resolve(strict=True)
    except OSError:
        fail("moriarty_ci_rust_snapshot_unavailable")
    if (
        not RUST_SNAPSHOT_ROOT.is_dir()
        or RUST_SNAPSHOT_ROOT == ROOT
        or ROOT in RUST_SNAPSHOT_ROOT.parents
    ):
        fail("moriarty_ci_rust_snapshot_invalid")
    CARGO_ENTRY_TRUSTED = _trusted_exact_path("cargo", RUST_SNAPSHOT_ROOT / "bin" / "cargo")
    RUSTC_ENTRY_TRUSTED = _trusted_exact_path("rustc", RUST_SNAPSHOT_ROOT / "bin" / "rustc")
    RUSTUP_TRUSTED = None
    RUSTUP_DISCOVERY_USED = False
    RUST_TOOLCHAIN_ID: str | None = "ci-snapshot"
    CARGO_TRUSTED = CARGO_ENTRY_TRUSTED
    RUSTC_TRUSTED = RUSTC_ENTRY_TRUSTED
else:
    CARGO_ENTRY_TRUSTED = _trusted_executable("cargo")
    RUSTC_ENTRY_TRUSTED = _trusted_executable("rustc")
    RUSTUP_TRUSTED = _trusted_executable_optional("rustup")
    RUSTUP_DISCOVERY_USED = False
    RUST_TOOLCHAIN_ID = None
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


def _trusted_version(trusted: TrustedExecutable) -> str:
    completed = trusted_run(
        trusted,
        ("--version",),
        cwd=REAL_HOME,
        env={"PATH": "/usr/bin:/bin", "HOME": str(REAL_HOME), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"moriarty_toolchain_version_unavailable:{trusted.name}")
    payload = completed.stdout or completed.stderr
    try:
        return payload.decode("utf-8", errors="strict").strip()
    except UnicodeError:
        fail(f"moriarty_toolchain_version_invalid:{trusted.name}")


def _require_expected_toolchain_versions() -> None:
    bindings = (
        (PYTHON_TRUSTED, "MORIARTY_EXPECTED_PYTHON_VERSION"),
        (RUSTC_TRUSTED, "MORIARTY_EXPECTED_RUSTC_VERSION"),
        (CARGO_TRUSTED, "MORIARTY_EXPECTED_CARGO_VERSION"),
    )
    for trusted, variable in bindings:
        expected = os.environ.get(variable)
        if expected is not None and _trusted_version(trusted) != expected:
            fail(f"moriarty_toolchain_version_drift:{trusted.name}")


_require_expected_toolchain_versions()

PYTHON_EXE = PYTHON_TRUSTED.invocation
GIT_EXE = GIT_TRUSTED.invocation
CARGO_EXE = CARGO_TRUSTED.invocation
RUSTC_EXE = RUSTC_TRUSTED.invocation

# Source-owned and closed. An external/model candidate finding must be reduced to
# one of these deterministic local probes before it is eligible for the accepted registry.
# Python probes run with -I and execute the validator through a tiny bootstrap. The
# bootstrap never adds the exact-export tools directory to sys.path; instead a custom
# finder serves exact-export tool modules only when their names do not collide with a
# standard-library module. This prevents tracked tools/json.py-style shadowing.
PYTHON_PROBE_BOOTSTRAP = r"""
import builtins
import importlib.abc
import importlib.util
import pathlib
import sys

validator = pathlib.Path(sys.argv[1]).resolve(strict=True)
root = validator.parents[1]
tools = root / "tools"

class ExactToolsLoader(importlib.abc.Loader):
    def __init__(self, path):
        self.path = path
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        module.__file__ = str(self.path)
        module.__cached__ = None
        code = compile(self.path.read_bytes(), str(self.path), "exec", dont_inherit=True, optimize=0)
        getattr(builtins, "exec")(code, module.__dict__)

class ExactToolsFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if "." in fullname or fullname in sys.stdlib_module_names:
            return None
        candidate = tools / (fullname + ".py")
        if not candidate.is_file():
            return None
        return importlib.util.spec_from_loader(fullname, ExactToolsLoader(candidate))

sys.meta_path.insert(0, ExactToolsFinder())
sys.path[:] = [entry for entry in sys.path if entry not in {"", str(root), str(tools)}]
sys.argv = [str(validator)]
namespace = {"__name__": "__main__", "__file__": str(validator), "__package__": None, "__cached__": None}
getattr(builtins, "exec")(compile(validator.read_bytes(), str(validator), "exec", dont_inherit=True, optimize=0), namespace)
"""

PYTHON_VALIDATORS = {
    "constitution": "tools/validate_constitution.py",
    "phase0": "tools/validate_phase0_gate.py",
    "phase1": "tools/validate_phase1_gate.py",
    "phase2": "tools/validate_phase2_gate.py",
    "phase3": "tools/validate_phase3_gate.py",
    "phase4": "tools/validate_phase4_gate.py",
    "phase5a": "tools/validate_phase5a_gate.py",
    "phase5": "tools/validate_phase5_gate.py",
    "phase5c": "tools/validate_phase5c_gate.py",
    "phase6": "tools/validate_phase6_gate.py",
    "phase7": "tools/validate_phase7_gate.py",
    "phase8": "tools/validate_phase8_gate.py",
}
PROBES: dict[str, tuple[str, ...]] = {
    probe_id: (PYTHON_EXE, "-I", "-c", PYTHON_PROBE_BOOTSTRAP, path)
    for probe_id, path in PYTHON_VALIDATORS.items()
}
PROBES["rust_all"] = (CARGO_EXE, "test", "--all-targets", "--frozen")

EXPECTED_RUST_BIN_TARGETS = frozenset({
    "qsol-fed.rs",
    "qsol-fed-bundle.rs",
    "qsol-fed-oracle.rs",
    "qsol-fed-sdk-conformance.rs",
})


def _cargo_dependency_table_reject_path(table: Any, label: str) -> None:
    if table is None:
        return
    if not isinstance(table, dict):
        fail(f"moriarty_cargo_dependency_table_invalid:{label}")
    for dependency_name, specification in table.items():
        if not isinstance(dependency_name, str) or not dependency_name:
            fail(f"moriarty_cargo_dependency_name_invalid:{label}")
        if isinstance(specification, dict) and "path" in specification:
            fail(f"moriarty_cargo_path_dependency_forbidden:{label}:{dependency_name}")


def _reject_repository_cargo_execution_hooks(manifest: dict[str, Any], source_root: Path) -> None:
    package = manifest.get("package")
    if not isinstance(package, dict):
        fail("moriarty_cargo_package_identity_drift")
    if package.get("build") not in (None, False) or os.path.lexists(source_root / "build.rs"):
        fail("moriarty_cargo_package_build_script_forbidden")
    if "links" in package:
        fail("moriarty_cargo_package_links_forbidden")
    if "patch" in manifest or "replace" in manifest:
        fail("moriarty_cargo_dependency_override_forbidden")

    for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(table_name)
        _cargo_dependency_table_reject_path(table, table_name)
        if table_name == "build-dependencies" and isinstance(table, dict) and table:
            fail("moriarty_cargo_build_dependencies_forbidden")

    targets = manifest.get("target")
    if targets is None:
        return
    if not isinstance(targets, dict):
        fail("moriarty_cargo_target_dependency_table_invalid")
    for selector, target_tables in targets.items():
        if not isinstance(selector, str) or not isinstance(target_tables, dict):
            fail("moriarty_cargo_target_dependency_table_invalid")
        for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
            table = target_tables.get(table_name)
            _cargo_dependency_table_reject_path(table, f"target:{selector}:{table_name}")
            if table_name == "build-dependencies" and isinstance(table, dict) and table:
                fail("moriarty_cargo_target_build_dependencies_forbidden")

def validate_rust_target_topology(source_root: Path) -> None:
    """Freeze the source-owned Cargo target surface used by rust_all."""
    manifest_path = source_root / "Cargo.toml"
    try:
        with manifest_path.open("rb") as handle:
            manifest = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        fail("moriarty_cargo_manifest_invalid")
    cargo_config_root = source_root / ".cargo"
    for config_name in ("config", "config.toml"):
        config_path = cargo_config_root / config_name
        try:
            config_info = os.lstat(config_path)
        except FileNotFoundError:
            continue
        except OSError:
            fail("moriarty_cargo_project_config_unreadable")
        if stat.S_ISLNK(config_info.st_mode) or stat.S_ISREG(config_info.st_mode) or stat.S_ISDIR(config_info.st_mode):
            fail(f"moriarty_cargo_project_config_forbidden:{config_name}")
        fail(f"moriarty_cargo_project_config_forbidden:{config_name}")
    package = manifest.get("package")
    if not isinstance(package, dict) or package.get("name") != "qsol-fed":
        fail("moriarty_cargo_package_identity_drift")
    _reject_repository_cargo_execution_hooks(manifest, source_root)
    for flag in ("autolib", "autobins", "autoexamples", "autotests", "autobenches"):
        if package.get(flag, True) is not True:
            fail(f"moriarty_cargo_auto_target_disabled:{flag}")
    for key in ("lib", "bin", "example", "test", "bench", "workspace"):
        if key in manifest:
            fail(f"moriarty_cargo_explicit_target_override:{key}")
    lib = source_root / "src/lib.rs"
    if not lib.is_file() or lib.is_symlink():
        fail("moriarty_cargo_library_target_missing")
    bin_root = source_root / "src/bin"
    try:
        actual_bins = {entry.name for entry in bin_root.iterdir() if entry.is_file() and not entry.is_symlink() and entry.suffix == ".rs"}
    except OSError:
        fail("moriarty_cargo_bin_target_directory_missing")
    if actual_bins != EXPECTED_RUST_BIN_TARGETS:
        fail("moriarty_cargo_bin_target_surface_drift")

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
ALLOWED_OWNER_PHASES = frozenset({"0", "1", "2", "3", "4", "5A", "5", "5C", "6", "7", "8", "cross-phase"})
MAX_OWNER_PHASES = 12
MAX_BOUNDARY_IDS = 32
MAX_ATTACK_PROBE_IDS = 16


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


_VERIFIED_TREE_CACHE: tuple[str, dict[str, tuple[str, str, bytes]]] | None = None


def _git_object_id(kind: str, payload: bytes) -> str:
    return hashlib.sha1(f"{kind} {len(payload)}\0".encode("ascii") + payload).hexdigest()


def _verified_git_object(kind: str, object_id: str, limit: int) -> bytes:
    if not TARGET_RE.fullmatch(object_id):
        fail("moriarty_git_object_id_invalid")
    payload = trusted_capture_bounded(
        GIT_TRUSTED,
        ("cat-file", kind, object_id),
        limit=limit,
        cwd=ROOT,
        env=_git_env(),
        overflow_error="moriarty_git_object_too_large",
        command_error="moriarty_git_object_read_failed",
    )
    if _git_object_id(kind, payload) != object_id:
        fail(f"moriarty_git_{kind}_object_hash_mismatch")
    return payload


def _verified_commit_files(commit: str) -> dict[str, tuple[str, str, bytes]]:
    global _VERIFIED_TREE_CACHE
    if _VERIFIED_TREE_CACHE is not None and _VERIFIED_TREE_CACHE[0] == commit:
        return _VERIFIED_TREE_CACHE[1]
    if not git_commit_exists(commit):
        fail("moriarty_exact_export_commit_missing")
    commit_payload = _verified_git_object("commit", commit, 1_048_576)
    first_line = commit_payload.split(b"\n", 1)[0]
    if not first_line.startswith(b"tree "):
        fail("moriarty_commit_tree_header_missing")
    try:
        root_tree = first_line[5:].decode("ascii", errors="strict")
    except UnicodeError:
        fail("moriarty_commit_tree_id_invalid")
    if not TARGET_RE.fullmatch(root_tree):
        fail("moriarty_commit_tree_id_invalid")

    files: dict[str, tuple[str, str, bytes]] = {}
    total_payload = 0
    total_tree_metadata = 0
    entry_count = 0
    # Iterative traversal avoids Python recursion exhaustion on adversarial trees.
    stack: list[tuple[str, str, int]] = [(root_tree, "", 0)]
    while stack:
        tree_id, prefix, depth = stack.pop()
        if depth > MAX_GIT_TREE_DEPTH:
            fail("moriarty_git_tree_depth_exceeded")
        remaining_metadata = MAX_GIT_TREE_METADATA_BYTES - total_tree_metadata
        if remaining_metadata <= 0:
            fail("moriarty_git_tree_metadata_exceeded")
        tree_payload = _verified_git_object("tree", tree_id, remaining_metadata)
        total_tree_metadata += len(tree_payload)
        if total_tree_metadata > MAX_GIT_TREE_METADATA_BYTES:
            fail("moriarty_git_tree_metadata_exceeded")
        cursor = 0
        child_trees: list[tuple[str, str, int]] = []
        while cursor < len(tree_payload):
            space = tree_payload.find(b" ", cursor)
            nul = tree_payload.find(b"\0", space + 1 if space >= 0 else cursor)
            if space <= cursor or nul <= space or nul + 21 > len(tree_payload):
                fail("moriarty_git_tree_object_malformed")
            mode_bytes = tree_payload[cursor:space]
            name_bytes = tree_payload[space + 1:nul]
            object_id = tree_payload[nul + 1:nul + 21].hex()
            cursor = nul + 21
            entry_count += 1
            if entry_count > MAX_GIT_TREE_ENTRIES:
                fail("moriarty_git_tree_entry_count_exceeded")
            try:
                mode = mode_bytes.decode("ascii", errors="strict")
                name = name_bytes.decode("utf-8", errors="strict")
            except UnicodeError:
                fail("moriarty_git_tree_entry_encoding_invalid")
            if not name or name in {".", ".."} or "/" in name or "\\" in name:
                fail("moriarty_git_tree_entry_name_invalid")
            relative = f"{prefix}/{name}" if prefix else name
            if len(relative.encode("utf-8")) > MAX_GIT_PATH_BYTES:
                fail("moriarty_git_tree_path_too_long")
            if relative in files:
                fail("moriarty_git_tree_duplicate_path")
            if mode == "40000":
                if depth >= MAX_GIT_TREE_DEPTH:
                    fail("moriarty_git_tree_depth_exceeded")
                child_trees.append((object_id, relative, depth + 1))
            elif mode in {"100644", "100755"}:
                remaining = MAX_GIT_ARCHIVE_BYTES - total_payload
                if remaining <= 0:
                    fail("moriarty_exact_export_archive_too_large")
                blob = _verified_git_object("blob", object_id, remaining)
                total_payload += len(blob)
                if total_payload > MAX_GIT_ARCHIVE_BYTES:
                    fail("moriarty_exact_export_archive_too_large")
                files[relative] = (mode, object_id, blob)
            else:
                fail("moriarty_exact_export_nonregular_entry_forbidden")
        if cursor != len(tree_payload):
            fail("moriarty_git_tree_object_malformed")
        # Reverse preserves Git tree order while keeping traversal iterative.
        stack.extend(reversed(child_trees))

    _VERIFIED_TREE_CACHE = (commit, files)
    return files


def _index_flags_output_clean(raw: bytes) -> bool:
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        return False
    for line in lines:
        if len(line) < 2 or line[1] != " ":
            return False
        tag = line[0]
        if tag == "S" or tag.islower():
            return False
    return True


def index_flags_clean() -> bool:
    completed = git("ls-files", "-t", "-v")
    return completed.returncode == 0 and _index_flags_output_clean(completed.stdout)


def _index_entries() -> dict[str, tuple[str, str]] | None:
    completed = git("ls-files", "-s", "-z")
    if completed.returncode != 0:
        return None
    entries: dict[str, tuple[str, str]] = {}
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii", errors="strict").split(" ")
            path = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError):
            return None
        if stage != "0" or mode not in {"100644", "100755"} or not TARGET_RE.fullmatch(object_id) or path in entries:
            return None
        entries[path] = (mode, object_id)
    return entries


def _worktree_file_matches(path: str, mode: str, object_id: str, expected_size: int) -> bool:
    candidate = ROOT / path
    try:
        initial = candidate.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(initial.st_mode) or candidate.is_symlink():
        return False
    if bool(initial.st_mode & 0o111) != (mode == "100755") or initial.st_size != expected_size:
        return False
    try:
        fd = os.open(candidate, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False
    digest = hashlib.sha1()
    digest.update(f"blob {initial.st_size}\0".encode("ascii"))
    total = 0
    try:
        opened = os.fstat(fd)
        if opened.st_dev != initial.st_dev or opened.st_ino != initial.st_ino or opened.st_size != initial.st_size:
            return False
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        final = os.fstat(fd)
    finally:
        os.close(fd)
    return (
        total == expected_size
        and final.st_dev == opened.st_dev
        and final.st_ino == opened.st_ino
        and final.st_size == opened.st_size
        and final.st_mtime_ns == opened.st_mtime_ns
        and digest.hexdigest() == object_id
    )


def tracked_tree_clean() -> bool:
    if not index_flags_clean():
        return False
    try:
        target = git_head()
        files = _verified_commit_files(target)
    except SystemExit:
        return False
    index = _index_entries()
    expected_index = {path: (mode, object_id) for path, (mode, object_id, _) in files.items()}
    if index != expected_index:
        return False
    return all(
        _worktree_file_matches(path, mode, object_id, len(blob))
        for path, (mode, object_id, blob) in files.items()
    )


def harness_files_match_target(target: str, extra_paths: Sequence[str] = ()) -> bool:
    try:
        files = _verified_commit_files(target)
    except SystemExit:
        return False
    for path in (*HARNESS_PATHS, *extra_paths):
        expected = files.get(path)
        if expected is None:
            return False
        try:
            actual = (ROOT / path).read_bytes()
        except OSError:
            return False
        if actual != expected[2]:
            return False
    return True


def git_archive_bytes(commit: str) -> bytes:
    """Build a bounded tar from hash-verified commit/tree/blob objects."""
    files = _verified_commit_files(commit)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as archive:
        for relative in sorted(files):
            mode, _, blob = files[relative]
            info = tarfile.TarInfo(relative)
            info.size = len(blob)
            info.mode = 0o755 if mode == "100755" else 0o644
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            archive.addfile(info, io.BytesIO(blob))
            if buffer.tell() > MAX_GIT_ARCHIVE_BYTES:
                fail("moriarty_exact_export_archive_too_large")
    encoded = buffer.getvalue()
    if len(encoded) > MAX_GIT_ARCHIVE_BYTES:
        fail("moriarty_exact_export_archive_too_large")
    return encoded


def git_commit_exists(commit: str) -> bool:
    if not TARGET_RE.fullmatch(commit):
        return False
    completed = git("cat-file", "-t", commit)
    return completed.returncode == 0 and completed.stdout == b"commit\n"


def git_is_ancestor(ancestor: str, descendant: str) -> bool:
    return (
        git_commit_exists(ancestor)
        and git_commit_exists(descendant)
        and git("merge-base", "--is-ancestor", ancestor, descendant).returncode == 0
    )


def _probe_environment(
    home: Path,
    cargo_home: Path,
    target_dir: Path,
    temp_dir: Path,
    tool_paths: Sequence[Path],
    rustc_path: Path | None = None,
    rustdoc_path: Path | None = None,
    rust_lib: Path | None = None,
) -> dict[str, str]:
    environment = {
        "PATH": os.pathsep.join([*(str(path) for path in tool_paths), "/usr/bin", "/bin"]),
        "HOME": str(home),
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_BUILD_JOBS": "2",
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
    if rustc_path is not None:
        environment["RUSTC"] = str(rustc_path)
    if rustdoc_path is not None:
        environment["RUSTDOC"] = str(rustdoc_path)
    if rust_lib is not None:
        environment["LD_LIBRARY_PATH"] = str(rust_lib)
    return environment


def _system_read_exec_paths() -> tuple[Path, ...]:
    # Closed runtime roots only. Never grant recursive /usr or /usr/local access.
    candidates = (Path("/usr/bin"), Path("/usr/lib"), Path("/usr/libexec"), Path("/bin"), Path("/lib"), Path("/lib64"))
    return tuple(path for path in candidates if path.exists())


def _system_read_paths() -> tuple[Path, ...]:
    # Credential-free runtime metadata only. Never grant recursive /etc access.
    candidates = (
        Path("/etc/ld.so.cache"),
        Path("/etc/localtime"),
        Path("/etc/nsswitch.conf"),
        Path("/etc/passwd"),
        Path("/etc/group"),
        Path("/etc/hosts"),
        Path("/dev/urandom"),
        Path("/dev/random"),
    )
    return tuple(path for path in candidates if path.is_file() and not path.is_symlink())


def _system_writable_files() -> tuple[Path, ...]:
    return tuple(path for path in (Path("/dev/null"),) if path.exists())


def _fresh_cargo_home(
    probe_id: str,
    template: Path,
    workspace: Path,
    label: str,
    rust_runtime: Path | None = None,
) -> Path:
    if probe_id == "rust_all":
        return create_isolated_cargo_home(template, workspace, label, rust_runtime)
    return create_empty_cargo_home(workspace, label)


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
            or not 1 <= len(owner_phases) <= MAX_OWNER_PHASES
            or not all(isinstance(value, str) and value in ALLOWED_OWNER_PHASES for value in owner_phases)
            or len(set(owner_phases)) != len(owner_phases)
            or not isinstance(boundary_ids, list)
            or not 1 <= len(boundary_ids) <= MAX_BOUNDARY_IDS
            or not all(isinstance(value, str) and re.fullmatch(r"[a-z0-9_./-]{1,128}", value) for value in boundary_ids)
            or len(set(boundary_ids)) != len(boundary_ids)
            or not isinstance(probe_ids, list)
            or not 1 <= len(probe_ids) <= MAX_ATTACK_PROBE_IDS
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
        "stderr_bytes", "stdout_truncated", "stderr_truncated", "status", "resolution_commit", "production_credentials_used",
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
        or not 1 <= len(item["owner_phases"]) <= MAX_OWNER_PHASES
        or not all(isinstance(value, str) and value in ALLOWED_OWNER_PHASES for value in item["owner_phases"])
        or len(set(item["owner_phases"])) != len(item["owner_phases"])
        or not isinstance(item["boundary_ids"], list)
        or not 1 <= len(item["boundary_ids"]) <= MAX_BOUNDARY_IDS
        or not all(isinstance(value, str) and re.fullmatch(r"[a-z0-9_./-]{1,128}", value) for value in item["boundary_ids"])
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
        or not 0 <= item["stdout_bytes"] <= MAX_PROBE_OUTPUT_BYTES
        or not isinstance(item["stderr_bytes"], int)
        or isinstance(item["stderr_bytes"], bool)
        or not 0 <= item["stderr_bytes"] <= MAX_PROBE_OUTPUT_BYTES
        or type(item["stdout_truncated"]) is not bool
        or type(item["stderr_truncated"]) is not bool
    ):
        fail("moriarty_counterexample_boundary_invalid")

    if item["failure_kind"] == "exit_nonzero":
        if (
            not isinstance(item["observed_exit_code"], int)
            or isinstance(item["observed_exit_code"], bool)
            or item["observed_exit_code"] == 0
            or not -(2**31) <= item["observed_exit_code"] <= 2**31 - 1
        ):
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
    if _ACTIVE_PROBE_CGROUP is not None:
        kill_probe_cgroup(_ACTIVE_PROBE_CGROUP)
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


def _classify_rust_failure(stderr: bytes) -> str:
    """Reduce compiler/Cargo stderr to a closed, non-secret diagnostic class."""
    text = stderr.decode("utf-8", errors="replace").lower()
    denied = "permission denied" in text or "os error 13" in text
    not_permitted = "operation not permitted" in text or "os error 1" in text
    if "/proc/" in text and (denied or not_permitted):
        return "proc_access_denied"
    # Prefer causal diagnostics before the generic `--sysroot` token that Cargo
    # includes in ordinary rustc command lines.
    if "failed to run custom build command" in text:
        return "build_script"
    if "linking with" in text or "linker" in text:
        return "linker"
    if "failed to download" in text or "offline mode" in text or "no matching package named" in text:
        return "offline_dependency"
    if "could not execute process" in text or "failed to run rustc" in text:
        return "rustc_spawn"
    if "read-only file system" in text or "os error 30" in text:
        return "read_only_filesystem"
    if denied:
        return "filesystem_permission"
    if not_permitted:
        return "seccomp_or_permission"
    if "can't find crate for `std`" in text or "couldn't find crate" in text:
        return "rust_sysroot"
    return "rust_exit_other"



_RUNTIME_NORMALIZATIONS: tuple[tuple[re.Pattern[bytes], bytes], ...] = (
    (re.compile(rb"(?m)^(\s*Finished .*) in (?:[0-9]+m )?[0-9]+(?:\.[0-9]+)?s$"), rb"\1 in <T>s"),
    (re.compile(rb"; finished in (?:[0-9]+m )?[0-9]+(?:\.[0-9]+)?s"), rb"; finished in <T>s"),
    (re.compile(rb"\(pid=[0-9]+\)"), rb"(pid=<PID>)"),
    (re.compile(rb"(thread '[^'\r\n]*' )\([0-9]+\)"), rb"\1(<TID>)"),
)


def _normalize_probe_output(
    data: bytes,
    *,
    probe_id: str,
    source_root: Path,
    target_dir: Path,
    home: Path,
    cargo_home: Path,
    temp_dir: Path,
    workspace_root: Path,
) -> bytes:
    """Normalize private per-run paths to stable reproducibility placeholders."""
    replacements = [
        (source_root, b"<SOURCE>"),
        (target_dir, b"<TARGET>"),
        (home, b"<HOME>"),
        (cargo_home, b"<CARGO_HOME>"),
        (temp_dir, b"<TMP>"),
        (workspace_root, b"<WORK>"),
    ]
    encoded: list[tuple[bytes, bytes]] = []
    for candidate, marker in replacements:
        raw = os.fsencode(str(candidate.resolve()))
        if not raw:
            fail("moriarty_workspace_normalization_path_invalid")
        encoded.append((raw, marker))
    normalized = data
    # Most-specific paths first so a workspace replacement cannot hide a child path.
    for raw, marker in sorted(encoded, key=lambda item: len(item[0]), reverse=True):
        normalized = normalized.replace(raw, marker)
    if probe_id == "rust_all":
        for pattern, replacement in _RUNTIME_NORMALIZATIONS:
            normalized = pattern.sub(replacement, normalized)
    return normalized


def _probe_failure_result(probe_id: str, kind: str, diagnostic: bytes) -> dict[str, Any]:
    bounded = diagnostic[:MAX_PROBE_OUTPUT_BYTES]
    return {
        "probe_id": probe_id,
        "ok": False,
        "exit_code": None,
        "failure_kind": kind,
        "stdout_sha256": bytes_ref(b""),
        "stderr_sha256": bytes_ref(bounded),
        "stdout_bytes": 0,
        "stderr_bytes": len(bounded),
        "stdout_truncated": False,
        "stderr_truncated": len(diagnostic) > len(bounded),
        "diagnostic_class": "harness_precheck" if probe_id == "rust_all" else None,
    }


def run_probe(
    probe_id: str,
    home: Path,
    source_root: Path,
    cargo_home: Path,
    target_dir: Path,
    python_exec: Path,
    cargo_exec: Path,
    rustc_exec: Path,
    rustdoc_exec: Path | None,
    rust_runtime: Path | None,
) -> dict[str, Any]:
    if not tracked_tree_clean():
        return _probe_failure_result(probe_id, "tool_error", b"tracked_tree_or_index_flags_dirty_before_probe")
    if landlock_abi_version() < 3:
        return _probe_failure_result(probe_id, "tool_error", b"landlock_abi3_unavailable")
    if not network_seccomp_supported():
        return _probe_failure_result(probe_id, "tool_error", b"network_seccomp_unavailable")
    if probe_id == "rust_all":
        try:
            validate_rust_target_topology(source_root)
        except SystemExit as exc:
            return _probe_failure_result(probe_id, "tool_error", str(exc).encode("utf-8", errors="replace"))
    cgroup = _probe_cgroup()
    if probe_cgroup_pids(cgroup):
        return _probe_failure_result(probe_id, "tool_error", b"probe_cgroup_not_empty_before_probe")
    home.mkdir(mode=0o700, parents=False, exist_ok=False)
    target_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    temp_dir = target_dir.parent / f"tmp-{target_dir.name}"
    temp_dir.mkdir(mode=0o700, parents=False, exist_ok=False)

    argv = PROBES[probe_id]
    trusted = PROBE_EXECUTABLES[probe_id]
    if not trusted_executable_matches(trusted):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_executable_fd_invalid_before_probe")
    if probe_id == "rust_all" and not trusted_executable_matches(RUSTC_TRUSTED):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_rustc_fd_invalid_before_probe")

    executable = cargo_exec if probe_id == "rust_all" else python_exec
    tool_paths = [python_exec.parent]
    rust_lib: Path | None = None
    if rust_runtime is not None:
        tool_paths.insert(0, rust_runtime / "bin")
        rust_lib = rust_runtime / "lib"
    elif probe_id == "rust_all":
        tool_paths.insert(0, cargo_exec.parent)

    read_exec_paths = [source_root, executable.parent, *_system_read_exec_paths()]
    if rust_runtime is not None:
        read_exec_paths.append(rust_runtime)
    elif probe_id == "rust_all":
        read_exec_paths.extend([cargo_exec.parent, rustc_exec.parent])
    private_writable_paths = [home, cargo_home, target_dir, temp_dir]
    writable_paths = [*private_writable_paths, *_system_writable_files()]
    if not probe_writable_tree_within_limits(tuple(private_writable_paths)):
        return _probe_failure_result(probe_id, "tool_error", b"writable_resource_limit_exceeded_before_probe")
    preexec = probe_isolation_preexec(
        tuple(read_exec_paths),
        _system_read_paths(),
        tuple(writable_paths),
        cgroup,
    )
    try:
        process = subprocess.Popen(
            list(argv),
            executable=str(executable),
            cwd=source_root,
            env=_probe_environment(
                home,
                cargo_home,
                target_dir,
                temp_dir,
                tool_paths,
                rustc_exec if probe_id == "rust_all" else None,
                rustdoc_exec if probe_id == "rust_all" else None,
                rust_lib,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=preexec,
            close_fds=True,
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
    truncated = {"stdout": False, "stderr": False}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    stderr_sample = bytearray()
    deadline = time.monotonic() + TIMEOUT_SECONDS
    post_exit_deadline: float | None = None
    termination_deadline: float | None = None
    failure_kind: str | None = None
    next_writable_check = time.monotonic() + _moriarty_isolation.PROBE_WRITABLE_CHECK_INTERVAL_SECONDS

    try:
        while selector.get_map():
            now = time.monotonic()
            if failure_kind is None and now >= next_writable_check:
                if not probe_writable_tree_within_limits(tuple(private_writable_paths)):
                    failure_kind = "tool_error"
                    _kill_probe_tree(process)
                    termination_deadline = now + TERMINATION_DRAIN_SECONDS
                next_writable_check = now + _moriarty_isolation.PROBE_WRITABLE_CHECK_INTERVAL_SECONDS
            remaining = deadline - now
            direct_exited = process.poll() is not None
            if remaining <= 0 and failure_kind is None:
                failure_kind = "timeout"
                _kill_probe_tree(process)
                termination_deadline = now + TERMINATION_DRAIN_SECONDS
            elif direct_exited and failure_kind is None:
                # Normal processes may exit before the parent consumes buffered
                # pipe bytes/EOF. Give them a bounded drain grace before calling
                # the still-open descriptors a descendant leak.
                if post_exit_deadline is None:
                    post_exit_deadline = now + POST_EXIT_DRAIN_SECONDS
                elif now >= post_exit_deadline:
                    failure_kind = "tool_error"
                    _kill_probe_tree(process)
                    termination_deadline = now + TERMINATION_DRAIN_SECONDS

            if failure_kind is not None and termination_deadline is None:
                termination_deadline = now + TERMINATION_DRAIN_SECONDS
            if termination_deadline is not None and now >= termination_deadline:
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

            limits = [0.1]
            if failure_kind is None and not direct_exited:
                limits.append(max(0.0, remaining))
            if post_exit_deadline is not None and failure_kind is None:
                limits.append(max(0.0, post_exit_deadline - now))
            if termination_deadline is not None:
                limits.append(max(0.0, termination_deadline - now))
            events = selector.select(timeout=min(limits))
            for key, _ in events:
                stream_name = key.data
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if probe_id == "rust_all" and stream_name == "stderr" and len(stderr_sample) < MAX_DIAGNOSTIC_SAMPLE_BYTES:
                    remaining_sample = MAX_DIAGNOSTIC_SAMPLE_BYTES - len(stderr_sample)
                    stderr_sample.extend(chunk[:remaining_sample])
                remaining_capture = max(0, MAX_PROBE_OUTPUT_BYTES - len(captured[stream_name]))
                if remaining_capture:
                    captured[stream_name].extend(chunk[:remaining_capture])
                counts[stream_name], overflow = bounded_output_update(
                    digests[stream_name], counts[stream_name], chunk
                )
                if overflow:
                    truncated[stream_name] = True
                    if failure_kind is None:
                        failure_kind = "tool_error"
                        _kill_probe_tree(process)
                        termination_deadline = time.monotonic() + TERMINATION_DRAIN_SECONDS

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
    cgroup_descendants = probe_cgroup_pids(cgroup)
    if leaked_descendants or cgroup_descendants:
        failure_kind = failure_kind or "tool_error"
        _kill_probe_tree(process)
    _reap_adopted_children()
    if probe_cgroup_pids(cgroup):
        failure_kind = failure_kind or "tool_error"
    if not probe_writable_tree_within_limits(tuple(private_writable_paths)):
        failure_kind = failure_kind or "tool_error"

    if not tracked_tree_clean():
        return _probe_failure_result(probe_id, "tool_error", b"tracked_tree_or_index_flags_dirty_after_probe")
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

    normalized = {
        name: _normalize_probe_output(
            bytes(captured[name]),
            probe_id=probe_id,
            source_root=source_root,
            target_dir=target_dir,
            home=home,
            cargo_home=cargo_home,
            temp_dir=temp_dir,
            workspace_root=source_root.parent,
        )
        for name in ("stdout", "stderr")
    }
    return {
        "probe_id": probe_id,
        "ok": ok,
        "exit_code": return_code if failure_kind == "exit_nonzero" or ok else None,
        "failure_kind": failure_kind,
        "stdout_sha256": bytes_ref(normalized["stdout"]),
        "stderr_sha256": bytes_ref(normalized["stderr"]),
        "stdout_bytes": len(normalized["stdout"]),
        "stderr_bytes": len(normalized["stderr"]),
        "stdout_truncated": truncated["stdout"],
        "stderr_truncated": truncated["stderr"],
        "diagnostic_class": _classify_rust_failure(bytes(stderr_sample)) if probe_id == "rust_all" and not ok else None,
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
        "stdout_truncated": result["stdout_truncated"],
        "stderr_truncated": result["stderr_truncated"],
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
        and result["stdout_truncated"] is item["stdout_truncated"]
        and result["stderr_truncated"] is item["stderr_truncated"]
    )


def _force_remove_probe_path(path: Path) -> None:
    """Remove a disposable probe path even after probe-controlled chmod(0)."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
    except FileNotFoundError:
        return
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                child = path / entry.name
                try:
                    child_info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(child_info.st_mode) and not stat.S_ISLNK(child_info.st_mode):
                    _force_remove_probe_path(child)
                else:
                    try:
                        child.unlink()
                    except FileNotFoundError:
                        pass
                    except IsADirectoryError:
                        _force_remove_probe_path(child)
    except FileNotFoundError:
        return
    try:
        path.rmdir()
    except FileNotFoundError:
        pass


def _cleanup_probe_writable_paths(*paths: Path) -> None:
    root = _probe_writable_root()
    for path in paths:
        absolute = Path(path).absolute()
        if absolute == root or not absolute.is_relative_to(root):
            fail("moriarty_probe_cleanup_path_escape")
        _force_remove_probe_path(absolute)

def _run_probe_with_cleanup(
    probe_id: str,
    home: Path,
    source_root: Path,
    cargo_home: Path,
    target_dir: Path,
    python_exec: Path,
    cargo_exec: Path,
    rustc_exec: Path,
    rustdoc_exec: Path | None,
    rust_runtime: Path | None,
) -> dict[str, Any]:
    temp_dir = target_dir.parent / f"tmp-{target_dir.name}"
    try:
        return run_probe(
            probe_id, home, source_root, cargo_home, target_dir,
            python_exec, cargo_exec, rustc_exec, rustdoc_exec, rust_runtime,
        )
    finally:
        _cleanup_probe_writable_paths(home, cargo_home, target_dir, temp_dir)


def _cleanup_replay_workspace_paths(workspace: Path, *paths: Path) -> None:
    root = Path(workspace).absolute()
    for path in paths:
        absolute = Path(path).absolute()
        if absolute == root or not absolute.is_relative_to(root):
            fail("moriarty_replay_cleanup_path_escape")
        _force_remove_probe_path(absolute)


def _run_counterexample_replay_probe(
    item: dict[str, Any],
    index: int,
    phase: str,
    commit: str,
    workspace: Path,
    python_exec: Path,
    cargo_exec: Path,
    rustc_exec: Path,
    rustdoc_exec: Path | None,
    rust_runtime: Path | None,
) -> dict[str, Any]:
    probe_id = item["regression_probe_ids"][0]
    label = f"accepted-{index}-{phase}"
    source_path = workspace / f"{label}-src"
    template_path = workspace / f"{label}-template"
    writable_root = _probe_writable_root()
    home = writable_root / f"{label}-home"
    cargo_home_path = writable_root / f"cargo-home-{label}"
    target_dir = writable_root / f"{label}-target"
    temp_dir = writable_root / f"tmp-{label}-target"
    try:
        source = create_exact_export(commit, workspace, git_archive_bytes, label)
        if probe_id == "rust_all" and not (source / "Cargo.lock").is_file():
            fail(f"moriarty_replay_{phase}_cargo_lock_missing")

        topology_valid = True
        if probe_id == "rust_all":
            try:
                validate_rust_target_topology(source)
            except SystemExit:
                # run_probe repeats this precheck and records the exact bounded
                # harness-precheck failure; no Cargo archive template is needed.
                topology_valid = False

        if probe_id == "rust_all" and topology_valid:
            template = create_verified_cargo_template(
                CARGO_CACHE_HOME,
                workspace,
                source / "Cargo.lock",
                f"{label}-template",
            )
            cargo_home = _fresh_cargo_home(probe_id, template, writable_root, label, rust_runtime)
        elif probe_id == "rust_all":
            cargo_home = cargo_home_path
        else:
            cargo_home = _fresh_cargo_home(probe_id, workspace, writable_root, label, rust_runtime)

        return _run_probe_with_cleanup(
            probe_id,
            home,
            source,
            cargo_home,
            target_dir,
            python_exec,
            cargo_exec,
            rustc_exec,
            rustdoc_exec,
            rust_runtime,
        )
    finally:
        _cleanup_probe_writable_paths(home, cargo_home_path, target_dir, temp_dir)
        replay_paths = [source_path]
        if probe_id == "rust_all":
            replay_paths.append(template_path)
        _cleanup_replay_workspace_paths(workspace, *replay_paths)


def verify_accepted_counterexamples(
    accepted: list[dict[str, Any]],
    workspace: Path,
    python_exec: Path,
    cargo_exec: Path,
    rustc_exec: Path,
    rustdoc_exec: Path | None,
    rust_runtime: Path | None,
) -> list[dict[str, Any]]:
    """Replay every accepted finding and return reportable transition evidence.

    Every entry, including unresolved entries, must reproduce its recorded target
    failure. Only resolved entries additionally require the same probe to pass at
    resolution_commit. Replay mismatch is report data, not an early process exit.
    """
    records: list[dict[str, Any]] = []
    for index, item in enumerate(accepted):
        probe_id = item["regression_probe_ids"][0]
        record: dict[str, Any] = {
            "counterexample_id": item["counterexample_id"],
            "status": item["status"],
            "probe_id": probe_id,
            "ok": False,
            "target_reproduced": False,
            "resolution_green": None,
            "failure_kind": None,
            "failure_result": None,
        }
        try:
            before = _run_counterexample_replay_probe(
                item,
                index,
                "target",
                item["target_commit"],
                workspace,
                python_exec,
                cargo_exec,
                rustc_exec,
                rustdoc_exec,
                rust_runtime,
            )
        except SystemExit:
            record["failure_kind"] = "replay_setup_error"
            records.append(record)
            continue

        target_reproduced = counterexample_failure_matches(item, before)
        record["target_reproduced"] = target_reproduced
        if not target_reproduced:
            record["failure_kind"] = "target_failure_not_reproduced"
            record["failure_result"] = report_probe_result(before)
            records.append(record)
            continue

        if item["status"] == "unresolved":
            record["ok"] = True
            records.append(record)
            continue

        resolution = item["resolution_commit"]
        assert isinstance(resolution, str)
        try:
            after = _run_counterexample_replay_probe(
                item,
                index,
                "resolution",
                resolution,
                workspace,
                python_exec,
                cargo_exec,
                rustc_exec,
                rustdoc_exec,
                rust_runtime,
            )
        except SystemExit:
            record["resolution_green"] = False
            record["failure_kind"] = "replay_setup_error"
            records.append(record)
            continue

        resolution_green = after["ok"] is True and after["exit_code"] == 0
        record["resolution_green"] = resolution_green
        if not resolution_green:
            record["failure_kind"] = "resolution_probe_not_green"
            record["failure_result"] = report_probe_result(after)
            records.append(record)
            continue
        record["ok"] = True
        records.append(record)
    return records


def report_probe_result(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result[key] for key in (
        "probe_id", "ok", "exit_code", "failure_kind",
        "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes",
        "stdout_truncated", "stderr_truncated",
    )}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the MORIARTY/1 exact-commit graduation harness", allow_abbrev=False)
    parser.add_argument("--target-commit", required=True, help="exact 40-character lowercase Git commit")
    parser.add_argument("--output", required=True, help="path for canonical moriarty-report/1 output")
    args = parser.parse_args()

    target = args.target_commit
    if target != _BOOTSTRAP_TARGET:
        fail("moriarty_target_commit_bootstrap_mismatch")
    if not TARGET_RE.fullmatch(target):
        fail("moriarty_target_commit_invalid")
    if git_head() != target:
        fail("moriarty_target_commit_does_not_match_checkout")
    if not tracked_tree_clean():
        fail("moriarty_target_tracked_tree_or_index_flags_dirty")
    if not harness_files_match_target(target):
        fail("moriarty_harness_worktree_bytes_do_not_match_target")

    quota_value = os.environ.get("MORIARTY_PROBE_WRITABLE_ROOT")
    if not quota_value:
        fail("moriarty_probe_quota_root_required")
    global _ACTIVE_PROBE_WRITABLE_ROOT, _ACTIVE_PROBE_CGROUP
    _ACTIVE_PROBE_WRITABLE_ROOT = probe_quota_root(Path(quota_value))
    global CARGO_CACHE_HOME
    CARGO_CACHE_HOME = cargo_cache_root(CARGO_CACHE_HOME)
    cgroup_value = os.environ.get("MORIARTY_PROBE_CGROUP")
    if not cgroup_value:
        fail("moriarty_probe_cgroup_required")
    _ACTIVE_PROBE_CGROUP = probe_cgroup_root(Path(cgroup_value))
    if probe_cgroup_pids(_ACTIVE_PROBE_CGROUP):
        fail("moriarty_probe_cgroup_not_empty_at_start")

    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-work-") as work_dir:
        workspace = Path(work_dir)
        if landlock_abi_version() < 3:
            fail("moriarty_landlock_abi3_required")
        if not network_seccomp_supported():
            fail("moriarty_network_seccomp_required")
        control_source = create_exact_export(target, workspace, git_archive_bytes, "control")
        if not (control_source / "Cargo.lock").is_file():
            fail("moriarty_committed_cargo_lock_missing")
        cargo_template = create_verified_cargo_template(
            CARGO_CACHE_HOME, workspace, control_source / "Cargo.lock"
        )
        python_exec = stage_executable_from_fd(
            PYTHON_TRUSTED.fd, workspace / "python-runtime" / "python3"
        )

        rust_source_root = (
            RUST_SNAPSHOT_ROOT
            if RUST_SNAPSHOT_ROOT is not None
            else (
                Path(CARGO_TRUSTED.executable).parent.parent
                if RUSTUP_DISCOVERY_USED
                else _direct_toolchain_root(CARGO_TRUSTED, RUSTC_TRUSTED)
            )
        )
        if rust_source_root is None:
            fail("moriarty_rust_toolchain_root_unavailable")
        rust_runtime = stage_rust_toolchain_runtime(
            rust_source_root,
            workspace / "rust-runtime",
            CARGO_TRUSTED.fd,
            RUSTC_TRUSTED.fd,
        )
        cargo_exec = rust_runtime / "bin" / "cargo"
        rustc_exec = rust_runtime / "bin" / "rustc"
        rustdoc_candidate = rust_runtime / "bin" / "rustdoc"
        rustdoc_exec = rustdoc_candidate if rustdoc_candidate.is_file() else None
        if rustdoc_exec is None:
            fail("moriarty_staged_rustdoc_missing")

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
            label = f"probe-{probe_index}-{probe_id}"
            probe_source = create_exact_export(target, workspace, git_archive_bytes, label)
            writable_root = _probe_writable_root()
            probe_cargo_home = _fresh_cargo_home(probe_id, cargo_template, writable_root, label, rust_runtime)
            results[probe_id] = _run_probe_with_cleanup(
                probe_id,
                writable_root / f"home-{probe_index}-{probe_id}",
                probe_source,
                probe_cargo_home,
                writable_root / f"target-{probe_index}-{probe_id}",
                python_exec,
                cargo_exec,
                rustc_exec,
                rustdoc_exec,
                rust_runtime,
            )
        remediation_replays = verify_accepted_counterexamples(
            accepted,
            workspace,
            python_exec,
            cargo_exec,
            rustc_exec,
            rustdoc_exec,
            rust_runtime,
        )

    generated: list[dict[str, Any]] = []
    accepted_unresolved_failures = {
        (item["attack_id"], item["regression_probe_ids"][0])
        for item in accepted
        if item["status"] == "unresolved"
    }
    for probe_id, result in results.items():
        if result["ok"]:
            continue
        owners = probe_users.get(probe_id, [])
        if len(owners) == 1 and result["failure_kind"] in {"exit_nonzero", "timeout", "tool_error"}:
            key = (owners[0]["id"], probe_id)
            if key not in accepted_unresolved_failures:
                generated.append(generated_counterexample(target, owners[0], result))

    unresolved_accepted = [item for item in accepted if item["status"] == "unresolved"]
    unresolved_count = len(unresolved_accepted) + len(generated)
    all_probes_ok = all(result["ok"] for result in results.values())
    all_replays_ok = all(item["ok"] for item in remediation_replays)

    if git_head() != target or not tracked_tree_clean() or not harness_files_match_target(target):
        fail("moriarty_target_or_harness_changed_during_probes")

    report = {
        "schema": REPORT_SCHEMA,
        "protocol": PROTOCOL,
        "target_commit": target,
        "corpus_ref": canonical_ref(corpus),
        "operator_profile": OPERATOR_PROFILE,
        "family_count": len(EXPECTED_FAMILIES),
        "executed_probe_count": len(ordered_probe_ids),
        "probe_results": [report_probe_result(results[probe_id]) for probe_id in ordered_probe_ids],
        "remediation_replays": remediation_replays,
        "counterexamples": accepted + generated,
        "unresolved_counterexamples": unresolved_count,
        "graduated": unresolved_count == 0 and all_probes_ok and all_replays_ok,
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
    if not report["graduated"] and "rust_all" in results and not results["rust_all"]["ok"]:
        diagnostic = {
            "schema": "moriarty-diagnostic/1",
            "target_commit": target,
            "probe_id": "rust_all",
            "failure_class": results["rust_all"].get("diagnostic_class") or "rust_exit_other",
            "authority_effect": "none",
        }
        diagnostic_path = output.parent / f"moriarty-diagnostic-{target}.json"
        write_report_exclusive(diagnostic_path, serialize(diagnostic).encode("utf-8"), ROOT)
    if git_head() != target or not tracked_tree_clean() or not harness_files_match_target(target):
        fail("moriarty_target_or_harness_changed_during_report_publication")

    # Authenticate the exact report bytes across the runner/validator process boundary.
    print(f"MORIARTY_REPORT_SHA256={hashlib.sha256(encoded).hexdigest()}")

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
        f"{sum(not result['ok'] for result in results.values())} failed probe(s), "
        f"{sum(not replay['ok'] for replay in remediation_replays)} failed remediation replay(s); report={output}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
