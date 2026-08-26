#!/usr/bin/env python3
"""One-shot remediation for the final Codex review on Phase 9.

This file is temporary scaffolding. The apply workflow commits only the transformed
normative/source files; this helper and its workflow are deleted before the final
exact-head CI run.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"phase9 round2 replacement drift:{label}:{count}")
    return text.replace(old, new, 1)


def replace_region(text: str, start: str, end: str, replacement: str, label: str) -> str:
    begin = text.find(start)
    finish = text.find(end, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        raise SystemExit(f"phase9 round2 region drift:{label}")
    return text[:begin] + replacement + text[finish:]


# ---------------------------------------------------------------------------
# tools/moriarty_isolation.py: kernel write-denial + child subreaper helpers.
# ---------------------------------------------------------------------------
iso = read("tools/moriarty_isolation.py")
iso = replace_once(iso, "import os\n", "import ctypes\nimport os\n", "isolation ctypes import")
iso = replace_once(iso, "import stat\n", "import stat\nimport sys\n", "isolation sys import")
marker = '''def proc_fd_path(fd: int) -> str:
'''
landlock = r'''# Linux Landlock ABI 3 is sufficient for write/truncate/refer denial.
# The syscall numbers are shared by x86_64 and aarch64 Linux.
_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_CHILD_SUBREAPER = 36

_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
_LANDLOCK_ACCESS_FS_REFER = 1 << 13
_LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
_LANDLOCK_WRITE_MASK = (
    _LANDLOCK_ACCESS_FS_WRITE_FILE
    | _LANDLOCK_ACCESS_FS_REMOVE_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_FILE
    | _LANDLOCK_ACCESS_FS_MAKE_CHAR
    | _LANDLOCK_ACCESS_FS_MAKE_DIR
    | _LANDLOCK_ACCESS_FS_MAKE_REG
    | _LANDLOCK_ACCESS_FS_MAKE_SOCK
    | _LANDLOCK_ACCESS_FS_MAKE_FIFO
    | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | _LANDLOCK_ACCESS_FS_MAKE_SYM
    | _LANDLOCK_ACCESS_FS_REFER
    | _LANDLOCK_ACCESS_FS_TRUNCATE
)


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _linux_libc() -> ctypes.CDLL:
    if sys.platform != "linux" or os.uname().machine not in {"x86_64", "aarch64"}:
        fail("moriarty_linux_landlock_platform_required")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc


def landlock_abi_version() -> int:
    if sys.platform != "linux" or os.uname().machine not in {"x86_64", "aarch64"}:
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(0),
        ctypes.c_size_t(0),
        ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    return int(result) if result >= 0 else 0


def enable_child_subreaper() -> None:
    """Keep double-fork/setsid descendants attached to the MORIARTY harness."""
    libc = _linux_libc()
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        fail("moriarty_child_subreaper_unavailable")


def apply_landlock_write_policy(writable_paths: tuple[Path, ...]) -> None:
    """Deny filesystem mutation everywhere except explicitly writable roots."""
    if landlock_abi_version() < 3:
        raise OSError("moriarty_landlock_abi3_required")
    libc = _linux_libc()
    ruleset_attr = _LandlockRulesetAttr(_LANDLOCK_WRITE_MASK)
    ruleset_fd = libc.syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset_attr),
        ctypes.sizeof(ruleset_attr),
        0,
    )
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    try:
        for root in writable_paths:
            resolved = Path(root).resolve(strict=True)
            path_fd = os.open(resolved, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = _LandlockPathBeneathAttr(_LANDLOCK_WRITE_MASK, path_fd)
                result = libc.syscall(
                    _LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    _LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(rule),
                    0,
                )
                if result != 0:
                    raise OSError(ctypes.get_errno(), f"landlock_add_rule:{resolved}")
            finally:
                os.close(path_fd)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl_no_new_privs")
        if libc.syscall(_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    finally:
        os.close(ruleset_fd)


def landlock_write_preexec(writable_paths: tuple[Path, ...]):
    roots = tuple(Path(path).resolve(strict=True) for path in writable_paths)

    def _apply() -> None:
        apply_landlock_write_policy(roots)

    return _apply


'''
iso = replace_once(iso, marker, landlock + marker, "isolation landlock helpers")
write("tools/moriarty_isolation.py", iso)


# ---------------------------------------------------------------------------
# tools/run_moriarty.py
# ---------------------------------------------------------------------------
runner = read("tools/run_moriarty.py")
runner = replace_once(
    runner,
    '''    create_exact_export,
    create_isolated_cargo_home,
    proc_fd_path,
    stage_executable_from_fd,
    write_report_exclusive,
''',
    '''    create_exact_export,
    create_isolated_cargo_home,
    enable_child_subreaper,
    landlock_abi_version,
    landlock_write_preexec,
    proc_fd_path,
    write_report_exclusive,
''',
    "runner isolation imports",
)
runner = replace_once(
    runner,
    '''if os.name != "posix":
    raise SystemExit("moriarty_requires_posix_process_group_isolation")

REAL_HOME''',
    '''if os.name != "posix" or sys.platform != "linux":
    raise SystemExit("moriarty_requires_linux_process_and_landlock_isolation")
enable_child_subreaper()

REAL_HOME''',
    "runner linux/subreaper requirement",
)

# Add exact-path and Rustup concrete-toolchain discovery helpers, then replace
# the old four-entry initialization block.
init_start = runner.index('PYTHON_TRUSTED = _trusted_executable("python3"')
init_end = runner.index('# Source-owned and closed.', init_start)
new_init = r'''def _trusted_exact_path(name: str, path: Path) -> TrustedExecutable:
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

'''
runner = runner[:init_start] + new_init + runner[init_end:]

runner = replace_once(
    runner,
    '''        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
''',
    '''        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
''',
    "git replace objects disabled",
)

# Probe environment no longer exposes ambient Rustup selection to the probe.
runner = replace_region(
    runner,
    'def _probe_environment(',
    'def validate_attack_corpus',
    r'''def _probe_environment(
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


''',
    "probe environment concrete rustc",
)

# Close the attack corpus itself and every attack record.
runner = replace_once(
    runner,
    '''def validate_attack_corpus(corpus: dict[str, Any]) -> list[dict[str, Any]]:
    if (
''',
    '''def validate_attack_corpus(corpus: dict[str, Any]) -> list[dict[str, Any]]:
    expected_corpus_fields = {
        "schema", "protocol", "attacks", "production_credentials_allowed",
        "production_targets_allowed", "constitutional_bypass_allowed", "authority_effect",
    }
    expected_attack_fields = {"id", "family", "owner_phases", "boundary_ids", "probe_ids"}
    if set(corpus) != expected_corpus_fields:
        fail("moriarty_attack_corpus_field_set_invalid")
    if (
''',
    "attack corpus top closure",
)
runner = replace_once(
    runner,
    '''        if not isinstance(attack, dict):
            fail("moriarty_attack_record_invalid")
''',
    '''        if not isinstance(attack, dict):
            fail("moriarty_attack_record_invalid")
        if set(attack) != expected_attack_fields:
            fail("moriarty_attack_field_set_invalid")
''',
    "attack record closure",
)

# Close the accepted registry wrapper.
runner = replace_once(
    runner,
    '''    if (
        registry.get("schema") != REGISTRY_SCHEMA
''',
    '''    expected_registry_fields = {
        "schema", "protocol", "counterexamples", "unresolved_counterexamples", "authority_effect",
    }
    if set(registry) != expected_registry_fields:
        fail("moriarty_counterexample_registry_field_set_invalid")
    if (
        registry.get("schema") != REGISTRY_SCHEMA
''',
    "registry wrapper closure",
)
runner = replace_once(
    runner,
    '''    if registry.get("unresolved_counterexamples") != unresolved:
''',
    '''    if type(registry.get("unresolved_counterexamples")) is not int:
        fail("moriarty_counterexample_registry_unresolved_type_invalid")
    if registry.get("unresolved_counterexamples") != unresolved:
''',
    "registry unresolved type",
)

# Replace process-group-only cleanup with subreaper-aware descendant containment.
runner = replace_region(
    runner,
    'def _kill_process_group(',
    'def _probe_failure_result',
    r'''def _process_parent_map() -> dict[int, int]:
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


''',
    "descendant containment",
)

# Replace run_probe wholesale so Landlock, bounded overflow, and hard drain are
# one coherent state machine.
runner = replace_region(
    runner,
    'def run_probe(',
    'def generated_counterexample',
    r'''def run_probe(
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


''',
    "run probe hardening",
)

# Use a control export only for fixture parsing; every executable probe gets a
# fresh exact export, eliminating cross-probe mutation even before Landlock.
runner = replace_once(
    runner,
    '''        source_root = create_exact_export(
            target, workspace, lambda *git_args: git(*git_args).returncode, "target"
        )
        if not (source_root / "Cargo.lock").is_file():
            fail("moriarty_committed_cargo_lock_missing")

        corpus = load_json(source_root / "fixtures/phase9/attack-corpus.json")
        attacks = validate_attack_corpus(corpus)
        registry = load_json(source_root / "fixtures/phase9/accepted-counterexamples.json")
''',
    '''        if landlock_abi_version() < 3:
            fail("moriarty_landlock_abi3_required")
        control_source = create_exact_export(
            target, workspace, lambda *git_args: git(*git_args).returncode, "control"
        )
        if not (control_source / "Cargo.lock").is_file():
            fail("moriarty_committed_cargo_lock_missing")

        corpus = load_json(control_source / "fixtures/phase9/attack-corpus.json")
        attacks = validate_attack_corpus(corpus)
        registry = load_json(control_source / "fixtures/phase9/accepted-counterexamples.json")
''',
    "control export",
)
results_start = runner.index('        results = {')
results_end = runner.index('        verify_resolved_counterexamples', results_start)
new_results = r'''        results: dict[str, dict[str, Any]] = {}
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
'''
runner = runner[:results_start] + new_results + runner[results_end:]
write("tools/run_moriarty.py", runner)


# ---------------------------------------------------------------------------
# tools/validate_phase9_gate.py
# ---------------------------------------------------------------------------
validator = read("tools/validate_phase9_gate.py")

# Close every nested contract object using the exact existing field sets.
execution_fields = {
    "target_is_exact_git_commit", "target_commit_format", "checked_out_head_must_equal_target",
    "tracked_worktree_must_be_clean", "probe_environment_allowlisted", "probe_process_group_isolated",
    "probe_output_bounded", "shell_execution", "fixed_repository_probe_map", "arbitrary_command_execution",
    "production_credentials_allowed", "production_targets_allowed", "outbound_network_targeting_allowed",
    "constitutional_bypass_allowed", "semantic_payload_execution_allowed", "authority_effect",
    "exact_source_export", "source_export_read_only", "untracked_inputs_excluded",
    "tool_exec_via_open_descriptor", "cargo_home_cache_only", "cargo_target_outside_source",
    "report_output_external_private_exclusive",
}
probe_fields = {
    "historical_phase_gates_are_regressions", "constitutional_gate_is_regression", "rust_all_targets_is_regression",
    "probe_ids_are_source_allowlisted", "unknown_probe_id", "probe_output_semantic_content_in_report",
    "failure_output_is_recorded_by_digest_and_size_only", "maximum_output_bytes_per_stream", "timeout_seconds",
    "cargo_network_access", "cargo_mode", "shared_probe_failure_implies_specific_attack",
    "cargo_lockfile_committed", "cargo_user_config_inherited",
}
counter_fields = {
    "accepted_schema", "accepted_findings_are_reproducible", "accepted_findings_require_observed_local_failure",
    "accepted_findings_bind_to_attack_corpus", "accepted_findings_name_attack_family",
    "accepted_findings_name_owning_phases", "accepted_findings_name_boundary_ids",
    "accepted_findings_name_fixed_regression_probes", "regression_probes_must_be_subset_of_attack_probes",
    "external_findings_are_candidates_only", "candidate_can_enter_accepted_registry_without_local_reproduction",
    "maximum_accepted_counterexamples", "unresolved_accepted_finding_blocks_graduation",
    "unresolved_regressions_execute_before_graduation_decision", "resolved_finding_remains_in_registry",
    "resolved_finding_becomes_regression", "resolution_commit_is_fix_commit", "resolution_commit_must_exist",
    "resolution_commit_descends_from_finding_target", "resolution_commit_is_in_reviewed_history",
    "finding_may_create_authority", "finding_may_contain_production_credentials",
    "finding_may_target_production_system", "counterexample_id_stable_through_resolution",
    "resolved_requires_fail_before_pass_after", "resolved_failure_metadata_must_reproduce",
}
report_fields = {
    "schema", "binds_exact_target_commit", "binds_canonical_attack_corpus_identity",
    "records_probe_results_without_raw_output", "records_generated_counterexamples",
    "graduated_requires_zero_unresolved_counterexamples", "graduated_requires_all_probes_green",
    "failed_report_metadata_exposed_before_exit", "maximum_canonical_bytes", "maximum_counterexamples",
    "security_proof", "no_counterexample_found_implies_none_exist", "authority_effect",
    "generated_report_nested_schema_validated", "report_persisted_for_ci_artifact_upload",
}
validator = replace_once(
    validator,
    '''    execution = state["execution_boundary"]
    required_true = {
''',
    '''    execution = state["execution_boundary"]
    expected_execution_fields = ''' + repr(execution_fields) + '''
    require(set(execution) == expected_execution_fields, "MORIARTY execution boundary field set is not closed")
    required_true = {
''',
    "execution field closure",
)
validator = replace_once(
    validator,
    '''    probes = state["probe_policy"]
    require(probes["cargo_network_access"] is False''',
    '''    probes = state["probe_policy"]
    expected_probe_fields = ''' + repr(probe_fields) + '''
    require(set(probes) == expected_probe_fields, "MORIARTY probe policy field set is not closed")
    require(probes["cargo_network_access"] is False''',
    "probe policy closure",
)
validator = replace_once(
    validator,
    '''    counterexamples = state["counterexample_policy"]
    for key in (
''',
    '''    counterexamples = state["counterexample_policy"]
    expected_counterexample_fields = ''' + repr(counter_fields) + '''
    require(set(counterexamples) == expected_counterexample_fields, "MORIARTY counterexample policy field set is not closed")
    for key in (
''',
    "counterexample policy closure",
)
validator = replace_once(
    validator,
    '''    report = state["report_policy"]
    for key in (
''',
    '''    report = state["report_policy"]
    expected_report_fields = ''' + repr(report_fields) + '''
    require(set(report) == expected_report_fields, "MORIARTY report policy field set is not closed")
    for key in (
''',
    "report policy closure",
)

# Attack-corpus and registry closure negative tests.
validator = replace_once(
    validator,
    '''    corpus = load("fixtures/phase9/attack-corpus.json")
    attacks = moriarty.validate_attack_corpus(corpus)
''',
    '''    corpus = load("fixtures/phase9/attack-corpus.json")
    attacks = moriarty.validate_attack_corpus(corpus)
    corpus_extra = copy.deepcopy(corpus)
    corpus_extra["command"] = "forbidden"
    _expect_reject(lambda: moriarty.validate_attack_corpus(corpus_extra), "undeclared attack-corpus field")
    attack_extra = copy.deepcopy(corpus)
    attack_extra["attacks"][0]["credential"] = "forbidden"
    _expect_reject(lambda: moriarty.validate_attack_corpus(attack_extra), "undeclared attack-record field")
''',
    "attack closure negative tests",
)
validator = replace_once(
    validator,
    '''    unresolved = sum(1 for item in values if isinstance(item, dict) and item.get("status") == "unresolved")
    require(registry.get("unresolved_counterexamples") == unresolved, "MORIARTY registry unresolved count drift")
''',
    '''    unresolved = sum(1 for item in values if isinstance(item, dict) and item.get("status") == "unresolved")
    require(registry.get("unresolved_counterexamples") == unresolved, "MORIARTY registry unresolved count drift")
    registry_extra = copy.deepcopy(registry)
    registry_extra["member_local_authority"] = "root"
    _expect_reject(
        lambda: moriarty.validate_registry(registry_extra, attacks, git_head()),
        "undeclared accepted-registry wrapper field",
    )
''',
    "registry closure negative test",
)

# Strengthen toolchain and source markers.
validator = replace_once(
    validator,
    '''        "create_isolated_cargo_home", "stage_executable_from_fd", "write_report_exclusive", "--frozen", "candidate",
''',
    '''        "create_isolated_cargo_home", "landlock_write_preexec", "write_report_exclusive", "--frozen", "candidate",
        "GIT_NO_REPLACE_OBJECTS", "RUSTUP_DISCOVERY_USED", "_rustup_which", "bounded_output_update",
        "enable_child_subreaper", "_kill_probe_tree", "drain_deadline",
''',
    "runner source hardening markers",
)

# Extend validate_probe_map with concrete Rustup resolution checks and bounded
# overflow semantics.
needle = '''    stale = moriarty.TrustedExecutable(
'''
insert = r'''    if moriarty.RUSTUP_DISCOVERY_USED:
        require(moriarty.RUSTUP_TRUSTED is not None, "MORIARTY Rustup discovery flag without Rustup")
        require(isinstance(moriarty.RUST_TOOLCHAIN_ID, str) and moriarty.RUST_TOOLCHAIN_ID, "MORIARTY concrete Rust toolchain id missing")
        require(not moriarty._same_trusted_inode(moriarty.CARGO_TRUSTED, moriarty.RUSTUP_TRUSTED), "MORIARTY Cargo still points at Rustup shim")
        require(not moriarty._same_trusted_inode(moriarty.RUSTC_TRUSTED, moriarty.RUSTUP_TRUSTED), "MORIARTY rustc still points at Rustup shim")
        require(Path(moriarty.CARGO_TRUSTED.executable).parent == Path(moriarty.RUSTC_TRUSTED.executable).parent, "MORIARTY concrete Cargo/rustc toolchain mismatch")
    require(moriarty._git_env().get("GIT_NO_REPLACE_OBJECTS") == "1", "MORIARTY Git replacement objects are not disabled")
    digest = hashlib.sha256()
    bounded_count, overflow = moriarty.bounded_output_update(digest, moriarty.MAX_PROBE_OUTPUT_BYTES - 1, b"AB")
    require(bounded_count == moriarty.MAX_PROBE_OUTPUT_BYTES and overflow is True, "MORIARTY output overflow bound regression failed")

'''
validator = replace_once(validator, needle, insert + needle, "probe map toolchain/output checks")

# Kernel write denial regression: fork, apply the same Landlock policy, and prove
# a chmod does not permit mutation of a forbidden source-like file.
iso_test_marker = '''def validate_report_common(report: dict[str, Any], target: str) -> None:
'''
landlock_test = r'''def validate_kernel_write_denial() -> None:
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
        pid = os.fork()
        if pid == 0:
            try:
                moriarty.apply_landlock_write_policy((allowed,))
                os.chmod(victim, 0o600)
                try:
                    victim.write_text("changed", encoding="utf-8")
                except PermissionError:
                    os._exit(0)
                os._exit(2)
            except BaseException:
                os._exit(3)
        _, status = os.waitpid(pid, 0)
        require(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, "MORIARTY Landlock write-denial regression failed")
        require(victim.read_text(encoding="utf-8") == "original", "MORIARTY Landlock victim changed")


'''
validator = replace_once(validator, iso_test_marker, landlock_test + iso_test_marker, "landlock negative test")
validator = replace_once(
    validator,
    '''    validate_isolation_negative_tests(target)
    execute_exact_commit_gate''',
    '''    validate_isolation_negative_tests(target)
    validate_kernel_write_denial()
    execute_exact_commit_gate''',
    "call landlock test",
)
write("tools/validate_phase9_gate.py", validator)


# ---------------------------------------------------------------------------
# MORIARTY.md: keep the human threat-boundary description aligned.
# ---------------------------------------------------------------------------
docs = read("MORIARTY.md")
docs = docs.replace(
    "The runner resolves Python, Git, Cargo, and rustc outside the repository, opens and validates the executable inode, and executes through `/proc/self/fd` while preserving the intended `argv[0]`. A pathname replacement after validation therefore cannot substitute the executed interpreter or tool.",
    "The runner resolves Python and Git outside the repository and executes them through already-open validated descriptors. If Cargo/rustc are Rustup shims, Rustup is used only once to identify one active toolchain; the concrete Cargo and rustc binaries are then opened and pinned, and probe execution no longer delegates tool selection back to ambient Rustup. Git replacement objects are disabled for all identity, cleanliness, ancestry, and archive operations.",
)
docs = docs.replace(
    "The clean-tree check still rejects tracked source/index drift, but probes do not execute from that mutable checkout. The runner creates a read-only exact-commit export from `git archive`, rejects archive links/special files, and executes every fixed probe from that export.",
    "The clean-tree check still rejects tracked source/index drift, but probes do not execute from that mutable checkout. The runner creates a fresh exact-commit `git archive` export for every fixed probe, rejects archive links/special files, and applies Linux Landlock so the child cannot mutate the export even after changing Unix mode bits. Cross-probe source mutation is therefore eliminated both by kernel write denial and by never sharing an executable export between probes.",
)
docs = docs.replace(
    "The reference runner uses no shell. Every probe is started in its own process group. A timeout or output-bound failure terminates the complete group so surviving descendants cannot keep consuming resources or mutate the checkout after the result is recorded.",
    "The reference runner uses no shell. Every probe starts in its own process group, while the harness is also a Linux child subreaper. Timeout, pipe-leak, or output-bound failure kills the process group plus every adopted/descendant PID found through `/proc`, repeats the scan to close fork races, and imposes a hard two-second drain deadline so a `setsid()` descendant cannot keep inherited pipes open indefinitely.",
)
write("MORIARTY.md", docs)

print("phase9 Codex round2 transform applied")
