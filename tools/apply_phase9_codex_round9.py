#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one marker, found {count}")
    return text.replace(old, new, 1)


RUN = Path("tools/run_moriarty.py")
ISO = Path("tools/moriarty_isolation.py")
VAL = Path("tools/validate_phase9_gate.py")


def patch_bootstrap(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''_BOOTSTRAP_GIT = Path("/usr/bin/git")
_BOOTSTRAP_TARGET_RE = re.compile(r"^[0-9a-f]{40}$")
''',
        '''_BOOTSTRAP_GIT = Path("/usr/bin/git")
_BOOTSTRAP_TARGET_RE = re.compile(r"^[0-9a-f]{40}$")
try:
    _BOOTSTRAP_GIT_FD = os.open(_BOOTSTRAP_GIT, os.O_RDONLY | os.O_CLOEXEC)
    _BOOTSTRAP_GIT_INFO = os.fstat(_BOOTSTRAP_GIT_FD)
except OSError:
    raise SystemExit("moriarty_bootstrap_system_git_unavailable")
if not stat.S_ISREG(_BOOTSTRAP_GIT_INFO.st_mode) or not (_BOOTSTRAP_GIT_INFO.st_mode & 0o111):
    raise SystemExit("moriarty_bootstrap_system_git_invalid")
''',
        f"{path}: bootstrap git pin",
    )
    text = replace_once(
        text,
        '''def _bootstrap_git(*args: str) -> subprocess.CompletedProcess[bytes]:
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
''',
        '''def _bootstrap_git(*args: str) -> subprocess.CompletedProcess[bytes]:
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
''',
        f"{path}: bootstrap git execution",
    )
    text = replace_once(
        text,
        '''def _bootstrap_target() -> str:
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
''',
        '''def _bootstrap_target() -> str:
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
''',
        f"{path}: bootstrap target parser",
    )
    path.write_text(text, encoding="utf-8")


patch_bootstrap(RUN)
patch_bootstrap(VAL)

# Isolation: inherited hard limits, foreign-prlimit denial, writable-tree bounds,
# and bounded Rust runtime staging.
iso = ISO.read_text(encoding="utf-8")
iso = replace_once(iso, "import re\nimport stat\n", "import re\nimport resource\nimport stat\n", "isolation: resource import")
iso = replace_once(
    iso,
    '''MAX_CARGO_INDEX_DEPTH = 16
_CARGO_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
''',
    '''MAX_CARGO_INDEX_DEPTH = 16
PROBE_RLIMIT_AS_BYTES = 2 * 1024 * 1024 * 1024
PROBE_RLIMIT_FSIZE_BYTES = 512 * 1024 * 1024
PROBE_RLIMIT_NPROC = 128
PROBE_RLIMIT_NOFILE = 256
PROBE_RLIMIT_CPU_SECONDS = 330
MAX_PROBE_WRITABLE_BYTES = 2 * 1024 * 1024 * 1024
MAX_PROBE_WRITABLE_ENTRIES = 65_536
MAX_PROBE_WRITABLE_DEPTH = 64
PROBE_WRITABLE_CHECK_INTERVAL_SECONDS = 1.0
MAX_TOOLCHAIN_STAGE_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOOLCHAIN_STAGE_BYTES = 3 * 1024 * 1024 * 1024
MAX_TOOLCHAIN_STAGE_ENTRIES = 32_768
MAX_TOOLCHAIN_STAGE_DEPTH = 32
_CARGO_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
''',
    "isolation: resource constants",
)
iso = replace_once(
    iso,
    '''def _io_uring_syscalls() -> tuple[int, int, int]:
    return (425, 426, 427)


def apply_network_seccomp_policy''',
    '''def _io_uring_syscalls() -> tuple[int, int, int]:
    return (425, 426, 427)


def _prlimit_syscall() -> int:
    machine = os.uname().machine
    if machine == "x86_64":
        return 302
    if machine == "aarch64":
        return 261
    fail("moriarty_prlimit_seccomp_arch_unsupported")


def apply_network_seccomp_policy''',
    "isolation: prlimit syscall",
)
iso = replace_once(
    iso,
    '''    for number in (*_io_uring_syscalls(), pidfd_signal_nr, *_process_memory_syscalls()):
        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))
        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))
    for number in (kill_nr, tkill_nr, tgkill_nr, rt_sigqueueinfo_nr, rt_tgsigqueueinfo_nr):
''',
    '''    for number in (*_io_uring_syscalls(), pidfd_signal_nr, *_process_memory_syscalls()):
        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))
        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))
    # prlimit64 is self-only: pid 0 may tighten the probe's own inherited hard
    # ceiling, while any named PID (including the harness) is denied.
    prlimit_block = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, 0),
        _SockFilter(_BPF_RET_K, 0, 0, deny),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),
    ]
    instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, len(prlimit_block), _prlimit_syscall()))
    instructions.extend(prlimit_block)
    for number in (kill_nr, tkill_nr, tgkill_nr, rt_sigqueueinfo_nr, rt_tgsigqueueinfo_nr):
''',
    "isolation: foreign prlimit denial",
)
iso = replace_once(
    iso,
    '''def probe_isolation_preexec(
    read_exec_paths: tuple[Path, ...],
    read_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
):
''',
    '''def _apply_probe_resource_limits() -> None:
    def set_ceiling(kind: int, ceiling: int) -> None:
        _soft, hard = resource.getrlimit(kind)
        target = ceiling if hard == resource.RLIM_INFINITY else min(ceiling, hard)
        if target <= 0:
            fail("moriarty_probe_resource_limit_unavailable")
        resource.setrlimit(kind, (target, target))

    set_ceiling(resource.RLIMIT_AS, PROBE_RLIMIT_AS_BYTES)
    set_ceiling(resource.RLIMIT_FSIZE, PROBE_RLIMIT_FSIZE_BYTES)
    set_ceiling(resource.RLIMIT_NPROC, PROBE_RLIMIT_NPROC)
    set_ceiling(resource.RLIMIT_NOFILE, PROBE_RLIMIT_NOFILE)
    set_ceiling(resource.RLIMIT_CPU, PROBE_RLIMIT_CPU_SECONDS)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def probe_writable_tree_within_limits(paths: tuple[Path, ...]) -> bool:
    total_bytes = 0
    total_entries = 0
    for supplied in paths:
        try:
            root = Path(supplied).resolve(strict=True)
        except OSError:
            return False
        if not root.is_dir():
            return False
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > MAX_PROBE_WRITABLE_DEPTH:
                return False
            try:
                with os.scandir(current) as iterator:
                    entries = list(iterator)
            except OSError:
                return False
            for entry in entries:
                total_entries += 1
                if total_entries > MAX_PROBE_WRITABLE_ENTRIES:
                    return False
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    return False
                if stat.S_ISDIR(info.st_mode):
                    stack.append((Path(entry.path), depth + 1))
                elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    total_bytes += info.st_size
                    if total_bytes > MAX_PROBE_WRITABLE_BYTES:
                        return False
                else:
                    return False
    return True


def probe_isolation_preexec(
    read_exec_paths: tuple[Path, ...],
    read_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
):
''',
    "isolation: probe resource helpers",
)
iso = replace_once(
    iso,
    '''    def _apply() -> None:
        apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)
        apply_network_seccomp_policy(harness_pid, harness_pgid)
''',
    '''    def _apply() -> None:
        _apply_probe_resource_limits()
        apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)
        apply_network_seccomp_policy(harness_pid, harness_pgid)
''',
    "isolation: preexec resource limits",
)
old_stage = '''def _stable_stage_source(source: Path, destination: Path, toolchain_root: Path) -> None:
    try:
        resolved = source.resolve(strict=True)
    except OSError:
        fail("moriarty_toolchain_source_unavailable")
    root = toolchain_root.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        fail("moriarty_toolchain_symlink_escape")
    if not resolved.is_file():
        fail("moriarty_toolchain_nonregular_file")
    first = resolved.stat()
    fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    first_hash = hashlib.sha256()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    out = os.open(destination, flags, 0o700)
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            first_hash.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(out, view)
                view = view[written:]
        os.fsync(out)
        os.lseek(fd, 0, os.SEEK_SET)
        second_hash = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            second_hash.update(chunk)
        last = os.fstat(fd)
    finally:
        os.close(out)
        os.close(fd)
    if first_hash.digest() != second_hash.digest():
        fail("moriarty_toolchain_source_changed_during_stage")
    if (
        first.st_dev != last.st_dev
        or first.st_ino != last.st_ino
        or first.st_size != last.st_size
        or first.st_mtime_ns != last.st_mtime_ns
    ):
        fail("moriarty_toolchain_source_identity_changed_during_stage")
    if bytes.fromhex(_sha256_regular_file(destination)) != first_hash.digest():
        fail("moriarty_toolchain_stage_digest_mismatch")
    os.chmod(destination, 0o500 if first.st_mode & 0o111 else 0o400)


def stage_rust_toolchain_runtime(
    toolchain_root: Path,
    destination: Path,
    pinned_cargo_fd: int,
    pinned_rustc_fd: int,
) -> Path:
    """Privately snapshot the Rustup toolchain `bin` + complete runtime `lib` tree."""
    root = toolchain_root.resolve(strict=True)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for subdir in ("bin", "lib"):
        source_root = root / subdir
        if not source_root.is_dir():
            fail(f"moriarty_toolchain_subdir_missing:{subdir}")
        for current, dirs, files in os.walk(source_root, followlinks=False):
            current_path = Path(current)
            rel = current_path.relative_to(root)
            output_dir = destination / rel
            output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            for directory in list(dirs):
                if (current_path / directory).is_symlink():
                    fail("moriarty_toolchain_directory_symlink_forbidden")
            for name in sorted(files):
                if subdir == "bin" and name in {"cargo", "rustc"} and current_path == source_root:
                    continue
                _stable_stage_source(current_path / name, output_dir / name, root)
    _copy_fd_to_path(pinned_cargo_fd, destination / "bin" / "cargo", 0o500)
    _copy_fd_to_path(pinned_rustc_fd, destination / "bin" / "rustc", 0o500)
    if not (destination / "bin" / "cargo").is_file() or not (destination / "bin" / "rustc").is_file():
        fail("moriarty_staged_rust_toolchain_incomplete")
    seal_read_only_tree(destination)
    return destination
'''
new_stage = '''def _stable_stage_source(source: Path, destination: Path, toolchain_root: Path, max_bytes: int) -> int:
    if max_bytes < 0:
        fail("moriarty_toolchain_stage_bytes_exceeded")
    try:
        resolved = source.resolve(strict=True)
    except OSError:
        fail("moriarty_toolchain_source_unavailable")
    root = toolchain_root.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        fail("moriarty_toolchain_symlink_escape")
    if not resolved.is_file():
        fail("moriarty_toolchain_nonregular_file")
    first = resolved.stat()
    file_ceiling = min(MAX_TOOLCHAIN_STAGE_FILE_BYTES, max_bytes)
    if first.st_size < 0 or first.st_size > file_ceiling:
        fail("moriarty_toolchain_stage_file_too_large")
    fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    first_hash = hashlib.sha256()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    out = os.open(destination, flags, 0o700)
    copied = 0
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > file_ceiling:
                fail("moriarty_toolchain_stage_file_too_large")
            first_hash.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(out, view)
                view = view[written:]
        os.fsync(out)
        os.lseek(fd, 0, os.SEEK_SET)
        second_hash = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            second_hash.update(chunk)
        last = os.fstat(fd)
    finally:
        os.close(out)
        os.close(fd)
    if copied != first.st_size or first_hash.digest() != second_hash.digest():
        fail("moriarty_toolchain_source_changed_during_stage")
    if (
        first.st_dev != last.st_dev
        or first.st_ino != last.st_ino
        or first.st_size != last.st_size
        or first.st_mtime_ns != last.st_mtime_ns
    ):
        fail("moriarty_toolchain_source_identity_changed_during_stage")
    if bytes.fromhex(_sha256_regular_file(destination, max_bytes=file_ceiling, too_large_error="moriarty_toolchain_stage_file_too_large")) != first_hash.digest():
        fail("moriarty_toolchain_stage_digest_mismatch")
    os.chmod(destination, 0o500 if first.st_mode & 0o111 else 0o400)
    return copied


def stage_rust_toolchain_runtime(
    toolchain_root: Path,
    destination: Path,
    pinned_cargo_fd: int,
    pinned_rustc_fd: int,
) -> Path:
    """Privately snapshot a bounded Rust toolchain `bin` + runtime `lib` tree."""
    root = toolchain_root.resolve(strict=True)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    total_bytes = 0
    total_entries = 0
    for subdir in ("bin", "lib"):
        source_root = root / subdir
        if not source_root.is_dir():
            fail(f"moriarty_toolchain_subdir_missing:{subdir}")
        for current, dirs, files in os.walk(source_root, followlinks=False):
            current_path = Path(current)
            rel = current_path.relative_to(root)
            if len(rel.parts) > MAX_TOOLCHAIN_STAGE_DEPTH:
                fail("moriarty_toolchain_stage_depth_exceeded")
            total_entries += len(dirs) + len(files)
            if total_entries > MAX_TOOLCHAIN_STAGE_ENTRIES:
                fail("moriarty_toolchain_stage_entries_exceeded")
            output_dir = destination / rel
            output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            for directory in list(dirs):
                if (current_path / directory).is_symlink():
                    fail("moriarty_toolchain_directory_symlink_forbidden")
            for name in sorted(files):
                if subdir == "bin" and name in {"cargo", "rustc"} and current_path == source_root:
                    continue
                remaining = MAX_TOOLCHAIN_STAGE_BYTES - total_bytes
                copied = _stable_stage_source(current_path / name, output_dir / name, root, remaining)
                total_bytes += copied
                if total_bytes > MAX_TOOLCHAIN_STAGE_BYTES:
                    fail("moriarty_toolchain_stage_bytes_exceeded")
    for fd, name in ((pinned_cargo_fd, "cargo"), (pinned_rustc_fd, "rustc")):
        info = os.fstat(fd)
        total_entries += 1
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size < 0
            or info.st_size > MAX_TOOLCHAIN_STAGE_FILE_BYTES
            or total_entries > MAX_TOOLCHAIN_STAGE_ENTRIES
            or total_bytes + info.st_size > MAX_TOOLCHAIN_STAGE_BYTES
        ):
            fail("moriarty_toolchain_pinned_component_bound_exceeded")
        _copy_fd_to_path(fd, destination / "bin" / name, 0o500)
        total_bytes += info.st_size
    if not (destination / "bin" / "cargo").is_file() or not (destination / "bin" / "rustc").is_file():
        fail("moriarty_staged_rust_toolchain_incomplete")
    seal_read_only_tree(destination)
    return destination
'''
iso = replace_once(iso, old_stage, new_stage, "isolation: bounded Rust stage")
ISO.write_text(iso, encoding="utf-8")

# Runner: consume an explicit pre-execution Rust snapshot, pin replay versions,
# watch aggregate writable storage, and bind argparse to the bootstrap target.
run = RUN.read_text(encoding="utf-8")
run = replace_once(
    run,
    '''probe_isolation_preexec = _moriarty_isolation.probe_isolation_preexec
proc_fd_path = _moriarty_isolation.proc_fd_path
''',
    '''probe_isolation_preexec = _moriarty_isolation.probe_isolation_preexec
probe_writable_tree_within_limits = _moriarty_isolation.probe_writable_tree_within_limits
proc_fd_path = _moriarty_isolation.proc_fd_path
''',
    "runner: writable watchdog alias",
)
old_toolchain = '''GIT_TRUSTED = _trusted_executable("git")
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
'''
new_toolchain = '''GIT_TRUSTED = _trusted_executable("git")
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
'''
run = replace_once(run, old_toolchain, new_toolchain, "runner: CI snapshot toolchain")
run = replace_once(
    run,
    '''    writable_paths = [home, cargo_home, target_dir, temp_dir, *_system_writable_files()]
    preexec = probe_isolation_preexec(
        tuple(read_exec_paths),
        _system_read_paths(),
        tuple(writable_paths),
    )
''',
    '''    private_writable_paths = [home, cargo_home, target_dir, temp_dir]
    writable_paths = [*private_writable_paths, *_system_writable_files()]
    if not probe_writable_tree_within_limits(tuple(private_writable_paths)):
        return _probe_failure_result(probe_id, "tool_error", b"writable_resource_limit_exceeded_before_probe")
    preexec = probe_isolation_preexec(
        tuple(read_exec_paths),
        _system_read_paths(),
        tuple(writable_paths),
    )
''',
    "runner: writable roots",
)
run = replace_once(
    run,
    '''    failure_kind: str | None = None

    try:
        while selector.get_map():
            now = time.monotonic()
''',
    '''    failure_kind: str | None = None
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
''',
    "runner: writable watchdog",
)
run = replace_once(
    run,
    '''    leaked_descendants = _descendant_pids(os.getpid())
    if leaked_descendants:
        failure_kind = failure_kind or "tool_error"
        _kill_probe_tree(process)
    _reap_adopted_children()

    if not tracked_tree_clean():
''',
    '''    leaked_descendants = _descendant_pids(os.getpid())
    if leaked_descendants:
        failure_kind = failure_kind or "tool_error"
        _kill_probe_tree(process)
    _reap_adopted_children()
    if not probe_writable_tree_within_limits(tuple(private_writable_paths)):
        failure_kind = failure_kind or "tool_error"

    if not tracked_tree_clean():
''',
    "runner: final writable bound",
)
run = replace_once(
    run,
    '''    parser = argparse.ArgumentParser(description="Run the MORIARTY/1 exact-commit graduation harness")
''',
    '''    parser = argparse.ArgumentParser(description="Run the MORIARTY/1 exact-commit graduation harness", allow_abbrev=False)
''',
    "runner: argparse abbreviations",
)
run = replace_once(
    run,
    '''    target = args.target_commit
    if not TARGET_RE.fullmatch(target):
''',
    '''    target = args.target_commit
    if target != _BOOTSTRAP_TARGET:
        fail("moriarty_target_commit_bootstrap_mismatch")
    if not TARGET_RE.fullmatch(target):
''',
    "runner: bootstrap target binding",
)
run = replace_once(
    run,
    '''        rust_source_root = (
            Path(CARGO_TRUSTED.executable).parent.parent
            if RUSTUP_DISCOVERY_USED
            else _direct_toolchain_root(CARGO_TRUSTED, RUSTC_TRUSTED)
        )
''',
    '''        rust_source_root = (
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
''',
    "runner: snapshot source root",
)
RUN.write_text(run, encoding="utf-8")

# Validator: executable regressions and CI/source-contract closure.
val = VAL.read_text(encoding="utf-8")
val = replace_once(
    val,
    '''    require(0 < moriarty.MAX_GIT_PATH_BYTES <= 4096, "MORIARTY Git path bound invalid")
    system_reads = moriarty._system_read_paths()
''',
    '''    require(0 < moriarty.MAX_GIT_PATH_BYTES <= 4096, "MORIARTY Git path bound invalid")
    isolation = moriarty._moriarty_isolation
    require(0 < isolation.PROBE_RLIMIT_NPROC <= 256, "MORIARTY process-count ceiling invalid")
    require(0 < isolation.PROBE_RLIMIT_NOFILE <= 512, "MORIARTY descriptor ceiling invalid")
    require(0 < isolation.PROBE_RLIMIT_AS_BYTES <= 2 * 1024 * 1024 * 1024, "MORIARTY address-space ceiling invalid")
    require(0 < isolation.PROBE_RLIMIT_FSIZE_BYTES <= 512 * 1024 * 1024, "MORIARTY file-size ceiling invalid")
    require(0 < isolation.MAX_PROBE_WRITABLE_BYTES <= 2 * 1024 * 1024 * 1024, "MORIARTY aggregate writable-byte ceiling invalid")
    require(0 < isolation.MAX_TOOLCHAIN_STAGE_BYTES <= 3 * 1024 * 1024 * 1024, "MORIARTY toolchain stage byte ceiling invalid")
    require(0 < isolation.MAX_TOOLCHAIN_STAGE_ENTRIES <= 32768, "MORIARTY toolchain stage entry ceiling invalid")
    system_reads = moriarty._system_read_paths()
''',
    "validator: resource bound assertions",
)
val = replace_once(
    val,
    '''    require(not moriarty.trusted_executable_matches(stale), "MORIARTY executable identity negative regression failed")


def validate_runner_source() -> None:
''',
    '''    require(not moriarty.trusted_executable_matches(stale), "MORIARTY executable identity negative regression failed")

    saved_argv = list(sys.argv)
    try:
        sys.argv = ["run_moriarty.py", "--target-commit", git_head(), "--target-commit", git_head()]
        _expect_reject(moriarty._bootstrap_target, "duplicate bootstrap target arguments")
        sys.argv = ["run_moriarty.py", f"--target-commit={git_head()}"]
        require(moriarty._bootstrap_target() == git_head(), "bootstrap target equals-form drift")
    finally:
        sys.argv = saved_argv


def validate_runner_source() -> None:
''',
    "validator: bootstrap target regressions",
)
val = replace_once(
    val,
    '''def validate_runner_source() -> None:
    source = (ROOT / "tools/run_moriarty.py").read_text(encoding="utf-8")
    validator_bootstrap = "\\n".join((ROOT / "tools/validate_phase9_gate.py").read_text(encoding="utf-8").splitlines()[:180])
''',
    '''def validate_runner_source() -> None:
    source = (ROOT / "tools/run_moriarty.py").read_text(encoding="utf-8")
    validator_source = (ROOT / "tools/validate_phase9_gate.py").read_text(encoding="utf-8")
    validator_bootstrap = "\\n".join(validator_source.splitlines()[:220])
    bootstrap_start = '_BOOTSTRAP_GIT = Path("/usr/bin/git")'
    runner_block = source[source.index(bootstrap_start):source.index("_BOOTSTRAP_TARGET =", source.index(bootstrap_start))]
    validator_block = validator_source[validator_source.index(bootstrap_start):validator_source.index("_BOOTSTRAP_TARGET =", validator_source.index(bootstrap_start))]
    require(runner_block == validator_block, "Phase 9 runner/validator bootstrap blocks diverged")
''',
    "validator: bootstrap parity",
)
val = replace_once(
    val,
    '''    for marker in (
        "provider-neutral-fixed-probe/1",''',
    '''    # These string checks are defense-in-depth maintenance tripwires only.
    # Enforcement comes from verified target bytes, the closed probe map, and the
    # Landlock/seccomp/resource boundary; marker presence is not a security proof.
    for marker in (
        "provider-neutral-fixed-probe/1",''',
    "validator: marker scan comment",
)
val = replace_once(
    val,
    '''        "_bootstrap_verified_blob", "compile(expected", "ALLOWED_OWNER_PHASES", "_RUNTIME_NORMALIZATIONS", "close_fds=True",
''',
    '''        "_bootstrap_verified_blob", "compile(expected", "ALLOWED_OWNER_PHASES", "_RUNTIME_NORMALIZATIONS", "close_fds=True",
        "probe_writable_tree_within_limits", "MORIARTY_RUST_TOOLCHAIN_ROOT", "allow_abbrev=False",
''',
    "validator: new runner markers",
)
val = replace_once(
    val,
    '''        require(not (second / "config.toml").exists(), "per-probe Cargo homes contaminated each other")

    cargo_dir = ROOT / ".cargo"
''',
    '''        require(not (second / "config.toml").exists(), "per-probe Cargo homes contaminated each other")

        writable_bound = root / "writable-bound"
        writable_bound.mkdir()
        oversized_writable = writable_bound / "oversized"
        oversized_writable.write_bytes(b"")
        os.truncate(oversized_writable, moriarty._moriarty_isolation.MAX_PROBE_WRITABLE_BYTES + 1)
        require(
            not moriarty.probe_writable_tree_within_limits((writable_bound,)),
            "aggregate writable storage bound regression failed",
        )

        fake_toolchain = root / "fake-toolchain"
        (fake_toolchain / "bin").mkdir(parents=True)
        (fake_toolchain / "lib" / "rustlib").mkdir(parents=True)
        (fake_toolchain / "bin" / "rustdoc").write_bytes(b"rustdoc")
        huge_runtime = fake_toolchain / "lib" / "oversized.so"
        huge_runtime.write_bytes(b"")
        os.truncate(huge_runtime, moriarty._moriarty_isolation.MAX_TOOLCHAIN_STAGE_FILE_BYTES + 1)
        _expect_reject(
            lambda: moriarty.stage_rust_toolchain_runtime(
                fake_toolchain,
                root / "fake-toolchain-stage",
                moriarty.CARGO_TRUSTED.fd,
                moriarty.RUSTC_TRUSTED.fd,
            ),
            "oversized Rust toolchain staging input",
        )

    cargo_dir = ROOT / ".cargo"
''',
    "validator: storage/toolchain negative tests",
)
val = replace_once(
    val,
    '''for number, args in (
    (queue_nr, (int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),
    (tgqueue_nr, (int(parent_pid), int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),
):
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        raise SystemExit(8)
forbidden_etc = Path("/etc/hostname")
''',
    '''for number, args in (
    (queue_nr, (int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),
    (tgqueue_nr, (int(parent_pid), int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),
):
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        raise SystemExit(8)
import resource
class RLimit(ctypes.Structure):
    _fields_ = [("cur", ctypes.c_ulong), ("maximum", ctypes.c_ulong)]
prlimit_nr = 302 if machine == "x86_64" else 261
new_limit = RLimit(1, 1)
ctypes.set_errno(0)
result = libc.syscall(prlimit_nr, int(parent_pid), resource.RLIMIT_NOFILE, ctypes.byref(new_limit), ctypes.c_void_p(0))
if result != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit(9)
forbidden_etc = Path("/etc/hostname")
''',
    "validator: prlimit kernel regression",
)
val = replace_once(val, "        raise SystemExit(9)\nctypes.set_errno(0)\nresult = libc.syscall(425", "        raise SystemExit(10)\nctypes.set_errno(0)\nresult = libc.syscall(425", "validator: etc exit renumber")
val = replace_once(val, "    raise SystemExit(10)\nraise SystemExit(0)\n", "    raise SystemExit(11)\nraise SystemExit(0)\n", "validator: io_uring exit renumber")
val = replace_once(
    val,
    '''    require("ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow, "CI does not checkout the exact PR-head/push commit")
''',
    '''    require("runs-on: ubuntu-24.04" in workflow, "CI runner OS is not pinned to ubuntu-24.04")
    require("ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow, "CI does not checkout the exact PR-head/push commit")
''',
    "validator: pinned runner marker",
)
val = replace_once(
    val,
    '''    require("MORIARTY_TARGET_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow, "CI MORIARTY target commit binding missing")
    require("cargo test --all-targets --locked" in workflow, "CI Rust suite is not lockfile-bound")
''',
    '''    require("MORIARTY_TARGET_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow, "CI MORIARTY target commit binding missing")
    snapshot_marker = "Snapshot trusted CI toolchains before repository execution"
    rust_test_marker = "Rust tests, state, Holodeck, adapters, SDKs, Assembly, transports, and fuzz smoke"
    require(snapshot_marker in workflow and workflow.index(snapshot_marker) < workflow.index(rust_test_marker), "CI toolchain snapshot does not precede repository execution")
    require('rustc 1.97.1 (8bab26f4f 2026-07-14)' in workflow, "CI rustc replay version is not pinned")
    require('cargo 1.97.1 (c980f4866 2026-06-30)' in workflow, "CI Cargo replay version is not pinned")
    require('Python 3.12.3' in workflow, "CI Python replay version is not pinned")
    require('$RUNNER_TEMP/moriarty-rust-toolchain/bin/cargo\" test --all-targets --locked' in workflow, "CI Rust suite does not use the pre-execution snapshot")
    require("MORIARTY_RUST_TOOLCHAIN_ROOT: ${{ runner.temp }}/moriarty-rust-toolchain" in workflow, "CI MORIARTY Rust snapshot binding missing")
    require("MORIARTY_EXPECTED_PYTHON_VERSION: Python 3.12.3" in workflow, "CI MORIARTY Python version binding missing")
    require("MORIARTY_EXPECTED_RUSTC_VERSION: rustc 1.97.1 (8bab26f4f 2026-07-14)" in workflow, "CI MORIARTY rustc version binding missing")
    require("MORIARTY_EXPECTED_CARGO_VERSION: cargo 1.97.1 (c980f4866 2026-06-30)" in workflow, "CI MORIARTY Cargo version binding missing")
''',
    "validator: CI snapshot contract",
)
val = replace_once(
    val,
    '''    require("python3 -I tools/validate_phase9_gate.py --target-commit \\"$MORIARTY_TARGET_COMMIT\\" --report-dir \\"$MORIARTY_REPORT_DIR\\"" in workflow, "CI missing isolated exact-commit Phase 9 gate")
''',
    '''    require("/usr/bin/python3 -I tools/validate_phase9_gate.py --target-commit \\"$MORIARTY_TARGET_COMMIT\\" --report-dir \\"$MORIARTY_REPORT_DIR\\"" in workflow, "CI missing isolated exact-commit Phase 9 gate")
''',
    "validator: pinned Python Phase9 command",
)
val = replace_once(
    val,
    '''    parser = argparse.ArgumentParser(description="Validate the Phase 9 MORIARTY/1 graduation gate")
''',
    '''    parser = argparse.ArgumentParser(description="Validate the Phase 9 MORIARTY/1 graduation gate", allow_abbrev=False)
''',
    "validator: argparse abbreviations",
)
val = replace_once(
    val,
    '''    target = args.target_commit or git_head()
    require(bool(TARGET_RE.fullmatch(target)), "Phase 9 target commit format invalid")
''',
    '''    target = args.target_commit or git_head()
    require(target == _BOOTSTRAP_TARGET, "Phase 9 target commit differs from bootstrap target")
    require(bool(TARGET_RE.fullmatch(target)), "Phase 9 target commit format invalid")
''',
    "validator: bootstrap target binding",
)
VAL.write_text(val, encoding="utf-8")
