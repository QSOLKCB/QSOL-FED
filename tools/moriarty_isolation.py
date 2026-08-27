#!/usr/bin/env python3
"""Isolation primitives for the MORIARTY/1 exact-commit runner."""
from __future__ import annotations

import ctypes
import errno
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tomllib
from pathlib import Path
from typing import Callable, NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_CHILD_SUBREAPER = 36
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

_LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
_LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
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
_LANDLOCK_READ_MASK = _LANDLOCK_ACCESS_FS_READ_FILE | _LANDLOCK_ACCESS_FS_READ_DIR
_LANDLOCK_READ_EXEC_MASK = _LANDLOCK_READ_MASK | _LANDLOCK_ACCESS_FS_EXECUTE
_LANDLOCK_HANDLED_MASK = _LANDLOCK_WRITE_MASK | _LANDLOCK_READ_EXEC_MASK

_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_DATA_ARCH_OFFSET = 4
_SECCOMP_DATA_ARG0_OFFSET = 16
_AF_UNIX = 1
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _linux_libc() -> ctypes.CDLL:
    if sys.platform != "linux" or os.uname().machine not in {"x86_64", "aarch64"}:
        fail("moriarty_linux_isolation_platform_required")
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


def network_seccomp_supported() -> bool:
    return sys.platform == "linux" and os.uname().machine in {"x86_64", "aarch64"}


def enable_child_subreaper() -> None:
    libc = _linux_libc()
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        fail("moriarty_child_subreaper_unavailable")


def _landlock_rights_for(path: Path, rights: int) -> int:
    if path.is_dir():
        return rights
    file_rights = (
        _LANDLOCK_ACCESS_FS_EXECUTE
        | _LANDLOCK_ACCESS_FS_WRITE_FILE
        | _LANDLOCK_ACCESS_FS_READ_FILE
        | _LANDLOCK_ACCESS_FS_TRUNCATE
    )
    return rights & file_rights


def _add_landlock_rule(libc: ctypes.CDLL, ruleset_fd: int, path: Path, rights: int) -> None:
    resolved = Path(path).resolve(strict=True)
    path_fd = os.open(resolved, os.O_PATH | os.O_CLOEXEC)
    try:
        allowed = _landlock_rights_for(resolved, rights)
        rule = _LandlockPathBeneathAttr(allowed, path_fd)
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


def apply_landlock_policy(
    read_exec_paths: tuple[Path, ...],
    read_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
    *,
    allow_self_proc: bool = True,
) -> None:
    """Allow only declared reads/execs and declared mutation roots.

    `/proc` is intentionally absent except for the probe's own PID subtree. That
    prevents a same-UID probe from reading the runner/validator/Actions process
    environments while preserving `/proc/self/*` functionality needed by runtimes.
    """
    if landlock_abi_version() < 3:
        raise OSError("moriarty_landlock_abi3_required")
    libc = _linux_libc()
    ruleset_attr = _LandlockRulesetAttr(_LANDLOCK_HANDLED_MASK)
    ruleset_fd = libc.syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset_attr),
        ctypes.sizeof(ruleset_attr),
        0,
    )
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    try:
        seen: set[tuple[str, int]] = set()
        for path, rights in (
            *((path, _LANDLOCK_READ_EXEC_MASK) for path in read_exec_paths),
            *((path, _LANDLOCK_READ_MASK) for path in read_paths),
            *((path, _LANDLOCK_READ_EXEC_MASK | _LANDLOCK_WRITE_MASK) for path in writable_paths),
        ):
            if not Path(path).exists():
                continue
            resolved = str(Path(path).resolve(strict=True))
            key = (resolved, rights)
            if key in seen:
                continue
            seen.add(key)
            _add_landlock_rule(libc, ruleset_fd, Path(resolved), rights)
        if allow_self_proc:
            self_proc = Path("/proc") / str(os.getpid())
            _add_landlock_rule(libc, ruleset_fd, self_proc, _LANDLOCK_READ_MASK)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl_no_new_privs")
        if libc.syscall(_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    finally:
        os.close(ruleset_fd)


def apply_landlock_write_policy(writable_paths: tuple[Path, ...]) -> None:
    """Backward-compatible write-only regression primitive."""
    if landlock_abi_version() < 3:
        raise OSError("moriarty_landlock_abi3_required")
    libc = _linux_libc()
    attr = _LandlockRulesetAttr(_LANDLOCK_WRITE_MASK)
    ruleset_fd = libc.syscall(_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    try:
        for root in writable_paths:
            _add_landlock_rule(libc, ruleset_fd, root, _LANDLOCK_WRITE_MASK)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl_no_new_privs")
        if libc.syscall(_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    finally:
        os.close(ruleset_fd)


def _socket_syscalls() -> tuple[int, int, int]:
    machine = os.uname().machine
    if machine == "x86_64":
        return (41, 53, _AUDIT_ARCH_X86_64)
    if machine == "aarch64":
        return (198, 199, _AUDIT_ARCH_AARCH64)
    fail("moriarty_network_seccomp_arch_unsupported")


def _io_uring_syscalls() -> tuple[int, int, int]:
    # io_uring syscall numbers are shared by the supported Linux architectures.
    return (425, 426, 427)


def apply_network_seccomp_policy() -> None:
    """Allow AF_UNIX IPC while denying external socket creation and io_uring.

    The filter first binds itself to the expected Linux audit architecture. It
    denies io_uring entirely so IORING_OP_SOCKET/CONNECT/SEND cannot bypass the
    native syscall policy. Native socket()/socketpair() are then allowed only for
    AF_UNIX; every other family fails at creation with EPERM. The probe receives
    no ambient network descriptors, so later socket I/O can only operate on local
    Unix-domain IPC descriptors created inside the sandbox.
    """
    libc = _linux_libc()
    deny = _SECCOMP_RET_ERRNO | errno.EPERM
    allow = _SECCOMP_RET_ALLOW
    socket_nr, socketpair_nr, audit_arch = _socket_syscalls()
    instructions: list[_SockFilter] = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, audit_arch),
        _SockFilter(_BPF_RET_K, 0, 0, deny),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),
    ]
    for number in _io_uring_syscalls():
        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))
        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))
    instructions.extend([
        _SockFilter(_BPF_JMP_JEQ_K, 2, 0, socket_nr),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, socketpair_nr),
        _SockFilter(_BPF_RET_K, 0, 0, allow),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_UNIX),
        _SockFilter(_BPF_RET_K, 0, 0, allow),
        _SockFilter(_BPF_RET_K, 0, 0, deny),
    ])
    array_type = _SockFilter * len(instructions)
    array = array_type(*instructions)
    program = _SockFprog(len(instructions), array)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl_no_new_privs_seccomp")
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl_seccomp_network_filter")


def probe_isolation_preexec(
    read_exec_paths: tuple[Path, ...],
    read_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
):
    read_exec = tuple(Path(path).resolve(strict=True) for path in read_exec_paths if Path(path).exists())
    readable = tuple(Path(path).resolve(strict=True) for path in read_paths if Path(path).exists())
    writable = tuple(Path(path).resolve(strict=True) for path in writable_paths if Path(path).exists())

    def _apply() -> None:
        apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)
        apply_network_seccomp_policy()

    return _apply


def landlock_write_preexec(writable_paths: tuple[Path, ...]):
    roots = tuple(Path(path).resolve(strict=True) for path in writable_paths)

    def _apply() -> None:
        apply_landlock_write_policy(roots)

    return _apply


def proc_fd_path(fd: int) -> str:
    path = Path(f"/proc/self/fd/{fd}")
    if not path.exists():
        fail("moriarty_proc_fd_unavailable")
    return str(path)


def _relative_archive_name(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail("moriarty_archive_member_path_invalid")
    return path


def extract_exact_archive_bytes(archive_bytes: bytes, destination: Path) -> None:
    """Extract trusted Git archive bytes without any named intermediate tar."""
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            _relative_archive_name(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                fail("moriarty_archive_special_member_forbidden")
            if not (member.isdir() or member.isfile()):
                fail("moriarty_archive_member_type_forbidden")
        for member in members:
            relative = _relative_archive_name(member.name)
            output = destination / relative
            if member.isdir():
                output.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                fail("moriarty_archive_file_unreadable")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(output, flags, 0o600)
            try:
                while True:
                    chunk = source.read(65536)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(fd, view)
                        view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
                source.close()
            os.chmod(output, 0o500 if member.mode & 0o111 else 0o400)


def seal_read_only_tree(root: Path) -> None:
    for current, dirs, files in os.walk(root, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            path = current_path / name
            if path.is_symlink():
                fail("moriarty_export_symlink_forbidden")
            mode = path.stat().st_mode
            os.chmod(path, 0o500 if mode & 0o111 else 0o400)
        for name in dirs:
            path = current_path / name
            if path.is_symlink():
                fail("moriarty_export_symlink_forbidden")
            os.chmod(path, 0o500)
    os.chmod(root, 0o500)


def create_exact_export(
    target_commit: str,
    workspace: Path,
    read_git_archive: Callable[[str], bytes],
    label: str,
) -> Path:
    """Materialize exact tracked bytes directly from pinned Git output."""
    source_root = workspace / f"{label}-src"
    archive_bytes = read_git_archive(target_commit)
    extract_exact_archive_bytes(archive_bytes, source_root)
    seal_read_only_tree(source_root)
    return source_root


def _copy_regular_file(source: Path, destination: Path, expected_sha256: str | None = None) -> None:
    if source.is_symlink() or not source.is_file():
        fail("moriarty_copy_source_nonregular")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | (getattr(os, "O_NOFOLLOW", 0)))
    source_hash = hashlib.sha256()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    output_fd = os.open(destination, flags, 0o600)
    try:
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                break
            source_hash.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                view = view[written:]
        os.fsync(output_fd)
    finally:
        os.close(output_fd)
        os.close(source_fd)
    digest = source_hash.hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        fail(f"moriarty_cargo_archive_checksum_mismatch:{source.name}")
    if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
        fail("moriarty_copy_digest_mismatch")


def _copy_regular_tree(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for current, dirs, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        output_dir = destination / relative
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in list(dirs):
            if (current_path / directory).is_symlink():
                fail("moriarty_cargo_cache_symlink_forbidden")
        for name in files:
            source_file = current_path / name
            if source_file.is_symlink() or not source_file.is_file():
                fail("moriarty_cargo_cache_nonregular_file")
            _copy_regular_file(source_file, output_dir / name)


def _locked_registry_packages(cargo_lock: Path) -> list[tuple[str, str, str]]:
    try:
        value = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        fail("moriarty_cargo_lock_parse_failed")
    packages: list[tuple[str, str, str]] = []
    for package in value.get("package", []):
        if not isinstance(package, dict):
            fail("moriarty_cargo_lock_package_invalid")
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("registry+"):
            continue
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(checksum, str)
            or len(checksum) != 64
            or any(ch not in "0123456789abcdef" for ch in checksum)
        ):
            fail("moriarty_cargo_lock_registry_package_invalid")
        packages.append((name, version, checksum))
    if not packages:
        fail("moriarty_cargo_lock_registry_packages_missing")
    return packages


def create_verified_cargo_template(
    real_cargo_home: Path, workspace: Path, cargo_lock: Path, label: str = "cargo-template"
) -> Path:
    """Build an immutable cache template from lock-authenticated `.crate` archives.

    Ambient unpacked `registry/src` executable code is never copied. Cargo must
    unpack each verified package archive into the disposable per-probe home.
    """
    if not label or "/" in label or "\\" in label or label in {".", ".."}:
        fail("moriarty_cargo_template_label_invalid")
    template = workspace / label
    template.mkdir(mode=0o700, parents=False, exist_ok=False)
    index_source = real_cargo_home / "registry" / "index"
    _copy_regular_tree(index_source, template / "registry" / "index")
    cache_root = real_cargo_home / "registry" / "cache"
    for name, version, checksum in _locked_registry_packages(cargo_lock):
        filename = f"{name}-{version}.crate"
        candidates = sorted(cache_root.glob(f"*/{filename}")) if cache_root.exists() else []
        matching: list[Path] = []
        for candidate in candidates:
            if candidate.is_file() and not candidate.is_symlink():
                digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
                if digest == checksum:
                    matching.append(candidate)
        if not matching:
            # Cargo.lock may include platform-specific packages not required by
            # the current runner target, so a preceding locked all-targets build
            # can legitimately leave their archives absent. Never synthesize or
            # trust an absent package. If any archive with this package filename
            # exists but none matches the lock checksum, reject it; otherwise the
            # later --frozen --offline Cargo probe remains the fail-closed test of
            # whether this target actually requires the absent package.
            if candidates:
                fail(f"moriarty_cargo_archive_checksum_mismatch:{filename}")
            continue
        selected = matching[0]
        cache_namespace = selected.parent.name
        _copy_regular_file(selected, template / "registry" / "cache" / cache_namespace / filename, checksum)
    if (template / "registry" / "src").exists():
        fail("moriarty_cargo_template_must_not_copy_registry_src")
    seal_read_only_tree(template)
    return template


def _owned_cargo_config(workspace: Path) -> bytes:
    """Return harness-owned Cargo settings without importing user configuration.

    The real runner stages Rust under `workspace/rust-runtime` before creating
    per-probe homes. When that runtime is present, explicitly pass its sysroot so
    rustc descendants do not need `/proc/self/exe` for toolchain discovery. The
    validator also exercises this helper before staging Rust, so the sysroot
    stanza is conditional while the offline policy remains unconditional.
    """
    lines = []
    rust_runtime = workspace / "rust-runtime"
    if rust_runtime.is_dir():
        sysroot = rust_runtime.resolve(strict=True)
        lines.extend([
            "[build]\n",
            f"rustflags = [\"--sysroot\", {json.dumps(str(sysroot))}]\n",
        ])
    lines.extend(["[net]\n", "offline = true\n"])
    return "".join(lines).encode("utf-8")


def create_isolated_cargo_home(template: Path, workspace: Path, label: str) -> Path:
    cargo_home = workspace / f"cargo-home-{label}"
    cargo_home.mkdir(mode=0o700, parents=False, exist_ok=False)
    _copy_regular_tree(template, cargo_home)
    config_toml = cargo_home / "config.toml"
    legacy_config = cargo_home / "config"
    credentials_path = cargo_home / "credentials.toml"
    if config_toml.exists() or legacy_config.exists() or credentials_path.exists():
        fail("moriarty_cargo_home_ambient_config_or_credentials")
    if (cargo_home / "registry" / "src").exists():
        fail("moriarty_cargo_home_preunpacked_source_forbidden")
    config = _owned_cargo_config(workspace)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(legacy_config, flags, 0o600)
    try:
        view = memoryview(config)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if legacy_config.read_bytes() != config or config_toml.exists() or credentials_path.exists():
        fail("moriarty_cargo_home_owned_config_mismatch")
    return cargo_home


def create_empty_cargo_home(workspace: Path, label: str) -> Path:
    cargo_home = workspace / f"cargo-home-{label}"
    cargo_home.mkdir(mode=0o700, parents=False, exist_ok=False)
    return cargo_home


def _copy_fd_to_path(source_fd: int, destination: Path, mode: int) -> str:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    output_fd = os.open(destination, flags, 0o700)
    digest = hashlib.sha256()
    try:
        source_copy = os.open(proc_fd_path(source_fd), os.O_RDONLY | os.O_CLOEXEC)
        try:
            while True:
                chunk = os.read(source_copy, 65536)
                if not chunk:
                    break
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output_fd, view)
                    view = view[written:]
            os.fsync(output_fd)
        finally:
            os.close(source_copy)
    finally:
        os.close(output_fd)
    if hashlib.sha256(destination.read_bytes()).digest() != digest.digest():
        fail("moriarty_staged_executable_digest_mismatch")
    os.chmod(destination, mode)
    return digest.hexdigest()


def stage_executable_from_fd(source_fd: int, destination: Path) -> Path:
    parent = destination.parent
    parent.mkdir(mode=0o700, parents=False, exist_ok=False)
    _copy_fd_to_path(source_fd, destination, 0o500)
    os.chmod(parent, 0o500)
    return destination


def _stable_stage_source(source: Path, destination: Path, toolchain_root: Path) -> None:
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
    if hashlib.sha256(destination.read_bytes()).digest() != first_hash.digest():
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


def private_directory(path: Path) -> bool:
    try:
        info = path.stat()
    except OSError:
        return False
    return path.is_dir() and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0


def write_report_exclusive(output: Path, encoded: bytes, repository_root: Path) -> None:
    if not output.is_absolute() or output.name in {"", ".", ".."}:
        fail("moriarty_report_output_must_be_absolute")
    try:
        repository = repository_root.resolve(strict=True)
        parent = output.parent.resolve(strict=True)
    except OSError:
        fail("moriarty_report_parent_unavailable")
    if parent == repository or repository in parent.parents:
        fail("moriarty_report_output_inside_repository")
    if not private_directory(parent):
        fail("moriarty_report_parent_not_private")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    directory_fd = os.open(parent, directory_flags)
    try:
        info = os.fstat(directory_fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            fail("moriarty_report_parent_changed")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(output.name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            fail("moriarty_report_output_exists")
        except OSError:
            fail("moriarty_report_output_open_failed")
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
