#!/usr/bin/env python3
"""One-shot transformer for the final Sol review on Phase 9.

Temporary scaffolding. The stored remediation workflow commits the transformed
normative/source files; this helper is deleted before the final exact-head run.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"phase9 sol replacement drift:{label}:{count}")
    return text.replace(old, new, 1)


def replace_region(text: str, start: str, end: str, replacement: str, label: str) -> str:
    begin = text.find(start)
    finish = text.find(end, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        raise SystemExit(f"phase9 sol region drift:{label}:{begin}:{finish}")
    return text[:begin] + replacement + text[finish:]


ISOLATION = r'''#!/usr/bin/env python3
"""Isolation primitives for the MORIARTY/1 exact-commit runner."""
from __future__ import annotations

import ctypes
import errno
import hashlib
import io
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
    return rights if path.is_dir() else rights & ~_LANDLOCK_ACCESS_FS_READ_DIR


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


def _network_syscalls() -> tuple[int, ...]:
    machine = os.uname().machine
    if machine == "x86_64":
        return (41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307)
    if machine == "aarch64":
        return (198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 242, 243, 269)
    fail("moriarty_network_seccomp_arch_unsupported")


def apply_network_seccomp_policy() -> None:
    """Deny socket creation and all socket I/O syscalls with EPERM."""
    libc = _linux_libc()
    instructions: list[_SockFilter] = [_SockFilter(_BPF_LD_W_ABS, 0, 0, 0)]
    deny = _SECCOMP_RET_ERRNO | errno.EPERM
    for number in _network_syscalls():
        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))
        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))
    instructions.append(_SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
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


def create_verified_cargo_template(real_cargo_home: Path, workspace: Path, cargo_lock: Path) -> Path:
    """Build an immutable cache template from lock-authenticated `.crate` archives.

    Ambient unpacked `registry/src` executable code is never copied. Cargo must
    unpack each verified package archive into the disposable per-probe home.
    """
    template = workspace / "cargo-template"
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
            fail(f"moriarty_verified_cargo_archive_missing:{filename}")
        selected = matching[0]
        cache_namespace = selected.parent.name
        _copy_regular_file(selected, template / "registry" / "cache" / cache_namespace / filename, checksum)
    if (template / "registry" / "src").exists():
        fail("moriarty_cargo_template_must_not_copy_registry_src")
    seal_read_only_tree(template)
    return template


def create_isolated_cargo_home(template: Path, workspace: Path, label: str) -> Path:
    cargo_home = workspace / f"cargo-home-{label}"
    cargo_home.mkdir(mode=0o700, parents=False, exist_ok=False)
    _copy_regular_tree(template, cargo_home)
    if (cargo_home / "config.toml").exists() or (cargo_home / "credentials.toml").exists():
        fail("moriarty_cargo_home_ambient_config_or_credentials")
    if (cargo_home / "registry" / "src").exists():
        fail("moriarty_cargo_home_preunpacked_source_forbidden")
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
'''
write("tools/moriarty_isolation.py", ISOLATION)


# ---------------------------------------------------------------------------
# tools/run_moriarty.py
# ---------------------------------------------------------------------------
runner = read("tools/run_moriarty.py")
runner = replace_once(
    runner,
    '''from moriarty_isolation import (  # noqa: E402
    create_exact_export,
    create_isolated_cargo_home,
    enable_child_subreaper,
    landlock_abi_version,
    landlock_write_preexec,
    proc_fd_path,
    write_report_exclusive,
)
''',
    '''from moriarty_isolation import (  # noqa: E402
    create_empty_cargo_home,
    create_exact_export,
    create_isolated_cargo_home,
    create_verified_cargo_template,
    enable_child_subreaper,
    landlock_abi_version,
    network_seccomp_supported,
    probe_isolation_preexec,
    proc_fd_path,
    stage_executable_from_fd,
    stage_rust_toolchain_runtime,
    write_report_exclusive,
)
''',
    "runner isolation imports",
)
runner = replace_once(
    runner,
    'MAX_REPORT_BYTES = 65_536\n',
    'MAX_REPORT_BYTES = 65_536\nMAX_GIT_ARCHIVE_BYTES = 64 * 1024 * 1024\nPOST_EXIT_DRAIN_SECONDS = 2.0\nTERMINATION_DRAIN_SECONDS = 2.0\nHARNESS_PATHS = ("tools/run_moriarty.py", "tools/moriarty_isolation.py", "tools/qsol_canonical.py")\n',
    "runner constants",
)

runner = replace_region(
    runner,
    'def tracked_tree_clean() -> bool:\n',
    'def git_commit_exists',
    r'''def _index_flags_output_clean(raw: bytes) -> bool:
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


def tracked_tree_clean() -> bool:
    return (
        git("diff", "--quiet", "HEAD", "--").returncode == 0
        and git("diff", "--cached", "--quiet", "--").returncode == 0
        and index_flags_clean()
    )


def harness_files_match_target(target: str, extra_paths: Sequence[str] = ()) -> bool:
    for path in (*HARNESS_PATHS, *extra_paths):
        completed = git("show", f"{target}:{path}")
        if completed.returncode != 0:
            return False
        try:
            actual = (ROOT / path).read_bytes()
        except OSError:
            return False
        if actual != completed.stdout:
            return False
    return True


def git_archive_bytes(commit: str) -> bytes:
    completed = git("archive", "--format=tar", commit)
    if completed.returncode != 0:
        fail("moriarty_exact_export_git_archive_failed")
    if len(completed.stdout) > MAX_GIT_ARCHIVE_BYTES:
        fail("moriarty_exact_export_archive_too_large")
    return completed.stdout


''',
    "runner tree/archive hardening",
)

runner = replace_region(
    runner,
    'def _probe_environment(\n',
    'def validate_attack_corpus',
    r'''def _probe_environment(
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
    return tuple(path for path in (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64")) if path.exists())


def _system_read_paths() -> tuple[Path, ...]:
    return tuple(path for path in (Path("/etc"), Path("/dev/urandom"), Path("/dev/random")) if path.exists())


def _system_writable_files() -> tuple[Path, ...]:
    return tuple(path for path in (Path("/dev/null"),) if path.exists())


def _fresh_cargo_home(probe_id: str, template: Path, workspace: Path, label: str) -> Path:
    if probe_id == "rust_all":
        return create_isolated_cargo_home(template, workspace, label)
    return create_empty_cargo_home(workspace, label)


''',
    "runner probe environment",
)

runner = replace_region(
    runner,
    'def _probe_failure_result(',
    'def generated_counterexample',
    r'''def _probe_failure_result(probe_id: str, kind: str, diagnostic: bytes) -> dict[str, Any]:
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
    writable_paths = [home, cargo_home, target_dir, temp_dir, *_system_writable_files()]
    preexec = probe_isolation_preexec(
        tuple(read_exec_paths),
        _system_read_paths(),
        tuple(writable_paths),
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
    truncated = {"stdout": False, "stderr": False}
    deadline = time.monotonic() + TIMEOUT_SECONDS
    post_exit_deadline: float | None = None
    termination_deadline: float | None = None
    failure_kind: str | None = None

    try:
        while selector.get_map():
            now = time.monotonic()
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
    if leaked_descendants:
        failure_kind = failure_kind or "tool_error"
        _kill_probe_tree(process)
    _reap_adopted_children()

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

    return {
        "probe_id": probe_id,
        "ok": ok,
        "exit_code": return_code if failure_kind == "exit_nonzero" or ok else None,
        "failure_kind": failure_kind,
        "stdout_sha256": "sha256:" + digests["stdout"].hexdigest(),
        "stderr_sha256": "sha256:" + digests["stderr"].hexdigest(),
        "stdout_bytes": counts["stdout"],
        "stderr_bytes": counts["stderr"],
        "stdout_truncated": truncated["stdout"],
        "stderr_truncated": truncated["stderr"],
    }


''',
    "runner probe execution",
)

runner = replace_region(
    runner,
    'def verify_resolved_counterexamples(\n',
    'def report_probe_result',
    r'''def verify_resolved_counterexamples(
    accepted: list[dict[str, Any]],
    workspace: Path,
    cargo_template: Path,
    python_exec: Path,
    cargo_exec: Path,
    rustc_exec: Path,
    rustdoc_exec: Path | None,
    rust_runtime: Path | None,
) -> None:
    for index, item in enumerate(accepted):
        if item["status"] != "resolved":
            continue
        probe_id = item["regression_probe_ids"][0]
        before_source = create_exact_export(
            item["target_commit"], workspace, git_archive_bytes, f"resolved-{index}-before"
        )
        before_cargo = _fresh_cargo_home(
            probe_id, cargo_template, workspace, f"resolved-{index}-before"
        )
        before = run_probe(
            probe_id,
            workspace / f"resolved-{index}-before-home",
            before_source,
            before_cargo,
            workspace / f"resolved-{index}-before-target",
            python_exec,
            cargo_exec,
            rustc_exec,
            rustdoc_exec,
            rust_runtime,
        )
        if not counterexample_failure_matches(item, before):
            fail("moriarty_resolution_target_failure_not_reproduced")

        resolution = item["resolution_commit"]
        assert isinstance(resolution, str)
        after_source = create_exact_export(
            resolution, workspace, git_archive_bytes, f"resolved-{index}-after"
        )
        after_cargo = _fresh_cargo_home(
            probe_id, cargo_template, workspace, f"resolved-{index}-after"
        )
        after = run_probe(
            probe_id,
            workspace / f"resolved-{index}-after-home",
            after_source,
            after_cargo,
            workspace / f"resolved-{index}-after-target",
            python_exec,
            cargo_exec,
            rustc_exec,
            rustdoc_exec,
            rust_runtime,
        )
        if after["ok"] is not True or after["exit_code"] != 0:
            fail("moriarty_resolution_fix_probe_not_green")


''',
    "runner remediation replay isolation",
)
runner = replace_region(
    runner,
    'def report_probe_result(result: dict[str, Any]) -> dict[str, Any]:\n',
    'def main() -> int:',
    r'''def report_probe_result(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result[key] for key in (
        "probe_id", "ok", "exit_code", "failure_kind",
        "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes",
        "stdout_truncated", "stderr_truncated",
    )}


''',
    "runner report projection",
)

runner = replace_region(
    runner,
    'def main() -> int:\n',
    'if __name__ == "__main__":',
    r'''def main() -> int:
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
        fail("moriarty_target_tracked_tree_or_index_flags_dirty")
    if not harness_files_match_target(target):
        fail("moriarty_harness_worktree_bytes_do_not_match_target")

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
            REAL_HOME / ".cargo", workspace, control_source / "Cargo.lock"
        )
        python_exec = stage_executable_from_fd(
            PYTHON_TRUSTED.fd, workspace / "python-runtime" / "python3"
        )

        rust_runtime: Path | None = None
        if RUSTUP_DISCOVERY_USED:
            rust_source_root = Path(CARGO_TRUSTED.executable).parent.parent
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
        else:
            cargo_exec = Path(CARGO_TRUSTED.executable)
            rustc_exec = Path(RUSTC_TRUSTED.executable)
            rustdoc_exec = None

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
            probe_cargo_home = _fresh_cargo_home(probe_id, cargo_template, workspace, label)
            results[probe_id] = run_probe(
                probe_id,
                workspace / f"home-{probe_index}-{probe_id}",
                probe_source,
                probe_cargo_home,
                workspace / f"target-{probe_index}-{probe_id}",
                python_exec,
                cargo_exec,
                rustc_exec,
                rustdoc_exec,
                rust_runtime,
            )
        verify_resolved_counterexamples(
            accepted,
            workspace,
            cargo_template,
            python_exec,
            cargo_exec,
            rustc_exec,
            rustdoc_exec,
            rust_runtime,
        )

    generated: list[dict[str, Any]] = []
    for probe_id, result in results.items():
        if result["ok"]:
            continue
        owners = probe_users.get(probe_id, [])
        if len(owners) == 1 and result["failure_kind"] in {"exit_nonzero", "timeout", "tool_error"}:
            generated.append(generated_counterexample(target, owners[0], result))

    unresolved_accepted = [item for item in accepted if item["status"] == "unresolved"]
    unresolved_count = len(unresolved_accepted) + len(generated)
    all_probes_ok = all(result["ok"] for result in results.values())

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
    if git_head() != target or not tracked_tree_clean() or not harness_files_match_target(target):
        fail("moriarty_target_or_harness_changed_during_report_publication")

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


''',
    "runner main",
)
write("tools/run_moriarty.py", runner)


# ---------------------------------------------------------------------------
# Claims/state/schema contract updates.
# ---------------------------------------------------------------------------
claims_path = ROOT / "claims/phase9.json"
claims = json.loads(claims_path.read_text(encoding="utf-8"))
claims["assurance"].update({
    "network_syscalls_denied": True,
    "probe_proc_read_isolated": True,
    "per_probe_cargo_home": True,
    "verified_cargo_registry_archives": True,
    "staged_rust_toolchain_runtime": True,
})
claims_path.write_text(json.dumps(claims, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

state_path = ROOT / "state/phase9.json"
state = json.loads(state_path.read_text(encoding="utf-8"))
state["execution_boundary"].update({
    "probe_network_syscalls_denied": True,
    "probe_proc_read_isolated": True,
    "rust_toolchain_runtime_staged": True,
})
state["probe_policy"].update({
    "cargo_home_per_probe": True,
    "cargo_registry_archives_verified_against_lock": True,
})
state["report_policy"].update({
    "probe_failure_kind_persisted": True,
    "probe_output_truncation_persisted": True,
})
state["phase9_gate"] = (
    "For the exact clean checked-out commit, MORIARTY/1 materializes tracked bytes directly from pinned Git archive output and runs each fixed probe from its own exact export. Linux Landlock enforces read/execute and write allowlists, exposes only the probe's own /proc PID subtree, and seccomp denies socket/network syscalls for the probe and descendants. Python is privately staged; Rustup toolchains are resolved to concrete Cargo/rustc and the complete bin/lib runtime is privately staged before adversarial execution. Cargo uses the committed lockfile, verified registry .crate archives, no ambient unpacked registry source, a fresh per-probe Cargo home, frozen offline resolution, and an external target directory. Resolved findings replay fail-before/pass-after with independent exports and Cargo state. Bounded reports persist failure kind and truncation metadata. No unresolved reproducible counterexample or failed fixed probe may cross graduation. MORIARTY adds assurance only and does not promote the Phase 8 capability surface."
)
state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

report_schema_path = ROOT / "schemas/moriarty-report-v1.schema.json"
report_schema = json.loads(report_schema_path.read_text(encoding="utf-8"))
probe_item = report_schema["properties"]["probe_results"]["items"]
probe_required = [
    "probe_id", "ok", "exit_code", "failure_kind", "stdout_sha256", "stderr_sha256",
    "stdout_bytes", "stderr_bytes", "stdout_truncated", "stderr_truncated",
]
probe_item["required"] = probe_required
probe_item["properties"] = {
    "probe_id": {"type": "string", "pattern": "^[a-z0-9_]{1,64}$"},
    "ok": {"type": "boolean"},
    "exit_code": {"type": ["integer", "null"], "minimum": -2147483648, "maximum": 2147483647},
    "failure_kind": {"type": ["string", "null"], "enum": [None, "exit_nonzero", "timeout", "tool_error"]},
    "stdout_sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "stderr_sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
    "stdout_bytes": {"type": "integer", "minimum": 0, "maximum": 1048576},
    "stderr_bytes": {"type": "integer", "minimum": 0, "maximum": 1048576},
    "stdout_truncated": {"type": "boolean"},
    "stderr_truncated": {"type": "boolean"},
}
report_schema_path.write_text(json.dumps(report_schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

counter_schema_path = ROOT / "schemas/moriarty-counterexample-v1.schema.json"
counter_schema = json.loads(counter_schema_path.read_text(encoding="utf-8"))
counter_schema["properties"]["stdout_bytes"]["maximum"] = 1048576
counter_schema["properties"]["stderr_bytes"]["maximum"] = 1048576
counter_schema_path.write_text(json.dumps(counter_schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# tools/validate_phase9_gate.py
# ---------------------------------------------------------------------------
validator = read("tools/validate_phase9_gate.py")
validator = replace_region(
    validator,
    'def _validate_claim_document(',
    'def validate_claims',
    r'''PHASE9_CLAIM_RULE = "Phase 9 adds adversarial graduation assurance, not a new runtime or protocol capability. The Phase 8 capability map remains unchanged. A MORIARTY report is evidence about execution of the exact reviewed regression surface, not a security proof, authority grant, production-deployment certification, or proof that no counterexample exists."


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


''',
    "validator claims",
)
validator = replace_region(
    validator,
    'def validate_claims() -> None:\n',
    'def validate_contract',
    r'''def validate_claims() -> None:
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


''',
    "validator claim negative tests",
)

# Update closed state field sets and required truths without replacing all semantic checks.
validator = replace_once(
    validator,
    "'source_export_read_only', 'tool_exec_via_open_descriptor', 'probe_environment_allowlisted'}",
    "'source_export_read_only', 'tool_exec_via_open_descriptor', 'probe_environment_allowlisted', 'probe_network_syscalls_denied', 'probe_proc_read_isolated', 'rust_toolchain_runtime_staged'}",
    "execution field additions",
)
validator = replace_once(
    validator,
    '"cargo_target_outside_source", "report_output_external_private_exclusive",\n    }',
    '"cargo_target_outside_source", "report_output_external_private_exclusive",\n        "probe_network_syscalls_denied", "probe_proc_read_isolated", "rust_toolchain_runtime_staged",\n    }',
    "execution true additions",
)
validator = replace_once(
    validator,
    "'unknown_probe_id', 'cargo_user_config_inherited'}",
    "'unknown_probe_id', 'cargo_user_config_inherited', 'cargo_home_per_probe', 'cargo_registry_archives_verified_against_lock'}",
    "probe policy fields",
)
validator = replace_once(
    validator,
    'require(probes["cargo_user_config_inherited"] is False, "MORIARTY Cargo user config became ambient")\n',
    'require(probes["cargo_user_config_inherited"] is False, "MORIARTY Cargo user config became ambient")\n    require(probes["cargo_home_per_probe"] is True, "MORIARTY Cargo home is shared across probes")\n    require(probes["cargo_registry_archives_verified_against_lock"] is True, "MORIARTY Cargo archives are not lock-authenticated")\n',
    "probe policy truths",
)
validator = replace_once(
    validator,
    "'failed_report_metadata_exposed_before_exit', 'graduated_requires_zero_unresolved_counterexamples'}",
    "'failed_report_metadata_exposed_before_exit', 'graduated_requires_zero_unresolved_counterexamples', 'probe_failure_kind_persisted', 'probe_output_truncation_persisted'}",
    "report policy fields",
)
validator = replace_once(
    validator,
    '"report_persisted_for_ci_artifact_upload",\n    ):',
    '"report_persisted_for_ci_artifact_upload", "probe_failure_kind_persisted",\n        "probe_output_truncation_persisted",\n    ):',
    "report policy truths",
)

validator = replace_region(
    validator,
    'def validate_schemas_and_fixtures() -> None:\n',
    'def validate_probe_map',
    r'''def _require_closed_schema_fields(schema: dict[str, Any], expected: set[str], name: str) -> None:
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
        "executed_probe_count", "probe_results", "counterexamples", "unresolved_counterexamples",
        "graduated", "production_credentials_used", "production_targets_used",
        "constitutional_bypass_used", "security_proof", "no_counterexample_found_implies_none_exist",
        "authority_effect",
    }
    probe_result_fields = {
        "probe_id", "ok", "exit_code", "failure_kind", "stdout_sha256", "stderr_sha256",
        "stdout_bytes", "stderr_bytes", "stdout_truncated", "stderr_truncated",
    }
    _require_closed_schema_fields(corpus_schema, corpus_fields, "attack corpus")
    _require_closed_schema_fields(corpus_schema["properties"]["attacks"]["items"], attack_fields, "attack record")
    _require_closed_schema_fields(counterexample_schema, counterexample_fields, "counterexample")
    _require_closed_schema_fields(report_schema, report_fields, "report")
    _require_closed_schema_fields(report_schema["properties"]["probe_results"]["items"], probe_result_fields, "probe result")

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

    corpus = load("fixtures/phase9/attack-corpus.json")
    attacks = moriarty.validate_attack_corpus(corpus)
    corpus_extra = copy.deepcopy(corpus)
    corpus_extra["command"] = "forbidden"
    _expect_reject(lambda: moriarty.validate_attack_corpus(corpus_extra), "undeclared attack-corpus field")
    attack_extra = copy.deepcopy(corpus)
    attack_extra["attacks"][0]["credential"] = "forbidden"
    _expect_reject(lambda: moriarty.validate_attack_corpus(attack_extra), "undeclared attack-record field")
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


''',
    "validator exact schemas",
)

# Probe-map source markers and index parser regressions.
validator = replace_once(
    validator,
    'require(moriarty._git_env().get("GIT_NO_REPLACE_OBJECTS") == "1", "MORIARTY Git replacement objects are not disabled")\n',
    'require(moriarty._git_env().get("GIT_NO_REPLACE_OBJECTS") == "1", "MORIARTY Git replacement objects are not disabled")\n    require(moriarty._index_flags_output_clean(b"H tools/run_moriarty.py\\n"), "normal Git index flag parser failed")\n    require(not moriarty._index_flags_output_clean(b"h tools/run_moriarty.py\\n"), "assume-unchanged index flag was accepted")\n    require(not moriarty._index_flags_output_clean(b"S tools/run_moriarty.py\\n"), "skip-worktree index flag was accepted")\n',
    "validator index regressions",
)
validator = replace_once(
    validator,
    '"create_isolated_cargo_home", "landlock_write_preexec", "write_report_exclusive", "--frozen", "candidate",\n',
    '"create_isolated_cargo_home", "create_verified_cargo_template", "probe_isolation_preexec",\n        "stage_rust_toolchain_runtime", "git_archive_bytes", "index_flags_clean",\n        "write_report_exclusive", "--frozen", "candidate",\n',
    "validator runner markers 1",
)
validator = replace_once(
    validator,
    '"enable_child_subreaper", "_kill_probe_tree", "drain_deadline",\n',
    '"enable_child_subreaper", "_kill_probe_tree", "post_exit_deadline", "termination_deadline",\n',
    "validator runner markers 2",
)
validator = replace_once(
    validator,
    '"security_proof", "no_counterexample_found_implies_none_exist",\n',
    '"security_proof", "no_counterexample_found_implies_none_exist", "stdout_truncated", "stderr_truncated",\n',
    "validator runner markers 3",
)

validator = replace_region(
    validator,
    'def validate_isolation_negative_tests(target: str) -> None:\n',
    'def validate_kernel_write_denial',
    r'''def validate_isolation_negative_tests(target: str) -> None:
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


''',
    "validator isolation negatives",
)

# Keep the existing write-denial regression, then insert network + /proc read denial.
insert = r'''

def validate_kernel_network_and_proc_denial() -> None:
    require(moriarty.network_seccomp_supported(), "MORIARTY requires network seccomp support")
    with tempfile.TemporaryDirectory(prefix="moriarty-net-proc-test-") as temp_dir:
        root = Path(temp_dir)
        writable = root / "writable"
        writable.mkdir(mode=0o700)
        parent_pid = os.getpid()
        program = r'''
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
    if exc.errno == errno.EPERM:
        raise SystemExit(0)
    raise
raise SystemExit(4)
'''
        preexec = moriarty.probe_isolation_preexec(
            tuple(path for path in (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64")) if path.exists()),
            tuple(path for path in (Path("/etc"), Path("/dev/urandom"), Path("/dev/random")) if path.exists()),
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
'''
validator = replace_once(
    validator,
    '\n\ndef validate_report_common(report: dict[str, Any], target: str) -> None:\n',
    insert + '\n\ndef validate_report_common(report: dict[str, Any], target: str) -> None:\n',
    "validator network/proc regression insertion",
)

validator = replace_once(
    validator,
    'result_fields = {"probe_id", "ok", "exit_code", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes"}',
    'result_fields = {"probe_id", "ok", "exit_code", "failure_kind", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes", "stdout_truncated", "stderr_truncated"}',
    "validator report result fields",
)
validator = replace_once(
    validator,
    '''        if item["ok"]:
            require(exit_code == 0, "MORIARTY successful probe lacks zero exit code")
        else:
            require(exit_code is None or exit_code != 0, "MORIARTY failed probe reports zero exit code")
''',
    '''        failure_kind = item["failure_kind"]
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
                require(item[f"{stream}_bytes"] == moriarty.MAX_PROBE_OUTPUT_BYTES, f"truncated {stream} did not stop at byte bound")
                require(failure_kind == "tool_error", f"truncated {stream} must be a tool_error")
''',
    "validator report result semantics",
)
validator = replace_once(
    validator,
    '''            "exit_code": item["exit_code"],
            "stdout_sha256": item["stdout_sha256"],
''',
    '''            "exit_code": item["exit_code"],
            "failure_kind": item["failure_kind"],
            "stdout_truncated": item["stdout_truncated"],
            "stderr_truncated": item["stderr_truncated"],
            "stdout_sha256": item["stdout_sha256"],
''',
    "failure diagnostic metadata",
)
validator = replace_once(
    validator,
    'require(moriarty.tracked_tree_clean(), "Phase 9 target tracked tree is dirty before runner")\n',
    'require(moriarty.tracked_tree_clean(), "Phase 9 target tracked tree/index flags are dirty before runner")\n    require(moriarty.harness_files_match_target(target, ("tools/validate_phase9_gate.py",)), "Phase 9 executed harness bytes differ from target")\n',
    "execute harness identity",
)
validator = replace_once(
    validator,
    '    validate_kernel_write_denial()\n    execute_exact_commit_gate',
    '    validate_kernel_write_denial()\n    validate_kernel_network_and_proc_denial()\n    execute_exact_commit_gate',
    "main isolation call",
)
write("tools/validate_phase9_gate.py", validator)


# ---------------------------------------------------------------------------
# MORIARTY.md concise architecture update.
# ---------------------------------------------------------------------------
docs = read("MORIARTY.md")
docs = replace_once(
    docs,
    "The reference runner uses no shell. Every probe starts in its own process group, while the harness is also a Linux child subreaper.",
    "The reference runner uses no shell. Every probe runs under a Landlock read/execute/write allowlist that exposes only its own `/proc/<pid>` subtree, so runner, validator, shell, and Actions-process environments are not readable by the probe. A seccomp filter denies socket creation and socket I/O syscalls and is inherited by all descendants; therefore `production_targets_used = false` is backed by a kernel network-denial boundary, not merely by fixed argv or Cargo offline mode. Every probe starts in its own process group, while the harness is also a Linux child subreaper.",
    "docs network/proc",
)
docs = replace_once(
    docs,
    "The Rust regression probe runs `cargo test --all-targets --frozen` against the committed `Cargo.lock`.",
    "The Rust regression probe runs `cargo test --all-targets --frozen` against the committed `Cargo.lock`. MORIARTY authenticates every registry `.crate` archive against the checksum recorded in that lockfile and never imports ambient unpacked `~/.cargo/registry/src` code. Each Rust execution receives a fresh disposable Cargo home projected from the immutable verified archive template, so current probes and fail-before/pass-after replays cannot contaminate one another. If Rustup is present, MORIARTY snapshots the concrete toolchain `bin` and complete runtime `lib` tree into a private read-only stage before adversarial execution, preventing later Rustup/toolchain pathname selection and pinning dynamically loaded rustc/LLVM code for the run.",
    "docs cargo/toolchain",
)
docs = replace_once(
    docs,
    "Standard output and error are hashed incrementally and capped at 1,048,576 bytes per stream rather than buffered without limit.",
    "Standard output and error are hashed incrementally and capped at 1,048,576 bytes per stream rather than buffered without limit. Persisted probe results include the failure kind plus independent stdout/stderr truncation flags, so a capped overflow cannot masquerade as an exact-bound stream, timeout, or unrelated tool error. A normally exited process receives a bounded drain grace to consume buffered bytes and EOF before retained descriptors are classified as a descendant leak.",
    "docs trunc/drain",
)
docs = replace_once(
    docs,
    "The runner creates a fresh exact-commit `git archive` export for every fixed probe, rejects archive links/special files, and applies Linux Landlock",
    "The runner consumes each exact-commit `git archive` directly from pinned Git stdout with no named intermediate tar, creates a fresh export for every fixed probe, rejects archive links/special files, and applies Linux Landlock",
    "docs archive",
)
write("MORIARTY.md", docs)

# Extra files are pre-staged so the stored remediation workflow's later `git add`
# of the four source/docs files still commits the full contract change atomically.
subprocess.run(
    [
        "git", "add",
        "claims/phase9.json",
        "state/phase9.json",
        "schemas/moriarty-report-v1.schema.json",
        "schemas/moriarty-counterexample-v1.schema.json",
    ],
    cwd=ROOT,
    check=True,
)
