#!/usr/bin/env python3
"""Isolation primitives for the MORIARTY/1 exact-commit runner."""
from __future__ import annotations

import ctypes
import errno
import hashlib
import io
import json
import os
import re
import resource
import stat
import sys
import tarfile
import time
import tomllib
from pathlib import Path
from typing import Callable, NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


MAX_CARGO_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_CARGO_INDEX_BYTES = 16 * 1024 * 1024
MAX_CARGO_INDEX_ENTRIES = 16_384
MAX_CARGO_INDEX_DEPTH = 16
MAX_CARGO_CACHE_BYTES = 1024 * 1024 * 1024
PROBE_RLIMIT_AS_BYTES = 2 * 1024 * 1024 * 1024
PROBE_RLIMIT_FSIZE_BYTES = 512 * 1024 * 1024
PROBE_RLIMIT_NPROC = 128
PROBE_RLIMIT_NOFILE = 256
PROBE_RLIMIT_CPU_SECONDS = 330
MAX_PROBE_WRITABLE_BYTES = 2 * 1024 * 1024 * 1024
MAX_PROBE_WRITABLE_ENTRIES = 65_536
MAX_PROBE_WRITABLE_DEPTH = 64
PROBE_WRITABLE_CHECK_INTERVAL_SECONDS = 1.0
PROBE_CGROUP_MEMORY_BYTES = 2 * 1024 * 1024 * 1024
PROBE_CGROUP_PIDS = 128
MAX_TOOLCHAIN_STAGE_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOOLCHAIN_STAGE_BYTES = 3 * 1024 * 1024 * 1024
MAX_TOOLCHAIN_STAGE_ENTRIES = 32_768
MAX_TOOLCHAIN_STAGE_DEPTH = 32
_CARGO_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_CARGO_PACKAGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")

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
_BPF_JMP_JSET_K = 0x45
_BPF_RET_K = 0x06
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_DATA_ARCH_OFFSET = 4
_SECCOMP_DATA_ARG0_OFFSET = 16
_AF_UNIX = 1
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7
_X32_SYSCALL_BIT = 0x40000000


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


def _socket_syscalls() -> tuple[int, int, int, int]:
    machine = os.uname().machine
    if machine == "x86_64":
        return (41, 53, 42, _AUDIT_ARCH_X86_64)
    if machine == "aarch64":
        return (198, 199, 203, _AUDIT_ARCH_AARCH64)
    fail("moriarty_network_seccomp_arch_unsupported")


def _signal_syscalls() -> tuple[int, int, int, int, int, int]:
    machine = os.uname().machine
    if machine == "x86_64":
        return (62, 200, 234, 424, 129, 297)
    if machine == "aarch64":
        return (129, 130, 131, 424, 138, 240)
    fail("moriarty_signal_seccomp_arch_unsupported")


def _process_memory_syscalls() -> tuple[int, int, int]:
    machine = os.uname().machine
    if machine == "x86_64":
        return (101, 310, 311)
    if machine == "aarch64":
        return (117, 270, 271)
    fail("moriarty_process_memory_seccomp_arch_unsupported")


def _io_uring_syscalls() -> tuple[int, int, int]:
    return (425, 426, 427)


def _prlimit_syscall() -> int:
    machine = os.uname().machine
    if machine == "x86_64":
        return 302
    if machine == "aarch64":
        return 261
    fail("moriarty_prlimit_seccomp_arch_unsupported")


def apply_network_seccomp_policy(harness_pid: int, harness_pgid: int) -> None:
    """Deny addressable IPC/network creation and probe-to-host control."""
    _ = (harness_pid, harness_pgid)
    libc = _linux_libc()
    deny = _SECCOMP_RET_ERRNO | errno.EPERM
    allow = _SECCOMP_RET_ALLOW
    socket_nr, socketpair_nr, connect_nr, audit_arch = _socket_syscalls()
    kill_nr, tkill_nr, tgkill_nr, pidfd_signal_nr, rt_sigqueueinfo_nr, rt_tgsigqueueinfo_nr = _signal_syscalls()
    instructions: list[_SockFilter] = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, audit_arch),
        _SockFilter(_BPF_RET_K, 0, 0, deny),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),
    ]
    if os.uname().machine == "x86_64":
        instructions.extend([
            _SockFilter(_BPF_JMP_JSET_K, 0, 1, _X32_SYSCALL_BIT),
            _SockFilter(_BPF_RET_K, 0, 0, deny),
        ])
    for number in (
        *_io_uring_syscalls(), pidfd_signal_nr, kill_nr, tkill_nr, tgkill_nr,
        rt_sigqueueinfo_nr, rt_tgsigqueueinfo_nr, *_process_memory_syscalls(),
    ):
        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))
        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))
    prlimit_block = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, 0),
        _SockFilter(_BPF_RET_K, 0, 0, deny),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),
    ]
    instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, len(prlimit_block), _prlimit_syscall()))
    instructions.extend(prlimit_block)
    instructions.extend([
        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, socket_nr), _SockFilter(_BPF_RET_K, 0, 0, deny),
        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, connect_nr), _SockFilter(_BPF_RET_K, 0, 0, deny),
        _SockFilter(_BPF_JMP_JEQ_K, 0, 4, socketpair_nr),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),
        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_UNIX),
        _SockFilter(_BPF_RET_K, 0, 0, allow), _SockFilter(_BPF_RET_K, 0, 0, deny),
        _SockFilter(_BPF_RET_K, 0, 0, allow),
    ])
    array_type = _SockFilter * len(instructions)
    array = array_type(*instructions)
    program = _SockFprog(len(instructions), array)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl_no_new_privs_seccomp")
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl_seccomp_network_filter")


def _apply_probe_resource_limits() -> None:
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
                    for entry in iterator:
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
            except OSError:
                return False
    return True


def _mountinfo_unescape(value: str) -> str:
    return value.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def _tmpfs_root(path: Path, *, maximum_bytes: int, require_empty: bool, label: str) -> Path:
    try:
        root = Path(path).resolve(strict=True)
        info = root.stat()
    except OSError:
        fail(f"moriarty_{label}_root_unavailable")
    if not root.is_dir() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        fail(f"moriarty_{label}_root_not_private")
    if not os.path.ismount(root):
        fail(f"moriarty_{label}_root_not_mount")
    fs_type = None
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.rstrip("\n").split()
                if "-" not in fields or len(fields) < 7:
                    continue
                separator = fields.index("-")
                mount_point = Path(_mountinfo_unescape(fields[4]))
                try:
                    resolved_mount = mount_point.resolve(strict=True)
                except OSError:
                    continue
                if resolved_mount == root:
                    fs_type = fields[separator + 1]
                    break
    except OSError:
        fail(f"moriarty_{label}_mountinfo_unavailable")
    if fs_type != "tmpfs":
        fail(f"moriarty_{label}_root_not_tmpfs")
    filesystem = os.statvfs(root)
    capacity = filesystem.f_blocks * filesystem.f_frsize
    if capacity <= 0 or capacity > maximum_bytes:
        fail(f"moriarty_{label}_capacity_invalid")
    if require_empty:
        with os.scandir(root) as iterator:
            if next(iterator, None) is not None:
                fail(f"moriarty_{label}_root_not_empty")
    return root


def probe_quota_root(path: Path) -> Path:
    return _tmpfs_root(path, maximum_bytes=MAX_PROBE_WRITABLE_BYTES, require_empty=True, label="probe_quota")


def cargo_cache_root(path: Path) -> Path:
    return _tmpfs_root(path, maximum_bytes=MAX_CARGO_CACHE_BYTES, require_empty=False, label="cargo_cache")


def _parse_cgroup_limit(path: Path, maximum: int, label: str) -> int:
    try:
        value = int(path.read_text(encoding="ascii").strip(), 10)
    except (OSError, UnicodeError, ValueError):
        fail(f"moriarty_probe_cgroup_{label}_invalid")
    if value <= 0 or value > maximum:
        fail(f"moriarty_probe_cgroup_{label}_invalid")
    return value


def probe_cgroup_root(path: Path) -> Path:
    try:
        root = Path(path).resolve(strict=True)
        cgroup_root = Path("/sys/fs/cgroup").resolve(strict=True)
    except OSError:
        fail("moriarty_probe_cgroup_unavailable")
    if root == cgroup_root or not root.is_relative_to(cgroup_root):
        fail("moriarty_probe_cgroup_path_invalid")
    if not (cgroup_root / "cgroup.controllers").is_file():
        fail("moriarty_probe_cgroup_v2_required")
    for name in ("cgroup.procs", "memory.max", "pids.max"):
        if not (root / name).is_file():
            fail(f"moriarty_probe_cgroup_file_missing:{name}")
    _parse_cgroup_limit(root / "memory.max", PROBE_CGROUP_MEMORY_BYTES, "memory_max")
    _parse_cgroup_limit(root / "pids.max", PROBE_CGROUP_PIDS, "pids_max")
    swap = root / "memory.swap.max"
    if swap.is_file() and swap.read_text(encoding="ascii").strip() != "0":
        fail("moriarty_probe_cgroup_swap_not_disabled")
    if not os.access(root / "cgroup.procs", os.W_OK):
        fail("moriarty_probe_cgroup_not_delegated")
    return root


def probe_cgroup_pids(root: Path) -> tuple[int, ...]:
    try:
        return tuple(sorted(int(v) for v in (root / "cgroup.procs").read_text(encoding="ascii").splitlines() if v))
    except (OSError, UnicodeError, ValueError):
        fail("moriarty_probe_cgroup_process_list_invalid")


def kill_probe_cgroup(root: Path) -> None:
    for _ in range(8):
        pids = probe_cgroup_pids(root)
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
        time.sleep(0.01)
    if probe_cgroup_pids(root):
        fail("moriarty_probe_cgroup_descendants_survived")


def _join_probe_cgroup(root: Path) -> None:
    try:
        with (root / "cgroup.procs").open("w", encoding="ascii") as handle:
            handle.write("0\n")
    except OSError as exc:
        raise OSError(exc.errno, "moriarty_probe_cgroup_join_failed") from exc


def _proc_status_unprivileged(status_text: str) -> bool:
    fields = {}
    for raw_line in status_text.splitlines():
        if ":" in raw_line:
            key, value = raw_line.split(":", 1)
            fields[key] = value.strip()
    try:
        uids = tuple(int(v) for v in fields["Uid"].split())
        gids = tuple(int(v) for v in fields["Gid"].split())
        capabilities = tuple(int(fields[k], 16) for k in ("CapInh", "CapPrm", "CapEff", "CapAmb"))
    except (KeyError, ValueError):
        return False
    return len(uids) == 4 and len(gids) == 4 and len(set(uids)) == 1 and len(set(gids)) == 1 and uids[0] != 0 and gids[0] != 0 and all(v == 0 for v in capabilities)


def require_unprivileged_probe_launcher() -> None:
    try:
        status_text = Path("/proc/self/status").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        fail("moriarty_launcher_privilege_status_unavailable")
    if not _proc_status_unprivileged(status_text):
        fail("moriarty_privileged_probe_launcher_rejected")


def probe_isolation_preexec(read_exec_paths, read_paths, writable_paths, cgroup_root=None):
    require_unprivileged_probe_launcher()
    read_exec = tuple(Path(p).resolve(strict=True) for p in read_exec_paths if Path(p).exists())
    readable = tuple(Path(p).resolve(strict=True) for p in read_paths if Path(p).exists())
    writable = tuple(Path(p).resolve(strict=True) for p in writable_paths if Path(p).exists())
    cgroup = probe_cgroup_root(cgroup_root) if cgroup_root is not None else None
    harness_pid = os.getpid(); harness_pgid = os.getpgrp()
    def _apply():
        if cgroup is not None:
            _join_probe_cgroup(cgroup)
        _apply_probe_resource_limits()
        apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)
        apply_network_seccomp_policy(harness_pid, harness_pgid)
    return _apply


def landlock_write_preexec(writable_paths):
    roots = tuple(Path(path).resolve(strict=True) for path in writable_paths)
    def _apply(): apply_landlock_write_policy(roots)
    return _apply


def proc_fd_path(fd: int) -> str:
    path = Path(f"/proc/self/fd/{fd}")
    if not path.exists(): fail("moriarty_proc_fd_unavailable")
    return str(path)


def _relative_archive_name(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail("moriarty_archive_member_path_invalid")
    return path


def extract_exact_archive_bytes(archive_bytes: bytes, destination: Path) -> None:
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            _relative_archive_name(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo() or not (member.isdir() or member.isfile()):
                fail("moriarty_archive_member_type_forbidden")
        for member in members:
            relative = _relative_archive_name(member.name); output = destination / relative
            if member.isdir(): output.mkdir(mode=0o700, parents=True, exist_ok=True); continue
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None: fail("moriarty_archive_file_unreadable")
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os,"O_NOFOLLOW",0), 0o600)
            try:
                while True:
                    chunk = source.read(65536)
                    if not chunk: break
                    view = memoryview(chunk)
                    while view: view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd); source.close()
            os.chmod(output, 0o500 if member.mode & 0o111 else 0o400)


def seal_read_only_tree(root: Path) -> None:
    for current, dirs, files in os.walk(root, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            path = current_path / name
            if path.is_symlink(): fail("moriarty_export_symlink_forbidden")
            os.chmod(path, 0o500 if path.stat().st_mode & 0o111 else 0o400)
        for name in dirs:
            path = current_path / name
            if path.is_symlink(): fail("moriarty_export_symlink_forbidden")
            os.chmod(path, 0o500)
    os.chmod(root, 0o500)


def create_exact_export(target_commit, workspace, read_git_archive, label):
    source_root = workspace / f"{label}-src"
    extract_exact_archive_bytes(read_git_archive(target_commit), source_root)
    seal_read_only_tree(source_root)
    return source_root


def _sha256_regular_file(path: Path, *, max_bytes=None, too_large_error="moriarty_regular_file_too_large") -> str:
    try: initial = path.lstat()
    except OSError: fail("moriarty_regular_file_unavailable")
    if path.is_symlink() or not stat.S_ISREG(initial.st_mode): fail("moriarty_regular_file_required")
    if max_bytes is not None and initial.st_size > max_bytes: fail(too_large_error)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os,"O_NOFOLLOW",0)); digest=hashlib.sha256(); total=0
    try:
        opened=os.fstat(fd)
        while True:
            chunk=os.read(fd,65536)
            if not chunk: break
            total+=len(chunk)
            if max_bytes is not None and total>max_bytes: fail(too_large_error)
            digest.update(chunk)
        final=os.fstat(fd)
    finally: os.close(fd)
    if final.st_dev!=opened.st_dev or final.st_ino!=opened.st_ino or final.st_size!=opened.st_size or final.st_mtime_ns!=opened.st_mtime_ns or total!=opened.st_size:
        fail("moriarty_regular_file_changed_during_hash")
    return digest.hexdigest()


def _copy_regular_file(source: Path, destination: Path, expected_sha256=None, *, max_bytes=None, too_large_error="moriarty_copy_source_too_large"):
    if source.is_symlink() or not source.is_file(): fail("moriarty_copy_source_nonregular")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    sf=os.open(source,os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0)); of=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600)
    digest=hashlib.sha256(); total=0
    try:
        while True:
            chunk=os.read(sf,65536)
            if not chunk: break
            total+=len(chunk)
            if max_bytes is not None and total>max_bytes: fail(too_large_error)
            digest.update(chunk); view=memoryview(chunk)
            while view: view=view[os.write(of,view):]
        os.fsync(of)
    finally: os.close(of); os.close(sf)
    actual=digest.hexdigest()
    if expected_sha256 is not None and actual!=expected_sha256: fail(f"moriarty_cargo_archive_checksum_mismatch:{source.name}")
    if _sha256_regular_file(destination)!=actual: fail("moriarty_copy_digest_mismatch")


def _copy_regular_tree(source: Path, destination: Path, *, max_entries=None, max_bytes=None, max_depth=None, bound_prefix="moriarty_copy_tree"):
    if not source.exists(): return
    destination.mkdir(mode=0o700, parents=True, exist_ok=True); entry_count=0; total_bytes=0
    for current, dirs, files in os.walk(source, followlinks=False):
        current_path=Path(current); relative=current_path.relative_to(source); depth=len(relative.parts)
        if max_depth is not None and depth>max_depth: fail(f"{bound_prefix}_depth_exceeded")
        output_dir=destination/relative; output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        entry_count+=len(dirs)+len(files)
        if max_entries is not None and entry_count>max_entries: fail(f"{bound_prefix}_entries_exceeded")
        for directory in list(dirs):
            if (current_path/directory).is_symlink(): fail("moriarty_cargo_cache_symlink_forbidden")
        for name in files:
            source_file=current_path/name
            remaining=None if max_bytes is None else max_bytes-total_bytes
            _copy_regular_file(source_file, output_dir/name, max_bytes=remaining, too_large_error=f"{bound_prefix}_bytes_exceeded")
            total_bytes+=(output_dir/name).stat().st_size
            if max_bytes is not None and total_bytes>max_bytes: fail(f"{bound_prefix}_bytes_exceeded")


def _locked_registry_packages(cargo_lock: Path):
    try: value=tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
    except (OSError,UnicodeError,tomllib.TOMLDecodeError): fail("moriarty_cargo_lock_parse_failed")
    packages=[]
    for package in value.get("package",[]):
        if not isinstance(package,dict): fail("moriarty_cargo_lock_package_invalid")
        source=package.get("source")
        if not isinstance(source,str) or not source.startswith("registry+"): continue
        name=package.get("name"); version=package.get("version"); checksum=package.get("checksum")
        if not isinstance(name,str) or not isinstance(version,str) or not isinstance(checksum,str) or _CARGO_PACKAGE_NAME_RE.fullmatch(name) is None or _CARGO_PACKAGE_VERSION_RE.fullmatch(version) is None or len(checksum)!=64 or any(ch not in "0123456789abcdef" for ch in checksum):
            fail("moriarty_cargo_lock_registry_package_invalid")
        packages.append((name,version,checksum))
    if not packages: fail("moriarty_cargo_lock_registry_packages_missing")
    return packages


def create_verified_cargo_template(real_cargo_home: Path, workspace: Path, cargo_lock: Path, label="cargo-template"):
    if not label or "/" in label or "\\" in label or label in {".",".."}: fail("moriarty_cargo_template_label_invalid")
    template=workspace/label; template.mkdir(mode=0o700,parents=False,exist_ok=False)
    _copy_regular_tree(real_cargo_home/"registry"/"index",template/"registry"/"index",max_entries=MAX_CARGO_INDEX_ENTRIES,max_bytes=MAX_CARGO_INDEX_BYTES,max_depth=MAX_CARGO_INDEX_DEPTH,bound_prefix="moriarty_cargo_index")
    cache_root=real_cargo_home/"registry"/"cache"; cache_root_resolved=cache_root.resolve(strict=True) if cache_root.exists() else None; template_resolved=template.resolve(strict=True)
    for name,version,checksum in _locked_registry_packages(cargo_lock):
        filename=f"{name}-{version}.crate"; candidates=sorted(cache_root.glob(f"*/{filename}")) if cache_root.exists() else []; matching=[]
        for candidate in candidates:
            if candidate.is_file() and not candidate.is_symlink():
                resolved=candidate.resolve(strict=True)
                if cache_root_resolved is None or not resolved.is_relative_to(cache_root_resolved): fail("moriarty_cargo_archive_escaped_cache_root")
                if _sha256_regular_file(candidate,max_bytes=MAX_CARGO_ARCHIVE_BYTES,too_large_error=f"moriarty_cargo_archive_too_large:{filename}")==checksum: matching.append(candidate)
        if not matching:
            if candidates: fail(f"moriarty_cargo_archive_checksum_mismatch:{filename}")
            continue
        selected=matching[0]; destination=template/"registry"/"cache"/selected.parent.name/filename
        _copy_regular_file(selected,destination,checksum)
        if not destination.resolve(strict=True).is_relative_to(template_resolved): fail("moriarty_cargo_archive_destination_escape")
    if (template/"registry"/"src").exists(): fail("moriarty_cargo_template_must_not_copy_registry_src")
    seal_read_only_tree(template); return template


def _owned_cargo_config(workspace: Path, rust_runtime=None):
    lines=[]; runtime=rust_runtime if rust_runtime is not None else workspace/"rust-runtime"
    if runtime.is_dir(): lines.extend(["[build]\n",f"rustflags = [\"--sysroot\", {json.dumps(str(runtime.resolve(strict=True)))}]\n"])
    lines.extend(["[net]\n","offline = true\n"]); return "".join(lines).encode()


def create_isolated_cargo_home(template,workspace,label,rust_runtime=None):
    cargo_home=workspace/f"cargo-home-{label}"; cargo_home.mkdir(mode=0o700,parents=False,exist_ok=False); _copy_regular_tree(template,cargo_home)
    legacy=cargo_home/"config"; config=_owned_cargo_config(workspace,rust_runtime); fd=os.open(legacy,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600)
    try: os.write(fd,config); os.fsync(fd)
    finally: os.close(fd)
    return cargo_home


def create_empty_cargo_home(workspace,label):
    p=workspace/f"cargo-home-{label}"; p.mkdir(mode=0o700,parents=False,exist_ok=False); return p


def _copy_fd_to_path(source_fd,destination,mode):
    destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True); out=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o700); digest=hashlib.sha256(); src=os.open(proc_fd_path(source_fd),os.O_RDONLY|os.O_CLOEXEC)
    try:
        while True:
            chunk=os.read(src,65536)
            if not chunk: break
            digest.update(chunk); os.write(out,chunk)
        os.fsync(out)
    finally: os.close(src); os.close(out)
    os.chmod(destination,mode); return digest.hexdigest()


def stage_executable_from_fd(source_fd,destination):
    destination.parent.mkdir(mode=0o700,parents=False,exist_ok=False); _copy_fd_to_path(source_fd,destination,0o500); os.chmod(destination.parent,0o500); return destination


def _stable_stage_source(source,destination,toolchain_root,max_bytes):
    if max_bytes<0: fail("moriarty_toolchain_stage_bytes_exceeded")
    resolved=source.resolve(strict=True); root=toolchain_root.resolve(strict=True)
    if resolved!=root and root not in resolved.parents: fail("moriarty_toolchain_symlink_escape")
    size=resolved.stat().st_size
    if size>min(MAX_TOOLCHAIN_STAGE_FILE_BYTES,max_bytes): fail("moriarty_toolchain_stage_file_too_large")
    _copy_regular_file(resolved,destination,max_bytes=size); os.chmod(destination,0o500 if resolved.stat().st_mode&0o111 else 0o400); return size


def stage_rust_toolchain_runtime(toolchain_root,destination,pinned_cargo_fd,pinned_rustc_fd):
    root=toolchain_root.resolve(strict=True); destination.mkdir(mode=0o700,parents=False,exist_ok=False); total=0; entries=0
    for subdir in ("bin","lib"):
        source_root=root/subdir
        for current,dirs,files in os.walk(source_root,followlinks=False):
            current_path=Path(current); rel=current_path.relative_to(root); entries+=len(dirs)+len(files)
            if len(rel.parts)>MAX_TOOLCHAIN_STAGE_DEPTH or entries>MAX_TOOLCHAIN_STAGE_ENTRIES: fail("moriarty_toolchain_stage_bound_exceeded")
            out=destination/rel; out.mkdir(mode=0o700,parents=True,exist_ok=True)
            for name in sorted(files):
                if subdir=="bin" and name in {"cargo","rustc"} and current_path==source_root: continue
                copied=_stable_stage_source(current_path/name,out/name,root,MAX_TOOLCHAIN_STAGE_BYTES-total); total+=copied
    for fd,name in ((pinned_cargo_fd,"cargo"),(pinned_rustc_fd,"rustc")): _copy_fd_to_path(fd,destination/"bin"/name,0o500)
    seal_read_only_tree(destination); return destination


def private_directory(path):
    try: info=path.stat()
    except OSError: return False
    return path.is_dir() and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)&0o077==0


def write_report_exclusive(output,encoded,repository_root):
    if not output.is_absolute(): fail("moriarty_report_output_must_be_absolute")
    parent=output.parent.resolve(strict=True); repository=repository_root.resolve(strict=True)
    if parent==repository or repository in parent.parents or not private_directory(parent): fail("moriarty_report_output_invalid")
    dfd=os.open(parent,os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_DIRECTORY",0))
    try:
        fd=os.open(output.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=dfd)
        try: os.write(fd,encoded); os.fsync(fd)
        finally: os.close(fd)
    finally: os.close(dfd)


MAX_CARGO_ARCHIVE_SCAN_ENTRIES = 16_384
MAX_CARGO_ARCHIVE_SCAN_BYTES = 512 * 1024 * 1024
MAX_CARGO_MANIFEST_BYTES = 1024 * 1024
TRUSTED_REGISTRY_BUILD_HOOK_ARCHIVES: frozenset[tuple[str, str, str]] = frozenset()


def _pidfd_descriptor_syscalls(): return (434,438)

def _keyring_syscalls():
    if os.uname().machine=="x86_64": return (248,249,250)
    if os.uname().machine=="aarch64": return (217,218,219)
    fail("moriarty_keyring_seccomp_arch_unsupported")


def _apply_sensitive_host_handle_seccomp_policy():
    libc=_linux_libc(); deny=_SECCOMP_RET_ERRNO|errno.EPERM; allow=_SECCOMP_RET_ALLOW; audit_arch=_socket_syscalls()[3]
    instructions=[_SockFilter(_BPF_LD_W_ABS,0,0,_SECCOMP_DATA_ARCH_OFFSET),_SockFilter(_BPF_JMP_JEQ_K,1,0,audit_arch),_SockFilter(_BPF_RET_K,0,0,deny),_SockFilter(_BPF_LD_W_ABS,0,0,0)]
    if os.uname().machine=="x86_64": instructions.extend([_SockFilter(_BPF_JMP_JSET_K,0,1,_X32_SYSCALL_BIT),_SockFilter(_BPF_RET_K,0,0,deny)])
    for number in (*_pidfd_descriptor_syscalls(),*_keyring_syscalls()): instructions.extend([_SockFilter(_BPF_JMP_JEQ_K,0,1,number),_SockFilter(_BPF_RET_K,0,0,deny)])
    instructions.append(_SockFilter(_BPF_RET_K,0,0,allow)); array_type=_SockFilter*len(instructions); array=array_type(*instructions); program=_SockFprog(len(instructions),array)
    if libc.prctl(_PR_SET_SECCOMP,_SECCOMP_MODE_FILTER,ctypes.byref(program),0,0)!=0: raise OSError(ctypes.get_errno(),"prctl_seccomp_sensitive_handle_filter")


_base_apply_network_seccomp_policy=apply_network_seccomp_policy

def apply_network_seccomp_policy(harness_pid,harness_pgid):
    _base_apply_network_seccomp_policy(harness_pid,harness_pgid); _apply_sensitive_host_handle_seccomp_policy()


def _crate_archive_declares_build_hook(archive_path,name,version):
    root_name=f"{name}-{version}"; prefix=root_name+"/"; manifest_bytes=None; root_build_rs=False; entries=0; expanded=0
    try:
        with tarfile.open(archive_path,mode="r|*") as archive:
            for member in archive:
                entries+=1; expanded+=max(0,member.size)
                if entries>MAX_CARGO_ARCHIVE_SCAN_ENTRIES or expanded>MAX_CARGO_ARCHIVE_SCAN_BYTES: fail(f"moriarty_cargo_archive_scan_bound_exceeded:{archive_path.name}")
                raw=member.name
                if raw.rstrip("/")==root_name: continue
                if not raw.startswith(prefix): fail(f"moriarty_cargo_archive_member_root_invalid:{archive_path.name}")
                relative=Path(raw[len(prefix):])
                if relative.is_absolute() or not relative.parts or any(p in {"",".",".."} for p in relative.parts): fail(f"moriarty_cargo_archive_member_path_invalid:{archive_path.name}")
                rel=relative.as_posix()
                if rel=="build.rs" and member.isfile(): root_build_rs=True
                if rel=="Cargo.toml" and member.isfile():
                    src=archive.extractfile(member)
                    if src is None: fail(f"moriarty_cargo_archive_manifest_unreadable:{archive_path.name}")
                    manifest_bytes=src.read(MAX_CARGO_MANIFEST_BYTES+1); src.close()
                    if len(manifest_bytes)>MAX_CARGO_MANIFEST_BYTES: fail(f"moriarty_cargo_archive_manifest_too_large:{archive_path.name}")
    except tarfile.TarError:
        return False
    except OSError:
        fail(f"moriarty_cargo_archive_scan_failed:{archive_path.name}")
    if manifest_bytes is None: fail(f"moriarty_cargo_archive_manifest_missing:{archive_path.name}")
    try: manifest=tomllib.loads(manifest_bytes.decode())
    except (UnicodeError,tomllib.TOMLDecodeError): fail(f"moriarty_cargo_archive_manifest_invalid:{archive_path.name}")
    package=manifest.get("package")
    if not isinstance(package,dict): fail(f"moriarty_cargo_archive_package_invalid:{archive_path.name}")
    declared=package.get("build"); links=package.get("links")
    return (declared is None and root_build_rs) or isinstance(declared,str) or links is not None


def _unapproved_registry_build_hooks(real_cargo_home,cargo_lock):
    cache_root=real_cargo_home/"registry"/"cache"; root=cache_root.resolve(strict=True) if cache_root.exists() else None; found=set()
    for name,version,checksum in _locked_registry_packages(cargo_lock):
        filename=f"{name}-{version}.crate"; selected=None
        for candidate in sorted(cache_root.glob(f"*/{filename}")) if cache_root.exists() else []:
            if candidate.is_file() and not candidate.is_symlink() and _sha256_regular_file(candidate,max_bytes=MAX_CARGO_ARCHIVE_BYTES,too_large_error=f"moriarty_cargo_archive_too_large:{filename}")==checksum:
                if root is None or not candidate.resolve(strict=True).is_relative_to(root): fail("moriarty_cargo_archive_escaped_cache_root")
                selected=candidate; break
        identity=(name,version,checksum)
        if selected is not None and _crate_archive_declares_build_hook(selected,name,version) and identity not in TRUSTED_REGISTRY_BUILD_HOOK_ARCHIVES: found.add(identity)
    return tuple(sorted(found))


_base_create_verified_cargo_template=create_verified_cargo_template

def create_verified_cargo_template(real_cargo_home,workspace,cargo_lock,label="cargo-template"):
    unapproved=_unapproved_registry_build_hooks(real_cargo_home,cargo_lock)
    if unapproved: fail("moriarty_registry_build_hook_unapproved:"+",".join(f"{n}@{v}:{c}" for n,v,c in unapproved))
    return _base_create_verified_cargo_template(real_cargo_home,workspace,cargo_lock,label)
