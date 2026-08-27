#!/usr/bin/env python3
from __future__ import annotations

import json
import py_compile
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one marker, found {count}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"{path}: start marker missing: {start!r}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"{path}: end marker missing: {end!r}")
    target.write_text(text[:start_index] + replacement + text[end_index:], encoding="utf-8")


# ---------------------------------------------------------------------------
# tools/moriarty_isolation.py
# ---------------------------------------------------------------------------
replace_once(
    "tools/moriarty_isolation.py",
    "import tarfile\nimport tomllib\n",
    "import tarfile\nimport time\nimport tomllib\n",
)
replace_once(
    "tools/moriarty_isolation.py",
    "MAX_CARGO_INDEX_DEPTH = 16\nPROBE_RLIMIT_AS_BYTES = 2 * 1024 * 1024 * 1024\n",
    "MAX_CARGO_INDEX_DEPTH = 16\nMAX_CARGO_CACHE_BYTES = 1024 * 1024 * 1024\nPROBE_RLIMIT_AS_BYTES = 2 * 1024 * 1024 * 1024\n",
)
replace_once(
    "tools/moriarty_isolation.py",
    "MAX_PROBE_WRITABLE_DEPTH = 64\nPROBE_WRITABLE_CHECK_INTERVAL_SECONDS = 1.0\n",
    "MAX_PROBE_WRITABLE_DEPTH = 64\nPROBE_WRITABLE_CHECK_INTERVAL_SECONDS = 1.0\nPROBE_CGROUP_MEMORY_BYTES = 2 * 1024 * 1024 * 1024\nPROBE_CGROUP_PIDS = 128\n",
)
replace_once(
    "tools/moriarty_isolation.py",
    "_BPF_JMP_JEQ_K = 0x15\n_BPF_RET_K = 0x06\n",
    "_BPF_JMP_JEQ_K = 0x15\n_BPF_JMP_JSET_K = 0x45\n_BPF_RET_K = 0x06\n",
)
replace_once(
    "tools/moriarty_isolation.py",
    "_AUDIT_ARCH_AARCH64 = 0xC00000B7\n",
    "_AUDIT_ARCH_AARCH64 = 0xC00000B7\n_X32_SYSCALL_BIT = 0x40000000\n",
)

replace_between(
    "tools/moriarty_isolation.py",
    "def apply_network_seccomp_policy(harness_pid: int, harness_pgid: int) -> None:\n",
    "\n\ndef _apply_probe_resource_limits() -> None:\n",
    '''def apply_network_seccomp_policy(harness_pid: int, harness_pgid: int) -> None:\n    \"\"\"Deny addressable IPC/network creation and probe-to-host control.\n\n    Addressable socket() and connect() are denied outright. Only anonymous\n    socketpair(AF_UNIX) IPC is admitted. Signal-delivery syscalls are denied\n    wholesale because seccomp cannot prove that an arbitrary same-UID PID/TID\n    belongs to the probe subtree. io_uring, pidfd signaling, ptrace/process_vm\n    access, and foreign-PID prlimit64 are also denied. On x86_64, x32 syscall\n    numbers are rejected before native-number dispatch.\n    \"\"\"\n    _ = (harness_pid, harness_pgid)\n    libc = _linux_libc()\n    deny = _SECCOMP_RET_ERRNO | errno.EPERM\n    allow = _SECCOMP_RET_ALLOW\n    socket_nr, socketpair_nr, connect_nr, audit_arch = _socket_syscalls()\n    kill_nr, tkill_nr, tgkill_nr, pidfd_signal_nr, rt_sigqueueinfo_nr, rt_tgsigqueueinfo_nr = _signal_syscalls()\n    instructions: list[_SockFilter] = [\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),\n        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, audit_arch),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),\n    ]\n    if os.uname().machine == \"x86_64\":\n        instructions.extend([\n            _SockFilter(_BPF_JMP_JSET_K, 0, 1, _X32_SYSCALL_BIT),\n            _SockFilter(_BPF_RET_K, 0, 0, deny),\n        ])\n    for number in (\n        *_io_uring_syscalls(),\n        pidfd_signal_nr,\n        kill_nr,\n        tkill_nr,\n        tgkill_nr,\n        rt_sigqueueinfo_nr,\n        rt_tgsigqueueinfo_nr,\n        *_process_memory_syscalls(),\n    ):\n        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))\n        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))\n    # prlimit64 is self-only: pid 0 may tighten the probe's own inherited hard\n    # ceiling, while any named PID is denied.\n    prlimit_block = [\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),\n        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, 0),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),\n    ]\n    instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, len(prlimit_block), _prlimit_syscall()))\n    instructions.extend(prlimit_block)\n    instructions.extend([\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, socket_nr),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, connect_nr),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 4, socketpair_nr),\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_UNIX),\n        _SockFilter(_BPF_RET_K, 0, 0, allow),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_RET_K, 0, 0, allow),\n    ])\n    array_type = _SockFilter * len(instructions)\n    array = array_type(*instructions)\n    program = _SockFprog(len(instructions), array)\n    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:\n        raise OSError(ctypes.get_errno(), \"prctl_no_new_privs_seccomp\")\n    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:\n        raise OSError(ctypes.get_errno(), \"prctl_seccomp_network_filter\")\n''',
)

replace_between(
    "tools/moriarty_isolation.py",
    "def probe_quota_root(path: Path) -> Path:\n",
    "\n\ndef probe_isolation_preexec(\n",
    '''def _tmpfs_root(path: Path, *, maximum_bytes: int, require_empty: bool, label: str) -> Path:\n    try:\n        root = Path(path).resolve(strict=True)\n        info = root.stat()\n    except OSError:\n        fail(f\"moriarty_{label}_root_unavailable\")\n    if not root.is_dir() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:\n        fail(f\"moriarty_{label}_root_not_private\")\n    if not os.path.ismount(root):\n        fail(f\"moriarty_{label}_root_not_mount\")\n\n    fs_type: str | None = None\n    try:\n        with open(\"/proc/self/mountinfo\", \"r\", encoding=\"utf-8\") as handle:\n            for line in handle:\n                fields = line.rstrip(\"\\n\").split()\n                if \"-\" not in fields or len(fields) < 7:\n                    continue\n                separator = fields.index(\"-\")\n                if separator + 1 >= len(fields):\n                    continue\n                mount_point = Path(_mountinfo_unescape(fields[4]))\n                try:\n                    resolved_mount = mount_point.resolve(strict=True)\n                except OSError:\n                    continue\n                if resolved_mount == root:\n                    fs_type = fields[separator + 1]\n                    break\n    except OSError:\n        fail(f\"moriarty_{label}_mountinfo_unavailable\")\n    if fs_type != \"tmpfs\":\n        fail(f\"moriarty_{label}_root_not_tmpfs\")\n\n    try:\n        filesystem = os.statvfs(root)\n    except OSError:\n        fail(f\"moriarty_{label}_statvfs_failed\")\n    capacity = filesystem.f_blocks * filesystem.f_frsize\n    if capacity <= 0 or capacity > maximum_bytes:\n        fail(f\"moriarty_{label}_capacity_invalid\")\n    if require_empty:\n        try:\n            with os.scandir(root) as iterator:\n                if next(iterator, None) is not None:\n                    fail(f\"moriarty_{label}_root_not_empty\")\n        except OSError:\n            fail(f\"moriarty_{label}_root_scan_failed\")\n    return root\n\n\ndef probe_quota_root(path: Path) -> Path:\n    \"\"\"Require an empty private tmpfs whose allocation ceiling is <= 2 GiB.\"\"\"\n    return _tmpfs_root(\n        path,\n        maximum_bytes=MAX_PROBE_WRITABLE_BYTES,\n        require_empty=True,\n        label=\"probe_quota\",\n    )\n\n\ndef cargo_cache_root(path: Path) -> Path:\n    \"\"\"Require a private quota-backed tmpfs for authenticated Cargo fetch input.\"\"\"\n    return _tmpfs_root(\n        path,\n        maximum_bytes=MAX_CARGO_CACHE_BYTES,\n        require_empty=False,\n        label=\"cargo_cache\",\n    )\n\n\ndef _parse_cgroup_limit(path: Path, maximum: int, label: str) -> int:\n    try:\n        raw = path.read_text(encoding=\"ascii\").strip()\n        value = int(raw, 10)\n    except (OSError, UnicodeError, ValueError):\n        fail(f\"moriarty_probe_cgroup_{label}_invalid\")\n    if value <= 0 or value > maximum:\n        fail(f\"moriarty_probe_cgroup_{label}_invalid\")\n    return value\n\n\ndef probe_cgroup_root(path: Path) -> Path:\n    \"\"\"Require an explicitly bounded cgroup-v2 memory/PID envelope.\"\"\"\n    try:\n        root = Path(path).resolve(strict=True)\n        cgroup_root = Path(\"/sys/fs/cgroup\").resolve(strict=True)\n    except OSError:\n        fail(\"moriarty_probe_cgroup_unavailable\")\n    if root == cgroup_root or not root.is_relative_to(cgroup_root):\n        fail(\"moriarty_probe_cgroup_path_invalid\")\n    if not (cgroup_root / \"cgroup.controllers\").is_file():\n        fail(\"moriarty_probe_cgroup_v2_required\")\n    for name in (\"cgroup.procs\", \"memory.max\", \"pids.max\"):\n        if not (root / name).is_file():\n            fail(f\"moriarty_probe_cgroup_file_missing:{name}\")\n    _parse_cgroup_limit(root / \"memory.max\", PROBE_CGROUP_MEMORY_BYTES, \"memory_max\")\n    _parse_cgroup_limit(root / \"pids.max\", PROBE_CGROUP_PIDS, \"pids_max\")\n    swap = root / \"memory.swap.max\"\n    if swap.is_file():\n        try:\n            if swap.read_text(encoding=\"ascii\").strip() != \"0\":\n                fail(\"moriarty_probe_cgroup_swap_not_disabled\")\n        except (OSError, UnicodeError):\n            fail(\"moriarty_probe_cgroup_swap_invalid\")\n    if not os.access(root / \"cgroup.procs\", os.W_OK):\n        fail(\"moriarty_probe_cgroup_not_delegated\")\n    return root\n\n\ndef probe_cgroup_pids(root: Path) -> tuple[int, ...]:\n    try:\n        values = (root / \"cgroup.procs\").read_text(encoding=\"ascii\").splitlines()\n        return tuple(sorted(int(value) for value in values if value))\n    except (OSError, UnicodeError, ValueError):\n        fail(\"moriarty_probe_cgroup_process_list_invalid\")\n\n\ndef kill_probe_cgroup(root: Path) -> None:\n    \"\"\"Kill every remaining task in the delegated probe cgroup.\"\"\"\n    for _ in range(8):\n        pids = probe_cgroup_pids(root)\n        if not pids:\n            return\n        for pid in pids:\n            try:\n                os.kill(pid, 9)\n            except ProcessLookupError:\n                pass\n        time.sleep(0.01)\n    if probe_cgroup_pids(root):\n        fail(\"moriarty_probe_cgroup_descendants_survived\")\n\n\ndef _join_probe_cgroup(root: Path) -> None:\n    try:\n        with (root / \"cgroup.procs\").open(\"w\", encoding=\"ascii\") as handle:\n            handle.write(\"0\\n\")\n    except OSError as exc:\n        raise OSError(exc.errno, \"moriarty_probe_cgroup_join_failed\") from exc\n''',
)

replace_between(
    "tools/moriarty_isolation.py",
    "def probe_isolation_preexec(\n",
    "\n\ndef landlock_write_preexec(writable_paths: tuple[Path, ...]):\n",
    '''def probe_isolation_preexec(\n    read_exec_paths: tuple[Path, ...],\n    read_paths: tuple[Path, ...],\n    writable_paths: tuple[Path, ...],\n    cgroup_root: Path | None = None,\n):\n    read_exec = tuple(Path(path).resolve(strict=True) for path in read_exec_paths if Path(path).exists())\n    readable = tuple(Path(path).resolve(strict=True) for path in read_paths if Path(path).exists())\n    writable = tuple(Path(path).resolve(strict=True) for path in writable_paths if Path(path).exists())\n    cgroup = probe_cgroup_root(cgroup_root) if cgroup_root is not None else None\n    harness_pid = os.getpid()\n    harness_pgid = os.getpgrp()\n\n    def _apply() -> None:\n        if cgroup is not None:\n            _join_probe_cgroup(cgroup)\n        _apply_probe_resource_limits()\n        apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)\n        apply_network_seccomp_policy(harness_pid, harness_pgid)\n\n    return _apply\n''',
)

# ---------------------------------------------------------------------------
# tools/run_moriarty.py
# ---------------------------------------------------------------------------
replace_once(
    "tools/run_moriarty.py",
    "import re\nimport selectors\n",
    "import re\nimport selectors\nimport shutil\n",
)
replace_once(
    "tools/run_moriarty.py",
    "import tempfile\nimport time\n",
    "import tempfile\nimport time\nimport tomllib\n",
)
replace_once(
    "tools/run_moriarty.py",
    "create_verified_cargo_template = _moriarty_isolation.create_verified_cargo_template\n",
    "create_verified_cargo_template = _moriarty_isolation.create_verified_cargo_template\ncargo_cache_root = _moriarty_isolation.cargo_cache_root\n",
)
replace_once(
    "tools/run_moriarty.py",
    "probe_quota_root = _moriarty_isolation.probe_quota_root\n",
    "probe_quota_root = _moriarty_isolation.probe_quota_root\nprobe_cgroup_root = _moriarty_isolation.probe_cgroup_root\nprobe_cgroup_pids = _moriarty_isolation.probe_cgroup_pids\nkill_probe_cgroup = _moriarty_isolation.kill_probe_cgroup\n",
)
replace_once(
    "tools/run_moriarty.py",
    "_ACTIVE_PROBE_WRITABLE_ROOT: Path | None = None\n\n\ndef _probe_writable_root() -> Path:\n",
    "_ACTIVE_PROBE_WRITABLE_ROOT: Path | None = None\n_ACTIVE_PROBE_CGROUP: Path | None = None\n\n\ndef _probe_writable_root() -> Path:\n",
)
replace_once(
    "tools/run_moriarty.py",
    "    return _ACTIVE_PROBE_WRITABLE_ROOT\n\n\ndef fail(message: str) -> NoReturn:\n",
    "    return _ACTIVE_PROBE_WRITABLE_ROOT\n\n\ndef _probe_cgroup() -> Path:\n    if _ACTIVE_PROBE_CGROUP is None:\n        fail(\"moriarty_probe_cgroup_not_initialized\")\n    return _ACTIVE_PROBE_CGROUP\n\n\ndef fail(message: str) -> NoReturn:\n",
)

replace_between(
    "tools/run_moriarty.py",
    "# Source-owned and closed. An external/model candidate finding must be reduced to\n",
    "PROBE_EXECUTABLES: dict[str, TrustedExecutable] = {\n",
    '''# Source-owned and closed. An external/model candidate finding must be reduced to\n# one of these deterministic local probes before it is eligible for the accepted registry.\n# Python probes run with -I and execute the validator through a tiny bootstrap. The\n# bootstrap never adds the exact-export tools directory to sys.path; instead a custom\n# finder serves exact-export tool modules only when their names do not collide with a\n# standard-library module. This prevents tracked tools/json.py-style shadowing.\nPYTHON_PROBE_BOOTSTRAP = r\"\"\"\nimport importlib.abc\nimport importlib.util\nimport pathlib\nimport sys\n\nvalidator = pathlib.Path(sys.argv[1]).resolve(strict=True)\nroot = validator.parents[1]\ntools = root / \"tools\"\n\nclass ExactToolsLoader(importlib.abc.Loader):\n    def __init__(self, path):\n        self.path = path\n    def create_module(self, spec):\n        return None\n    def exec_module(self, module):\n        module.__file__ = str(self.path)\n        module.__cached__ = None\n        code = compile(self.path.read_bytes(), str(self.path), \"exec\", dont_inherit=True, optimize=0)\n        exec(code, module.__dict__)\n\nclass ExactToolsFinder(importlib.abc.MetaPathFinder):\n    def find_spec(self, fullname, path=None, target=None):\n        if \".\" in fullname or fullname in sys.stdlib_module_names:\n            return None\n        candidate = tools / (fullname + \".py\")\n        if not candidate.is_file():\n            return None\n        return importlib.util.spec_from_loader(fullname, ExactToolsLoader(candidate))\n\nsys.meta_path.insert(0, ExactToolsFinder())\nsys.path[:] = [entry for entry in sys.path if entry not in {\"\", str(root), str(tools)}]\nsys.argv = [str(validator)]\nnamespace = {\"__name__\": \"__main__\", \"__file__\": str(validator), \"__package__\": None, \"__cached__\": None}\nexec(compile(validator.read_bytes(), str(validator), \"exec\", dont_inherit=True, optimize=0), namespace)\n\"\"\"\n\nPYTHON_VALIDATORS = {\n    \"constitution\": \"tools/validate_constitution.py\",\n    \"phase0\": \"tools/validate_phase0_gate.py\",\n    \"phase1\": \"tools/validate_phase1_gate.py\",\n    \"phase2\": \"tools/validate_phase2_gate.py\",\n    \"phase3\": \"tools/validate_phase3_gate.py\",\n    \"phase4\": \"tools/validate_phase4_gate.py\",\n    \"phase5a\": \"tools/validate_phase5a_gate.py\",\n    \"phase5\": \"tools/validate_phase5_gate.py\",\n    \"phase5c\": \"tools/validate_phase5c_gate.py\",\n    \"phase6\": \"tools/validate_phase6_gate.py\",\n    \"phase7\": \"tools/validate_phase7_gate.py\",\n    \"phase8\": \"tools/validate_phase8_gate.py\",\n}\nPROBES: dict[str, tuple[str, ...]] = {\n    probe_id: (PYTHON_EXE, \"-I\", \"-c\", PYTHON_PROBE_BOOTSTRAP, path)\n    for probe_id, path in PYTHON_VALIDATORS.items()\n}\nPROBES[\"rust_all\"] = (CARGO_EXE, \"test\", \"--all-targets\", \"--frozen\")\n\nEXPECTED_RUST_BIN_TARGETS = frozenset({\n    \"qsol-fed.rs\",\n    \"qsol-fed-bundle.rs\",\n    \"qsol-fed-oracle.rs\",\n    \"qsol-fed-sdk-conformance.rs\",\n})\n\n\ndef validate_rust_target_topology(source_root: Path) -> None:\n    \"\"\"Freeze the source-owned Cargo target surface used by rust_all.\"\"\"\n    manifest_path = source_root / \"Cargo.toml\"\n    try:\n        with manifest_path.open(\"rb\") as handle:\n            manifest = tomllib.load(handle)\n    except (OSError, tomllib.TOMLDecodeError):\n        fail(\"moriarty_cargo_manifest_invalid\")\n    package = manifest.get(\"package\")\n    if not isinstance(package, dict) or package.get(\"name\") != \"qsol-fed\":\n        fail(\"moriarty_cargo_package_identity_drift\")\n    for flag in (\"autolib\", \"autobins\", \"autoexamples\", \"autotests\", \"autobenches\"):\n        if package.get(flag, True) is not True:\n            fail(f\"moriarty_cargo_auto_target_disabled:{flag}\")\n    for key in (\"lib\", \"bin\", \"example\", \"test\", \"bench\", \"workspace\"):\n        if key in manifest:\n            fail(f\"moriarty_cargo_explicit_target_override:{key}\")\n    lib = source_root / \"src/lib.rs\"\n    if not lib.is_file() or lib.is_symlink():\n        fail(\"moriarty_cargo_library_target_missing\")\n    bin_root = source_root / \"src/bin\"\n    try:\n        actual_bins = {entry.name for entry in bin_root.iterdir() if entry.is_file() and not entry.is_symlink() and entry.suffix == \".rs\"}\n    except OSError:\n        fail(\"moriarty_cargo_bin_target_directory_missing\")\n    if actual_bins != EXPECTED_RUST_BIN_TARGETS:\n        fail(\"moriarty_cargo_bin_target_surface_drift\")\n\n''',
)

# Add cgroup-aware kill containment.
replace_once(
    "tools/run_moriarty.py",
    '''def _kill_probe_tree(process: subprocess.Popen[bytes]) -> None:\n    try:\n        os.killpg(process.pid, signal.SIGKILL)\n    except ProcessLookupError:\n        pass\n''',
    '''def _kill_probe_tree(process: subprocess.Popen[bytes]) -> None:\n    try:\n        os.killpg(process.pid, signal.SIGKILL)\n    except ProcessLookupError:\n        pass\n    if _ACTIVE_PROBE_CGROUP is not None:\n        kill_probe_cgroup(_ACTIVE_PROBE_CGROUP)\n''',
)

# Validate Cargo topology and join an aggregate cgroup before every real probe.
replace_once(
    "tools/run_moriarty.py",
    '''    if not network_seccomp_supported():\n        return _probe_failure_result(probe_id, "tool_error", b"network_seccomp_unavailable")\n    home.mkdir(mode=0o700, parents=False, exist_ok=False)\n''',
    '''    if not network_seccomp_supported():\n        return _probe_failure_result(probe_id, "tool_error", b"network_seccomp_unavailable")\n    if probe_id == "rust_all":\n        try:\n            validate_rust_target_topology(source_root)\n        except SystemExit as exc:\n            return _probe_failure_result(probe_id, "tool_error", str(exc).encode("utf-8", errors="replace"))\n    cgroup = _probe_cgroup()\n    if probe_cgroup_pids(cgroup):\n        return _probe_failure_result(probe_id, "tool_error", b"probe_cgroup_not_empty_before_probe")\n    home.mkdir(mode=0o700, parents=False, exist_ok=False)\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''    preexec = probe_isolation_preexec(\n        tuple(read_exec_paths),\n        _system_read_paths(),\n        tuple(writable_paths),\n    )\n''',
    '''    preexec = probe_isolation_preexec(\n        tuple(read_exec_paths),\n        _system_read_paths(),\n        tuple(writable_paths),\n        cgroup,\n    )\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''    leaked_descendants = _descendant_pids(os.getpid())\n    if leaked_descendants:\n        failure_kind = failure_kind or "tool_error"\n        _kill_probe_tree(process)\n    _reap_adopted_children()\n''',
    '''    leaked_descendants = _descendant_pids(os.getpid())\n    cgroup_descendants = probe_cgroup_pids(cgroup)\n    if leaked_descendants or cgroup_descendants:\n        failure_kind = failure_kind or "tool_error"\n        _kill_probe_tree(process)\n    _reap_adopted_children()\n    if probe_cgroup_pids(cgroup):\n        failure_kind = failure_kind or "tool_error"\n''',
)

# Persist truncation state in accepted/generated counterexamples and replay identity matching.
replace_once(
    "tools/run_moriarty.py",
    '''        "stdout_bytes": result["stdout_bytes"],\n        "stderr_bytes": result["stderr_bytes"],\n        "status": "unresolved",\n''',
    '''        "stdout_bytes": result["stdout_bytes"],\n        "stderr_bytes": result["stderr_bytes"],\n        "stdout_truncated": result["stdout_truncated"],\n        "stderr_truncated": result["stderr_truncated"],\n        "status": "unresolved",\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''        and result["stdout_bytes"] == item["stdout_bytes"]\n        and result["stderr_bytes"] == item["stderr_bytes"]\n    )\n''',
    '''        and result["stdout_bytes"] == item["stdout_bytes"]\n        and result["stderr_bytes"] == item["stderr_bytes"]\n        and result["stdout_truncated"] is item["stdout_truncated"]\n        and result["stderr_truncated"] is item["stderr_truncated"]\n    )\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''        "observed_exit_code", "stdout_sha256", "stderr_sha256", "stdout_bytes",\n        "stderr_bytes", "status", "resolution_commit", "production_credentials_used",\n''',
    '''        "observed_exit_code", "stdout_sha256", "stderr_sha256", "stdout_bytes",\n        "stderr_bytes", "stdout_truncated", "stderr_truncated", "status", "resolution_commit", "production_credentials_used",\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''        or not 0 <= item["stderr_bytes"] <= MAX_PROBE_OUTPUT_BYTES\n    ):\n''',
    '''        or not 0 <= item["stderr_bytes"] <= MAX_PROBE_OUTPUT_BYTES\n        or type(item["stdout_truncated"]) is not bool\n        or type(item["stderr_truncated"]) is not bool\n    ):\n''',
)

# Clean disposable writable state after every current and replay probe.
insert_marker = "def _run_counterexample_replay_probe(\n"
cleanup_code = '''def _cleanup_probe_writable_paths(*paths: Path) -> None:\n    root = _probe_writable_root()\n    for path in paths:\n        absolute = Path(path).absolute()\n        if absolute == root or not absolute.is_relative_to(root):\n            fail("moriarty_probe_cleanup_path_escape")\n        try:\n            info = os.lstat(absolute)\n        except FileNotFoundError:\n            continue\n        if stat.S_ISLNK(info.st_mode):\n            absolute.unlink()\n        elif stat.S_ISDIR(info.st_mode):\n            shutil.rmtree(absolute)\n        else:\n            absolute.unlink()\n\n\ndef _run_probe_with_cleanup(\n    probe_id: str,\n    home: Path,\n    source_root: Path,\n    cargo_home: Path,\n    target_dir: Path,\n    python_exec: Path,\n    cargo_exec: Path,\n    rustc_exec: Path,\n    rustdoc_exec: Path | None,\n    rust_runtime: Path | None,\n) -> dict[str, Any]:\n    temp_dir = target_dir.parent / f"tmp-{target_dir.name}"\n    try:\n        return run_probe(\n            probe_id, home, source_root, cargo_home, target_dir,\n            python_exec, cargo_exec, rustc_exec, rustdoc_exec, rust_runtime,\n        )\n    finally:\n        _cleanup_probe_writable_paths(home, cargo_home, target_dir, temp_dir)\n\n\n'''
replace_once("tools/run_moriarty.py", insert_marker, cleanup_code + insert_marker)
replace_once(
    "tools/run_moriarty.py",
    '''    return run_probe(\n        probe_id,\n        writable_root / f"{label}-home",\n''',
    '''    return _run_probe_with_cleanup(\n        probe_id,\n        writable_root / f"{label}-home",\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''            results[probe_id] = run_probe(\n                probe_id,\n''',
    '''            results[probe_id] = _run_probe_with_cleanup(\n                probe_id,\n''',
)

# Require quota-backed authenticated Cargo input plus a cgroup-v2 envelope.
replace_once(
    "tools/run_moriarty.py",
    '''    global _ACTIVE_PROBE_WRITABLE_ROOT\n    _ACTIVE_PROBE_WRITABLE_ROOT = probe_quota_root(Path(quota_value))\n\n    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-work-") as work_dir:\n''',
    '''    global _ACTIVE_PROBE_WRITABLE_ROOT, _ACTIVE_PROBE_CGROUP\n    _ACTIVE_PROBE_WRITABLE_ROOT = probe_quota_root(Path(quota_value))\n    global CARGO_CACHE_HOME\n    CARGO_CACHE_HOME = cargo_cache_root(CARGO_CACHE_HOME)\n    cgroup_value = os.environ.get("MORIARTY_PROBE_CGROUP")\n    if not cgroup_value:\n        fail("moriarty_probe_cgroup_required")\n    _ACTIVE_PROBE_CGROUP = probe_cgroup_root(Path(cgroup_value))\n    if probe_cgroup_pids(_ACTIVE_PROBE_CGROUP):\n        fail("moriarty_probe_cgroup_not_empty_at_start")\n\n    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-work-") as work_dir:\n''',
)

# Do not synthesize a second unresolved record for an already accepted attack/probe failure.
replace_once(
    "tools/run_moriarty.py",
    '''    generated: list[dict[str, Any]] = []\n    for probe_id, result in results.items():\n''',
    '''    generated: list[dict[str, Any]] = []\n    accepted_unresolved_failures = {\n        (item["attack_id"], item["regression_probe_ids"][0])\n        for item in accepted\n        if item["status"] == "unresolved"\n    }\n    for probe_id, result in results.items():\n''',
)
replace_once(
    "tools/run_moriarty.py",
    '''        if len(owners) == 1 and result["failure_kind"] in {"exit_nonzero", "timeout", "tool_error"}:\n            generated.append(generated_counterexample(target, owners[0], result))\n''',
    '''        if len(owners) == 1 and result["failure_kind"] in {"exit_nonzero", "timeout", "tool_error"}:\n            key = (owners[0]["id"], probe_id)\n            if key not in accepted_unresolved_failures:\n                generated.append(generated_counterexample(target, owners[0], result))\n''',
)

# ---------------------------------------------------------------------------
# schemas/moriarty-counterexample-v1.schema.json
# ---------------------------------------------------------------------------
schema_path = Path("schemas/moriarty-counterexample-v1.schema.json")
schema = json.loads(schema_path.read_text(encoding="utf-8"))
for field in ("stdout_truncated", "stderr_truncated"):
    if field not in schema["required"]:
        insert_at = schema["required"].index("status")
        schema["required"].insert(insert_at, field)
    schema["properties"][field] = {"type": "boolean"}
schema_path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

# ---------------------------------------------------------------------------
# tools/validate_phase9_gate.py
# ---------------------------------------------------------------------------
replace_between(
    "tools/validate_phase9_gate.py",
    "EXPECTED_PROBES = {\n",
    "}\nHARD_FALSE_CLAIMS = {\n",
    '''EXPECTED_PROBES = {\n    probe_id: ("-I", "-c", moriarty.PYTHON_PROBE_BOOTSTRAP, path)\n    for probe_id, path in moriarty.PYTHON_VALIDATORS.items()\n}\nEXPECTED_PROBES["rust_all"] = ("test", "--all-targets", "--frozen")\nHARD_FALSE_CLAIMS = {\n''',
)
# The replacement above includes the HARD_FALSE_CLAIMS opener, remove duplicated opener if present.
replace_once(
    "tools/validate_phase9_gate.py",
    "HARD_FALSE_CLAIMS = {\nHARD_FALSE_CLAIMS = {\n",
    "HARD_FALSE_CLAIMS = {\n",
)

# Freeze immutable claim header values and MORIARTY protocol identity.
replace_once(
    "tools/validate_phase9_gate.py",
    '''    require(current.get("document_type") == "qsol-fed-phase9-moriarty-claims", "Phase 9 claim id drift")\n    require(current.get("gate_id") == "qsol-fed-phase9-moriarty-gate/1", "Phase 9 gate id drift")\n''',
    '''    require(current.get("document_type") == "qsol-fed-phase9-moriarty-claims", "Phase 9 claim id drift")\n    require(current.get("schema_version") == 1, "Phase 9 claim schema version drift")\n    require(current.get("protocol") == "qsol-fed/0", "Phase 9 constitutional protocol drift")\n    require(current.get("wire_protocol") == "qsol-fed/1", "Phase 9 wire protocol drift")\n    require(current.get("phase") == "9", "Phase 9 phase label drift")\n    require(current.get("gate_id") == "qsol-fed-phase9-moriarty-gate/1", "Phase 9 gate id drift")\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''    require(isinstance(assurance, dict) and set(assurance) == expected_assurance, "Phase 9 assurance field set is not closed")\n    for key in (\n''',
    '''    require(isinstance(assurance, dict) and set(assurance) == expected_assurance, "Phase 9 assurance field set is not closed")\n    require(assurance.get("moriarty_protocol") == "MORIARTY/1", "Phase 9 MORIARTY protocol drift")\n    for key in (\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''    claim_drift = copy.deepcopy(current)\n    claim_drift["claim_rule"] = "Phase 9 grants authority"\n    _expect_reject(lambda: _validate_claim_document(previous, claim_drift), "claim rule drift")\n''',
    '''    claim_drift = copy.deepcopy(current)\n    claim_drift["claim_rule"] = "Phase 9 grants authority"\n    _expect_reject(lambda: _validate_claim_document(previous, claim_drift), "claim rule drift")\n    for field, bad_value in (("schema_version", 2), ("protocol", "qsol-fed/9"), ("wire_protocol", "qsol-fed/9"), ("phase", "10")):\n        header_drift = copy.deepcopy(current)\n        header_drift[field] = bad_value\n        _expect_reject(lambda value=header_drift: _validate_claim_document(previous, value), f"claim header drift: {field}")\n    moriarty_drift = copy.deepcopy(current)\n    moriarty_drift["assurance"]["moriarty_protocol"] = "MORIARTY/2"\n    _expect_reject(lambda: _validate_claim_document(previous, moriarty_drift), "MORIARTY protocol drift")\n''',
)

# Counterexample schema/fixture synchronization for truncation state.
replace_once(
    "tools/validate_phase9_gate.py",
    '''        "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes", "status",\n        "resolution_commit", "production_credentials_used", "production_targets_used",\n''',
    '''        "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes", "stdout_truncated",\n        "stderr_truncated", "status", "resolution_commit", "production_credentials_used", "production_targets_used",\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''        "stdout_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES, "stderr_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES,\n        "status": "resolved", "resolution_commit": "e" * 40, "production_credentials_used": False,\n''',
    '''        "stdout_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES, "stderr_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES,\n        "stdout_truncated": True, "stderr_truncated": True,\n        "status": "resolved", "resolution_commit": "e" * 40, "production_credentials_used": False,\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''        "stdout_bytes": 0,\n        "stderr_bytes": 0,\n        "status": "unresolved",\n''',
    '''        "stdout_bytes": 0,\n        "stderr_bytes": 0,\n        "stdout_truncated": False,\n        "stderr_truncated": False,\n        "status": "unresolved",\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''    require(counter_props["stderr_bytes"].get("maximum") == moriarty.MAX_PROBE_OUTPUT_BYTES, "counterexample stderr bound schema drift")\n''',
    '''    require(counter_props["stderr_bytes"].get("maximum") == moriarty.MAX_PROBE_OUTPUT_BYTES, "counterexample stderr bound schema drift")\n    require(counter_props["stdout_truncated"].get("type") == "boolean" and counter_props["stderr_truncated"].get("type") == "boolean", "counterexample truncation schema drift")\n''',
)

# Validate target topology and isolated Python bootstrap against a tracked stdlib-name shadow.
probe_insert = '''    isolation = moriarty._moriarty_isolation\n'''
probe_extra = '''    moriarty.validate_rust_target_topology(ROOT)\n    with tempfile.TemporaryDirectory(prefix="moriarty-topology-negative-") as temp_dir:\n        fake = Path(temp_dir)\n        (fake / "src").mkdir()\n        (fake / "src/lib.rs").write_text("", encoding="utf-8")\n        (fake / "src/bin").mkdir()\n        for name in moriarty.EXPECTED_RUST_BIN_TARGETS:\n            (fake / "src/bin" / name).write_text("", encoding="utf-8")\n        (fake / "Cargo.toml").write_text('[package]\\nname="qsol-fed"\\nversion="0.0.0"\\nedition="2024"\\n\\n[lib]\\npath="/dev/null"\\n', encoding="utf-8")\n        _expect_reject(lambda: moriarty.validate_rust_target_topology(fake), "Cargo target topology override")\n    with tempfile.TemporaryDirectory(prefix="moriarty-python-shadow-") as temp_dir:\n        fake = Path(temp_dir)\n        (fake / "tools").mkdir()\n        (fake / "tools/json.py").write_text("import os; os._exit(97)\\n", encoding="utf-8")\n        validator = fake / "tools/validator.py"\n        validator.write_text("import json\\nassert 'json.py' in str(getattr(json, '__file__', ''))\\n", encoding="utf-8")\n        completed = subprocess.run(\n            [sys.executable, "-I", "-c", moriarty.PYTHON_PROBE_BOOTSTRAP, str(validator)],\n            cwd=fake,\n            env={"PATH": "/usr/bin:/bin", "HOME": str(fake), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},\n            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,\n        )\n        require(completed.returncode == 0, "MORIARTY isolated Python bootstrap admitted stdlib shadow")\n'''
replace_once("tools/validate_phase9_gate.py", probe_insert, probe_extra + probe_insert)

# The fake validator assertion above needs to distinguish stdlib json from the local shadow.
replace_once(
    "tools/validate_phase9_gate.py",
    '''        validator.write_text("import json\\nassert 'json.py' in str(getattr(json, '__file__', ''))\\n", encoding="utf-8")\n''',
    '''        validator.write_text("import json, pathlib\\np=pathlib.Path(json.__file__).resolve()\\nassert p != pathlib.Path(__file__).with_name('json.py').resolve()\\n", encoding="utf-8")\n''',
)

# Runner binding includes the cgroup envelope.
replace_once(
    "tools/validate_phase9_gate.py",
    '''    "MORIARTY_CARGO_CACHE_ROOT",\n    "MORIARTY_PROBE_WRITABLE_ROOT",\n)\n''',
    '''    "MORIARTY_CARGO_CACHE_ROOT",\n    "MORIARTY_PROBE_WRITABLE_ROOT",\n    "MORIARTY_PROBE_CGROUP",\n)\n''',
)

# Kernel regression: all signal ABIs denied and x32 syscall-number path denied on x86_64.
replace_once(
    "tools/validate_phase9_gate.py",
    '''queue_nr, tgqueue_nr = ((129, 297) if machine == "x86_64" else (138, 240))\nfor number, args in (\n    (queue_nr, (int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),\n    (tgqueue_nr, (int(parent_pid), int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),\n):\n''',
    '''queue_nr, tgqueue_nr = ((129, 297) if machine == "x86_64" else (138, 240))\nfor number, args in (\n    (queue_nr, (int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),\n    (tgqueue_nr, (int(parent_pid), int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),\n):\n''',
)
replace_once(
    "tools/validate_phase9_gate.py",
    '''ctypes.set_errno(0)\nresult = libc.syscall(425, 1, ctypes.c_void_p(0))\nif result != -1 or ctypes.get_errno() != errno.EPERM:\n    raise SystemExit(11)\nraise SystemExit(0)\n''',
    '''ctypes.set_errno(0)\nresult = libc.syscall(425, 1, ctypes.c_void_p(0))\nif result != -1 or ctypes.get_errno() != errno.EPERM:\n    raise SystemExit(11)\nif machine == "x86_64":\n    ctypes.set_errno(0)\n    result = libc.syscall(0x40000000 | 41, 2, 1, 0)\n    if result != -1 or ctypes.get_errno() != errno.EPERM:\n        raise SystemExit(12)\nraise SystemExit(0)\n''',
)

# CI/docs marker contract for quota-backed Cargo cache, cgroup and source-pinned Rust acquisition.
replace_once(
    "tools/validate_phase9_gate.py",
    '''    require("sudo mount -t tmpfs" in workflow and "size=2147483648" in workflow, "CI MORIARTY hard writable tmpfs quota missing")\n    require("MORIARTY_CARGO_CACHE_ROOT: ${{ runner.temp }}/moriarty-cargo-source" in workflow, "CI MORIARTY authenticated Cargo cache binding missing")\n    require("MORIARTY_PROBE_WRITABLE_ROOT: /mnt/qsol-moriarty-probe-writable" in workflow, "CI MORIARTY writable quota binding missing")\n''',
    '''    require("sudo mount -t tmpfs" in workflow and "size=2147483648" in workflow, "CI MORIARTY hard writable tmpfs quota missing")\n    require("size=1073741824" in workflow and "/mnt/qsol-moriarty-cargo-source" in workflow, "CI MORIARTY Cargo fetch quota missing")\n    require("timeout --kill-after=5s 120s" in workflow, "CI MORIARTY Cargo fetch timeout missing")\n    require("rustup toolchain install 1.97.1" in workflow, "CI MORIARTY exact Rust toolchain acquisition missing")\n    require("memory.max" in workflow and "pids.max" in workflow and "MORIARTY_PROBE_CGROUP" in workflow, "CI MORIARTY cgroup aggregate resource envelope missing")\n    require("MORIARTY_PROBE_WRITABLE_ROOT: /mnt/qsol-moriarty-probe-writable" in workflow, "CI MORIARTY writable quota binding missing")\n''',
)

# Validate quota/cgroup binding before launching the runner.
replace_once(
    "tools/validate_phase9_gate.py",
    '''    moriarty.probe_quota_root(Path(quota_value))\n    validate_runner_toolchain_binding_negative(target)\n''',
    '''    moriarty.probe_quota_root(Path(quota_value))\n    cache_value = os.environ.get("MORIARTY_CARGO_CACHE_ROOT")\n    require(cache_value is not None, "MORIARTY Cargo cache binding missing")\n    moriarty.cargo_cache_root(Path(cache_value))\n    cgroup_value = os.environ.get("MORIARTY_PROBE_CGROUP")\n    require(cgroup_value is not None, "MORIARTY cgroup binding missing")\n    moriarty.probe_cgroup_root(Path(cgroup_value))\n    validate_runner_toolchain_binding_negative(target)\n''',
)

# ---------------------------------------------------------------------------
# MORIARTY.md local invocation contract
# ---------------------------------------------------------------------------
replace_between(
    "MORIARTY.md",
    "## Running locally\n",
    "\nThe report is intentionally ephemeral.",
    '''## Running locally\n\nLocal execution requires the same kernel-backed writable and process-resource boundaries as CI. The following example uses two private tmpfs mounts and a delegated cgroup-v2 child. It also uses an explicit Cargo cache root; populate that cache with the exact pinned toolchain before invoking MORIARTY.\n\n```bash\nset -euo pipefail\nTARGET="$(git rev-parse HEAD)"\nREPORT_DIR="$(mktemp -d)"\nchmod 700 "$REPORT_DIR"\n\nPROBE_QUOTA=/mnt/qsol-moriarty-probe-writable\nCARGO_CACHE=/mnt/qsol-moriarty-cargo-source\nsudo install -d -m 0700 "$PROBE_QUOTA" "$CARGO_CACHE"\nsudo mount -t tmpfs -o "size=2147483648,nosuid,nodev,mode=0700,uid=$(id -u),gid=$(id -g)" tmpfs "$PROBE_QUOTA"\nsudo mount -t tmpfs -o "size=1073741824,nosuid,nodev,mode=0700,uid=$(id -u),gid=$(id -g)" tmpfs "$CARGO_CACHE"\n\nCURRENT_CGROUP="$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)"\nCGROUP="/sys/fs/cgroup${CURRENT_CGROUP}/qsol-moriarty-probe"\nsudo mkdir "$CGROUP"\necho 2147483648 | sudo tee "$CGROUP/memory.max" >/dev/null\necho 128 | sudo tee "$CGROUP/pids.max" >/dev/null\nif test -f "$CGROUP/memory.swap.max"; then echo 0 | sudo tee "$CGROUP/memory.swap.max" >/dev/null; fi\nsudo chown "$(id -u):$(id -g)" "$CGROUP/cgroup.procs"\n\nexport MORIARTY_PROBE_WRITABLE_ROOT="$PROBE_QUOTA"\nexport MORIARTY_CARGO_CACHE_ROOT="$CARGO_CACHE"\nexport MORIARTY_PROBE_CGROUP="$CGROUP"\n# Also export MORIARTY_RUST_TOOLCHAIN_ROOT and the three MORIARTY_EXPECTED_*\n# version bindings to the exact trusted toolchain snapshot used for the run.\n\npython3 -I tools/validate_phase9_gate.py --target-commit "$TARGET" --report-dir "$REPORT_DIR"\n```\n\nDirect runner invocation uses the same required environment bindings:\n\n```bash\npython3 -I tools/run_moriarty.py \\\n  --target-commit "$TARGET" \\\n  --output "$REPORT_DIR/moriarty-report.json"\n```\n\nCleanup after the run:\n\n```bash\nsudo rmdir "$CGROUP"\nsudo umount "$PROBE_QUOTA" "$CARGO_CACHE"\nsudo rmdir "$PROBE_QUOTA" "$CARGO_CACHE"\n```\n\n''',
)
replace_once(
    "MORIARTY.md",
    "Probe seccomp permits only anonymous `AF_UNIX` `socketpair()` IPC, denies addressable `socket()`/`connect()`, io_uring networking, harness-directed signals, pidfd signaling, ptrace, and process-memory syscalls.",
    "Probe seccomp permits only anonymous `AF_UNIX` `socketpair()` IPC, denies addressable `socket()`/`connect()`, io_uring networking, every probe-originated signal-delivery syscall, pidfd signaling, ptrace/process-memory syscalls, and x32 syscall numbers on x86_64. Aggregate probe memory/PIDs are bounded by cgroup v2; per-process rlimits remain defense-in-depth. `diagnostic_class` is advisory classification only and never affects graduation.",
)

# Compile/parse all modified machine surfaces before the applicator may commit.
for path in ("tools/moriarty_isolation.py", "tools/run_moriarty.py", "tools/validate_phase9_gate.py"):
    py_compile.compile(path, doraise=True)
json.loads(Path("schemas/moriarty-counterexample-v1.schema.json").read_text(encoding="utf-8"))
print("round12-source-transform-ok")
