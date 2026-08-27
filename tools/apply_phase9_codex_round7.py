#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def update(path: str, transform) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    new = transform(text)
    if new == text:
        raise SystemExit(f"{path}: transformer made no change")
    p.write_text(new, encoding="utf-8")


BOOTSTRAP_HELPERS = r'''ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.dont_write_bytecode = True
_BOOTSTRAP_GIT = Path("/usr/bin/git")
_BOOTSTRAP_TARGET_RE = re.compile(r"^[0-9a-f]{40}$")


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


def _bootstrap_target() -> str:
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


def _bootstrap_git_object(kind: str, object_id: str) -> bytes:
    if _BOOTSTRAP_TARGET_RE.fullmatch(object_id) is None:
        raise SystemExit("moriarty_bootstrap_object_id_invalid")
    completed = _bootstrap_git("cat-file", kind, object_id)
    if completed.returncode != 0:
        raise SystemExit(f"moriarty_bootstrap_{kind}_read_failed")
    payload = completed.stdout
    actual = hashlib.sha1(f"{kind} {len(payload)}\\0".encode("ascii") + payload).hexdigest()
    if actual != object_id:
        raise SystemExit(f"moriarty_bootstrap_{kind}_hash_mismatch")
    return payload


def _bootstrap_tree_entry(tree_payload: bytes, wanted: str) -> tuple[str, str]:
    cursor = 0
    while cursor < len(tree_payload):
        space = tree_payload.find(b" ", cursor)
        nul = tree_payload.find(b"\\0", space + 1 if space >= 0 else cursor)
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
    first_line = commit_payload.split(b"\\n", 1)[0]
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
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise SystemExit(f"moriarty_bootstrap_spec_unavailable:{name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module
'''


def transform_runner(text: str) -> str:
    text = replace_once(
        text,
        "import io\nimport json\n",
        "import io\nimport importlib.machinery\nimport importlib.util\nimport json\n",
        "runner importlib imports",
    )
    old_bootstrap = '''ROOT = Path(__file__).resolve().parents[1]\nTOOLS = ROOT / "tools"\nif str(TOOLS) not in sys.path:\n    sys.path.insert(0, str(TOOLS))\n\nfrom qsol_canonical import serialize  # noqa: E402\nfrom moriarty_isolation import (  # noqa: E402\n    create_empty_cargo_home,\n    create_exact_export,\n    create_isolated_cargo_home,\n    create_verified_cargo_template,\n    enable_child_subreaper,\n    landlock_abi_version,\n    network_seccomp_supported,\n    probe_isolation_preexec,\n    proc_fd_path,\n    stage_executable_from_fd,\n    stage_rust_toolchain_runtime,\n    write_report_exclusive,\n)\n'''
    new_bootstrap = BOOTSTRAP_HELPERS + '''\n_BOOTSTRAP_TARGET = _bootstrap_target()\nif Path(__file__).read_bytes() != _bootstrap_verified_blob(_BOOTSTRAP_TARGET, "tools/run_moriarty.py"):\n    raise SystemExit("moriarty_bootstrap_runner_source_mismatch")\n_qsol_canonical = _load_verified_source_module("qsol_canonical", _BOOTSTRAP_TARGET)\n_moriarty_isolation = _load_verified_source_module("moriarty_isolation", _BOOTSTRAP_TARGET)\nserialize = _qsol_canonical.serialize\ncreate_empty_cargo_home = _moriarty_isolation.create_empty_cargo_home\ncreate_exact_export = _moriarty_isolation.create_exact_export\ncreate_isolated_cargo_home = _moriarty_isolation.create_isolated_cargo_home\ncreate_verified_cargo_template = _moriarty_isolation.create_verified_cargo_template\nenable_child_subreaper = _moriarty_isolation.enable_child_subreaper\nlandlock_abi_version = _moriarty_isolation.landlock_abi_version\nnetwork_seccomp_supported = _moriarty_isolation.network_seccomp_supported\nprobe_isolation_preexec = _moriarty_isolation.probe_isolation_preexec\nproc_fd_path = _moriarty_isolation.proc_fd_path\nstage_executable_from_fd = _moriarty_isolation.stage_executable_from_fd\nstage_rust_toolchain_runtime = _moriarty_isolation.stage_rust_toolchain_runtime\nwrite_report_exclusive = _moriarty_isolation.write_report_exclusive\n'''
    text = replace_once(text, old_bootstrap, new_bootstrap, "runner verified bootstrap")
    text = replace_once(text, "MAX_REPORT_BYTES = 65_536", "MAX_REPORT_BYTES = 512 * 1024", "report byte ceiling")
    family_tail = '''    "transport_nat_relay_store_forward_archive",\n    "cross_phase_contradictions",\n}\n\n\ndef load_json'''
    family_new = '''    "transport_nat_relay_store_forward_archive",\n    "cross_phase_contradictions",\n}\nALLOWED_OWNER_PHASES = frozenset({"0", "1", "2", "3", "4", "5A", "5", "5C", "6", "7", "8", "cross-phase"})\nMAX_OWNER_PHASES = 12\nMAX_BOUNDARY_IDS = 32\nMAX_ATTACK_PROBE_IDS = 16\n\n\ndef load_json'''
    text = replace_once(text, family_tail, family_new, "owner phase constants")
    old_attack = '''            or not isinstance(owner_phases, list)\n            or not owner_phases\n            or not all(isinstance(value, str) and value for value in owner_phases)\n            or len(set(owner_phases)) != len(owner_phases)\n            or not isinstance(boundary_ids, list)\n            or not boundary_ids\n            or not all(isinstance(value, str) and re.fullmatch(r"[a-z0-9_./-]{1,128}", value) for value in boundary_ids)\n            or len(set(boundary_ids)) != len(boundary_ids)\n            or not isinstance(probe_ids, list)\n            or not probe_ids\n            or not all(isinstance(value, str) and value in PROBES for value in probe_ids)\n            or len(set(probe_ids)) != len(probe_ids)\n'''
    new_attack = '''            or not isinstance(owner_phases, list)\n            or not 1 <= len(owner_phases) <= MAX_OWNER_PHASES\n            or not all(isinstance(value, str) and value in ALLOWED_OWNER_PHASES for value in owner_phases)\n            or len(set(owner_phases)) != len(owner_phases)\n            or not isinstance(boundary_ids, list)\n            or not 1 <= len(boundary_ids) <= MAX_BOUNDARY_IDS\n            or not all(isinstance(value, str) and re.fullmatch(r"[a-z0-9_./-]{1,128}", value) for value in boundary_ids)\n            or len(set(boundary_ids)) != len(boundary_ids)\n            or not isinstance(probe_ids, list)\n            or not 1 <= len(probe_ids) <= MAX_ATTACK_PROBE_IDS\n            or not all(isinstance(value, str) and value in PROBES for value in probe_ids)\n            or len(set(probe_ids)) != len(probe_ids)\n'''
    text = replace_once(text, old_attack, new_attack, "attack owner phase enum")
    old_shape = '''        or not isinstance(item["owner_phases"], list)\n        or not item["owner_phases"]\n        or len(set(item["owner_phases"])) != len(item["owner_phases"])\n        or not isinstance(item["boundary_ids"], list)\n        or not item["boundary_ids"]\n        or len(set(item["boundary_ids"])) != len(item["boundary_ids"])\n'''
    new_shape = '''        or not isinstance(item["owner_phases"], list)\n        or not 1 <= len(item["owner_phases"]) <= MAX_OWNER_PHASES\n        or not all(isinstance(value, str) and value in ALLOWED_OWNER_PHASES for value in item["owner_phases"])\n        or len(set(item["owner_phases"])) != len(item["owner_phases"])\n        or not isinstance(item["boundary_ids"], list)\n        or not 1 <= len(item["boundary_ids"]) <= MAX_BOUNDARY_IDS\n        or not all(isinstance(value, str) and re.fullmatch(r"[a-z0-9_./-]{1,128}", value) for value in item["boundary_ids"])\n        or len(set(item["boundary_ids"])) != len(item["boundary_ids"])\n'''
    text = replace_once(text, old_shape, new_shape, "counterexample owner phase enum")
    normalize_marker = '''\n\ndef _normalize_probe_output(\n    data: bytes,\n    *,\n'''
    normalize_insert = '''\n\n_RUNTIME_NORMALIZATIONS: tuple[tuple[re.Pattern[bytes], bytes], ...] = (\n    (re.compile(rb"(?m)^(\\s*Finished .*) in (?:[0-9]+m )?[0-9]+(?:\\.[0-9]+)?s$"), rb"\\1 in <T>s"),\n    (re.compile(rb"; finished in (?:[0-9]+m )?[0-9]+(?:\\.[0-9]+)?s"), rb"; finished in <T>s"),\n    (re.compile(rb"\\(pid=[0-9]+\\)"), rb"(pid=<PID>)"),\n    (re.compile(rb"(thread '[^'\\r\\n]*' )\\([0-9]+\\)"), rb"\\1(<TID>)"),\n)\n\n\ndef _normalize_probe_output(\n    data: bytes,\n    *,\n    probe_id: str,\n'''
    text = replace_once(text, normalize_marker, normalize_insert, "runtime normalization patterns")
    normalize_tail = '''    for raw, marker in sorted(encoded, key=lambda item: len(item[0]), reverse=True):\n        normalized = normalized.replace(raw, marker)\n    return normalized\n'''
    normalize_tail_new = '''    for raw, marker in sorted(encoded, key=lambda item: len(item[0]), reverse=True):\n        normalized = normalized.replace(raw, marker)\n    if probe_id == "rust_all":\n        for pattern, replacement in _RUNTIME_NORMALIZATIONS:\n            normalized = pattern.sub(replacement, normalized)\n    return normalized\n'''
    text = replace_once(text, normalize_tail, normalize_tail_new, "apply runtime normalization")
    text = replace_once(
        text,
        '''        name: _normalize_probe_output(\n            bytes(captured[name]),\n            source_root=source_root,\n''',
        '''        name: _normalize_probe_output(\n            bytes(captured[name]),\n            probe_id=probe_id,\n            source_root=source_root,\n''',
        "run_probe normalization id",
    )
    text = replace_once(text, "            preexec_fn=preexec,\n            bufsize=0,", "            preexec_fn=preexec,\n            close_fds=True,\n            bufsize=0,", "probe close fds")
    return text


def transform_isolation(text: str) -> str:
    text = replace_once(
        text,
        "MAX_CARGO_ARCHIVE_BYTES = 64 * 1024 * 1024\n",
        "MAX_CARGO_ARCHIVE_BYTES = 64 * 1024 * 1024\nMAX_CARGO_INDEX_BYTES = 16 * 1024 * 1024\nMAX_CARGO_INDEX_ENTRIES = 16_384\nMAX_CARGO_INDEX_DEPTH = 16\n",
        "cargo index constants",
    )
    old_seccomp = '''def _socket_syscalls() -> tuple[int, int, int]:\n    machine = os.uname().machine\n    if machine == "x86_64":\n        return (41, 53, _AUDIT_ARCH_X86_64)\n    if machine == "aarch64":\n        return (198, 199, _AUDIT_ARCH_AARCH64)\n    fail("moriarty_network_seccomp_arch_unsupported")\n\n\ndef _io_uring_syscalls() -> tuple[int, int, int]:\n    # io_uring syscall numbers are shared by the supported Linux architectures.\n    return (425, 426, 427)\n\n\ndef apply_network_seccomp_policy() -> None:\n    """Allow AF_UNIX IPC while denying external socket creation and io_uring.\n\n    The filter first binds itself to the expected Linux audit architecture. It\n    denies io_uring entirely so IORING_OP_SOCKET/CONNECT/SEND cannot bypass the\n    native syscall policy. Native socket()/socketpair() are then allowed only for\n    AF_UNIX; every other family fails at creation with EPERM. The probe receives\n    no ambient network descriptors, so later socket I/O can only operate on local\n    Unix-domain IPC descriptors created inside the sandbox.\n    """\n    libc = _linux_libc()\n    deny = _SECCOMP_RET_ERRNO | errno.EPERM\n    allow = _SECCOMP_RET_ALLOW\n    socket_nr, socketpair_nr, audit_arch = _socket_syscalls()\n    instructions: list[_SockFilter] = [\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),\n        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, audit_arch),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),\n    ]\n    for number in _io_uring_syscalls():\n        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))\n        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))\n    instructions.extend([\n        _SockFilter(_BPF_JMP_JEQ_K, 2, 0, socket_nr),\n        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, socketpair_nr),\n        _SockFilter(_BPF_RET_K, 0, 0, allow),\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_UNIX),\n        _SockFilter(_BPF_RET_K, 0, 0, allow),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n    ])\n    array_type = _SockFilter * len(instructions)\n    array = array_type(*instructions)\n    program = _SockFprog(len(instructions), array)\n    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:\n        raise OSError(ctypes.get_errno(), "prctl_no_new_privs_seccomp")\n    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:\n        raise OSError(ctypes.get_errno(), "prctl_seccomp_network_filter")\n\n\ndef probe_isolation_preexec(\n    read_exec_paths: tuple[Path, ...],\n    read_paths: tuple[Path, ...],\n    writable_paths: tuple[Path, ...],\n):\n    read_exec = tuple(Path(path).resolve(strict=True) for path in read_exec_paths if Path(path).exists())\n    readable = tuple(Path(path).resolve(strict=True) for path in read_paths if Path(path).exists())\n    writable = tuple(Path(path).resolve(strict=True) for path in writable_paths if Path(path).exists())\n\n    def _apply() -> None:\n        apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)\n        apply_network_seccomp_policy()\n\n    return _apply\n'''
    new_seccomp = '''def _socket_syscalls() -> tuple[int, int, int, int]:\n    machine = os.uname().machine\n    if machine == "x86_64":\n        return (41, 53, 42, _AUDIT_ARCH_X86_64)\n    if machine == "aarch64":\n        return (198, 199, 203, _AUDIT_ARCH_AARCH64)\n    fail("moriarty_network_seccomp_arch_unsupported")\n\n\ndef _signal_syscalls() -> tuple[int, int, int, int]:\n    machine = os.uname().machine\n    if machine == "x86_64":\n        return (62, 200, 234, 424)\n    if machine == "aarch64":\n        return (129, 130, 131, 424)\n    fail("moriarty_signal_seccomp_arch_unsupported")\n\n\ndef _process_memory_syscalls() -> tuple[int, int, int]:\n    machine = os.uname().machine\n    if machine == "x86_64":\n        return (101, 310, 311)\n    if machine == "aarch64":\n        return (117, 270, 271)\n    fail("moriarty_process_memory_seccomp_arch_unsupported")\n\n\ndef _io_uring_syscalls() -> tuple[int, int, int]:\n    return (425, 426, 427)\n\n\ndef apply_network_seccomp_policy(harness_pid: int, harness_pgid: int) -> None:\n    """Deny addressable IPC/network creation and probe-to-harness control.\n\n    Addressable socket() and connect() are denied outright. Only anonymous\n    socketpair(AF_UNIX) IPC is admitted, so a probe cannot name Docker, systemd,\n    X11, abstract-namespace, or other ambient Unix-domain endpoints. io_uring,\n    pidfd signaling, ptrace/process_vm access, and signals directed at the\n    harness/broadcast group are also denied.\n    """\n    libc = _linux_libc()\n    deny = _SECCOMP_RET_ERRNO | errno.EPERM\n    allow = _SECCOMP_RET_ALLOW\n    socket_nr, socketpair_nr, connect_nr, audit_arch = _socket_syscalls()\n    kill_nr, tkill_nr, tgkill_nr, pidfd_signal_nr = _signal_syscalls()\n    forbidden_targets = (\n        harness_pid & 0xFFFFFFFF,\n        (-harness_pgid) & 0xFFFFFFFF,\n        0xFFFFFFFF,\n    )\n    instructions: list[_SockFilter] = [\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),\n        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, audit_arch),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),\n    ]\n    for number in (*_io_uring_syscalls(), pidfd_signal_nr, *_process_memory_syscalls()):\n        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))\n        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, deny))\n    for number in (kill_nr, tkill_nr, tgkill_nr):\n        block: list[_SockFilter] = [_SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET)]\n        for target in forbidden_targets:\n            block.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, target))\n            block.append(_SockFilter(_BPF_RET_K, 0, 0, deny))\n        block.append(_SockFilter(_BPF_LD_W_ABS, 0, 0, 0))\n        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, len(block), number))\n        instructions.extend(block)\n    instructions.extend([\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, socket_nr),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, connect_nr),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 4, socketpair_nr),\n        _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),\n        _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_UNIX),\n        _SockFilter(_BPF_RET_K, 0, 0, allow),\n        _SockFilter(_BPF_RET_K, 0, 0, deny),\n        _SockFilter(_BPF_RET_K, 0, 0, allow),\n    ])\n    array_type = _SockFilter * len(instructions)\n    array = array_type(*instructions)\n    program = _SockFprog(len(instructions), array)\n    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:\n        raise OSError(ctypes.get_errno(), "prctl_no_new_privs_seccomp")\n    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:\n        raise OSError(ctypes.get_errno(), "prctl_seccomp_network_filter")\n\n\ndef probe_isolation_preexec(\n    read_exec_paths: tuple[Path, ...],\n    read_paths: tuple[Path, ...],\n    writable_paths: tuple[Path, ...],\n):\n    read_exec = tuple(Path(path).resolve(strict=True) for path in read_exec_paths if Path(path).exists())\n    readable = tuple(Path(path).resolve(strict=True) for path in read_paths if Path(path).exists())\n    writable = tuple(Path(path).resolve(strict=True) for path in writable_paths if Path(path).exists())\n    harness_pid = os.getpid()\n    harness_pgid = os.getpgrp()\n\n    def _apply() -> None:\n        apply_landlock_policy(read_exec, readable, writable, allow_self_proc=True)\n        apply_network_seccomp_policy(harness_pid, harness_pgid)\n\n    return _apply\n'''
    text = replace_once(text, old_seccomp, new_seccomp, "seccomp addressable IPC and signals")
    old_copy = '''def _copy_regular_file(source: Path, destination: Path, expected_sha256: str | None = None) -> None:\n    if source.is_symlink() or not source.is_file():\n        fail("moriarty_copy_source_nonregular")\n    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)\n    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | (getattr(os, "O_NOFOLLOW", 0)))\n    source_hash = hashlib.sha256()\n    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)\n    output_fd = os.open(destination, flags, 0o600)\n    try:\n        while True:\n            chunk = os.read(source_fd, 65536)\n            if not chunk:\n                break\n            source_hash.update(chunk)\n            view = memoryview(chunk)\n            while view:\n                written = os.write(output_fd, view)\n                view = view[written:]\n        os.fsync(output_fd)\n    finally:\n        os.close(output_fd)\n        os.close(source_fd)\n    digest = source_hash.hexdigest()\n    if expected_sha256 is not None and digest != expected_sha256:\n        fail(f"moriarty_cargo_archive_checksum_mismatch:{source.name}")\n    if _sha256_regular_file(destination) != digest:\n        fail("moriarty_copy_digest_mismatch")\n\n\ndef _copy_regular_tree(source: Path, destination: Path) -> None:\n    if not source.exists():\n        return\n    destination.mkdir(mode=0o700, parents=True, exist_ok=True)\n    for current, dirs, files in os.walk(source, followlinks=False):\n        current_path = Path(current)\n        relative = current_path.relative_to(source)\n        output_dir = destination / relative\n        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)\n        for directory in list(dirs):\n            if (current_path / directory).is_symlink():\n                fail("moriarty_cargo_cache_symlink_forbidden")\n        for name in files:\n            source_file = current_path / name\n            if source_file.is_symlink() or not source_file.is_file():\n                fail("moriarty_cargo_cache_nonregular_file")\n            _copy_regular_file(source_file, output_dir / name)\n'''
    new_copy = '''def _copy_regular_file(\n    source: Path,\n    destination: Path,\n    expected_sha256: str | None = None,\n    *,\n    max_bytes: int | None = None,\n    too_large_error: str = "moriarty_copy_source_too_large",\n) -> None:\n    if source.is_symlink() or not source.is_file():\n        fail("moriarty_copy_source_nonregular")\n    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)\n    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | (getattr(os, "O_NOFOLLOW", 0)))\n    source_hash = hashlib.sha256()\n    total = 0\n    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)\n    output_fd = os.open(destination, flags, 0o600)\n    try:\n        while True:\n            chunk = os.read(source_fd, 65536)\n            if not chunk:\n                break\n            total += len(chunk)\n            if max_bytes is not None and total > max_bytes:\n                fail(too_large_error)\n            source_hash.update(chunk)\n            view = memoryview(chunk)\n            while view:\n                written = os.write(output_fd, view)\n                view = view[written:]\n        os.fsync(output_fd)\n    finally:\n        os.close(output_fd)\n        os.close(source_fd)\n    digest = source_hash.hexdigest()\n    if expected_sha256 is not None and digest != expected_sha256:\n        fail(f"moriarty_cargo_archive_checksum_mismatch:{source.name}")\n    if _sha256_regular_file(destination) != digest:\n        fail("moriarty_copy_digest_mismatch")\n\n\ndef _copy_regular_tree(\n    source: Path,\n    destination: Path,\n    *,\n    max_entries: int | None = None,\n    max_bytes: int | None = None,\n    max_depth: int | None = None,\n    bound_prefix: str = "moriarty_copy_tree",\n) -> None:\n    if not source.exists():\n        return\n    destination.mkdir(mode=0o700, parents=True, exist_ok=True)\n    entry_count = 0\n    total_bytes = 0\n    for current, dirs, files in os.walk(source, followlinks=False):\n        current_path = Path(current)\n        relative = current_path.relative_to(source)\n        depth = len(relative.parts)\n        if max_depth is not None and depth > max_depth:\n            fail(f"{bound_prefix}_depth_exceeded")\n        output_dir = destination / relative\n        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)\n        entry_count += len(dirs) + len(files)\n        if max_entries is not None and entry_count > max_entries:\n            fail(f"{bound_prefix}_entries_exceeded")\n        for directory in list(dirs):\n            if (current_path / directory).is_symlink():\n                fail("moriarty_cargo_cache_symlink_forbidden")\n        for name in files:\n            source_file = current_path / name\n            if source_file.is_symlink() or not source_file.is_file():\n                fail("moriarty_cargo_cache_nonregular_file")\n            remaining = None if max_bytes is None else max_bytes - total_bytes\n            if remaining is not None and remaining < 0:\n                fail(f"{bound_prefix}_bytes_exceeded")\n            output_file = output_dir / name\n            _copy_regular_file(\n                source_file,\n                output_file,\n                max_bytes=remaining,\n                too_large_error=f"{bound_prefix}_bytes_exceeded",\n            )\n            total_bytes += output_file.stat().st_size\n            if max_bytes is not None and total_bytes > max_bytes:\n                fail(f"{bound_prefix}_bytes_exceeded")\n'''
    text = replace_once(text, old_copy, new_copy, "bounded copy tree")
    text = replace_once(
        text,
        '    _copy_regular_tree(index_source, template / "registry" / "index")',
        '    _copy_regular_tree(\n        index_source,\n        template / "registry" / "index",\n        max_entries=MAX_CARGO_INDEX_ENTRIES,\n        max_bytes=MAX_CARGO_INDEX_BYTES,\n        max_depth=MAX_CARGO_INDEX_DEPTH,\n        bound_prefix="moriarty_cargo_index",\n    )',
        "bounded cargo index projection",
    )
    return text


def transform_validator(text: str) -> str:
    text = replace_once(
        text,
        "import hashlib\nimport json\n",
        "import hashlib\nimport importlib.machinery\nimport importlib.util\nimport json\n",
        "validator importlib imports",
    )
    old_bootstrap = '''ROOT = Path(__file__).resolve().parents[1]\nTOOLS = ROOT / "tools"\nif str(TOOLS) not in sys.path:\n    sys.path.insert(0, str(TOOLS))\n\nfrom qsol_canonical import canonicalize, serialize  # noqa: E402\nimport run_moriarty as moriarty  # noqa: E402\n'''
    new_bootstrap = BOOTSTRAP_HELPERS + '''\n_BOOTSTRAP_TARGET = _bootstrap_target()\n_qsol_canonical = _load_verified_source_module("qsol_canonical", _BOOTSTRAP_TARGET)\nmoriarty = _load_verified_source_module("run_moriarty", _BOOTSTRAP_TARGET)\nserialize = _qsol_canonical.serialize\n'''
    text = replace_once(text, old_bootstrap, new_bootstrap, "validator verified bootstrap")
    text = replace_once(
        text,
        '''    normalized_paths = moriarty._normalize_probe_output(\n        b"/tmp/private-run/probe-12-rust_all-src /tmp/private-run/target-12-rust_all /tmp/private-run/home-12-rust_all /tmp/private-run/cargo-home-probe-12-rust_all /tmp/private-run/tmp-target-12-rust_all /tmp/private-run/other",\n        source_root=norm_root / "probe-12-rust_all-src",\n''',
        '''    normalized_paths = moriarty._normalize_probe_output(\n        b"/tmp/private-run/probe-12-rust_all-src /tmp/private-run/target-12-rust_all /tmp/private-run/home-12-rust_all /tmp/private-run/cargo-home-probe-12-rust_all /tmp/private-run/tmp-target-12-rust_all /tmp/private-run/other",\n        probe_id="rust_all",\n        source_root=norm_root / "probe-12-rust_all-src",\n''',
        "validator path normalization id",
    )
    normalization_test_marker = '''    require(\n        normalized_paths == b"<SOURCE> <TARGET> <HOME> <CARGO_HOME> <TMP> <WORK>/other",\n        "MORIARTY complete per-probe output normalization regression failed",\n    )\n'''
    normalization_test_new = normalization_test_marker + '''    rust_a = moriarty._normalize_probe_output(\n        b"Finished `test` profile [unoptimized + debuginfo] target(s) in 0.63s\\ntest result: FAILED. 1 failed; finished in 0.02s\\nthread 'main' (pid=12345)",\n        probe_id="rust_all", source_root=norm_root / "src", target_dir=norm_root / "target",\n        home=norm_root / "home", cargo_home=norm_root / "cargo", temp_dir=norm_root / "tmp", workspace_root=norm_root,\n    )\n    rust_b = moriarty._normalize_probe_output(\n        b"Finished `test` profile [unoptimized + debuginfo] target(s) in 1.18s\\ntest result: FAILED. 1 failed; finished in 0.91s\\nthread 'main' (pid=54321)",\n        probe_id="rust_all", source_root=norm_root / "src", target_dir=norm_root / "target",\n        home=norm_root / "home", cargo_home=norm_root / "cargo", temp_dir=norm_root / "tmp", workspace_root=norm_root,\n    )\n    require(rust_a == rust_b, "MORIARTY Rust runtime-field normalization regression failed")\n'''
    text = replace_once(text, normalization_test_marker, normalization_test_new, "rust nondeterminism regression")
    corpus_marker = '''    attack_extra = copy.deepcopy(corpus)\n    attack_extra["attacks"][0]["credential"] = "forbidden"\n    _expect_reject(lambda: moriarty.validate_attack_corpus(attack_extra), "undeclared attack-record field")\n'''
    corpus_new = corpus_marker + '''    bad_owner = copy.deepcopy(corpus)\n    bad_owner["attacks"][0]["owner_phases"] = ["https://evil.example"]\n    _expect_reject(lambda: moriarty.validate_attack_corpus(bad_owner), "owner phase outside closed enum")\n    owner_schema = corpus_schema["properties"]["attacks"]["items"]["properties"]["owner_phases"]\n    require(set(owner_schema["items"].get("enum", [])) == moriarty.ALLOWED_OWNER_PHASES, "MORIARTY owner phase schema/runner enum drift")\n    require(owner_schema.get("maxItems") == moriarty.MAX_OWNER_PHASES, "MORIARTY owner phase count schema drift")\n'''
    text = replace_once(text, corpus_marker, corpus_new, "owner phase negative regression")
    text = replace_once(text, '        "owner_phases": ["phase0"],', '        "owner_phases": ["0"],', "bad exit allowed owner phase")
    runner_markers = '''        "security_proof", "no_counterexample_found_implies_none_exist", "stdout_truncated", "stderr_truncated",\n'''
    runner_markers_new = '''        "security_proof", "no_counterexample_found_implies_none_exist", "stdout_truncated", "stderr_truncated",\n        "_bootstrap_verified_blob", "SourceFileLoader", "ALLOWED_OWNER_PHASES", "_RUNTIME_NORMALIZATIONS", "close_fds=True",\n'''
    text = replace_once(text, runner_markers, runner_markers_new, "runner hardening markers")
    docs_marker = '''    for marker in (\n        "MORIARTY/1", "PROVIDER NEUTRAL", "EXACT COMMIT", "COUNTEREXAMPLE != AUTHORITY",\n'''
    docs_new = '''    threat = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")\n    for marker in (\n        "## Residual risks", "anonymous `AF_UNIX` `socketpair()`",\n        "RESIDUAL RISK ACKNOWLEDGED != RESIDUAL RISK ACCEPTED AS AUTHORITY",\n        "BOUNDED EXPOSURE != ZERO EXPOSURE",\n    ):\n        require(marker in threat, f"THREAT_MODEL.md residual-risk marker missing: {marker}")\n\n    for marker in (\n        "MORIARTY/1", "PROVIDER NEUTRAL", "EXACT COMMIT", "COUNTEREXAMPLE != AUTHORITY",\n'''
    text = replace_once(text, docs_marker, docs_new, "threat model markers")
    bootstrap_source_marker = '''def validate_runner_source() -> None:\n    source = (ROOT / "tools/run_moriarty.py").read_text(encoding="utf-8")\n'''
    bootstrap_source_new = '''def validate_runner_source() -> None:\n    source = (ROOT / "tools/run_moriarty.py").read_text(encoding="utf-8")\n    validator_bootstrap = "\\n".join((ROOT / "tools/validate_phase9_gate.py").read_text(encoding="utf-8").splitlines()[:180])\n    require("sys.path.insert" not in validator_bootstrap, "Phase 9 validator bootstrap reintroduced checkout import search")\n    require("_bootstrap_verified_blob" in validator_bootstrap and "SourceFileLoader" in validator_bootstrap, "Phase 9 validator bootstrap is not target-byte verified")\n'''
    text = replace_once(text, bootstrap_source_marker, bootstrap_source_new, "validator bootstrap self-check")
    old_kernel = '''try:\n    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nexcept OSError as exc:\n    if exc.errno != errno.EPERM:\n        raise\nelse:\n    raise SystemExit(4)\nimport ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\nlibc.syscall.restype = ctypes.c_long\nresult = libc.syscall(425, 1, ctypes.c_void_p(0))\nif result != -1 or ctypes.get_errno() != errno.EPERM:\n    raise SystemExit(5)\nraise SystemExit(0)\n'''
    new_kernel = '''try:\n    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nexcept OSError as exc:\n    if exc.errno != errno.EPERM:\n        raise\nelse:\n    raise SystemExit(4)\ntry:\n    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\nexcept OSError as exc:\n    if exc.errno != errno.EPERM:\n        raise\nelse:\n    raise SystemExit(5)\nleft, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)\ntry:\n    try:\n        left.connect("/tmp/moriarty-forbidden.sock")\n    except OSError as exc:\n        if exc.errno != errno.EPERM:\n            raise\n    else:\n        raise SystemExit(6)\nfinally:\n    left.close(); right.close()\ntry:\n    import os, signal\n    os.kill(int(parent_pid), signal.SIGCONT)\nexcept OSError as exc:\n    if exc.errno != errno.EPERM:\n        raise\nelse:\n    raise SystemExit(7)\nimport ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\nlibc.syscall.restype = ctypes.c_long\nresult = libc.syscall(425, 1, ctypes.c_void_p(0))\nif result != -1 or ctypes.get_errno() != errno.EPERM:\n    raise SystemExit(8)\nraise SystemExit(0)\n'''
    text = replace_once(text, old_kernel, new_kernel, "network signal kernel regression")
    canonical_old = '''    raw = report_path.read_bytes()\n    require(len(raw) <= moriarty.MAX_REPORT_BYTES, "MORIARTY report exceeds canonical byte bound")\n    require(canonicalize(raw.decode("utf-8")) == raw, "MORIARTY report is not exact canonical JSON")\n    report = json.loads(raw)\n'''
    canonical_new = '''    raw = report_path.read_bytes()\n    require(len(raw) <= moriarty.MAX_REPORT_BYTES, "MORIARTY report exceeds canonical byte bound")\n    try:\n        decoded = raw.decode("utf-8", errors="strict")\n        report = json.loads(decoded)\n        canonical = serialize(report).encode("utf-8")\n    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:\n        raise SystemExit(f"MORIARTY report canonical parse failed: {exc}")\n    require(canonical == raw, "MORIARTY report is not exact canonical JSON")\n'''
    text = replace_once(text, canonical_old, canonical_new, "large report canonical validation")
    isolation_marker = '''        workspace_bad = root / "workspace-bad"\n        workspace_bad.mkdir()\n'''
    isolation_new = '''        oversized_index = ambient / "registry" / "index" / "oversized"\n        oversized_index.write_bytes(b"")\n        oversized_index.truncate(moriarty._moriarty_isolation.MAX_CARGO_INDEX_BYTES + 1)\n        workspace_index = root / "workspace-index"\n        workspace_index.mkdir()\n        _expect_reject(\n            lambda: moriarty.create_verified_cargo_template(ambient, workspace_index, lock),\n            "oversized Cargo registry index projection",\n        )\n        oversized_index.unlink()\n        workspace_bad = root / "workspace-bad"\n        workspace_bad.mkdir()\n'''
    text = replace_once(text, isolation_marker, isolation_new, "cargo index bound regression")
    capacity_marker = '''    require(report_props["authority_effect"].get("const") == "none", "MORIARTY report schema gained authority")\n\n    corpus = load("fixtures/phase9/attack-corpus.json")\n'''
    capacity_new = '''    require(report_props["authority_effect"].get("const") == "none", "MORIARTY report schema gained authority")\n    require(moriarty.MAX_REPORT_BYTES == 512 * 1024, "MORIARTY report byte ceiling drift")\n    max_boundary_ids = [f"b{index:02d}" + "x" * 125 for index in range(moriarty.MAX_BOUNDARY_IDS)]\n    max_counterexample = {\n        "schema": moriarty.COUNTEREXAMPLE_SCHEMA, "counterexample_id": "sha256:" + "f" * 64,\n        "target_commit": "f" * 40, "attack_id": "MOR-999", "family": max(moriarty.EXPECTED_FAMILIES, key=len),\n        "owner_phases": list(sorted(moriarty.ALLOWED_OWNER_PHASES)), "boundary_ids": max_boundary_ids,\n        "regression_probe_ids": ["p" * 64], "failure_kind": "exit_nonzero", "observed_exit_code": -2147483648,\n        "stdout_sha256": "sha256:" + "f" * 64, "stderr_sha256": "sha256:" + "f" * 64,\n        "stdout_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES, "stderr_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES,\n        "status": "resolved", "resolution_commit": "e" * 40, "production_credentials_used": False,\n        "production_targets_used": False, "constitutional_bypass_used": False, "authority_effect": "none",\n    }\n    max_result = {\n        "probe_id": "p" * 64, "ok": False, "exit_code": -2147483648, "failure_kind": "exit_nonzero",\n        "stdout_sha256": "sha256:" + "f" * 64, "stderr_sha256": "sha256:" + "f" * 64,\n        "stdout_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES, "stderr_bytes": moriarty.MAX_PROBE_OUTPUT_BYTES,\n        "stdout_truncated": True, "stderr_truncated": True,\n    }\n    max_replay = {\n        "counterexample_id": "sha256:" + "f" * 64, "status": "resolved", "probe_id": "p" * 64,\n        "ok": False, "target_reproduced": False, "resolution_green": False,\n        "failure_kind": "target_failure_not_reproduced", "failure_result": max_result,\n    }\n    max_report = {\n        "schema": moriarty.REPORT_SCHEMA, "protocol": moriarty.PROTOCOL, "target_commit": "f" * 40,\n        "corpus_ref": "sha256:" + "f" * 64, "operator_profile": moriarty.OPERATOR_PROFILE,\n        "family_count": 15, "executed_probe_count": len(EXPECTED_PROBES),\n        "probe_results": [max_result] * len(EXPECTED_PROBES),\n        "remediation_replays": [max_replay] * moriarty.MAX_ACCEPTED_COUNTEREXAMPLES,\n        "counterexamples": [max_counterexample] * moriarty.MAX_REPORT_COUNTEREXAMPLES,\n        "unresolved_counterexamples": moriarty.MAX_REPORT_COUNTEREXAMPLES, "graduated": False,\n        "production_credentials_used": False, "production_targets_used": False,\n        "constitutional_bypass_used": False, "security_proof": False,\n        "no_counterexample_found_implies_none_exist": False, "authority_effect": "none",\n    }\n    require(len(serialize(max_report).encode("utf-8")) <= moriarty.MAX_REPORT_BYTES, "MORIARTY schema-admitted worst-case report exceeds byte ceiling")\n\n    corpus = load("fixtures/phase9/attack-corpus.json")\n'''
    text = replace_once(text, capacity_marker, capacity_new, "report capacity regression")
    return text


def transform_state(text: str) -> str:
    text = replace_once(text, '"maximum_canonical_bytes": 65536', '"maximum_canonical_bytes": 524288', "state report bytes")
    old = 'and seccomp denies socket/network syscalls for the probe and descendants.'
    new = 'and seccomp denies addressable socket creation/connections, io_uring networking, harness-directed signaling, and process-memory access while permitting only anonymous AF_UNIX socketpair IPC.'
    text = replace_once(text, old, new, "state seccomp description")
    return text


def transform_moriarty_doc(text: str) -> str:
    text = replace_once(
        text,
        'The accepted registry is capped at 32 records. Combined accepted and generated counterexamples are capped at 48 per report, and the entire canonical report is capped at 65,536 bytes. The declared registry state therefore cannot silently grow beyond the canonical report profile it is supposed to graduate under.',
        'The accepted registry is capped at 32 records. Combined accepted and generated counterexamples are capped at 48 per report, and the entire canonical report is capped at 524,288 bytes. The Phase 9 validator constructs a schema-maximal synthetic evidence projection and requires it to remain within this ceiling, so every admitted registry/report state remains publishable as bounded failure evidence.',
        "MORIARTY report capacity docs",
    )
    old = 'Runtime hardening notes: probe stdin is always harness-owned `/dev/null`; reproducibility digests normalize only the private per-run MORIARTY workspace prefix; Git commit/tree/blob bytes are rehashed before export; repository-local fsmonitor/hooks are neutralized; non-system Python and non-self-contained direct Rust installations fail closed rather than importing mutable runtime trees. Cargo package archives are hashed through bounded streaming descriptors before admission.'
    new = 'Runtime hardening notes: Phase 9 bootstrap modules are loaded only from source files whose bytes match hash-verified target Git blobs; probe stdin is harness-owned `/dev/null` and inherited descriptors are closed; reproducibility digests normalize per-probe source/target/HOME/Cargo/TMP paths plus a closed set of Rust timing/PID fields; Git commit/tree/blob bytes are rehashed before export; repository-local fsmonitor/hooks are neutralized; non-system Python and non-self-contained direct Rust installations fail closed rather than importing mutable runtime trees. Cargo package archives are hashed through bounded streaming descriptors and Cargo index projection has independent entry/byte/depth ceilings. Probe seccomp permits only anonymous `AF_UNIX` `socketpair()` IPC, denies addressable `socket()`/`connect()`, io_uring networking, harness-directed signals, pidfd signaling, ptrace, and process-memory syscalls.'
    text = replace_once(text, old, new, "MORIARTY hardening notes")
    return text


def transform_threat(text: str) -> str:
    marker = '''## Security invariant\n'''
    section = '''## Residual risks\n\nPhase 9 hardens the adversarial harness but does not eliminate every risk. The following residual risks are acknowledged, bounded, and intentionally not overclaimed as solved.\n\n| ID | Residual risk | Why it remains | Bounding control |\n|----|---------------|----------------|------------------|\n| R1 | Kernel isolation is Linux-specific | Landlock ABI >= 3 and the seccomp policy are implemented only for Linux x86_64/aarch64 | The runner fails closed on any other platform rather than degrading to weaker isolation |\n| R2 | Anonymous local IPC remains permitted | Some runtimes require connected local IPC | Addressable `socket()` and `connect()` are denied; only anonymous `AF_UNIX` `socketpair()` is admitted, so pathname and abstract-namespace services such as Docker/systemd/X11 cannot be named |\n| R3 | Process-tree termination has a scan race | `/proc` descendant discovery is a sample rather than an atomic kernel primitive | Child-subreaper adoption, process-group SIGKILL, repeated rescans, harness-directed signal denial, and a hard two-second pipe-drain deadline bound the escape window |\n| R4 | Git object identity uses SHA-1 | The repository's current Git object format is SHA-1 | Commit/tree/blob bytes are rehashed against their object IDs and replacement objects are disabled; this is exact repository identity, not a general SHA-1 security claim |\n| R5 | Probe output is stored by digest and byte count only | Raw adversary-controlled output is intentionally excluded from reports | Readers must rerun the fixed probe locally to inspect semantics; report artifacts cannot silently launder raw output into authority |\n| R6 | Truncated streams lose tail bytes | Streams are capped at 1,048,576 bytes per probe | Truncation is persisted as explicit `tool_error` metadata with per-stream flags, so capped output cannot masquerade as complete output |\n| R7 | The attack corpus is closed and finite | Fifteen source-owned families cannot enumerate all possible attacks | `no_counterexample_found_implies_none_exist = false` is machine-enforced; external observations remain candidates until reviewed local reproduction |\n| R8 | Shared-probe failures can be ambiguous | Several fixed probes cover multiple attack families | Ambiguous failures block graduation as failed-probe evidence without fabricating family-specific counterexamples |\n| R9 | Host toolchains are trusted at pin time | Python, Git, Cargo, and rustc originate from the host | Bootstrap source bytes are target-verified; executable inode/size/mtime pinning, descriptor-bound execution, staged read-only Rust runtime snapshots, and directory-chain checks bound substitution rather than claiming immunity to an already-compromised host |\n| R10 | The harness runs as the invoking user | Phase 9 does not claim a VM, container, or host-level sandbox (`host_level_sandbox = false`) | Landlock read/exec/write allowlists, self-only `/proc`, addressable-IPC denial, harness-signal denial, and ptrace/process-memory denial bound same-UID reach; kernel privilege escalation remains out of scope |\n| R11 | CI infrastructure is trusted | GitHub-hosted runners, checkout actions, and artifact storage sit outside the MORIARTY kernel boundary | Exact PR-head/push SHA binding, `persist-credentials: false`, hash-verified source bootstrap, and locally rerunnable gates limit what CI compromise can silently forge |\n| R12 | Cargo.lock currency is a maintenance risk | Frozen offline resolution pins dependencies but does not track upstream advisories | Dependency updates are ordinary reviewed commits that must repass every gate; MORIARTY greenness never implies dependency freshness |\n\nNone of these residual risks weakens the report semantics: a green MORIARTY report remains evidence about the exact reviewed regression surface only.\n\n```text\nRESIDUAL RISK ACKNOWLEDGED != RESIDUAL RISK ACCEPTED AS AUTHORITY\nBOUNDED EXPOSURE != ZERO EXPOSURE\n```\n\n'''
    return replace_once(text, marker, section + marker, "THREAT_MODEL residual risks")


update("tools/run_moriarty.py", transform_runner)
update("tools/moriarty_isolation.py", transform_isolation)
update("tools/validate_phase9_gate.py", transform_validator)
update("state/phase9.json", transform_state)
update("MORIARTY.md", transform_moriarty_doc)
update("THREAT_MODEL.md", transform_threat)
