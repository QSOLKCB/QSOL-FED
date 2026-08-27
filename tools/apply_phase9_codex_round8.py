#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one marker, found {count}")
    return text.replace(old, new, 1)


def patch_bootstrap(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "import importlib.machinery\nimport importlib.util\n",
        "import builtins\nimport types\n",
        f"{path}: bootstrap imports",
    )
    old = '''def _load_verified_source_module(name: str, target: str):
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
    new = '''def _load_verified_source_module(name: str, target: str):
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
'''
    text = replace_once(text, old, new, f"{path}: verified module loader")
    path.write_text(text, encoding="utf-8")


run_path = Path("tools/run_moriarty.py")
iso_path = Path("tools/moriarty_isolation.py")
val_path = Path("tools/validate_phase9_gate.py")

patch_bootstrap(run_path)
patch_bootstrap(val_path)

run = run_path.read_text(encoding="utf-8")
run = replace_once(
    run,
    '''def _system_read_paths() -> tuple[Path, ...]:
    return tuple(path for path in (Path("/etc"), Path("/dev/urandom"), Path("/dev/random")) if path.exists())
''',
    '''def _system_read_paths() -> tuple[Path, ...]:
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
''',
    "run: system read allowlist",
)
run = replace_once(
    run,
    '''    if git_head() != target or not tracked_tree_clean() or not harness_files_match_target(target):
        fail("moriarty_target_or_harness_changed_during_report_publication")

    if report["graduated"]:
''',
    '''    if git_head() != target or not tracked_tree_clean() or not harness_files_match_target(target):
        fail("moriarty_target_or_harness_changed_during_report_publication")

    # Authenticate the exact report bytes across the runner/validator process boundary.
    print(f"MORIARTY_REPORT_SHA256={hashlib.sha256(encoded).hexdigest()}")

    if report["graduated"]:
''',
    "run: report byte attestation",
)
run_path.write_text(run, encoding="utf-8")

iso = iso_path.read_text(encoding="utf-8")
iso = replace_once(iso, "import os\nimport stat\n", "import os\nimport re\nimport stat\n", "isolation: re import")
iso = replace_once(
    iso,
    '''def _signal_syscalls() -> tuple[int, int, int, int]:
    machine = os.uname().machine
    if machine == "x86_64":
        return (62, 200, 234, 424)
    if machine == "aarch64":
        return (129, 130, 131, 424)
    fail("moriarty_signal_seccomp_arch_unsupported")
''',
    '''def _signal_syscalls() -> tuple[int, int, int, int, int, int]:
    machine = os.uname().machine
    if machine == "x86_64":
        # kill, tkill, tgkill, pidfd_send_signal, rt_sigqueueinfo, rt_tgsigqueueinfo
        return (62, 200, 234, 424, 129, 297)
    if machine == "aarch64":
        # asm-generic signal-delivery syscall numbers.
        return (129, 130, 131, 424, 138, 240)
    fail("moriarty_signal_seccomp_arch_unsupported")
''',
    "isolation: signal syscall set",
)
iso = replace_once(
    iso,
    '''    kill_nr, tkill_nr, tgkill_nr, pidfd_signal_nr = _signal_syscalls()
''',
    '''    kill_nr, tkill_nr, tgkill_nr, pidfd_signal_nr, rt_sigqueueinfo_nr, rt_tgsigqueueinfo_nr = _signal_syscalls()
''',
    "isolation: signal unpack",
)
iso = replace_once(
    iso,
    '''    for number in (kill_nr, tkill_nr, tgkill_nr):
''',
    '''    for number in (kill_nr, tkill_nr, tgkill_nr, rt_sigqueueinfo_nr, rt_tgsigqueueinfo_nr):
''',
    "isolation: queued signal filtering",
)
iso = replace_once(
    iso,
    '''MAX_CARGO_INDEX_DEPTH = 16
''',
    '''MAX_CARGO_INDEX_DEPTH = 16
_CARGO_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_CARGO_PACKAGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
''',
    "isolation: cargo component regexes",
)
iso = replace_once(
    iso,
    '''            or len(checksum) != 64
            or any(ch not in "0123456789abcdef" for ch in checksum)
        ):
''',
    '''            or _CARGO_PACKAGE_NAME_RE.fullmatch(name) is None
            or _CARGO_PACKAGE_VERSION_RE.fullmatch(version) is None
            or len(checksum) != 64
            or any(ch not in "0123456789abcdef" for ch in checksum)
        ):
''',
    "isolation: cargo lock component validation",
)
iso = replace_once(
    iso,
    '''    cache_root = real_cargo_home / "registry" / "cache"
    for name, version, checksum in _locked_registry_packages(cargo_lock):
        filename = f"{name}-{version}.crate"
        candidates = sorted(cache_root.glob(f"*/{filename}")) if cache_root.exists() else []
''',
    '''    cache_root = real_cargo_home / "registry" / "cache"
    cache_root_resolved = cache_root.resolve(strict=True) if cache_root.exists() else None
    template_resolved = template.resolve(strict=True)
    for name, version, checksum in _locked_registry_packages(cargo_lock):
        filename = f"{name}-{version}.crate"
        if Path(filename).name != filename or "/" in filename or "\\\\" in filename:
            fail("moriarty_cargo_lock_registry_package_path_invalid")
        candidates = sorted(cache_root.glob(f"*/{filename}")) if cache_root.exists() else []
''',
    "isolation: cargo cache root binding",
)
iso = replace_once(
    iso,
    '''        for candidate in candidates:
            if candidate.is_file() and not candidate.is_symlink():
                digest = _sha256_regular_file(
''',
    '''        for candidate in candidates:
            if candidate.is_file() and not candidate.is_symlink():
                resolved_candidate = candidate.resolve(strict=True)
                if cache_root_resolved is None or not resolved_candidate.is_relative_to(cache_root_resolved):
                    fail("moriarty_cargo_archive_escaped_cache_root")
                digest = _sha256_regular_file(
''',
    "isolation: cargo candidate containment",
)
iso = replace_once(
    iso,
    '''        selected = matching[0]
        cache_namespace = selected.parent.name
        _copy_regular_file(selected, template / "registry" / "cache" / cache_namespace / filename, checksum)
''',
    '''        selected = matching[0]
        cache_namespace = selected.parent.name
        destination = template / "registry" / "cache" / cache_namespace / filename
        if not destination.is_relative_to(template) or not destination.parent.is_relative_to(template):
            fail("moriarty_cargo_archive_destination_escape")
        _copy_regular_file(selected, destination, checksum)
        resolved_destination = destination.resolve(strict=True)
        if not resolved_destination.is_relative_to(template_resolved):
            fail("moriarty_cargo_archive_destination_escape")
''',
    "isolation: cargo destination containment",
)
iso_path.write_text(iso, encoding="utf-8")

val = val_path.read_text(encoding="utf-8")
val = replace_once(val, "import re\nimport subprocess\n", "import re\nimport stat\nimport subprocess\n", "validator: stat import")
val = replace_once(
    val,
    '''    require("_bootstrap_verified_blob" in validator_bootstrap and "SourceFileLoader" in validator_bootstrap, "Phase 9 validator bootstrap is not target-byte verified")
''',
    '''    require("_bootstrap_verified_blob" in validator_bootstrap and "compile(expected" in validator_bootstrap and "SourceFileLoader" not in validator_bootstrap, "Phase 9 validator bootstrap does not execute verified target bytes directly")
''',
    "validator: bootstrap marker",
)
val = replace_once(val, '"_bootstrap_verified_blob", "SourceFileLoader", "ALLOWED_OWNER_PHASES"', '"_bootstrap_verified_blob", "compile(expected", "ALLOWED_OWNER_PHASES"', "validator: runner marker")
val = replace_once(
    val,
    '''            if item[f"{stream}_truncated"]:
                require(item[f"{stream}_bytes"] == moriarty.MAX_PROBE_OUTPUT_BYTES, f"truncated {stream} did not stop at byte bound")
                require(failure_kind == "tool_error", f"truncated {stream} must be a tool_error")
''',
    '''            if item[f"{stream}_truncated"]:
                # Digests/counts are over normalized bounded evidence, which can be
                # shorter than the raw 1 MiB prefix after path/timing/PID replacement.
                require(0 < item[f"{stream}_bytes"] <= moriarty.MAX_PROBE_OUTPUT_BYTES, f"truncated {stream} normalized byte count invalid")
                require(failure_kind == "tool_error", f"truncated {stream} must be a tool_error")
''',
    "validator: normalized truncated count",
)
val = replace_once(
    val,
    '''        preexec = moriarty.probe_isolation_preexec(
            tuple(path for path in (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64")) if path.exists()),
            tuple(path for path in (Path("/etc"), Path("/dev/urandom"), Path("/dev/random")) if path.exists()),
            tuple(path for path in (writable, Path("/dev/null")) if path.exists()),
        )
''',
    '''        preexec = moriarty.probe_isolation_preexec(
            tuple(path for path in (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64")) if path.exists()),
            moriarty._system_read_paths(),
            tuple(path for path in (writable, Path("/dev/null")) if path.exists()),
        )
''',
    "validator: kernel read allowlist",
)
val = replace_once(
    val,
    '''try:
    import os, signal
    os.kill(int(parent_pid), signal.SIGCONT)
except OSError as exc:
    if exc.errno != errno.EPERM:
        raise
else:
    raise SystemExit(7)
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
result = libc.syscall(425, 1, ctypes.c_void_p(0))
if result != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit(8)
raise SystemExit(0)
''',
    '''try:
    import os, signal
    os.kill(int(parent_pid), signal.SIGCONT)
except OSError as exc:
    if exc.errno != errno.EPERM:
        raise
else:
    raise SystemExit(7)
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
machine = os.uname().machine
queue_nr, tgqueue_nr = ((129, 297) if machine == "x86_64" else (138, 240))
for number, args in (
    (queue_nr, (int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),
    (tgqueue_nr, (int(parent_pid), int(parent_pid), signal.SIGUSR1, ctypes.c_void_p(0))),
):
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        raise SystemExit(8)
forbidden_etc = Path("/etc/hostname")
if forbidden_etc.exists():
    try:
        forbidden_etc.read_bytes()
    except PermissionError:
        pass
    else:
        raise SystemExit(9)
ctypes.set_errno(0)
result = libc.syscall(425, 1, ctypes.c_void_p(0))
if result != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit(10)
raise SystemExit(0)
''',
    "validator: queued signal and etc regression",
)
val = replace_once(
    val,
    '''    require(0 < moriarty.MAX_GIT_PATH_BYTES <= 4096, "MORIARTY Git path bound invalid")

    bad_exit = {
''',
    '''    require(0 < moriarty.MAX_GIT_PATH_BYTES <= 4096, "MORIARTY Git path bound invalid")
    system_reads = moriarty._system_read_paths()
    require(Path("/etc") not in system_reads, "MORIARTY recursive /etc read access reintroduced")
    require(all(path.is_file() and not path.is_dir() for path in system_reads), "MORIARTY system read allowlist contains a directory")

    bad_exit = {
''',
    "validator: system read assertions",
)
val = replace_once(
    val,
    '''        workspace_index = root / "workspace-index"
        workspace_index.mkdir()
        _expect_reject(
            lambda: moriarty.create_verified_cargo_template(ambient, workspace_index, lock),
            "oversized Cargo registry index projection",
        )
''',
    '''        traversal_lock = root / "Cargo-traversal.lock"
        traversal_lock.write_text(
            'version = 4\\n\\n[[package]]\\nname = "../../payload"\\nversion = "1.0.0"\\nsource = "registry+https://github.com/rust-lang/crates.io-index"\\nchecksum = "' + good_sha + '"\\n',
            encoding="utf-8",
        )
        workspace_traversal = root / "workspace-traversal"
        workspace_traversal.mkdir()
        _expect_reject(
            lambda: moriarty.create_verified_cargo_template(ambient, workspace_traversal, traversal_lock),
            "Cargo.lock package path traversal",
        )
        workspace_index = root / "workspace-index"
        workspace_index.mkdir()
        _expect_reject(
            lambda: moriarty.create_verified_cargo_template(ambient, workspace_index, lock),
            "oversized Cargo registry index projection",
        )
''',
    "validator: cargo traversal regression",
)
helper = '''\n\ndef _runner_report_attestation(stdout: bytes) -> str:\n    prefix = b"MORIARTY_REPORT_SHA256="\n    values = [line[len(prefix):].decode("ascii", errors="strict") for line in stdout.splitlines() if line.startswith(prefix)]\n    require(len(values) == 1 and re.fullmatch(r"[0-9a-f]{64}", values[0]) is not None, "MORIARTY runner report attestation missing or invalid")\n    return values[0]\n\n\ndef _read_attested_report(path: Path, expected_sha256: str) -> bytes:\n    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)\n    try:\n        fd = os.open(path, flags)\n    except OSError as exc:\n        raise SystemExit(f"MORIARTY attested report open failed: {exc}")\n    try:\n        before = os.fstat(fd)\n        require(stat.S_ISREG(before.st_mode), "MORIARTY attested report is not a regular file")\n        require(before.st_uid == os.getuid(), "MORIARTY attested report owner drift")\n        require(before.st_nlink == 1, "MORIARTY attested report link-count drift")\n        require(0 <= before.st_size <= moriarty.MAX_REPORT_BYTES, "MORIARTY report exceeds canonical byte bound")\n        chunks: list[bytes] = []\n        total = 0\n        while True:\n            chunk = os.read(fd, min(65536, moriarty.MAX_REPORT_BYTES + 1 - total))\n            if not chunk:\n                break\n            chunks.append(chunk)\n            total += len(chunk)\n            require(total <= moriarty.MAX_REPORT_BYTES, "MORIARTY report exceeds canonical byte bound")\n        after = os.fstat(fd)\n        require(\n            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)\n            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),\n            "MORIARTY attested report changed during descriptor read",\n        )\n        raw = b"".join(chunks)\n        require(len(raw) == before.st_size, "MORIARTY attested report size drift")\n        require(hashlib.sha256(raw).hexdigest() == expected_sha256, "MORIARTY report bytes do not match runner attestation")\n        return raw\n    finally:\n        os.close(fd)\n'''
val = replace_once(val, "\n\ndef execute_exact_commit_gate(target: str, report_dir: Path | None) -> None:\n", helper + "\n\ndef execute_exact_commit_gate(target: str, report_dir: Path | None) -> None:\n", "validator: attested report helper")
val = replace_once(
    val,
    '''    if not report_path.exists():
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        diagnostic = stderr or stdout or "no runner output"
        raise SystemExit(
            "MORIARTY runner did not emit report: "
            + diagnostic[:2048]
        )
    raw = report_path.read_bytes()
    require(len(raw) <= moriarty.MAX_REPORT_BYTES, "MORIARTY report exceeds canonical byte bound")
''',
    '''    if not report_path.exists():
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        diagnostic = stderr or stdout or "no runner output"
        raise SystemExit(
            "MORIARTY runner did not emit report: "
            + diagnostic[:2048]
        )
    attested_sha256 = _runner_report_attestation(completed.stdout)
    raw = _read_attested_report(report_path, attested_sha256)
''',
    "validator: attested report read",
)
val_path.write_text(val, encoding="utf-8")
