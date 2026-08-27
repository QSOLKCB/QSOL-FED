#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def patch_isolation() -> None:
    path = ROOT / "tools/moriarty_isolation.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "\n_LANDLOCK_CREATE_RULESET = 444\n",
        "\nMAX_CARGO_ARCHIVE_BYTES = 64 * 1024 * 1024\n\n_LANDLOCK_CREATE_RULESET = 444\n",
        "cargo archive size constant",
    )
    marker = "\ndef _copy_regular_file(source: Path, destination: Path, expected_sha256: str | None = None) -> None:\n"
    helper = r'''
def _sha256_regular_file(
    path: Path,
    *,
    max_bytes: int | None = None,
    too_large_error: str = "moriarty_regular_file_too_large",
) -> str:
    """Hash a stable regular file through an fd without materializing it in memory."""
    try:
        initial = path.lstat()
    except OSError:
        fail("moriarty_regular_file_unavailable")
    if path.is_symlink() or not stat.S_ISREG(initial.st_mode):
        fail("moriarty_regular_file_required")
    if max_bytes is not None and initial.st_size > max_bytes:
        fail(too_large_error)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(fd)
        if (
            opened.st_dev != initial.st_dev
            or opened.st_ino != initial.st_ino
            or opened.st_size != initial.st_size
            or opened.st_mtime_ns != initial.st_mtime_ns
        ):
            fail("moriarty_regular_file_changed_before_hash")
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                fail(too_large_error)
            digest.update(chunk)
        final = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        final.st_dev != opened.st_dev
        or final.st_ino != opened.st_ino
        or final.st_size != opened.st_size
        or final.st_mtime_ns != opened.st_mtime_ns
        or total != opened.st_size
    ):
        fail("moriarty_regular_file_changed_during_hash")
    return digest.hexdigest()


def _copy_regular_file(source: Path, destination: Path, expected_sha256: str | None = None) -> None:
'''
    text = replace_once(text, marker, "\n" + helper, "streaming file hash helper")
    text = replace_once(
        text,
        '    if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:\n        fail("moriarty_copy_digest_mismatch")\n',
        '    if _sha256_regular_file(destination) != digest:\n        fail("moriarty_copy_digest_mismatch")\n',
        "copy destination streaming verification",
    )
    text = replace_once(
        text,
        '                digest = hashlib.sha256(candidate.read_bytes()).hexdigest()\n                if digest == checksum:\n',
        '                digest = _sha256_regular_file(\n                    candidate,\n                    max_bytes=MAX_CARGO_ARCHIVE_BYTES,\n                    too_large_error=f"moriarty_cargo_archive_too_large:{filename}",\n                )\n                if digest == checksum:\n',
        "cargo archive streaming hash",
    )
    text = replace_once(
        text,
        '    if hashlib.sha256(destination.read_bytes()).digest() != digest.digest():\n        fail("moriarty_staged_executable_digest_mismatch")\n',
        '    if bytes.fromhex(_sha256_regular_file(destination)) != digest.digest():\n        fail("moriarty_staged_executable_digest_mismatch")\n',
        "staged executable streaming verification",
    )
    text = replace_once(
        text,
        '    if hashlib.sha256(destination.read_bytes()).digest() != first_hash.digest():\n        fail("moriarty_toolchain_stage_digest_mismatch")\n',
        '    if bytes.fromhex(_sha256_regular_file(destination)) != first_hash.digest():\n        fail("moriarty_toolchain_stage_digest_mismatch")\n',
        "toolchain streaming verification",
    )
    path.write_text(text, encoding="utf-8")


def patch_runner() -> None:
    path = ROOT / "tools/run_moriarty.py"
    text = path.read_text(encoding="utf-8")

    direct_start = text.index("def _direct_toolchain_root(")
    direct_end = text.index("\n\nPYTHON_TRUSTED =", direct_start)
    direct_new = r'''def _direct_toolchain_root(cargo: TrustedExecutable, rustc: TrustedExecutable) -> Path:
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
'''
    text = text[:direct_start] + direct_new + text[direct_end:]

    text = replace_once(
        text,
        'PYTHON_TRUSTED = _trusted_executable("python3", preferred=Path(sys.executable))\n',
        '''_python_preferred = Path(sys.executable)\ntry:\n    _python_preferred_resolved = _python_preferred.resolve(strict=True)\nexcept OSError:\n    _python_preferred_resolved = Path("/")\nif Path("/usr") not in _python_preferred_resolved.parents:\n    _python_preferred = None\nPYTHON_TRUSTED = _trusted_executable("python3", preferred=_python_preferred)\nif Path("/usr") not in Path(PYTHON_TRUSTED.executable).resolve(strict=True).parents:\n    fail("moriarty_python_runtime_outside_system_prefix")\n''',
        "system Python runtime restriction",
    )

    old_git_env = '''def _git_env() -> dict[str, str]:\n    return {\n        "PATH": os.pathsep.join(sorted({str(Path(GIT_EXE).parent), "/usr/bin", "/bin"})),\n        "LANG": "C.UTF-8",\n        "LC_ALL": "C.UTF-8",\n        "GIT_CONFIG_NOSYSTEM": "1",\n        "GIT_CONFIG_GLOBAL": "/dev/null",\n        "GIT_ATTR_NOSYSTEM": "1",\n        "GIT_NO_REPLACE_OBJECTS": "1",\n    }\n'''
    new_git_env = '''def _git_env() -> dict[str, str]:\n    return {\n        "PATH": os.pathsep.join(sorted({str(Path(GIT_EXE).parent), "/usr/bin", "/bin"})),\n        "LANG": "C.UTF-8",\n        "LC_ALL": "C.UTF-8",\n        "GIT_CONFIG_NOSYSTEM": "1",\n        "GIT_CONFIG_GLOBAL": "/dev/null",\n        "GIT_ATTR_NOSYSTEM": "1",\n        "GIT_NO_REPLACE_OBJECTS": "1",\n        "GIT_OPTIONAL_LOCKS": "0",\n        "GIT_CONFIG_COUNT": "3",\n        "GIT_CONFIG_KEY_0": "core.fsmonitor",\n        "GIT_CONFIG_VALUE_0": "false",\n        "GIT_CONFIG_KEY_1": "core.hooksPath",\n        "GIT_CONFIG_VALUE_1": "/dev/null",\n        "GIT_CONFIG_KEY_2": "core.attributesFile",\n        "GIT_CONFIG_VALUE_2": "/dev/null",\n    }\n'''
    text = replace_once(text, old_git_env, new_git_env, "sanitized repository-local Git execution config")

    block_start = text.index("def _index_flags_output_clean(")
    block_end = text.index("\ndef _probe_environment(", block_start)
    verified_block = r'''_VERIFIED_TREE_CACHE: tuple[str, dict[str, tuple[str, str, bytes]]] | None = None


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

    def walk(tree_id: str, prefix: str) -> None:
        nonlocal total_payload
        tree_payload = _verified_git_object("tree", tree_id, MAX_GIT_ARCHIVE_BYTES)
        cursor = 0
        while cursor < len(tree_payload):
            space = tree_payload.find(b" ", cursor)
            nul = tree_payload.find(b"\0", space + 1 if space >= 0 else cursor)
            if space <= cursor or nul <= space or nul + 21 > len(tree_payload):
                fail("moriarty_git_tree_object_malformed")
            mode_bytes = tree_payload[cursor:space]
            name_bytes = tree_payload[space + 1:nul]
            object_id = tree_payload[nul + 1:nul + 21].hex()
            cursor = nul + 21
            try:
                mode = mode_bytes.decode("ascii", errors="strict")
                name = name_bytes.decode("utf-8", errors="strict")
            except UnicodeError:
                fail("moriarty_git_tree_entry_encoding_invalid")
            if not name or name in {".", ".."} or "/" in name or "\\" in name:
                fail("moriarty_git_tree_entry_name_invalid")
            relative = f"{prefix}/{name}" if prefix else name
            if relative in files:
                fail("moriarty_git_tree_duplicate_path")
            if mode == "40000":
                walk(object_id, relative)
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

    walk(root_tree, "")
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

'''
    text = text[:block_start] + verified_block + text[block_end:]

    text = replace_once(
        text,
        '        if not isinstance(item["observed_exit_code"], int) or isinstance(item["observed_exit_code"], bool) or item["observed_exit_code"] == 0:\n',
        '        if (\n            not isinstance(item["observed_exit_code"], int)\n            or isinstance(item["observed_exit_code"], bool)\n            or item["observed_exit_code"] == 0\n            or not -(2**31) <= item["observed_exit_code"] <= 2**31 - 1\n        ):\n',
        "counterexample exit code range",
    )

    normalize_marker = "\ndef _probe_failure_result(probe_id: str, kind: str, diagnostic: bytes) -> dict[str, Any]:\n"
    normalize_helper = r'''
def _normalize_probe_output(data: bytes, workspace_root: Path) -> bytes:
    """Remove the private per-run workspace prefix from reproducibility metadata."""
    root = os.fsencode(str(workspace_root.resolve()))
    if not root:
        fail("moriarty_workspace_normalization_root_invalid")
    return data.replace(root, b"<WORK>")


def _probe_failure_result(probe_id: str, kind: str, diagnostic: bytes) -> dict[str, Any]:
'''
    text = replace_once(text, normalize_marker, "\n" + normalize_helper, "output normalization helper")

    text = replace_once(
        text,
        '    truncated = {"stdout": False, "stderr": False}\n    stderr_sample = bytearray()\n',
        '    truncated = {"stdout": False, "stderr": False}\n    captured = {"stdout": bytearray(), "stderr": bytearray()}\n    stderr_sample = bytearray()\n',
        "bounded output capture buffers",
    )
    text = replace_once(
        text,
        '                counts[stream_name], overflow = bounded_output_update(\n                    digests[stream_name], counts[stream_name], chunk\n                )\n',
        '                remaining_capture = max(0, MAX_PROBE_OUTPUT_BYTES - len(captured[stream_name]))\n                if remaining_capture:\n                    captured[stream_name].extend(chunk[:remaining_capture])\n                counts[stream_name], overflow = bounded_output_update(\n                    digests[stream_name], counts[stream_name], chunk\n                )\n',
        "capture admitted output bytes",
    )
    text = replace_once(
        text,
        '            stdout=subprocess.PIPE,\n            stderr=subprocess.PIPE,\n            start_new_session=True,\n',
        '            stdin=subprocess.DEVNULL,\n            stdout=subprocess.PIPE,\n            stderr=subprocess.PIPE,\n            start_new_session=True,\n',
        "closed probe stdin",
    )
    old_result = '''    return {\n        "probe_id": probe_id,\n        "ok": ok,\n        "exit_code": return_code if failure_kind == "exit_nonzero" or ok else None,\n        "failure_kind": failure_kind,\n        "stdout_sha256": "sha256:" + digests["stdout"].hexdigest(),\n        "stderr_sha256": "sha256:" + digests["stderr"].hexdigest(),\n        "stdout_bytes": counts["stdout"],\n        "stderr_bytes": counts["stderr"],\n        "stdout_truncated": truncated["stdout"],\n        "stderr_truncated": truncated["stderr"],\n        "diagnostic_class": _classify_rust_failure(bytes(stderr_sample)) if probe_id == "rust_all" and not ok else None,\n    }\n'''
    new_result = '''    normalized = {\n        name: _normalize_probe_output(bytes(captured[name]), source_root.parent)\n        for name in ("stdout", "stderr")\n    }\n    return {\n        "probe_id": probe_id,\n        "ok": ok,\n        "exit_code": return_code if failure_kind == "exit_nonzero" or ok else None,\n        "failure_kind": failure_kind,\n        "stdout_sha256": bytes_ref(normalized["stdout"]),\n        "stderr_sha256": bytes_ref(normalized["stderr"]),\n        "stdout_bytes": len(normalized["stdout"]),\n        "stderr_bytes": len(normalized["stderr"]),\n        "stdout_truncated": truncated["stdout"],\n        "stderr_truncated": truncated["stderr"],\n        "diagnostic_class": _classify_rust_failure(bytes(stderr_sample)) if probe_id == "rust_all" and not ok else None,\n    }\n'''
    text = replace_once(text, old_result, new_result, "normalized persisted probe result")
    path.write_text(text, encoding="utf-8")


def patch_validator() -> None:
    path = ROOT / "tools/validate_phase9_gate.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '    require(moriarty._git_env().get("GIT_NO_REPLACE_OBJECTS") == "1", "MORIARTY Git replacement objects are not disabled")\n',
        '''    git_env = moriarty._git_env()\n    require(git_env.get("GIT_NO_REPLACE_OBJECTS") == "1", "MORIARTY Git replacement objects are not disabled")\n    require(git_env.get("GIT_CONFIG_KEY_0") == "core.fsmonitor" and git_env.get("GIT_CONFIG_VALUE_0") == "false", "MORIARTY Git fsmonitor execution is not neutralized")\n    require(git_env.get("GIT_CONFIG_KEY_1") == "core.hooksPath" and git_env.get("GIT_CONFIG_VALUE_1") == "/dev/null", "MORIARTY Git hooks path is not neutralized")\n    require(Path("/usr") in Path(moriarty.PYTHON_TRUSTED.executable).resolve(strict=True).parents, "MORIARTY Python runtime is not system-prefixed")\n''',
        "Git and Python runtime regressions",
    )
    text = replace_once(
        text,
        '    require(bounded_count == moriarty.MAX_PROBE_OUTPUT_BYTES and overflow is True, "MORIARTY output overflow bound regression failed")\n',
        '''    require(bounded_count == moriarty.MAX_PROBE_OUTPUT_BYTES and overflow is True, "MORIARTY output overflow bound regression failed")\n    require(moriarty._normalize_probe_output(b"x /tmp/private-run/a", Path("/tmp/private-run")) == b"x <WORK>/a", "MORIARTY workspace output normalization regression failed")\n\n    bad_exit = {\n        "schema": moriarty.COUNTEREXAMPLE_SCHEMA,\n        "counterexample_id": "sha256:" + "0" * 64,\n        "target_commit": git_head(),\n        "attack_id": "MOR-001",\n        "family": next(iter(moriarty.EXPECTED_FAMILIES)),\n        "owner_phases": ["phase0"],\n        "boundary_ids": ["phase0"],\n        "regression_probe_ids": ["phase0"],\n        "failure_kind": "exit_nonzero",\n        "observed_exit_code": 2**31,\n        "stdout_sha256": "sha256:" + "0" * 64,\n        "stderr_sha256": "sha256:" + "0" * 64,\n        "stdout_bytes": 0,\n        "stderr_bytes": 0,\n        "status": "unresolved",\n        "resolution_commit": None,\n        "production_credentials_used": False,\n        "production_targets_used": False,\n        "constitutional_bypass_used": False,\n        "authority_effect": "none",\n    }\n    bad_exit["counterexample_id"] = moriarty.canonical_ref(moriarty.counterexample_identity_projection(bad_exit))\n    _expect_reject(lambda: moriarty.validate_counterexample_shape(bad_exit), "counterexample signed-32-bit exit bound")\n''',
        "normalization and exit range regressions",
    )
    marker_old = '        "stage_rust_toolchain_runtime", "git_archive_bytes", "trusted_capture_bounded", "index_flags_clean",\n'
    marker_new = '        "stage_rust_toolchain_runtime", "git_archive_bytes", "trusted_capture_bounded", "index_flags_clean",\n        "_verified_commit_files", "_git_object_id", "_normalize_probe_output", "stdin=subprocess.DEVNULL",\n'
    text = replace_once(text, marker_old, marker_new, "runner hardening markers")
    path.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    path = ROOT / "MORIARTY.md"
    text = path.read_text(encoding="utf-8")
    anchor = "MORIARTY REPORT != SECURITY PROOF"
    if anchor not in text:
        raise SystemExit("docs anchor missing")
    note = "\n\nRuntime hardening notes: probe stdin is always harness-owned `/dev/null`; reproducibility digests normalize only the private per-run MORIARTY workspace prefix; Git commit/tree/blob bytes are rehashed before export; repository-local fsmonitor/hooks are neutralized; non-system Python and non-self-contained direct Rust installations fail closed rather than importing mutable runtime trees. Cargo package archives are hashed through bounded streaming descriptors before admission.\n"
    if "Runtime hardening notes:" not in text:
        text += note
    path.write_text(text, encoding="utf-8")


patch_isolation()
patch_runner()
patch_validator()
patch_docs()
