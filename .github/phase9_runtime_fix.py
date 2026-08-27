from pathlib import Path

runner_path = Path("tools/run_moriarty.py")
validator_path = Path("tools/validate_phase9_gate.py")
runner = runner_path.read_text(encoding="utf-8")
validator = validator_path.read_text(encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1:
        return text.replace(old, new, 1)
    if old_count == 0 and new_count == 1:
        return text
    raise SystemExit(f"{label}: unexpected source state old={old_count} new={new_count}")

runner = replace_once(
    runner,
    '        "CARGO_NET_OFFLINE": "true",\n        "CARGO_TERM_COLOR": "never",\n',
    '        "CARGO_NET_OFFLINE": "true",\n        "CARGO_BUILD_JOBS": "2",\n        "CARGO_TERM_COLOR": "never",\n',
    "Cargo build jobs cap",
)

runner = replace_once(
    runner,
    '    candidates = (Path("/usr/bin"), Path("/usr/lib"), Path("/bin"), Path("/lib"), Path("/lib64"))\n',
    '    candidates = (Path("/usr/bin"), Path("/usr/lib"), Path("/usr/libexec"), Path("/bin"), Path("/lib"), Path("/lib64"))\n',
    "system runtime helper closure",
)

old_classifier = '''def _classify_rust_failure(stderr: bytes) -> str:\n    """Reduce compiler/Cargo stderr to a closed, non-secret diagnostic class."""\n    text = stderr.decode("utf-8", errors="replace").lower()\n    denied = "permission denied" in text or "os error 13" in text\n    not_permitted = "operation not permitted" in text or "os error 1" in text\n    if "/proc/" in text and (denied or not_permitted):\n        return "proc_access_denied"\n    if "can't find crate for `std`" in text or "couldn't find crate" in text or "sysroot" in text:\n        return "rust_sysroot"\n    if "failed to run custom build command" in text:\n        return "build_script"\n    if "linking with" in text or "linker" in text:\n        return "linker"\n    if "failed to download" in text or "offline mode" in text or "no matching package named" in text:\n        return "offline_dependency"\n    if "could not execute process" in text or "failed to run rustc" in text:\n        return "rustc_spawn"\n    if denied:\n        return "filesystem_permission"\n    if not_permitted:\n        return "seccomp_or_permission"\n    if "read-only file system" in text or "os error 30" in text:\n        return "read_only_filesystem"\n    return "rust_exit_other"\n'''
new_classifier = '''def _classify_rust_failure(stderr: bytes) -> str:\n    """Reduce compiler/Cargo stderr to a closed, non-secret diagnostic class."""\n    text = stderr.decode("utf-8", errors="replace").lower()\n    denied = "permission denied" in text or "os error 13" in text\n    not_permitted = "operation not permitted" in text or "os error 1" in text\n    if "/proc/" in text and (denied or not_permitted):\n        return "proc_access_denied"\n    # Prefer causal diagnostics before the generic `--sysroot` token that Cargo\n    # includes in ordinary rustc command lines.\n    if "failed to run custom build command" in text:\n        return "build_script"\n    if "linking with" in text or "linker" in text:\n        return "linker"\n    if "failed to download" in text or "offline mode" in text or "no matching package named" in text:\n        return "offline_dependency"\n    if "could not execute process" in text or "failed to run rustc" in text:\n        return "rustc_spawn"\n    if "read-only file system" in text or "os error 30" in text:\n        return "read_only_filesystem"\n    if denied:\n        return "filesystem_permission"\n    if not_permitted:\n        return "seccomp_or_permission"\n    if "can't find crate for `std`" in text or "couldn't find crate" in text:\n        return "rust_sysroot"\n    return "rust_exit_other"\n'''
runner = replace_once(runner, old_classifier, new_classifier, "Rust diagnostic classifier")

anchor = '''    system_exec_reads = moriarty._system_read_exec_paths()\n    require(Path("/usr") not in system_exec_reads, "MORIARTY recursive /usr read/exec access reintroduced")\n    for path in system_exec_reads:\n        resolved = path.resolve(strict=True)\n        require(resolved != Path("/usr/local") and Path("/usr/local") not in resolved.parents, "MORIARTY /usr/local read/exec exposure reintroduced")\n'''
replacement = '''    system_exec_reads = moriarty._system_read_exec_paths()\n    require(Path("/usr") not in system_exec_reads, "MORIARTY recursive /usr read/exec access reintroduced")\n    require(all(path != Path("/usr/local") for path in system_exec_reads), "MORIARTY /usr/local read/exec root reintroduced")\n    for path in system_exec_reads:\n        resolved = path.resolve(strict=True)\n        require(resolved != Path("/usr/local") and Path("/usr/local") not in resolved.parents, "MORIARTY /usr/local read/exec exposure reintroduced")\n    probe_env = moriarty._probe_environment(Path("/tmp/h"), Path("/tmp/c"), Path("/tmp/t"), Path("/tmp/x"), [Path("/usr/bin")])\n    require(probe_env.get("CARGO_BUILD_JOBS") == "2", "MORIARTY Cargo build-job cap missing")\n    require(moriarty._classify_rust_failure(b"error: linking with `cc` failed; rustc --sysroot /private") == "linker", "Rust linker diagnostic masked by sysroot token")\n    require(moriarty._classify_rust_failure(b"permission denied while invoking helper; rustc --sysroot /private") == "filesystem_permission", "Rust permission diagnostic masked by sysroot token")\n'''
validator = replace_once(validator, anchor, replacement, "runtime closure negative tests")

runner_path.write_text(runner, encoding="utf-8")
validator_path.write_text(validator, encoding="utf-8")
