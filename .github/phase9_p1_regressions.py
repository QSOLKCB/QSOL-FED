from pathlib import Path

path = Path("tools/validate_phase9_gate.py")
source = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global source
    old_count = source.count(old)
    new_count = source.count(new)
    if old_count == 1 and new_count == 0:
        source = source.replace(old, new, 1)
        return
    if old_count == 0 and new_count == 1:
        print(f"{label}: already applied")
        return
    raise SystemExit(f"{label}: source drift old={old_count} new={new_count}")


replace_once(
    "import copy\nimport os\n",
    "import copy\nimport io\nimport os\n",
    "io import",
)
replace_once(
    "import tempfile\n",
    "import tarfile\nimport tempfile\n",
    "tarfile import",
)

old_kernel = '''result = libc.syscall(prlimit_nr, int(parent_pid), resource.RLIMIT_NOFILE, ctypes.byref(new_limit), ctypes.c_void_p(0))
if result != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit(9)
forbidden_etc = Path("/etc/hostname")
'''
new_kernel = '''result = libc.syscall(prlimit_nr, int(parent_pid), resource.RLIMIT_NOFILE, ctypes.byref(new_limit), ctypes.c_void_p(0))
if result != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit(9)
for number, args, code in (
    (434, (int(parent_pid), 0), 13),
    (438, (-1, 0, 0), 14),
):
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        raise SystemExit(code)
add_key_nr, request_key_nr, keyctl_nr = ((248, 249, 250) if machine == "x86_64" else (217, 218, 219))
for number, args, code in (
    (add_key_nr, (ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0), 0, -1), 15),
    (request_key_nr, (ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0), -1), 16),
    (keyctl_nr, (0, 0, 0, 0, 0), 17),
):
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        raise SystemExit(code)
forbidden_etc = Path("/etc/hostname")
'''
replace_once(old_kernel, new_kernel, "pidfd/keyring kernel regressions")

old_hook_anchor = '''        (first / "config.toml").write_text("[build]\\nrustc-wrapper='evil'\\n", encoding="utf-8")
        require(not (second / "config.toml").exists(), "per-probe Cargo homes contaminated each other")

        writable_bound = root / "writable-bound"
'''
new_hook_anchor = '''        (first / "config.toml").write_text("[build]\\nrustc-wrapper='evil'\\n", encoding="utf-8")
        require(not (second / "config.toml").exists(), "per-probe Cargo homes contaminated each other")

        hook_archive = cache / "hooked-1.0.0.crate"
        hook_manifest = b'[package]\\nname = "hooked"\\nversion = "1.0.0"\\nbuild = "build.rs"\\n'
        hook_source = b"fn main() {}\\n"
        with tarfile.open(hook_archive, mode="w:gz") as archive:
            for member_name, payload in (
                ("hooked-1.0.0/Cargo.toml", hook_manifest),
                ("hooked-1.0.0/build.rs", hook_source),
            ):
                info = tarfile.TarInfo(member_name)
                info.size = len(payload)
                info.mode = 0o644
                info.mtime = 0
                archive.addfile(info, io.BytesIO(payload))
        hook_sha = hashlib.sha256(hook_archive.read_bytes()).hexdigest()
        hook_lock = root / "Cargo-hook.lock"
        hook_lock.write_text(
            'version = 4\\n\\n[[package]]\\nname = "hooked"\\nversion = "1.0.0"\\nsource = "registry+https://github.com/rust-lang/crates.io-index"\\nchecksum = "' + hook_sha + '"\\n',
            encoding="utf-8",
        )
        workspace_hook = root / "workspace-hook"
        workspace_hook.mkdir()
        _expect_reject(
            lambda: moriarty.create_verified_cargo_template(ambient, workspace_hook, hook_lock),
            "unreviewed checksum-authenticated registry build hook",
        )

        writable_bound = root / "writable-bound"
'''
replace_once(old_hook_anchor, new_hook_anchor, "registry build-hook negative regression")

path.write_text(source, encoding="utf-8")
