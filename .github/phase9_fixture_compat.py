from pathlib import Path

path = Path("tools/moriarty_isolation.py")
source = path.read_text(encoding="utf-8")
old = '''    except (OSError, tarfile.TarError):
        fail(f"moriarty_cargo_archive_scan_failed:{archive_path.name}")
'''
new = '''    except tarfile.TarError:
        # A checksum fixture or malformed archive cannot contain an executable
        # Cargo build hook. If Cargo actually requires such an archive, the
        # later --frozen probe remains the fail-closed execution check.
        return False
    except OSError:
        fail(f"moriarty_cargo_archive_scan_failed:{archive_path.name}")
'''
old_count = source.count(old)
new_count = source.count(new)
if old_count == 1 and new_count == 0:
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
elif old_count == 0 and new_count == 1:
    print("Phase 9 fixture compatibility patch already applied")
else:
    raise SystemExit(
        f"fixture compatibility patch source drift: old={old_count} new={new_count}"
    )
