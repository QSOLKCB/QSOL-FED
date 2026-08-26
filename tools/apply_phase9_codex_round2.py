#!/usr/bin/env python3
"""Temporary one-shot patch: admit only present lock-authenticated Cargo archives."""
from __future__ import annotations

from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "tools/moriarty_isolation.py"
text = path.read_text(encoding="utf-8")
old = '''        if not matching:\n            fail(f"moriarty_verified_cargo_archive_missing:{filename}")\n        selected = matching[0]\n        cache_namespace = selected.parent.name\n        _copy_regular_file(selected, template / "registry" / "cache" / cache_namespace / filename, checksum)\n'''
new = '''        if not matching:\n            # Cargo.lock may contain platform-specific registry packages that are\n            # not required by this runner target and therefore were not fetched\n            # by the preceding locked all-targets CI build. Do not synthesize or\n            # trust an absent archive. If the package is actually needed, the\n            # later --frozen --offline probe will fail closed. If any candidate\n            # archive exists but none matches the lock checksum, reject it.\n            if candidates:\n                fail(f"moriarty_cargo_archive_checksum_mismatch:{filename}")\n            continue\n        selected = matching[0]\n        cache_namespace = selected.parent.name\n        _copy_regular_file(selected, template / "registry" / "cache" / cache_namespace / filename, checksum)\n'''
if text.count(old) != 1:
    raise SystemExit(f"Cargo archive presence patch drift:{text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
