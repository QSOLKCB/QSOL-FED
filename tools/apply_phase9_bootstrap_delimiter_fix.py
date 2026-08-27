#!/usr/bin/env python3
from pathlib import Path

for name in ("tools/run_moriarty.py", "tools/validate_phase9_gate.py"):
    path = Path(name)
    text = path.read_text(encoding="utf-8")
    replacements = (
        ('tree_payload.find(b"\\\\0",', 'tree_payload.find(b"\\x00",'),
        ('commit_payload.split(b"\\\\n", 1)', 'commit_payload.split(b"\\n", 1)'),
    )
    for old, new in replacements:
        count = text.count(old)
        if count != 1:
            raise SystemExit(f"{name}: expected one {old!r}, found {count}")
        text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
