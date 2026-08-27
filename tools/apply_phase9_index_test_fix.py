#!/usr/bin/env python3
from pathlib import Path

path = Path("tools/validate_phase9_gate.py")
text = path.read_text(encoding="utf-8")
old = '        oversized_index.truncate(moriarty._moriarty_isolation.MAX_CARGO_INDEX_BYTES + 1)'
new = '        os.truncate(oversized_index, moriarty._moriarty_isolation.MAX_CARGO_INDEX_BYTES + 1)'
if text.count(old) != 1:
    raise SystemExit(f"expected one truncate marker, found {text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
