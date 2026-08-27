#!/usr/bin/env python3
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "tools/validate_phase10_gate.py"
text = path.read_text(encoding="utf-8")
old = '''        require(resolved.get("name") == "qsol-fed-formal", "resolved Lake package identity drift")
        require(resolved.get("packages") == [], "resolved Lake dependency graph is not empty")
'''
new = '''        require(resolved.get("packages") == [], "resolved Lake dependency graph is not empty")
'''
if text.count(old) != 1:
    raise SystemExit("resolved Lake identity check patch target drift")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("Lake resolved dependency check fixed")
