#!/usr/bin/env python3
from pathlib import Path

path = Path('tools/validate_phase9_gate.py')
text = path.read_text(encoding='utf-8')
old = '"shell=True", "os.system(", "eval(", "exec(", "requests.", "urllib.", "socket.",'
new = '"shell=True", "os.system(", "eval(", "requests.", "urllib.", "socket.",'
if text.count(old) != 1:
    raise SystemExit(f'phase9 exec-scan tuple drift:{text.count(old)}')
text = text.replace(old, new, 1)
marker = '''        require(forbidden not in source, f"MORIARTY runner gained forbidden dynamic/target capability: {forbidden}")
    validate_probe_map()
'''
replacement = '''        require(forbidden not in source, f"MORIARTY runner gained forbidden dynamic/target capability: {forbidden}")
    require(
        re.search(r"(?<![A-Za-z0-9_])exec\\s*\\(", source) is None,
        "MORIARTY runner gained forbidden standalone exec call",
    )
    validate_probe_map()
'''
if text.count(marker) != 1:
    raise SystemExit(f'phase9 exec-scan marker drift:{text.count(marker)}')
path.write_text(text.replace(marker, replacement, 1), encoding='utf-8')
