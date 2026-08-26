#!/usr/bin/env python3
from pathlib import Path

path = Path('MORIARTY.md')
text = path.read_text(encoding='utf-8')
old = 'The runner creates a fresh exact-commit `git archive` export for every fixed probe, rejects archive links/special files, and applies Linux Landlock so the child cannot mutate the export even after changing Unix mode bits.'
new = 'The runner creates a fresh read-only exact-commit export from `git archive` for every fixed probe, rejects archive links/special files, and applies Linux Landlock so the child cannot mutate the export even after changing Unix mode bits.'
if text.count(old) != 1:
    raise SystemExit(f'phase9 docs marker drift:{text.count(old)}')
path.write_text(text.replace(old, new, 1), encoding='utf-8')
