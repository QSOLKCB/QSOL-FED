#!/usr/bin/env python3
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path('tools').resolve()))
import moriarty_isolation as iso

print(f'LANDLOCK_ABI={iso.landlock_abi_version()}')
with tempfile.TemporaryDirectory(prefix='moriarty-landlock-diag-') as temp_dir:
    root = Path(temp_dir)
    allowed = root / 'allowed'
    forbidden = root / 'forbidden'
    allowed.mkdir(mode=0o700)
    forbidden.mkdir(mode=0o700)
    victim = forbidden / 'victim.txt'
    victim.write_text('original', encoding='utf-8')
    os.chmod(victim, 0o400)
    try:
        iso.apply_landlock_write_policy((allowed,))
        print('LANDLOCK_APPLY=ok')
    except BaseException as exc:
        print(f'LANDLOCK_APPLY=error:{type(exc).__name__}:{exc!r}')
        raise SystemExit(91)
    try:
        os.chmod(victim, 0o600)
        print('CHMOD=ok')
    except BaseException as exc:
        print(f'CHMOD=error:{type(exc).__name__}:{exc!r}')
    try:
        victim.write_text('changed', encoding='utf-8')
        print('WRITE=unexpected-success')
        raise SystemExit(92)
    except PermissionError as exc:
        print(f'WRITE=denied:{exc!r}')
        raise SystemExit(93)
