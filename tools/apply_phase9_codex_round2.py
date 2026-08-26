#!/usr/bin/env python3
from pathlib import Path

path = Path('tools/validate_phase9_gate.py')
text = path.read_text(encoding='utf-8')
start = text.index('def validate_kernel_write_denial() -> None:')
end = text.index('\n\ndef validate_report_common', start)
replacement = """def validate_kernel_write_denial() -> None:
    require(moriarty.landlock_abi_version() >= 3, \"MORIARTY requires Linux Landlock ABI >= 3\")
    with tempfile.TemporaryDirectory(prefix=\"moriarty-landlock-test-\") as temp_dir:
        root = Path(temp_dir)
        allowed = root / \"allowed\"
        forbidden = root / \"forbidden\"
        allowed.mkdir(mode=0o700)
        forbidden.mkdir(mode=0o700)
        victim = forbidden / \"victim.txt\"
        victim.write_text(\"original\", encoding=\"utf-8\")
        os.chmod(victim, 0o400)
        program = r'''\nimport os\nimport sys\nfrom pathlib import Path\nsys.path.insert(0, sys.argv[1])\nimport moriarty_isolation as isolation\nallowed = Path(sys.argv[2])\nvictim = Path(sys.argv[3])\nisolation.apply_landlock_write_policy((allowed,))\nos.chmod(victim, 0o600)\ntry:\n    victim.write_text(\"changed\", encoding=\"utf-8\")\nexcept PermissionError:\n    raise SystemExit(0)\nraise SystemExit(2)\n'''
        completed = subprocess.run(
            [sys.executable, \"-I\", \"-c\", program, str(TOOLS), str(allowed), str(victim)],
            cwd=ROOT,
            env={
                \"PATH\": \"/usr/bin:/bin\",
                \"HOME\": str(root),
                \"PYTHONNOUSERSITE\": \"1\",
                \"PYTHONDONTWRITEBYTECODE\": \"1\",
                \"LANG\": \"C.UTF-8\",
                \"LC_ALL\": \"C.UTF-8\",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        require(
            completed.returncode == 0,
            \"MORIARTY Landlock write-denial regression failed: \"
            + completed.stderr.decode(\"utf-8\", errors=\"replace\")[:256],
        )
        require(victim.read_text(encoding=\"utf-8\") == \"original\", \"MORIARTY Landlock victim changed\")
"""
path.write_text(text[:start] + replacement + text[end:], encoding='utf-8')
