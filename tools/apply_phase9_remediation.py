#!/usr/bin/env python3
"""One-shot source transformation for the Phase 9 security-review remediation."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"phase9 remediation replacement drift:{label}:{text.count(old)}")
    return text.replace(old, new, 1)


def replace_region(text: str, start: str, end: str, new: str, label: str) -> str:
    begin = text.find(start)
    finish = text.find(end, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        raise SystemExit(f"phase9 remediation region drift:{label}")
    return text[:begin] + new + text[finish:]


# ---------------------------------------------------------------------------
# Harden tools/run_moriarty.py
# ---------------------------------------------------------------------------
runner = read("tools/run_moriarty.py")
runner = replace_once(
    runner,
    "from qsol_canonical import serialize  # noqa: E402\n",
    "from qsol_canonical import serialize  # noqa: E402\nfrom moriarty_isolation import (  # noqa: E402\n    create_exact_export,\n    create_isolated_cargo_home,\n    proc_fd_path,\n    write_report_exclusive,\n)\n",
    "runner isolation imports",
)
runner = replace_region(
    runner,
    "@dataclass(frozen=True)\nclass TrustedExecutable:",
    "def _directory_chain_safe",
    '''@dataclass(frozen=True)
class TrustedExecutable:
    """Bind a source-owned argv[0] label to an already-open executable inode."""

    name: str
    invocation: str
    executable: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    mode: int
    fd: int


''',
    "trusted executable dataclass",
)
runner = replace_region(
    runner,
    "def _trusted_executable(",
    "def trusted_executable_matches",
    '''def _trusted_executable(name: str, *, preferred: Path | None = None) -> TrustedExecutable:
    candidates: list[Path] = []
    if preferred is not None:
        candidates.append(preferred)
    candidates.extend([
        Path("/usr/local/cargo/bin") / name,
        Path("/usr/local/bin") / name,
        Path("/usr/bin") / name,
        Path("/bin") / name,
        REAL_HOME / ".cargo" / "bin" / name,
    ])
    for candidate in candidates:
        invocation = candidate.absolute()
        try:
            target = invocation.resolve(strict=True)
            target_stat = target.stat()
        except OSError:
            continue
        if not target.is_file() or not os.access(invocation, os.X_OK):
            continue
        if target == ROOT or ROOT in target.parents or invocation == ROOT or ROOT in invocation.parents:
            continue
        if not _directory_chain_safe(invocation) or not _directory_chain_safe(target):
            continue
        if not stat.S_ISREG(target_stat.st_mode) or not (target_stat.st_mode & 0o111):
            continue
        try:
            fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
            pinned = os.fstat(fd)
        except OSError:
            continue
        if (
            pinned.st_dev != target_stat.st_dev
            or pinned.st_ino != target_stat.st_ino
            or pinned.st_size != target_stat.st_size
            or pinned.st_mtime_ns != target_stat.st_mtime_ns
            or stat.S_IMODE(pinned.st_mode) != stat.S_IMODE(target_stat.st_mode)
        ):
            os.close(fd)
            continue
        return TrustedExecutable(
            name=name,
            invocation=str(invocation),
            executable=str(target),
            device=pinned.st_dev,
            inode=pinned.st_ino,
            size=pinned.st_size,
            mtime_ns=pinned.st_mtime_ns,
            mode=stat.S_IMODE(pinned.st_mode),
            fd=fd,
        )
    fail(f"moriarty_trusted_executable_unavailable:{name}")


''',
    "trusted executable open",
)
runner = replace_region(
    runner,
    "def trusted_executable_matches",
    "def trusted_run",
    '''def trusted_executable_matches(trusted: TrustedExecutable) -> bool:
    """Verify that the already-open executable descriptor still names the pinned inode."""
    try:
        info = os.fstat(trusted.fd)
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and bool(info.st_mode & 0o111)
        and info.st_dev == trusted.device
        and info.st_ino == trusted.inode
        and info.st_size == trusted.size
        and info.st_mtime_ns == trusted.mtime_ns
        and stat.S_IMODE(info.st_mode) == trusted.mode
    )


''',
    "trusted descriptor validation",
)
runner = replace_region(
    runner,
    "def trusted_run(",
    "PYTHON_TRUSTED =",
    '''def trusted_run(
    trusted: TrustedExecutable,
    args: Sequence[str],
    **kwargs: Any,
) -> subprocess.CompletedProcess[bytes]:
    if not trusted_executable_matches(trusted):
        fail(f"moriarty_trusted_executable_changed:{trusted.name}")
    inherited_fds = tuple(kwargs.pop("pass_fds", ()))
    pass_fds = tuple(dict.fromkeys((*inherited_fds, trusted.fd)))
    return subprocess.run(
        [trusted.invocation, *args],
        executable=proc_fd_path(trusted.fd),
        pass_fds=pass_fds,
        **kwargs,
    )


''',
    "trusted fd exec",
)
runner = runner.replace('"rust_all": (CARGO_EXE, "test", "--all-targets", "--offline"),', '"rust_all": (CARGO_EXE, "test", "--all-targets", "--frozen"),')
runner = runner.replace('fail(f"moriarty_json_load_failed:{path.relative_to(ROOT)}:{exc}")', 'fail(f"moriarty_json_load_failed:{path}:{exc}")')
runner = runner.replace('fail(f"moriarty_json_object_required:{path.relative_to(ROOT)}")', 'fail(f"moriarty_json_object_required:{path}")')
runner = replace_region(
    runner,
    "def _probe_environment(",
    "def validate_attack_corpus",
    '''def _probe_environment(home: Path, cargo_home: Path, target_dir: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "CARGO_HOME": str(cargo_home),
        "RUSTUP_HOME": str(REAL_HOME / ".rustup"),
        "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "RUSTC": proc_fd_path(RUSTC_TRUSTED.fd),
        "RUST_BACKTRACE": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


''',
    "isolated probe environment",
)
runner = replace_region(
    runner,
    "def validate_counterexample_shape",
    "def validate_registry",
    '''def counterexample_identity_projection(item: dict[str, Any]) -> dict[str, Any]:
    """Hash immutable discovery/reproduction facts, not mutable resolution state."""
    return {
        key: value
        for key, value in item.items()
        if key not in {"counterexample_id", "status", "resolution_commit"}
    }


def validate_counterexample_shape(item: Any) -> None:
    if not isinstance(item, dict):
        fail("moriarty_counterexample_not_object")
    required = {
        "schema", "counterexample_id", "target_commit", "attack_id", "family",
        "owner_phases", "boundary_ids", "regression_probe_ids", "failure_kind",
        "observed_exit_code", "stdout_sha256", "stderr_sha256", "stdout_bytes",
        "stderr_bytes", "status", "resolution_commit", "production_credentials_used",
        "production_targets_used", "constitutional_bypass_used", "authority_effect",
    }
    if set(item) != required:
        fail("moriarty_counterexample_field_set_invalid")
    if (
        item["schema"] != COUNTEREXAMPLE_SCHEMA
        or not isinstance(item["counterexample_id"], str)
        or not SHA256_REF_RE.fullmatch(item["counterexample_id"])
        or not isinstance(item["target_commit"], str)
        or not TARGET_RE.fullmatch(item["target_commit"])
        or not isinstance(item["attack_id"], str)
        or not re.fullmatch(r"MOR-[0-9]{3}", item["attack_id"])
        or item["family"] not in EXPECTED_FAMILIES
        or not isinstance(item["owner_phases"], list)
        or not item["owner_phases"]
        or len(set(item["owner_phases"])) != len(item["owner_phases"])
        or not isinstance(item["boundary_ids"], list)
        or not item["boundary_ids"]
        or len(set(item["boundary_ids"])) != len(item["boundary_ids"])
        or not isinstance(item["regression_probe_ids"], list)
        or len(item["regression_probe_ids"]) != 1
        or not all(probe_id in PROBES for probe_id in item["regression_probe_ids"])
        or item["failure_kind"] not in {"exit_nonzero", "timeout", "tool_error"}
        or item["status"] not in {"unresolved", "resolved"}
        or item["production_credentials_used"] is not False
        or item["production_targets_used"] is not False
        or item["constitutional_bypass_used"] is not False
        or item["authority_effect"] != "none"
        or not isinstance(item["stdout_sha256"], str)
        or not SHA256_REF_RE.fullmatch(item["stdout_sha256"])
        or not isinstance(item["stderr_sha256"], str)
        or not SHA256_REF_RE.fullmatch(item["stderr_sha256"])
        or not isinstance(item["stdout_bytes"], int)
        or isinstance(item["stdout_bytes"], bool)
        or not 0 <= item["stdout_bytes"] <= 9007199254740991
        or not isinstance(item["stderr_bytes"], int)
        or isinstance(item["stderr_bytes"], bool)
        or not 0 <= item["stderr_bytes"] <= 9007199254740991
    ):
        fail("moriarty_counterexample_boundary_invalid")

    if item["failure_kind"] == "exit_nonzero":
        if not isinstance(item["observed_exit_code"], int) or isinstance(item["observed_exit_code"], bool) or item["observed_exit_code"] == 0:
            fail("moriarty_exit_failure_requires_nonzero_exit_code")
    elif item["observed_exit_code"] is not None:
        fail("moriarty_nonexit_failure_exit_code_must_be_null")

    if item["status"] == "unresolved":
        if item["resolution_commit"] is not None:
            fail("moriarty_unresolved_counterexample_has_resolution_commit")
    elif not isinstance(item["resolution_commit"], str) or not TARGET_RE.fullmatch(item["resolution_commit"]):
        fail("moriarty_resolved_counterexample_missing_resolution_commit")

    if item["counterexample_id"] != canonical_ref(counterexample_identity_projection(item)):
        fail("moriarty_counterexample_identity_mismatch")


''',
    "stable counterexample identity",
)
runner = replace_region(
    runner,
    "def run_probe(",
    "def generated_counterexample",
    '''def run_probe(
    probe_id: str,
    home: Path,
    source_root: Path,
    cargo_home: Path,
    target_dir: Path,
) -> dict[str, Any]:
    if not tracked_tree_clean():
        return _probe_failure_result(probe_id, "tool_error", b"tracked_tree_dirty_before_probe")
    home.mkdir(mode=0o700, parents=False, exist_ok=False)
    target_dir.mkdir(mode=0o700, parents=False, exist_ok=False)

    argv = PROBES[probe_id]
    trusted = PROBE_EXECUTABLES[probe_id]
    if not trusted_executable_matches(trusted):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_executable_fd_invalid_before_probe")
    if probe_id == "rust_all" and not trusted_executable_matches(RUSTC_TRUSTED):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_rustc_fd_invalid_before_probe")
    pass_fds = (trusted.fd,) if probe_id != "rust_all" else (trusted.fd, RUSTC_TRUSTED.fd)
    try:
        process = subprocess.Popen(
            list(argv),
            executable=proc_fd_path(trusted.fd),
            pass_fds=pass_fds,
            cwd=source_root,
            env=_probe_environment(home, cargo_home, target_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as exc:
        return _probe_failure_result(probe_id, "tool_error", str(exc).encode("utf-8", errors="replace"))

    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    counts = {"stdout": 0, "stderr": 0}
    deadline = time.monotonic() + TIMEOUT_SECONDS
    failure_kind: str | None = None

    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0 and failure_kind is None:
                failure_kind = "timeout"
                _kill_process_group(process)
            events = selector.select(timeout=max(0.0, min(0.1, remaining)) if failure_kind is None else 0.1)
            for key, _ in events:
                stream_name = key.data
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                counts[stream_name] += len(chunk)
                digests[stream_name].update(chunk)
                if counts[stream_name] > MAX_PROBE_OUTPUT_BYTES and failure_kind is None:
                    failure_kind = "tool_error"
                    _kill_process_group(process)
            if process.poll() is not None and not events:
                time.sleep(0.01)
        remaining = max(0.0, deadline - time.monotonic())
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            failure_kind = failure_kind or "timeout"
            _kill_process_group(process)
            process.wait(timeout=1)
            return_code = None
    except subprocess.TimeoutExpired:
        failure_kind = failure_kind or "timeout"
        _kill_process_group(process)
        return_code = None
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass

    if not tracked_tree_clean():
        return _probe_failure_result(probe_id, "tool_error", b"tracked_tree_dirty_after_probe")
    if not trusted_executable_matches(trusted):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_executable_fd_invalid_after_probe")
    if probe_id == "rust_all" and not trusted_executable_matches(RUSTC_TRUSTED):
        return _probe_failure_result(probe_id, "tool_error", b"trusted_rustc_fd_invalid_after_probe")
    if counts["stdout"] > MAX_PROBE_OUTPUT_BYTES or counts["stderr"] > MAX_PROBE_OUTPUT_BYTES:
        failure_kind = "tool_error"

    if failure_kind is None and return_code == 0:
        ok = True
    else:
        ok = False
        if failure_kind is None:
            failure_kind = "exit_nonzero"

    return {
        "probe_id": probe_id,
        "ok": ok,
        "exit_code": return_code if failure_kind == "exit_nonzero" or ok else None,
        "failure_kind": failure_kind,
        "stdout_sha256": "sha256:" + digests["stdout"].hexdigest(),
        "stderr_sha256": "sha256:" + digests["stderr"].hexdigest(),
        "stdout_bytes": counts["stdout"],
        "stderr_bytes": counts["stderr"],
    }


''',
    "probe execution isolation",
)
runner = replace_once(
    runner,
    '''    projection = dict(item)
    projection.pop("counterexample_id")
    item["counterexample_id"] = canonical_ref(projection)
''',
    '''    item["counterexample_id"] = canonical_ref(counterexample_identity_projection(item))
''',
    "generated counterexample stable id",
)
resolution_helpers = '''def counterexample_failure_matches(item: dict[str, Any], result: dict[str, Any]) -> bool:
    return (
        result["ok"] is False
        and result["failure_kind"] == item["failure_kind"]
        and result["exit_code"] == item["observed_exit_code"]
        and result["stdout_sha256"] == item["stdout_sha256"]
        and result["stderr_sha256"] == item["stderr_sha256"]
        and result["stdout_bytes"] == item["stdout_bytes"]
        and result["stderr_bytes"] == item["stderr_bytes"]
    )


def verify_resolved_counterexamples(
    accepted: list[dict[str, Any]],
    workspace: Path,
    cargo_home: Path,
) -> None:
    for index, item in enumerate(accepted):
        if item["status"] != "resolved":
            continue
        probe_id = item["regression_probe_ids"][0]
        before_source = create_exact_export(
            item["target_commit"], workspace, lambda *args: git(*args).returncode, f"resolved-{index}-before"
        )
        before = run_probe(
            probe_id,
            workspace / f"resolved-{index}-before-home",
            before_source,
            cargo_home,
            workspace / f"resolved-{index}-before-target",
        )
        if not counterexample_failure_matches(item, before):
            fail("moriarty_resolution_target_failure_not_reproduced")

        resolution = item["resolution_commit"]
        assert isinstance(resolution, str)
        after_source = create_exact_export(
            resolution, workspace, lambda *args: git(*args).returncode, f"resolved-{index}-after"
        )
        after = run_probe(
            probe_id,
            workspace / f"resolved-{index}-after-home",
            after_source,
            cargo_home,
            workspace / f"resolved-{index}-after-target",
        )
        if after["ok"] is not True or after["exit_code"] != 0:
            fail("moriarty_resolution_fix_probe_not_green")


'''
runner = runner.replace("def report_probe_result(result: dict[str, Any]) -> dict[str, Any]:\n", resolution_helpers + "def report_probe_result(result: dict[str, Any]) -> dict[str, Any]:\n", 1)
start = '    corpus = load_json(ROOT / "fixtures/phase9/attack-corpus.json")\n'
end = '    generated: list[dict[str, Any]] = []\n'
begin = runner.find(start)
finish = runner.find(end, begin)
if begin < 0 or finish < 0:
    raise SystemExit("phase9 remediation main probe region drift")
main_probe = '''    with tempfile.TemporaryDirectory(prefix="qsol-fed-moriarty-work-") as work_dir:
        workspace = Path(work_dir)
        cargo_home = create_isolated_cargo_home(REAL_HOME / ".cargo", workspace)
        source_root = create_exact_export(
            target, workspace, lambda *git_args: git(*git_args).returncode, "target"
        )
        if not (source_root / "Cargo.lock").is_file():
            fail("moriarty_committed_cargo_lock_missing")

        corpus = load_json(source_root / "fixtures/phase9/attack-corpus.json")
        attacks = validate_attack_corpus(corpus)
        registry = load_json(source_root / "fixtures/phase9/accepted-counterexamples.json")
        accepted = validate_registry(registry, attacks, target)

        requested_probe_ids: list[str] = []
        for attack in attacks:
            requested_probe_ids.extend(attack["probe_ids"])
        for item in accepted:
            requested_probe_ids.extend(item["regression_probe_ids"])

        ordered_probe_ids: list[str] = []
        seen_probes: set[str] = set()
        for probe_id in requested_probe_ids:
            if probe_id not in seen_probes:
                seen_probes.add(probe_id)
                ordered_probe_ids.append(probe_id)

        probe_users: dict[str, list[dict[str, Any]]] = {probe_id: [] for probe_id in ordered_probe_ids}
        for attack in attacks:
            for probe_id in attack["probe_ids"]:
                probe_users.setdefault(probe_id, []).append(attack)

        results = {
            probe_id: run_probe(
                probe_id,
                workspace / f"home-{probe_id}",
                source_root,
                cargo_home,
                workspace / f"target-{probe_id}",
            )
            for probe_id in ordered_probe_ids
        }
        verify_resolved_counterexamples(accepted, workspace, cargo_home)

'''
runner = runner[:begin] + main_probe + runner[finish:]
old_output = '''    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encoded)
'''
new_output = '''    output = Path(args.output)
    write_report_exclusive(output, encoded, ROOT)
    if git_head() != target or not tracked_tree_clean():
        fail("moriarty_target_changed_during_report_publication")
'''
runner = replace_once(runner, old_output, new_output, "exclusive report publication")
write("tools/run_moriarty.py", runner)


# ---------------------------------------------------------------------------
# Harden tools/validate_phase9_gate.py
# ---------------------------------------------------------------------------
validator = read("tools/validate_phase9_gate.py")
validator = validator.replace("import argparse\n", "import argparse\nimport copy\nimport os\n")
validator = validator.replace('"rust_all": ("test", "--all-targets", "--offline"),', '"rust_all": ("test", "--all-targets", "--frozen"),')
validator = replace_region(
    validator,
    "def validate_claims()",
    "def validate_contract()",
    '''def _validate_claim_document(previous: dict[str, Any], current: dict[str, Any]) -> None:
    expected_top = {
        "document_type", "schema_version", "protocol", "wire_protocol", "phase", "gate_id",
        "gate_status", "historical_baseline", "runtime_override_allowed", "claim_surface_changed",
        "capabilities", "assurance", "claim_rule", "promotion_requirements",
    }
    expected_assurance = {
        "moriarty_protocol", "provider_neutral", "exact_commit_binding",
        "reproducible_counterexample_contract", "accepted_counterexample_registry",
        "fixed_repository_probe_map", "cross_phase_regression_sweep",
        "isolated_source_export", "committed_cargo_lock", "opened_executable_binding",
        "cache_only_cargo_home", "exclusive_external_report_output",
        "remediation_transition_verified", "production_credentials_used",
        "production_targets_used", "constitutional_bypass_used", "report_is_security_proof",
        "no_counterexample_found_means_none_exist", "authority_effect",
    }
    expected_promotions = {
        "interoperable_federation", "production_networking", "remote_execution",
        "host_level_sandbox", "oracle_holodeck_synthetic_admission",
    }
    require(set(current) == expected_top, "Phase 9 claim manifest field set is not closed")
    require(current.get("document_type") == "qsol-fed-phase9-moriarty-claims", "Phase 9 claim id drift")
    require(current.get("gate_id") == "qsol-fed-phase9-moriarty-gate/1", "Phase 9 gate id drift")
    require(current.get("gate_status") == "enforced", "Phase 9 gate not enforced")
    require(current.get("historical_baseline") == "claims/phase8.json", "Phase 9 claim baseline drift")
    require(current.get("runtime_override_allowed") is False, "Phase 9 claims became runtime configurable")
    require(current.get("claim_surface_changed") is False, "MORIARTY incorrectly promoted runtime capability surface")
    require(current.get("capabilities") == previous.get("capabilities"), "Phase 9 changed the Phase 8 capability map")
    for key in HARD_FALSE_CLAIMS:
        require(current["capabilities"].get(key) is False, f"Phase 9 overclaim enabled: {key}")
    assurance = current.get("assurance")
    require(isinstance(assurance, dict) and set(assurance) == expected_assurance, "Phase 9 assurance field set is not closed")
    for key in (
        "provider_neutral", "exact_commit_binding", "reproducible_counterexample_contract",
        "accepted_counterexample_registry", "fixed_repository_probe_map", "cross_phase_regression_sweep",
        "isolated_source_export", "committed_cargo_lock", "opened_executable_binding",
        "cache_only_cargo_home", "exclusive_external_report_output", "remediation_transition_verified",
    ):
        require(assurance.get(key) is True, f"Phase 9 assurance drift: {key}")
    for key in (
        "production_credentials_used", "production_targets_used", "constitutional_bypass_used",
        "report_is_security_proof", "no_counterexample_found_means_none_exist",
    ):
        require(assurance.get(key) is False, f"Phase 9 assurance overclaim/bypass: {key}")
    require(assurance.get("authority_effect") == "none", "MORIARTY assurance gained authority")
    promotions = current.get("promotion_requirements")
    require(isinstance(promotions, dict) and set(promotions) == expected_promotions, "Phase 9 promotion requirement field set is not closed")


def validate_claims() -> None:
    previous = load("claims/phase8.json")
    current = load("claims/phase9.json")
    _validate_claim_document(previous, current)
    malicious = copy.deepcopy(current)
    malicious["assurance"]["security_proof"] = True
    _expect_reject(lambda: _validate_claim_document(previous, malicious), "undeclared assurance claim")


''',
    "closed claims",
)
validator = replace_region(
    validator,
    "def validate_contract()",
    "def validate_schemas_and_fixtures()",
    '''def validate_contract() -> None:
    state = load("state/phase9.json")
    expected_top = {
        "document_type", "schema_version", "protocol", "wire_protocol", "moriarty_protocol", "purpose",
        "feature_dependency", "claim_surface_changed", "capability_baseline", "assurance_manifest",
        "attack_corpus", "accepted_counterexample_registry", "counterexample_schema", "report_schema",
        "attack_corpus_schema", "reference_runner", "gate_validator", "operator_model",
        "execution_boundary", "attack_families", "probe_policy", "counterexample_policy",
        "report_policy", "phase9_gate",
    }
    require(set(state) == expected_top, "Phase 9 contract top-level field set is not closed")
    require(state.get("document_type") == "qsol-fed-phase9-moriarty-contract", "Phase 9 state id drift")
    require(state.get("moriarty_protocol") == "MORIARTY/1", "MORIARTY protocol drift")
    require(state.get("feature_dependency") is False, "MORIARTY became a feature dependency")
    require(state.get("claim_surface_changed") is False, "MORIARTY changed capability claim surface")
    require(state.get("capability_baseline") == "claims/phase8.json", "MORIARTY capability baseline drift")
    require(set(state.get("attack_families", [])) == EXPECTED_FAMILIES, "MORIARTY attack-family set drift")

    operator = state["operator_model"]
    require(set(operator) == {
        "provider_neutral", "reference_operator_may_be_codex", "operator_output_is_authority",
        "operator_output_is_security_proof", "operator_may_supply_commands",
        "operator_may_supply_repository_targets", "operator_may_supply_network_targets",
        "operator_may_supply_credentials", "operator_may_disable_constitution",
        "candidate_findings_require_local_reproduction",
    }, "MORIARTY operator field set is not closed")
    for key in ("provider_neutral", "reference_operator_may_be_codex", "candidate_findings_require_local_reproduction"):
        require(operator[key] is True, f"MORIARTY operator rule drift: {key}")
    for key in (
        "operator_output_is_authority", "operator_output_is_security_proof", "operator_may_supply_commands",
        "operator_may_supply_repository_targets", "operator_may_supply_network_targets",
        "operator_may_supply_credentials", "operator_may_disable_constitution",
    ):
        require(operator[key] is False, f"MORIARTY operator boundary weakened: {key}")

    execution = state["execution_boundary"]
    required_true = {
        "target_is_exact_git_commit", "checked_out_head_must_equal_target", "tracked_worktree_must_be_clean",
        "fixed_repository_probe_map", "probe_environment_allowlisted", "probe_process_group_isolated",
        "probe_output_bounded", "exact_source_export", "source_export_read_only",
        "untracked_inputs_excluded", "tool_exec_via_open_descriptor", "cargo_home_cache_only",
        "cargo_target_outside_source", "report_output_external_private_exclusive",
    }
    for key in required_true:
        require(execution[key] is True, f"MORIARTY exact/fixed execution boundary drift: {key}")
    for key in (
        "shell_execution", "arbitrary_command_execution", "production_credentials_allowed",
        "production_targets_allowed", "outbound_network_targeting_allowed",
        "constitutional_bypass_allowed", "semantic_payload_execution_allowed",
    ):
        require(execution[key] is False, f"MORIARTY execution boundary weakened: {key}")
    require(execution["authority_effect"] == "none", "MORIARTY execution gained authority")

    probes = state["probe_policy"]
    require(probes["cargo_network_access"] is False, "MORIARTY Cargo probe regained network access")
    require(probes["cargo_mode"] == "frozen", "MORIARTY Cargo mode is not frozen")
    require(probes["cargo_lockfile_committed"] is True, "MORIARTY Cargo lockfile is not committed")
    require(probes["cargo_user_config_inherited"] is False, "MORIARTY Cargo user config became ambient")
    require(probes["shared_probe_failure_implies_specific_attack"] is False, "shared probe can fabricate specific counterexample")
    require(probes["maximum_output_bytes_per_stream"] == moriarty.MAX_PROBE_OUTPUT_BYTES, "MORIARTY output bound drift")

    counterexamples = state["counterexample_policy"]
    for key in (
        "accepted_findings_are_reproducible", "accepted_findings_require_observed_local_failure",
        "accepted_findings_bind_to_attack_corpus", "accepted_findings_name_attack_family",
        "accepted_findings_name_owning_phases", "accepted_findings_name_boundary_ids",
        "accepted_findings_name_fixed_regression_probes", "regression_probes_must_be_subset_of_attack_probes",
        "external_findings_are_candidates_only", "unresolved_accepted_finding_blocks_graduation",
        "unresolved_regressions_execute_before_graduation_decision", "resolved_finding_remains_in_registry",
        "resolved_finding_becomes_regression", "resolution_commit_is_fix_commit", "resolution_commit_must_exist",
        "resolution_commit_descends_from_finding_target", "resolution_commit_is_in_reviewed_history",
        "counterexample_id_stable_through_resolution", "resolved_requires_fail_before_pass_after",
        "resolved_failure_metadata_must_reproduce",
    ):
        require(counterexamples[key] is True, f"MORIARTY counterexample policy drift: {key}")
    for key in (
        "candidate_can_enter_accepted_registry_without_local_reproduction", "finding_may_create_authority",
        "finding_may_contain_production_credentials", "finding_may_target_production_system",
    ):
        require(counterexamples[key] is False, f"MORIARTY counterexample boundary weakened: {key}")
    require(counterexamples["maximum_accepted_counterexamples"] == moriarty.MAX_ACCEPTED_COUNTEREXAMPLES, "MORIARTY registry count bound drift")

    report = state["report_policy"]
    for key in (
        "binds_exact_target_commit", "binds_canonical_attack_corpus_identity",
        "records_probe_results_without_raw_output", "records_generated_counterexamples",
        "graduated_requires_zero_unresolved_counterexamples", "graduated_requires_all_probes_green",
        "failed_report_metadata_exposed_before_exit", "generated_report_nested_schema_validated",
        "report_persisted_for_ci_artifact_upload",
    ):
        require(report[key] is True, f"MORIARTY report policy drift: {key}")
    require(report["maximum_canonical_bytes"] == moriarty.MAX_REPORT_BYTES, "MORIARTY report byte bound drift")
    require(report["security_proof"] is False, "MORIARTY report overclaimed security proof")
    require(report["no_counterexample_found_implies_none_exist"] is False, "MORIARTY report overclaimed exhaustiveness")
    require(report["authority_effect"] == "none", "MORIARTY report gained authority")


''',
    "closed contract",
)
validator = validator.replace(
    'require(isinstance(counterexample_schema.get("allOf"), list), "MORIARTY counterexample conditional semantics missing")',
    'require(isinstance(counterexample_schema.get("allOf"), list), "MORIARTY counterexample conditional semantics missing")\n    require(counter_props["regression_probe_ids"].get("maxItems") == 1, "MORIARTY counterexample must bind one observed regression probe")\n    require((ROOT / "Cargo.lock").is_file(), "MORIARTY committed Cargo.lock missing")',
)
validator = validator.replace(
    'mode=moriarty.PYTHON_TRUSTED.mode,\n    )',
    'mode=moriarty.PYTHON_TRUSTED.mode,\n        fd=moriarty.PYTHON_TRUSTED.fd,\n    )',
    1,
)
validator = replace_region(
    validator,
    "def validate_runner_source()",
    "def validate_docs_and_ci()",
    '''def validate_runner_source() -> None:
    source = (ROOT / "tools/run_moriarty.py").read_text(encoding="utf-8")
    for marker in (
        "provider-neutral-fixed-probe/1", "moriarty-counterexample/1", "moriarty-report/1",
        "PROBES: dict[str, tuple[str, ...]]", "PROBE_EXECUTABLES", "TrustedExecutable",
        "proc_fd_path(trusted.fd)", "pass_fds=pass_fds", "create_exact_export",
        "create_isolated_cargo_home", "write_report_exclusive", "--frozen", "candidate",
        "tracked_tree_clean", "start_new_session=True", "selectors.DefaultSelector",
        "MAX_PROBE_OUTPUT_BYTES", "git_commit_exists", "git_is_ancestor",
        "moriarty_counterexample_attack_not_in_corpus", "moriarty_resolution_commit_missing",
        "counterexample_identity_projection", "verify_resolved_counterexamples",
        "production_credentials_used", "production_targets_used", "constitutional_bypass_used",
        "security_proof", "no_counterexample_found_implies_none_exist",
    ):
        require(marker in source, f"MORIARTY runner marker missing: {marker}")
    require("accepted_external" not in source, "MORIARTY runner still admits accepted_external")
    for forbidden in (
        "shell=True", "os.system(", "eval(", "exec(", "requests.", "urllib.", "socket.",
        "--command", "--url", "--host", "--credential", "--token",
    ):
        require(forbidden not in source, f"MORIARTY runner gained forbidden dynamic/target capability: {forbidden}")
    validate_probe_map()


''',
    "runner source markers",
)
validator = validator.replace(
    '"reopens the owning phase", "production credentials", "production targets",',
    '"reopens the owning phase", "production credentials", "production targets",\n        "cargo test --all-targets --frozen", "read-only exact-commit export",\n        "fail-before/pass-after", "stable through resolution",',
)
validator = validator.replace(
    'require("python3 tools/validate_phase9_gate.py --target-commit \\\"$MORIARTY_TARGET_COMMIT\\\"" in workflow, "CI missing exact-commit Phase 9 gate")',
    'require("cargo test --all-targets --locked" in workflow, "CI Rust suite is not lockfile-bound")\n    require("MORIARTY_REPORT_DIR" in workflow, "CI MORIARTY persistent report directory missing")\n    require("actions/upload-artifact@v4" in workflow and "Preserve Phase 9 MORIARTY report" in workflow, "CI MORIARTY report artifact preservation missing")\n    require("python3 tools/validate_phase9_gate.py --target-commit \\\"$MORIARTY_TARGET_COMMIT\\\" --report-dir \\\"$MORIARTY_REPORT_DIR\\\"" in workflow, "CI missing exact-commit Phase 9 gate")',
)
validator = replace_once(
    validator,
    '''def _reidentify(item: dict[str, Any]) -> None:
    projection = dict(item)
    projection.pop("counterexample_id")
    item["counterexample_id"] = moriarty.canonical_ref(projection)
''',
    '''def _reidentify(item: dict[str, Any]) -> None:
    item["counterexample_id"] = moriarty.canonical_ref(moriarty.counterexample_identity_projection(item))
''',
    "stable test identity",
)
validator = validator.replace(
    '        "nonexistent resolution commit",\n    )\n\n\ndef validate_report_common',
    '''        "nonexistent resolution commit",
    )

    stable = _counterexample_for_test(target, attack)
    original_id = stable["counterexample_id"]
    stable["status"] = "resolved"
    stable["resolution_commit"] = target
    _reidentify(stable)
    require(stable["counterexample_id"] == original_id, "counterexample identity changed through resolution")


def validate_isolation_negative_tests(target: str) -> None:
    with tempfile.TemporaryDirectory(prefix="moriarty-cargo-home-test-") as temp_dir:
        root = Path(temp_dir)
        ambient = root / "ambient"
        (ambient / "registry").mkdir(parents=True)
        (ambient / "config.toml").write_text("[build]\\nrustc-wrapper='evil'\\n", encoding="utf-8")
        workspace = root / "workspace"
        workspace.mkdir()
        isolated = moriarty.create_isolated_cargo_home(ambient, workspace)
        require(not (isolated / "config.toml").exists(), "ambient Cargo config entered isolated Cargo home")

    cargo_dir = ROOT / ".cargo"
    config = cargo_dir / "config.toml"
    require(not config.exists(), "negative test requires no tracked repository Cargo config")
    cargo_dir.mkdir(exist_ok=True)
    try:
        config.write_text("[build]\\nrustc-wrapper='evil'\\n", encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="moriarty-export-test-") as temp_dir:
            workspace = Path(temp_dir)
            export = moriarty.create_exact_export(
                target, workspace, lambda *args: moriarty.git(*args).returncode, "negative-untracked"
            )
            require(not (export / ".cargo/config.toml").exists(), "untracked Cargo config entered exact export")
            require((export / "Cargo.lock").read_bytes() == (ROOT / "Cargo.lock").read_bytes(), "exact export lockfile drift")
    finally:
        try:
            config.unlink()
        except FileNotFoundError:
            pass
        try:
            cargo_dir.rmdir()
        except OSError:
            pass

    _expect_reject(
        lambda: moriarty.write_report_exclusive(ROOT / "moriarty-report-negative.json", b"{}", ROOT),
        "repository-local report output",
    )
    with tempfile.TemporaryDirectory(prefix="moriarty-report-test-") as temp_dir:
        parent = Path(temp_dir)
        os.chmod(parent, 0o700)
        victim = parent / "victim"
        victim.write_bytes(b"unchanged")
        output = parent / "report.json"
        output.symlink_to(victim)
        _expect_reject(
            lambda: moriarty.write_report_exclusive(output, b"{}", ROOT),
            "symlinked report output",
        )
        require(victim.read_bytes() == b"unchanged", "report symlink negative test modified victim")


def validate_report_common''',
    1,
)
validator = replace_region(
    validator,
    "def validate_report_common(",
    "def validate_success_report",
    '''def validate_report_common(report: dict[str, Any], target: str) -> None:
    expected_fields = {
        "schema", "protocol", "target_commit", "corpus_ref", "operator_profile", "family_count",
        "executed_probe_count", "probe_results", "counterexamples", "unresolved_counterexamples",
        "graduated", "production_credentials_used", "production_targets_used",
        "constitutional_bypass_used", "security_proof", "no_counterexample_found_implies_none_exist",
        "authority_effect",
    }
    require(set(report) == expected_fields, "MORIARTY generated report field-set drift")
    require(report["schema"] == "moriarty-report/1", "MORIARTY generated report schema drift")
    require(report["protocol"] == "MORIARTY/1", "MORIARTY generated report protocol drift")
    require(report["target_commit"] == target, "MORIARTY generated report target drift")
    require(report["corpus_ref"] == canonical_ref(load("fixtures/phase9/attack-corpus.json")), "MORIARTY generated report corpus reference drift")
    require(report["operator_profile"] == "provider-neutral-fixed-probe/1", "MORIARTY generated report operator drift")
    require(report["family_count"] == 15, "MORIARTY generated report family count drift")
    require(report["executed_probe_count"] == len(EXPECTED_PROBES), "MORIARTY did not execute complete fixed-probe set")

    probe_results = report["probe_results"]
    result_fields = {"probe_id", "ok", "exit_code", "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes"}
    require(isinstance(probe_results, list) and len(probe_results) == len(EXPECTED_PROBES), "MORIARTY report probe result count drift")
    require({item.get("probe_id") for item in probe_results if isinstance(item, dict)} == set(EXPECTED_PROBES), "MORIARTY report probe set drift")
    for item in probe_results:
        require(isinstance(item, dict) and set(item) == result_fields, "MORIARTY nested probe result schema drift")
        require(isinstance(item["probe_id"], str) and item["probe_id"] in EXPECTED_PROBES, "MORIARTY probe result id invalid")
        require(type(item["ok"]) is bool, "MORIARTY probe result ok must be boolean")
        exit_code = item["exit_code"]
        require(exit_code is None or (type(exit_code) is int and -2147483648 <= exit_code <= 2147483647), "MORIARTY probe exit code invalid")
        if item["ok"]:
            require(exit_code == 0, "MORIARTY successful probe lacks zero exit code")
        else:
            require(exit_code is None or exit_code != 0, "MORIARTY failed probe reports zero exit code")
        for digest in ("stdout_sha256", "stderr_sha256"):
            require(isinstance(item[digest], str) and moriarty.SHA256_REF_RE.fullmatch(item[digest]) is not None, f"MORIARTY probe digest invalid: {digest}")
        for size in ("stdout_bytes", "stderr_bytes"):
            require(type(item[size]) is int and 0 <= item[size] <= moriarty.MAX_PROBE_OUTPUT_BYTES, f"MORIARTY probe byte bound invalid: {size}")

    counterexamples = report["counterexamples"]
    require(isinstance(counterexamples, list) and len(counterexamples) <= moriarty.MAX_REPORT_COUNTEREXAMPLES, "MORIARTY report counterexample count drift")
    attacks = moriarty.validate_attack_corpus(load("fixtures/phase9/attack-corpus.json"))
    attack_by_id = {attack["id"]: attack for attack in attacks}
    unresolved = 0
    for item in counterexamples:
        moriarty.validate_counterexample_shape(item)
        attack = attack_by_id.get(item["attack_id"])
        require(attack is not None, "MORIARTY report counterexample attack not in corpus")
        require(item["family"] == attack["family"], "MORIARTY report counterexample family mismatch")
        require(item["owner_phases"] == attack["owner_phases"], "MORIARTY report counterexample owner mismatch")
        require(item["boundary_ids"] == attack["boundary_ids"], "MORIARTY report counterexample boundary mismatch")
        require(set(item["regression_probe_ids"]).issubset(set(attack["probe_ids"])), "MORIARTY report counterexample probe mismatch")
        unresolved += item["status"] == "unresolved"
    require(type(report["unresolved_counterexamples"]) is int and report["unresolved_counterexamples"] == unresolved, "MORIARTY report unresolved count inconsistent")

    for key in (
        "production_credentials_used", "production_targets_used", "constitutional_bypass_used",
        "security_proof", "no_counterexample_found_implies_none_exist",
    ):
        require(report[key] is False, f"MORIARTY generated report overclaim/bypass: {key}")
    require(report["authority_effect"] == "none", "MORIARTY generated report gained authority")
    all_ok = all(item["ok"] for item in probe_results)
    require(type(report["graduated"]) is bool and report["graduated"] == (all_ok and unresolved == 0), "MORIARTY graduation Boolean inconsistent with report evidence")


''',
    "nested report validation",
)
validator = replace_region(
    validator,
    "def execute_exact_commit_gate(",
    "def main()",
    '''def execute_exact_commit_gate(target: str, report_dir: Path | None) -> None:
    require(git_head() == target, "Phase 9 target commit does not match checked-out HEAD")
    require(moriarty.tracked_tree_clean(), "Phase 9 target tracked tree is dirty before runner")
    registry = load("fixtures/phase9/accepted-counterexamples.json")
    if report_dir is None:
        report_dir = Path(tempfile.mkdtemp(prefix="qsol-fed-moriarty-report-"))
    else:
        report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(report_dir, 0o700)
    report_path = report_dir / f"moriarty-report-{target}.json"
    require(not report_path.exists(), "MORIARTY report destination already exists")

    completed = moriarty.trusted_run(
        moriarty.PYTHON_TRUSTED,
        ("tools/run_moriarty.py", "--target-commit", target, "--output", str(report_path)),
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(report_dir),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(report_path.exists(), "MORIARTY runner did not emit report")
    raw = report_path.read_bytes()
    require(len(raw) <= moriarty.MAX_REPORT_BYTES, "MORIARTY report exceeds canonical byte bound")
    require(canonicalize(raw.decode("utf-8")) == raw, "MORIARTY report is not exact canonical JSON")
    report = json.loads(raw)
    validate_report_common(report, target)

    injected = copy.deepcopy(report)
    injected["probe_results"][0]["raw_output"] = "forbidden"
    _expect_reject(lambda: validate_report_common(injected, target), "nested raw probe output")
    malformed = copy.deepcopy(report)
    malformed["probe_results"][0]["stdout_sha256"] = "sha256:not-a-digest"
    _expect_reject(lambda: validate_report_common(malformed, target), "malformed nested probe digest")

    if completed.returncode != 0:
        raise SystemExit("MORIARTY runner blocked exact commit: " + failure_diagnostic(report))
    validate_success_report(report, registry)


''',
    "persistent report execution",
)
validator = validator.replace(
    'parser.add_argument("--target-commit", help="exact checked-out commit; defaults to Git HEAD")',
    'parser.add_argument("--target-commit", help="exact checked-out commit; defaults to Git HEAD")\n    parser.add_argument("--report-dir", help="private external directory for persistent MORIARTY report")',
)
validator = validator.replace(
    '    validate_counterexample_negative_tests(target)\n    execute_exact_commit_gate(target)\n',
    '    validate_counterexample_negative_tests(target)\n    validate_isolation_negative_tests(target)\n    execute_exact_commit_gate(target, Path(args.report_dir).resolve() if args.report_dir else None)\n',
)
write("tools/validate_phase9_gate.py", validator)


# ---------------------------------------------------------------------------
# Update machine contracts, schemas, docs, and CI.
# ---------------------------------------------------------------------------
claims_path = ROOT / "claims/phase9.json"
claims = json.loads(claims_path.read_text(encoding="utf-8"))
claims["assurance"].update({
    "isolated_source_export": True,
    "committed_cargo_lock": True,
    "opened_executable_binding": True,
    "cache_only_cargo_home": True,
    "exclusive_external_report_output": True,
    "remediation_transition_verified": True,
})
claims_path.write_text(json.dumps(claims, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

state_path = ROOT / "state/phase9.json"
state = json.loads(state_path.read_text(encoding="utf-8"))
state["execution_boundary"].update({
    "exact_source_export": True,
    "source_export_read_only": True,
    "untracked_inputs_excluded": True,
    "tool_exec_via_open_descriptor": True,
    "cargo_home_cache_only": True,
    "cargo_target_outside_source": True,
    "report_output_external_private_exclusive": True,
})
state["probe_policy"]["cargo_mode"] = "frozen"
state["probe_policy"]["cargo_lockfile_committed"] = True
state["probe_policy"]["cargo_user_config_inherited"] = False
state["counterexample_policy"].update({
    "counterexample_id_stable_through_resolution": True,
    "resolved_requires_fail_before_pass_after": True,
    "resolved_failure_metadata_must_reproduce": True,
})
state["report_policy"]["generated_report_nested_schema_validated"] = True
state["report_policy"]["report_persisted_for_ci_artifact_upload"] = True
state["phase9_gate"] = (
    "For the exact clean checked-out commit, MORIARTY/1 exports only tracked bytes from the requested commit into a read-only private source tree; untracked repository inputs are excluded. "
    "Python, Git, Cargo, and rustc are executed through already-open validated executable descriptors while preserving the intended argv[0]. Cargo uses the committed Cargo.lock with cargo test --all-targets --frozen, a cache-only private CARGO_HOME with no ambient user configuration or credentials, and CARGO_TARGET_DIR outside the source export. "
    "The constitutional gate, every historical Phase 0-8 gate, and all accepted regressions execute under bounded process-group-isolated probes. Resolved findings must reproduce the recorded failure at target_commit and pass the same single fixed probe at resolution_commit; the counterexample identity remains stable across resolution. "
    "Reports are closed nested structures published exclusively to a private external directory without following a pre-existing destination. No unresolved reproducible counterexample or failed fixed probe may cross graduation. MORIARTY adds assurance only and does not promote the Phase 8 capability surface."
)
state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

counter_schema_path = ROOT / "schemas/moriarty-counterexample-v1.schema.json"
counter_schema = json.loads(counter_schema_path.read_text(encoding="utf-8"))
counter_schema["properties"]["regression_probe_ids"]["maxItems"] = 1
counter_schema_path.write_text(json.dumps(counter_schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

ai_path = ROOT / "README4AI.md"
ai = json.loads(ai_path.read_text(encoding="utf-8"))
ai["phase9_moriarty"].update({
    "isolated_exact_commit_export": True,
    "committed_cargo_lock": True,
    "cargo_frozen": True,
    "ambient_cargo_config_inherited": False,
    "opened_executable_descriptor_binding": True,
    "resolved_counterexample_fail_before_pass_after": True,
    "persistent_ci_report_artifact": True,
})
ai_path.write_text(json.dumps(ai, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

workflow_path = ROOT / ".github/workflows/ci.yml"
workflow = workflow_path.read_text(encoding="utf-8")
workflow = workflow.replace("      - name: Capture generated Cargo lockfile\n        run: |\n          echo '---BEGIN-QSOL-FED-CARGO-LOCK---'\n          cat Cargo.lock\n          echo '---END-QSOL-FED-CARGO-LOCK---'\n", "")
workflow = workflow.replace("run: cargo test --all-targets", "run: cargo test --all-targets --locked", 1)
workflow = workflow.replace("cargo run --quiet", "cargo run --locked --quiet")
old_phase9 = '''      - name: Phase 9 MORIARTY/1 exact-commit graduation gate
        env:
          MORIARTY_TARGET_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}
        run: python3 tools/validate_phase9_gate.py --target-commit "$MORIARTY_TARGET_COMMIT"
'''
new_phase9 = '''      - name: Phase 9 MORIARTY/1 exact-commit graduation gate
        env:
          MORIARTY_TARGET_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}
          MORIARTY_REPORT_DIR: ${{ runner.temp }}/moriarty-report
        run: |
          install -d -m 700 "$MORIARTY_REPORT_DIR"
          python3 tools/validate_phase9_gate.py --target-commit "$MORIARTY_TARGET_COMMIT" --report-dir "$MORIARTY_REPORT_DIR"
      - name: Preserve Phase 9 MORIARTY report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: phase9-moriarty-report-${{ github.run_id }}
          path: ${{ runner.temp }}/moriarty-report/*.json
          if-no-files-found: warn
          retention-days: 14
'''
if old_phase9 not in workflow:
    raise SystemExit("phase9 remediation CI phase9 block drift")
workflow = workflow.replace(old_phase9, new_phase9, 1)
workflow_path.write_text(workflow, encoding="utf-8")

docs_path = ROOT / "MORIARTY.md"
docs = docs_path.read_text(encoding="utf-8")
docs = docs.replace(
    "The runner resolves Python, Git, Cargo, and rustc to absolute executables outside the repository. Probe subprocesses receive an allowlisted environment rather than inheriting arbitrary caller variables: semantic credentials, proxy settings, execution wrappers, `PYTHONPATH`, and similar ambient controls are absent. Cargo credentials are rejected if present.",
    "The runner resolves Python, Git, Cargo, and rustc outside the repository, opens and validates the executable inode, and executes through `/proc/self/fd` while preserving the intended `argv[0]`. A pathname replacement after validation therefore cannot substitute the executed interpreter or tool. Probe subprocesses receive an allowlisted environment rather than inheriting caller credentials, proxy settings, wrappers, `PYTHONPATH`, or similar ambient controls.",
)
docs = docs.replace(
    "The Rust regression probe runs `cargo test --all-targets --offline` with `CARGO_NET_OFFLINE=true`. It may use the local Cargo cache but cannot contact a registry or Git dependency source during MORIARTY execution. QSOL-FED does not currently carry a committed `Cargo.lock`, so Phase 9 does not pretend `--frozen` is available; adding a reviewed lockfile is the path to a later locked-and-offline probe.",
    "The Rust regression probe runs `cargo test --all-targets --frozen` against the committed `Cargo.lock`. `--frozen` combines locked dependency resolution with offline execution, so Cargo cannot rewrite dependency resolution or contact a registry or Git source. MORIARTY projects only registry cache material into a private cache-only `CARGO_HOME`; user Cargo configuration and credentials are not inherited. Build artifacts go to an external `CARGO_TARGET_DIR`, never into the read-only source export.",
)
docs = docs.replace(
    "The clean-tree check runs before probes, around each probe, and before the final report. Untracked build outputs such as `target/` are not part of the exact-commit claim; tracked validator or probe changes are. A dirty tracked tree cannot graduate an unchanged Git SHA.",
    "The clean-tree check still rejects tracked source/index drift, but probes do not execute from that mutable checkout. The runner creates a read-only exact-commit export from `git archive`, rejects archive links/special files, and executes every fixed probe from that export. Untracked files, including an untracked repository-local `.cargo/config.toml`, are therefore absent from the execution tree rather than merely ignored by `git diff`.",
)
docs = docs.replace(
    "A syntactically plausible but nonexistent SHA is therefore not remediation evidence. An unresolved accepted finding blocks graduation, but its regression probes still execute before the final graduation decision so a fix can demonstrate that the regression has gone green.",
    "A syntactically plausible but nonexistent SHA is therefore not remediation evidence. In addition, a resolved record is replayed in isolated exports: its single fixed regression probe must reproduce the recorded failure kind, exit semantics, hashes, and byte counts at `target_commit`, then return zero at `resolution_commit`. This is explicit fail-before/pass-after remediation evidence. `counterexample_id` hashes only immutable discovery/reproduction facts, so the finding identity remains stable through resolution. An unresolved accepted finding blocks graduation, but its regression still executes before the final decision.",
)
docs = docs.replace(
    "A successful report requires every fixed probe to return zero and every accepted counterexample to be resolved. If the runner returns nonzero, the gate validates the common report structure first and emits a compact diagnostic containing failed probe IDs, exit codes, output hashes/byte counts, counterexample IDs and unresolved state before CI exits. The temporary full report need not survive for its reproduction metadata to remain visible in the job log.",
    "A successful report requires every fixed probe to return zero and every accepted counterexample to be resolved. The gate mirrors the closed nested report schema for each probe result and counterexample, rejects undeclared raw-output fields, malformed digests, invalid byte counts, and inconsistent graduation state. Reports are created exclusively with no-follow semantics inside a private external directory, never inside the repository or through a pre-existing destination, and CI uploads the report artifact even when graduation fails.",
)
docs = docs.replace(
    "python3 tools/validate_phase9_gate.py --target-commit \"$TARGET\"",
    "REPORT_DIR=\"$(mktemp -d)\"\nchmod 700 \"$REPORT_DIR\"\npython3 tools/validate_phase9_gate.py --target-commit \"$TARGET\" --report-dir \"$REPORT_DIR\"",
)
docs = docs.replace(
    "  --output /tmp/moriarty-report.json",
    "  --output \"$REPORT_DIR/moriarty-report.json\"",
)
docs_path.write_text(docs, encoding="utf-8")

# Remove the one-shot transformer and its workflow from the committed result.
(ROOT / "tools/apply_phase9_remediation.py").unlink()
workflow_self = ROOT / ".github/workflows/apply-phase9-remediation.yml"
if workflow_self.exists():
    workflow_self.unlink()
