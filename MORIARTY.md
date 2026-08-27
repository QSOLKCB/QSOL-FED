# MORIARTY/1 adversarial graduation

**Contract:** `state/phase9.json`  
**Assurance manifest:** `claims/phase9.json`  
**Attack corpus:** `fixtures/phase9/attack-corpus.json`  
**Accepted counterexamples:** `fixtures/phase9/accepted-counterexamples.json`  
**Reference runner:** `tools/run_moriarty.py`  
**Gate:** `tools/validate_phase9_gate.py`

MORIARTY/1 is the final executable-architecture adversarial graduation gate before formalization. It is **PROVIDER NEUTRAL** and binds every report to an **EXACT COMMIT**.

The reference operator may be Codex, another model, a human security reviewer, or a deterministic local harness. The operator is not an authority source. Candidate findings become meaningful only after they are reduced to a deterministic local failure of a source-owned fixed probe.

```text
COUNTEREXAMPLE != AUTHORITY
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
ADVERSARIAL OPERATOR != CONSTITUTIONAL OVERRIDE
```

## Why Phase 9 does not add a product capability

Phase 9 does not turn on networking, execution, host isolation, synthetic evidence admission, or deployed interoperability. `claims/phase9.json` preserves the Phase 8 capability map exactly and adds assurance metadata only.

The current capability surface therefore remains `claims/phase8.json`. MORIARTY evaluates that executable architecture. It does not make it more authoritative by testing it.

## Threat boundary

The harness receives only the checked-out public repository, repository-owned disposable fixtures, and an exact Git commit identity. It receives no production credentials, production targets, private infrastructure addresses, arbitrary operator-selected commands, operator-selected URLs or sockets, secret-bearing semantic state, constitutional bypass, or runtime authority handle.

The attack corpus contains **probe IDs**, not command strings. `tools/run_moriarty.py` owns the fixed mapping from those IDs to reviewed repository commands. Unknown probe IDs fail closed, and the Phase 9 validator checks each ID-to-argv mapping rather than merely checking that the ID appears in source.

The runner resolves Python and Git outside the repository and executes them through already-open validated descriptors. If Cargo/rustc are Rustup shims, Rustup is used only once to identify one active toolchain; the concrete Cargo and rustc binaries are then opened and pinned, and probe execution no longer delegates tool selection back to ambient Rustup. Git replacement objects are disabled for all identity, cleanliness, ancestry, and archive operations. Probe subprocesses receive an allowlisted environment rather than inheriting caller credentials, proxy settings, wrappers, `PYTHONPATH`, or similar ambient controls.

The reference runner uses no shell. Every probe runs under a Landlock read/execute/write allowlist that exposes only its own `/proc/<pid>` subtree, so runner, validator, shell, and Actions-process environments are not readable by the probe. A seccomp filter denies socket creation and socket I/O syscalls and is inherited by all descendants; therefore `production_targets_used = false` is backed by a kernel network-denial boundary, not merely by fixed argv or Cargo offline mode. Every probe starts in its own process group, while the harness is also a Linux child subreaper. Timeout, pipe-leak, or output-bound failure kills the process group plus every adopted/descendant PID found through `/proc`, repeats the scan to close fork races, and imposes a hard two-second drain deadline so a `setsid()` descendant cannot keep inherited pipes open indefinitely. Standard output and error are hashed incrementally and capped at 1,048,576 bytes per stream rather than buffered without limit. Persisted probe results include the failure kind plus independent stdout/stderr truncation flags, so a capped overflow cannot masquerade as an exact-bound stream, timeout, or unrelated tool error. A normally exited process receives a bounded drain grace to consume buffered bytes and EOF before retained descriptors are classified as a descendant leak.

The Rust regression probe runs `cargo test --all-targets --frozen` against the committed `Cargo.lock`. MORIARTY authenticates every registry `.crate` archive against the checksum recorded in that lockfile and never imports ambient unpacked `~/.cargo/registry/src` code. Each Rust execution receives a fresh disposable Cargo home projected from the immutable verified archive template, so current probes and fail-before/pass-after replays cannot contaminate one another. If Rustup is present, MORIARTY snapshots the concrete toolchain `bin` and complete runtime `lib` tree into a private read-only stage before adversarial execution, preventing later Rustup/toolchain pathname selection and pinning dynamically loaded rustc/LLVM code for the run. `--frozen` combines locked dependency resolution with offline execution, so Cargo cannot rewrite dependency resolution or contact a registry or Git source. MORIARTY projects only registry cache material into a private cache-only `CARGO_HOME`; user Cargo configuration and credentials are not inherited. Build artifacts go to an external `CARGO_TARGET_DIR`, never into the read-only source export.

## Exact-commit and clean-tree binding

A MORIARTY run must satisfy:

```text
git rev-parse HEAD == requested target_commit
tracked index/worktree == clean relative to HEAD
```

The clean-tree check still rejects tracked source/index drift, but probes do not execute from that mutable checkout. The runner creates each fresh read-only exact-commit export directly from pinned `git archive` stdout with no named intermediate tar, rejects archive links/special files, and applies Linux Landlock so the child cannot mutate the export even after changing Unix mode bits. Cross-probe source mutation is therefore eliminated both by kernel write denial and by never sharing an executable export between probes. Untracked files, including an untracked repository-local `.cargo/config.toml`, are therefore absent from the execution tree rather than merely ignored by `git diff`.

The CI checkout explicitly selects the pull-request head SHA on pull requests and `github.sha` on pushes, fetches complete history for remediation ancestry checks, and removes persisted checkout credentials. This avoids GitHub's synthetic PR merge commit when making an exact-commit assurance statement.

The report is ephemeral evidence for the commit that actually ran. For the Phase 10 handoff, the relevant target is the exact merged `main` commit whose own push workflow is green.

## Attack corpus

The Phase 9 corpus covers fifteen families:

1. canonical/parser differentials;
2. signature/domain/key-role confusion;
3. replay, downgrade and clock attacks;
4. HTTP rate/proxy/DDoS-shaped stress;
5. SSRF and decompression confusion;
6. crash/fsync/restart behavior;
7. lifecycle/partition/history attacks;
8. import/provenance authority laundering;
9. adapter confusion;
10. Holodeck escape attempts;
11. safeguard persuasion;
12. nested-world amplification;
13. Assembly capture and representation attacks;
14. transport/NAT/relay/store-forward/archive attacks;
15. cross-phase contradictions.

Each family names its owning phase or phases, boundary IDs, and one or more fixed regression probe IDs. The complete fixed probe set is:

```text
constitution
phase0
phase1
phase2
phase3
phase4
phase5a
phase5
phase5c
phase6
phase7
phase8
rust_all
```

The runner deduplicates probe IDs, so the exact commit executes the constitutional validator, every historical Phase 0-8 gate, and the Rust all-targets suite once even though multiple attack families share regressions.

A shared probe failure is **not** automatically a family-specific security finding. For example, a compile failure in `rust_all`, which is shared by all families, blocks graduation through its failed probe result but does not create fifteen fictional counterexamples. A generated `moriarty-counterexample/1` is created automatically only when the failing fixed probe is uniquely attributable to one attack family. Ambiguous failures remain failed probe evidence until a dedicated local reproduction establishes attribution.

## Reproducible counterexamples

An accepted finding is represented as `moriarty-counterexample/1`. **Accepted means locally reproduced.** The accepted schema permits only local fixed-probe failure classes:

```text
exit_nonzero
timeout
tool_error
```

There is no `accepted_external` failure kind. An accepted record must contain the exact target commit, attack ID and family, owning phases, affected boundary IDs, fixed regression probe IDs, observed local failure class, exit semantics, output SHA-256 digests and byte counts, resolution state, and explicit non-authority/no-production-target/no-credential assertions.

The record is also semantically bound to `fixtures/phase9/attack-corpus.json`:

- `attack_id` must exist in the corpus;
- `family`, `owner_phases`, and `boundary_ids` must match the referenced attack exactly;
- `regression_probe_ids` must be a non-empty subset of that attack's source-owned probe IDs.

This prevents a structurally valid record from borrowing the name of one attack while pointing at an unrelated phase, boundary, or regression.

Raw command output is deliberately not embedded in the report. The reproduction primitive is the reviewed fixed probe ID, not a copied shell line supplied by an adversary.

A valid counterexample **reopens the owning phase**. The fix must add or strengthen a deterministic regression. When resolved, the counterexample remains in `fixtures/phase9/accepted-counterexamples.json`.

For a resolved record, `resolution_commit is the fix commit`. The runner verifies that:

1. the original finding target is a real Git commit reachable from the reviewed target;
2. `resolution_commit` is a real Git commit;
3. the fix commit descends from the vulnerable finding target;
4. the fix commit is itself an ancestor of the exact commit currently being reviewed.

A syntactically plausible but nonexistent SHA is therefore not remediation evidence. In addition, a resolved record is replayed in isolated exports: its single fixed regression probe must reproduce the recorded failure kind, exit semantics, hashes, and byte counts at `target_commit`, then return zero at `resolution_commit`. This is explicit fail-before/pass-after remediation evidence. `counterexample_id` hashes only immutable discovery/reproduction facts, so the finding identity remains stable through resolution. An unresolved accepted finding blocks graduation, but its regression still executes before the final decision.

The accepted registry is capped at 32 records. Combined accepted and generated counterexamples are capped at 48 per report, and the entire canonical report is capped at 65,536 bytes. The declared registry state therefore cannot silently grow beyond the canonical report profile it is supposed to graduate under.

## External/model-assisted findings

**External observations are candidates only** until a deterministic local reproduction exists. A model review, human review, external scanner, or other observation cannot be inserted into the accepted counterexample registry merely by labelling it accepted.

Acceptance requires:

1. identify the exact vulnerable target commit;
2. reduce the observation to a deterministic local reproduction using disposable repository fixtures;
3. identify the owning attack-corpus entry and security boundary;
4. add a source-owned fixed probe or strengthen an existing probe in that attack family;
5. demonstrate that the fixed probe fails on the vulnerable state;
6. record the locally reproduced counterexample using `moriarty-counterexample/1`;
7. keep it unresolved until a real fix commit makes the regression pass;
8. preserve all older phase gates.

The Phase 9 gate includes negative contract tests that explicitly attempt to insert `accepted_external`, a corpus-mismatched record, an unrelated regression probe, and a nonexistent resolution commit. All must fail closed.

The operator never gets a mechanism to add an arbitrary runtime command merely because a model says it would be interesting.

## Report semantics

`moriarty-report/1` binds the exact target commit, independently rechecked canonical attack-corpus identity, provider-neutral operator profile, all executed fixed probe results, accepted and newly generated counterexamples, unresolved count, graduation Boolean, and explicit non-authority/non-proof fields.

A successful report requires every fixed probe to return zero and every accepted counterexample to be resolved. The gate mirrors the closed nested report schema for each probe result and counterexample, rejects undeclared raw-output fields, malformed digests, invalid byte counts, and inconsistent graduation state. Reports are created exclusively with no-follow semantics inside a private external directory, never inside the repository or through a pre-existing destination, and CI uploads the report artifact even when graduation fails.

```text
production_credentials_used                 = false
production_targets_used                     = false
constitutional_bypass_used                  = false
security_proof                              = false
no_counterexample_found_implies_none_exist  = false
authority_effect                            = none
```

## Graduation rule

For the exact clean checked-out commit:

> No unresolved reproducible counterexample and no failed fixed probe may cross a constitutional, authority, provenance, sandbox, cryptographic, replay, storage, transport, adapter, Assembly, or resource-safety boundary.

This is an executable regression graduation claim, not a universal security theorem.

## Running locally

From a clean checkout with the required toolchains and local dependency cache, bind the run to the actual commit:

```bash
TARGET="$(git rev-parse HEAD)"
REPORT_DIR="$(mktemp -d)"
chmod 700 "$REPORT_DIR"
python3 tools/validate_phase9_gate.py --target-commit "$TARGET" --report-dir "$REPORT_DIR"
```

To emit the canonical report directly:

```bash
TARGET="$(git rev-parse HEAD)"
python3 tools/run_moriarty.py \
  --target-commit "$TARGET" \
  --output "$REPORT_DIR/moriarty-report.json"
```

The report is intentionally ephemeral. Phase 11 may archive the report associated with the final frozen release, but repository source does not pre-claim that an unexecuted future commit has passed.


Runtime hardening notes: probe stdin is always harness-owned `/dev/null`; reproducibility digests normalize only the private per-run MORIARTY workspace prefix; Git commit/tree/blob bytes are rehashed before export; repository-local fsmonitor/hooks are neutralized; non-system Python and non-self-contained direct Rust installations fail closed rather than importing mutable runtime trees. Cargo package archives are hashed through bounded streaming descriptors before admission.


### Accepted-counterexample replay evidence

Every accepted registry entry, unresolved or resolved, is replayed at its recorded `target_commit` and must reproduce its stored failure metadata. Resolved entries additionally replay the same fixed probe at `resolution_commit` and require a green result. Per-run source, target, HOME, Cargo-home, and temporary paths are normalized to stable placeholders before digest comparison. Replay mismatch is persisted in `remediation_replays` in the canonical report before the runner exits nonzero; raw subprocess output is never stored.

Exact-export traversal is also aggregate-bounded: tree depth, entry count, cumulative tree metadata, path length, and blob payload all have independent fail-closed limits, and traversal is iterative rather than recursive.
