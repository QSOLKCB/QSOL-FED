# Threat Model

## Assets

QSOL-FED must protect:

- local sovereignty and governance;
- evidence labels and provenance;
- Council integrity;
- local history;
- node identity keys and credentials;
- capability boundaries;
- execution environment;
- availability;
- protocol-version integrity.

## Adversaries

Assume a peer may be malicious, compromised, buggy, stale, spoofed, replaying old traffic, correctly authenticated but unauthorized, or attempting to exploit parser/resource limits.

Also assume local adapters and AI models can be wrong. Model confidence is not a security primitive.

Phase 9 additionally assumes that a repository-aware adversarial operator may deliberately search across phase boundaries for contradictions, authority laundering, parser splits, unsafe restart behavior, transport confusion, Assembly capture, or Holodeck escape paths. The operator is untrusted input to the review process, not an execution or authority principal.

## Primary threats

### T1. Authority injection

A peer submits a message that attempts to create local governance/evidence/voting authority.

**Mitigation:** hard-coded Prime Directive admission rejection; foreign material remains data-only by default.

### T2. Remote code/tool execution

A peer disguises executable instructions as a capability, payload, tool request or imported object.

**Mitigation:** arbitrary remote execution is absent/forbidden in v1; local adapters must not execute semantic payload content.

### T3. State laundering

Foreign state is imported and relabelled as locally authoritative merely because it is signed or content-addressed.

**Mitigation:** foreign state identity is preserved; import is not authority; local descendants require explicit local processes.

### T4. Consensus laundering

A remote Council majority is treated as evidence or a local vote.

**Mitigation:** remote Council reports are attributed artifacts only; consensus is not truth; vote injection is forbidden.

### T5. Capability confusion

Advertisement is mistaken for authorization, or version negotiation enables unknown behavior.

**Mitigation:** capability != entitlement; explicit version negotiation; unknown authority semantics reject.

### T6. Signature confusion

A valid signature is interpreted as truth, identity semantics or authorization.

**Mitigation:** signature/authentication and local admission are separate stages.

### T7. Replay

Captured valid envelopes are resent to produce duplicate effects.

**Mitigation:** durable message identity, expiry and replay state; replay freshness remains separate from authority and local admission.

### T8. Downgrade

A peer forces an older protocol/capability mode that weakens constitutional protections.

**Mitigation:** unsupported majors reject; no downgrade may disable constitutional invariants.

### T9. Resource exhaustion

Oversized/deep JSON, decompression bombs, object floods or expensive verification consume resources.

**Mitigation:** bounded framing, depth, size, rate, queue and cache policies; deterministic exhaustion drills cover API, Holodeck and transport surfaces.

### T10. SSRF / confused deputy

A peer causes the node to fetch arbitrary URLs or access local/cloud metadata services.

**Mitigation:** no arbitrary peer-directed fetch; reviewed fixed/disclosed retrieval mechanisms only.

### T11. Secret exfiltration

Credentials leak into payloads, logs, prompts or exported provenance.

**Mitigation:** separate operational secret state; semantic state prohibition; secret-aware logging and adapters.

### T12. Parser ambiguity / canonicalization split

Different implementations sign or hash semantically equivalent but byte-different structures.

**Mitigation:** frozen canonicalization, hostile fixtures and cross-language golden vectors.

### T13. Sybil / peer swarm

Many identities attempt to manufacture apparent consensus or exhaust resources.

**Mitigation:** Federation does not equate peer count with truth or authority; local peering/rate policies remain sovereign. Assembly registry uniqueness is not overclaimed as proof of real-world principal uniqueness.

### T14. Compromised trusted peer

A previously trusted key behaves maliciously.

**Mitigation:** trust never bypasses Prime Directive invariants; key lifecycle, compromise/recovery/revocation and local quarantine remain authoritative across transports.

### T15. Local adapter privilege escalation

A NEXUS/ORACLE/ARK adapter accidentally maps foreign data into local authority-bearing operations.

**Mitigation:** adapter calls preserve the same invariant IDs as the core node and remain data/observation/preservation membranes rather than authority bridges.

### T16. Cross-phase contradiction

Two individually valid phase contracts compose into a path that weakens an earlier invariant, for example transport changing identity semantics, Assembly output becoming a member-local command, or archival presence changing provenance meaning.

**Mitigation:** MORIARTY/1 maps explicit cross-phase attack families to every historical phase gate plus the complete Rust regression suite. A reproducible contradiction reopens the owning phase and becomes a permanent regression.

### T17. Adversarial-operator confused deputy

A model or human reviewer proposes a command, URL, credential, target, or constitutional bypass and the security harness executes it merely because it was supplied as an adversarial test.

**Mitigation:** the Phase 9 attack corpus contains source-owned probe IDs only. The runner owns a closed fixed argv map, invokes no shell, accepts no operator-selected command/network target/credential, and binds execution to the exact checked-out commit.

### T18. Security-report overclaim

A green adversarial run is described as proof that no vulnerability or counterexample exists.

**Mitigation:** every report hard-codes `security_proof = false` and `no_counterexample_found_implies_none_exist = false`.

## Current non-claims

The repository now implements historical identity, replay, reference API, state, Holodeck, adapter, SDK, Assembly and transport-resilience gates, but it still does not claim:

- production networking;
- arbitrary remote execution;
- host-level sandbox isolation;
- deployed interoperable federation;
- Holodeck synthetic output as ORACLE evidence;
- universal security merely because MORIARTY/1 is green.

Those claims require their own explicit evidence and reviewed promotion path. Phase 9 intentionally changes none of them.

## MORIARTY/1 adversarial boundary

MORIARTY receives public repository blueprints and disposable repository fixtures only. It receives no production credentials, production targets, private infrastructure endpoints, member-local authority handles, or constitutional bypass.

Accepted findings use `moriarty-counterexample/1`. A finding remains blocking until locally reproduced, assigned to its owning phase/boundary, repaired, and preserved as a regression.

```text
COUNTEREXAMPLE != AUTHORITY
ADVERSARIAL OPERATOR != EXECUTION AUTHORITY
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
```

## Residual risks

Phase 9 hardens the adversarial harness but does not eliminate every risk. The following residual risks are acknowledged, bounded, and intentionally not overclaimed as solved.

| ID | Residual risk | Why it remains | Bounding control |
|----|---------------|----------------|------------------|
| R1 | Kernel isolation is Linux-specific | Landlock ABI >= 3 and the seccomp policy are implemented only for Linux x86_64/aarch64 | The runner fails closed on any other platform rather than degrading to weaker isolation |
| R2 | Anonymous local IPC remains permitted | Some runtimes require connected local IPC | Addressable `socket()` and `connect()` are denied; only anonymous `AF_UNIX` `socketpair()` is admitted, so pathname and abstract-namespace services such as Docker/systemd/X11 cannot be named |
| R3 | Process-tree termination has a scan race | `/proc` descendant discovery is a sample rather than an atomic kernel primitive | Child-subreaper adoption, process-group SIGKILL, repeated rescans, harness-directed signal denial, and a hard two-second pipe-drain deadline bound the escape window |
| R4 | Git object identity uses SHA-1 | The repository's current Git object format is SHA-1 | Commit/tree/blob bytes are rehashed against their object IDs and replacement objects are disabled; this is exact repository identity, not a general SHA-1 security claim |
| R5 | Probe output is stored by digest and byte count only | Raw adversary-controlled output is intentionally excluded from reports | Readers must rerun the fixed probe locally to inspect semantics; report artifacts cannot silently launder raw output into authority |
| R6 | Truncated streams lose tail bytes | Streams are capped at 1,048,576 bytes per probe | Truncation is persisted as explicit `tool_error` metadata with per-stream flags, so capped output cannot masquerade as complete output |
| R7 | The attack corpus is closed and finite | Fifteen source-owned families cannot enumerate all possible attacks | `no_counterexample_found_implies_none_exist = false` is machine-enforced; external observations remain candidates until reviewed local reproduction |
| R8 | Shared-probe failures can be ambiguous | Several fixed probes cover multiple attack families | Ambiguous failures block graduation as failed-probe evidence without fabricating family-specific counterexamples |
| R9 | Host toolchains are trusted at pin time | Python, Git, Cargo, and rustc originate from the host | Bootstrap source bytes are target-verified; executable inode/size/mtime pinning, descriptor-bound execution, staged read-only Rust runtime snapshots, and directory-chain checks bound substitution rather than claiming immunity to an already-compromised host |
| R10 | The harness runs as the invoking user | Phase 9 does not claim a VM, container, or host-level sandbox (`host_level_sandbox = false`) | Landlock read/exec/write allowlists, self-only `/proc`, addressable-IPC denial, harness-signal denial, and ptrace/process-memory denial bound same-UID reach; kernel privilege escalation remains out of scope |
| R11 | CI infrastructure is trusted | GitHub-hosted runners, checkout actions, and artifact storage sit outside the MORIARTY kernel boundary | Exact PR-head/push SHA binding, `persist-credentials: false`, hash-verified source bootstrap, and locally rerunnable gates limit what CI compromise can silently forge |
| R12 | Cargo.lock currency is a maintenance risk | Frozen offline resolution pins dependencies but does not track upstream advisories | Dependency updates are ordinary reviewed commits that must repass every gate; MORIARTY greenness never implies dependency freshness |

None of these residual risks weakens the report semantics: a green MORIARTY report remains evidence about the exact reviewed regression surface only.

```text
RESIDUAL RISK ACKNOWLEDGED != RESIDUAL RISK ACCEPTED AS AUTHORITY
BOUNDED EXPOSURE != ZERO EXPOSURE
```

## Security invariant

The most important threat-model rule is intentionally boring:

> No amount of remote agreement, simulated persuasion, adversarial confidence, or green-report ceremony is itself permission to cross a local authority boundary.
