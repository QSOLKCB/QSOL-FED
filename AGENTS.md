# AGENTS.md

## Machine contribution contract

QSOL-FED is a security-sensitive federation boundary. Protocol convenience never overrides the Charter, Prime Directive, frozen historical contracts, or executable phase gates.

### Read first

Read `README4AI.md`, `CHARTER.md`, `PRIME_DIRECTIVE.md`, all historical/current `claims/*.json`, `invariants/fed-v1.json`, `wire/phase1.json`, `crypto/phase2.json`, `api/phase3.json`, `state/phase4.json`, `state/phase5a-holodeck.json`, `state/phase5.json`, `state/phase5c.json`, `state/phase6.json`, `state/phase7.json`, `state/phase8.json`, `state/phase9.json`, `CANONICAL_JSON.md`, `CRYPTOGRAPHY.md`, `API.md`, `TLS_PROFILE.md`, `FEDERATION_STATE.md`, `HOLODECK.md`, `QSOL_ADAPTERS.md`, `SDK.md`, `docs/THIRD_PARTY_INTEGRATION.md`, `ASSEMBLY.md`, `TRANSPORTS.md`, `MORIARTY.md`, `fixtures/phase9/attack-corpus.json`, `fixtures/phase9/accepted-counterexamples.json`, `src/invariants.rs`, `src/claims.rs`, `src/store.rs`, `src/peering.rs`, `src/bundle.rs`, `src/holodeck.rs`, `src/qsol_adapters.rs`, `src/oracle_live.rs`, `src/sdk.rs`, `src/assembly.rs`, `src/transport.rs`, `tools/run_moriarty.py`, `tools/validate_phase9_gate.py`, and `THREAT_MODEL.md` before changing security, state, simulation, adapter, SDK, governance, transport, archive, relay, NAT, resilience, adversarial-graduation, or assurance semantics.

### Core constitutional rules

No peer, model, config, request, signature, trust label, imported bundle, capability advertisement, persisted object, Holodeck program, simulated actor, Council report, ORACLE observation, ORACLE transport response, ARK record, SDK participant, Assembly proposal, Assembly vote, governance receipt, transport frame, NAT ticket, relay receipt, offline package, archive record, partition recovery path, adversarial persona, candidate finding, counterexample record, or MORIARTY report may directly create member-local governance authority, promote evidence, create/reweight local Council votes, install capabilities, rewrite history, mutate citizenship/identity authority, trigger arbitrary remote execution, place secrets in semantic state, or disable constitutional/Holodeck safeguards.

Unknown authority-bearing effects fail closed.

### Historical Phase 0–4 rules

`claims/phase0.json` is immutable historical release truth. Run `python3 tools/validate_phase0_gate.py`.

`wire/phase1.json` and `CANONICAL_JSON.md` freeze canonical bytes and identities. Rust/Python golden vectors remain byte-identical. Run `python3 tools/validate_phase1_gate.py`.

`crypto/phase2.json`, `CRYPTOGRAPHY.md`, and `claims/phase2.json` preserve Ed25519 identity, frozen clocks, key lifecycle, durable replay, and signature/trust/authority separation. A valid signature never bypasses local admission. Run `python3 tools/validate_phase2_gate.py`.

`api/phase3.json`, `API.md`, `TLS_PROFILE.md`, and `claims/phase3.json` preserve the six routes, canonical/body/rate limits, trusted proxy rules, local-recipient-before-replay, replay compaction, SSRF/redirect isolation, secret-safe audit, and opt-in listener. Run `python3 tools/validate_phase3_gate.py`.

`state/phase4.json`, `FEDERATION_STATE.md`, and `claims/phase4.json` preserve foreign/quarantine attribution, lifecycle prefix immutability, separate trust/policy, persist-before-live local changes, crash-recoverable namespace move, bounded offline bundles, and import `authority = none`. **Silent reconciliation remains forbidden; partition rejoin requires explicit reconciliation.** Run `python3 tools/validate_phase4_gate.py`.

### Historical Phase 5A Holodeck rules

`state/phase5a-holodeck.json`, `HOLODECK.md`, and `claims/phase5a.json` remain the historical synthetic-world contract.

The Holodeck is a capability-less application-level sandbox, not a host/VM/hardware sandbox claim. Synthetic identity, role, capability, event, consensus, or output never becomes Federation identity, permission, governance, real history, or evidence. Boundary violations freeze before audit append. **Computer, end program** cannot be blocked.

This is the feature-level **Moriarty Rule**. Run `python3 tools/validate_phase5a_gate.py`.

### Historical Phase 5 QSOL adapter rules

`state/phase5.json`, `QSOL_ADAPTERS.md`, and `claims/phase5.json` preserve the native NEXUS bridge, report-only Council federation, ORACLE non-authority observation membrane, and ARK offline preservation boundary.

NEXUS native verification remains pinned; Council import cannot inject votes or promote evidence; Council-of-Councils uses reports rather than a shared ballot; `SIMULATION != AUTHORITY`; ORACLE suggestions remain non-evidence; ARK archival presence is not authority or real-world-history proof. Run `python3 tools/validate_phase5_gate.py`.

### Historical Phase 5C QSOL-ORACLE live transport rules

`state/phase5c.json`, `claims/phase5c.json`, `contracts/oracle-fed-membrane-v1.json`, and `src/oracle_live.rs` preserve the attested local stdio ORACLE boundary.

Recompute donor release identity; verify every fingerprinted runtime file; stage and re-attest a private runtime before launch; fixed entrypoint `python3 -I tools/fed_transport.py serve`; no caller-selected command/URL/socket; normalize request IDs; bound stdout before process completion; never use `wait_with_output()`; `known | conflict | unknown` remain observations; `ledger_mutated = false`, `transport_authority = none`, `truth_claim = false`, `evidence_promotion = false`, and `authority_effect = none`. `oracle_holodeck_synthetic_admission = false` remains mandatory.

Run `python3 tools/validate_phase5c_gate.py`.

### Historical Phase 6 third-party SDK rules

`state/phase6.json`, `claims/phase6.json`, `SDK.md`, `docs/THIRD_PARTY_INTEGRATION.md`, and `src/sdk.rs` preserve the governance-neutral `qsol-fed-sdk/1` boundary.

Rust, Python, and TypeScript/JavaScript reference implementations must reproduce byte-identical conformance vectors. The neutral third-party node must retain local governance and require no NEXUS, ORACLE, ARK, Holodeck, or QSOL internal governance. The frozen `fed:qsol:` v1 namespace is wire syntax, not a loyalty oath. `SDK CONFORMANCE != TRUST` and `WIRE COMPATIBILITY != GOVERNANCE MEMBERSHIP`.

Run `python3 tools/validate_phase6_gate.py`.

### Historical Phase 7 Federation Assembly rules

`state/phase7.json`, `claims/phase7.json`, `ASSEMBLY.md`, `schemas/assembly-member-v1.schema.json`, `schemas/assembly-proposal-v1.schema.json`, `schemas/governance-receipt-v1.schema.json`, and `src/assembly.rs` preserve the Assembly boundary.

- Assembly membership is separate from Federation network membership.
- Network membership never grants Assembly membership or voting rights.
- Assembly admission requires explicit local opt-in.
- One active NFC-normalized representation subject is allowed per Assembly registry; this does **not** prove real-world principal uniqueness.
- Representation is `one-member-one-vote/1`; one member gets one immutable vote per proposal.
- Each proposal freezes its electorate when opened; later membership changes do not reweight that electorate.
- The deterministic `qsol-fed-charter-gate/1` maps declared effects to existing invariant IDs.
- A current-lineage proposal that conflicts with the Charter becomes `fork_required`; ordinary voting may not silently weaken the sitting constitutional lineage.
- NEXUS remains advisory-only with zero vote weight and no authority.
- Finalization is terminal; final outcomes live in receipts and active proposal capacity is reclaimed only after receipt derivation succeeds.
- Accepted proposals and governance receipts do not merge source, create tags/releases, upgrade members, or mutate a running protocol.
- `member_local_authority_mutated = false`, `protocol_changed_automatically = false`, and `authority_effect = none` remain mandatory.
- `src/assembly.rs` remains positive-capability allowlisted and contains no network/process/tool/member-authority handles.

`ASSEMBLY MEMBERSHIP != NETWORK MEMBERSHIP`, `ASSEMBLY VOTE != MEMBER-LOCAL COMMAND`, `NEXUS ADVICE != VOTE WEIGHT`, and `ASSEMBLY ACCEPTANCE != DEPLOYMENT` remain historical law.

Run `python3 tools/validate_phase7_gate.py`.

### Current Phase 8 capability rules

`state/phase8.json`, `claims/phase8.json`, `TRANSPORTS.md`, `schemas/transport-frame-v1.schema.json`, `schemas/nat-traversal-ticket-v1.schema.json`, `schemas/relay-receipt-v1.schema.json`, `schemas/offline-package-v1.schema.json`, `schemas/transport-drill-report-v1.schema.json`, and `src/transport.rs` define the current runtime/protocol capability boundary. Phase 9 adds assurance only and does not replace this claim manifest.

- WebSocket, QUIC, Unix/local IPC, offline/sneakernet and store-forward are reference **framing/resilience profiles**, not certified production socket services.
- Every profile carries the same bounded `qsol-fed-transport-frame/1` and preserves original `message_id`, `payload_ref`, and `provenance_ref`.
- A transport frame is data only and `authority_effect = none`.
- Phase 2 authenticated identity remains the identity source; transport profile or route may never replace sender identity.
- NAT tickets are short-lived route hints for WebSocket/QUIC only; ticket node must equal the already authenticated sender; NAT tickets grant no trust or authority and candidates may not embed credentials.
- Relay receipts are provenance only, max 16 hops, preserving original frame/message/payload identity and explicitly linking the prior receipt. Relay presence/count never creates trust or authority.
- Offline/sneakernet physical possession and archival presence never bypass local admission or become authority.
- Store-forward queues remain bounded to 1,024 active frames, reject duplicates, preserve FIFO order, and never silently reconcile local governance/trust/evidence state after a partition.
- A compromised or non-current key remains rejected on every transport. Phase 2 lifecycle remains authoritative; transport failover cannot revive a key or skip replay/local-admission checks.
- `qsol-fed-archive-compatibility/1` preserves historical canonical bytes and object identity; unknown future majors reject until an explicit migration contract; historical receipts are never silently reinterpreted.
- Every profile runs resource-exhaustion, partition, key-compromise, relay, archive and Holodeck-independence drills. NAT identity drills apply to WebSocket/QUIC.
- Holodeck transport is outside the sandbox. Carrying a receipt over a network does not rewrite the sandbox's `network_used = false`, and offline media does not make simulation authoritative.
- `src/transport.rs` is production-import allowlisted and must not import socket/process/filesystem backends or member-authority subsystems.

```text
TRANSPORT != IDENTITY
ROUTE != TRUST
RELAY != AUTHORITY
PARTITION RECOVERY != SILENT RECONCILIATION
NETWORK OUTSIDE HOLODECK != NETWORK INSIDE HOLODECK
REFERENCE TRANSPORT PROFILE != PRODUCTION NETWORK SERVICE
```

Run `python3 tools/validate_phase8_gate.py` after transport/schema/archive/NAT/relay/claim/roadmap changes.

### Current Phase 9 MORIARTY/1 adversarial graduation rules

`state/phase9.json`, `claims/phase9.json`, `MORIARTY.md`, `fixtures/phase9/attack-corpus.json`, `fixtures/phase9/accepted-counterexamples.json`, `schemas/moriarty-attack-corpus-v1.schema.json`, `schemas/moriarty-counterexample-v1.schema.json`, `schemas/moriarty-report-v1.schema.json`, `tools/run_moriarty.py`, and `tools/validate_phase9_gate.py` define the current executable-architecture assurance boundary.

- MORIARTY/1 is provider-neutral. Codex may be the reference operator, but model/operator output is never authority or a security proof.
- The checked-out Git `HEAD` must equal the requested exact target commit. Pull-request CI checks out the PR head SHA rather than GitHub's synthetic merge commit; push CI uses `github.sha`.
- The attack corpus contains source-owned probe IDs only. It cannot provide a shell command, executable path, URL, host, token, credential, production target, or constitutional override.
- The runner owns a closed argv map for the constitutional validator, every historical Phase 0–8 gate, and `cargo test --all-targets`. Unknown probe IDs reject.
- The runner uses no shell and receives no production credentials, production targets, arbitrary network targets, semantic execution handles, or constitutional bypass.
- The 15 attack families include parser/canonicalization, crypto/key role, replay/clock/downgrade, HTTP/resource, SSRF/decompression, crash/fsync/restart, lifecycle/partition/history, import/provenance laundering, adapters, Holodeck escape/persuasion/nesting, Assembly capture, transport/NAT/relay/store-forward/archive, and cross-phase contradictions.
- External/model-assisted findings are candidate findings only until reduced to a deterministic local reproduction with disposable repository fixtures.
- Every accepted finding is `moriarty-counterexample/1`, names the owning phase/boundary and fixed regression probe, and reopens that owning phase.
- Unresolved accepted findings block graduation. Resolved findings remain in the registry and their fixed probes remain regressions.
- `claims/phase9.json` is assurance metadata. Its capability map must equal `claims/phase8.json` exactly; `claims/phase8.json` remains the current capability manifest.
- The canonical report binds target commit and corpus identity, stores subprocess output hashes/byte counts rather than semantic raw output, and hard-codes `authority_effect = none`.

```text
COUNTEREXAMPLE != AUTHORITY
MORIARTY REPORT != SECURITY PROOF
NO COUNTEREXAMPLE FOUND != NO COUNTEREXAMPLE EXISTS
```

Run `python3 tools/validate_phase9_gate.py --target-commit "$(git rev-parse HEAD)"` after adversarial-contract/corpus/registry/report/gate/CI changes.

### Claim discipline

Historical capability manifests: `claims/phase0.json`, `claims/phase2.json`, `claims/phase3.json`, `claims/phase4.json`, `claims/phase5a.json`, `claims/phase5.json`, `claims/phase5c.json`, `claims/phase6.json`, `claims/phase7.json`. Current capability manifest: `claims/phase8.json`. Current adversarial-assurance manifest: `claims/phase9.json`.

Current hard-false capability claims include `oracle_holodeck_synthetic_admission`, `host_level_sandbox`, `production_networking`, `remote_execution`, and deployed `interoperable_federation`.

### Change discipline

Security-critical changes require synchronized source, machine contract, human docs, schemas, tests, claims, fixtures, and gate validators. Never weaken an old validator merely to make a successor pass. Convert current-state assumptions into historical preservation checks while retaining the old security semantics.

A Phase 9 finding must strengthen the owning regression surface rather than adding a one-off exemption to MORIARTY.

### Tests

```bash
cargo test --all-targets
python3 tools/validate_constitution.py
python3 tools/validate_phase0_gate.py
python3 tools/validate_phase1_gate.py
python3 tools/validate_phase2_gate.py
python3 tools/validate_phase3_gate.py
python3 tools/validate_phase4_gate.py
python3 tools/validate_phase5a_gate.py
python3 tools/validate_phase5_gate.py
python3 tools/validate_phase5c_gate.py
python3 tools/validate_phase6_gate.py
python3 tools/validate_phase7_gate.py
python3 tools/validate_phase8_gate.py
python3 tools/validate_phase9_gate.py --target-commit "$(git rev-parse HEAD)"
```

### Architecture rule

QSOL-NEXUS remains a Council service and possible Federation/Assembly participant, not the sovereign owner of QSOL-FED. QSOL-ORACLE remains an evidentiary membrane, QSOL-ARK an archive/recovery system, and third-party nodes remain possible without adopting QSOL governance. The Assembly governs protocol-evolution proposals only; it does not own member-local state. Phase 8 transports move already-identified protocol material; they do not become identity, trust, governance, evidence, or execution authorities. Phase 9 attacks and reports measure the reviewed boundary; they do not become authority, capability, or proof.

### Security comedy clause

A valid signature is not trust, a bundle is not authority, an ORACLE suggestion is not evidence, an archive is not truth, `fed:qsol:` is not a loyalty oath, an Assembly supermajority is not `sudo`, a NAT candidate is not a passport, a relay is not a bishop conferring legitimacy, and Professor Moriarty still does not get `admin=true` because it would improve the plot.
