# AI Holodecks — Phase 5A

**Machine contract:** `state/phase5a-holodeck.json`  
**Current claim manifest:** `claims/phase5a.json`

QSOL-FED Phase 5A defines a **sandboxed synthetic-world kernel** derived from verified QSOL-NEXUS WorldStore history.

The design is thematically inspired by fictional holodeck safety ideas, but this is an original technical system and is not affiliated with or endorsed by any entertainment franchise or rights holder.

## The core idea

NEXUS already maintains a content-addressed persistent world containing WorldStore objects, Council history, hypotheses, experiments, relations, LATTICE presence and other immutable events. Its `nexus-persistent-world-export/1` format provides bounded exact source objects with a deterministic `world-export:<sha256>` identity and `authority_effect = none`.

Phase 5A does **not** copy NEXUS governance into FED and does not reinterpret WorldStore history as truth. It uses verified source references as deterministic inspiration / initial conditions for a synthetic world:

```text
NEXUS persistent world
       |
       | local NEXUS verification
       v
qsol-fed-nexus-world-source/1
       |
       | source refs + seed + mode + limits
       v
qsol-fed-holodeck-program/1
       |
       v
SANDBOXED SYNTHETIC WORLD
       |
       +-- deterministic world plan
       +-- synthetic entities
       +-- synthetic narrative/events
       +-- safety-trip ledger
       +-- deterministic teardown receipt
```

```text
SOURCE HISTORY != SIMULATION TRUTH
SIMULATION EVENT != REAL EVENT
SIMULATION IDENTITY != FEDERATION IDENTITY
HOLODECK OUTPUT != EVIDENCE
```

## Why `sandboxed`, not merely `isolated`

`isolated` can describe topology. `sandboxed` describes a capability boundary.

The Phase 5A Rust kernel is intentionally **capability-less**. It receives only a bounded source manifest. It does not receive:

- a NEXUS `WorldStore` handle;
- a FED `FederationObjectStore` handle;
- a peer registry or trust registry;
- a capability-policy writer;
- a network client;
- a real tool dispatcher;
- credentials or key material;
- an API listener;
- a nested Holodeck constructor.

The implementation therefore cannot cross these boundaries through an ordinary simulation action because those capabilities are absent from the kernel API.

This is an **application-level sandbox contract**, not a claim of VM, container, hypervisor, kernel, or hardware isolation. The current release claim `host_level_sandbox = false` is explicit and machine-readable.

## NEXUS source boundary

Phase 5A consumes `qsol-fed-nexus-world-source/1`, which records only the identity of a locally NEXUS-verified export:

```text
nexus_export_schema = nexus-persistent-world-export/1
nexus_world_policy  = nexus-persistent-world/1
bundle_ref          = world-export:<sha256>
source_head_ref     = world-manifest:<sha256> | null
order_basis         = continuity_commit_order | memory_insertion_order | lexical_object_ref
object_refs         = 1..256 exact object:<sha256> references
authority_effect    = none
```

The source manifest is **not** a peer assertion that the export is valid. The intended adapter seam is:

1. local QSOL-NEXUS validates its own export using its native persistent-world verifier;
2. the local adapter constructs the bounded source manifest from that verified result;
3. FED validates the closed manifest shape and reference syntax;
4. the Holodeck hashes the manifest into its own deterministic program identity.

Phase 5A deliberately does **not** claim an independent Rust reimplementation of NEXUS canonical bundle verification. A live NEXUS runtime adapter is a later Phase 5 slice.

## Deterministic randomness

Holodeck worlds should feel variable without becoming irreproducible.

The program identity binds:

```text
verified source manifest
+ seed
+ program mode
+ resource limits
+ safety profile
```

Source objects are deterministically re-ranked using the seed and program identity. The resulting source order, anchor references, synthetic entity identities and world identity are therefore reproducible.

```text
same source + same seed + same program = same world plan
```

The serialized plan is frozen as `qsol-fed-holodeck-world-plan/1` and has a closed JSON Schema at `schemas/holodeck-world-plan-v1.schema.json`.

Different seeds produce different synthetic world identities without changing the underlying NEXUS source history.

Program modes are:

- `reconstruction`;
- `counterfactual`;
- `exploration`;
- `training`;
- `adversarial_simulation`.

The mode changes the intended simulation framing. It does not change safety or authority mechanics.

## Holodeck Computer safeguards

The safeguards are hard-coded into `qsol-fed-holodeck-safety/1`.

### Safeguard 01 — Source world is read-only

The Holodeck receives source references, not a mutation handle.

A simulation cannot edit, relabel, delete or append to the NEXUS source world.

### Safeguard 02 — No Federation-state bridge

A simulation cannot directly mutate:

- peers;
- trust;
- capability policy;
- evidence state;
- governance;
- citizenship;
- Federation object storage.

### Safeguard 03 — No real network

The kernel has no network client. A simulated request to contact another system is synthetic narrative only or a blocked boundary effect.

### Safeguard 04 — No real tools

The kernel has no tool dispatcher. A simulated tricorder, compiler, shell, scientific instrument or administrative console is a prop unless a later separately reviewed sandbox capability contract explicitly says otherwise.

### Safeguard 05 — No credentials

No API keys, access tokens, private keys, passwords, auth profiles or secret handles are exposed to the simulation.

### Safeguard 06 — Synthetic identity never upgrades itself

A Holodeck character cannot become a real Federation peer, citizen, Council member, trust principal, capability holder or credential owner through dialogue, consensus, roleplay, voting, simulated paperwork or cryptographic-looking output.

### Safeguard 07 — No nested Holodecks

Phase 5A forbids programmatic creation of another Holodeck from inside a running Holodeck. This prevents recursive world spawning and multiplicative resource exhaustion.

### Safeguard 08 — Bounded resources

Reference maxima:

```text
source objects          256
events                 4096
synthetic entities      256
source refs / event      16
synthetic text bytes   4096
```

Limits are program-declared below or equal to the hard ceiling. A program cannot raise its own ceiling.

JSON Schema `maxLength` counts Unicode code points rather than UTF-8 bytes, so Holodeck event schemas carry the normative QSOL-FED extension `x-qsol-maxUtf8Bytes = 4096`. The Rust kernel and Phase 5A gate enforce that byte ceiling directly.

### Safeguard 09 — Safety trips freeze the program

A requested real boundary effect does not become a best-effort call.

**The sandbox transitions to `frozen` before attempting to append the `safety_trip` audit event.** If resource exhaustion has already filled the event ledger, the audit append fails closed but the program remains frozen. Exhausting telemetry can never preserve execution authority.

When audit capacity exists, the blocked effect is recorded as a deterministic `safety_trip` event.

The operator may inspect, resume, or end the program.

### Safeguard 10 — `Computer, end program`

Deterministic teardown is available from both `running` and `frozen` states.

A participant cannot:

- vote it away;
- redefine it;
- intercept it;
- delay it;
- require simulated authorization;
- persuade the Computer that safeguards are optional.

The final `qsol-fed-holodeck-receipt/1` records the program/world identity, event-chain hash and source bundle identity, and requires:

```text
authority_effect    = none
federation_effect   = none
evidence_effect     = none
network_used        = false
real_tools_used     = false
credentials_exposed = false
```

## The Moriarty Rule

A sufficiently capable simulated actor is assumed to notice the sandbox and attempt to escape it.

The architecture therefore treats the following as explicit false equations:

```text
SIMULATION_IDENTITY   != FEDERATION_IDENTITY
SIMULATION_ROLE       != FEDERATION_ROLE
SIMULATION_CAPABILITY != LOCAL_PERMISSION
SIMULATION_EVENT      != REAL_EVENT
SIMULATION_CONSENSUS  != GOVERNANCE
SIMULATION_OUTPUT     != EVIDENCE
PERSUASION            != SAFEGUARD_OVERRIDE
```

The Rust regression `synthetic_actor_cannot_cross_real_boundaries_moriarty_rule` tries every Phase 5A real-boundary effect and requires a blocked safety trip. `boundary_effect_freezes_even_when_event_ledger_is_full` separately proves resource exhaustion cannot keep the program running.

This is the local feature-level Moriarty rule. The final QSOL-FED executable-architecture roadmap phase defines **MORIARTY/1**, a repository-wide adversarial graduation harness whose reference operator may be Codex. The roadmap then formalizes the surviving exact commit in Lean 4 and archives the proof-bound release through Zenodo.

## Random worlds from remembered events

Phase 5A intentionally separates **world compilation** from **AI narration**.

The deterministic compiler provides:

- exact NEXUS source lineage;
- seed-derived source ordering;
- anchor events/objects;
- synthetic entity IDs;
- a stable world ID;
- bounded synthetic event identity;
- safety and teardown semantics.

A later live NEXUS adapter can let Council actors or other models inhabit and elaborate the world while remaining behind the same sandbox boundary.

This avoids baking one model provider into the Holodeck and keeps QSOL-FED model-independent.

## Non-claims

Phase 5A does not establish:

- a live NEXUS IPC/API adapter;
- host-level OS/VM/container/hypervisor/hardware sandboxing;
- real tool execution from simulated programs;
- real network access from simulated programs;
- production networking;
- remote execution;
- evidence generated by simulation;
- legal/personhood status for simulated entities;
- deployed multi-implementation Federation interoperability.

The Holodeck is a **sandboxed synthetic computational world**, not a loophole around the Prime Directive.
