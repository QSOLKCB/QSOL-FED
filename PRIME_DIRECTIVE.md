# Federation Prime Directive

**Document:** `qsol-fed-prime-directive/1`

## Rule

A Federation member may exchange information, evidence, requests and voluntarily accepted capabilities with another member, but may not silently alter that member's governance, memory, identity, evidence state, authority structure or execution environment.

The receiver always retains the final local admission decision.

## Hard prohibitions for v1

A remote peer MUST NOT be able to cause any of the following merely through Federation protocol input:

1. mutate local governance;
2. promote or rewrite local evidence status;
3. create, delete or reweight a local Council vote;
4. install or enable a local capability;
5. rewrite or relabel local history;
6. change local citizenship, identity authority or role authority;
7. execute arbitrary local tools, commands or code;
8. claim local authority on the basis of remote identity, consensus or signature;
9. convert foreign state into local authoritative state by import alone;
10. place secrets or credentials into semantic Federation state;
11. disable or weaken this directive at runtime.

## Allowed classes of interaction

Subject to authentication, validation, provenance and local policy, a peer MAY:

- announce protocol identity and supported capabilities;
- offer evidence or request evidence;
- offer a hypothesis;
- issue a challenge or response;
- submit a Council report or minority report;
- submit an experiment receipt;
- submit citations or publication references;
- request a locally defined, explicitly admitted non-authority-bearing operation in a future protocol version.

Receiving an allowed message still does not make its content true, trusted or authoritative.

## Admission states

The reference policy uses three conceptual outcomes:

```text
ACCEPT_AS_DATA
QUARANTINE
REJECT
```

`ACCEPT_AS_DATA` means the material may enter a foreign/attributed data path. It does **not** mean evidence promotion, trust, execution or authority.

`QUARANTINE` means the material is structurally recognizable but cannot cross into a local live domain without another explicit local process.

`REJECT` means the requested effect violates the constitutional boundary or is unknown and authority-bearing.

## Mandatory ordering

No transport or integration is allowed to bypass constitutional admission:

```text
receive
  -> framing and size checks
  -> protocol parse
  -> authentication/signature checks
  -> replay/expiry checks
  -> capability checks
  -> PRIME DIRECTIVE GATE
  -> local adapter
```

A future implementation may reject earlier. It may not admit an otherwise forbidden action earlier.

## No emergency backdoor

The protocol does not define a peer-controlled `override`, `admin`, `emergency`, `root`, `force`, `trusted=true`, `please=true`, or equivalent field that disables these rules.

A local operator can always modify their own software outside the protocol. That is a source/operational act, not Federation authority. QSOL-FED must not pretend software invariants are physically unchangeable; the security property is that they are **not remotely or runtime-configurably bypassable by protocol participants**.

## Amendment boundary

Weakening a hard prohibition is a constitutional change. It requires explicit source modification, tests, threat-model review and protocol compatibility analysis. An ordinary feature flag is insufficient.
