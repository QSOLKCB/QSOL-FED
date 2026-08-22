# Architecture

## 1. Purpose

QSOL-FED is a federation layer for **sovereign computational systems**. Its purpose is interoperability without forced convergence.

The architecture separates constitutional authority from transport convenience:

```text
+----------------------------------------------------------+
|                   FEDERATION CHARTER                     |
| sovereignty, rights, obligations, amendment boundaries  |
+----------------------------+-----------------------------+
                             |
+----------------------------v-----------------------------+
|                    PRIME DIRECTIVE                       |
| deterministic non-interference admission boundary       |
+----------------------------+-----------------------------+
                             |
+----------------------------v-----------------------------+
|                    FEDERATION PROTOCOL                   |
| identity, envelopes, provenance, capabilities, versions |
+----------------------------+-----------------------------+
                             |
+----------------------------v-----------------------------+
|                    REFERENCE API                         |
| HTTP/JSON now; other transports may carry same envelope |
+----------------------------+-----------------------------+
                             |
+----------------------------v-----------------------------+
|                    LOCAL ADAPTERS                        |
| NEXUS | ORACLE | ARK | research nodes | third parties   |
+----------------------------------------------------------+
```

## 2. Sovereignty boundary

Every node owns its own:

- governance;
- evidence state;
- local history;
- identities and citizenship semantics;
- execution environment;
- capability admission;
- secrets;
- persistence rules;
- local trust configuration.

A Federation message can carry claims *about* these things. It cannot modify them directly.

## 3. Federation node

A reference node eventually contains:

```text
Inbound Transport
      |
      v
Framing / Size Limits
      |
      v
Protocol Decoder
      |
      v
Signature + Identity Verification
      |
      v
Replay / Expiry Checks
      |
      v
Capability Admission
      |
      v
PRIME DIRECTIVE GATE
      |
      +---- reject
      |
      +---- quarantine/data-only
      v
Local Adapter Boundary
      |
      v
Local System Decision
```

No parser, transport, signature verifier or peer identity layer bypasses the Prime Directive gate.

## 4. Federation envelope

The protocol unit is a canonical envelope, not an HTTP endpoint. A conceptual envelope includes:

```text
protocol
message_id
sender
recipient
message_class
payload_ref
provenance_ref
issued_at
expires_at
authority_claim = none
signature
```

The exact canonicalization and signature suite are deferred to a reviewed protocol phase. PR #1 defines the structure and claim boundary only.

## 5. Data plane vs authority plane

QSOL-FED deliberately has a rich **data plane** and a tiny **authority plane**.

Foreign peers may offer data. They do not receive local authority.

Examples:

| Foreign input | Local interpretation |
|---|---|
| evidence offer | attributed foreign material |
| Council report | attributed foreign deliberation artifact |
| hypothesis | foreign proposal |
| experiment receipt | foreign execution claim/receipt pending verification |
| capability advertisement | claim that peer supports a capability |
| publication | foreign publication object |

None of these automatically become local evidence, votes, capabilities, executable instructions or truth.

## 6. QSOL-NEXUS relationship

NEXUS remains a local deliberative Council. A NEXUS adapter may:

- export attributed Council reports;
- import foreign Council reports as foreign objects;
- offer hypotheses and minority reports;
- request or offer evidence references.

It may not allow a remote Federation peer to:

- inject a vote into an active local Council session;
- alter vote weight;
- rewrite a Council result;
- promote a foreign consensus into local evidence;
- mutate NEXUS governance.

A future "Council of Councils" is therefore a federation of attributed reports and independent deliberations, not one giant vote bucket.

## 7. ORACLE and ARK relationship

A future ORACLE adapter should exchange evidence observations and conflict/unknown states while preserving local authority boundaries.

A future ARK adapter should support content-addressed archival exchange and offline recovery bundles without allowing archival presence to become authority.

## 8. Transport independence

The reference HTTP API is deliberately replaceable. A conforming transport must preserve canonical envelope bytes and admission semantics.

Potential transports include:

- HTTP/HTTPS;
- WebSocket;
- QUIC;
- local Unix-domain sockets;
- offline signed bundles.

Transport security does not replace protocol validation.

## 9. No global canonical state

QSOL-FED does not require all nodes to agree.

A claim may simultaneously be:

```text
Node A: verified locally
Node B: inferred locally
Node C: conflict locally
Node D: unknown locally
```

Federation preserves the disagreement and provenance. It does not collapse the states into a synthetic global truth label.

## 10. Versioning

Protocol compatibility is explicit. Major versions may change constitutional or wire semantics. Minor additive capability evolution must remain negotiable and default-deny when unknown.

A node must never silently reinterpret a message from an unsupported major version.

## 11. Trust model

The network assumes peers may be:

- honest;
- buggy;
- compromised;
- malicious;
- overconfident;
- stale;
- correctly authenticated but unauthorized for a requested local action.

Therefore identity, authenticity, truth and authority remain separate dimensions.
