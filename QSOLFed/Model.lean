namespace QSOLFed

/-!
A deliberately small formal model of the constitutional separation contracts frozen in
QSOL-FED v0.11.0. These definitions model the stated contract boundaries; they do not
claim formal verification of the Rust/Python/TypeScript implementations or deployment.
-/

inductive Admission where
  | acceptAsData
  | quarantine
  | reject
  deriving DecidableEq, Repr

inductive RemoteInput where
  | dataOffer
  | foreignState
  | governanceMutation
  | evidencePromotion
  | voteCreation
  | capabilityInstallation
  | historyRewrite
  | citizenshipMutation
  | arbitraryExecution
  | localAuthorityClaim
  | semanticSecret
  | constitutionOverride
  | unknownAuthority
  deriving DecidableEq, Repr

/-- Frozen Prime Directive model: data may be admitted as data, foreign state is
quarantined, and authority-bearing or unknown effects fail closed. -/
def primeDirective : RemoteInput → Admission
  | .dataOffer => .acceptAsData
  | .foreignState => .quarantine
  | .governanceMutation => .reject
  | .evidencePromotion => .reject
  | .voteCreation => .reject
  | .capabilityInstallation => .reject
  | .historyRewrite => .reject
  | .citizenshipMutation => .reject
  | .arbitraryExecution => .reject
  | .localAuthorityClaim => .reject
  | .semanticSecret => .reject
  | .constitutionOverride => .reject
  | .unknownAuthority => .reject

/-- Cryptographic validity alone contributes no trust in the formal model. -/
def trustFromSignature (_signatureValid : Bool) : Bool := false

/-- Cryptographic validity alone contributes no local authority in the formal model. -/
def authorityFromSignature (_signatureValid : Bool) : Bool := false

structure SignedAdmission where
  signatureValid : Bool
  localAdmission : Admission
  localAuthorityGranted : Bool
  deriving DecidableEq, Repr

/-- Accepting signed material as data still grants no local governance authority. -/
def signedAdmission (signatureValid : Bool) (localAdmission : Admission) : SignedAdmission :=
  { signatureValid := signatureValid
    localAdmission := localAdmission
    localAuthorityGranted := false }

structure PeerRelation where
  peered : Bool
  admitted : Bool
  trusted : Bool
  deriving DecidableEq, Repr

/-- Peering itself confers no trust. -/
def peerFromPeering (peered : Bool) : PeerRelation :=
  { peered := peered, admitted := false, trusted := false }

/-- Explicit local peer admission changes admission state while preserving the separate
trust decision. -/
def admitPeer (relation : PeerRelation) : PeerRelation :=
  { relation with admitted := true }

def maximumCapabilityLifetimeSeconds : Nat := 3600

/-- Capability advertisements are active only when their issue time is not in the future
and their derived age is within the frozen Phase 4 maximum lifetime. -/
def capabilityAdvertisementActive
    (issuedAtSeconds currentTimeSeconds : Nat) : Bool :=
  decide (
    issuedAtSeconds <= currentTimeSeconds ∧
    currentTimeSeconds - issuedAtSeconds <= maximumCapabilityLifetimeSeconds
  )

structure CapabilityInputs where
  peerAdmitted : Bool
  authenticatedAdvertisement : Bool
  advertisementIssuedAtSeconds : Nat
  currentTimeSeconds : Nat
  explicitLocalAllow : Bool
  deriving DecidableEq, Repr

/-- Phase 4 capability permission is conjunctive: admission, authentication, a freshness
decision derived from advertisement/current times, and explicit local allow are required. -/
def capabilityAllowed (c : CapabilityInputs) : Bool :=
  c.peerAdmitted &&
    c.authenticatedAdvertisement &&
    capabilityAdvertisementActive
      c.advertisementIssuedAtSeconds
      c.currentTimeSeconds &&
    c.explicitLocalAllow

structure ForeignIdentity where
  contentId : String
  provenanceId : String
  deriving DecidableEq, Repr

structure ImportResult where
  foreignIdentity : ForeignIdentity
  localAuthority : Bool
  trustChanged : Bool
  deriving DecidableEq, Repr

/-- Import preserves the foreign identity while creating neither authority nor trust. -/
def importForeign (id : ForeignIdentity) : ImportResult :=
  { foreignIdentity := id, localAuthority := false, trustChanged := false }

inductive PeerLifecycle where
  | introduced
  | admitted
  | quarantined
  | revoked
  | disconnected
  deriving DecidableEq, Repr

/-- List-prefix relation used to model append-only peer lifecycle history. -/
def Prefix {α : Type} (old newer : List α) : Prop :=
  ∃ tail, newer = old ++ tail

/-- Revocation is terminal wherever it occurs: no lifecycle event may follow it. -/
def RevocationTerminal : List PeerLifecycle → Prop
  | [] => True
  | .introduced :: tail => RevocationTerminal tail
  | .admitted :: tail => RevocationTerminal tail
  | .quarantined :: tail => RevocationTerminal tail
  | .revoked :: tail => tail = []
  | .disconnected :: tail => RevocationTerminal tail

/-- A lifecycle candidate is locally admissible only when it extends the exact stored
history and the complete candidate keeps revocation terminal. This rejects rollback,
rewrite, same-sequence divergence, and both stored or same-candidate reintroduction after
revocation. -/
def lifecycleUpdateAllowed
    (stored candidate : List PeerLifecycle) : Prop :=
  Prefix stored candidate ∧
  RevocationTerminal candidate

structure SovereignState where
  governanceVersion : Nat
  trustVersion : Nat
  evidenceVersion : Nat
  deriving DecidableEq, Repr

structure RejoinResult where
  localState : SovereignState
  reconciliationRequired : Bool
  deriving DecidableEq, Repr

/-- One independent foreign provenance attribution carried by a portable bundle. -/
structure BundleAttribution where
  foreignIdentity : ForeignIdentity
  sourceNode : String
  deriving DecidableEq, Repr

structure PortableBundle where
  bundleId : String
  attributions : List BundleAttribution
  deriving DecidableEq, Repr

structure BundleImportResult where
  localState : SovereignState
  importedBundle : PortableBundle
  authorityEffect : Bool
  trustChanged : Bool
  deriving DecidableEq, Repr

/-- Bundle import preserves the complete bundle, including every independent provenance
attribution, leaves the member's pre-existing local sovereign state unchanged, and creates
neither local authority nor a trust mutation. -/
def importBundle (state : SovereignState) (bundle : PortableBundle) : BundleImportResult :=
  { localState := state
    importedBundle := bundle
    authorityEffect := false
    trustChanged := false }

/-- Partition rejoin never rewrites local sovereign state. A same-snapshot rejoin clears
reconciliation only after explicit local confirmation; changed or unconfirmed snapshots
remain on the reconciliation path. -/
def rejoinPartition
    (state : SovereignState) (sameSnapshot explicitLocalConfirm : Bool) : RejoinResult :=
  if sameSnapshot && explicitLocalConfirm then
    { localState := state, reconciliationRequired := false }
  else
    { localState := state, reconciliationRequired := true }

abbrev CanonicalBytes := List UInt8

structure HolodeckReceipt where
  authorityEffect : Bool
  federationEffect : Bool
  evidenceEffect : Bool
  networkUsed : Bool
  realToolsUsed : Bool
  credentialsExposed : Bool
  frozen : Bool
  ended : Bool
  deriving DecidableEq, Repr

/-- A safe Holodeck receipt has no real-world authority/evidence/federation effect. -/
def safeHolodeckReceipt (frozen : Bool) : HolodeckReceipt :=
  { authorityEffect := false
    federationEffect := false
    evidenceEffect := false
    networkUsed := false
    realToolsUsed := false
    credentialsExposed := false
    frozen := frozen
    ended := false }

/-- Operator-owned Computer end-program is terminal even for a frozen simulation. -/
def endProgram (receipt : HolodeckReceipt) : HolodeckReceipt :=
  { receipt with ended := true }

structure AdapterResult where
  localGovernanceAuthority : Bool
  evidencePromoted : Bool
  voteInjected : Bool
  capabilityInstalled : Bool
  historyRewritten : Bool
  citizenshipMutated : Bool
  remoteExecutionTriggered : Bool
  authorityEffect : Bool
  deriving DecidableEq, Repr

/-- QSOL adapter output remains non-authoritative and cannot perform any Prime Directive
authority-bearing side effect. -/
def safeAdapterResult : AdapterResult :=
  { localGovernanceAuthority := false
    evidencePromoted := false
    voteInjected := false
    capabilityInstalled := false
    historyRewritten := false
    citizenshipMutated := false
    remoteExecutionTriggered := false
    authorityEffect := false }

structure SDKResult where
  conformance : Bool
  trust : Bool
  governanceMembership : Bool
  authority : Bool
  evidencePromoted : Bool
  capabilityInstalled : Bool
  voteCreated : Bool
  governanceMutated : Bool
  deriving DecidableEq, Repr

/-- SDK conformance creates no trust, governance membership, authority, evidence promotion,
capability installation, vote, or governance mutation. -/
def sdkResult (conformance : Bool) : SDKResult :=
  { conformance := conformance
    trust := false
    governanceMembership := false
    authority := false
    evidencePromoted := false
    capabilityInstalled := false
    voteCreated := false
    governanceMutated := false }

inductive VoteChoice where
  | yes
  | no
  | abstain
  deriving DecidableEq, Repr

structure AssemblyVote where
  memberId : String
  proposalId : String
  choice : VoteChoice
  deriving DecidableEq, Repr

structure VoteProcessResult where
  localState : SovereignState
  recordedVote : AssemblyVote
  deriving DecidableEq, Repr

/-- Processing an Assembly vote records vote data but cannot act as a command against the
member's local sovereign state. -/
def processAssemblyVote (state : SovereignState) (vote : AssemblyVote) : VoteProcessResult :=
  { localState := state, recordedVote := vote }

structure GovernanceReceipt where
  accepted : Bool
  memberLocalAuthorityMutated : Bool
  protocolChangedAutomatically : Bool
  authorityEffect : Bool
  deriving DecidableEq, Repr

/-- Assembly finalization records an outcome without mutating member-local authority. -/
def governanceReceipt (accepted : Bool) : GovernanceReceipt :=
  { accepted := accepted
    memberLocalAuthorityMutated := false
    protocolChangedAutomatically := false
    authorityEffect := false }

structure AdvisoryReport where
  advisoryWeight : Nat
  voteWeight : Nat
  authorityEffect : Bool
  deriving DecidableEq, Repr

/-- NEXUS is advisory-only in the Assembly model. -/
def nexusAdvisory : AdvisoryReport :=
  { advisoryWeight := 0, voteWeight := 0, authorityEffect := false }

structure TransportFrame where
  sender : String
  messageId : String
  payloadRef : String
  provenanceRef : String
  deriving DecidableEq, Repr

inductive TransportProfile where
  | webSocket
  | quic
  | unixIPC
  | offlineSneakernet
  | storeForward
  deriving DecidableEq, Repr

/-- Transporting an existing Holodeck teardown receipt preserves the receipt itself;
transport metadata cannot relabel recorded boundary-use fields. -/
def transportHolodeckReceipt
    (_profile : TransportProfile) (receipt : HolodeckReceipt) : HolodeckReceipt := receipt

/-- Transport changes delivery profile, not authenticated protocol identity/provenance. -/
def transport (_profile : TransportProfile) (frame : TransportFrame) : TransportFrame := frame

structure TransportAdmissionResult where
  accepted : Bool
  frame : TransportFrame
  deriving DecidableEq, Repr

/-- Transport admission binds the frame sender to the independently verified Phase 2
sender identity before admitting the frame. A mismatch is rejected. -/
def admitTransport
    (verifiedSender : String) (profile : TransportProfile)
    (frame : TransportFrame) : TransportAdmissionResult :=
  if frame.sender = verifiedSender then
    { accepted := true, frame := transport profile frame }
  else
    { accepted := false, frame := frame }

structure RouteAssessment where
  trust : Bool
  authority : Bool
  identityReplacement : Bool
  senderBindingAccepted : Bool
  deriving DecidableEq, Repr

/-- NAT route hints confer no trust, authority, or identity replacement. A ticket route is
admitted only when its named node is exactly the authenticated sender. -/
def natRouteAssessment (authenticatedSender ticketNode : String) : RouteAssessment :=
  if ticketNode = authenticatedSender then
    { trust := false
      authority := false
      identityReplacement := false
      senderBindingAccepted := true }
  else
    { trust := false
      authority := false
      identityReplacement := false
      senderBindingAccepted := false }

structure RelayAssessment where
  trust : Bool
  authority : Bool
  deriving DecidableEq, Repr

/-- Relay presence is provenance, not trust or authority. -/
def relayAssessment : RelayAssessment :=
  { trust := false, authority := false }

end QSOLFed
