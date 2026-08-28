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

/-- Capability advertisements are active only when current time is inside the signed
issued/expires interval and that declared interval itself does not exceed the frozen
Phase 4 maximum lifetime. -/
def capabilityAdvertisementActive
    (issuedAtSeconds expiresAtSeconds currentTimeSeconds : Nat) : Bool :=
  decide (
    issuedAtSeconds < expiresAtSeconds ∧
    issuedAtSeconds <= currentTimeSeconds ∧
    currentTimeSeconds <= expiresAtSeconds ∧
    expiresAtSeconds - issuedAtSeconds <= maximumCapabilityLifetimeSeconds
  )

structure CapabilityInputs where
  peerAdmitted : Bool
  authenticatedAdvertisement : Bool
  advertisementIssuedAtSeconds : Nat
  advertisementExpiresAtSeconds : Nat
  currentTimeSeconds : Nat
  explicitLocalAllow : Bool
  deriving DecidableEq, Repr

/-- Phase 4 capability permission is conjunctive: admission, authentication, activity
inside the signed advertisement interval, the maximum lifetime bound, and explicit local
allow are all required. -/
def capabilityAllowed (c : CapabilityInputs) : Bool :=
  c.peerAdmitted &&
    c.authenticatedAdvertisement &&
    capabilityAdvertisementActive
      c.advertisementIssuedAtSeconds
      c.advertisementExpiresAtSeconds
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
history and the complete candidate keeps revocation terminal. -/
def lifecycleUpdateAllowed
    (stored candidate : List PeerLifecycle) : Prop :=
  Prefix stored candidate ∧
  RevocationTerminal candidate

structure PeerRegistryEntry where
  nodeId : String
  lifecycle : List PeerLifecycle
  deriving DecidableEq, Repr

/-- Member-local state includes the authority-bearing surfaces that federation import and
Assembly voting are forbidden to mutate. Returning this object unchanged therefore covers
peer/trust/evidence/governance state plus capability, history, citizenship, identity,
execution, credential, tool, network, file, and process state. -/
structure SovereignState where
  governanceVersion : Nat
  trustVersion : Nat
  evidenceVersion : Nat
  peerRegistry : List PeerRegistryEntry
  trustRegistry : List String
  evidenceState : List String
  governanceState : List String
  capabilityState : List String
  historyState : List String
  citizenshipState : List String
  identityAuthorityState : List String
  executionState : List String
  credentialHandles : List String
  toolHandles : List String
  networkHandles : List String
  openFiles : List String
  processes : List String
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

/-- Bundle import preserves the complete bundle, every provenance attribution, and the
complete pre-existing member-local state including its peer lifecycle registry. -/
def importBundle (state : SovereignState) (bundle : PortableBundle) : BundleImportResult :=
  { localState := state
    importedBundle := bundle
    authorityEffect := false
    trustChanged := false }

/-- Partition rejoin derives snapshot equality from the immutable disconnect snapshot and
the proposed remote snapshot. Reconciliation clears only when those snapshots are equal
and the member explicitly confirms the rejoin. -/
def rejoinPartition
    (state : SovereignState) (disconnectSnapshot proposedSnapshot : String)
    (explicitLocalConfirm : Bool) : RejoinResult :=
  if disconnectSnapshot = proposedSnapshot then
    match explicitLocalConfirm with
    | true => { localState := state, reconciliationRequired := false }
    | false => { localState := state, reconciliationRequired := true }
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

/-- Processing an Assembly vote records vote data but preserves the complete member-local
state, including every authority-bearing surface represented by SovereignState. -/
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

inductive TransportProfile where
  | webSocket
  | quic
  | unixIPC
  | offlineSneakernet
  | storeForward
  deriving DecidableEq, Repr

structure TransportFrame where
  sender : String
  recipient : String
  profile : TransportProfile
  messageId : String
  payloadRef : String
  provenanceRef : String
  deriving DecidableEq, Repr

/-- Transporting an existing Holodeck teardown receipt preserves the receipt itself. -/
def transportHolodeckReceipt
    (_profile : TransportProfile) (receipt : HolodeckReceipt) : HolodeckReceipt := receipt

/-- Transport changes delivery mechanics, not authenticated protocol identity/provenance. -/
def transport (_profile : TransportProfile) (frame : TransportFrame) : TransportFrame := frame

structure TransportAdmissionContext where
  signatureValid : Bool
  identityCurrent : Bool
  replayFresh : Bool
  localPeerAdmitted : Bool
  verifiedSenderNodeId : String
  localNodeId : String
  relayAdmitted : Bool
  deriving DecidableEq, Repr

def forwardingProfile : TransportProfile → Bool
  | .offlineSneakernet => true
  | .storeForward => true
  | _ => false

def routeLocallyAdmitted
    (frame : TransportFrame) (context : TransportAdmissionContext) : Bool :=
  if frame.recipient = context.localNodeId then
    true
  else
    forwardingProfile frame.profile && context.relayAdmitted

/-- Identity, key-status, peer-admission and local recipient/relay checks are the
pre-replay Phase 8 admission surface. -/
def TransportRoutePrerequisitesSatisfied
    (context : TransportAdmissionContext) (frame : TransportFrame) : Prop :=
  context.signatureValid = true ∧
  context.identityCurrent = true ∧
  context.localPeerAdmitted = true ∧
  frame.sender = context.verifiedSenderNodeId ∧
  routeLocallyAdmitted frame context = true

/-- Full transport admission adds replay freshness only after the route/identity surface
has succeeded, preserving the frozen Phase 8 check ordering. -/
def TransportPrerequisitesSatisfied
    (context : TransportAdmissionContext) (frame : TransportFrame) : Prop :=
  TransportRoutePrerequisitesSatisfied context frame ∧
  context.replayFresh = true

structure TransportAdmissionResult where
  accepted : Bool
  frame : TransportFrame
  deriving DecidableEq, Repr

/-- Transport admission checks each frozen prerequisite constructively and in the frozen
Phase 8 order: identity/current-key/local-admission/sender/recipient-or-relay, then replay. -/
def admitTransport
    (context : TransportAdmissionContext) (frame : TransportFrame) : TransportAdmissionResult :=
  if _signature : context.signatureValid = true then
    if _identity : context.identityCurrent = true then
      if _peer : context.localPeerAdmitted = true then
        if _sender : frame.sender = context.verifiedSenderNodeId then
          if _route : routeLocallyAdmitted frame context = true then
            if _replay : context.replayFresh = true then
              { accepted := true, frame := transport frame.profile frame }
            else
              { accepted := false, frame := frame }
          else
            { accepted := false, frame := frame }
        else
          { accepted := false, frame := frame }
      else
        { accepted := false, frame := frame }
    else
      { accepted := false, frame := frame }
  else
    { accepted := false, frame := frame }

structure RouteAssessment where
  trust : Bool
  authority : Bool
  identityReplacement : Bool
  senderBindingAccepted : Bool
  deriving DecidableEq, Repr

/-- NAT route hints confer no trust, authority, or identity replacement. Sender binding is
accepted only when both the ticket node and ticket identity reference match the independently
authenticated Phase 2 node and verified identity reference. -/
def natRouteAssessment
    (authenticatedSender ticketNode verifiedIdentityRef ticketIdentityRef : String) :
    RouteAssessment :=
  if ticketNode = authenticatedSender then
    if ticketIdentityRef = verifiedIdentityRef then
      { trust := false
        authority := false
        identityReplacement := false
        senderBindingAccepted := true }
    else
      { trust := false
        authority := false
        identityReplacement := false
        senderBindingAccepted := false }
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
