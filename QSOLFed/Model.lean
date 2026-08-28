namespace QSOLFed

/-! Abstract Phase 10 model of selected immutable QSOL-FED v0.11.0 contracts. -/

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

def trustFromSignature (_signatureValid : Bool) : Bool := false

def authorityFromSignature (_signatureValid : Bool) : Bool := false

structure SignedAdmission where
  signatureValid : Bool
  localAdmission : Admission
  localAuthorityGranted : Bool
  deriving DecidableEq, Repr

def signedAdmission (signatureValid : Bool) (localAdmission : Admission) : SignedAdmission :=
  { signatureValid := signatureValid
    localAdmission := localAdmission
    localAuthorityGranted := false }

structure PeerRelation where
  peered : Bool
  admitted : Bool
  trusted : Bool
  deriving DecidableEq, Repr

def peerFromPeering (peered : Bool) : PeerRelation :=
  { peered := peered, admitted := false, trusted := false }

def admitPeer (relation : PeerRelation) : PeerRelation :=
  { relation with admitted := true }

def maximumCapabilityLifetimeSeconds : Nat := 3600

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

def importForeign (id : ForeignIdentity) : ImportResult :=
  { foreignIdentity := id, localAuthority := false, trustChanged := false }

inductive PeerLifecycle where
  | introduced
  | admitted
  | quarantined
  | revoked
  | disconnected
  deriving DecidableEq, Repr

def Prefix {α : Type} (old newer : List α) : Prop :=
  ∃ tail, newer = old ++ tail

def RevocationTerminal : List PeerLifecycle → Prop
  | [] => True
  | .introduced :: tail => RevocationTerminal tail
  | .admitted :: tail => RevocationTerminal tail
  | .quarantined :: tail => RevocationTerminal tail
  | .revoked :: tail => tail = []
  | .disconnected :: tail => RevocationTerminal tail

def lifecycleUpdateAllowed
    (stored candidate : List PeerLifecycle) : Prop :=
  Prefix stored candidate ∧ RevocationTerminal candidate

structure PeerRegistryEntry where
  nodeId : String
  lifecycle : List PeerLifecycle
  deriving DecidableEq, Repr

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

def importBundle (state : SovereignState) (bundle : PortableBundle) : BundleImportResult :=
  { localState := state
    importedBundle := bundle
    authorityEffect := false
    trustChanged := false }

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

def safeHolodeckReceipt (frozen : Bool) : HolodeckReceipt :=
  { authorityEffect := false
    federationEffect := false
    evidenceEffect := false
    networkUsed := false
    realToolsUsed := false
    credentialsExposed := false
    frozen := frozen
    ended := false }

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

def processAssemblyVote (state : SovereignState) (vote : AssemblyVote) : VoteProcessResult :=
  { localState := state, recordedVote := vote }

structure GovernanceReceipt where
  accepted : Bool
  memberLocalAuthorityMutated : Bool
  protocolChangedAutomatically : Bool
  authorityEffect : Bool
  deriving DecidableEq, Repr

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

def transportHolodeckReceipt
    (_profile : TransportProfile) (receipt : HolodeckReceipt) : HolodeckReceipt := receipt

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
  match frame.recipient == context.localNodeId with
  | true => true
  | false => forwardingProfile frame.profile && context.relayAdmitted

structure TransportAdmissionResult where
  signatureValid : Bool
  identityCurrent : Bool
  replayFresh : Bool
  localPeerAdmitted : Bool
  senderMatchesVerified : Bool
  routeAdmitted : Bool
  accepted : Bool
  frame : TransportFrame
  deriving DecidableEq, Repr

/-- The result records every independently derived Phase 8 prerequisite. Sender matching
and route admission are derived inside this operation from the independently verified
sender, local node, profile and explicit relay admission, never supplied by the caller. -/
def admitTransport
    (context : TransportAdmissionContext) (frame : TransportFrame) : TransportAdmissionResult :=
  let senderMatchesVerified := frame.sender == context.verifiedSenderNodeId
  let routeAdmitted := routeLocallyAdmitted frame context
  { signatureValid := context.signatureValid
    identityCurrent := context.identityCurrent
    replayFresh := context.replayFresh
    localPeerAdmitted := context.localPeerAdmitted
    senderMatchesVerified := senderMatchesVerified
    routeAdmitted := routeAdmitted
    accepted := context.signatureValid &&
      context.identityCurrent &&
      context.localPeerAdmitted &&
      senderMatchesVerified &&
      routeAdmitted &&
      context.replayFresh
    frame := transport frame.profile frame }

structure RouteAssessment where
  trust : Bool
  authority : Bool
  identityReplacement : Bool
  senderBindingAccepted : Bool
  deriving DecidableEq, Repr

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

def relayAssessment : RelayAssessment :=
  { trust := false, authority := false }

end QSOLFed
