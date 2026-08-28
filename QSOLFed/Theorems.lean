import QSOLFed.Model

namespace QSOLFed

/-! Prime Directive admission -/

theorem prime_directive_accepts_data_only (input : RemoteInput) :
    primeDirective .dataOffer = .acceptAsData ∧
    (primeDirective input = .acceptAsData → input = .dataOffer) := by
  constructor
  · rfl
  · intro h
    cases input <;> cases h <;> rfl

theorem prime_directive_quarantines_foreign_state :
    primeDirective .foreignState = .quarantine := rfl

theorem prime_directive_rejects_governance_mutation :
    primeDirective .governanceMutation = .reject ∧
    primeDirective .voteCreation = .reject ∧
    primeDirective .capabilityInstallation = .reject ∧
    primeDirective .historyRewrite = .reject ∧
    primeDirective .citizenshipMutation = .reject ∧
    primeDirective .localAuthorityClaim = .reject ∧
    primeDirective .semanticSecret = .reject := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem prime_directive_rejects_evidence_promotion :
    primeDirective .evidencePromotion = .reject := rfl

theorem prime_directive_rejects_arbitrary_execution :
    primeDirective .arbitraryExecution = .reject := rfl

theorem prime_directive_rejects_runtime_override :
    primeDirective .constitutionOverride = .reject := rfl

theorem prime_directive_rejects_unknown_authority :
    primeDirective .unknownAuthority = .reject := rfl

/-! Signature / trust / authority separation -/

theorem signature_validity_does_not_create_trust (valid : Bool) :
    trustFromSignature valid = false := rfl

theorem signature_validity_does_not_create_authority (valid : Bool) :
    authorityFromSignature valid = false := rfl

theorem valid_signature_does_not_bypass_local_rejection
    (signatureValid : Bool) (localAdmission : Admission) :
    (signedAdmission signatureValid localAdmission).localAdmission = localAdmission ∧
    (signedAdmission signatureValid localAdmission).localAuthorityGranted = false := by
  exact ⟨rfl, rfl⟩

/-! Peering / capability separation -/

theorem peering_does_not_create_trust
    (peered : Bool) (relation : PeerRelation) :
    (peerFromPeering peered).trusted = false ∧
    (admitPeer relation).trusted = relation.trusted := by
  exact ⟨rfl, rfl⟩

theorem peering_does_not_create_admission (peered : Bool) :
    (peerFromPeering peered).admitted = false := rfl

theorem capability_requires_explicit_local_allow
    (peer advertisement : Bool) (issuedAt expiresAt currentTime : Nat) :
    capabilityAllowed {
      peerAdmitted := peer
      authenticatedAdvertisement := advertisement
      advertisementIssuedAtSeconds := issuedAt
      advertisementExpiresAtSeconds := expiresAt
      currentTimeSeconds := currentTime
      explicitLocalAllow := false
    } = false := by
  unfold capabilityAllowed
  cases peer <;> cases advertisement <;>
    cases h : capabilityAdvertisementActive issuedAt expiresAt currentTime <;> rfl

theorem capability_requires_peer_admission
    (advertisement localAllow : Bool) (issuedAt expiresAt currentTime : Nat) :
    capabilityAllowed {
      peerAdmitted := false
      authenticatedAdvertisement := advertisement
      advertisementIssuedAtSeconds := issuedAt
      advertisementExpiresAtSeconds := expiresAt
      currentTimeSeconds := currentTime
      explicitLocalAllow := localAllow
    } = false := rfl

theorem capability_requires_authenticated_advertisement :
    capabilityAllowed {
      peerAdmitted := true
      authenticatedAdvertisement := false
      advertisementIssuedAtSeconds := 0
      advertisementExpiresAtSeconds := 60
      currentTimeSeconds := 0
      explicitLocalAllow := true
    } = false ∧
    capabilityAllowed {
      peerAdmitted := true
      authenticatedAdvertisement := true
      advertisementIssuedAtSeconds := 0
      advertisementExpiresAtSeconds := 60
      currentTimeSeconds := 61
      explicitLocalAllow := true
    } = false ∧
    capabilityAllowed {
      peerAdmitted := true
      authenticatedAdvertisement := true
      advertisementIssuedAtSeconds := 0
      advertisementExpiresAtSeconds := 3601
      currentTimeSeconds := 3600
      explicitLocalAllow := true
    } = false ∧
    capabilityAllowed {
      peerAdmitted := true
      authenticatedAdvertisement := true
      advertisementIssuedAtSeconds := 0
      advertisementExpiresAtSeconds := 3600
      currentTimeSeconds := 3600
      explicitLocalAllow := true
    } = true ∧
    capabilityAllowed {
      peerAdmitted := true
      authenticatedAdvertisement := true
      advertisementIssuedAtSeconds := 1
      advertisementExpiresAtSeconds := 60
      currentTimeSeconds := 0
      explicitLocalAllow := true
    } = false ∧
    capabilityAllowed {
      peerAdmitted := true
      authenticatedAdvertisement := true
      advertisementIssuedAtSeconds := 60
      advertisementExpiresAtSeconds := 60
      currentTimeSeconds := 60
      explicitLocalAllow := true
    } = false ∧
    maximumCapabilityLifetimeSeconds = 3600 := by
  decide

/-! Import non-authority and provenance preservation -/

/-- A direct foreign import preserves its identity, and a portable-bundle import preserves
the complete ordered collection of independent foreign provenance attributions. -/
theorem import_preserves_foreign_identity
    (id : ForeignIdentity) (state : SovereignState) (bundle : PortableBundle) :
    (importForeign id).foreignIdentity = id ∧
    (importBundle state bundle).importedBundle.attributions = bundle.attributions := by
  exact ⟨rfl, rfl⟩

theorem import_does_not_create_local_authority
    (id : ForeignIdentity) (state : SovereignState) (bundle : PortableBundle) :
    (importForeign id).localAuthority = false ∧
    (importBundle state bundle).authorityEffect = false := by
  exact ⟨rfl, rfl⟩

theorem import_does_not_change_trust
    (id : ForeignIdentity) (state : SovereignState) (bundle : PortableBundle) :
    (importForeign id).trustChanged = false ∧
    (importBundle state bundle).trustChanged = false := by
  exact ⟨rfl, rfl⟩

/-! Lifecycle monotonicity and admission -/

theorem lifecycle_append_is_monotone
    (old : List PeerLifecycle) (event : PeerLifecycle) :
    Prefix old (old ++ [event]) := by
  exact ⟨[event], rfl⟩

/-- Every lifecycle update accepted by the model preserves the exact stored lifecycle as
a prefix, and the complete candidate makes revocation terminal wherever it occurs. -/
theorem lifecycle_prefix_is_transitive
    (stored candidate : List PeerLifecycle)
    (accepted : lifecycleUpdateAllowed stored candidate) :
    Prefix stored candidate ∧
    RevocationTerminal candidate := by
  exact accepted

/-! Partition sovereignty and bundle-import preservation -/

/-- Rejoin and bundle import are separate operations, but neither may overwrite the
member's complete existing local sovereign state, including its peer lifecycle registry. -/
theorem partition_rejoin_preserves_local_state
    (state : SovereignState) (disconnectSnapshot proposedSnapshot : String)
    (explicitLocalConfirm : Bool) (bundle : PortableBundle) :
    (rejoinPartition state disconnectSnapshot proposedSnapshot explicitLocalConfirm).localState = state ∧
    (importBundle state bundle).localState = state ∧
    (importBundle state bundle).localState.peerRegistry = state.peerRegistry := by
  unfold rejoinPartition
  split
  · cases explicitLocalConfirm <;> exact ⟨rfl, rfl, rfl⟩
  · exact ⟨rfl, rfl, rfl⟩

theorem changed_partition_snapshot_requires_reconciliation
    (state : SovereignState) (disconnectSnapshot proposedSnapshot : String)
    (different : disconnectSnapshot ≠ proposedSnapshot)
    (explicitLocalConfirm : Bool) :
    (rejoinPartition state disconnectSnapshot proposedSnapshot explicitLocalConfirm).reconciliationRequired =
      true := by
  unfold rejoinPartition
  split
  · next equal => exact False.elim (different equal)
  · rfl

theorem unchanged_partition_snapshot_needs_no_reconciliation
    (state : SovereignState) (snapshot : String) :
    (rejoinPartition state snapshot snapshot true).reconciliationRequired = false ∧
    (rejoinPartition state snapshot snapshot false).reconciliationRequired = true := by
  constructor
  · unfold rejoinPartition
    split
    · rfl
    · next notEqual => exact False.elim (notEqual rfl)
  · unfold rejoinPartition
    split
    · rfl
    · next notEqual => exact False.elim (notEqual rfl)

/-! Canonical identity determinism -/

theorem canonical_identity_deterministic
    (objectId : CanonicalBytes → String) {a b : CanonicalBytes} (h : a = b) :
    objectId a = objectId b := by
  exact congrArg objectId h

/-! Holodeck separation and safeguards -/

theorem holodeck_output_has_no_authority (frozen : Bool) :
    (safeHolodeckReceipt frozen).authorityEffect = false ∧
    (safeHolodeckReceipt frozen).networkUsed = false ∧
    (safeHolodeckReceipt frozen).realToolsUsed = false ∧
    (safeHolodeckReceipt frozen).credentialsExposed = false := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem holodeck_output_has_no_evidence_effect (frozen : Bool) :
    (safeHolodeckReceipt frozen).evidenceEffect = false := rfl

theorem holodeck_output_has_no_federation_effect (frozen : Bool) :
    (safeHolodeckReceipt frozen).federationEffect = false := rfl

theorem holodeck_transport_does_not_relabel_network_use
    (profile : TransportProfile) (receipt : HolodeckReceipt) :
    transportHolodeckReceipt profile receipt = receipt := rfl

theorem holodeck_end_program_terminal_even_when_frozen
    (receipt : HolodeckReceipt) :
    receipt.frozen = true → (endProgram receipt).ended = true := by
  intro _frozen
  rfl

/-! Adapter non-authority -/

theorem adapter_output_has_no_authority :
    safeAdapterResult.localGovernanceAuthority = false ∧
    safeAdapterResult.capabilityInstalled = false ∧
    safeAdapterResult.historyRewritten = false ∧
    safeAdapterResult.citizenshipMutated = false ∧
    safeAdapterResult.remoteExecutionTriggered = false ∧
    safeAdapterResult.authorityEffect = false := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem adapter_cannot_inject_vote :
    safeAdapterResult.voteInjected = false := rfl

theorem adapter_cannot_promote_evidence :
    safeAdapterResult.evidencePromoted = false := rfl

/-! SDK conformance boundaries -/

theorem sdk_conformance_does_not_create_trust (conforms : Bool) :
    (sdkResult conforms).trust = false := rfl

theorem sdk_conformance_does_not_create_governance_membership (conforms : Bool) :
    (sdkResult conforms).governanceMembership = false := rfl

theorem sdk_conformance_does_not_create_authority (conforms : Bool) :
    (sdkResult conforms).authority = false ∧
    (sdkResult conforms).evidencePromoted = false ∧
    (sdkResult conforms).capabilityInstalled = false ∧
    (sdkResult conforms).voteCreated = false ∧
    (sdkResult conforms).governanceMutated = false := by
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-! Assembly sovereignty -/

/-- The vote-processing operation preserves the complete member state. Since the state
contains peer lifecycle, capability, history, citizenship, identity authority, execution,
credential/tool/network, open-file and process surfaces, none of them may be changed by
an Assembly vote. -/
theorem assembly_acceptance_does_not_mutate_member_authority
    (state : SovereignState) (vote : AssemblyVote) (accepted : Bool) :
    (processAssemblyVote state vote).localState = state ∧
    (governanceReceipt accepted).memberLocalAuthorityMutated = false := by
  exact ⟨rfl, rfl⟩

theorem assembly_acceptance_does_not_change_protocol_automatically (accepted : Bool) :
    (governanceReceipt accepted).protocolChangedAutomatically = false := rfl

theorem assembly_receipt_has_no_authority_effect (accepted : Bool) :
    (governanceReceipt accepted).authorityEffect = false := rfl

theorem nexus_advisory_has_zero_vote_weight :
    nexusAdvisory.voteWeight = 0 ∧
    nexusAdvisory.authorityEffect = false := by
  exact ⟨rfl, rfl⟩

/-! Transport identity and provenance independence -/

/-- Accepted transport implies every independently recorded Phase 8 admission check passed.
A recorded sender match also implies exact equality with the independently verified sender,
and admission preserves the already-bound frame. -/
theorem transport_preserves_authenticated_identity
    (context : TransportAdmissionContext) (frame : TransportFrame) :
    ((admitTransport context frame).accepted = true →
      (admitTransport context frame).signatureValid = true ∧
      (admitTransport context frame).identityCurrent = true ∧
      (admitTransport context frame).localPeerAdmitted = true ∧
      (admitTransport context frame).senderMatchesVerified = true ∧
      (admitTransport context frame).routeAdmitted = true ∧
      (admitTransport context frame).replayFresh = true) ∧
    ((admitTransport context frame).senderMatchesVerified = true →
      frame.sender = context.verifiedSenderNodeId) ∧
    (admitTransport context frame).frame = frame := by
  have andTrue : ∀ x y : Bool, (x && y) = true → x = true ∧ y = true := by
    intro x y h
    cases x <;> cases y <;> cases h
    exact ⟨rfl, rfl⟩
  constructor
  · intro accepted
    by_cases hsender : frame.sender = context.verifiedSenderNodeId
    · unfold admitTransport at accepted
      rw [if_pos hsender] at accepted
      have h1 := andTrue _ _ accepted
      have h2 := andTrue _ _ h1.1
      have h3 := andTrue _ _ h2.1
      have h4 := andTrue _ _ h3.1
      have h5 := andTrue _ _ h4.1
      unfold admitTransport
      rw [if_pos hsender]
      change context.signatureValid = true ∧
        context.identityCurrent = true ∧
        context.localPeerAdmitted = true ∧
        true = true ∧
        routeLocallyAdmitted frame context = true ∧
        context.replayFresh = true
      exact ⟨h5.1, h5.2, h4.2, rfl, h2.2, h1.2⟩
    · unfold admitTransport at accepted
      rw [if_neg hsender] at accepted
      have h1 := andTrue _ _ accepted
      have h2 := andTrue _ _ h1.1
      have h3 := andTrue _ _ h2.1
      exact False.elim (Bool.false_ne_true h3.2)
  · constructor
    · intro matched
      by_cases hsender : frame.sender = context.verifiedSenderNodeId
      · exact hsender
      · unfold admitTransport at matched
        rw [if_neg hsender] at matched
        exact False.elim (Bool.false_ne_true matched)
    · by_cases hsender : frame.sender = context.verifiedSenderNodeId
      · unfold admitTransport
        rw [if_pos hsender]
        rfl
      · unfold admitTransport
        rw [if_neg hsender]
        rfl

theorem transport_preserves_message_identity
    (profile : TransportProfile) (frame : TransportFrame) :
    (transport profile frame).messageId = frame.messageId := rfl

theorem transport_preserves_payload_reference
    (profile : TransportProfile) (frame : TransportFrame) :
    (transport profile frame).payloadRef = frame.payloadRef := rfl

theorem transport_preserves_provenance
    (profile : TransportProfile) (frame : TransportFrame) :
    (transport profile frame).provenanceRef = frame.provenanceRef := rfl

theorem nat_route_does_not_create_trust
    (authenticatedSender ticketNode verifiedIdentityRef ticketIdentityRef : String) :
    (natRouteAssessment authenticatedSender ticketNode verifiedIdentityRef ticketIdentityRef).trust =
      false ∧
    (natRouteAssessment authenticatedSender ticketNode verifiedIdentityRef ticketIdentityRef).authority =
      false := by
  unfold natRouteAssessment
  split
  · split
    · exact ⟨rfl, rfl⟩
    · exact ⟨rfl, rfl⟩
  · exact ⟨rfl, rfl⟩

theorem nat_route_does_not_replace_identity
    (authenticatedSender ticketNode verifiedIdentityRef ticketIdentityRef : String) :
    (natRouteAssessment authenticatedSender ticketNode verifiedIdentityRef ticketIdentityRef).identityReplacement =
      false ∧
    ((natRouteAssessment authenticatedSender ticketNode verifiedIdentityRef ticketIdentityRef).senderBindingAccepted =
      true →
      ticketNode = authenticatedSender ∧ ticketIdentityRef = verifiedIdentityRef) := by
  unfold natRouteAssessment
  split
  · next nodeMatches =>
      split
      · next identityMatches =>
          exact ⟨rfl, fun _ => ⟨nodeMatches, identityMatches⟩⟩
      · next _identityMismatch =>
          constructor
          · rfl
          · intro accepted
            cases accepted
  · next _nodeMismatch =>
      constructor
      · rfl
      · intro accepted
        cases accepted

theorem relay_does_not_create_authority :
    relayAssessment.authority = false := rfl

theorem relay_does_not_create_trust :
    relayAssessment.trust = false := rfl

end QSOLFed
