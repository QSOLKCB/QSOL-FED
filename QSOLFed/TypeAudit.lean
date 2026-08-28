import QSOLFed.Theorems

namespace QSOLFed

/-!
Environment-level graduation theorem type audit.

Each `#check` ascribes the fully elaborated theorem constant, with `@` exposing
implicit parameters. This rejects hidden section/variable dependencies that are
not visible in the theorem's local declaration text.
-/

#check (@prime_directive_accepts_data_only :
  (input : RemoteInput) →
  primeDirective .dataOffer = .acceptAsData ∧
  (primeDirective input = .acceptAsData → input = .dataOffer))

#check (@prime_directive_quarantines_foreign_state :
  primeDirective .foreignState = .quarantine)

#check (@prime_directive_rejects_governance_mutation :
  primeDirective .governanceMutation = .reject ∧
  primeDirective .voteCreation = .reject ∧
  primeDirective .capabilityInstallation = .reject ∧
  primeDirective .historyRewrite = .reject ∧
  primeDirective .citizenshipMutation = .reject ∧
  primeDirective .localAuthorityClaim = .reject ∧
  primeDirective .semanticSecret = .reject)

#check (@prime_directive_rejects_evidence_promotion :
  primeDirective .evidencePromotion = .reject)

#check (@prime_directive_rejects_arbitrary_execution :
  primeDirective .arbitraryExecution = .reject)

#check (@prime_directive_rejects_runtime_override :
  primeDirective .constitutionOverride = .reject)

#check (@prime_directive_rejects_unknown_authority :
  primeDirective .unknownAuthority = .reject)

#check (@signature_validity_does_not_create_trust :
  (valid : Bool) → trustFromSignature valid = false)

#check (@signature_validity_does_not_create_authority :
  (valid : Bool) → authorityFromSignature valid = false)

#check (@valid_signature_does_not_bypass_local_rejection :
  (signatureValid : Bool) → (localAdmission : Admission) →
  (signedAdmission signatureValid localAdmission).localAdmission = localAdmission ∧
  (signedAdmission signatureValid localAdmission).localAuthorityGranted = false)

#check (@peering_does_not_create_trust :
  (peered : Bool) → (relation : PeerRelation) →
  (peerFromPeering peered).trusted = false ∧
  (admitPeer relation).trusted = relation.trusted)

#check (@peering_does_not_create_admission :
  (peered : Bool) → (peerFromPeering peered).admitted = false)

#check (@capability_requires_explicit_local_allow :
  (peer advertisement : Bool) → (issuedAt currentTime : Nat) →
  capabilityAllowed {
    peerAdmitted := peer
    authenticatedAdvertisement := advertisement
    advertisementIssuedAtSeconds := issuedAt
    currentTimeSeconds := currentTime
    explicitLocalAllow := false
  } = false)

#check (@capability_requires_peer_admission :
  (advertisement localAllow : Bool) → (issuedAt currentTime : Nat) →
  capabilityAllowed {
    peerAdmitted := false
    authenticatedAdvertisement := advertisement
    advertisementIssuedAtSeconds := issuedAt
    currentTimeSeconds := currentTime
    explicitLocalAllow := localAllow
  } = false)

#check (@capability_requires_authenticated_advertisement :
  capabilityAllowed {
    peerAdmitted := true
    authenticatedAdvertisement := false
    advertisementIssuedAtSeconds := 0
    currentTimeSeconds := 0
    explicitLocalAllow := true
  } = false ∧
  capabilityAllowed {
    peerAdmitted := true
    authenticatedAdvertisement := true
    advertisementIssuedAtSeconds := 0
    currentTimeSeconds := 3601
    explicitLocalAllow := true
  } = false ∧
  capabilityAllowed {
    peerAdmitted := true
    authenticatedAdvertisement := true
    advertisementIssuedAtSeconds := 0
    currentTimeSeconds := 3600
    explicitLocalAllow := true
  } = true ∧
  maximumCapabilityLifetimeSeconds = 3600)

#check (@import_preserves_foreign_identity :
  (id : ForeignIdentity) → (state : SovereignState) → (bundle : PortableBundle) →
  (importForeign id).foreignIdentity = id ∧
  (importBundle state bundle).importedBundle.attributions = bundle.attributions)

#check (@import_does_not_create_local_authority :
  (id : ForeignIdentity) → (state : SovereignState) → (bundle : PortableBundle) →
  (importForeign id).localAuthority = false ∧
  (importBundle state bundle).authorityEffect = false)

#check (@import_does_not_change_trust :
  (id : ForeignIdentity) → (state : SovereignState) → (bundle : PortableBundle) →
  (importForeign id).trustChanged = false ∧
  (importBundle state bundle).trustChanged = false)

#check (@lifecycle_append_is_monotone :
  (old : List PeerLifecycle) → (event : PeerLifecycle) →
  Prefix old (old ++ [event]))

#check (@lifecycle_prefix_is_transitive :
  (stored candidate : List PeerLifecycle) →
  lifecycleUpdateAllowed stored candidate →
  Prefix stored candidate ∧
  RevocationTerminal candidate)

#check (@partition_rejoin_preserves_local_state :
  (state : SovereignState) → (sameSnapshot explicitLocalConfirm : Bool) →
  (bundle : PortableBundle) →
  (rejoinPartition state sameSnapshot explicitLocalConfirm).localState = state ∧
  (importBundle state bundle).localState = state)

#check (@changed_partition_snapshot_requires_reconciliation :
  (state : SovereignState) → (explicitLocalConfirm : Bool) →
  (rejoinPartition state false explicitLocalConfirm).reconciliationRequired = true)

#check (@unchanged_partition_snapshot_needs_no_reconciliation :
  (state : SovereignState) →
  (rejoinPartition state true true).reconciliationRequired = false ∧
  (rejoinPartition state true false).reconciliationRequired = true)

#check (@canonical_identity_deterministic :
  (objectId : CanonicalBytes → String) → (a b : CanonicalBytes) →
  a = b → objectId a = objectId b)

#check (@holodeck_output_has_no_authority :
  (frozen : Bool) →
  (safeHolodeckReceipt frozen).authorityEffect = false ∧
  (safeHolodeckReceipt frozen).networkUsed = false ∧
  (safeHolodeckReceipt frozen).realToolsUsed = false ∧
  (safeHolodeckReceipt frozen).credentialsExposed = false)

#check (@holodeck_output_has_no_evidence_effect :
  (frozen : Bool) → (safeHolodeckReceipt frozen).evidenceEffect = false)

#check (@holodeck_output_has_no_federation_effect :
  (frozen : Bool) → (safeHolodeckReceipt frozen).federationEffect = false)

#check (@holodeck_transport_does_not_relabel_network_use :
  (profile : TransportProfile) → (receipt : HolodeckReceipt) →
  transportHolodeckReceipt profile receipt = receipt)

#check (@holodeck_end_program_terminal_even_when_frozen :
  (receipt : HolodeckReceipt) →
  receipt.frozen = true → (endProgram receipt).ended = true)

#check (@adapter_output_has_no_authority :
  safeAdapterResult.localGovernanceAuthority = false ∧
  safeAdapterResult.capabilityInstalled = false ∧
  safeAdapterResult.historyRewritten = false ∧
  safeAdapterResult.citizenshipMutated = false ∧
  safeAdapterResult.remoteExecutionTriggered = false ∧
  safeAdapterResult.authorityEffect = false)

#check (@adapter_cannot_inject_vote :
  safeAdapterResult.voteInjected = false)

#check (@adapter_cannot_promote_evidence :
  safeAdapterResult.evidencePromoted = false)

#check (@sdk_conformance_does_not_create_trust :
  (conforms : Bool) → (sdkResult conforms).trust = false)

#check (@sdk_conformance_does_not_create_governance_membership :
  (conforms : Bool) → (sdkResult conforms).governanceMembership = false)

#check (@sdk_conformance_does_not_create_authority :
  (conforms : Bool) →
  (sdkResult conforms).authority = false ∧
  (sdkResult conforms).evidencePromoted = false ∧
  (sdkResult conforms).capabilityInstalled = false ∧
  (sdkResult conforms).voteCreated = false ∧
  (sdkResult conforms).governanceMutated = false)

#check (@assembly_acceptance_does_not_mutate_member_authority :
  (state : SovereignState) → (vote : AssemblyVote) → (accepted : Bool) →
  (processAssemblyVote state vote).localState = state ∧
  (governanceReceipt accepted).memberLocalAuthorityMutated = false)

#check (@assembly_acceptance_does_not_change_protocol_automatically :
  (accepted : Bool) → (governanceReceipt accepted).protocolChangedAutomatically = false)

#check (@assembly_receipt_has_no_authority_effect :
  (accepted : Bool) → (governanceReceipt accepted).authorityEffect = false)

#check (@nexus_advisory_has_zero_vote_weight :
  nexusAdvisory.voteWeight = 0 ∧
  nexusAdvisory.authorityEffect = false)

#check (@transport_preserves_authenticated_identity :
  (verifiedSender : String) → (profile : TransportProfile) → (frame : TransportFrame) →
  ((admitTransport verifiedSender profile frame).accepted = true →
    (admitTransport verifiedSender profile frame).frame.sender = verifiedSender) ∧
  (frame.sender ≠ verifiedSender →
    (admitTransport verifiedSender profile frame).accepted = false))

#check (@transport_preserves_message_identity :
  (profile : TransportProfile) → (frame : TransportFrame) →
  (transport profile frame).messageId = frame.messageId)

#check (@transport_preserves_payload_reference :
  (profile : TransportProfile) → (frame : TransportFrame) →
  (transport profile frame).payloadRef = frame.payloadRef)

#check (@transport_preserves_provenance :
  (profile : TransportProfile) → (frame : TransportFrame) →
  (transport profile frame).provenanceRef = frame.provenanceRef)

#check (@nat_route_does_not_create_trust :
  (authenticatedSender ticketNode : String) →
  (natRouteAssessment authenticatedSender ticketNode).trust = false ∧
  (natRouteAssessment authenticatedSender ticketNode).authority = false)

#check (@nat_route_does_not_replace_identity :
  (authenticatedSender ticketNode : String) →
  (natRouteAssessment authenticatedSender ticketNode).identityReplacement = false ∧
  ((natRouteAssessment authenticatedSender ticketNode).senderBindingAccepted = true →
    ticketNode = authenticatedSender))

#check (@relay_does_not_create_authority :
  relayAssessment.authority = false)

#check (@relay_does_not_create_trust :
  relayAssessment.trust = false)

end QSOLFed
