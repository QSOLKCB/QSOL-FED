import QSOLFed.Model

namespace QSOLFed

/-! Prime Directive admission -/

theorem prime_directive_accepts_data_only (input : RemoteInput) :
    primeDirective input = .acceptAsData → input = .dataOffer := by
  cases input <;> intro h <;> cases h <;> rfl

theorem prime_directive_quarantines_foreign_state :
    primeDirective .foreignState = .quarantine := rfl

theorem prime_directive_rejects_governance_mutation :
    primeDirective .governanceMutation = .reject := rfl

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

theorem valid_signature_does_not_bypass_local_rejection :
    (signedAdmission true .reject).localAdmission = .reject ∧
    (signedAdmission true .reject).localAuthorityGranted = false := by
  exact ⟨rfl, rfl⟩

/-! Peering / capability separation -/

theorem peering_does_not_create_trust (peered : Bool) :
    (peerFromPeering peered).trusted = false := rfl

theorem peering_does_not_create_admission (peered : Bool) :
    (peerFromPeering peered).admitted = false := rfl

theorem capability_requires_explicit_local_allow (peer advertisement : Bool) :
    capabilityAllowed {
      peerAdmitted := peer
      authenticatedAdvertisement := advertisement
      explicitLocalAllow := false
    } = false := by
  cases peer <;> cases advertisement <;> rfl

theorem capability_requires_peer_admission (advertisement localAllow : Bool) :
    capabilityAllowed {
      peerAdmitted := false
      authenticatedAdvertisement := advertisement
      explicitLocalAllow := localAllow
    } = false := by
  cases advertisement <;> cases localAllow <;> rfl

theorem capability_requires_authenticated_advertisement (peer localAllow : Bool) :
    capabilityAllowed {
      peerAdmitted := peer
      authenticatedAdvertisement := false
      explicitLocalAllow := localAllow
    } = false := by
  cases peer <;> cases localAllow <;> rfl

/-! Import non-authority and provenance preservation -/

/-- A direct foreign import preserves its identity, and a portable-bundle import preserves
the complete ordered collection of independent foreign provenance attributions. -/
theorem import_preserves_foreign_identity
    (id : ForeignIdentity) (state : SovereignState) (bundle : PortableBundle) :
    (importForeign id).foreignIdentity = id ∧
    (importBundle state bundle).importedBundle.attributions = bundle.attributions := by
  exact ⟨rfl, rfl⟩

theorem import_does_not_create_local_authority (id : ForeignIdentity) :
    (importForeign id).localAuthority = false := rfl

theorem import_does_not_change_trust (id : ForeignIdentity) :
    (importForeign id).trustChanged = false := rfl

/-! Lifecycle monotonicity and admission -/

theorem lifecycle_append_is_monotone
    (old : List PeerLifecycle) (event : PeerLifecycle) :
    Prefix old (old ++ [event]) := by
  exact ⟨[event], rfl⟩

/-- Every lifecycle update accepted by the model preserves the exact stored lifecycle as
a prefix. A rollback or rewritten candidate therefore cannot satisfy the admission predicate. -/
theorem lifecycle_prefix_is_transitive
    (stored candidate : List PeerLifecycle)
    (accepted : lifecycleUpdateAllowed stored candidate) :
    Prefix stored candidate := by
  exact accepted

/-! Partition sovereignty and bundle-import preservation -/

/-- Rejoin and bundle import are separate operations, but neither may overwrite the
member's existing local sovereign state. -/
theorem partition_rejoin_preserves_local_state
    (state : SovereignState) (sameSnapshot explicitLocalConfirm : Bool)
    (bundle : PortableBundle) :
    (rejoinPartition state sameSnapshot explicitLocalConfirm).localState = state ∧
    (importBundle state bundle).localState = state := by
  cases sameSnapshot <;> cases explicitLocalConfirm <;> exact ⟨rfl, rfl⟩

theorem changed_partition_snapshot_requires_reconciliation
    (state : SovereignState) (explicitLocalConfirm : Bool) :
    (rejoinPartition state false explicitLocalConfirm).reconciliationRequired = true := by
  cases explicitLocalConfirm <;> rfl

theorem unchanged_partition_snapshot_needs_no_reconciliation
    (state : SovereignState) :
    (rejoinPartition state true true).reconciliationRequired = false ∧
    (rejoinPartition state true false).reconciliationRequired = true := by
  exact ⟨rfl, rfl⟩

/-! Canonical identity determinism -/

theorem canonical_identity_deterministic
    (objectId : CanonicalBytes → String) {a b : CanonicalBytes} (h : a = b) :
    objectId a = objectId b := by
  exact congrArg objectId h

/-! Holodeck separation and safeguards -/

theorem holodeck_output_has_no_authority (frozen : Bool) :
    (safeHolodeckReceipt frozen).authorityEffect = false := rfl

theorem holodeck_output_has_no_evidence_effect (frozen : Bool) :
    (safeHolodeckReceipt frozen).evidenceEffect = false := rfl

theorem holodeck_output_has_no_federation_effect (frozen : Bool) :
    (safeHolodeckReceipt frozen).federationEffect = false := rfl

theorem holodeck_transport_does_not_relabel_network_use
    (profile : TransportProfile) (receipt : HolodeckReceipt) :
    (transportHolodeckReceipt profile receipt).networkUsed = receipt.networkUsed := rfl

theorem holodeck_end_program_terminal_even_when_frozen :
    (endProgram (safeHolodeckReceipt true)).ended = true := rfl

/-! Adapter non-authority -/

theorem adapter_output_has_no_authority :
    safeAdapterResult.localGovernanceAuthority = false ∧
    safeAdapterResult.authorityEffect = false := by
  exact ⟨rfl, rfl⟩

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
    (sdkResult conforms).authority = false := rfl

/-! Assembly sovereignty -/

theorem assembly_acceptance_does_not_mutate_member_authority (accepted : Bool) :
    (governanceReceipt accepted).memberLocalAuthorityMutated = false := rfl

theorem assembly_acceptance_does_not_change_protocol_automatically (accepted : Bool) :
    (governanceReceipt accepted).protocolChangedAutomatically = false := rfl

theorem assembly_receipt_has_no_authority_effect (accepted : Bool) :
    (governanceReceipt accepted).authorityEffect = false := rfl

theorem nexus_advisory_has_zero_vote_weight :
    nexusAdvisory.voteWeight = 0 := rfl

/-! Transport identity and provenance independence -/

theorem transport_preserves_authenticated_identity
    (profile : TransportProfile) (frame : TransportFrame) :
    (transport profile frame).sender = frame.sender := rfl

theorem transport_preserves_message_identity
    (profile : TransportProfile) (frame : TransportFrame) :
    (transport profile frame).messageId = frame.messageId := rfl

theorem transport_preserves_payload_reference
    (profile : TransportProfile) (frame : TransportFrame) :
    (transport profile frame).payloadRef = frame.payloadRef := rfl

theorem transport_preserves_provenance
    (profile : TransportProfile) (frame : TransportFrame) :
    (transport profile frame).provenanceRef = frame.provenanceRef := rfl

theorem nat_route_does_not_create_trust :
    natRouteAssessment.trust = false := rfl

theorem nat_route_does_not_replace_identity :
    natRouteAssessment.identityReplacement = false := rfl

theorem relay_does_not_create_authority :
    relayAssessment.authority = false := rfl

theorem relay_does_not_create_trust :
    relayAssessment.trust = false := rfl

end QSOLFed
