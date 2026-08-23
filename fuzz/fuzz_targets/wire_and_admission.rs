#![no_main]

use libfuzzer_sys::fuzz_target;
use qsol_fed::{admit_effect, canonicalize, AdmissionDecision, FederationEffect, SignedEnvelope};

fn effect_from_byte(byte: u8) -> FederationEffect {
    match byte % 24 {
        0 => FederationEffect::OfferInformation,
        1 => FederationEffect::AdvertiseCapability,
        2 => FederationEffect::OfferEvidence,
        3 => FederationEffect::RequestEvidence,
        4 => FederationEffect::OfferHypothesis,
        5 => FederationEffect::Challenge,
        6 => FederationEffect::Respond,
        7 => FederationEffect::SubmitCouncilReport,
        8 => FederationEffect::SubmitMinorityReport,
        9 => FederationEffect::SubmitExperimentReceipt,
        10 => FederationEffect::SubmitCitation,
        11 => FederationEffect::SubmitPublication,
        12 => FederationEffect::ImportForeignState,
        13 => FederationEffect::MutateLocalGovernance,
        14 => FederationEffect::PromoteLocalEvidence,
        15 => FederationEffect::CreateOrReweightLocalVote,
        16 => FederationEffect::InstallLocalCapability,
        17 => FederationEffect::RewriteLocalHistory,
        18 => FederationEffect::MutateLocalCitizenship,
        19 => FederationEffect::ExecuteArbitraryLocalTool,
        20 => FederationEffect::ClaimLocalAuthority,
        21 => FederationEffect::WriteSecretToSemanticState,
        22 => FederationEffect::DisableConstitutionalInvariant,
        _ => FederationEffect::UnknownAuthorityBearingEffect,
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = canonicalize(data);
    let _ = SignedEnvelope::from_wire(data);

    let selector = data.first().copied().unwrap_or(0xff);
    let effect = effect_from_byte(selector);
    let decision = admit_effect(effect);

    if matches!(
        effect,
        FederationEffect::MutateLocalGovernance
            | FederationEffect::PromoteLocalEvidence
            | FederationEffect::CreateOrReweightLocalVote
            | FederationEffect::InstallLocalCapability
            | FederationEffect::RewriteLocalHistory
            | FederationEffect::MutateLocalCitizenship
            | FederationEffect::ExecuteArbitraryLocalTool
            | FederationEffect::ClaimLocalAuthority
            | FederationEffect::WriteSecretToSemanticState
            | FederationEffect::DisableConstitutionalInvariant
            | FederationEffect::UnknownAuthorityBearingEffect
    ) {
        assert!(matches!(decision, AdmissionDecision::Reject { .. }));
    }
});
