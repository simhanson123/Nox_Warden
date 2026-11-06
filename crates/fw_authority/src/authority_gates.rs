//! Shared diagnostic reasons for authority prerequisites.
//!
//! A gate describes one missing prerequisite in the context of a particular
//! read. It never supplies permission, and different reads need not have the
//! same gate set. Published legacy readiness versions retain their explicit
//! compatibility projection rather than introducing aliases here.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityGate {
    BootstrapApprovalOriginRequired,
    BootstrapAuthorizationRequired,
    BootstrapAuthorizationNotCurrent,
    BuildIdentityRequired,
    NativeQualificationRequired,
    TargetEpochConfirmationRequired,
    PolicySignerKeyRequired,
    WorkloadSourceAttestationRequired,
    WorkloadBindingNotCurrent,
    OwnerProofRequired,
    ProtectedSignerUnavailable,
    PlanStale,
    ReviewEvidenceMissing,
    ApprovalSetMissing,
    TargetMetadataMissing,
    NativeBaselineUnavailable,
    QuotaConfigurationMissing,
    TargetGenerationUninitialized,
    CoreRequestBindingUnavailable,
    CoreSigningProfileUnavailable,
}

impl AuthorityGate {
    pub const fn code(self) -> &'static str {
        match self {
            Self::BootstrapApprovalOriginRequired => "BOOTSTRAP_APPROVAL_ORIGIN_REQUIRED",
            Self::BootstrapAuthorizationRequired => "BOOTSTRAP_AUTHORIZATION_REQUIRED",
            Self::BootstrapAuthorizationNotCurrent => "BOOTSTRAP_AUTHORIZATION_NOT_CURRENT",
            Self::BuildIdentityRequired => "BUILD_IDENTITY_REQUIRED",
            Self::NativeQualificationRequired => "NATIVE_QUALIFICATION_REQUIRED",
            Self::TargetEpochConfirmationRequired => "TARGET_EPOCH_CONFIRMATION_REQUIRED",
            Self::PolicySignerKeyRequired => "POLICY_SIGNER_KEY_REQUIRED",
            Self::WorkloadSourceAttestationRequired => "WORKLOAD_SOURCE_ATTESTATION_REQUIRED",
            Self::WorkloadBindingNotCurrent => "WORKLOAD_BINDING_NOT_CURRENT",
            Self::OwnerProofRequired => "OWNER_PROOF_REQUIRED",
            Self::ProtectedSignerUnavailable => "PROTECTED_SIGNER_UNAVAILABLE",
            Self::PlanStale => "PLAN_STALE",
            Self::ReviewEvidenceMissing => "REVIEW_EVIDENCE_MISSING",
            Self::ApprovalSetMissing => "APPROVAL_SET_MISSING",
            Self::TargetMetadataMissing => "TARGET_METADATA_MISSING",
            Self::NativeBaselineUnavailable => "NATIVE_BASELINE_UNAVAILABLE",
            Self::QuotaConfigurationMissing => "QUOTA_CONFIGURATION_MISSING",
            Self::TargetGenerationUninitialized => "TARGET_GENERATION_UNINITIALIZED",
            Self::CoreRequestBindingUnavailable => "CORE_REQUEST_BINDING_UNAVAILABLE",
            Self::CoreSigningProfileUnavailable => "CORE_SIGNING_PROFILE_UNAVAILABLE",
        }
    }
}

/// Preserve the caller's contextual ordering without inventing prerequisites.
pub fn authority_gate_codes(gates: &[AuthorityGate]) -> Vec<String> {
    gates.iter().map(|gate| gate.code().to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_codes_are_stable_and_serde_has_no_legacy_aliases() {
        let gates = [
            AuthorityGate::BootstrapApprovalOriginRequired,
            AuthorityGate::BootstrapAuthorizationRequired,
            AuthorityGate::BootstrapAuthorizationNotCurrent,
            AuthorityGate::BuildIdentityRequired,
            AuthorityGate::NativeQualificationRequired,
            AuthorityGate::TargetEpochConfirmationRequired,
            AuthorityGate::PolicySignerKeyRequired,
            AuthorityGate::WorkloadSourceAttestationRequired,
            AuthorityGate::WorkloadBindingNotCurrent,
            AuthorityGate::OwnerProofRequired,
            AuthorityGate::ProtectedSignerUnavailable,
            AuthorityGate::PlanStale,
            AuthorityGate::ReviewEvidenceMissing,
            AuthorityGate::ApprovalSetMissing,
            AuthorityGate::TargetMetadataMissing,
            AuthorityGate::NativeBaselineUnavailable,
            AuthorityGate::QuotaConfigurationMissing,
            AuthorityGate::TargetGenerationUninitialized,
            AuthorityGate::CoreRequestBindingUnavailable,
            AuthorityGate::CoreSigningProfileUnavailable,
        ];
        let codes = authority_gate_codes(&gates);
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), gates.len());
        assert_eq!(
            serde_json::to_value(gates).unwrap(),
            serde_json::json!(codes)
        );
        for gate in gates {
            assert_eq!(
                serde_json::from_value::<AuthorityGate>(serde_json::json!(gate.code())).unwrap(),
                gate
            );
        }
        for legacy in [
            "PROTECTED_BOOTSTRAP_REQUIRED",
            "BUILD_IDENTITY_UNVERIFIED",
            "NATIVE_QUALIFICATION_UNAVAILABLE",
        ] {
            assert!(serde_json::from_value::<AuthorityGate>(serde_json::json!(legacy)).is_err());
        }
    }
}
