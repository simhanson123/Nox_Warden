#![cfg(feature = "approval-proofs")]
//! Same-plan diagnostics over real synthetic owner, signer and peer signatures.
//! The readback fixture is structural evidence, never native qualification.
#[allow(dead_code)]
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/core_access_review_fixture.rs"]
mod core_review;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/registry_fixture.rs"]
mod registry_fixture;
#[path = "support/target_bootstrap_fixture.rs"]
mod target_fixture;

use fw_authority::*;
use fw_contracts::canonical_hash;
use fw_domain::Policy;
use fw_planner::{compose_access_patch, core_access_effect_summary};
use registry_fixture::{Fixture, NOW};
use serde_json::Value;
use std::collections::BTreeSet;
use target_fixture::TargetFixture;

fn register_matching_plan(f: &mut Fixture, target: &TargetFixture) -> String {
    let (mut plan, requirements, _, mut provenance, _) = core_review::fixture_at(NOW, 0);
    provenance.envelope = f.envelope.clone();
    provenance.delegation = f.delegation.clone();
    plan["authority_epoch"] = f.manifest.new_epoch.clone().into();
    plan["target_capability_hash"] = target.capability.hash().unwrap().into();
    plan["workload_binding_hash"] = canonical_hash(&f.workload).unwrap().into();
    plan["workload_binding_valid_until"] = f.workload.payload.expires_at.clone().into();
    core_review::core::rehash(&mut plan, &mut provenance);
    let mut review = core_review::rebuild(&mut plan, &provenance);
    review.before.management_baseline_hash = target.baseline.hash().unwrap();
    let policies: Vec<Policy> = serde_json::from_value(plan["requested_policies"].clone()).unwrap();
    let candidate = compose_access_patch(
        &review.before,
        &policies,
        &review.after.associations,
        &BTreeSet::new(),
    )
    .unwrap();
    plan["baseline_hash"] = candidate.baseline_hash.into();
    plan["desired_state_hash"] = candidate.desired_state_hash.into();
    plan["request_patch_hash"] = candidate.request_patch_hash.into();
    plan["rollback_authority"]["baseline_hash"] = plan["baseline_hash"].clone();
    review.after = candidate.state;
    plan["effect_summary"] =
        serde_json::to_value(core_access_effect_summary(&review.before, &review.after).unwrap())
            .unwrap();
    review.verify(&plan).unwrap();
    let window = core_review::window(&plan, &provenance);
    f.store
        .provision_target_metadata_project(&f.tenant, NOW)
        .unwrap();
    f.store
        .register_reviewed_core_access_plan(
            &f.tenant,
            &plan,
            &requirements,
            &review,
            &provenance,
            &window,
            NOW,
        )
        .unwrap();
    plan["plan_id"].as_str().unwrap().to_owned()
}
fn has_gate(status: &SigningReadinessV3, gate: AuthorityGate) -> bool {
    status
        .snapshot
        .snapshot
        .reasons
        .iter()
        .any(|reason| reason == gate.code())
}
fn no_production(status: &SigningReadinessV3) {
    assert!(
        !status.snapshot.snapshot.signing_allowed && !status.snapshot.snapshot.dispatch_allowed
    );
    for gate in [
        AuthorityGate::BuildIdentityRequired,
        AuthorityGate::NativeQualificationRequired,
        AuthorityGate::PolicySignerKeyRequired,
        AuthorityGate::WorkloadSourceAttestationRequired,
        AuthorityGate::CoreSigningProfileUnavailable,
    ] {
        assert!(has_gate(status, gate), "{}", gate.code());
    }
}

#[test]
fn canonical_readiness_binds_current_receipt_to_plan_and_retains_expired_epoch_history() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let target = TargetFixture::new(&mut f);
    let plan = register_matching_plan(&mut f, &target);
    f.store
        .pin_target_bootstrap_key(&f.tenant, &target.pin, None, NOW)
        .unwrap();
    f.approve(2);
    let authorization = f.authorize();
    let pending = f
        .store
        .signing_readiness_v3(&f.tenant, &plan, &f.verifier, NOW)
        .unwrap();
    assert_eq!(
        pending.bootstrap_authorization_hash.as_deref(),
        Some(authorization.status.content_hash.as_str())
    );
    assert!(!has_gate(
        &pending,
        AuthorityGate::BootstrapAuthorizationRequired
    ));
    assert!(has_gate(
        &pending,
        AuthorityGate::TargetEpochConfirmationRequired
    ));
    assert!(pending.target_bootstrap.is_none());
    no_production(&pending);
    let bundle = f
        .store
        .issue_target_bootstrap_challenge(
            &f.tenant,
            &f.manifest.manifest_id,
            None,
            &target.baseline,
            &target.capability,
            NOW,
        )
        .unwrap();
    let receipt = target.receipt(bundle.challenge, NOW);
    let accepted = f
        .store
        .admit_target_bootstrap_confirmation(&f.tenant, &receipt, NOW + 1)
        .unwrap();
    let current = f
        .store
        .signing_readiness_v3(&f.tenant, &plan, &f.verifier, NOW + 1)
        .unwrap();
    assert!(!has_gate(
        &current,
        AuthorityGate::TargetEpochConfirmationRequired
    ));
    let history = current.target_bootstrap.as_ref().unwrap();
    assert!(history.current_for_plan && history.current_confirmation_eligibility);
    assert_eq!(history.confirmation_hash, accepted.confirmation_hash);
    assert_eq!(history.accepted_epoch, "1");
    assert_eq!(history.highest_generation, "0");
    assert_eq!(history.state, "target_confirmed_pending_qualification");
    assert!(current.snapshot.snapshot.valid_until <= history.valid_until);
    no_production(&current);
    for version in [1, 2] {
        let result = if version == 1 {
            f.store
                .signing_readiness(&f.tenant, &plan, &f.verifier, NOW + 1)
                .map(|_| ())
        } else {
            f.store
                .signing_readiness_v2(&f.tenant, &plan, &f.verifier, NOW + 1)
                .map(|_| ())
        };
        assert!(matches!(
            result,
            Err(AuthorityError::Invalid(SIGNING_READINESS_V3_REQUIRED))
        ));
    }
    let expired = f
        .store
        .signing_readiness_v3(&f.tenant, &plan, &f.verifier, NOW + 301)
        .unwrap();
    let retained = expired.target_bootstrap.as_ref().unwrap();
    assert_eq!(retained.confirmation_hash, accepted.confirmation_hash);
    assert_eq!(retained.accepted_epoch, "1");
    assert!(!retained.current_for_plan && !retained.current_confirmation_eligibility);
    assert!(has_gate(
        &expired,
        AuthorityGate::TargetEpochConfirmationRequired
    ));
    no_production(&expired);
    assert!(matches!(
        f.store
            .signing_readiness_v2(&f.tenant, &plan, &f.verifier, NOW + 301),
        Err(AuthorityError::Invalid(SIGNING_READINESS_V3_REQUIRED))
    ));
    let serialized = serde_json::to_value(expired).unwrap();
    assert_eq!(serialized["schema_version"], "fw.signing-readiness/v3");
    assert_eq!(
        serialized["target_bootstrap"]["accepted_epoch"],
        Value::String("1".into())
    );
}
