//! Actual DSSE/current-proof/quota mechanics under private test-only witnesses.
//! The witness is absent from the binary and never qualifies native authority.
use super::super::{
    core_access_fixture as original_fixture,
    signing_test_support::{Fixture, NOW, native},
};
use super::*;
use ed25519_dalek::SigningKey;
use fw_planner::{PolicyAssociation, PolicyReviewEvidence, compose_access_patch};
use std::collections::BTreeSet;

const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

fn claim(f: &mut Fixture, job: &str) -> signing_jobs::SigningClaim {
    let tx = f
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let result =
        signing_jobs::claim_in_tx(&tx, &f.tenant, job, "signer", WORKER, 0, 30, NOW).unwrap();
    tx.commit().unwrap();
    result
}

fn sign(
    f: &mut Fixture,
    claim: &signing_jobs::SigningClaim,
    authority: &ProtectedSigningAuthority,
    now: i64,
) -> Result<SignerResult> {
    let tx = f
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let signed = sign_claim_in_tx(
        &tx,
        &f.tenant,
        &f.verifier,
        claim,
        "fixture-signing-key",
        &SigningKey::from_bytes(&[81; 32]),
        authority,
        now,
    )?;
    tx.commit()?;
    Ok(signed)
}

#[test]
fn retained_signer_uses_real_current_originals_and_returns_exact_committed_retry() {
    let mut f = Fixture::new();
    let intent = test_prepare(&mut f, NOW).intent;
    let claim = claim(&mut f, &intent.job_id);
    let result = sign(&mut f, &claim, &test_authority(), NOW).unwrap();
    assert_eq!(
        result.signed_grant.dsse.payload_type,
        crate::POLICY_CHANGE_GRANT_TYPE
    );
    assert_eq!(f.count("authority_signing_results"), 1);
    assert_eq!(f.count("authority_signing_outbox"), 1);
    assert!(matches!(
        f.store
            .claim_signing_dispatch(&f.tenant, &intent.job_id, WORKER, 0, 30, NOW),
        Err(AuthorityError::Invalid(
            "protected signing authority unavailable"
        ))
    ));
    let retry = f
        .store
        .sign_retained_job(
            &f.tenant,
            &f.verifier,
            &intent.job_id,
            WORKER,
            999,
            "fixture-signing-key",
            &SigningKey::from_bytes(&[81; 32]),
            NOW + 301,
        )
        .unwrap();
    assert_eq!(bytes(&retry).unwrap(), bytes(&result).unwrap());
    assert_eq!(f.count("authority_signing_quota_usage"), 1);
}

#[test]
fn signer_checks_revocation_and_quota_cutover_before_using_the_key() {
    for revoked in ["credential", "role", "quota"] {
        let mut f = Fixture::new();
        let intent = test_prepare(&mut f, NOW).intent;
        let claim = claim(&mut f, &intent.job_id);
        match revoked {
            "credential" => f
                .store
                .revoke_credential(&f.tenant, &f.credential_id, NOW + 1)
                .unwrap(),
            "role" => f
                .store
                .revoke_role(&f.tenant, &f.membership_id, NOW + 1)
                .unwrap(),
            _ => f
                .store
                .revoke_signing_project_quota(&f.tenant, 1, NOW + 1)
                .unwrap(),
        }
        assert!(sign(&mut f, &claim, &test_authority(), NOW + 1).is_err());
        assert_eq!(f.count("authority_signing_results"), 0);
        assert_eq!(f.count("authority_signing_quota_usage"), 0);
        assert_eq!(f.count("authority_signing_outbox"), 0);
    }
}

#[test]
fn signer_refuses_wrong_purpose_key_and_keeps_commit_atomic_on_audit_failure() {
    let mut f = Fixture::new();
    let intent = test_prepare(&mut f, NOW).intent;
    let claim = claim(&mut f, &intent.job_id);
    let mut wrong = test_authority();
    wrong.trust.payload_type = crate::CORE_GRANT_TYPE.into();
    assert!(matches!(
        sign(&mut f, &claim, &wrong, NOW),
        Err(AuthorityError::Signature)
    ));
    let mut wrong = test_authority();
    wrong.trust.public_key = SigningKey::from_bytes(&[82; 32]).verifying_key().to_bytes();
    assert!(matches!(
        sign(&mut f, &claim, &wrong, NOW),
        Err(AuthorityError::Signature)
    ));
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = attempts.clone();
    // Test-only authorizer replaces the raw connection hook without changing
    // the released schema; rejection reaches the real composed audit write.
    f.store
        .connection
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Insert {
                    table_name: "authority_audit"
                }
            ) && observed.fetch_add(1, Ordering::SeqCst) + 1 == 3
            {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
    assert!(sign(&mut f, &claim, &test_authority(), NOW).is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert_eq!(f.count("authority_signing_results"), 0);
    assert_eq!(f.count("authority_signing_quota_usage"), 0);
    assert_eq!(f.count("authority_signing_outbox"), 0);
    f.reopen();
    sign(&mut f, &claim, &test_authority(), NOW).unwrap();
    assert_eq!(f.count("authority_signing_quota_usage"), 1);
}

#[test]
fn retained_evidence_rejects_other_payloads_and_call_times() {
    let mut f = Fixture::new();
    let intent = test_prepare(&mut f, NOW).intent;
    let tx = f.store.connection.transaction().unwrap();
    let prepared = job_at(&tx, &f.tenant, &intent.job_id).unwrap();
    let checked = snapshot(
        &tx,
        &f.tenant,
        &f.verifier,
        &test_request_from_intent(&tx, &f.tenant, &intent.intent_id),
        NOW,
    )
    .unwrap();
    let evidence = RetainedJobEvidence {
        payload_bytes: prepared.payload_bytes().to_vec(),
        context: grant_context(&f.tenant, &checked, NOW).unwrap(),
    };
    let mut changed = prepared.job().payload.clone();
    changed["target_generation"] = "2".into();
    assert!(crate::AuthorityEvidence::verify_for_signing(&evidence, &changed, NOW).is_err());
    assert!(
        crate::AuthorityEvidence::verify_for_signing(&evidence, &prepared.job().payload, NOW + 1)
            .is_err()
    );
}

fn test_request_from_intent(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    intent: &str,
) -> SigningRequest {
    intent_at(tx, tenant, intent).unwrap().request
}

fn core_fixture() -> (Fixture, crate::CoreAccessProvenance) {
    let mut f = Fixture::new();
    let (mut plan, mut original) = original_fixture::fixture_at(NOW);
    for field in [
        "org_id",
        "project_id",
        "target_id",
        "principal_id",
        "source_snapshot_hash",
        "target_capability_hash",
    ] {
        plan[field] = f.plan[field].clone();
    }
    plan["target_generation"] = "1".into();
    let mut scope = serde_json::to_value(&f.review.before.policies[0].scope).unwrap();
    scope["transport"] = plan["requested_policies"][0]["scope"]["transport"].clone();
    {
        let policy = &mut plan["requested_policies"][0];
        for field in ["org_id", "project_id", "target_id"] {
            policy[field] = f.plan[field].clone();
        }
        policy["scope"] = scope.clone();
        policy["log_mode"] = "none".into();
        policy["lifetime"]["not_before"] = at(NOW).unwrap().into();
        policy["lifetime"]["expires_at"] = at(NOW + 3600).unwrap().into();
        let normalized: fw_domain::Policy = serde_json::from_value(policy.clone()).unwrap();
        *policy = serde_json::to_value(normalized.normalized().unwrap()).unwrap();
    }
    original.envelope.org_id = f.tenant.org_id.clone();
    original.envelope.project_id = f.tenant.project_id.clone();
    original.envelope.target_id = native::TARGET.into();
    original.envelope.scope = serde_json::from_value(scope.clone()).unwrap();
    original.envelope.excluded_destination_cidrs.clear();
    original.delegation.org_id = f.tenant.org_id.clone();
    original.delegation.project_id = f.tenant.project_id.clone();
    original.delegation.target_id = native::TARGET.into();
    original.delegation.allowed_principal_ids =
        vec![f.plan["principal_id"].as_str().unwrap().into()];
    original.request.source_asset_ids =
        serde_json::from_value(scope["source_asset_ids"].clone()).unwrap();
    original.request.destination_asset_ids =
        serde_json::from_value(scope["destination_asset_ids"].clone()).unwrap();
    original.delegation.source_asset_ids = original.request.source_asset_ids.clone();
    original.delegation.destination_asset_ids = original.request.destination_asset_ids.clone();
    original_fixture::rehash(&mut plan, &mut original);
    let requirements = f.requirements.clone();
    plan["approval_requirements_hash"] = canonical_hash(&requirements).unwrap().into();
    // Preserve the exact currently observed baseline from the original fixture.
    // A conflicting baseline at the same generation must remain a refusal.
    let before = f.review.before.clone();
    let policies: Vec<fw_domain::Policy> =
        serde_json::from_value(plan["requested_policies"].clone()).unwrap();
    let basis = fw_planner::core_access_authority_basis_hash(&plan).unwrap();
    let associations = policies
        .iter()
        .map(|policy| PolicyAssociation {
            policy_hash: canonical_hash(policy).unwrap(),
            lease_id: Some(original.lease_id.clone()),
            request_id: original.request_id.clone(),
            authority_basis_hash: basis.clone(),
        })
        .collect::<Vec<_>>();
    let composed =
        compose_access_patch(&before, &policies, &associations, &BTreeSet::new()).unwrap();
    plan["baseline_hash"] = composed.baseline_hash.into();
    plan["desired_state_hash"] = composed.desired_state_hash.into();
    plan["request_patch_hash"] = composed.request_patch_hash.into();
    plan["rollback_authority"]["baseline_hash"] = plan["baseline_hash"].clone();
    plan["effect_summary"] = serde_json::to_value(
        fw_planner::core_access_effect_summary(&before, &composed.state).unwrap(),
    )
    .unwrap();
    plan["artifact_hash"] = fw_backend_linux::compile_portable(&composed.state, &f.references)
        .unwrap()
        .artifact_hash()
        .unwrap()
        .into();
    let review = PolicyReviewEvidence {
        before,
        after: composed.state,
    };
    let window = super::super::core_access_review_fixture::window(&plan, &original);
    f.store
        .register_reviewed_core_access_plan(
            &f.tenant,
            &plan,
            &requirements,
            &review,
            &original,
            &window,
            NOW,
        )
        .unwrap();
    f.store
        .register_native_compilation(&f.tenant, plan["plan_id"].as_str().unwrap(), 1, NOW)
        .unwrap();
    let compiled = fw_native_evidence::compile_evidence(&plan, &review, &f.references).unwrap();
    let installation = native::installation(compiled.baseline(), NOW);
    let challenge = f
        .store
        .challenge_native_observation(
            &f.tenant,
            plan["plan_id"].as_str().unwrap(),
            fw_native_evidence::ArtifactRole::Baseline,
            &installation,
            Some(&f.baseline_receipt_hash),
            1,
            1,
            NOW,
        )
        .unwrap();
    let proof = native::proof(
        &challenge,
        installation.clone(),
        native::snapshot(&installation.native),
        NOW,
    );
    f.store
        .admit_native_observation(&f.tenant, &proof, NOW)
        .unwrap();
    let approval_hash = f.approve(plan["plan_id"].as_str().unwrap(), NOW);
    f.plan = plan;
    f.review = review;
    f.current_approval_hash = approval_hash;
    let d = &original.delegation;
    let pin = SigningRootQuotaPin {
        root_id: d.root_id.clone(),
        not_before: NOW,
        not_after: NOW + 7200,
        limits: SigningQuotaLimits {
            active_leases: d.max_active_leases as i64,
            new_leases_per_day: d.max_new_leases_per_day as i64,
            unique_destinations_per_day: d.max_unique_destinations_per_day as i64,
            cumulative_seconds_per_day: d.max_cumulative_lease_seconds_per_day as i64,
            concurrent_deployments: d.max_concurrent_deployments as i64,
        },
    };
    f.store
        .pin_signing_root_quota(&f.tenant, &pin, None, NOW)
        .unwrap();
    f.store
        .pin_signing_project_quota(&f.tenant, &pin, None, NOW)
        .unwrap();
    test_initialize(&mut f, NOW);
    (f, original)
}

#[test]
fn strict_core_job_lifecycle_derives_original_cost_and_durable_exact_signature() {
    let (mut f, original) = core_fixture();
    let request = test_request(&f);
    let mut authority = test_authority();
    authority.trust.payload_type = crate::CORE_GRANT_TYPE.into();
    let tx = f
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let prepared = prepare_in_tx(&tx, &f.tenant, &f.verifier, &request, &authority, NOW).unwrap();
    tx.commit().unwrap();
    let claim = claim(&mut f, &prepared.intent.job_id);
    let result = sign(&mut f, &claim, &authority, NOW).unwrap();
    let payload = &result.signed_grant.payload;
    assert_eq!(payload["schema_version"], "f.grant/v1");
    assert_eq!(payload["lease_id"], original.lease_id);
    assert_eq!(payload["request_id"], original.request_id);
    assert_eq!(
        payload["reservation"]["projected_cumulative_lease_seconds_per_day"],
        3600
    );
    assert_eq!(payload["reservation"]["projected_active_leases"], 1);
    assert!(payload.get("dispatch_reservation_id").is_none());
    assert!(matches!(
        f.store
            .claim_signing_dispatch(&f.tenant, &prepared.intent.job_id, WORKER, 0, 30, NOW),
        Err(AuthorityError::Binding)
    ));
    f.reopen();
    let retry = f
        .store
        .sign_retained_job(
            &f.tenant,
            &f.verifier,
            &prepared.intent.job_id,
            WORKER,
            99,
            "fixture-signing-key",
            &SigningKey::from_bytes(&[81; 32]),
            NOW + 301,
        )
        .unwrap();
    assert_eq!(bytes(&result).unwrap(), bytes(&retry).unwrap());
    assert_eq!(f.count("authority_signing_results"), 1);
    assert_eq!(f.count("authority_signing_quota_usage"), 1);
}
