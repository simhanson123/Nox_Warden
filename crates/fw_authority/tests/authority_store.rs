#![cfg(feature = "approval-proofs")]

//! Real signatures against the durable authority transaction. These software
//! authenticators establish storage and verifier behavior, not human consent or
//! the deployment's operating-system trust boundary.
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;

use approval_authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_authority::{
    ApprovalDecision, ApprovalRole, AuthorityStore, AuthorityTenant, DecisionResult, IssuedApproval,
};
use fw_webauthn::{AuthenticationResponse, Credential, WebAuthn};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};
use tempfile::TempDir;

const NOW: i64 = 1_700_000_000;
const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const PLAN: &str = "44444444-4444-4444-8444-444444444444";
const OTHER: &str = "99999999-9999-4999-8999-999999999999";
const IDEMPOTENCY: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const IDEMPOTENCY_2: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn time(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn requirements() -> Value {
    json!({
        "schema_version": "f.approval-requirements/v1",
        "profile": "lab_owner", "minimum_humans": 1,
        "required_roles": ["owner"], "distinct_principals": true,
        "author_may_approve": true, "max_approval_age_seconds": 3600,
        "require_webauthn": true,
        "role_policy_hash": fw_contracts::hash_bytes(b"independently configured role policy")
    })
}

fn plan(requirements: &Value) -> Value {
    let hash = fw_contracts::hash_bytes(b"synthetic immutable plan evidence");
    let operations = json!([{
        "op": "remove_policy", "policy_id": OTHER, "expected_revision": 1,
        "expected_policy_hash": hash
    }]);
    let gates: Vec<Value> = [
        "schema",
        "identity",
        "scope",
        "quota",
        "semantic",
        "expiry",
        "capability",
        "baseline",
    ]
    .into_iter()
    .map(|gate| {
        json!({
            "gate_id": gate, "required": true, "result": "PASS", "evidence_hash": hash
        })
    })
    .collect();
    json!({
        "schema_version": "f.policy-change-plan/v1", "change_kind": "policy_change",
        "plan_id": PLAN, "request_id": OTHER, "request_revision": 1, "request_hash": hash,
        "org_id": ORG, "project_id": PROJECT, "target_id": OTHER, "principal_id": PRINCIPAL,
        "created_at": time(NOW), "valid_until": time(NOW + 3600),
        "request_patch_hash": fw_contracts::canonical_hash(&operations).unwrap(),
        "operations": operations,
        "baseline_hash": hash, "desired_state_hash": hash,
        "candidate_state_ref": {
            "store_id": "authority_test", "object_hash": hash,
            "media_type": "application/json", "size_bytes": 128
        },
        "source_snapshot_hash": hash, "target_capability_hash": hash,
        "guardrail_hash": hash, "compiler_hash": hash, "validator_hash": hash,
        "artifact_hash": hash, "validation_report_hash": hash,
        "effect_summary": {
            "relation": "restricting", "newly_allowed_region_hash": hash,
            "removed_region_hash": hash, "counterexample_hashes": [],
            "analysis_profile": "native-union-minus-deny/v1", "complete": true
        },
        "gates": gates,
        "approval_requirements_hash": fw_contracts::canonical_hash(requirements).unwrap(),
        "probe_spec_hash": hash, "authority_epoch": "1", "target_generation": "1",
        "confirm_timeout_seconds": 60,
        "rollback_authority": {
            "profile": "preserve-current-restrictions", "scope_bound_hash": hash,
            "baseline_hash": hash, "artifact_hash": hash, "valid_until": time(NOW + 3600)
        },
        "normalization_version": "f.normalize/nfc-v1"
    })
}

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    verifier: WebAuthn,
    key: Authenticator,
    credential: Credential,
    membership: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with_counter(1)
    }

    fn with_counter(counter: u32) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Authority test key", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        store
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://identity.example.test",
                "reviewer-alice",
                NOW,
            )
            .unwrap();
        store
            .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
            .unwrap();
        let activation = store
            .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
            .unwrap();
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &key.assertion(&activation.options, counter, 0x05, ORIGIN),
                &verifier,
                NOW,
            )
            .unwrap();
        let membership = store
            .grant_role(
                &tenant,
                PRINCIPAL,
                ApprovalRole::Owner,
                NOW,
                NOW + 7200,
                NOW,
            )
            .unwrap();
        let requirements = requirements();
        store
            .register_plan(&tenant, &plan(&requirements), &requirements, NOW)
            .unwrap();
        Self {
            _directory: directory,
            path,
            store,
            tenant,
            verifier,
            key,
            credential,
            membership,
        }
    }

    fn issue(&mut self, decision: ApprovalDecision, now: i64) -> IssuedApproval {
        self.store
            .issue_challenge(
                &self.tenant,
                PRINCIPAL,
                &self.credential.id(),
                PLAN,
                ApprovalRole::Owner,
                decision,
                &self.verifier,
                now,
            )
            .unwrap()
    }

    fn submit(
        &mut self,
        issued: &IssuedApproval,
        response: &AuthenticationResponse,
        key: &str,
        now: i64,
    ) -> fw_authority::Result<DecisionResult> {
        self.store.admit_decision(
            &self.tenant,
            PRINCIPAL,
            issued.challenge.challenge_id(),
            key,
            response,
            &self.verifier,
            now,
        )
    }

    fn restart(&mut self) {
        self.store = AuthorityStore::open(&self.path).unwrap();
    }
}

#[test]
fn signed_decision_and_exact_retry_survive_restart_without_changing_result() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let first = f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    assert!(!first.replayed);
    assert_eq!(first.approval["decision"], "approve");
    assert_eq!(
        first.approval["challenge_id"],
        issued.challenge.challenge_id()
    );
    f.restart();
    let replay = f
        .submit(&issued, &response, IDEMPOTENCY, NOW + 600)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(first.approval, replay.approval);
}

#[test]
fn issued_challenge_and_private_verification_state_survive_restart_before_response() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    f.restart();
    let recorded = f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    assert!(!recorded.replayed);
    assert_eq!(
        recorded.approval["challenge_id"],
        issued.challenge.challenge_id()
    );
}

#[test]
fn challenge_cannot_be_consumed_again_with_different_bytes_or_idempotency_key() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    let changed = f.key.assertion(&issued.options, 3, 0x05, ORIGIN);
    assert!(f.submit(&issued, &changed, IDEMPOTENCY, NOW + 2).is_err());
    assert!(
        f.submit(&issued, &response, IDEMPOTENCY_2, NOW + 2)
            .is_err()
    );
    assert!(
        f.submit(&issued, &response, IDEMPOTENCY, NOW + 2)
            .unwrap()
            .replayed
    );
}

#[test]
fn zero_counter_authenticator_still_has_durable_one_use_challenge() {
    let mut f = Fixture::with_counter(0);
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 0, 0x05, ORIGIN);
    let first = f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    f.restart();
    assert!(
        f.submit(&issued, &response, IDEMPOTENCY_2, NOW + 2)
            .is_err()
    );
    let replay = f.submit(&issued, &response, IDEMPOTENCY, NOW + 2).unwrap();
    assert!(replay.replayed);
    assert_eq!(first.approval, replay.approval);
}

#[test]
fn invalid_signature_does_not_consume_challenge_or_advance_credential() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let mut forged = response.clone();
    forged.response.signature = "AA".into();
    assert!(f.submit(&issued, &forged, IDEMPOTENCY, NOW + 1).is_err());
    f.restart();
    let accepted = f.submit(&issued, &response, IDEMPOTENCY, NOW + 2).unwrap();
    assert!(!accepted.replayed);
}

#[test]
fn proof_user_verification_and_original_origin_are_required() {
    for (flags, origin) in [
        (0x01, ORIGIN),
        (0x04, ORIGIN),
        (0x05, "http://localhost:9999"),
    ] {
        let mut f = Fixture::new();
        let issued = f.issue(ApprovalDecision::Approve, NOW);
        let invalid = f.key.assertion(&issued.options, 2, flags, origin);
        assert!(f.submit(&issued, &invalid, IDEMPOTENCY, NOW + 1).is_err());
        let valid = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
        assert!(f.submit(&issued, &valid, IDEMPOTENCY, NOW + 2).is_ok());
    }
}

#[test]
fn challenge_expiry_and_cross_tenant_or_principal_replays_are_rejected() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let other_tenant = AuthorityTenant::new(ORG, OTHER).unwrap();
    assert!(
        f.store
            .admit_decision(
                &other_tenant,
                PRINCIPAL,
                issued.challenge.challenge_id(),
                IDEMPOTENCY,
                &response,
                &f.verifier,
                NOW + 1,
            )
            .is_err()
    );
    assert!(
        f.store
            .admit_decision(
                &f.tenant,
                OTHER,
                issued.challenge.challenge_id(),
                IDEMPOTENCY,
                &response,
                &f.verifier,
                NOW + 1,
            )
            .is_err()
    );
    assert!(
        f.submit(
            &issued,
            &response,
            IDEMPOTENCY,
            issued.challenge.expires_at()
        )
        .is_err()
    );
}

#[test]
fn current_credential_revocation_blocks_previously_issued_challenge() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    f.store
        .revoke_credential(&f.tenant, &f.credential.id(), NOW + 1)
        .unwrap();
    f.restart();
    assert!(f.submit(&issued, &response, IDEMPOTENCY, NOW + 2).is_err());
    assert!(
        f.store
            .begin_credential_activation(&f.tenant, &f.credential.id(), &f.verifier, NOW + 2)
            .is_err()
    );
    assert!(
        f.store
            .pin_credential(&f.tenant, &f.credential, NOW + 2, NOW + 7200, NOW + 2)
            .is_err()
    );
}

#[test]
fn revoked_role_cannot_be_resurrected_to_use_an_old_challenge() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    f.store
        .revoke_role(&f.tenant, &f.membership, NOW + 1)
        .unwrap();
    assert!(f.submit(&issued, &response, IDEMPOTENCY, NOW + 2).is_err());
    f.store
        .grant_role(
            &f.tenant,
            PRINCIPAL,
            ApprovalRole::Owner,
            NOW + 2,
            NOW + 7200,
            NOW + 2,
        )
        .unwrap();
    assert!(f.submit(&issued, &response, IDEMPOTENCY, NOW + 3).is_err());
}

#[test]
fn retired_plan_blocks_previously_issued_challenge() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    f.store.retire_plan(&f.tenant, PLAN, NOW + 1).unwrap();
    assert!(f.submit(&issued, &response, IDEMPOTENCY, NOW + 2).is_err());
}

#[test]
fn reject_decision_stays_reject_across_restart_and_proof_review() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Reject, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let result = f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    assert_eq!(result.approval["decision"], "reject");
    assert_eq!(result.decision(), ApprovalDecision::Reject);
    f.restart();
    let retained = f
        .store
        .verify_retained_decision(
            &f.tenant,
            result.approval["approval_id"].as_str().unwrap(),
            &f.verifier,
            NOW + 600,
        )
        .unwrap();
    assert_eq!(retained.approval(), &result.approval);
    assert_eq!(retained.approval()["decision"], "reject");
    assert_eq!(retained.decision(), ApprovalDecision::Reject);
}

// Test-only reconstruction of the previous published schema. Product code has
// no downgrade operation; all v1 tables, original bytes and counters are kept.
fn restore_v1_fixture(path: &std::path::Path) {
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch(
        "DROP TRIGGER authority_public_key_registry_no_update;
        DROP TRIGGER authority_public_key_registry_no_delete;
        DROP TABLE authority_public_key_registry;
        DROP TRIGGER authority_schema_migrations_no_update;
        DROP TRIGGER authority_schema_migrations_no_delete;
        DROP TABLE authority_schema_migrations;
        PRAGMA user_version=1;",
    )
    .unwrap();
}

#[test]
fn backed_up_v1_migration_preserves_original_decisions_proofs_and_exact_retries() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let assertion = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let decision = f.submit(&issued, &assertion, IDEMPOTENCY, NOW + 1).unwrap();
    drop(f.store);
    restore_v1_fixture(&f.path);
    let original = snapshot(&f.path);
    assert!(matches!(
        AuthorityStore::open(&f.path),
        Err(fw_authority::AuthorityError::MigrationRequired {
            found: 1,
            required: 2
        })
    ));
    assert_eq!(snapshot(&f.path), original);
    let backup = f.path.with_file_name("before-v2.sqlite3");
    AuthorityStore::migrate_v1(&f.path, &backup).unwrap();
    assert_eq!(snapshot(&backup), original);
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(backup.with_extension("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest["database_hash"],
        fw_contracts::hash_bytes(&std::fs::read(&backup).unwrap())
    );
    for old in &original {
        assert_eq!(
            snapshot(&f.path)
                .into_iter()
                .find(|row| row.0 == old.0)
                .as_ref(),
            Some(old)
        );
    }
    f.store = AuthorityStore::open(&f.path).unwrap();
    let replay = f
        .submit(&issued, &assertion, IDEMPOTENCY, NOW + 600)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.approval, decision.approval);
    f.store
        .verify_retained_decision(
            &f.tenant,
            decision.approval["approval_id"].as_str().unwrap(),
            &f.verifier,
            NOW + 600,
        )
        .unwrap();
    let second = f.path.with_file_name("unnecessary-backup.sqlite3");
    AuthorityStore::migrate_v1(&f.path, &second).unwrap();
    assert!(!second.exists());
}

#[test]
fn duplicate_public_keys_abort_v1_migration_without_changing_original_records() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut f = Fixture::new();
    f.store
        .revoke_credential(&f.tenant, &f.credential.id(), NOW + 1)
        .unwrap();
    drop(f.store);
    restore_v1_fixture(&f.path);
    let mut value = serde_json::to_value(&f.credential).unwrap();
    value["passkey"]["cred"]["cred_id"] = json!(URL_SAFE_NO_PAD.encode([0x42; 32]));
    let renamed: Credential = serde_json::from_value(value).unwrap();
    let fingerprint = renamed.key_fingerprint().unwrap();
    let fingerprint: Vec<u8> = (7..71)
        .step_by(2)
        .map(|i| u8::from_str_radix(&fingerprint[i..i + 2], 16).unwrap())
        .collect();
    let db = rusqlite::Connection::open(&f.path).unwrap();
    db.execute("INSERT INTO authority_credentials(org_id,project_id,credential_id,principal_id,key_fingerprint,credential_bytes,revision,state,not_before,not_after,pinned_at)
        VALUES(?,?,?,?,?,?,1,'pending',?,?,?)",rusqlite::params![ORG,PROJECT,renamed.id(),PRINCIPAL,fingerprint,
        fw_contracts::canonical_bytes(&renamed).unwrap(),NOW,NOW+7200,NOW+1]).unwrap();
    drop(db);
    let original = snapshot(&f.path);
    let backup = f.path.with_file_name("duplicates-before-v2.sqlite3");
    assert!(AuthorityStore::migrate_v1(&f.path, &backup).is_err());
    assert_eq!(snapshot(&f.path), original);
    assert_eq!(snapshot(&backup), original);
    assert_eq!(
        rusqlite::Connection::open(&f.path)
            .unwrap()
            .query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert!(matches!(
        AuthorityStore::open(&f.path),
        Err(fw_authority::AuthorityError::MigrationRequired { .. })
    ));
}

#[test]
fn migration_refuses_unknown_schema_and_never_overwrites_backup_files() {
    let f = Fixture::new();
    drop(f.store);
    restore_v1_fixture(&f.path);
    let backup = f.path.with_file_name("existing-backup.sqlite3");
    std::fs::write(&backup, b"existing-private-backup").unwrap();
    let original = snapshot(&f.path);
    assert!(AuthorityStore::migrate_v1(&f.path, &backup).is_err());
    assert_eq!(std::fs::read(&backup).unwrap(), b"existing-private-backup");
    assert_eq!(snapshot(&f.path), original);
    let db = rusqlite::Connection::open(&f.path).unwrap();
    db.execute_batch("DROP TRIGGER authority_credentials_no_delete;")
        .unwrap();
    drop(db);
    let unexpected = f.path.with_file_name("unexpected-schema.sqlite3");
    assert!(AuthorityStore::migrate_v1(&f.path, &unexpected).is_err());
    assert!(!unexpected.exists());
}

#[test]
fn migrated_database_requires_its_exact_migration_checksum() {
    let f = Fixture::new();
    let db = rusqlite::Connection::open(&f.path).unwrap();
    db.execute_batch(
        "DROP TRIGGER authority_schema_migrations_no_update;
        UPDATE authority_schema_migrations SET checksum=zeroblob(32) WHERE version=2;",
    )
    .unwrap();
    drop(db);
    let before = snapshot(&f.path);
    assert!(AuthorityStore::open(&f.path).is_err());
    assert_eq!(snapshot(&f.path), before);
}

#[test]
fn retained_proof_uses_saved_counter_and_admission_time_but_current_revocations() {
    let mut f = Fixture::new();
    let first = f.issue(ApprovalDecision::Approve, NOW);
    let first_response = f.key.assertion(&first.options, 2, 0x05, ORIGIN);
    let first_result = f
        .submit(&first, &first_response, IDEMPOTENCY, NOW + 1)
        .unwrap();
    let second = f.issue(ApprovalDecision::Approve, NOW + 2);
    let second_response = f.key.assertion(&second.options, 3, 0x05, ORIGIN);
    f.submit(&second, &second_response, IDEMPOTENCY_2, NOW + 3)
        .unwrap();
    f.restart();
    let approval_id = first_result.approval["approval_id"].as_str().unwrap();
    let retained = f
        .store
        .verify_retained_decision(&f.tenant, approval_id, &f.verifier, NOW + 600)
        .unwrap();
    assert_eq!(retained.approval(), &first_result.approval);
    f.store
        .revoke_credential(&f.tenant, &f.credential.id(), NOW + 601)
        .unwrap();
    assert!(
        f.store
            .verify_retained_decision(&f.tenant, approval_id, &f.verifier, NOW + 602)
            .is_err()
    );
}

#[test]
fn retained_decision_is_invalid_after_role_revocation_or_approval_expiry() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let result = f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    let id = result.approval["approval_id"].as_str().unwrap();
    assert!(
        f.store
            .verify_retained_decision(&f.tenant, id, &f.verifier, NOW + 3600)
            .is_err()
    );
    f.store
        .revoke_role(&f.tenant, &f.membership, NOW + 2)
        .unwrap();
    assert!(
        f.store
            .verify_retained_decision(&f.tenant, id, &f.verifier, NOW + 3)
            .is_err()
    );
}

#[test]
fn concurrent_identical_submissions_produce_one_decision_and_one_replay() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = f.path.clone();
            let response = response.clone();
            let challenge_id = issued.challenge.challenge_id().to_owned();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
                let verifier = WebAuthn::new(ORIGIN).unwrap();
                barrier.wait();
                store.admit_decision(
                    &tenant,
                    PRINCIPAL,
                    &challenge_id,
                    IDEMPOTENCY,
                    &response,
                    &verifier,
                    NOW + 1,
                )
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.replayed).count(), 1);
    assert_eq!(results[0].approval, results[1].approval);
}

#[test]
fn concurrent_different_submissions_cannot_both_consume_zero_counter_challenge() {
    let mut f = Fixture::with_counter(0);
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 0, 0x05, ORIGIN);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [IDEMPOTENCY, IDEMPOTENCY_2]
        .into_iter()
        .map(|idempotency| {
            let path = f.path.clone();
            let response = response.clone();
            let challenge_id = issued.challenge.challenge_id().to_owned();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
                let verifier = WebAuthn::new(ORIGIN).unwrap();
                barrier.wait();
                store.admit_decision(
                    &tenant,
                    PRINCIPAL,
                    &challenge_id,
                    idempotency,
                    &response,
                    &verifier,
                    NOW + 1,
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
}

#[test]
fn plan_registration_rejects_conflicts_hash_only_inputs_and_invalid_requirements() {
    let mut f = Fixture::new();
    let req = requirements();
    let original = plan(&req);
    let mut changed = original.clone();
    changed["artifact_hash"] = json!(fw_contracts::hash_bytes(b"substituted artifact"));
    assert!(
        f.store
            .register_plan(&f.tenant, &changed, &req, NOW)
            .is_err()
    );
    let hash_only =
        json!({"plan_id": OTHER, "plan_hash": fw_contracts::canonical_hash(&original).unwrap()});
    assert!(
        f.store
            .register_plan(&f.tenant, &hash_only, &req, NOW)
            .is_err()
    );
    let mut invalid_req = req.clone();
    invalid_req["require_webauthn"] = json!(false);
    let mut new_plan = plan(&invalid_req);
    new_plan["plan_id"] = json!(OTHER);
    assert!(
        f.store
            .register_plan(&f.tenant, &new_plan, &invalid_req, NOW)
            .is_err()
    );
    let mut unrelated_req = req;
    unrelated_req["max_approval_age_seconds"] = json!(7200);
    assert!(
        f.store
            .register_plan(&f.tenant, &new_plan, &unrelated_req, NOW)
            .is_err()
    );
}

#[test]
fn authority_store_refuses_foreign_database_and_unknown_schema_version() {
    let directory = tempfile::tempdir().unwrap();
    let controller_path = directory.path().join("controller.sqlite3");
    let db = rusqlite::Connection::open(&controller_path).unwrap();
    db.execute_batch("CREATE TABLE owners(principal_id TEXT PRIMARY KEY); INSERT INTO owners VALUES ('controller-owner');").unwrap();
    drop(db);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&controller_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(AuthorityStore::open(&controller_path).is_err());
    let db = rusqlite::Connection::open(&controller_path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM owners", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    let future_path = directory.path().join("future.sqlite3");
    drop(AuthorityStore::open(&future_path).unwrap());
    let db = rusqlite::Connection::open(&future_path).unwrap();
    db.execute_batch("PRAGMA user_version=999;").unwrap();
    drop(db);
    assert!(AuthorityStore::open(&future_path).is_err());
}

#[test]
fn concurrent_first_open_creates_one_complete_authority_schema() {
    let directory = tempfile::tempdir().unwrap();
    // Repeat the same initial-open race on fresh databases. Both connections
    // remain alive after their workers return, so one cannot rely on the other
    // connection closing to finish schema creation or select the journal mode.
    for attempt in 0..16 {
        let path = directory
            .path()
            .join(format!("authority-{attempt}.sqlite3"));
        assert!(!path.exists());
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    AuthorityStore::open(path)
                })
            })
            .collect();
        let mut stores: Vec<_> = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap()
                    .unwrap_or_else(|error| panic!("first-open race {attempt}: {error:?}"))
            })
            .collect();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        stores[0]
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://identity.example.test",
                "reviewer-alice",
                NOW,
            )
            .unwrap();
        stores[1]
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://identity.example.test",
                "reviewer-alice",
                NOW,
            )
            .unwrap();
        let db = rusqlite::Connection::open(path).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT schema_identity FROM authority_metadata WHERE singleton=1",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "fw.authority-store/v1"
        );
        assert_eq!(
            db.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM authority_principals", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            1
        );
    }
}

#[test]
fn authority_cannot_use_plan_or_principal_before_its_local_admission_time() {
    let mut f = Fixture::new();
    let req = requirements();
    let mut later_plan = plan(&req);
    later_plan["plan_id"] = json!(OTHER);
    // The plan's signed content predates its independent authority admission.
    // A backwards clock must not make it available before that local admission.
    f.store
        .register_plan(&f.tenant, &later_plan, &req, NOW + 100)
        .unwrap();
    assert!(matches!(
        f.store.issue_challenge(
            &f.tenant,
            PRINCIPAL,
            &f.credential.id(),
            OTHER,
            ApprovalRole::Owner,
            ApprovalDecision::Approve,
            &f.verifier,
            NOW + 50,
        ),
        Err(fw_authority::AuthorityError::Time)
    ));
    f.store
        .provision_principal(
            &f.tenant,
            OTHER,
            "https://identity.example.test",
            "later-reviewer",
            NOW + 100,
        )
        .unwrap();
    assert!(matches!(
        f.store.grant_role(
            &f.tenant,
            OTHER,
            ApprovalRole::Owner,
            NOW,
            NOW + 7200,
            NOW + 50,
        ),
        Err(fw_authority::AuthorityError::Time)
    ));
}

fn snapshot(path: &std::path::Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let db = rusqlite::Connection::open(path).unwrap();
    let tables: Vec<String> = db.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE 'authority_%' ORDER BY name",
    ).unwrap().query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
    tables
        .into_iter()
        .map(|table| {
            // Names come from our fixed schema, never external input.
            assert!(table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
            let mut statement = db
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|index| row.get(index))
                        .collect::<Result<Vec<rusqlite::types::Value>, _>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

#[test]
fn storage_failure_at_each_decision_write_rolls_back_counter_consumption_evidence_and_audit() {
    for (table, action) in [
        ("authority_credentials", "UPDATE"),
        ("authority_challenges", "UPDATE"),
        ("authority_evidence", "INSERT"),
        ("authority_decisions", "INSERT"),
        ("authority_audit", "INSERT"),
        ("authority_audit_heads", "UPDATE"),
    ] {
        let mut f = Fixture::new();
        let issued = f.issue(ApprovalDecision::Approve, NOW);
        let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
        let before = snapshot(&f.path);
        let db = rusqlite::Connection::open(&f.path).unwrap();
        db.execute_batch(&format!(
            "CREATE TRIGGER test_storage_failure BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END;"
        )).unwrap();
        assert!(
            f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).is_err(),
            "{table}"
        );
        assert_eq!(
            snapshot(&f.path),
            before,
            "partial commit after failed {action} on {table}"
        );
        db.execute_batch("DROP TRIGGER test_storage_failure;")
            .unwrap();
        f.restart();
        assert!(
            !f.submit(&issued, &response, IDEMPOTENCY, NOW + 2)
                .unwrap()
                .replayed
        );
    }
}

#[test]
fn exact_retry_does_not_advance_counter_audit_or_expiry() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    let before = snapshot(&f.path);
    assert!(
        f.submit(&issued, &response, IDEMPOTENCY, NOW + 1000)
            .unwrap()
            .replayed
    );
    assert_eq!(snapshot(&f.path), before);
}

#[test]
fn repeated_invalid_proofs_remain_unconsumed_and_fail_closed_after_restart() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let valid = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let mut invalid = valid.clone();
    invalid.response.signature = "AA".into();
    for _ in 0..10 {
        assert!(f.submit(&issued, &invalid, IDEMPOTENCY, NOW + 1).is_err());
    }
    f.restart();
    assert!(f.submit(&issued, &valid, IDEMPOTENCY, NOW + 2).is_err());
    let db = rusqlite::Connection::open(&f.path).unwrap();
    let (attempts, consumed): (i64, Option<i64>) = db
        .query_row(
            "SELECT attempts,consumed_at FROM authority_challenges WHERE challenge_id=?1",
            [issued.challenge.challenge_id()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(attempts, 10);
    assert_eq!(consumed, None);
    assert_eq!(
        db.query_row("SELECT count(*) FROM authority_decisions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let before = snapshot(&f.path);
    for _ in 0..20 {
        assert!(f.submit(&issued, &invalid, IDEMPOTENCY, NOW + 3).is_err());
    }
    assert_eq!(
        snapshot(&f.path),
        before,
        "locked challenge allows unbounded durable failure noise"
    );
}

#[test]
fn evidence_preserves_original_signed_client_bytes_and_pre_update_credential() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let mut response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let original_client_data = format!(
        "{{\n \"origin\": {origin}, \"challenge\": {challenge}, \"type\": \"webauthn.get\", \"crossOrigin\": false\n}}",
        origin = json!(ORIGIN),
        challenge = issued.options["publicKey"]["challenge"],
    );
    response.response.client_data_json = URL_SAFE_NO_PAD.encode(original_client_data.as_bytes());
    f.key.resign(&mut response);
    let result = f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    let db = rusqlite::Connection::open(&f.path).unwrap();
    let (assertion, before, after): (Vec<u8>, Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT assertion_bytes,pre_credential_bytes,post_credential_bytes FROM authority_evidence",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    let saved: AuthenticationResponse = serde_json::from_slice(&assertion).unwrap();
    assert_eq!(
        serde_json::to_value(saved).unwrap(),
        serde_json::to_value(&response).unwrap()
    );
    assert_ne!(before, after);
    assert!(
        f.store
            .verify_retained_decision(
                &f.tenant,
                result.approval["approval_id"].as_str().unwrap(),
                &f.verifier,
                NOW + 600,
            )
            .is_ok()
    );
}

#[test]
fn stale_issued_credential_snapshot_cannot_replace_a_newer_successful_counter() {
    let mut f = Fixture::new();
    let first = f.issue(ApprovalDecision::Approve, NOW);
    let second = f.issue(ApprovalDecision::Approve, NOW);
    let first_response = f.key.assertion(&first.options, 2, 0x05, ORIGIN);
    let second_response = f.key.assertion(&second.options, 3, 0x05, ORIGIN);
    f.submit(&first, &first_response, IDEMPOTENCY, NOW + 1)
        .unwrap();
    assert!(
        f.submit(&second, &second_response, IDEMPOTENCY_2, NOW + 2)
            .is_err()
    );
    let fresh = f.issue(ApprovalDecision::Approve, NOW + 2);
    let fresh_response = f.key.assertion(&fresh.options, 3, 0x05, ORIGIN);
    assert!(
        f.submit(&fresh, &fresh_response, IDEMPOTENCY_2, NOW + 3)
            .is_ok()
    );
}

#[test]
fn registration_is_pending_until_the_independent_store_verifies_possession() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = AuthorityStore::open(directory.path().join("authority.sqlite3")).unwrap();
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new(PRINCIPAL);
    let registration = verifier
        .begin_registration(PRINCIPAL, "Pending authority key", &[])
        .unwrap();
    let credential = verifier
        .finish_registration(
            &registration.state,
            &key.registration(&registration.options),
        )
        .unwrap();
    store
        .provision_principal(
            &tenant,
            PRINCIPAL,
            "https://identity.example.test",
            "reviewer-alice",
            NOW,
        )
        .unwrap();
    store
        .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
        .unwrap();
    store
        .grant_role(
            &tenant,
            PRINCIPAL,
            ApprovalRole::Owner,
            NOW,
            NOW + 7200,
            NOW,
        )
        .unwrap();
    let req = requirements();
    store
        .register_plan(&tenant, &plan(&req), &req, NOW)
        .unwrap();
    assert!(
        store
            .issue_challenge(
                &tenant,
                PRINCIPAL,
                &credential.id(),
                PLAN,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &verifier,
                NOW
            )
            .is_err()
    );
    let activation = store
        .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
        .unwrap();
    let response = key.assertion(&activation.options, 1, 0x05, ORIGIN);
    store
        .finish_credential_activation(
            &tenant,
            &activation.activation_id,
            &response,
            &verifier,
            NOW + 1,
        )
        .unwrap();
    assert!(
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &response,
                &verifier,
                NOW + 2
            )
            .is_err()
    );
    assert!(
        store
            .issue_challenge(
                &tenant,
                PRINCIPAL,
                &credential.id(),
                PLAN,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &verifier,
                NOW + 2
            )
            .is_ok()
    );
}

#[test]
fn activation_audit_failure_rolls_back_possession_and_counter_transition() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let mut store = AuthorityStore::open(&path).unwrap();
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new(PRINCIPAL);
    let registration = verifier
        .begin_registration(PRINCIPAL, "Authority key", &[])
        .unwrap();
    let credential = verifier
        .finish_registration(
            &registration.state,
            &key.registration(&registration.options),
        )
        .unwrap();
    store
        .provision_principal(
            &tenant,
            PRINCIPAL,
            "https://identity.example.test",
            "reviewer-alice",
            NOW,
        )
        .unwrap();
    store
        .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
        .unwrap();
    let activation = store
        .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
        .unwrap();
    let response = key.assertion(&activation.options, 1, 0x05, ORIGIN);
    let before = snapshot(&path);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER test_activation_audit_failure BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(ABORT, 'injected activation audit failure'); END;").unwrap();
    assert!(
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &response,
                &verifier,
                NOW + 1
            )
            .is_err()
    );
    assert_eq!(snapshot(&path), before);
    db.execute_batch("DROP TRIGGER test_activation_audit_failure;")
        .unwrap();
    store = AuthorityStore::open(&path).unwrap();
    store
        .finish_credential_activation(
            &tenant,
            &activation.activation_id,
            &response,
            &verifier,
            NOW + 2,
        )
        .unwrap();
    assert!(
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &response,
                &verifier,
                NOW + 3
            )
            .is_err()
    );
}

#[test]
fn failed_activation_proof_and_expiry_are_durable_without_activating_the_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let mut store = AuthorityStore::open(&path).unwrap();
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new(PRINCIPAL);
    let registration = verifier
        .begin_registration(PRINCIPAL, "Pending authority key", &[])
        .unwrap();
    let credential = verifier
        .finish_registration(
            &registration.state,
            &key.registration(&registration.options),
        )
        .unwrap();
    store
        .provision_principal(
            &tenant,
            PRINCIPAL,
            "https://identity.example.test",
            "reviewer-alice",
            NOW,
        )
        .unwrap();
    store
        .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
        .unwrap();
    let activation = store
        .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
        .unwrap();
    let response = key.assertion(&activation.options, 1, 0x05, ORIGIN);
    let mut invalid = response.clone();
    invalid.response.signature = "AA".into();
    assert!(
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &invalid,
                &verifier,
                NOW + 1
            )
            .is_err()
    );
    store = AuthorityStore::open(&path).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let (attempts, consumed): (i64, Option<i64>) = db
        .query_row(
            "SELECT attempts,consumed_at FROM authority_activations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(attempts, 1);
    assert_eq!(consumed, None);
    assert!(
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &response,
                &verifier,
                NOW + 300
            )
            .is_err()
    );
    assert_eq!(
        db.query_row("SELECT state FROM authority_credentials", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "pending"
    );
    let fresh = store
        .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW + 301)
        .unwrap();
    let fresh_response = key.assertion(&fresh.options, 1, 0x05, ORIGIN);
    store
        .finish_credential_activation(
            &tenant,
            &fresh.activation_id,
            &fresh_response,
            &verifier,
            NOW + 302,
        )
        .unwrap();
}

#[test]
fn concurrent_credential_revocation_and_admission_never_leave_current_authority() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let barrier = Arc::new(Barrier::new(2));
    let admission_path = f.path.clone();
    let admission_barrier = barrier.clone();
    let challenge_id = issued.challenge.challenge_id().to_owned();
    let admission = thread::spawn(move || {
        let mut store = AuthorityStore::open(admission_path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        admission_barrier.wait();
        store.admit_decision(
            &tenant,
            PRINCIPAL,
            &challenge_id,
            IDEMPOTENCY,
            &response,
            &verifier,
            NOW + 1,
        )
    });
    let revoke_path = f.path.clone();
    let credential_id = f.credential.id();
    let revocation = thread::spawn(move || {
        let mut store = AuthorityStore::open(revoke_path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        barrier.wait();
        store.revoke_credential(&tenant, &credential_id, NOW + 1)
    });
    let admission = admission.join().unwrap();
    revocation.join().unwrap().unwrap();
    if let Ok(recorded) = admission {
        assert!(!recorded.replayed);
        assert!(
            f.store
                .verify_retained_decision(
                    &f.tenant,
                    recorded.approval["approval_id"].as_str().unwrap(),
                    &f.verifier,
                    NOW + 2,
                )
                .is_err()
        );
    }
    assert!(
        f.store
            .issue_challenge(
                &f.tenant,
                PRINCIPAL,
                &f.credential.id(),
                PLAN,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW + 2
            )
            .is_err()
    );
}

#[test]
fn substituted_current_public_key_invalidates_retained_decision() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let recorded = f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    let other = Authenticator::new(PRINCIPAL);
    let registration = f
        .verifier
        .begin_registration(PRINCIPAL, "Substituted key", &[])
        .unwrap();
    let other_credential = f
        .verifier
        .finish_registration(
            &registration.state,
            &other.registration(&registration.options),
        )
        .unwrap();
    let db = rusqlite::Connection::open(&f.path).unwrap();
    let original: Vec<u8> = db
        .query_row(
            "SELECT credential_bytes FROM authority_credentials",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut substituted: Value = serde_json::from_slice(&original).unwrap();
    substituted["passkey"]["cred"]["cred"] =
        serde_json::to_value(other_credential).unwrap()["passkey"]["cred"]["cred"].clone();
    // Simulate a corrupted mutable credential record while the separately pinned
    // fingerprint stays unchanged. A same credential ID is not the same key.
    db.execute(
        "UPDATE authority_credentials SET credential_bytes=?1,revision=revision+1",
        [fw_contracts::canonical_bytes(&substituted).unwrap()],
    )
    .unwrap();
    assert!(
        f.store
            .verify_retained_decision(
                &f.tenant,
                recorded.approval["approval_id"].as_str().unwrap(),
                &f.verifier,
                NOW + 2,
            )
            .is_err()
    );
}

#[test]
fn immutable_records_reject_sql_updates_and_corrupted_proof_is_detected_on_read() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let response = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let recorded = f.submit(&issued, &response, IDEMPOTENCY, NOW + 1).unwrap();
    let db = rusqlite::Connection::open(&f.path).unwrap();
    for table in [
        "authority_plans",
        "authority_requirements",
        "authority_evidence",
        "authority_decisions",
        "authority_audit",
    ] {
        assert!(
            db.execute(&format!("UPDATE {table} SET canonical_bytes=x'7b7d'"), [])
                .is_err(),
            "mutable {table}"
        );
        assert!(
            db.execute(&format!("DELETE FROM {table}"), []).is_err(),
            "deletable {table}"
        );
    }
    // This deliberately bypasses the SQL immutability guard to model damaged
    // stored bytes. It does not claim resistance against a database administrator
    // who can rewrite the entire independent authority trust root.
    db.execute_batch("DROP TRIGGER authority_evidence_no_update;")
        .unwrap();
    let encoded: Vec<u8> = db
        .query_row(
            "SELECT assertion_bytes FROM authority_evidence",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut altered: Value = serde_json::from_slice(&encoded).unwrap();
    altered["response"]["signature"] = json!("AA");
    db.execute(
        "UPDATE authority_evidence SET assertion_bytes=?1",
        [fw_contracts::canonical_bytes(&altered).unwrap()],
    )
    .unwrap();
    assert!(
        f.store
            .verify_retained_decision(
                &f.tenant,
                recorded.approval["approval_id"].as_str().unwrap(),
                &f.verifier,
                NOW + 2,
            )
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn authority_path_rejects_symlinks_hardlinks_and_shared_writable_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("authority.sqlite3");
    drop(AuthorityStore::open(&real).unwrap());
    let symbolic = directory.path().join("symbolic.sqlite3");
    symlink(&real, &symbolic).unwrap();
    assert!(AuthorityStore::open(&symbolic).is_err());
    let hard = directory.path().join("hard.sqlite3");
    std::fs::hard_link(&real, &hard).unwrap();
    assert!(AuthorityStore::open(&hard).is_err());
    assert!(AuthorityStore::open(&real).is_err());
    std::fs::remove_file(hard).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(AuthorityStore::open(&real).is_err());
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(AuthorityStore::open(&real).is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(AuthorityStore::open(&real).is_ok());
}

fn pending_key(
    path: &std::path::Path,
) -> (
    AuthorityStore,
    AuthorityTenant,
    WebAuthn,
    Authenticator,
    Credential,
) {
    let mut store = AuthorityStore::open(path).unwrap();
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new(PRINCIPAL);
    let registration = verifier
        .begin_registration(PRINCIPAL, "Pending authority key", &[])
        .unwrap();
    let credential = verifier
        .finish_registration(
            &registration.state,
            &key.registration(&registration.options),
        )
        .unwrap();
    store
        .provision_principal(
            &tenant,
            PRINCIPAL,
            "https://identity.example.test",
            "reviewer-alice",
            NOW,
        )
        .unwrap();
    store
        .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
        .unwrap();
    (store, tenant, verifier, key, credential)
}

#[test]
fn challenge_sql_guards_preserve_issued_state_attempt_budget_and_single_consumption() {
    let mut f = Fixture::new();
    let issued = f.issue(ApprovalDecision::Approve, NOW);
    let valid = f.key.assertion(&issued.options, 2, 0x05, ORIGIN);
    let mut invalid = valid.clone();
    invalid.response.signature = "AA".into();
    assert!(f.submit(&issued, &invalid, IDEMPOTENCY, NOW + 1).is_err());
    let db = rusqlite::Connection::open(&f.path).unwrap();
    let before = snapshot(&f.path);
    for assignment in [
        "attempts=0",
        "attempts=attempts",
        "attempts=NULL",
        "attempts=attempts+2",
        "state_bytes=x'7b7d',attempts=attempts+1",
        "payload_bytes=x'7b7d',attempts=attempts+1",
        "credential_bytes=x'7b7d',attempts=attempts+1",
        "credential_revision=credential_revision+1,attempts=attempts+1",
        "expires_at=expires_at+300,attempts=attempts+1",
        "consumed_at=issued_at-1",
        "consumed_at=expires_at",
        "attempts=attempts+1,consumed_at=issued_at+1",
    ] {
        assert!(
            db.execute(
                &format!("UPDATE authority_challenges SET {assignment} WHERE challenge_id=?1"),
                [issued.challenge.challenge_id()]
            )
            .is_err(),
            "accepted challenge mutation: {assignment}"
        );
    }
    assert_eq!(snapshot(&f.path), before);
    f.submit(&issued, &valid, IDEMPOTENCY, NOW + 2).unwrap();
    let consumed = snapshot(&f.path);
    for assignment in [
        "consumed_at=consumed_at",
        "consumed_at=NULL",
        "consumed_at=consumed_at+1",
        "attempts=attempts+1",
    ] {
        assert!(
            db.execute(
                &format!("UPDATE authority_challenges SET {assignment} WHERE challenge_id=?1"),
                [issued.challenge.challenge_id()]
            )
            .is_err()
        );
    }
    assert_eq!(snapshot(&f.path), consumed);
}

#[test]
fn activation_sql_guards_preserve_pending_state_attempt_budget_and_single_consumption() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let (mut store, tenant, verifier, key, credential) = pending_key(&path);
    let activation = store
        .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
        .unwrap();
    let valid = key.assertion(&activation.options, 1, 0x05, ORIGIN);
    let mut invalid = valid.clone();
    invalid.response.signature = "AA".into();
    assert!(
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &invalid,
                &verifier,
                NOW + 1
            )
            .is_err()
    );
    let db = rusqlite::Connection::open(&path).unwrap();
    let before = snapshot(&path);
    for assignment in [
        "attempts=0",
        "attempts=attempts",
        "attempts=NULL",
        "attempts=attempts+2",
        "state_bytes=x'7b7d',attempts=attempts+1",
        "credential_revision=credential_revision+1,attempts=attempts+1",
        "expires_at=expires_at+300,attempts=attempts+1",
        "consumed_at=issued_at-1",
        "consumed_at=expires_at",
        "attempts=attempts+1,consumed_at=issued_at+1",
    ] {
        assert!(
            db.execute(
                &format!("UPDATE authority_activations SET {assignment} WHERE activation_id=?1"),
                [&activation.activation_id]
            )
            .is_err(),
            "accepted activation mutation: {assignment}"
        );
    }
    assert_eq!(snapshot(&path), before);
    store
        .finish_credential_activation(
            &tenant,
            &activation.activation_id,
            &valid,
            &verifier,
            NOW + 2,
        )
        .unwrap();
    let consumed = snapshot(&path);
    for assignment in [
        "consumed_at=consumed_at",
        "consumed_at=NULL",
        "consumed_at=consumed_at+1",
        "attempts=attempts+1",
    ] {
        assert!(
            db.execute(
                &format!("UPDATE authority_activations SET {assignment} WHERE activation_id=?1"),
                [&activation.activation_id]
            )
            .is_err()
        );
    }
    assert_eq!(snapshot(&path), consumed);
}

#[test]
fn outstanding_ceremony_limits_count_locked_records_until_their_original_expiry() {
    let mut f = Fixture::new();
    let locked = f.issue(ApprovalDecision::Approve, NOW);
    let mut invalid = f.key.assertion(&locked.options, 2, 0x05, ORIGIN);
    invalid.response.signature = "AA".into();
    for _ in 0..10 {
        assert!(f.submit(&locked, &invalid, IDEMPOTENCY, NOW + 1).is_err());
    }
    for _ in 1..16 {
        f.issue(ApprovalDecision::Approve, NOW);
    }
    f.restart();
    assert!(matches!(
        f.store.issue_challenge(
            &f.tenant,
            PRINCIPAL,
            &f.credential.id(),
            PLAN,
            ApprovalRole::Owner,
            ApprovalDecision::Approve,
            &f.verifier,
            NOW + 299
        ),
        Err(fw_authority::AuthorityError::Quota)
    ));
    assert!(
        f.store
            .issue_challenge(
                &f.tenant,
                PRINCIPAL,
                &f.credential.id(),
                PLAN,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW + 300
            )
            .is_ok()
    );

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authority.sqlite3");
    let (mut store, tenant, verifier, key, credential) = pending_key(&path);
    let locked = store
        .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
        .unwrap();
    let valid = key.assertion(&locked.options, 1, 0x05, ORIGIN);
    let mut invalid = valid.clone();
    invalid.response.signature = "AA".into();
    for _ in 0..10 {
        assert!(
            store
                .finish_credential_activation(
                    &tenant,
                    &locked.activation_id,
                    &invalid,
                    &verifier,
                    NOW + 1
                )
                .is_err()
        );
    }
    assert!(
        store
            .finish_credential_activation(
                &tenant,
                &locked.activation_id,
                &valid,
                &verifier,
                NOW + 2
            )
            .is_err()
    );
    for _ in 1..16 {
        store
            .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
            .unwrap();
    }
    store = AuthorityStore::open(&path).unwrap();
    assert!(matches!(
        store.begin_credential_activation(&tenant, &credential.id(), &verifier, NOW + 299),
        Err(fw_authority::AuthorityError::Quota)
    ));
    assert!(
        store
            .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW + 300)
            .is_ok()
    );
}
