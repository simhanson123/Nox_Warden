#![cfg(feature = "approval-proofs")]
//! Synthetic semantic evidence tests; no native gates, signer or dispatch authority.
#[path = "support/approval_authenticator.rs"]
mod authenticator;
#[path = "support/authority_legacy.rs"]
#[allow(dead_code)]
mod authority_legacy;
#[path = "../../fw_authority_service/tests/support/plans.rs"]
mod plans;
#[path = "support/private_directory.rs"]
mod private_directory;
use authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_authority::{
    ApprovalDecision, ApprovalRole, AuthorityError, AuthorityStore, AuthorityTenant,
};
use fw_planner::PolicyReviewEvidence;
use fw_webauthn::{Credential, WebAuthn};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
const NOW: i64 = 1_700_000_000;
const IDEMPOTENCY: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    plan: Value,
    requirements: Value,
    evidence: PolicyReviewEvidence,
    verifier: WebAuthn,
    key: Authenticator,
    credential: Credential,
}
impl Fixture {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let tenant = AuthorityTenant::new(plans::ORG, plans::PROJECT).unwrap();
        store
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://identity.example.test",
                "alice",
                NOW,
            )
            .unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "alice", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
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
        let activation = store
            .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
            .unwrap();
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &key.assertion(&activation.options, 1, 0x05, ORIGIN),
                &verifier,
                NOW,
            )
            .unwrap();
        let (plan, requirements, evidence) = plans::complete_plan(NOW);
        Self {
            _directory: directory,
            path,
            store,
            tenant,
            plan,
            requirements,
            evidence,
            verifier,
            key,
            credential,
        }
    }
    fn register(&mut self, now: i64) {
        self.store
            .register_reviewed_plan(
                &self.tenant,
                &self.plan,
                &self.requirements,
                &self.evidence,
                now,
            )
            .unwrap();
    }
}
fn snapshot(path: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let db = Connection::open(path).unwrap();
    let mut statement=db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    let tables = statement
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut statement = db
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

#[test]
fn exact_review_survives_reopen_retry_and_retains_no_dispatch_authority() {
    let mut f = Fixture::new();
    f.register(NOW + 1);
    let before = snapshot(&f.path);
    f.store = AuthorityStore::open(&f.path).unwrap();
    f.register(NOW + 2);
    assert_eq!(snapshot(&f.path), before);
    let review = f
        .store
        .policy_review_evidence(&f.tenant, plans::PLAN, NOW + 2)
        .unwrap()
        .unwrap();
    assert_eq!(
        review.plan_hash(),
        fw_contracts::canonical_hash(&f.plan).unwrap()
    );
    assert_eq!(
        review.canonical_bytes(),
        fw_contracts::canonical_bytes(&f.evidence).unwrap()
    );
    assert_eq!(
        review.evidence_hash(),
        fw_contracts::hash_bytes(review.canonical_bytes())
    );
    let db = Connection::open(&f.path).unwrap();
    for table in [
        "authority_signing_intents",
        "authority_signing_jobs",
        "authority_signing_results",
        "authority_signing_outbox",
        "authority_signing_quota_reservations",
    ] {
        assert_eq!(
            db.query_row::<i64, _, _>(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get(0))
                .unwrap(),
            0,
            "semantic review created signing state in {table}"
        );
    }
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT count(*) FROM authority_audit WHERE kind='plan_review_evidence_registered'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    assert!(
        db.execute("DELETE FROM authority_plan_review_evidence", [])
            .is_err()
    );
    assert!(
        db.execute(
            "UPDATE authority_plan_review_evidence SET admitted_at=admitted_at+1",
            []
        )
        .is_err()
    );
}

#[test]
fn missing_review_blocks_checked_approve_in_both_transactions_but_allows_reject() {
    let mut f = Fixture::new();
    f.store
        .register_plan(&f.tenant, &f.plan, &f.requirements, NOW)
        .unwrap();
    assert!(
        f.store
            .policy_review_evidence(&f.tenant, plans::PLAN, NOW)
            .unwrap()
            .is_none()
    );
    let before = snapshot(&f.path);
    assert!(
        f.store
            .issue_reviewed_challenge(
                &f.tenant,
                PRINCIPAL,
                &f.credential.id(),
                plans::PLAN,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.path), before);
    // The trusted low-level API remains explicitly separate from reviewed service admission.
    let unchecked = f
        .store
        .issue_challenge(
            &f.tenant,
            PRINCIPAL,
            &f.credential.id(),
            plans::PLAN,
            ApprovalRole::Owner,
            ApprovalDecision::Approve,
            &f.verifier,
            NOW,
        )
        .unwrap();
    let assertion = f.key.assertion(&unchecked.options, 2, 0x05, ORIGIN);
    let before = snapshot(&f.path);
    assert!(
        f.store
            .admit_reviewed_decision(
                &f.tenant,
                PRINCIPAL,
                unchecked.challenge.challenge_id(),
                IDEMPOTENCY,
                &assertion,
                &f.verifier,
                NOW + 1
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.path), before);
    let rejected = f
        .store
        .issue_reviewed_challenge(
            &f.tenant,
            PRINCIPAL,
            &f.credential.id(),
            plans::PLAN,
            ApprovalRole::Owner,
            ApprovalDecision::Reject,
            &f.verifier,
            NOW + 1,
        )
        .unwrap();
    let assertion = f.key.assertion(&rejected.options, 2, 0x05, ORIGIN);
    let decision = f
        .store
        .admit_reviewed_decision(
            &f.tenant,
            PRINCIPAL,
            rejected.challenge.challenge_id(),
            IDEMPOTENCY,
            &assertion,
            &f.verifier,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(decision.decision(), ApprovalDecision::Reject);
}

#[test]
fn approved_admission_rechecks_durable_review_and_retains_exact_proof() {
    let mut f = Fixture::new();
    f.register(NOW);
    let challenge = f
        .store
        .issue_reviewed_challenge(
            &f.tenant,
            PRINCIPAL,
            &f.credential.id(),
            plans::PLAN,
            ApprovalRole::Owner,
            ApprovalDecision::Approve,
            &f.verifier,
            NOW + 1,
        )
        .unwrap();
    let assertion = f.key.assertion(&challenge.options, 2, 0x05, ORIGIN);
    let decision = f
        .store
        .admit_reviewed_decision(
            &f.tenant,
            PRINCIPAL,
            challenge.challenge.challenge_id(),
            IDEMPOTENCY,
            &assertion,
            &f.verifier,
            NOW + 1,
        )
        .unwrap();
    f.store = AuthorityStore::open(&f.path).unwrap();
    let original = snapshot(&f.path);
    let retry = f
        .store
        .admit_reviewed_decision(
            &f.tenant,
            PRINCIPAL,
            challenge.challenge.challenge_id(),
            IDEMPOTENCY,
            &assertion,
            &f.verifier,
            NOW + 2,
        )
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.approval, decision.approval);
    assert_eq!(snapshot(&f.path), original);
    f.store
        .verify_retained_decision(
            &f.tenant,
            decision.approval["approval_id"].as_str().unwrap(),
            &f.verifier,
            NOW + 2,
        )
        .unwrap();
}

#[test]
fn invalid_recomposition_tenant_hash_size_and_immutable_collision_leave_no_rows() {
    for case in 0..8 {
        let mut f = Fixture::new();
        match case {
            0 => {
                f.evidence.after.management_baseline_hash =
                    fw_contracts::hash_bytes(b"changed management")
            }
            1 => f.evidence.before.target_id = PRINCIPAL.into(),
            2 => f.plan["candidate_state_ref"]["size_bytes"] = json!(1),
            3 => {
                f.plan["effect_summary"]["removed_region_hash"] =
                    json!(fw_contracts::hash_bytes(b"changed effects"))
            }
            4 => f.plan["org_id"] = json!(plans::PROJECT),
            5 => {
                f.plan["source_snapshot_hash"] = json!(fw_contracts::hash_bytes(b"other registry"))
            }
            6 => f.plan["operations"][0]["expected_revision"] = json!(99),
            _ => f.plan["change_kind"] = json!("add_access_lease"),
        }
        let before = snapshot(&f.path);
        assert!(
            f.store
                .register_reviewed_plan(&f.tenant, &f.plan, &f.requirements, &f.evidence, NOW)
                .is_err(),
            "case {case}"
        );
        assert_eq!(snapshot(&f.path), before, "case {case}");
    }
    let mut f = Fixture::new();
    f.register(NOW);
    let original = snapshot(&f.path);
    f.plan["compiler_hash"] = json!(fw_contracts::hash_bytes(b"different immutable reference"));
    assert!(matches!(
        f.store
            .register_reviewed_plan(&f.tenant, &f.plan, &f.requirements, &f.evidence, NOW + 1),
        Err(AuthorityError::Conflict)
    ));
    assert_eq!(snapshot(&f.path), original);
    let mut oversized = f.plan.clone();
    oversized["extra"] = json!("x".repeat(128 * 1024));
    assert!(f.evidence.verify(&oversized).is_err());
    let mut nested = Value::Null;
    for _ in 0..40 {
        nested = json!([nested]);
    }
    let mut deep = f.plan.clone();
    deep["extra"] = nested;
    assert!(f.evidence.verify(&deep).is_err());
}

#[test]
fn evidence_or_final_audit_failure_rolls_back_plan_requirements_review_and_security() {
    for failure in ["evidence", "audit"] {
        let mut f = Fixture::new();
        let db = Connection::open(&f.path).unwrap();
        if failure == "evidence" {
            db.execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON authority_plan_review_evidence BEGIN SELECT RAISE(ABORT,'injected review failure'); END;").unwrap();
        } else {
            db.execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON authority_audit WHEN NEW.kind='plan_review_evidence_registered' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
        }
        let original = snapshot(&f.path);
        assert!(
            f.store
                .register_reviewed_plan(&f.tenant, &f.plan, &f.requirements, &f.evidence, NOW)
                .is_err()
        );
        assert_eq!(snapshot(&f.path), original);
        db.execute_batch("DROP TRIGGER injected_failure;").unwrap();
        f.register(NOW);
    }
}

#[test]
fn tampered_evidence_is_rejected_on_read_retry_and_proof_admission() {
    for column in [
        "plan_hash=zeroblob(32)",
        "evidence_hash=zeroblob(32)",
        "canonical_bytes=x'7b7d'",
        "admitted_at=1700000005",
    ] {
        let mut f = Fixture::new();
        // Admission later than creation makes backdating to a post-creation time detectable.
        f.register(NOW + 10);
        let challenge = f
            .store
            .issue_reviewed_challenge(
                &f.tenant,
                PRINCIPAL,
                &f.credential.id(),
                plans::PLAN,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW + 10,
            )
            .unwrap();
        let assertion = f.key.assertion(&challenge.options, 2, 0x05, ORIGIN);
        let db = Connection::open(&f.path).unwrap();
        db.execute_batch(&format!("DROP TRIGGER authority_plan_review_evidence_no_update; UPDATE authority_plan_review_evidence SET {column};")).unwrap();
        let original = snapshot(&f.path);
        assert!(
            f.store
                .policy_review_evidence(&f.tenant, plans::PLAN, NOW + 11)
                .is_err(),
            "{column}"
        );
        assert!(
            f.store
                .register_reviewed_plan(&f.tenant, &f.plan, &f.requirements, &f.evidence, NOW + 11)
                .is_err()
        );
        assert!(
            f.store
                .admit_reviewed_decision(
                    &f.tenant,
                    PRINCIPAL,
                    challenge.challenge.challenge_id(),
                    IDEMPOTENCY,
                    &assertion,
                    &f.verifier,
                    NOW + 11
                )
                .is_err()
        );
        assert_eq!(snapshot(&f.path), original);
    }
}

#[test]
fn v3_migration_requires_validated_backup_and_does_not_invent_legacy_evidence() {
    let mut f = Fixture::new();
    f.store
        .register_plan(&f.tenant, &f.plan, &f.requirements, NOW)
        .unwrap();
    drop(f.store);
    authority_legacy::restore_v3(&f.path);
    let original = snapshot(&f.path);
    assert!(matches!(
        AuthorityStore::open(&f.path),
        Err(AuthorityError::MigrationRequired {
            found: 3,
            required: 7
        })
    ));
    assert_eq!(snapshot(&f.path), original);
    let backup = f.path.with_file_name("before-v4.sqlite3");
    AuthorityStore::migrate(&f.path, &backup).unwrap();
    assert_eq!(snapshot(&backup), original);
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(backup.with_extension("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["database_schema"], 3);
    assert_eq!(
        manifest["database_hash"],
        fw_contracts::hash_bytes(&std::fs::read(&backup).unwrap())
    );
    f.store = AuthorityStore::open(&f.path).unwrap();
    assert!(
        f.store
            .policy_review_evidence(&f.tenant, plans::PLAN, NOW + 1)
            .unwrap()
            .is_none()
    );
    assert!(
        f.store
            .issue_reviewed_challenge(
                &f.tenant,
                PRINCIPAL,
                &f.credential.id(),
                plans::PLAN,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW + 1
            )
            .is_err()
    );
    f.register(NOW + 1);
}

#[test]
fn separate_connections_import_once_without_replacing_review_or_duplicate_audit() {
    let f = Fixture::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let tasks = (0..2)
        .map(|_| {
            let (path, plan, requirements, evidence, tenant, barrier) = (
                f.path.clone(),
                f.plan.clone(),
                f.requirements.clone(),
                f.evidence.clone(),
                f.tenant.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                barrier.wait();
                store
                    .register_reviewed_plan(&tenant, &plan, &requirements, &evidence, NOW)
                    .unwrap();
            })
        })
        .collect::<Vec<_>>();
    for task in tasks {
        task.join().unwrap();
    }
    let db = Connection::open(&f.path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT count(*) FROM authority_plan_review_evidence",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT count(*) FROM authority_audit WHERE kind='plan_review_evidence_registered'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn v3_foreign_key_failure_preserves_backup_and_rolls_back_new_review_schema() {
    let f = Fixture::new();
    drop(f.store);
    authority_legacy::restore_v3(&f.path);
    let db = Connection::open(&f.path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    db.execute(
        "INSERT INTO authority_principals VALUES(?,?,?,'https://identity.example.test','orphan',?)",
        rusqlite::params![plans::PROJECT, plans::ORG, PRINCIPAL, NOW],
    )
    .unwrap();
    drop(db);
    let original = snapshot(&f.path);
    let backup = f.path.with_file_name("invalid-v3.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    assert_eq!(snapshot(&backup), original);
    assert_eq!(snapshot(&f.path), original);
    let db = Connection::open(&f.path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        3
    );
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT count(*) FROM sqlite_schema WHERE name='authority_plan_review_evidence'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
}
