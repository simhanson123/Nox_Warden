//! Late write failures through real authority API transactions. The private
//! hooks alter no schema, grant no authority and are discarded by reopening.
//! Actual pending mutations prove these are rollback tests, not early guard
//! refusals. Device/observer signatures are genuine test signatures only.
use super::*;
use crate::ApprovalRole;
use fw_backend_linux::{LabReferences, PortableArtifact, compile_portable};
use fw_native_evidence::ArtifactRole;
use rusqlite::hooks::{Action, AuthAction, AuthContext, Authorization};
use signing_test_support::{
    NOW,
    authenticator::{Authenticator, ORIGIN, PRINCIPAL},
    native, private_directory,
};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use super::core_access_fixture as core_fixture;

struct Database {
    _directory: tempfile::TempDir,
    path: PathBuf,
    store: AuthorityStore,
}
impl Database {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let path = directory.path().join("authority.sqlite3");
        let store = AuthorityStore::open(&path).unwrap();
        Self {
            _directory: directory,
            path,
            store,
        }
    }
    fn reopen(&mut self) {
        self.store = AuthorityStore::open(&self.path).unwrap();
        assert!(!self.store.connection.is_forensic_arithmetic_fixture());
    }
    fn rows(&self) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
        let db = Connection::open(&self.path).unwrap();
        let tables = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap()
            .query_map([], |row| row.get::<_, String>(0)).unwrap()
            .collect::<rusqlite::Result<Vec<_>>>().unwrap();
        tables
            .into_iter()
            .map(|table| {
                let mut query = db
                    .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
                    .unwrap();
                let columns = query.column_count();
                let rows = query
                    .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                (table, rows)
            })
            .collect()
    }
}

#[derive(Default)]
struct Reached {
    attempts: AtomicUsize,
    changed: Mutex<BTreeSet<String>>,
}

// The existing cfg(test) raw connection accessor is private to the crate. The
// normal IntegrityConnection transaction checks and released SQL guards still
// execute. Installing this authorizer expires cached statements, so the chosen
// INSERT is denied at its real preparation after preceding SQL has executed.
fn reject_insert(store: &AuthorityStore, table: &'static str, nth: usize) -> Arc<Reached> {
    let reached = Arc::new(Reached::default());
    let observed = reached.clone();
    store
        .connection
        .update_hook(Some(move |_: Action, _: &str, table: &str, _: i64| {
            observed.changed.lock().unwrap().insert(table.to_owned());
        }));
    let observed = reached.clone();
    store
        .connection
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(context.action, AuthAction::Insert { table_name } if table_name == table)
                && observed.attempts.fetch_add(1, Ordering::SeqCst) + 1 == nth
            {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
    reached
}

fn assert_late_failure(error: AuthorityError, reached: &Reached, nth: usize, changed: &[&str]) {
    assert!(
        matches!(error, AuthorityError::Storage(rusqlite::Error::SqliteFailure(ref code, _))
        if code.code == rusqlite::ErrorCode::AuthorizationForStatementDenied),
        "{error:?}"
    );
    assert_eq!(reached.attempts.load(Ordering::SeqCst), nth);
    let actual = reached.changed.lock().unwrap();
    for table in changed {
        assert!(
            actual.contains(*table),
            "no pending mutation of {table}: {actual:?}"
        );
    }
}

struct NativeFixture {
    database: Database,
    tenant: AuthorityTenant,
    references: LabReferences,
    artifact: PortableArtifact,
}
impl NativeFixture {
    fn new() -> Self {
        let mut database = Database::new();
        let (tenant, _, _, review, references) = native::setup(&mut database.store, NOW);
        let artifact = compile_portable(&review.after, &references).unwrap();
        Self {
            database,
            tenant,
            references,
            artifact,
        }
    }
}

#[test]
fn core_provenance_audit_failure_rolls_back_request_binding_and_security() {
    let mut f = Database::new();
    let (plan, provenance) = core_fixture::fixture();
    let tenant = AuthorityTenant::new(
        plan["org_id"].as_str().unwrap(),
        plan["project_id"].as_str().unwrap(),
    )
    .unwrap();
    f.store
        .provision_principal(
            &tenant,
            plan["principal_id"].as_str().unwrap(),
            "https://identity.example.test",
            "core-test-user",
            NOW,
        )
        .unwrap();
    f.store
        .register_plan(&tenant, &plan, &core_fixture::requirements(), NOW)
        .unwrap();
    let before = f.rows();
    let reached = reject_insert(&f.store, "authority_audit", 1);
    let error = f
        .store
        .register_core_access_provenance(
            &tenant,
            plan["plan_id"].as_str().unwrap(),
            &provenance,
            NOW + 1,
        )
        .unwrap_err();
    assert_late_failure(
        error,
        &reached,
        1,
        &[
            "authority_core_access_requests",
            "authority_core_access_plan_bindings",
            "authority_projects",
        ],
    );
    assert_eq!(f.rows(), before);
    f.reopen();
    let admitted = f
        .store
        .register_core_access_provenance(
            &tenant,
            plan["plan_id"].as_str().unwrap(),
            &provenance,
            NOW + 1,
        )
        .unwrap();
    assert!(!admitted.signing_allowed && !admitted.dispatch_allowed);
    let committed = f.rows();
    f.store
        .register_core_access_provenance(
            &tenant,
            plan["plan_id"].as_str().unwrap(),
            &provenance,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(f.rows(), committed);
}

#[test]
fn reviewed_plan_evidence_and_final_audit_failures_roll_back_the_complete_import() {
    for evidence_write in [true, false] {
        let mut f = Database::new();
        let tenant = AuthorityTenant::new(native::ORG, native::PROJECT).unwrap();
        f.store
            .provision_target_metadata_project(&tenant, NOW)
            .unwrap();
        let (plan, requirements, review, _) = native::native_plan(NOW);
        let before = f.rows();
        let (table, nth) = if evidence_write {
            ("authority_plan_review_evidence", 1)
        } else {
            ("authority_audit", 2)
        };
        let reached = reject_insert(&f.store, table, nth);
        let error = f
            .store
            .register_reviewed_plan(&tenant, &plan, &requirements, &review, NOW)
            .unwrap_err();
        let mut changed = vec![
            "authority_plans",
            "authority_requirements",
            "authority_requirement_roles",
            "authority_projects",
            "authority_audit",
            "authority_audit_heads",
        ];
        if !evidence_write {
            changed.push("authority_plan_review_evidence");
        }
        assert_late_failure(error, &reached, nth, &changed);
        assert_eq!(f.rows(), before);
        f.reopen();
        f.store
            .register_reviewed_plan(&tenant, &plan, &requirements, &review, NOW)
            .unwrap();
        assert!(
            f.store
                .policy_review_evidence(&tenant, native::PLAN, NOW)
                .unwrap()
                .is_some()
        );
        let committed = f.rows();
        f.store
            .register_reviewed_plan(&tenant, &plan, &requirements, &review, NOW)
            .unwrap();
        assert_eq!(f.rows(), committed);
    }
}

#[test]
fn native_compilation_challenge_and_observation_audit_failures_roll_back() {
    let mut f = NativeFixture::new();
    let before = f.database.rows();
    let reached = reject_insert(&f.database.store, "authority_audit", 1);
    let error = f
        .database
        .store
        .register_native_compilation(&f.tenant, native::PLAN, 1, NOW)
        .unwrap_err();
    assert_late_failure(
        error,
        &reached,
        1,
        &[
            "authority_native_compilations",
            "authority_native_compilation_heads",
        ],
    );
    assert_eq!(f.database.rows(), before);
    f.database.reopen();
    let compilation = f
        .database
        .store
        .register_native_compilation(&f.tenant, native::PLAN, 1, NOW)
        .unwrap();
    assert!(!compilation.production_qualified && !compilation.dispatch_allowed);

    let installation = native::installation(&f.artifact, NOW);
    let before = f.database.rows();
    let reached = reject_insert(&f.database.store, "authority_audit", 1);
    let error = f
        .database
        .store
        .challenge_native_observation(
            &f.tenant,
            native::PLAN,
            ArtifactRole::Candidate,
            &installation,
            None,
            1,
            1,
            NOW,
        )
        .unwrap_err();
    assert_late_failure(error, &reached, 1, &["authority_native_challenges"]);
    assert_eq!(f.database.rows(), before);
    f.database.reopen();
    let challenge = f
        .database
        .store
        .challenge_native_observation(
            &f.tenant,
            native::PLAN,
            ArtifactRole::Candidate,
            &installation,
            None,
            1,
            1,
            NOW,
        )
        .unwrap();
    let proof = native::proof(
        &challenge,
        installation.clone(),
        native::snapshot(&installation.native),
        NOW + 1,
    );
    // Time observation is a separate durable security transaction by contract.
    // Prime that floor through the real read API before comparing rollback rows.
    f.database
        .store
        .current_target_metadata(&f.tenant, native::TARGET, NOW + 1)
        .unwrap();
    let before = f.database.rows();
    let reached = reject_insert(&f.database.store, "authority_audit", 1);
    let error = f
        .database
        .store
        .admit_native_observation(&f.tenant, &proof, NOW + 1)
        .unwrap_err();
    assert_late_failure(
        error,
        &reached,
        1,
        &[
            "authority_native_observations",
            "authority_native_observation_heads",
        ],
    );
    assert_eq!(f.database.rows(), before);
    f.database.reopen();
    assert!(
        !f.database
            .store
            .admit_native_observation(&f.tenant, &proof, NOW + 1)
            .unwrap()
            .replayed
    );
    let committed = f.database.rows();
    assert!(
        f.database
            .store
            .admit_native_observation(&f.tenant, &proof, NOW + 1)
            .unwrap()
            .replayed
    );
    assert_eq!(f.database.rows(), committed);
}

#[test]
fn native_reference_and_observer_pin_audit_failures_leave_no_partial_trust() {
    for observer in [false, true] {
        let mut f = NativeFixture::new();
        let references = NativeReferencePin {
            target_id: native::TARGET.into(),
            references: f.references.clone(),
            not_before: NOW,
            not_after: NOW + 4000,
        };
        let observer_pin = NativeObserverPin {
            target_id: native::TARGET.into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[99; 32])
                .verifying_key()
                .to_bytes(),
            not_before: NOW,
            not_after: NOW + 4000,
        };
        let before = f.database.rows();
        let reached = reject_insert(&f.database.store, "authority_audit", 1);
        let result = if observer {
            f.database
                .store
                .pin_native_observer(&f.tenant, &observer_pin, Some(1), NOW)
        } else {
            f.database
                .store
                .pin_native_references(&f.tenant, &references, Some(1), NOW)
        };
        let mut changed = vec![
            "authority_native_pins",
            "authority_native_pin_heads",
            "authority_projects",
        ];
        if observer {
            changed.extend([
                "authority_native_observer_keys",
                "authority_native_observer_revocations",
            ]);
        }
        assert_late_failure(result.unwrap_err(), &reached, 1, &changed);
        assert_eq!(f.database.rows(), before);
        f.database.reopen();
        let revision = if observer {
            f.database
                .store
                .pin_native_observer(&f.tenant, &observer_pin, Some(1), NOW)
                .unwrap()
        } else {
            f.database
                .store
                .pin_native_references(&f.tenant, &references, Some(1), NOW)
                .unwrap()
        };
        assert_eq!(revision, 2);
    }
}

#[test]
fn target_metadata_audit_failure_preserves_unconsumed_report_and_exact_retry() {
    let mut f = NativeFixture::new();
    let challenge = f
        .database
        .store
        .issue_target_report_challenge(&f.tenant, native::TARGET, NOW + 1)
        .unwrap();
    let proof = fw_target_evidence::sign_report(
        &challenge,
        &canonical_bytes(&native::metadata_report(NOW + 2)).unwrap(),
        &native::METADATA_SEED,
        NOW + 2,
    )
    .unwrap();
    // Preserve the separately committed anti-rollback floor while demanding a
    // byte/rowid exact rollback of every other retained table in this attempt.
    f.database
        .store
        .current_target_metadata(&f.tenant, native::TARGET, NOW + 2)
        .unwrap();
    let before = f.database.rows();
    let reached = reject_insert(&f.database.store, "authority_audit", 1);
    let error = f
        .database
        .store
        .admit_target_report(&f.tenant, &proof, NOW + 2)
        .unwrap_err();
    assert_late_failure(
        error,
        &reached,
        1,
        &[
            "authority_target_metadata",
            "authority_target_metadata_heads",
        ],
    );
    assert_eq!(f.database.rows(), before);
    f.database.reopen();
    assert!(
        !f.database
            .store
            .admit_target_report(&f.tenant, &proof, NOW + 2)
            .unwrap()
            .replayed
    );
    let committed = f.database.rows();
    assert!(
        f.database
            .store
            .admit_target_report(&f.tenant, &proof, NOW + 2)
            .unwrap()
            .replayed
    );
    assert_eq!(f.database.rows(), committed);
}

#[test]
fn transport_pin_audit_failure_rolls_back_key_pin_clock_and_security() {
    let mut f = NativeFixture::new();
    let pin = TargetTransportPin {
        target_id: "55555555-5555-4555-8555-555555555555".into(),
        public_key: ed25519_dalek::SigningKey::from_bytes(&[98; 32])
            .verifying_key()
            .to_bytes(),
        certificate_fingerprint: hash_bytes(b"atomicity second target certificate"),
        platform: "linux".into(),
        not_before: NOW,
        not_after: NOW + 3600,
    };
    let before = f.database.rows();
    let reached = reject_insert(&f.database.store, "authority_audit", 1);
    let error = f
        .database
        .store
        .pin_target_transport(&f.tenant, &pin, None, NOW)
        .unwrap_err();
    assert_late_failure(
        error,
        &reached,
        1,
        &[
            "authority_target_keys",
            "authority_target_pins",
            "authority_target_pin_heads",
            "authority_target_clocks",
            "authority_projects",
        ],
    );
    assert_eq!(f.database.rows(), before);
    f.database.reopen();
    assert_eq!(
        f.database
            .store
            .pin_target_transport(&f.tenant, &pin, None, NOW)
            .unwrap(),
        1
    );
    let committed = f.database.rows();
    assert_eq!(
        f.database
            .store
            .pin_target_transport(&f.tenant, &pin, None, NOW)
            .unwrap(),
        1
    );
    assert_eq!(f.database.rows(), committed);
}

#[test]
fn pending_and_active_login_audit_failures_roll_back_consumption_and_activation() {
    for active in [false, true] {
        let mut f = Database::new();
        let tenant = AuthorityTenant::new(native::ORG, native::PROJECT).unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Pinned reviewer", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        f.store
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://authority.example.test",
                "reviewer",
                NOW,
            )
            .unwrap();
        f.store
            .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
            .unwrap();
        if active {
            let activation = f
                .store
                .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
                .unwrap();
            f.store
                .finish_credential_activation(
                    &tenant,
                    &activation.activation_id,
                    &key.assertion(&activation.options, 0, 5, ORIGIN),
                    &verifier,
                    NOW,
                )
                .unwrap();
        }
        f.store
            .grant_role(
                &tenant,
                PRINCIPAL,
                ApprovalRole::Owner,
                NOW,
                NOW + 7200,
                NOW,
            )
            .unwrap();
        let login = f
            .store
            .begin_review_login(&tenant, PRINCIPAL, &credential.id(), &verifier, NOW + 1)
            .unwrap();
        let proof = key.assertion(&login.options, 0, 5, ORIGIN);
        let before = f.rows();
        let reached = reject_insert(&f.store, "authority_audit", 1);
        let error = f
            .store
            .finish_review_login(&tenant, &login, &proof, &verifier, NOW + 2)
            .unwrap_err();
        let mut changed = vec!["authority_credentials"];
        if !active {
            changed.extend(["authority_activations", "authority_projects"]);
        }
        assert_late_failure(error, &reached, 1, &changed);
        assert_eq!(f.rows(), before);
        f.reopen();
        f.store
            .finish_review_login(&tenant, &login, &proof, &verifier, NOW + 2)
            .unwrap();
        let committed = f.rows();
        assert!(
            f.store
                .finish_review_login(&tenant, &login, &proof, &verifier, NOW + 2)
                .is_err()
        );
        assert_eq!(f.rows(), committed);
    }
}
