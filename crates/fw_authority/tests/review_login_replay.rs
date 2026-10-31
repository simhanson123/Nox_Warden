#![cfg(feature = "approval-proofs")]

//! Actual P-256 signatures exercising durable authority-login consumption.
//! Software authentication is not evidence of human consent or OS isolation.
#[allow(dead_code)]
#[path = "support/approval_authenticator.rs"]
mod authenticator;
#[path = "support/private_directory.rs"]
mod private_directory;

use authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_authority::{ApprovalRole, AuthorityStore, AuthorityTenant, ReviewLogin};
use fw_webauthn::{AuthenticationResponse, Credential, WebAuthn};
use rusqlite::{Connection, types::Value};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};

const NOW: i64 = 1_700_000_000;
const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    tenant: AuthorityTenant,
    verifier: WebAuthn,
    key: Authenticator,
    credential: Credential,
}

impl Fixture {
    fn new(active: bool) -> Self {
        let directory = private_directory::private_directory();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
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
        store
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://authority.example.test",
                "reviewer",
                NOW,
            )
            .unwrap();
        store
            .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
            .unwrap();
        if active {
            let activation = store
                .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
                .unwrap();
            store
                .finish_credential_activation(
                    &tenant,
                    &activation.activation_id,
                    &key.assertion(&activation.options, 0, 5, ORIGIN),
                    &verifier,
                    NOW,
                )
                .unwrap();
        }
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
        Self {
            _directory: directory,
            path,
            tenant,
            verifier,
            key,
            credential,
        }
    }

    fn open(&self) -> AuthorityStore {
        AuthorityStore::open(&self.path).unwrap()
    }

    fn login(&self, store: &mut AuthorityStore) -> (ReviewLogin, AuthenticationResponse) {
        let login = store
            .begin_review_login(
                &self.tenant,
                PRINCIPAL,
                &self.credential.id(),
                &self.verifier,
                NOW + 1,
            )
            .unwrap();
        let proof = self.key.assertion(&login.options, 0, 5, ORIGIN);
        (login, proof)
    }
}

fn snapshot(connection: &Connection) -> Vec<Vec<Vec<Value>>> {
    [
        "authority_projects",
        "authority_credentials",
        "authority_activations",
        "authority_audit",
    ]
    .iter()
    .map(|table| {
        let mut query = connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let count = query.column_count();
        query
            .query_map([], |row| (0..count).map(|index| row.get(index)).collect())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    })
    .collect()
}

#[test]
fn zero_counter_login_is_consumed_across_database_reopen() {
    let f = Fixture::new(true);
    let mut store = f.open();
    let raw = Connection::open(&f.path).unwrap();
    let (login, proof) = f.login(&mut store);
    let saved = serde_json::to_vec(&login).unwrap();
    store
        .finish_review_login(&f.tenant, &login, &proof, &f.verifier, NOW + 2)
        .unwrap();
    let after_success = snapshot(&raw);
    drop(store);
    let mut store = f.open();
    let restored: ReviewLogin = serde_json::from_slice(&saved).unwrap();
    assert!(
        store
            .finish_review_login(&f.tenant, &restored, &proof, &f.verifier, NOW + 3)
            .is_err()
    );
    assert!(
        after_success == snapshot(&raw),
        "replay must not change counters, consumption or audit"
    );
    let fresh = store
        .begin_review_login(
            &f.tenant,
            PRINCIPAL,
            &f.credential.id(),
            &f.verifier,
            NOW + 3,
        )
        .unwrap();
    let fresh_proof = f.key.assertion(&fresh.options, 0, 5, ORIGIN);
    store
        .finish_review_login(&f.tenant, &fresh, &fresh_proof, &f.verifier, NOW + 4)
        .unwrap();
    assert!(
        store
            .finish_review_login(&f.tenant, &restored, &proof, &f.verifier, NOW + 4)
            .is_err()
    );
}

#[test]
fn simultaneous_zero_counter_logins_on_separate_connections_have_one_winner() {
    let f = Fixture::new(true);
    let mut store = f.open();
    let (login, proof) = f.login(&mut store);
    let login = serde_json::to_vec(&login).unwrap();
    let proof = serde_json::to_vec(&proof).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let raw = Connection::open(&f.path).unwrap();
    let before: i64 = raw
        .query_row("SELECT revision FROM authority_credentials", [], |r| {
            r.get(0)
        })
        .unwrap();
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let (path, tenant, login, proof, barrier) = (
                f.path.clone(),
                f.tenant.clone(),
                login.clone(),
                proof.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                let mut store = AuthorityStore::open(&path).unwrap();
                let login: ReviewLogin = serde_json::from_slice(&login).unwrap();
                let proof: AuthenticationResponse = serde_json::from_slice(&proof).unwrap();
                let verifier = WebAuthn::new(ORIGIN).unwrap();
                barrier.wait();
                store
                    .finish_review_login(&tenant, &login, &proof, &verifier, NOW + 2)
                    .is_ok()
            })
        })
        .collect();
    let successes = threads
        .into_iter()
        .map(|thread| usize::from(thread.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 1);
    let revision: i64 = raw
        .query_row("SELECT revision FROM authority_credentials", [], |r| {
            r.get(0)
        })
        .unwrap();
    let events: i64 = raw
        .query_row(
            "SELECT count(*) FROM authority_audit WHERE kind='review_login_verified'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(revision, before + 1);
    assert_eq!(events, 1);
}

#[test]
fn audit_failure_rolls_back_consumption_and_pending_activation_then_same_proof_retries() {
    for active in [false, true] {
        let f = Fixture::new(active);
        let mut store = f.open();
        let (login, proof) = f.login(&mut store);
        let raw = Connection::open(&f.path).unwrap();
        let before = snapshot(&raw);
        raw.execute_batch("CREATE TRIGGER injected_review_audit_failure BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(
            store
                .finish_review_login(&f.tenant, &login, &proof, &f.verifier, NOW + 2)
                .is_err()
        );
        assert!(
            before == snapshot(&raw),
            "failed audit must roll back credential, activation, security revision and audit"
        );
        raw.execute_batch("DROP TRIGGER injected_review_audit_failure;")
            .unwrap();
        store
            .finish_review_login(&f.tenant, &login, &proof, &f.verifier, NOW + 2)
            .unwrap();
        let after = snapshot(&raw);
        assert!(
            store
                .finish_review_login(&f.tenant, &login, &proof, &f.verifier, NOW + 2)
                .is_err()
        );
        assert!(
            after == snapshot(&raw),
            "successful retry must consume exactly once"
        );
    }
}
