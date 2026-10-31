#![cfg(feature = "approval-proofs")]

//! Independent pending-key possession, provisioning and rollback regressions.
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;

use approval_authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_authority::{ApprovalRole, AuthorityStore, AuthorityTenant};
use fw_webauthn::{Credential, WebAuthn};
use rusqlite::{Connection, params};
use std::sync::{Arc, Barrier};

const ORG: &str = "11111111-1111-4111-8111-111111111112";
const PROJECT: &str = "11111111-1111-4111-8111-111111111113";
const OTHER: &str = "22222222-2222-4222-8222-222222222222";
const ISSUER: &str = "https://identity.example.test";
const NOW: i64 = 1_700_000_000;

struct Pending {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    verifier: WebAuthn,
    credential: Credential,
    key: Authenticator,
}
impl Pending {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Pending key", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        store
            .provision_principal(&tenant, PRINCIPAL, ISSUER, "alice", NOW)
            .unwrap();
        store
            .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
            .unwrap();
        Self {
            _directory: directory,
            path,
            store,
            tenant,
            verifier,
            credential,
            key,
        }
    }
    fn count(&self, query: &str) -> i64 {
        Connection::open(&self.path)
            .unwrap()
            .query_row(query, [], |r| r.get(0))
            .unwrap()
    }
}

#[test]
fn trusted_identity_cannot_be_aliased_or_rebound_inside_a_tenant() {
    let mut p = Pending::new();
    let before = p.count("SELECT count(*) FROM authority_audit");
    p.store
        .provision_principal(&p.tenant, PRINCIPAL, ISSUER, "alice", NOW + 1)
        .unwrap();
    assert_eq!(p.count("SELECT count(*) FROM authority_audit"), before);
    assert!(
        p.store
            .provision_principal(&p.tenant, OTHER, ISSUER, "alice", NOW + 1)
            .is_err()
    );
    assert!(
        p.store
            .provision_principal(&p.tenant, PRINCIPAL, ISSUER, "another-person", NOW + 1)
            .is_err()
    );
    assert_eq!(p.count("SELECT count(*) FROM authority_principals"), 1);
    assert_eq!(p.count("SELECT count(*) FROM authority_audit"), before);
    // The other project is a distinct trusted tenant, not an alias in this one.
    let other = AuthorityTenant::new(ORG, OTHER).unwrap();
    p.store
        .provision_principal(&other, PRINCIPAL, ISSUER, "alice", NOW + 1)
        .unwrap();
    assert!(
        p.store
            .grant_role(&other, OTHER, ApprovalRole::Owner, NOW, NOW + 7200, NOW + 1)
            .is_err()
    );
    assert!(
        p.store
            .provision_principal(&p.tenant, OTHER, &"a".repeat(2049), "bob", NOW + 1)
            .is_err()
    );
    assert!(
        p.store
            .provision_principal(&p.tenant, OTHER, ISSUER, &"b".repeat(513), NOW + 1)
            .is_err()
    );
    assert!(
        p.store
            .provision_principal(&p.tenant, OTHER, ISSUER, "bob\n", NOW + 1)
            .is_err()
    );
}

#[test]
fn invalid_activation_attempts_remain_exhausted_after_restart() {
    let mut p = Pending::new();
    let activation = p
        .store
        .begin_credential_activation(&p.tenant, &p.credential.id(), &p.verifier, NOW)
        .unwrap();
    let invalid = p.key.assertion(&activation.options, 1, 0x01, ORIGIN);
    for _ in 0..10 {
        assert!(
            p.store
                .finish_credential_activation(
                    &p.tenant,
                    &activation.activation_id,
                    &invalid,
                    &p.verifier,
                    NOW + 1
                )
                .is_err()
        );
    }
    assert_eq!(p.count("SELECT attempts FROM authority_activations"), 10);
    assert_eq!(
        p.count("SELECT count(*) FROM authority_activations WHERE consumed_at IS NOT NULL"),
        0
    );
    assert_eq!(
        p.count("SELECT count(*) FROM authority_audit WHERE kind='credential_activation_failed'"),
        10
    );
    p.store = AuthorityStore::open(&p.path).unwrap();
    let valid = p.key.assertion(&activation.options, 1, 0x05, ORIGIN);
    assert!(
        p.store
            .finish_credential_activation(
                &p.tenant,
                &activation.activation_id,
                &valid,
                &p.verifier,
                NOW + 2
            )
            .is_err()
    );
    assert_eq!(
        p.count("SELECT count(*) FROM authority_audit WHERE kind='credential_activation_failed'"),
        10
    );
    assert_eq!(
        p.count("SELECT count(*) FROM authority_credentials WHERE state='active'"),
        0
    );
    let fresh = p
        .store
        .begin_credential_activation(&p.tenant, &p.credential.id(), &p.verifier, NOW + 2)
        .unwrap();
    p.store
        .finish_credential_activation(
            &p.tenant,
            &fresh.activation_id,
            &p.key.assertion(&fresh.options, 1, 0x05, ORIGIN),
            &p.verifier,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        p.count("SELECT count(*) FROM authority_credentials WHERE state='active'"),
        1
    );
}

#[test]
fn zero_counter_activation_race_has_one_durable_winner() {
    let mut p = Pending::new();
    let activation = p
        .store
        .begin_credential_activation(&p.tenant, &p.credential.id(), &p.verifier, NOW)
        .unwrap();
    let response = p.key.assertion(&activation.options, 0, 0x05, ORIGIN);
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = p.path.clone();
            let tenant = p.tenant.clone();
            let response = response.clone();
            let id = activation.activation_id.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                let verifier = WebAuthn::new(ORIGIN).unwrap();
                barrier.wait();
                store
                    .finish_credential_activation(&tenant, &id, &response, &verifier, NOW + 1)
                    .is_ok()
            })
        })
        .collect();
    barrier.wait();
    assert_eq!(
        workers
            .into_iter()
            .map(|w| usize::from(w.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(p.count("SELECT revision FROM authority_credentials"), 2);
    assert_eq!(
        p.count("SELECT count(*) FROM authority_audit WHERE kind='credential_activated'"),
        1
    );
    assert_eq!(
        p.count("SELECT count(*) FROM authority_activations WHERE consumed_at IS NOT NULL"),
        1
    );
}

#[test]
fn activation_audit_failure_rolls_back_key_counter_and_consumption() {
    let mut p = Pending::new();
    let activation = p
        .store
        .begin_credential_activation(&p.tenant, &p.credential.id(), &p.verifier, NOW)
        .unwrap();
    let response = p.key.assertion(&activation.options, 1, 0x05, ORIGIN);
    let connection = Connection::open(&p.path).unwrap();
    let original: Vec<u8> = connection
        .query_row(
            "SELECT credential_bytes FROM authority_credentials",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let before_revision = p.count("SELECT security_revision FROM authority_projects");
    connection.execute_batch("CREATE TRIGGER reject_activation_audit BEFORE INSERT ON authority_audit WHEN NEW.kind='credential_activated' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
    assert!(
        p.store
            .finish_credential_activation(
                &p.tenant,
                &activation.activation_id,
                &response,
                &p.verifier,
                NOW + 1
            )
            .is_err()
    );
    assert_eq!(p.count("SELECT revision FROM authority_credentials"), 1);
    assert_eq!(
        p.count("SELECT count(*) FROM authority_credentials WHERE state='pending'"),
        1
    );
    assert_eq!(
        p.count("SELECT count(*) FROM authority_activations WHERE consumed_at IS NOT NULL"),
        0
    );
    assert_eq!(
        p.count("SELECT security_revision FROM authority_projects"),
        before_revision
    );
    let after: Vec<u8> = connection
        .query_row(
            "SELECT credential_bytes FROM authority_credentials",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(original, after);
    connection
        .execute_batch("DROP TRIGGER reject_activation_audit")
        .unwrap();
    p.store = AuthorityStore::open(&p.path).unwrap();
    p.store
        .finish_credential_activation(
            &p.tenant,
            &activation.activation_id,
            &response,
            &p.verifier,
            NOW + 2,
        )
        .unwrap();
    assert_eq!(
        p.count("SELECT count(*) FROM authority_credentials WHERE state='active'"),
        1
    );
}

#[test]
fn pending_credential_revocation_is_permanent_and_scoped() {
    let mut p = Pending::new();
    let activation = p
        .store
        .begin_credential_activation(&p.tenant, &p.credential.id(), &p.verifier, NOW)
        .unwrap();
    let response = p.key.assertion(&activation.options, 1, 0x05, ORIGIN);
    let other = AuthorityTenant::new(ORG, OTHER).unwrap();
    assert!(
        p.store
            .revoke_credential(&other, &p.credential.id(), NOW + 1)
            .is_err()
    );
    p.store
        .revoke_credential(&p.tenant, &p.credential.id(), NOW + 1)
        .unwrap();
    p.store = AuthorityStore::open(&p.path).unwrap();
    assert!(
        p.store
            .finish_credential_activation(
                &p.tenant,
                &activation.activation_id,
                &response,
                &p.verifier,
                NOW + 2
            )
            .is_err()
    );
    assert!(
        p.store
            .pin_credential(&p.tenant, &p.credential, NOW, NOW + 7200, NOW + 2)
            .is_err()
    );
    assert!(
        p.store
            .begin_credential_activation(&p.tenant, &p.credential.id(), &p.verifier, NOW + 2)
            .is_err()
    );
    p.store
        .revoke_credential(&p.tenant, &p.credential.id(), NOW + 2)
        .unwrap();
    assert_eq!(
        p.count("SELECT count(*) FROM authority_audit WHERE kind='credential_revoked'"),
        1
    );
    let row: (String, Option<i64>, i64) = Connection::open(&p.path)
        .unwrap()
        .query_row(
            "SELECT state,activated_at,revision FROM authority_credentials WHERE credential_id=?",
            params![p.credential.id()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(row, ("revoked".into(), None, 2));
}

#[test]
fn activation_is_time_bounded_and_scoped_to_its_origin_and_tenant() {
    let mut p = Pending::new();
    let activation = p
        .store
        .begin_credential_activation(&p.tenant, &p.credential.id(), &p.verifier, NOW)
        .unwrap();
    let response = p.key.assertion(&activation.options, 1, 0x05, ORIGIN);
    let other = AuthorityTenant::new(ORG, OTHER).unwrap();
    assert!(
        p.store
            .finish_credential_activation(
                &other,
                &activation.activation_id,
                &response,
                &p.verifier,
                NOW + 1
            )
            .is_err()
    );
    let wrong_origin = WebAuthn::new("http://localhost:9999").unwrap();
    assert!(
        p.store
            .finish_credential_activation(
                &p.tenant,
                &activation.activation_id,
                &response,
                &wrong_origin,
                NOW + 1
            )
            .is_err()
    );
    assert!(
        p.store
            .finish_credential_activation(
                &p.tenant,
                &activation.activation_id,
                &response,
                &p.verifier,
                NOW - 1
            )
            .is_err()
    );
    assert!(
        p.store
            .finish_credential_activation(
                &p.tenant,
                &activation.activation_id,
                &response,
                &p.verifier,
                NOW + 300
            )
            .is_err()
    );
    assert_eq!(
        p.count("SELECT count(*) FROM authority_credentials WHERE state='active'"),
        0
    );
}
