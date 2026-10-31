#![cfg(feature = "approval-proofs")]

use fw_authority::{AuthorityError, AuthorityStore, AuthorityTenant};
use rusqlite::{Connection, params};
use tempfile::{Builder, TempDir};

const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const FIRST: &str = "44444444-4444-4444-8444-444444444444";
const SECOND: &str = "55555555-5555-4555-8555-555555555555";
const NOW: i64 = 1_700_000_000;

#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/audit_verification.rs"]
mod verification;

fn fixture() -> (TempDir, AuthorityStore, AuthorityTenant) {
    let mut builder = Builder::new();
    builder.prefix("authority-audit-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let directory = builder.tempdir().unwrap();
    let store = AuthorityStore::open(directory.path().join("authority.sqlite3")).unwrap();
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    (directory, store, tenant)
}

fn provision(store: &mut AuthorityStore, tenant: &AuthorityTenant, id: &str, now: i64) {
    store
        .provision_principal(tenant, id, "local-oob", id, now)
        .unwrap();
}

fn snapshot(connection: &Connection) -> (i64, i64, i64, Vec<u8>, Vec<u8>) {
    connection
        .query_row(
            "SELECT (SELECT count(*) FROM authority_principals), security_revision,
         (SELECT count(*) FROM authority_audit), sequence,event_hash
         FROM authority_projects JOIN authority_audit_heads USING(org_id,project_id)
         WHERE org_id=? AND project_id=?",
            params![ORG, PROJECT],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap()
}

#[test]
fn backward_append_rolls_back_principal_security_revision_and_audit() {
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, FIRST, NOW + 100);
    let connection = Connection::open(directory.path().join("authority.sqlite3")).unwrap();
    let before = snapshot(&connection);
    assert!(matches!(
        store.provision_principal(&tenant, SECOND, "local-oob", SECOND, NOW + 50),
        Err(AuthorityError::Time)
    ));
    assert_eq!(snapshot(&connection), before);
    provision(&mut store, &tenant, SECOND, NOW + 100);
    assert_eq!(snapshot(&connection).0, 2);
}

#[test]
fn backward_time_rolls_back_a_genuine_zero_counter_activation_and_all_mutations() {
    use approval_authenticator::{Authenticator, ORIGIN, PRINCIPAL};
    use fw_webauthn::WebAuthn;
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, PRINCIPAL, NOW);
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let key = Authenticator::new(PRINCIPAL);
    let registration = verifier
        .begin_registration(PRINCIPAL, "Audit rollback key", &[])
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
    let activation = store
        .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
        .unwrap();
    let response = key.assertion(&activation.options, 0, 0x05, ORIGIN);
    provision(&mut store, &tenant, SECOND, NOW + 100);
    let connection = Connection::open(directory.path().join("authority.sqlite3")).unwrap();
    let full_snapshot = || {
        [
            "authority_credentials",
            "authority_activations",
            "authority_projects",
            "authority_audit",
            "authority_audit_heads",
        ]
        .map(|table| {
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let count = statement.column_count();
            statement
                .query_map([], |row| {
                    (0..count)
                        .map(|index| row.get::<_, rusqlite::types::Value>(index))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        })
    };
    let before = full_snapshot();
    assert!(matches!(
        store.finish_credential_activation(
            &tenant,
            &activation.activation_id,
            &response,
            &verifier,
            NOW + 50
        ),
        Err(AuthorityError::Time)
    ));
    assert_eq!(full_snapshot(), before);
    drop(store);
    let mut store = AuthorityStore::open(directory.path().join("authority.sqlite3")).unwrap();
    store
        .finish_credential_activation(
            &tenant,
            &activation.activation_id,
            &response,
            &verifier,
            NOW + 100,
        )
        .unwrap();
    assert_eq!(
        store
            .verify_audit_chain(&tenant)
            .unwrap()
            .unwrap()
            .last_recorded_at,
        Some(NOW + 100)
    );
}
