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

#[test]
fn public_principal_audit_tail_cannot_be_replaced_or_rewound() {
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, FIRST, NOW);
    provision(&mut store, &tenant, SECOND, NOW + 1);
    let path = directory.path().join("authority.sqlite3");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
        .unwrap();
    let before = snapshot(&connection);
    let first: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT sequence,event_hash FROM authority_audit ORDER BY sequence LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    // This public-API reproduction previously erased the second genuine audit
    // event without changing any guard or principal, then rewound its head.
    let replace = connection.execute("INSERT OR REPLACE INTO authority_audit
        (rowid,org_id,project_id,sequence,event_hash,previous_hash,kind,resource_id,recorded_at,canonical_bytes)
        SELECT (SELECT MAX(rowid) FROM authority_audit),org_id,project_id,sequence,event_hash,
        previous_hash,kind,resource_id,recorded_at,canonical_bytes FROM authority_audit ORDER BY sequence LIMIT 1", []);
    assert!(replace.is_err());
    let rewind = connection.execute(
        "UPDATE authority_audit_heads SET sequence=?,event_hash=?",
        params![first.0, first.1],
    );
    assert!(rewind.is_err());
    assert_eq!(snapshot(&connection), before);
    assert_eq!(
        store
            .verify_audit_chain(&tenant)
            .unwrap()
            .unwrap()
            .event_count,
        2
    );
    drop(store);
    let mut reopened = AuthorityStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .verify_audit_chain(&tenant)
            .unwrap()
            .unwrap()
            .event_count,
        2
    );
}

#[test]
fn audit_head_identity_genesis_and_exact_next_event_are_guarded() {
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, FIRST, NOW);
    let connection = Connection::open(directory.path().join("authority.sqlite3")).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA recursive_triggers=OFF")
        .unwrap();
    let before = snapshot(&connection);
    for mutation in [
        "DELETE FROM authority_audit_heads",
        "INSERT OR REPLACE INTO authority_audit_heads SELECT * FROM authority_audit_heads",
        "INSERT OR REPLACE INTO authority_audit_heads(rowid,org_id,project_id,sequence,event_hash) SELECT rowid,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',project_id,zeroblob(8),zeroblob(32) FROM authority_audit_heads",
        "UPDATE OR REPLACE authority_audit_heads SET rowid=rowid+1",
        "UPDATE authority_audit_heads SET org_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'",
        "UPDATE authority_audit_heads SET sequence=x'0000000000000000',event_hash=zeroblob(32)",
        "UPDATE authority_audit_heads SET sequence=x'0000000000000002',event_hash=zeroblob(32)",
        "UPDATE authority_audit_heads SET sequence=x'0000000000000003',event_hash=zeroblob(32)",
    ] {
        assert!(connection.execute_batch(mutation).is_err(), "{mutation}");
        assert_eq!(snapshot(&connection), before);
    }
    // A normal same-time application append advances one exact linked event.
    provision(&mut store, &tenant, SECOND, NOW);
    assert_eq!(
        store
            .verify_audit_chain(&tenant)
            .unwrap()
            .unwrap()
            .event_count,
        2
    );
}

#[test]
fn sql_audit_head_successor_preserves_unsigned_u64_boundaries() {
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, FIRST, NOW);
    let connection = Connection::open(directory.path().join("authority.sqlite3")).unwrap();
    let advance: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_audit_heads_advance'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let append_guards =
        ["authority_audit_exact_next", "authority_audit_project_head"].map(|name| {
            let sql: String = connection
                .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [name], |r| {
                    r.get(0)
                })
                .unwrap();
            connection
                .execute_batch(&format!("DROP TRIGGER {name}"))
                .unwrap();
            sql
        });
    // A focused SQL arithmetic fixture cannot contain 2^63 genuine events.
    // Isolate the retained head's BLOB successor predicate from the schema13
    // atomic append guards, which require a genuine complete preceding tail.
    for previous in [
        0u64,
        15,
        255,
        u32::MAX as u64,
        i64::MAX as u64,
        u64::MAX - 1,
        u64::MAX,
    ] {
        connection
            .execute_batch("DROP TRIGGER authority_audit_heads_advance")
            .unwrap();
        connection
            .execute(
                "UPDATE authority_audit_heads SET sequence=?,event_hash=zeroblob(32)",
                [previous.to_be_bytes().as_slice()],
            )
            .unwrap();
        connection.execute_batch(&advance).unwrap();
        for next in [previous, previous.wrapping_add(2), previous.wrapping_add(1)] {
            let tx = connection.unchecked_transaction().unwrap();
            // The genuine sequence1 collision is intentionally retained.
            let insert=tx.execute("INSERT INTO authority_audit(org_id,project_id,sequence,event_hash,previous_hash,kind,resource_id,recorded_at,canonical_bytes) VALUES(?,?,?, ?,zeroblob(32),'probe','probe',?,x'7b7d')",params![ORG,PROJECT,next.to_be_bytes().as_slice(),[7u8;32].as_slice(),NOW]);
            if next == 1 {
                assert!(insert.is_err());
            } else {
                insert.unwrap();
            }
            let result = tx.execute(
                "UPDATE authority_audit_heads SET sequence=?,event_hash=?",
                params![next.to_be_bytes().as_slice(), [7u8; 32].as_slice()],
            );
            // Sequence1 is the genuine first event and has a different hash.
            if previous == 0 && next == 1 {
                assert!(result.is_err());
            } else {
                assert_eq!(
                    result.is_ok(),
                    previous.checked_add(1) == Some(next),
                    "previous={previous} next={next}"
                );
            }
            tx.rollback().unwrap();
        }
    }
    for guard in append_guards {
        connection.execute_batch(&guard).unwrap();
    }
}
