#![cfg(feature = "approval-proofs")]
#[allow(dead_code)]
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[allow(dead_code)]
#[path = "support/authority_legacy.rs"]
mod authority_legacy;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/registry_fixture.rs"]
mod registry_fixture;
use fw_authority::*;
use fw_contracts::{canonical_bytes, canonical_hash};
use registry_fixture::{Fixture, NOW, OWNER, sign_workload};
use rusqlite::Connection;

#[test]
fn owner_bound_assertion_and_independent_dsse_commit_pending_authority() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    assert!(
        f.store
            .authorize_retained_bootstrap(
                &f.tenant,
                &f.manifest.manifest_id,
                &f.bootstrap_pin.key_id,
                &f.bootstrap_key,
                &f.verifier,
                NOW
            )
            .is_err()
    );
    let proof = f.approve(2);
    assert!(!proof.replayed);
    let signed = f.authorize();
    assert_eq!(
        signed.status.state,
        "authorized_pending_target_confirmation"
    );
    assert!(
        !signed.status.current && !signed.status.signing_allowed && !signed.status.dispatch_allowed
    );
    let verified = verify_bootstrap_authorization(
        &signed.authorization,
        &f.manifest,
        &[proof.proof],
        &f.bootstrap_pin,
        NOW,
    )
    .unwrap();
    assert_eq!(verified.hash(), signed.status.content_hash);
    let same = f.authorize();
    assert_eq!(
        canonical_bytes(&same.authorization).unwrap(),
        canonical_bytes(&signed.authorization).unwrap()
    );
    drop(f.store);
    let mut reopened = AuthorityStore::open(&f.path).unwrap();
    let status = reopened
        .read_registry_object(
            &f.tenant,
            "bootstrap_authorization",
            &f.manifest.manifest_id,
            NOW,
        )
        .unwrap()
        .unwrap();
    assert_eq!(status.content_hash, signed.status.content_hash);
    assert!(!status.dispatch_allowed);
}

#[test]
fn forged_owner_assertion_is_not_consumed_as_approval() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let challenge = f
        .store
        .issue_bootstrap_challenge(
            &f.tenant,
            OWNER,
            &f.credential.id(),
            &f.manifest.manifest_id,
            &f.verifier,
            NOW,
        )
        .unwrap();
    let wrong = f
        .authenticator
        .assertion(&challenge.options, 2, 5, "https://other.example");
    assert!(
        f.store
            .admit_bootstrap_proof(
                &f.tenant,
                OWNER,
                challenge.challenge.challenge_id(),
                &wrong,
                &f.verifier,
                NOW
            )
            .is_err()
    );
    let db = Connection::open(&f.path).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT attempts FROM authority_bootstrap_challenges",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM authority_bootstrap_proofs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let valid = f
        .authenticator
        .assertion(&challenge.options, 2, 5, approval_authenticator::ORIGIN);
    let proof = f
        .store
        .admit_bootstrap_proof(
            &f.tenant,
            OWNER,
            challenge.challenge.challenge_id(),
            &valid,
            &f.verifier,
            NOW,
        )
        .unwrap();
    let replay = f
        .store
        .admit_bootstrap_proof(
            &f.tenant,
            OWNER,
            challenge.challenge.challenge_id(),
            &valid,
            &f.verifier,
            NOW,
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.proof_hash, proof.proof_hash);
    assert!(
        f.store
            .admit_bootstrap_proof(
                &f.tenant,
                OWNER,
                challenge.challenge.challenge_id(),
                &wrong,
                &f.verifier,
                NOW
            )
            .is_err()
    );
}

#[test]
fn revoked_owner_and_wrong_signer_key_cannot_authorize_manifest() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    f.approve(2);
    assert!(
        f.store
            .authorize_retained_bootstrap(
                &f.tenant,
                &f.manifest.manifest_id,
                &f.bootstrap_pin.key_id,
                &f.issuer_key,
                &f.verifier,
                NOW
            )
            .is_err()
    );
    f.store
        .revoke_role(&f.tenant, &f.membership, NOW + 1)
        .unwrap();
    assert!(
        f.store
            .authorize_retained_bootstrap(
                &f.tenant,
                &f.manifest.manifest_id,
                &f.bootstrap_pin.key_id,
                &f.bootstrap_key,
                &f.verifier,
                NOW + 1
            )
            .is_err()
    );
    assert_eq!(
        Connection::open(&f.path)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM authority_bootstrap_pending_heads",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn no_self_asserted_root_can_stage_or_authorize() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let mut manifest = f.manifest.clone();
    manifest.manifest_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into();
    manifest.trust_root_hash = fw_contracts::hash_bytes(b"self declared root");
    assert!(
        f.store
            .stage_bootstrap_manifest(&f.tenant, &manifest, NOW)
            .is_err()
    );
    assert_eq!(Connection::open(&f.path).unwrap().query_row("SELECT count(*) FROM authority_registry_objects WHERE object_kind='bootstrap_manifest'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
}

#[test]
fn initial_bootstrap_cannot_ignore_an_existing_target_epoch() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    f.approve(2);
    drop(f.store);
    let db = Connection::open(&f.path).unwrap();
    db.execute(
        "INSERT INTO authority_signing_target_heads VALUES(?,?,?,?,?,NULL,?)",
        rusqlite::params![
            f.tenant.org_id(),
            f.tenant.project_id(),
            f.manifest.target_id,
            9u64.to_be_bytes().as_slice(),
            0u64.to_be_bytes().as_slice(),
            NOW
        ],
    )
    .unwrap();
    drop(db);
    f.store = AuthorityStore::open(&f.path).unwrap();
    assert!(matches!(
        f.store.authorize_retained_bootstrap(
            &f.tenant,
            &f.manifest.manifest_id,
            &f.bootstrap_pin.key_id,
            &f.bootstrap_key,
            &f.verifier,
            NOW
        ),
        Err(AuthorityError::Conflict)
    ));
    let db = Connection::open(&f.path).unwrap();
    let (epoch, generation): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT epoch,generation FROM authority_signing_target_heads",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(epoch, 9u64.to_be_bytes());
    assert_eq!(generation, 0u64.to_be_bytes());
    assert_eq!(db.query_row("SELECT count(*) FROM authority_registry_objects WHERE object_kind='bootstrap_authorization'",[],|row|row.get::<_,i64>(0)).unwrap(),0);
}

#[test]
fn signed_workload_epoch_and_revocation_survive_restart() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let mut payload = f.workload.payload.clone();
    payload.binding_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into();
    payload.binding_epoch = "2".into();
    let second = sign_workload(payload, &f.issuer_key, &f.issuer_pin.key_id);
    let status = f
        .store
        .admit_workload_binding(&f.tenant, &second, NOW)
        .unwrap();
    assert!(status.current);
    let old = f
        .store
        .admit_workload_binding(&f.tenant, &f.workload, NOW)
        .unwrap();
    assert!(!old.current);
    assert_eq!(old.state, "historical");
    f.store
        .revoke_registry_object(&f.tenant, &status.content_hash, NOW + 1)
        .unwrap();
    drop(f.store);
    let mut store = AuthorityStore::open(&f.path).unwrap();
    let status = store
        .read_registry_object(
            &f.tenant,
            "workload_binding",
            &second.payload.binding_id,
            NOW + 1,
        )
        .unwrap()
        .unwrap();
    assert!(status.revoked);
    assert!(!status.current);
}

#[test]
fn expired_signed_identity_advances_durable_time_even_when_new_admission_fails() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let mut payload = f.workload.payload.clone();
    payload.binding_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into();
    payload.binding_epoch = "2".into();
    payload.expires_at = registry_fixture::at(NOW + 10);
    let expired = sign_workload(payload, &f.issuer_key, &f.issuer_pin.key_id);
    assert!(matches!(
        f.store
            .admit_workload_binding(&f.tenant, &expired, NOW + 10),
        Err(AuthorityError::Time)
    ));
    drop(f.store);
    let mut store = AuthorityStore::open(&f.path).unwrap();
    assert!(matches!(
        store.admit_workload_binding(&f.tenant, &expired, NOW + 9),
        Err(AuthorityError::Time)
    ));
}

#[test]
fn key_revocation_blocks_current_identity_but_preserves_original_signature() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let hash = canonical_hash(&f.workload).unwrap();
    f.store
        .revoke_registry_trust_key(&f.tenant, &f.issuer_pin.key_id, NOW + 1)
        .unwrap();
    let old = f
        .store
        .admit_workload_binding(&f.tenant, &f.workload, NOW + 1)
        .unwrap();
    assert!(!old.current);
    assert_eq!(old.content_hash, hash);
    drop(f.store);
    assert!(AuthorityStore::open(&f.path).is_ok());
}

#[test]
fn immutable_registry_replace_and_clock_rewind_are_refused() {
    let directory = private_directory::private_directory();
    let f = Fixture::new(directory.path(), NOW);
    let db = Connection::open(&f.path).unwrap();
    assert!(db.execute_batch("INSERT OR REPLACE INTO authority_registry_objects SELECT * FROM authority_registry_objects LIMIT 1").is_err());
    assert!(
        db.execute(
            "UPDATE authority_registry_clocks SET observed_at=?",
            [NOW - 1]
        )
        .is_err()
    );
    assert!(
        db.execute_batch("DELETE FROM authority_registry_objects")
            .is_err()
    );
}

fn remove_guard_and_restore(db: &Connection, table: &str, sql: &str) {
    let name = format!("{table}_no_delete");
    let guard: String = db
        .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [&name], |r| {
            r.get(0)
        })
        .unwrap();
    db.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
    db.execute_batch(sql).unwrap();
    db.execute_batch(&guard).unwrap();
}

#[test]
fn second_workload_does_not_hide_missing_first_current_head() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let mut payload = f.workload.payload.clone();
    payload.binding_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into();
    payload.workload_id = "second-workload".into();
    let second = sign_workload(payload, &f.issuer_key, &f.issuer_pin.key_id);
    f.store
        .admit_workload_binding(&f.tenant, &second, NOW)
        .unwrap();
    drop(f.store);
    let db = Connection::open(&f.path).unwrap();
    remove_guard_and_restore(
        &db,
        "authority_workload_heads",
        "DELETE FROM authority_workload_heads WHERE workload_id='synthetic-workload'",
    );
    drop(db);
    assert!(AuthorityStore::open(&f.path).is_err());
}

#[test]
fn missing_pending_epoch_head_is_not_repaired_from_retained_signature() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    f.approve(2);
    f.authorize();
    drop(f.store);
    let db = Connection::open(&f.path).unwrap();
    remove_guard_and_restore(
        &db,
        "authority_bootstrap_pending_heads",
        "DELETE FROM authority_bootstrap_pending_heads",
    );
    drop(db);
    assert!(AuthorityStore::open(&f.path).is_err());
}

#[test]
fn historical_bootstrap_proof_cannot_claim_an_unreached_credential_revision() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    f.approve(2);
    drop(f.store);
    let db = Connection::open(&f.path).unwrap();
    let guard: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_bootstrap_challenge_transition'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_bootstrap_challenge_transition; UPDATE authority_bootstrap_challenges SET credential_revision=credential_revision+100").unwrap();
    db.execute_batch(&guard).unwrap();
    drop(db);
    assert!(AuthorityStore::open(&f.path).is_err());
}

#[test]
fn v14_migration_preserves_unchanged_principal_audit_and_creates_empty_registry() {
    let directory = private_directory::private_directory();
    let path = directory.path().join("legacy.sqlite3");
    let mut store = AuthorityStore::open(&path).unwrap();
    let tenant = AuthorityTenant::new(
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
    )
    .unwrap();
    store
        .provision_principal(&tenant, OWNER, "fixture", OWNER, NOW)
        .unwrap();
    drop(store);
    authority_legacy::restore_v14(&path);
    let snapshot = |path: &std::path::Path| {
        let db = Connection::open(path).unwrap();
        let row: (i64, String, String, i64) = db
            .query_row(
                "SELECT rowid,issuer,subject,created_at FROM authority_principals",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        let audit: Vec<u8> = db
            .query_row("SELECT canonical_bytes FROM authority_audit", [], |r| {
                r.get(0)
            })
            .unwrap();
        (row, audit)
    };
    let before = snapshot(&path);
    assert!(matches!(
        AuthorityStore::open(&path),
        Err(AuthorityError::MigrationRequired {
            found: 14,
            required: 15
        })
    ));
    let backup = directory.path().join("backup.sqlite3");
    AuthorityStore::migrate(&path, &backup).unwrap();
    assert_eq!(before, snapshot(&path));
    assert_eq!(before, snapshot(&backup));
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        15
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM authority_registry_objects", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let mut reopened = AuthorityStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .verify_audit_chain(&tenant)
            .unwrap()
            .unwrap()
            .event_count,
        1
    );
}
