#![cfg(feature = "approval-proofs")]
#[path = "support/authority_legacy.rs"]
#[allow(dead_code)]
mod authority_legacy;
#[path = "support/native_fixture.rs"]
mod native_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;
use fw_authority::{AuthorityError, AuthorityStore, SigningRequest};
use fw_contracts::{canonical_hash, hash_bytes};
use fw_webauthn::WebAuthn;
use rusqlite::Connection;
const NOW: i64 = 1_800_000_000;
#[test]
fn public_preparation_never_promotes_lab_evidence_or_caller_hashes_to_signing() {
    let dir = private_directory::private_directory();
    let path = dir.path().join("authority.sqlite3");
    let mut store = AuthorityStore::open(&path).unwrap();
    let (tenant, plan, _, _, _) = native_fixture::setup(&mut store, NOW);
    let verifier = WebAuthn::new("http://localhost:8787").unwrap();
    let request = SigningRequest {
        request_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        plan_id: native_fixture::PLAN.into(),
        expected_plan_hash: canonical_hash(&plan).unwrap(),
        expected_approval_set_hash: hash_bytes(b"caller hash is not authority"),
    };
    for now in [NOW, NOW + 1] {
        assert!(
            store
                .prepare_signing_intent(&tenant, &verifier, &request, now)
                .is_err()
        );
    }
    drop(store);
    let mut store = AuthorityStore::open(&path).unwrap();
    let status = store
        .signing_readiness(&tenant, native_fixture::PLAN, &verifier, NOW + 1)
        .unwrap();
    assert!(!status.signing_allowed);
    assert!(!status.dispatch_allowed);
    assert!(status.target_generation.is_none());
    assert!(status.latest_intent.is_none());
    for reason in [
        "PROTECTED_BOOTSTRAP_REQUIRED",
        "BUILD_IDENTITY_REQUIRED",
        "NATIVE_QUALIFICATION_REQUIRED",
        "PROTECTED_SIGNER_UNAVAILABLE",
    ] {
        assert!(status.reasons.iter().any(|r| r == reason));
    }
    let db = Connection::open(path).unwrap();
    for table in [
        "authority_signing_intents",
        "authority_signing_jobs",
        "authority_signing_target_heads",
        "authority_signing_quota_reservations",
        "authority_signing_quota_usage",
        "authority_signing_outbox",
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let mut injected = serde_json::to_value(request).unwrap();
    injected["production_qualified"] = true.into();
    assert!(serde_json::from_value::<SigningRequest>(injected).is_err());
}
#[test]
fn schema_six_requires_private_explicit_backup_and_creates_no_signing_trust() {
    let dir = private_directory::private_directory();
    let path = dir.path().join("authority.sqlite3");
    let mut store = AuthorityStore::open(&path).unwrap();
    let (tenant, _, _, _, _) = native_fixture::setup(&mut store, NOW);
    let receipt = store
        .current_target_metadata(&tenant, native_fixture::TARGET, NOW)
        .unwrap()
        .unwrap()
        .receipt;
    drop(store);
    authority_legacy::restore_v6(&path);
    assert!(matches!(
        AuthorityStore::open(&path),
        Err(AuthorityError::MigrationRequired {
            found: 6,
            required: 16
        })
    ));
    let backup = dir.path().join("before-v7.sqlite3");
    AuthorityStore::migrate(&path, &backup).unwrap();
    let mut store = AuthorityStore::open(&path).unwrap();
    assert_eq!(
        store
            .current_target_metadata(&tenant, native_fixture::TARGET, NOW)
            .unwrap()
            .unwrap()
            .receipt,
        receipt
    );
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        16
    );
    let before = Connection::open(backup).unwrap();
    assert_eq!(
        before
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    for table in [
        "authority_signing_quota_pins",
        "authority_signing_quota_transitions",
        "authority_signing_target_heads",
        "authority_signing_intents",
        "authority_signing_jobs",
        "authority_signing_outbox",
    ] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
