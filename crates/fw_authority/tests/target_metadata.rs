#![cfg(feature = "approval-proofs")]
//! Real Ed25519 signatures over synthetic metadata; no native qualification.
#[path = "support/authority_legacy.rs"]
#[allow(dead_code)]
mod authority_legacy;
#[path = "support/integrity_fixture.rs"]
mod integrity_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;
use ed25519_dalek::SigningKey;
use fw_authority::{AuthorityError, AuthorityStore, AuthorityTenant, TargetTransportPin};
use fw_contracts::{canonical_bytes, hash_bytes};
use fw_target_evidence::{SignedMetadataReport, TargetMetadataChallenge, sign_report, timestamp};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};
const NOW: i64 = 1_700_000_000;
const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const TARGET: &str = "44444444-4444-4444-8444-444444444444";
const ADMIN: &str = "11111111-1111-4111-8111-111111111111";
fn report(target: &str, at: i64) -> Value {
    let features = [
        "timed_allow",
        "persistent_deny",
        "strict_current_union",
        "atomic_apply",
        "semantic_readback",
        "writer_fencing",
        "independent_watchdog",
        "new_management_probe",
        "interface_scope",
        "process_binding",
        "independent_expiry",
        "boot_guard",
        "crash_fail_closed",
        "absolute_deadline_guard",
    ];
    let features=features.iter().map(|name|(name.to_string(),json!({"state":"unverified","reason_code":"QUALIFICATION_REQUIRED","evidence_hash":null}))).collect::<serde_json::Map<_,_>>();
    json!({"schema_version":"f.target-capability/v1","target_id":target,"platform":"linux","enforcement_backend":"nftables","capability_version":"f.target-capability/v1","os_version":"synthetic Linux","backend_version":"unverified","executor_build_hash":hash_bytes(b"test binary"),"checked_at":timestamp(at).unwrap(),"valid_until":timestamp(at+300).unwrap(),"profiles":[],"families":["ipv4","ipv6"],"directions":["input","output"],"protocols":[],"binding_kinds":["host"],"features":features,"max_policies":1,"max_rules":1,"max_artifact_bytes":1,"qualification_profiles":[],"interfaces":[]})
}
struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    pin: TargetTransportPin,
    seed: [u8; 32],
}
impl Fixture {
    fn new() -> Self {
        let dir = private_directory::private_directory();
        let path = dir.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        store
            .provision_principal(
                &tenant,
                ADMIN,
                "https://identity.example.test",
                "admin",
                NOW,
            )
            .unwrap();
        let mut seed = [0; 32];
        openssl::rand::rand_bytes(&mut seed).unwrap();
        let pin = TargetTransportPin {
            target_id: TARGET.into(),
            public_key: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            certificate_fingerprint: hash_bytes(b"independently pinned test certificate"),
            platform: "linux".into(),
            not_before: NOW,
            not_after: NOW + 3600,
        };
        store
            .pin_target_transport(&tenant, &pin, None, NOW)
            .unwrap();
        Self {
            _dir: dir,
            path,
            store,
            tenant,
            pin,
            seed,
        }
    }
    fn challenge(&mut self, now: i64) -> TargetMetadataChallenge {
        self.store
            .issue_target_report_challenge(&self.tenant, TARGET, now)
            .unwrap()
    }
    fn proof(&self, challenge: &TargetMetadataChallenge, now: i64) -> SignedMetadataReport {
        sign_report(
            challenge,
            &canonical_bytes(&report(TARGET, now)).unwrap(),
            &self.seed,
            now,
        )
        .unwrap()
    }
    fn count(&self, table: &str) -> i64 {
        Connection::open(&self.path)
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    fn state_counts(&self) -> Vec<i64> {
        [
            "authority_target_challenges",
            "authority_target_metadata",
            "authority_target_metadata_heads",
            "authority_audit",
        ]
        .map(|table| self.count(table))
        .into()
    }
    fn rotate(&mut self, at: i64) -> TargetTransportPin {
        let mut seed = [0; 32];
        openssl::rand::rand_bytes(&mut seed).unwrap();
        let mut next = self.pin.clone();
        next.public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        next.certificate_fingerprint = hash_bytes(b"next independent certificate");
        next.not_before = at;
        assert_eq!(
            self.store
                .pin_target_transport(&self.tenant, &next, Some(1), at)
                .unwrap(),
            2
        );
        next
    }
}
#[test]
fn admission_is_durable_exact_replay_does_not_refresh_or_qualify() {
    let mut f = Fixture::new();
    let challenge = f.challenge(NOW + 1);
    let proof = f.proof(&challenge, NOW + 2);
    let accepted = f
        .store
        .admit_target_report(&f.tenant, &proof, NOW + 2)
        .unwrap();
    assert!(!accepted.replayed);
    assert_eq!(accepted.receipt.enforcement_status, "unverified");
    assert_eq!(accepted.receipt.assurance, "authenticated_metadata_only");
    assert_eq!(accepted.receipt.valid_until, timestamp(NOW + 301).unwrap());
    let counts = f.state_counts();
    drop(f.store);
    f.store = AuthorityStore::open(&f.path).unwrap();
    let replay = f
        .store
        .admit_target_report(&f.tenant, &proof, NOW + 3)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.receipt, accepted.receipt);
    assert_eq!(f.state_counts(), counts);
    let current = f
        .store
        .current_target_metadata(&f.tenant, TARGET, NOW + 3)
        .unwrap()
        .unwrap();
    assert_eq!(current.receipt, accepted.receipt);
    assert_eq!(current.report, report(TARGET, NOW + 2));
    assert_eq!(current.enforcement_status, "unverified");
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 301)
            .unwrap()
            .is_none()
    );
    let historical = f
        .store
        .admit_target_report(&f.tenant, &proof, NOW + 500)
        .unwrap();
    assert!(historical.replayed);
    assert_eq!(historical.receipt.valid_until, accepted.receipt.valid_until);
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 500)
            .unwrap()
            .is_none()
    );
}
#[test]
fn signature_binding_and_changed_retry_are_refused_without_consumption() {
    let mut f = Fixture::new();
    let challenge = f.challenge(NOW + 1);
    let proof = f.proof(&challenge, NOW + 2);
    let before = f.state_counts();
    let mut forged = proof.clone();
    forged.signature.replace_range(
        0..1,
        if &forged.signature[..1] == "A" {
            "B"
        } else {
            "A"
        },
    );
    assert!(
        f.store
            .admit_target_report(&f.tenant, &forged, NOW + 2)
            .is_err()
    );
    assert_eq!(f.state_counts(), before);
    let mut cross = proof.clone();
    cross.challenge.project_id = "55555555-5555-4555-8555-555555555555".into();
    assert!(
        f.store
            .admit_target_report(&f.tenant, &cross, NOW + 2)
            .is_err()
    );
    assert_eq!(f.state_counts(), before);
    let mut substituted = proof.clone();
    substituted.challenge.nonce = challenge.nonce.chars().rev().collect();
    assert!(
        f.store
            .admit_target_report(&f.tenant, &substituted, NOW + 2)
            .is_err()
    );
    assert_eq!(f.state_counts(), before);
    f.store
        .admit_target_report(&f.tenant, &proof, NOW + 2)
        .unwrap();
    let mut changed = report(TARGET, NOW + 2);
    changed["os_version"] = "different measured bytes".into();
    let changed = sign_report(
        &challenge,
        &canonical_bytes(&changed).unwrap(),
        &f.seed,
        NOW + 2,
    )
    .unwrap();
    assert!(matches!(
        f.store.admit_target_report(&f.tenant, &changed, NOW + 2),
        Err(AuthorityError::Conflict)
    ));
    assert_eq!(f.count("authority_target_metadata"), 1);
}
#[test]
fn challenge_capacity_is_four_and_expiry_is_exclusive_without_deleting_history() {
    let mut f = Fixture::new();
    let first = f.challenge(NOW);
    for _ in 0..3 {
        f.challenge(NOW);
    }
    assert!(matches!(
        f.store
            .issue_target_report_challenge(&f.tenant, TARGET, NOW),
        Err(AuthorityError::Quota)
    ));
    let proof = f.proof(&first, NOW + 1);
    f.store
        .admit_target_report(&f.tenant, &proof, NOW + 1)
        .unwrap();
    f.challenge(NOW + 1);
    assert!(matches!(
        f.store
            .issue_target_report_challenge(&f.tenant, TARGET, NOW + 1),
        Err(AuthorityError::Quota)
    ));
    f.challenge(NOW + 300);
    assert_eq!(f.count("authority_target_challenges"), 6);
    assert!(matches!(
        f.store
            .issue_target_report_challenge(&f.tenant, TARGET, NOW + 1),
        Err(AuthorityError::Time)
    ));
}
#[test]
fn altered_audit_schema_refuses_report_without_row_changes_then_allows_exact_retry() {
    let mut f = Fixture::new();
    let challenge = f.challenge(NOW + 1);
    let proof = f.proof(&challenge, NOW + 2);
    let before = integrity_fixture::rows(&f.path);
    let db = Connection::open(&f.path).unwrap();
    db.execute_batch("CREATE TRIGGER injected_metadata_audit BEFORE INSERT ON authority_audit WHEN NEW.kind='target_metadata_admitted' BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    // The unknown trigger is refused at entry, before clock or report writes.
    assert!(matches!(
        f.store.admit_target_report(&f.tenant, &proof, NOW + 2),
        Err(AuthorityError::Invalid(_))
    ));
    assert_eq!(integrity_fixture::rows(&f.path), before);
    db.execute_batch("DROP TRIGGER injected_metadata_audit;")
        .unwrap();
    let retry = f
        .store
        .admit_target_report(&f.tenant, &proof, NOW + 2)
        .unwrap();
    assert!(!retry.replayed);
    assert_eq!(f.count("authority_target_metadata"), 1);
}
#[test]
fn concurrent_consumption_has_one_new_admission_and_one_historical_receipt() {
    let mut f = Fixture::new();
    let challenge = f.challenge(NOW + 1);
    let proof = f.proof(&challenge, NOW + 2);
    let barrier = Arc::new(Barrier::new(2));
    let tasks = (0..2)
        .map(|_| {
            let (path, tenant, proof, barrier) = (
                f.path.clone(),
                f.tenant.clone(),
                proof.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                barrier.wait();
                store.admit_target_report(&tenant, &proof, NOW + 2).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let mut outcomes = tasks
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    outcomes.sort_by_key(|r| r.replayed);
    assert!(!outcomes[0].replayed);
    assert!(outcomes[1].replayed);
    assert_eq!(outcomes[0].receipt, outcomes[1].receipt);
    assert_eq!(f.count("authority_target_metadata"), 1);
}
#[test]
fn revoked_rotated_or_rebound_keys_cannot_restore_current_metadata() {
    let mut f = Fixture::new();
    let challenge = f.challenge(NOW + 1);
    let proof = f.proof(&challenge, NOW + 2);
    f.store
        .admit_target_report(&f.tenant, &proof, NOW + 2)
        .unwrap();
    let old = f.pin.clone();
    let next = f.rotate(NOW + 3);
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 3)
            .unwrap()
            .is_none()
    );
    assert!(
        f.store
            .admit_target_report(&f.tenant, &proof, NOW + 3)
            .unwrap()
            .replayed
    );
    assert!(
        f.store
            .pin_target_transport(&f.tenant, &old, Some(2), NOW + 3)
            .is_err()
    );
    let mut moved = old.clone();
    moved.target_id = "55555555-5555-4555-8555-555555555555".into();
    moved.certificate_fingerprint = hash_bytes(b"moved cert");
    assert!(
        f.store
            .pin_target_transport(&f.tenant, &moved, None, NOW + 3)
            .is_err()
    );
    let other = AuthorityTenant::new(ORG, "66666666-6666-4666-8666-666666666666").unwrap();
    f.store
        .provision_principal(
            &other,
            ADMIN,
            "https://identity.example.test",
            "admin",
            NOW + 3,
        )
        .unwrap();
    assert!(
        f.store
            .pin_target_transport(&other, &next, None, NOW + 3)
            .is_err()
    );
    f.store
        .revoke_target_transport(&f.tenant, TARGET, 2, NOW + 4)
        .unwrap();
    assert!(
        f.store
            .issue_target_report_challenge(&f.tenant, TARGET, NOW + 4)
            .is_err()
    );
    assert!(
        f.store
            .pin_target_transport(&f.tenant, &next, Some(2), NOW + 4)
            .is_err()
    );
}
#[test]
fn pin_renewal_cas_invalidates_old_challenges_and_preserves_original_retries() {
    let mut f = Fixture::new();
    assert_eq!(
        f.store
            .pin_target_transport(&f.tenant, &f.pin, None, NOW)
            .unwrap(),
        1
    );
    let challenge = f.challenge(NOW + 1);
    let proof = f.proof(&challenge, NOW + 2);
    let mut renewal = f.pin.clone();
    renewal.certificate_fingerprint = hash_bytes(b"renewed certificate");
    renewal.not_before = NOW + 2;
    renewal.not_after = NOW + 7200;
    assert!(
        f.store
            .pin_target_transport(&f.tenant, &renewal, Some(9), NOW + 2)
            .is_err()
    );
    assert_eq!(
        f.store
            .pin_target_transport(&f.tenant, &renewal, Some(1), NOW + 2)
            .unwrap(),
        2
    );
    assert_eq!(
        f.store
            .pin_target_transport(&f.tenant, &renewal, Some(1), NOW + 3)
            .unwrap(),
        2
    );
    assert!(
        f.store
            .admit_target_report(&f.tenant, &proof, NOW + 3)
            .is_err()
    );
    assert_eq!(f.count("authority_target_metadata"), 0);
}
#[test]
fn revocation_racing_admission_never_leaves_current_metadata() {
    let mut f = Fixture::new();
    let challenge = f.challenge(NOW + 1);
    let proof = f.proof(&challenge, NOW + 2);
    let barrier = Arc::new(Barrier::new(2));
    let (path, tenant, b) = (f.path.clone(), f.tenant.clone(), barrier.clone());
    let admission = std::thread::spawn(move || {
        let mut s = AuthorityStore::open(path).unwrap();
        b.wait();
        s.admit_target_report(&tenant, &proof, NOW + 2)
    });
    let (path, tenant, b) = (f.path.clone(), f.tenant.clone(), barrier.clone());
    let revoke = std::thread::spawn(move || {
        let mut s = AuthorityStore::open(path).unwrap();
        b.wait();
        s.revoke_target_transport(&tenant, TARGET, 1, NOW + 2)
            .unwrap()
    });
    let _ = admission.join().unwrap();
    revoke.join().unwrap();
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 2)
            .unwrap()
            .is_none()
    );
}
#[test]
fn expired_read_or_refused_admission_retains_clock_floor_across_restart() {
    for action in ["read", "admit", "pin"] {
        let mut f = Fixture::new();
        let challenge = f.challenge(NOW + 1);
        let proof = f.proof(&challenge, NOW + 2);
        f.store
            .admit_target_report(&f.tenant, &proof, NOW + 2)
            .unwrap();
        match action {
            "read" => assert!(
                f.store
                    .current_target_metadata(&f.tenant, TARGET, NOW + 400)
                    .unwrap()
                    .is_none()
            ),
            "admit" => {
                let next = f.challenge(NOW + 3);
                let next = f.proof(&next, NOW + 4);
                assert!(
                    f.store
                        .admit_target_report(&f.tenant, &next, NOW + 400)
                        .is_err()
                );
            }
            "pin" => assert!(
                f.store
                    .pin_target_transport(&f.tenant, &f.pin, Some(1), NOW + 4000)
                    .is_err()
            ),
            _ => unreachable!(),
        }
        drop(f.store);
        f.store = AuthorityStore::open(&f.path).unwrap();
        assert!(
            matches!(
                f.store.current_target_metadata(&f.tenant, TARGET, NOW + 10),
                Err(AuthorityError::Time)
            ),
            "{action}"
        );
        assert!(
            matches!(
                f.store
                    .issue_target_report_challenge(&f.tenant, TARGET, NOW + 10),
                Err(AuthorityError::Time)
            ),
            "{action}"
        );
    }
}
#[test]
fn partial_head_and_projection_corruption_is_refused() {
    for corruption in ["report_head", "pin_head", "admitted", "proof", "clock"] {
        let mut f = Fixture::new();
        let c1 = f.challenge(NOW + 1);
        let p1 = f.proof(&c1, NOW + 2);
        let first = f
            .store
            .admit_target_report(&f.tenant, &p1, NOW + 2)
            .unwrap();
        let c2 = f.challenge(NOW + 3);
        let p2 = f.proof(&c2, NOW + 4);
        f.store
            .admit_target_report(&f.tenant, &p2, NOW + 4)
            .unwrap();
        if corruption == "pin_head" {
            let mut renewal = f.pin.clone();
            renewal.certificate_fingerprint = hash_bytes(b"renewal");
            f.store
                .pin_target_transport(&f.tenant, &renewal, Some(1), NOW + 5)
                .unwrap();
        }
        if corruption != "clock" {
            // Later semantic refusal must still preserve the observed floor.
            f.store
                .current_target_metadata(&f.tenant, TARGET, NOW + 6)
                .unwrap();
        }
        let db = Connection::open(&f.path).unwrap();
        match corruption {
            "report_head" => {
                db.execute(
                    "UPDATE authority_target_metadata_heads SET receipt_id=?",
                    [first.receipt.receipt_id],
                )
                .unwrap();
            }
            "pin_head" => {
                db.execute(
                    "UPDATE authority_target_pin_heads SET revision=?",
                    [1u64.to_be_bytes().as_slice()],
                )
                .unwrap();
            }
            "admitted" => {
                let guard =
                    integrity_fixture::trigger_sql(&db, "authority_target_metadata_no_update");
                db.execute_batch("DROP TRIGGER authority_target_metadata_no_update; UPDATE authority_target_metadata SET admitted_at=admitted_at+1;").unwrap();
                db.execute_batch(&guard).unwrap();
            }
            "proof" => {
                let guard =
                    integrity_fixture::trigger_sql(&db, "authority_target_metadata_no_update");
                db.execute_batch("DROP TRIGGER authority_target_metadata_no_update; UPDATE authority_target_metadata SET proof_bytes=x'7b7d';").unwrap();
                db.execute_batch(&guard).unwrap();
            }
            "clock" => {
                db.execute("UPDATE authority_target_clocks SET observed_at=?", [NOW])
                    .unwrap();
                let mut expected = integrity_fixture::rows(&f.path);
                let (_, clocks) = expected
                    .iter_mut()
                    .find(|(table, _)| table == "authority_target_clocks")
                    .unwrap();
                assert_eq!(clocks.len(), 1);
                assert_eq!(clocks[0].len(), 4);
                assert_eq!(clocks[0][3], rusqlite::types::Value::Integer(NOW));
                // Even a later semantic refusal retains the separately committed
                // observation time; every other stored value must stay intact.
                clocks[0][3] = rusqlite::types::Value::Integer(NOW + 1);
                assert!(
                    f.store
                        .current_target_metadata(&f.tenant, TARGET, NOW + 1)
                        .is_err()
                );
                assert_eq!(integrity_fixture::rows(&f.path), expected);
                continue;
            }
            _ => unreachable!(),
        }
        let damaged = integrity_fixture::rows(&f.path);
        assert!(
            f.store
                .current_target_metadata(&f.tenant, TARGET, NOW + 6)
                .is_err(),
            "{corruption}"
        );
        assert_eq!(integrity_fixture::rows(&f.path), damaged);
    }
}
#[test]
fn older_or_same_time_conflicting_report_does_not_replace_current_head() {
    let mut f = Fixture::new();
    let old = f.challenge(NOW);
    let newer = f.challenge(NOW);
    let p_new = f.proof(&newer, NOW + 2);
    let p_old = f.proof(&old, NOW + 1);
    let current = f
        .store
        .admit_target_report(&f.tenant, &p_new, NOW + 2)
        .unwrap();
    assert!(matches!(
        f.store.admit_target_report(&f.tenant, &p_old, NOW + 3),
        Err(AuthorityError::Conflict)
    ));
    let mut changed = report(TARGET, NOW + 2);
    changed["os_version"] = "conflicting report".into();
    let conflict =
        sign_report(&old, &canonical_bytes(&changed).unwrap(), &f.seed, NOW + 2).unwrap();
    assert!(matches!(
        f.store.admit_target_report(&f.tenant, &conflict, NOW + 3),
        Err(AuthorityError::Conflict)
    ));
    assert_eq!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 3)
            .unwrap()
            .unwrap()
            .receipt,
        current.receipt
    );
    let original = f.proof(&old, NOW + 4);
    assert!(
        !f.store
            .admit_target_report(&f.tenant, &original, NOW + 4)
            .unwrap()
            .replayed
    );
}
#[test]
fn v4_migration_requires_private_backup_and_invents_no_target_trust() {
    let f = Fixture::new();
    drop(f.store);
    authority_legacy::restore_v4(&f.path);
    let db = Connection::open(&f.path).unwrap();
    let audit: i64 = db
        .query_row("SELECT count(*) FROM authority_audit", [], |r| r.get(0))
        .unwrap();
    drop(db);
    assert!(matches!(
        AuthorityStore::open(&f.path),
        Err(AuthorityError::MigrationRequired {
            found: 4,
            required: 14
        })
    ));
    let backup = f.path.with_file_name("v4-backup.sqlite3");
    AuthorityStore::migrate(&f.path, &backup).unwrap();
    let b = Connection::open(backup).unwrap();
    assert_eq!(
        b.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        4
    );
    let db = Connection::open(&f.path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        14
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM authority_audit", [], |r| r.get(0))
            .unwrap(),
        audit
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM authority_target_pins", [], |r| r
            .get(0))
            .unwrap(),
        0
    );
    let mut s = AuthorityStore::open(&f.path).unwrap();
    assert!(
        s.current_target_metadata(&f.tenant, TARGET, NOW + 1)
            .unwrap()
            .is_none()
    );
    assert!(
        s.issue_target_report_challenge(&f.tenant, TARGET, NOW + 1)
            .is_err()
    );
}
#[test]
fn altered_audit_schema_refuses_pin_without_partial_trust_then_allows_exact_retry() {
    let mut f = Fixture::new();
    let mut next = f.pin.clone();
    next.target_id = "55555555-5555-4555-8555-555555555555".into();
    let mut seed = [0; 32];
    openssl::rand::rand_bytes(&mut seed).unwrap();
    next.public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    next.certificate_fingerprint = hash_bytes(b"second target cert");
    let db = Connection::open(&f.path).unwrap();
    db.execute_batch("CREATE TRIGGER injected_pin_audit BEFORE INSERT ON authority_audit WHEN NEW.kind='target_transport_pinned' BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    let before = integrity_fixture::rows(&f.path);
    assert!(matches!(
        f.store
            .pin_target_transport(&f.tenant, &next, None, NOW + 1),
        Err(AuthorityError::Invalid(_))
    ));
    assert_eq!(f.count("authority_target_pins"), 1);
    assert_eq!(f.count("authority_target_keys"), 1);
    assert_eq!(f.count("authority_target_clocks"), 1);
    assert_eq!(integrity_fixture::rows(&f.path), before);
    db.execute_batch("DROP TRIGGER injected_pin_audit;")
        .unwrap();
    assert_eq!(
        f.store
            .pin_target_transport(&f.tenant, &next, None, NOW + 1)
            .unwrap(),
        1
    );
}
#[test]
fn metadata_head_cannot_be_transplanted_between_targets() {
    let mut f = Fixture::new();
    let mut next = f.pin.clone();
    next.target_id = "55555555-5555-4555-8555-555555555555".into();
    let mut seed = [0; 32];
    openssl::rand::rand_bytes(&mut seed).unwrap();
    next.public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    next.certificate_fingerprint = hash_bytes(b"other cert");
    f.store
        .pin_target_transport(&f.tenant, &next, None, NOW)
        .unwrap();
    let c = f.challenge(NOW + 1);
    let p = f.proof(&c, NOW + 2);
    let receipt = f
        .store
        .admit_target_report(&f.tenant, &p, NOW + 2)
        .unwrap()
        .receipt;
    Connection::open(&f.path)
        .unwrap()
        .execute(
            "INSERT INTO authority_target_metadata_heads VALUES(?,?,?,?)",
            params![ORG, PROJECT, next.target_id, receipt.receipt_id],
        )
        .unwrap();
    assert!(
        f.store
            .current_target_metadata(&f.tenant, &next.target_id, NOW + 2)
            .is_err()
    );
}

#[test]
fn old_signed_report_cannot_be_rebound_to_same_key_certificate_renewal() {
    let mut f = Fixture::new();
    let challenge = f.challenge(NOW + 1);
    let proof = f.proof(&challenge, NOW + 2);
    let mut receipt = f
        .store
        .admit_target_report(&f.tenant, &proof, NOW + 2)
        .unwrap()
        .receipt;
    let mut renewal = f.pin.clone();
    renewal.certificate_fingerprint = hash_bytes(b"same key renewed cert");
    f.store
        .pin_target_transport(&f.tenant, &renewal, Some(1), NOW + 2)
        .unwrap();
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 2)
            .unwrap()
            .is_none()
    );
    // Simulate a partial database projection rewrite. Keep the exact original
    // signature and challenge, but rewrite both the row and canonical receipt
    // to the new pin. Equal timestamps deliberately avoid a time-only defense.
    receipt.key_revision = "2".into();
    receipt.certificate_fingerprint = renewal.certificate_fingerprint;
    let db = Connection::open(&f.path).unwrap();
    let guard = integrity_fixture::trigger_sql(&db, "authority_target_metadata_no_update");
    db.execute_batch("DROP TRIGGER authority_target_metadata_no_update")
        .unwrap();
    db.execute(
        "UPDATE authority_target_metadata SET pin_revision=?,receipt_bytes=? WHERE receipt_id=?",
        params![
            2u64.to_be_bytes().as_slice(),
            canonical_bytes(&receipt).unwrap(),
            receipt.receipt_id
        ],
    )
    .unwrap();
    db.execute_batch(&guard).unwrap();
    let damaged = integrity_fixture::rows(&f.path);
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 2)
            .is_err()
    );
    assert!(
        f.store
            .admit_target_report(&f.tenant, &proof, NOW + 2)
            .is_err()
    );
    assert_eq!(integrity_fixture::rows(&f.path), damaged);
}

#[test]
fn metadata_namespace_initialization_creates_no_human_or_signing_authority() {
    let dir = private_directory::private_directory();
    let path = dir.path().join("metadata.sqlite3");
    let mut store = AuthorityStore::open(&path).unwrap();
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    store
        .provision_target_metadata_project(&tenant, NOW)
        .unwrap();
    store
        .provision_target_metadata_project(&tenant, NOW + 1)
        .unwrap();
    let db = Connection::open(&path).unwrap();
    for table in [
        "authority_principals",
        "authority_credentials",
        "authority_roles",
        "authority_basis_pins",
        "authority_human_bindings",
        "authority_target_pins",
    ] {
        assert_eq!(
            db.query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap(),
            0,
            "{table}"
        );
    }
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM authority_audit", [], |r| r.get(0))
            .unwrap(),
        1
    );
    let pin = TargetTransportPin {
        target_id: TARGET.into(),
        public_key: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
        certificate_fingerprint: hash_bytes(b"test cert"),
        platform: "linux".into(),
        not_before: NOW,
        not_after: NOW + 300,
    };
    store
        .pin_target_transport(&tenant, &pin, None, NOW + 1)
        .unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM authority_principals", [], |r| r
            .get(0))
            .unwrap(),
        0
    );
}
#[test]
fn challenge_and_current_metadata_are_clipped_to_pinned_certificate_validity() {
    let mut f = Fixture::new();
    let mut pin = f.pin.clone();
    pin.certificate_fingerprint = hash_bytes(b"near expiry certificate");
    pin.not_after = NOW + 5;
    f.store
        .pin_target_transport(&f.tenant, &pin, Some(1), NOW + 1)
        .unwrap();
    let challenge = f.challenge(NOW + 2);
    assert_eq!(challenge.expires_at, timestamp(NOW + 5).unwrap());
    let proof = f.proof(&challenge, NOW + 3);
    let result = f
        .store
        .admit_target_report(&f.tenant, &proof, NOW + 3)
        .unwrap();
    assert_eq!(result.receipt.valid_until, timestamp(NOW + 5).unwrap());
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 4)
            .unwrap()
            .is_some()
    );
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, NOW + 5)
            .unwrap()
            .is_none()
    );
    assert!(
        f.store
            .issue_target_report_challenge(&f.tenant, TARGET, NOW + 5)
            .is_err()
    );
}
#[test]
fn v4_migration_foreign_key_failure_preserves_source_version_and_backup() {
    let f = Fixture::new();
    drop(f.store);
    authority_legacy::restore_v4(&f.path);
    let db = Connection::open(&f.path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    db.execute(
        "INSERT INTO authority_principals VALUES(?,?,?,'https://fixture.example','orphan',?)",
        params![PROJECT, ORG, ADMIN, NOW],
    )
    .unwrap();
    drop(db);
    let backup = f.path.with_file_name("invalid-v4-backup.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    for path in [&f.path, &backup] {
        let db = Connection::open(path).unwrap();
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            4
        );
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT count(*) FROM sqlite_schema WHERE name='authority_target_pins'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            db.query_row::<i64, _, _>("SELECT count(*) FROM authority_principals", [], |r| r
                .get(0))
                .unwrap(),
            2
        );
    }
}

#[test]
fn accidental_future_read_survives_reopen_and_allows_recovery_only_at_the_clock_floor() {
    let mut f = Fixture::new();
    let accepted_challenge = f.challenge(NOW + 1);
    let accepted_proof = f.proof(&accepted_challenge, NOW + 2);
    let accepted = f
        .store
        .admit_target_report(&f.tenant, &accepted_proof, NOW + 2)
        .unwrap();
    let pending_challenge = f.challenge(NOW + 3);
    let pending_proof = f.proof(&pending_challenge, NOW + 4);
    let future = NOW + 1800;
    let before = f.state_counts();
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, future)
            .unwrap()
            .is_none()
    );
    // The mistaken future read records only a security clock observation. It
    // neither deletes the old proof nor rewrites its expiry or audit history.
    assert_eq!(f.state_counts(), before);
    drop(f.store);
    f.store = AuthorityStore::open(&f.path).unwrap();
    let clock_path = f.path.clone();
    let observed = || {
        Connection::open(&clock_path)
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT observed_at FROM authority_target_clocks WHERE org_id=? AND project_id=? AND target_id=?",
                params![ORG, PROJECT, TARGET],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(observed(), future);
    for earlier in [NOW + 5, future - 1] {
        assert!(matches!(
            f.store
                .pin_target_transport(&f.tenant, &f.pin, Some(1), earlier),
            Err(AuthorityError::Time)
        ));
        assert!(matches!(
            f.store
                .issue_target_report_challenge(&f.tenant, TARGET, earlier),
            Err(AuthorityError::Time)
        ));
        for proof in [&accepted_proof, &pending_proof] {
            assert!(matches!(
                f.store.admit_target_report(&f.tenant, proof, earlier),
                Err(AuthorityError::Time)
            ));
        }
        assert!(matches!(
            f.store.current_target_metadata(&f.tenant, TARGET, earlier),
            Err(AuthorityError::Time)
        ));
        assert!(matches!(
            f.store
                .revoke_target_transport(&f.tenant, TARGET, 1, earlier),
            Err(AuthorityError::Time)
        ));
        assert_eq!(observed(), future);
        assert_eq!(f.state_counts(), before);
        assert_eq!(f.count("authority_target_pins"), 1);
        assert_eq!(f.count("authority_target_key_revocations"), 0);
    }

    // Legitimate time reaching the existing floor restores operations, not old
    // current authority. This test never changes the OS clock or lowers a row.
    assert_eq!(
        f.store
            .pin_target_transport(&f.tenant, &f.pin, Some(1), future)
            .unwrap(),
        1
    );
    let replay = f
        .store
        .admit_target_report(&f.tenant, &accepted_proof, future)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.receipt, accepted.receipt);
    assert!(
        f.store
            .admit_target_report(&f.tenant, &pending_proof, future)
            .is_err()
    );
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, future)
            .unwrap()
            .is_none()
    );
    let fresh_challenge = f.challenge(future);
    let fresh_proof = f.proof(&fresh_challenge, future);
    let fresh = f
        .store
        .admit_target_report(&f.tenant, &fresh_proof, future)
        .unwrap();
    assert!(!fresh.replayed);
    assert_ne!(fresh.receipt.receipt_id, accepted.receipt.receipt_id);
    drop(f.store);
    f.store = AuthorityStore::open(&f.path).unwrap();
    assert_eq!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, future)
            .unwrap()
            .unwrap()
            .receipt,
        fresh.receipt
    );
    f.store
        .revoke_target_transport(&f.tenant, TARGET, 1, future)
        .unwrap();
    assert!(
        f.store
            .current_target_metadata(&f.tenant, TARGET, future)
            .unwrap()
            .is_none()
    );
    assert_eq!(observed(), future);
}

#[test]
fn successful_future_challenge_also_fences_later_audited_writes_in_the_same_project() {
    let mut f = Fixture::new();
    let mut second = f.pin.clone();
    second.target_id = "55555555-5555-4555-8555-555555555555".into();
    let mut seed = [0u8; 32];
    openssl::rand::rand_bytes(&mut seed).unwrap();
    second.public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    second.certificate_fingerprint = hash_bytes(b"separate target certificate");
    f.store
        .pin_target_transport(&f.tenant, &second, None, NOW + 1)
        .unwrap();
    let future = NOW + 1800;
    f.store
        .issue_target_report_challenge(&f.tenant, TARGET, future)
        .unwrap();
    drop(f.store);
    f.store = AuthorityStore::open(&f.path).unwrap();
    let before = f.state_counts();
    // The second target's own clock has not moved to `future`, so a read is
    // possible. Its challenge mutation cannot append behind the project audit
    // head written by the first target's successful future operation.
    assert!(
        f.store
            .current_target_metadata(&f.tenant, &second.target_id, NOW + 2)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        f.store
            .issue_target_report_challenge(&f.tenant, &second.target_id, NOW + 2),
        Err(AuthorityError::Time)
    ));
    assert_eq!(f.state_counts(), before);
    assert!(
        f.store
            .issue_target_report_challenge(&f.tenant, &second.target_id, future)
            .is_ok()
    );
}
