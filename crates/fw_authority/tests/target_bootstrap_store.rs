#![cfg(feature = "approval-proofs")]
#[allow(dead_code)]
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/registry_fixture.rs"]
mod registry_fixture;
#[path = "support/target_bootstrap_fixture.rs"]
mod target_fixture;
use ed25519_dalek::SigningKey;
use fw_authority::*;
use fw_contracts::{canonical_bytes, hash_bytes};
use registry_fixture::{Fixture, NOW, at};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use target_fixture::TargetFixture;

fn setup() -> (tempfile::TempDir, Fixture, TargetFixture) {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let target = TargetFixture::new(&mut f);
    f.store
        .pin_target_bootstrap_key(&f.tenant, &target.pin, None, NOW)
        .unwrap();
    f.approve(2);
    f.authorize();
    (directory, f, target)
}
fn challenge(
    f: &mut Fixture,
    target: &TargetFixture,
    expected: Option<u64>,
) -> TargetBootstrapBundle {
    f.store
        .issue_target_bootstrap_challenge(
            &f.tenant,
            &f.manifest.manifest_id,
            expected,
            &target.baseline,
            &target.capability,
            f.now,
        )
        .unwrap()
}
fn admit(
    f: &mut Fixture,
    receipt: &SignedTargetBootstrapConfirmation,
    now: i64,
) -> TargetBootstrapStatus {
    f.store
        .admit_target_bootstrap_confirmation(&f.tenant, receipt, now)
        .unwrap()
}
fn count(path: &std::path::Path, table: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
type RetainedRows = Vec<(String, Vec<Vec<rusqlite::types::Value>>)>;
fn retained_rows(path: &std::path::Path) -> RetainedRows {
    let connection = Connection::open(path).unwrap();
    let names: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,10)='authority_' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut statement = connection
                .prepare(&format!("SELECT rowid,* FROM {name} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}
fn tamper(path: &std::path::Path, table: &str, sql: &str) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA recursive_triggers=OFF;")
        .unwrap();
    let triggers: Vec<(String, String)> = connection
        .prepare(
            "SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND tbl_name=? ORDER BY name",
        )
        .unwrap()
        .query_map([table], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for (name, _) in &triggers {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{name}\";"))
            .unwrap();
    }
    connection.execute_batch(sql).unwrap();
    for (_, sql) in triggers {
        connection.execute_batch(&sql).unwrap();
    }
}

#[test]
fn real_owner_and_independent_signatures_retain_epoch_without_opening_policy_authority() {
    let (_directory, mut f, target) = setup();
    let bundle = challenge(&mut f, &target, None);
    bundle.validate(&f.bootstrap_pin, NOW).unwrap();
    let again = challenge(&mut f, &target, None);
    assert_eq!(
        bundle.canonical_bytes().unwrap(),
        again.canonical_bytes().unwrap()
    );
    let receipt = target.receipt(bundle.challenge, NOW);
    let status = admit(&mut f, &receipt, NOW + 1);
    assert_eq!(status.accepted_epoch, "1");
    assert_eq!(status.highest_generation, "0");
    assert!(status.current_confirmation_eligibility);
    assert!(!status.replayed && !status.signing_allowed && !status.dispatch_allowed);
    let repeated = admit(&mut f, &receipt, NOW + 1);
    assert!(repeated.replayed);
    assert_eq!(status.confirmation_hash, repeated.confirmation_hash);
    let historical = admit(&mut f, &receipt, NOW + 301);
    assert!(historical.replayed && !historical.current_confirmation_eligibility);
    assert_eq!(historical.accepted_epoch, "1");
    assert_eq!(
        count(&f.path, "authority_target_bootstrap_confirmations"),
        1
    );
    assert_eq!(count(&f.path, "authority_signing_target_heads"), 0);
    let raw: Vec<u8> = Connection::open(&f.path)
        .unwrap()
        .query_row(
            "SELECT canonical_bytes FROM authority_target_bootstrap_confirmations",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(raw, receipt.canonical_bytes().unwrap());
    drop(f.store);
    let mut reopened = AuthorityStore::open(&f.path).unwrap();
    let status = reopened
        .read_target_bootstrap_status(&f.tenant, &target.pin.target_id, NOW + 302)
        .unwrap()
        .unwrap();
    assert_eq!(status.confirmation_hash, historical.confirmation_hash);
    assert_eq!(status.accepted_epoch, "1");
    assert!(!status.current_confirmation_eligibility);
}

#[test]
fn rotation_requires_the_actual_confirmed_predecessor_and_preserves_exact_old_receipt() {
    let (_directory, mut f, target) = setup();
    let first = target.receipt(challenge(&mut f, &target, None).challenge, NOW);
    let first_status = admit(&mut f, &first, NOW + 1);
    f.now = NOW + 2;
    target.stage(&mut f, Some(1), 2);
    f.approve(3);
    f.authorize();
    assert!(
        f.store
            .issue_target_bootstrap_challenge(
                &f.tenant,
                &f.manifest.manifest_id,
                None,
                &target.baseline,
                &target.capability,
                f.now
            )
            .is_err()
    );
    let second_bundle = challenge(&mut f, &target, Some(1));
    assert_eq!(
        second_bundle
            .challenge
            .previous_confirmation_hash
            .as_deref(),
        Some(first_status.confirmation_hash.as_str())
    );
    let second = target.receipt(second_bundle.challenge, NOW + 2);
    let second_status = admit(&mut f, &second, NOW + 3);
    assert_eq!(second_status.accepted_epoch, "2");
    assert_eq!(second_status.confirmation_revision, "2");
    let old = admit(&mut f, &first, NOW + 4);
    assert!(old.replayed && !old.current_confirmation_eligibility);
    assert_eq!(old.confirmation_hash, first_status.confirmation_hash);
    let head = f
        .store
        .read_target_bootstrap_status(&f.tenant, &target.pin.target_id, NOW + 4)
        .unwrap()
        .unwrap();
    assert_eq!(head.confirmation_hash, second_status.confirmation_hash);
    assert_eq!(
        count(&f.path, "authority_target_bootstrap_confirmations"),
        2
    );
    drop(f.store);
    AuthorityStore::open(&f.path).unwrap();
}

#[test]
fn target_key_or_origin_rotation_cannot_complete_an_old_unconsumed_challenge() {
    for rotate_origin in [false, true] {
        let (_directory, mut f, target) = setup();
        let receipt = target.receipt(challenge(&mut f, &target, None).challenge, NOW);
        if rotate_origin {
            f.store
                .pin_bootstrap_approval_origin(
                    &f.tenant,
                    &BootstrapApprovalOriginPin {
                        schema_version: "fw.bootstrap-approval-origin-pin/v1".into(),
                        org_id: f.tenant.org_id().into(),
                        project_id: f.tenant.project_id().into(),
                        revision: "2".into(),
                        origin: approval_authenticator::ORIGIN.into(),
                        rp_id: f.verifier.rp_id().into(),
                        not_before: at(NOW - 60),
                        not_after: at(NOW + 3600),
                    },
                    Some(1),
                    NOW + 1,
                )
                .unwrap();
        } else {
            let mut pin = target.pin.clone();
            pin.revision = "2".into();
            pin.key_id = "target-bootstrap-2".into();
            pin.public_key = SigningKey::from_bytes(&[74; 32]).verifying_key().to_bytes();
            f.store
                .pin_target_bootstrap_key(&f.tenant, &pin, Some(1), NOW + 1)
                .unwrap();
        }
        assert!(
            f.store
                .admit_target_bootstrap_confirmation(&f.tenant, &receipt, NOW + 1)
                .is_err()
        );
        assert_eq!(
            count(&f.path, "authority_target_bootstrap_confirmations"),
            0
        );
        drop(f.store);
        AuthorityStore::open(&f.path).unwrap();
    }
}

#[test]
fn later_same_second_revocation_preserves_history_but_closes_current_eligibility() {
    for revoke_root in [false, true] {
        let (_directory, mut f, target) = setup();
        let receipt = target.receipt(challenge(&mut f, &target, None).challenge, NOW);
        admit(&mut f, &receipt, NOW + 1);
        if revoke_root {
            f.store
                .revoke_registry_trust_key(&f.tenant, &f.bootstrap_pin.key_id, NOW + 1)
                .unwrap();
        } else {
            f.store
                .revoke_target_bootstrap_key(&f.tenant, &target.pin.target_id, 1, NOW + 1)
                .unwrap();
        }
        let status = admit(&mut f, &receipt, NOW + 1);
        assert!(status.replayed && !status.current_confirmation_eligibility);
        assert_eq!(status.accepted_epoch, "1");
        drop(f.store);
        AuthorityStore::open(&f.path).unwrap();
    }
}

#[test]
fn restored_guards_do_not_hide_missing_heads_or_changed_original_receipt_bytes() {
    for mode in 0..3 {
        let (_directory, mut f, target) = setup();
        let receipt = target.receipt(challenge(&mut f, &target, None).challenge, NOW);
        admit(&mut f, &receipt, NOW + 1);
        drop(f.store);
        if mode == 0 {
            tamper(
                &f.path,
                "authority_target_bootstrap_confirmation_heads",
                "DELETE FROM authority_target_bootstrap_confirmation_heads",
            );
        } else if mode == 1 {
            tamper(
                &f.path,
                "authority_target_bootstrap_key_heads",
                "DELETE FROM authority_target_bootstrap_key_heads",
            );
        } else {
            let connection = Connection::open(&f.path).unwrap();
            let original: Vec<u8> = connection
                .query_row(
                    "SELECT canonical_bytes FROM authority_target_bootstrap_confirmations",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let altered = [b" ".as_slice(), original.as_slice()].concat();
            let sql=connection.query_row("SELECT sql FROM sqlite_schema WHERE name='authority_target_bootstrap_confirmations_no_update'",[],|r|r.get::<_,String>(0)).unwrap();
            connection
                .execute_batch("DROP TRIGGER authority_target_bootstrap_confirmations_no_update;")
                .unwrap();
            connection
                .execute(
                    "UPDATE authority_target_bootstrap_confirmations SET canonical_bytes=?",
                    [altered],
                )
                .unwrap();
            connection.execute_batch(&sql).unwrap();
        }
        assert!(AuthorityStore::open(&f.path).is_err(), "mode {mode}");
    }
}

fn old_pin(f: &mut Fixture, public_key: [u8; 32], kind: u8, revision: Option<u64>) -> Result<()> {
    let target = f.manifest.target_id.clone();
    match kind {
        0 => {
            let mut pin = f.bootstrap_pin.clone();
            pin.key_id = "other-registry-purpose".into();
            pin.public_key = public_key;
            f.store
                .pin_registry_trust_key(&f.tenant, &pin, f.now)
                .map(|_| ())
        }
        1 => f
            .store
            .pin_target_transport(
                &f.tenant,
                &TargetTransportPin {
                    target_id: target,
                    public_key,
                    certificate_fingerprint: hash_bytes(&public_key),
                    platform: "linux".into(),
                    not_before: NOW - 60,
                    not_after: NOW + 3600,
                },
                revision,
                f.now,
            )
            .map(|_| ()),
        _ => f
            .store
            .pin_native_observer(
                &f.tenant,
                &NativeObserverPin {
                    target_id: target,
                    public_key,
                    not_before: NOW - 60,
                    not_after: NOW + 3600,
                },
                revision,
                f.now,
            )
            .map(|_| ()),
    }
}

#[test]
fn target_key_purpose_separation_is_bidirectional_and_survives_retirement() {
    for kind in 0..3 {
        for target_first in [false, true] {
            for retired in [false, true] {
                let directory = private_directory::private_directory();
                let mut f = Fixture::new(directory.path(), NOW);
                let target = TargetFixture::new(&mut f);
                if kind == 2 {
                    old_pin(
                        &mut f,
                        SigningKey::from_bytes(&[96; 32]).verifying_key().to_bytes(),
                        1,
                        None,
                    )
                    .unwrap();
                }
                if target_first {
                    f.store
                        .pin_target_bootstrap_key(&f.tenant, &target.pin, None, NOW)
                        .unwrap();
                    if retired {
                        f.store
                            .revoke_target_bootstrap_key(&f.tenant, &target.pin.target_id, 1, NOW)
                            .unwrap();
                    }
                    let before = retained_rows(&f.path);
                    assert!(
                        old_pin(&mut f, target.pin.public_key, kind, None).is_err(),
                        "kind={kind}, target_first={target_first}, retired={retired}"
                    );
                    assert_eq!(retained_rows(&f.path), before);
                } else {
                    old_pin(&mut f, target.pin.public_key, kind, None).unwrap();
                    if retired {
                        if kind == 0 {
                            f.store
                                .revoke_registry_trust_key(&f.tenant, "other-registry-purpose", NOW)
                                .unwrap();
                        } else {
                            old_pin(
                                &mut f,
                                SigningKey::from_bytes(&[97; 32]).verifying_key().to_bytes(),
                                kind,
                                Some(1),
                            )
                            .unwrap();
                        }
                    }
                    let before = retained_rows(&f.path);
                    assert!(
                        f.store
                            .pin_target_bootstrap_key(&f.tenant, &target.pin, None, NOW)
                            .is_err(),
                        "kind={kind}, target_first={target_first}, retired={retired}"
                    );
                    assert_eq!(retained_rows(&f.path), before);
                }
                let audit_before = count(&f.path, "authority_audit");
                drop(f.store);
                let mut reopened = AuthorityStore::open(&f.path).unwrap();
                assert!(
                    reopened
                        .read_target_bootstrap_status(&f.tenant, &target.pin.target_id, NOW)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(count(&f.path, "authority_audit"), audit_before);
            }
        }
    }
}

#[test]
fn registry_separation_from_transport_and_observer_uses_public_key_bytes() {
    let public = SigningKey::from_bytes(&[94; 32]).verifying_key().to_bytes();
    assert_ne!(
        hash_bytes(&public),
        fw_target_evidence::fingerprint(&public).unwrap()
    );
    for kind in [1, 2] {
        for registry_first in [false, true] {
            for retired in [false, true] {
                let directory = private_directory::private_directory();
                let mut f = Fixture::new(directory.path(), NOW);
                if kind == 2 {
                    old_pin(
                        &mut f,
                        SigningKey::from_bytes(&[96; 32]).verifying_key().to_bytes(),
                        1,
                        None,
                    )
                    .unwrap();
                }
                let first = if registry_first { 0 } else { kind };
                let second = if registry_first { kind } else { 0 };
                old_pin(&mut f, public, first, None).unwrap();
                if retired {
                    if first == 0 {
                        f.store
                            .revoke_registry_trust_key(&f.tenant, "other-registry-purpose", NOW)
                            .unwrap();
                    } else {
                        old_pin(
                            &mut f,
                            SigningKey::from_bytes(&[97; 32]).verifying_key().to_bytes(),
                            first,
                            Some(1),
                        )
                        .unwrap();
                    }
                }
                let before = retained_rows(&f.path);
                assert!(
                    old_pin(&mut f, public, second, None).is_err(),
                    "kind={kind}, registry_first={registry_first}, retired={retired}"
                );
                assert_eq!(retained_rows(&f.path), before);
                drop(f.store);
                AuthorityStore::open(&f.path).unwrap();
            }
        }
    }
}

#[test]
fn direct_sql_purpose_guards_reject_unique_cross_role_rows_with_positive_controls() {
    for (kind, target_first) in (0..3).flat_map(|kind| [false, true].map(|first| (kind, first))) {
        let directory = private_directory::private_directory();
        let mut f = Fixture::new(directory.path(), NOW);
        let target = TargetFixture::new(&mut f);
        if target_first {
            f.store
                .pin_target_bootstrap_key(&f.tenant, &target.pin, None, NOW)
                .unwrap();
        } else {
            if kind == 2 {
                old_pin(
                    &mut f,
                    SigningKey::from_bytes(&[96; 32]).verifying_key().to_bytes(),
                    1,
                    None,
                )
                .unwrap();
            }
            old_pin(&mut f, target.pin.public_key, kind, None).unwrap();
        }
        let connection = Connection::open(&f.path).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF; BEGIN IMMEDIATE;",
            )
            .unwrap();
        for alias in [true, false] {
            let public = if alias {
                target.pin.public_key
            } else {
                SigningKey::from_bytes(&[95; 32]).verifying_key().to_bytes()
            };
            let fingerprint = Sha256::digest(public).to_vec();
            let result = if target_first {
                insert_old_key(&connection, &f, public, kind)
            } else {
                let mut pin = target.pin.clone();
                pin.public_key = public;
                let canonical = pin.canonical_bytes().unwrap();
                let digest = Sha256::digest(&canonical).to_vec();
                connection.execute("INSERT INTO authority_target_bootstrap_key_pins VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",params![f.tenant.org_id(),f.tenant.project_id(),pin.target_id,1u64.to_be_bytes().as_slice(),pin.key_id,public.as_slice(),fingerprint,NOW-60,NOW+3600,NOW,digest,canonical])
            };
            if alias {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("target bootstrap key purpose alias"),
                    "kind={kind}, target_first={target_first}"
                );
            } else {
                assert_eq!(result.unwrap(), 1);
            }
        }
        connection.execute_batch("ROLLBACK;").unwrap();
        drop(connection);
        drop(f.store);
        AuthorityStore::open(&f.path).unwrap();
    }
}

fn insert_old_key(
    connection: &Connection,
    f: &Fixture,
    public: [u8; 32],
    kind: u8,
) -> rusqlite::Result<usize> {
    if kind == 0 {
        let mut pin = f.bootstrap_pin.clone();
        pin.key_id = "raw-unique-registry-key".into();
        pin.public_key = public;
        connection.execute(
            "INSERT INTO authority_registry_keys VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                f.tenant.org_id(),
                f.tenant.project_id(),
                pin.key_id,
                pin.target_id,
                pin.payload_type,
                public.as_slice(),
                Sha256::digest(public).to_vec(),
                pin.not_before,
                pin.not_after,
                NOW,
                canonical_bytes(&pin).unwrap()
            ],
        )
    } else {
        let fingerprint = fw_target_evidence::fingerprint(&public).unwrap();
        let fingerprint: Vec<u8> = fingerprint
            .strip_prefix("sha256:")
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let table = if kind == 1 {
            "authority_target_keys"
        } else {
            "authority_native_observer_keys"
        };
        connection.execute(
            &format!("INSERT INTO {table} VALUES(?,?,?,?,?,?)"),
            params![
                f.tenant.org_id(),
                fingerprint,
                f.tenant.project_id(),
                f.manifest.target_id,
                public.as_slice(),
                NOW
            ],
        )
    }
}

#[test]
fn direct_sql_legacy_role_guards_compare_distinct_fingerprint_domains() {
    for (kind, registry_first) in [1, 2]
        .into_iter()
        .flat_map(|kind| [false, true].map(|first| (kind, first)))
    {
        let directory = private_directory::private_directory();
        let mut f = Fixture::new(directory.path(), NOW);
        let public = SigningKey::from_bytes(&[94; 32]).verifying_key().to_bytes();
        let first = if registry_first { 0 } else { kind };
        let second = if registry_first { kind } else { 0 };
        if kind == 2 && !registry_first {
            old_pin(
                &mut f,
                SigningKey::from_bytes(&[96; 32]).verifying_key().to_bytes(),
                1,
                None,
            )
            .unwrap();
        }
        old_pin(&mut f, public, first, None).unwrap();
        let before = retained_rows(&f.path);
        let connection = Connection::open(&f.path).unwrap();
        connection
            .execute_batch("BEGIN IMMEDIATE; SAVEPOINT independent_key;")
            .unwrap();
        let independent = SigningKey::from_bytes(&[95; 32]).verifying_key().to_bytes();
        assert_eq!(
            insert_old_key(&connection, &f, independent, second).unwrap(),
            1
        );
        connection
            .execute_batch("ROLLBACK TO independent_key; RELEASE independent_key;")
            .unwrap();
        assert!(
            insert_old_key(&connection, &f, public, second)
                .unwrap_err()
                .to_string()
                .contains("authority key purpose alias"),
            "kind={kind}, registry_first={registry_first}"
        );
        connection.execute_batch("ROLLBACK;").unwrap();
        assert_eq!(retained_rows(&f.path), before);
        drop(connection);
        drop(f.store);
        AuthorityStore::open(&f.path).unwrap();
    }
}

#[test]
fn oversized_or_deep_typed_receipt_refuses_before_advancing_the_clock() {
    let (_directory, mut f, target) = setup();
    let receipt = target.receipt(challenge(&mut f, &target, None).challenge, NOW);
    let mut deep = serde_json::Value::Null;
    for _ in 0..fw_contracts::MAX_DEPTH + 1 {
        deep = serde_json::Value::Array(vec![deep]);
    }
    for readback in [
        deep,
        serde_json::json!({"oversized":"x".repeat(MAX_TARGET_BOOTSTRAP_BYTES)}),
    ] {
        let mut malformed = receipt.clone();
        malformed.payload.readback = readback;
        assert!(
            f.store
                .admit_target_bootstrap_confirmation(&f.tenant, &malformed, NOW + 1000)
                .is_err()
        );
        assert_eq!(
            count(&f.path, "authority_target_bootstrap_confirmations"),
            0
        );
        let floor: i64 = Connection::open(&f.path)
            .unwrap()
            .query_row(
                "SELECT observed_at FROM authority_registry_clocks WHERE org_id=? AND project_id=?",
                params![f.tenant.org_id(), f.tenant.project_id()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(floor, NOW);
    }
    admit(&mut f, &receipt, NOW + 1);
}
