use super::super::signing_test_support::{Fixture, NOW};
use super::*;

const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

#[derive(Clone, Copy, Debug)]
enum Corruption {
    DispatchCreated,
    DeliveredEvent,
    DeliveryBeforeClaim,
    DeliveryAtClaimExpiry,
}

fn ready(delivered: bool) -> (Fixture, String) {
    let mut f = Fixture::new();
    let outcome = signing_intents::test_prepare(&mut f, NOW);
    let job = outcome.intent.job_id;
    let tx = f.store.connection.transaction().unwrap();
    let signer = fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).unwrap();
    tx.commit().unwrap();
    signing_intents::test_finalize(&mut f, &signer, NOW).unwrap();
    if delivered {
        let tx = f.store.connection.transaction().unwrap();
        let dispatch =
            fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 0, 2, NOW + 10).unwrap();
        fixture_deliver(&tx, &f.tenant, &dispatch, NOW + 10).unwrap();
        tx.commit().unwrap();
    }
    (f, job)
}

fn corrupt(db: &Connection, job: &str, case: Corruption) {
    let names = match case {
        Corruption::DispatchCreated | Corruption::DeliveredEvent => vec![
            "authority_signing_work_events_immutable_update",
            "authority_signing_work_heads_update",
        ],
        Corruption::DeliveryBeforeClaim | Corruption::DeliveryAtClaimExpiry => {
            vec!["authority_signing_deliveries_immutable_update"]
        }
    };
    let definitions = names
        .iter()
        .filter_map(|name| {
            db.query_row("SELECT sql FROM sqlite_schema WHERE name=?", [name], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .unwrap()
            .map(|definition| (*name, definition))
        })
        .collect::<Vec<_>>();
    for (name, _) in &definitions {
        db.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
    }
    match case {
        Corruption::DispatchCreated => {
            for table in [
                "authority_signing_work_events",
                "authority_signing_work_heads",
            ] {
                assert_eq!(db.execute(&format!("UPDATE {table} SET updated_at=?1,available_at=?1 WHERE job_id=?2 AND phase='dispatch'"), params![NOW + 1, job]).unwrap(), 1);
            }
        }
        Corruption::DeliveredEvent => {
            assert_eq!(db.execute("UPDATE authority_signing_work_events SET updated_at=?1 WHERE job_id=?2 AND phase='dispatch' AND kind='delivered'", params![NOW + 11, job]).unwrap(), 1);
            assert_eq!(db.execute("UPDATE authority_signing_work_heads SET updated_at=?1 WHERE job_id=?2 AND phase='dispatch'", params![NOW + 11, job]).unwrap(), 1);
        }
        Corruption::DeliveryBeforeClaim | Corruption::DeliveryAtClaimExpiry => {
            let recorded = match case {
                Corruption::DeliveryBeforeClaim => NOW + 9,
                Corruption::DeliveryAtClaimExpiry => NOW + 12,
                _ => unreachable!(),
            };
            assert_eq!(
                db.execute(
                    "UPDATE authority_signing_deliveries SET recorded_at=? WHERE job_id=?",
                    params![recorded, job]
                )
                .unwrap(),
                1
            );
        }
    }
    for (_, definition) in definitions {
        db.execute_batch(&definition).unwrap();
    }
}

fn snapshot(db: &Connection) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let names = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND lower(substr(name,1,7))<>'sqlite_' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut statement = db
                .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}

#[test]
fn retained_dispatch_timestamps_fail_runtime_and_maintenance_with_restored_guards() {
    for previous in [8, 9, 10] {
        for case in [
            Corruption::DispatchCreated,
            Corruption::DeliveredEvent,
            Corruption::DeliveryBeforeClaim,
            Corruption::DeliveryAtClaimExpiry,
        ] {
            let (f, job) = ready(!matches!(case, Corruption::DispatchCreated));
            drop(f.store);
            match previous {
                8 => migrations::legacy::restore_v8(&f.path),
                9 => migrations::legacy::restore_v9(&f.path),
                10 => migrations::legacy::restore_v10(&f.path),
                _ => unreachable!(),
            }
            let mut db = Connection::open(&f.path).unwrap();
            corrupt(&db, &job, case);
            let tx = db.transaction().unwrap();
            assert!(
                validate_work_histories(&tx).is_err(),
                "v{previous}: {case:?}"
            );
            assert!(
                lifecycle_status(&tx, &f.tenant, &job, NOW + 20).is_err(),
                "v{previous}: {case:?}"
            );
            tx.rollback().unwrap();
            let before = snapshot(&db);
            drop(db);
            let backup = f.directory.path().join("invalid-time-backup.sqlite3");
            assert!(
                AuthorityStore::migrate(&f.path, &backup).is_err(),
                "v{previous}: {case:?}"
            );
            for path in [&f.path, &backup] {
                let db = Connection::open(path).unwrap();
                assert_eq!(
                    db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                        .unwrap(),
                    previous
                );
                assert_eq!(snapshot(&db), before, "{path:?}: {case:?}");
            }
            let manifest: Value = serde_json::from_slice(
                &std::fs::read(backup.with_extension("manifest.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(manifest["database_schema"], previous);
            assert_eq!(
                manifest["database_hash"],
                hash_bytes(&std::fs::read(&backup).unwrap())
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
}

#[test]
fn exact_dispatch_timestamps_allow_the_claim_start_and_last_live_second() {
    for delivered_at in [NOW + 10, NOW + 11] {
        let (mut f, job) = ready(false);
        let tx = f.store.connection.transaction().unwrap();
        let dispatch =
            fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 0, 2, NOW + 10).unwrap();
        fixture_deliver(&tx, &f.tenant, &dispatch, delivered_at).unwrap();
        validate_work_histories(&tx).unwrap();
        assert_eq!(
            lifecycle_status(&tx, &f.tenant, &job, delivered_at)
                .unwrap()
                .dispatch_state
                .as_deref(),
            Some("delivered")
        );
        tx.commit().unwrap();
        f.reopen();
        let tx = f.store.connection.transaction().unwrap();
        validate_work_histories(&tx).unwrap();
    }
}
