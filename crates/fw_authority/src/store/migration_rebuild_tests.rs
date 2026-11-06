use super::*;

fn retained_rows(path: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let db = Connection::open(path).unwrap();
    let names=db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,10)='authority_' ORDER BY name").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut query = db
                .prepare(&format!("SELECT rowid,* FROM {name} ORDER BY rowid"))
                .unwrap();
            let count = query.column_count();
            let rows = query
                .query_map([], |r| {
                    (0..count)
                        .map(|i| r.get(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}

fn assert_retained(path: &Path, before: &[(String, Vec<Vec<rusqlite::types::Value>>)]) {
    let after = retained_rows(path);
    for (name, rows) in before {
        let actual = &after.iter().find(|(table, _)| table == name).unwrap().1;
        if name == "authority_schema_migrations" {
            assert!(actual.starts_with(rows));
        } else {
            assert_eq!(actual, rows, "rowids/types/bytes in {name}");
        }
    }
}

#[test]
fn nullable_upgrade_preserves_guarded_rooted_lifecycles_and_all_rowids() {
    for state in ["reserved", "released", "issued", "unknown", "active"] {
        let (f, _) = prepared_in_state(state);
        drop(f.store);
        legacy::restore_v11(&f.path);
        let before = retained_rows(&f.path);
        let backup = f.directory.path().join("schema11.sqlite3");
        AuthorityStore::migrate(&f.path, &backup).unwrap();
        assert_eq!(version(&f.path), 15);
        assert_eq!(version(&backup), 11);
        assert_eq!(retained_rows(&backup), before);
        assert_retained(&f.path, &before);
        assert_private_backup(&backup, 11);
        let mut reopened = AuthorityStore::open(&f.path).unwrap();
        let tx = reopened.connection.transaction().unwrap();
        validate_retained_integrity(&tx).unwrap();
        tx.commit().unwrap();
    }
}

#[test]
fn every_rebuild_error_rolls_back_original_schema_rows_and_private_backup() {
    for stage in [
        "guards-dropped",
        "rows-copied",
        "parent-dropped",
        "rows-restored",
        "guards-restored",
        "references-verified",
        "version-recorded",
        "before-commit",
    ] {
        let (f, _) = prepared_in_state("active");
        drop(f.store);
        legacy::restore_v11(&f.path);
        let before = retained_rows(&f.path);
        let before_schema = schema_digest(&Connection::open(&f.path).unwrap()).unwrap();
        let backup = f.directory.path().join("before-rebuild.sqlite3");
        MIGRATION_FAILURE.with(|requested| *requested.borrow_mut() = Some(stage));
        MIGRATION_FK_RESTORED.with(|restored| restored.set(false));
        let result = AuthorityStore::migrate(&f.path, &backup);
        MIGRATION_FAILURE.with(|requested| *requested.borrow_mut() = None);
        assert!(
            matches!(
                result,
                Err(AuthorityError::Invalid(
                    "injected authority migration failure"
                ))
            ),
            "{stage}: {result:?}"
        );
        assert!(
            MIGRATION_FK_RESTORED.with(|restored| restored.get()),
            "{stage}"
        );
        assert_eq!(version(&f.path), 11, "{stage}");
        assert_eq!(retained_rows(&f.path), before, "{stage}");
        assert_eq!(retained_rows(&backup), before, "{stage}");
        assert_eq!(
            schema_digest(&Connection::open(&f.path).unwrap()).unwrap(),
            before_schema,
            "{stage}"
        );
        assert_private_backup(&backup, 11);
    }
}

#[test]
fn abrupt_process_exit_after_parent_drop_recovers_the_original_transaction() {
    let (f, _) = prepared_in_state("active");
    drop(f.store);
    legacy::restore_v11(&f.path);
    let before = retained_rows(&f.path);
    let backup = f.directory.path().join("before-crash.sqlite3");
    let status = worker(&f.path, &backup)
        .env("FW_TEST_MIGRATION_CRASH", "parent-dropped")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(89));
    assert_eq!(version(&f.path), 11);
    assert_eq!(retained_rows(&f.path), before);
    assert_eq!(retained_rows(&backup), before);
    let next = f.directory.path().join("after-crash.sqlite3");
    AuthorityStore::migrate(&f.path, &next).unwrap();
    assert_eq!(version(&f.path), 15);
    assert_retained(&f.path, &before);
}

#[test]
fn competing_maintenance_processes_commit_one_upgrade_and_keep_all_evidence() {
    let (f, _) = prepared_in_state("unknown");
    drop(f.store);
    legacy::restore_v11(&f.path);
    let before = retained_rows(&f.path);
    let first = f.directory.path().join("first.sqlite3");
    let second = f.directory.path().join("second.sqlite3");
    let mut a = worker(&f.path, &first).spawn().unwrap();
    let mut b = worker(&f.path, &second).spawn().unwrap();
    assert!(a.wait().unwrap().success());
    assert!(b.wait().unwrap().success());
    assert_eq!(
        usize::from(first.exists()) + usize::from(second.exists()),
        1
    );
    assert_eq!(version(&f.path), 15);
    assert_retained(&f.path, &before);
}

fn worker(path: &Path, backup: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "store::migrations::tests::rebuild_tests::migration_process_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("FW_TEST_MIGRATION_SOURCE", path)
        .env("FW_TEST_MIGRATION_BACKUP", backup);
    command
}

#[test]
#[ignore = "isolated subprocess fixture, invoked by rebuild tests"]
fn migration_process_worker() {
    let path = std::env::var_os("FW_TEST_MIGRATION_SOURCE").unwrap();
    let backup = std::env::var_os("FW_TEST_MIGRATION_BACKUP").unwrap();
    // Warm only the independent schema reference before the deliberate exit.
    known_v14().unwrap();
    if let Ok(stage) = std::env::var("FW_TEST_MIGRATION_CRASH") {
        let stage = match stage.as_str() {
            "parent-dropped" => "parent-dropped",
            "backup-files-created" => "backup-files-created",
            _ => panic!("unknown fixture crash stage"),
        };
        MIGRATION_FAILURE.with(|requested| *requested.borrow_mut() = Some(stage));
        MIGRATION_CRASH.with(|crash| crash.set(true));
    }
    AuthorityStore::migrate(Path::new(&path), Path::new(&backup)).unwrap();
}

#[test]
fn schema12_upgrade_preserves_all_retained_bytes_and_current_maintenance_is_noop() {
    for state in ["reserved", "released", "issued", "unknown", "active"] {
        let (f, _) = prepared_in_state(state);
        drop(f.store);
        legacy::restore_v12(&f.path);
        validate_v12(&Connection::open(&f.path).unwrap()).unwrap();
        let before = retained_rows(&f.path);
        let backup = f.directory.path().join("schema12.sqlite3");
        assert!(matches!(
            AuthorityStore::open(&f.path),
            Err(AuthorityError::MigrationRequired {
                found: 12,
                required: 15
            })
        ));
        AuthorityStore::migrate(&f.path, &backup).unwrap();
        assert_eq!(version(&f.path), 15);
        assert_eq!(version(&backup), 12);
        assert_eq!(retained_rows(&backup), before);
        assert_retained(&f.path, &before);
        assert_private_backup(&backup, 12);
        let current = retained_rows(&f.path);
        let noop = f.directory.path().join("same-version.sqlite3");
        AuthorityStore::migrate(&f.path, &noop).unwrap();
        assert!(!noop.exists());
        assert!(!noop.with_extension("manifest.json").exists());
        assert_eq!(retained_rows(&f.path), current);
        AuthorityStore::open(&f.path).unwrap();
    }
}

#[test]
fn schema13_errors_restore_schema12_bytes_history_backup_and_foreign_keys() {
    for stage in [
        "schema13-guards-created",
        "schema13-version-recorded",
        "before-commit",
    ] {
        let (f, _) = prepared_in_state("active");
        drop(f.store);
        legacy::restore_v12(&f.path);
        let before = retained_rows(&f.path);
        let schema = schema_digest(&Connection::open(&f.path).unwrap()).unwrap();
        let backup = f.directory.path().join("schema12-failed.sqlite3");
        MIGRATION_FAILURE.with(|requested| *requested.borrow_mut() = Some(stage));
        MIGRATION_FK_RESTORED.with(|restored| restored.set(false));
        let result = AuthorityStore::migrate(&f.path, &backup);
        MIGRATION_FAILURE.with(|requested| *requested.borrow_mut() = None);
        assert!(
            matches!(
                result,
                Err(AuthorityError::Invalid(
                    "injected authority migration failure"
                ))
            ),
            "{stage}: {result:?}"
        );
        assert!(MIGRATION_FK_RESTORED.with(|restored| restored.get()));
        assert_eq!(version(&f.path), 12);
        assert_eq!(retained_rows(&f.path), before);
        assert_eq!(retained_rows(&backup), before);
        assert_eq!(
            schema_digest(&Connection::open(&f.path).unwrap()).unwrap(),
            schema
        );
        assert_private_backup(&backup, 12);
    }
}

#[test]
fn interrupted_backup_retains_incomplete_private_pair_and_new_destination_recovers() {
    let (f, _) = prepared_in_state("active");
    drop(f.store);
    legacy::restore_v12(&f.path);
    let before = retained_rows(&f.path);
    let interrupted = f.directory.path().join("interrupted.sqlite3");
    let status = worker(&f.path, &interrupted)
        .env("FW_TEST_MIGRATION_CRASH", "backup-files-created")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(89));
    assert_eq!(version(&f.path), 12);
    assert_eq!(retained_rows(&f.path), before);
    for path in [&interrupted, &interrupted.with_extension("manifest.json")] {
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
        }
    }
    assert!(AuthorityStore::migrate(&f.path, &interrupted).is_err());
    let fresh = f.directory.path().join("retry.sqlite3");
    AuthorityStore::migrate(&f.path, &fresh).unwrap();
    assert_eq!(version(&f.path), 15);
    assert_eq!(retained_rows(&fresh), before);
    assert_retained(&f.path, &before);
    assert!(interrupted.exists());
    assert_eq!(
        fs::metadata(interrupted.with_extension("manifest.json"))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_real_commit_lock_failure_rolls_back_and_restores_foreign_keys() {
    let (f, _) = prepared_in_state("issued");
    drop(f.store);
    legacy::restore_v11(&f.path);
    let before = retained_rows(&f.path);
    let reader = Connection::open(&f.path).unwrap();
    reader
        .execute_batch("PRAGMA journal_mode=DELETE; BEGIN; SELECT * FROM authority_metadata;")
        .unwrap();
    let backup = f.directory.path().join("commit-blocked.sqlite3");
    MIGRATION_FK_RESTORED.with(|restored| restored.set(false));
    let result = AuthorityStore::migrate(&f.path, &backup);
    assert!(
        matches!(result,Err(AuthorityError::Storage(rusqlite::Error::SqliteFailure(code,_))) if code.code==rusqlite::ErrorCode::DatabaseBusy),
        "{result:?}"
    );
    assert!(MIGRATION_FK_RESTORED.with(|restored| restored.get()));
    reader.execute_batch("COMMIT").unwrap();
    assert_eq!(version(&f.path), 11);
    assert_eq!(retained_rows(&f.path), before);
    assert_eq!(retained_rows(&backup), before);
    assert_private_backup(&backup, 11);
}

#[test]
fn damaged_known_schema11_graph_is_backed_up_before_upgrade_refusal() {
    let (f, _) = prepared_in_state("active");
    drop(f.store);
    legacy::restore_v11(&f.path);
    let db = Connection::open(&f.path).unwrap();
    let guard: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_signing_jobs_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER authority_signing_jobs_no_delete; DELETE FROM authority_signing_jobs;").unwrap();
    db.execute_batch(&guard).unwrap();
    drop(db);
    let before = retained_rows(&f.path);
    let backup = f.directory.path().join("orphaned-schema11.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    assert_eq!(version(&f.path), 11);
    assert_eq!(retained_rows(&f.path), before);
    assert_eq!(retained_rows(&backup), before);
    assert_private_backup(&backup, 11);
}

#[test]
fn schema15_upgrade_preserves_every_retained_state_and_starts_without_registry_authority() {
    for state in ["reserved", "released", "issued", "unknown", "active"] {
        let (f, _) = prepared_in_state(state);
        drop(f.store);
        legacy::restore_v14(&f.path);
        let before = retained_rows(&f.path);
        let backup = f.directory.path().join("schema14.sqlite3");
        AuthorityStore::migrate(&f.path, &backup).unwrap();
        assert_eq!(version(&f.path), 15);
        assert_eq!(version(&backup), 14);
        assert_eq!(retained_rows(&backup), before);
        assert_retained(&f.path, &before);
        let db = Connection::open(&f.path).unwrap();
        for table in [
            "authority_registry_keys",
            "authority_registry_objects",
            "authority_bootstrap_proofs",
            "authority_bootstrap_pending_heads",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        AuthorityStore::open(&f.path).unwrap();
    }
}

#[test]
fn schema15_late_failures_preserve_schema14_rows_rowids_history_and_private_backup() {
    for stage in [
        "schema15-registry-created",
        "schema15-version-recorded",
        "before-commit",
    ] {
        let (f, _) = prepared_in_state("unknown");
        drop(f.store);
        legacy::restore_v14(&f.path);
        let before = retained_rows(&f.path);
        let schema = schema_digest(&Connection::open(&f.path).unwrap()).unwrap();
        let backup = f.directory.path().join("schema14-failed.sqlite3");
        MIGRATION_FAILURE.with(|requested| *requested.borrow_mut() = Some(stage));
        let result = AuthorityStore::migrate(&f.path, &backup);
        MIGRATION_FAILURE.with(|requested| *requested.borrow_mut() = None);
        assert!(result.is_err(), "{stage}");
        assert_eq!(version(&f.path), 14);
        assert_eq!(retained_rows(&f.path), before);
        assert_eq!(retained_rows(&backup), before);
        assert_eq!(
            schema_digest(&Connection::open(&f.path).unwrap()).unwrap(),
            schema
        );
        assert_private_backup(&backup, 14);
    }
}
