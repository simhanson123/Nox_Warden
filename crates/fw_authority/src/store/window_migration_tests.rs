// Populated released-schema13 inputs stay exact; no fixed window is inferred.
use super::*;

fn provenance_database() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    AuthorityTenant,
    Value,
) {
    let directory = crate::store::signing_test_support::private_directory::private_directory();
    let path = directory.path().join("core.sqlite3");
    let mut store = AuthorityStore::open(&path).unwrap();
    let (plan, provenance) = crate::store::core_access_fixture::fixture();
    let tenant = AuthorityTenant::new(
        plan["org_id"].as_str().unwrap(),
        plan["project_id"].as_str().unwrap(),
    )
    .unwrap();
    store
        .provision_principal(
            &tenant,
            plan["principal_id"].as_str().unwrap(),
            "https://identity.example.test",
            "legacy-core-user",
            NOW,
        )
        .unwrap();
    store
        .register_plan(
            &tenant,
            &plan,
            &crate::store::core_access_fixture::requirements(),
            NOW,
        )
        .unwrap();
    store
        .register_core_access_provenance(
            &tenant,
            plan["plan_id"].as_str().unwrap(),
            &provenance,
            NOW + 1,
        )
        .unwrap();
    drop(store);
    legacy::restore_v13(&path);
    (directory, path, tenant, plan)
}

fn exact_rows(path: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let db = Connection::open(path).unwrap();
    let names=db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,10)='authority_' ORDER BY name").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut statement = db
                .prepare(&format!("SELECT rowid,* FROM {name} ORDER BY rowid"))
                .unwrap();
            let count = statement.column_count();
            let rows = statement
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

#[test]
fn populated_schema13_migration_preserves_exact_original_bytes_and_infers_no_window() {
    let (directory, path, tenant, plan) = provenance_database();
    let before = exact_rows(&path);
    assert!(matches!(
        AuthorityStore::open(&path),
        Err(AuthorityError::MigrationRequired {
            found: 13,
            required: 15
        })
    ));
    let backup = directory.path().join("schema13-backup.sqlite3");
    AuthorityStore::migrate(&path, &backup).unwrap();
    assert_eq!(version(&path), 15);
    assert_eq!(version(&backup), 13);
    assert_eq!(exact_rows(&backup), before);
    let after = exact_rows(&path);
    for (name, rows) in before {
        let current = &after.iter().find(|(n, _)| n == &name).unwrap().1;
        if name == "authority_schema_migrations" {
            assert!(current.starts_with(&rows));
            assert_eq!(current.len(), 15);
        } else {
            assert_eq!(current, &rows, "{name}");
        }
    }
    let mut store = AuthorityStore::open(&path).unwrap();
    let status = store
        .read_core_access_provenance(&tenant, plan["plan_id"].as_str().unwrap(), NOW + 2)
        .unwrap()
        .unwrap();
    assert_eq!(status.lease_seconds, 3600);
    assert!(
        store
            .read_core_access_lease_window(&tenant, plan["plan_id"].as_str().unwrap(), NOW + 2)
            .unwrap()
            .is_none()
    );
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM authority_core_access_lease_windows",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM authority_plan_review_evidence",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_private_backup(&backup, 13);
}

#[test]
fn schema14_late_migration_failures_preserve_source_rows_schema_backup_and_fk_state() {
    for stage in [
        "schema14-window-created",
        "schema14-version-recorded",
        "before-commit",
    ] {
        let (directory, path, _, _) = provenance_database();
        let before = exact_rows(&path);
        let before_schema = schema_digest(&Connection::open(&path).unwrap()).unwrap();
        let backup = directory.path().join("failed-schema14.sqlite3");
        MIGRATION_FAILURE.with(|requested| *requested.borrow_mut() = Some(stage));
        MIGRATION_FK_RESTORED.with(|restored| restored.set(false));
        let result = AuthorityStore::migrate(&path, &backup);
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
        assert_eq!(version(&path), 13);
        assert_eq!(exact_rows(&path), before);
        assert_eq!(exact_rows(&backup), before);
        assert_eq!(
            schema_digest(&Connection::open(&path).unwrap()).unwrap(),
            before_schema
        );
        assert_private_backup(&backup, 13);
    }
}
