use super::*;
use crate::store::migrations::legacy;

type SchemaObject = (String, String, String, Option<String>);

#[derive(Debug, PartialEq)]
struct RetainedDatabase {
    version: i64,
    schema: Vec<SchemaObject>,
    tables: Vec<(String, Vec<Vec<rusqlite::types::Value>>)>,
}

fn database_snapshot(path: &std::path::Path) -> RetainedDatabase {
    let db = Connection::open(path).unwrap();
    let version = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    let schema = db
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE lower(substr(name,1,7))<>'sqlite_' ORDER BY type,name")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<std::result::Result<Vec<SchemaObject>, _>>()
        .unwrap();
    let tables = schema
        .iter()
        .filter(|(kind, _, _, _)| kind == "table")
        .map(|(_, name, _, _)| {
            let quoted = name.replace('"', "\"\"");
            let mut query = db
                .prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY rowid"))
                .unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            (name.clone(), rows)
        })
        .collect();
    RetainedDatabase {
        version,
        schema,
        tables,
    }
}

fn private_v7_backup(path: &std::path::Path, expected: &RetainedDatabase) {
    assert_eq!(database_snapshot(path), *expected);
    let manifest_path = path.with_extension("manifest.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["database_schema"], 7);
    assert_eq!(
        manifest["database_hash"],
        hash_bytes(&std::fs::read(path).unwrap())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in [path, manifest_path.as_path()] {
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

fn assert_uncertain_dispatch_history(db: &Connection, job: &str) {
    let unknown_events: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM authority_signing_work_events WHERE job_id=? AND phase='dispatch' AND state='unknown'",
            [job],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(unknown_events, 1);
    let head: String = db
        .query_row(
            "SELECT state FROM authority_signing_work_heads WHERE job_id=? AND phase='dispatch'",
            [job],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(head, "claimed");
}

#[test]
fn v7_unknown_relabelled_as_issued_cannot_migrate_or_erase_original_history() {
    let (f, job, reservation) = real_reservation("unknown");
    drop(f.store);
    legacy::restore_v7(&f.path);
    let db = Connection::open(&f.path).unwrap();
    db.pragma_update(None, "foreign_keys", "ON").unwrap();
    assert_uncertain_dispatch_history(&db, &job);
    // Published v7 permits this ordinary projection update without removing
    // any guard. The prior UNKNOWN event still forbids forgetting uncertainty.
    assert_eq!(
        db.execute(
            "UPDATE authority_signing_quota_reservations SET state='issued' WHERE reservation_id=?",
            [&reservation],
        )
        .unwrap(),
        1
    );
    drop(db);
    let before = database_snapshot(&f.path);
    assert_eq!(before.version, 7);
    let backup = f
        .directory
        .path()
        .join("unknown-before-rejected-upgrade.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    assert_eq!(database_snapshot(&f.path), before);
    private_v7_backup(&backup, &before);
}

#[test]
fn v7_unknown_with_a_later_claim_preserves_uncertainty_and_every_original_record() {
    let (mut f, job, reservation) = real_reservation("unknown");
    drop(f.store);
    legacy::restore_v7(&f.path);
    let before = database_snapshot(&f.path);
    assert_eq!(before.version, 7);
    let backup = f
        .directory
        .path()
        .join("unknown-before-valid-upgrade.sqlite3");
    AuthorityStore::migrate(&f.path, &backup).unwrap();
    private_v7_backup(&backup, &before);
    let after = database_snapshot(&f.path);
    assert!(after.version > before.version);
    for (name, rows) in &before.tables {
        if name == "authority_schema_migrations" {
            continue;
        }
        assert_eq!(
            &after
                .tables
                .iter()
                .find(|(table, _)| table == name)
                .unwrap()
                .1,
            rows,
            "retained v7 evidence changed: {name}"
        );
    }
    f.store = AuthorityStore::open(&f.path).unwrap();
    assert_uncertain_dispatch_history(&f.store.connection, &job);
    let tx = f.store.connection.transaction().unwrap();
    let saved = read(&tx, &f.tenant, &reservation).unwrap();
    assert_eq!(saved.state, "unknown");
    assert!(saved.held());
    let status = signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW + 6).unwrap();
    assert_eq!(status.dispatch_state.as_deref(), Some("claimed"));
    assert!(status.quota_held);
    assert!(matches!(
        reserve(&tx, &f.tenant, &id(930), &change(2), NOW + 300, NOW + 6),
        Err(AuthorityError::Quota)
    ));
}

#[test]
fn restored_guards_cannot_hide_retained_unknown_work_history_from_reads_or_accounting() {
    let (mut f, job, reservation) = real_reservation("unknown");
    assert_uncertain_dispatch_history(&f.store.connection, &job);
    let saved_guards = f
        .store
        .connection
        .prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND tbl_name IN ('authority_signing_quota_reservations','authority_signing_quota_transitions','authority_signing_quota_transition_heads') ORDER BY name")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    // Model damaged quota projections/history followed by exact guard repair.
    // Keep all signed results and dispatch work events, including UNKNOWN.
    for (name, _) in &saved_guards {
        f.store
            .connection
            .execute_batch(&format!("DROP TRIGGER {name}"))
            .unwrap();
    }
    let previous_issued: i64 = f.store.connection.query_row(
        "SELECT MAX(revision) FROM authority_signing_quota_transitions WHERE reservation_id=? AND state='issued'",
        [&reservation], |r| r.get(0),
    ).unwrap();
    f.store.connection.execute(
        "UPDATE authority_signing_quota_transition_heads SET revision=?,state='issued' WHERE reservation_id=?",
        params![previous_issued, reservation],
    ).unwrap();
    f.store
        .connection
        .execute(
            "UPDATE authority_signing_quota_reservations SET state='issued' WHERE reservation_id=?",
            [&reservation],
        )
        .unwrap();
    f.store
        .connection
        .execute(
            "DELETE FROM authority_signing_quota_transitions WHERE reservation_id=? AND revision>?",
            params![reservation, previous_issued],
        )
        .unwrap();
    for (_, sql) in &saved_guards {
        f.store.connection.execute_batch(sql).unwrap();
    }
    assert_uncertain_dispatch_history(&f.store.connection, &job);
    for reopened in [false, true] {
        if reopened {
            drop(f.store);
            f.store = match AuthorityStore::open(&f.path) {
                Ok(store) => store,
                // Current-version opening may reject retained corruption too.
                Err(_) => return,
            };
        }
        let tx = f.store.connection.transaction().unwrap();
        assert!(read(&tx, &f.tenant, &reservation).is_err());
        assert!(signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW + 6).is_err());
        assert!(matches!(
            reserve(&tx, &f.tenant, &id(931), &change(2), NOW + 300, NOW + 6),
            Err(AuthorityError::Invalid(_) | AuthorityError::Binding)
        ));
    }
}
