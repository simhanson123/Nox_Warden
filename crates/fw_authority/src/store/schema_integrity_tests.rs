use super::*;
use crate::store::signing_test_support::{Fixture, NOW};

fn inject(connection: &Connection, kind: &str, name: &str, table: &str, sql: &str, rootpage: i64) {
    connection
        .execute_batch("PRAGMA writable_schema=ON")
        .unwrap();
    connection
        .execute(
            "INSERT INTO sqlite_schema(type,name,tbl_name,rootpage,sql) VALUES(?,?,?,?,?)",
            params![kind, name, table, rootpage, sql],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema=RESET")
        .unwrap();
}

#[test]
fn reserved_name_object_inventory_is_checked_live_at_open_and_maintenance() {
    for (kind, name, table, sql) in [
        (
            "trigger",
            "sqlite_zz_hidden",
            "authority_projects",
            "CREATE TRIGGER sqlite_zz_hidden AFTER UPDATE ON authority_projects BEGIN SELECT 1; END",
        ),
        (
            "view",
            "sqlite_zz_hidden",
            "sqlite_zz_hidden",
            "CREATE VIEW sqlite_zz_hidden AS SELECT 1",
        ),
        (
            "table",
            "sqlite_zz_hidden",
            "sqlite_zz_hidden",
            "CREATE TABLE sqlite_zz_hidden(value TEXT)",
        ),
        (
            "index",
            "sqlite_autoindex_fake_1",
            "authority_projects",
            "CREATE INDEX sqlite_autoindex_fake_1 ON authority_projects(security_revision)",
        ),
        (
            "trigger",
            "sqlite_stat1",
            "authority_projects",
            "CREATE TRIGGER sqlite_stat1 AFTER UPDATE ON authority_projects BEGIN SELECT 1; END",
        ),
        (
            "table",
            "sqlite_stat1",
            "sqlite_stat1",
            "CREATE TABLE sqlite_stat1(value TEXT)",
        ),
    ] {
        let f = Fixture::new();
        let db = Connection::open(&f.path).unwrap();
        let rootpage = if kind == "table" {
            db.query_row(
                "SELECT rootpage FROM sqlite_schema WHERE name='authority_projects'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        } else {
            0
        };
        inject(&db, kind, name, table, sql, rootpage);
        assert!(
            migrations::validate_live_schema(&f.store.connection).is_err(),
            "{kind} {name}"
        );
        assert!(AuthorityStore::open(&f.path).is_err(), "{kind} {name}");
        let backup = f.directory.path().join("refused.sqlite3");
        assert!(
            AuthorityStore::migrate(&f.path, &backup).is_err(),
            "{kind} {name}"
        );
        assert!(!backup.exists(), "unexpected schema rejected before backup");
    }
}

#[test]
fn analyze_uses_only_exact_supported_engine_objects() {
    let mut f = Fixture::new();
    let db = Connection::open(&f.path).unwrap();
    db.execute_batch("ANALYZE").unwrap();
    migrations::validate_live_schema(&db).unwrap();
    drop(f.store);
    f.store = AuthorityStore::open(&f.path).unwrap();
    f.store
        .provision_principal(
            &f.tenant,
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "local-oob",
            "analyzed",
            NOW,
        )
        .unwrap();
}

#[test]
fn adjacent_and_signing_identity_guards_refuse_exact_replacement_with_each_pragma() {
    for foreign_keys in [false, true] {
        for recursive in [false, true] {
            let mut f = Fixture::new();
            let prepared = signing_intents::test_prepare(&mut f, NOW);
            let job = prepared.intent.job_id;
            let tx = f.store.connection.transaction().unwrap();
            let signer = signing_jobs::fixture_claim(
                &tx,
                &f.tenant,
                &job,
                "signer",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                0,
                2,
                NOW,
            )
            .unwrap();
            tx.commit().unwrap();
            signing_intents::test_finalize(&mut f, &signer, NOW).unwrap();
            let tx = f.store.connection.transaction().unwrap();
            let dispatch = signing_jobs::fixture_claim(
                &tx,
                &f.tenant,
                &job,
                "dispatch",
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                0,
                2,
                NOW,
            )
            .unwrap();
            signing_jobs::fixture_deliver(&tx, &f.tenant, &dispatch, NOW).unwrap();
            tx.commit().unwrap();
            let db = Connection::open(&f.path).unwrap();
            db.pragma_update(None, "foreign_keys", foreign_keys)
                .unwrap();
            db.pragma_update(None, "recursive_triggers", recursive)
                .unwrap();
            for table in [
                "authority_signing_intents",
                "authority_signing_jobs",
                "authority_signing_results",
                "authority_signing_outbox",
                "authority_signing_quota_reservations",
                "authority_signing_quota_transitions",
                "authority_signing_quota_usage",
                "authority_signing_quota_pins",
                "authority_signing_quota_heads",
                "authority_signing_quota_clocks",
                "authority_signing_target_heads",
                "authority_audit",
                "authority_audit_heads",
                "authority_target_pins",
                "authority_target_pin_heads",
                "authority_target_clocks",
                "authority_native_pins",
                "authority_native_pin_heads",
            ] {
                let before: i64 = db
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert!(before > 0, "populated {table}");
                assert!(db.execute(&format!("INSERT OR REPLACE INTO {table}(rowid,{} ) SELECT rowid,{} FROM {table} LIMIT 1",columns(&db,table),columns(&db,table)),[]).is_err(),"rowid collision: {table} FK={foreign_keys} recursive={recursive}");
                assert!(
                    db.execute(
                        &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table} LIMIT 1"),
                        []
                    )
                    .is_err(),
                    "logical collision: {table}"
                );
                assert!(db.execute(&format!("UPDATE OR REPLACE {table} SET rowid=rowid+100000 WHERE rowid=(SELECT min(rowid) FROM {table})"),[]).is_err(),"rowid move: {table}");
                assert_eq!(
                    db.query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get(0))
                        .unwrap(),
                    before
                );
            }
            drop(f.store);
            let mut reopened = AuthorityStore::open(&f.path).unwrap();
            let tx = reopened.connection.transaction().unwrap();
            signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap();
            tx.commit().unwrap();
        }
    }
}

fn columns(connection: &Connection, table: &str) -> String {
    connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join(",")
}

// This creates a physically stale partial index while returning sqlite_schema
// to its exact original bytes. It intentionally never updates application rows.
fn empty_held_index(connection: &Connection, index: &str) {
    let original: String = connection
        .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [index], |r| {
            r.get(0)
        })
        .unwrap();
    let empty = original.replacen("WHERE ", "WHERE 0 AND ", 1);
    assert_ne!(empty, original);
    connection
        .execute_batch("PRAGMA writable_schema=ON")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_schema SET sql=? WHERE name=?",
            params![empty, index],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema=RESET")
        .unwrap();
    connection
        .execute_batch(&format!("REINDEX {index}"))
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema=ON")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_schema SET sql=? WHERE name=?",
            params![original, index],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema=RESET")
        .unwrap();
}

#[test]
fn stale_physical_held_index_with_exact_schema_refuses_live_open_and_maintenance() {
    for index in [
        "authority_signing_quota_transition_project_held",
        "authority_signing_quota_transition_root_held",
    ] {
        let mut f = Fixture::new();
        let prepared = signing_intents::test_prepare(&mut f, NOW);
        let tx = f.store.connection.transaction().unwrap();
        let cost = signing_quota::read(&tx, &f.tenant, &prepared.intent.reservation_id)
            .unwrap()
            .cost;
        tx.commit().unwrap();
        let db = Connection::open(&f.path).unwrap();
        let rows_before: i64 = db
            .query_row(
                "SELECT count(*) FROM authority_signing_quota_transition_heads NOT INDEXED",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows_before, 1);
        empty_held_index(&db, index);
        // Metadata-only comparison cannot see the missing physical index rows.
        migrations::validate_live_schema(&db).unwrap();
        let indexed: i64 = db.query_row(&format!("SELECT count(*) FROM authority_signing_quota_transition_heads INDEXED BY {index} WHERE state IN ('reserved','issued','unknown','active')"), [], |r| r.get(0)).unwrap();
        assert_eq!(indexed, 0);
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT count(*) FROM authority_signing_quota_transition_heads NOT INDEXED",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            rows_before
        );
        let physical: String = db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_ne!(physical, "ok");
        assert!(f.store.connection.transaction().is_err());
        // Preserve the independent scope-level rejection check after the live
        // connection has already refused to return a transaction.
        let mut forensic = Connection::open(&f.path).unwrap();
        let tx = forensic.transaction().unwrap();
        let admitted = signing_quota::reserve(
            &tx,
            &f.tenant,
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            &cost,
            NOW + 120,
            NOW,
        )
        .is_ok();
        tx.rollback().unwrap();
        let opened = AuthorityStore::open(&f.path).is_ok();
        let backup = f.directory.path().join("damaged-index.sqlite3");
        let maintained = AuthorityStore::migrate(&f.path, &backup).is_ok();
        assert!(
            !admitted && !opened && !maintained,
            "{index}: stale physical index accepted live={admitted}, open={opened}, maintenance={maintained}"
        );
        assert!(!backup.exists());
        // Refusal never repairs the index or rewrites the held obligation.
        assert_ne!(
            db.query_row::<String, _, _>("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap(),
            "ok"
        );
    }
}

#[test]
fn stale_physical_source_index_is_rejected_before_upgrade_rebuild_or_backup() {
    for version in [9, 11, 12] {
        let mut f = Fixture::new();
        signing_intents::test_prepare(&mut f, NOW);
        drop(f.store);
        match version {
            9 => migrations::legacy::restore_v9(&f.path),
            11 => migrations::legacy::restore_v11(&f.path),
            12 => migrations::legacy::restore_v12(&f.path),
            _ => unreachable!(),
        }
        let db = Connection::open(&f.path).unwrap();
        empty_held_index(&db, "authority_signing_quota_transition_project_held");
        match version {
            9 => migrations::validate_v9(&db).unwrap(),
            11 => migrations::validate_v11(&db).unwrap(),
            12 => migrations::validate_v12(&db).unwrap(),
            _ => unreachable!(),
        }
        assert_ne!(
            db.query_row::<String, _, _>("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap(),
            "ok"
        );
        let backup = f.directory.path().join("stale-source.sqlite3");
        assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
        assert!(!backup.exists());
        assert!(!backup.with_extension("manifest.json").exists());
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            version
        );
        assert_ne!(
            db.query_row::<String, _, _>("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap(),
            "ok"
        );
    }
}

#[test]
fn reserved_objects_are_refused_before_legacy_upgrade_creates_a_backup() {
    for (kind, table, sql) in [
        (
            "trigger",
            "authority_projects",
            "CREATE TRIGGER sqlite_zz_hidden AFTER UPDATE ON authority_projects BEGIN SELECT 1; END",
        ),
        (
            "view",
            "sqlite_zz_hidden",
            "CREATE VIEW sqlite_zz_hidden AS SELECT 1",
        ),
        (
            "table",
            "sqlite_zz_hidden",
            "CREATE TABLE sqlite_zz_hidden(value TEXT)",
        ),
        (
            "index",
            "authority_projects",
            "CREATE INDEX sqlite_zz_hidden ON authority_projects(security_revision)",
        ),
    ] {
        let f = Fixture::new();
        drop(f.store);
        migrations::legacy::restore_v10(&f.path);
        let db = Connection::open(&f.path).unwrap();
        let rootpage = if kind == "table" {
            db.query_row(
                "SELECT rootpage FROM sqlite_schema WHERE name='authority_projects'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        } else {
            0
        };
        inject(&db, kind, "sqlite_zz_hidden", table, sql, rootpage);
        let backup = f.directory.path().join("unrecognized.sqlite3");
        assert!(AuthorityStore::migrate(&f.path, &backup).is_err(), "{kind}");
        assert!(!backup.exists(), "{kind}");
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            10
        );
    }
}
