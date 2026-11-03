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
