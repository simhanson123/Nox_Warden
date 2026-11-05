//! Test-only reconstruction of the previously published schema. Product APIs
//! do not expose schema downgrade or erase authority records.
pub fn restore_v2(path: &std::path::Path) {
    restore_v3(path);
    let db = rusqlite::Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    for table in [
        "authority_admission_results",
        "authority_set_revocations",
        "authority_decision_revocations",
        "authority_set_heads",
        "authority_approval_set_members",
        "authority_approval_sets",
        "authority_human_bindings",
        "authority_basis_heads",
        "authority_basis_pins",
    ] {
        db.execute_batch(&format!("DROP TABLE {table};")).unwrap();
    }
    for index in [
        "authority_plan_set_identity",
        "authority_decision_set_identity",
        "authority_role_set_identity",
        "authority_plan_decision_lookup",
    ] {
        db.execute_batch(&format!("DROP INDEX {index};")).unwrap();
    }
    let trigger: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=3;").unwrap();
    db.execute_batch(&trigger).unwrap();
    db.pragma_update(None, "user_version", 2).unwrap();
}

#[allow(dead_code)]
pub fn restore_v3(path: &std::path::Path) {
    restore_v4(path);
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch("DROP TABLE authority_plan_review_evidence;")
        .unwrap();
    let trigger: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=4;").unwrap();
    db.execute_batch(&trigger).unwrap();
    db.pragma_update(None, "user_version", 3).unwrap();
}

#[allow(dead_code)]
pub fn restore_v4(path: &std::path::Path) {
    restore_v5(path);
    let db = rusqlite::Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    for table in [
        "authority_target_metadata_heads",
        "authority_target_metadata",
        "authority_target_challenges",
        "authority_target_clocks",
        "authority_target_pin_heads",
        "authority_target_pins",
        "authority_target_key_revocations",
        "authority_target_keys",
    ] {
        db.execute_batch(&format!("DROP TABLE {table};")).unwrap();
    }
    let trigger: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=5;").unwrap();
    db.execute_batch(&trigger).unwrap();
    db.pragma_update(None, "user_version", 4).unwrap();
}

#[allow(dead_code)]
pub fn restore_v5(path: &std::path::Path) {
    restore_v6(path);
    let db = rusqlite::Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    for table in [
        "authority_native_observation_heads",
        "authority_native_observations",
        "authority_native_challenges",
        "authority_native_compilation_heads",
        "authority_native_compilations",
        "authority_native_observer_revocations",
        "authority_native_observer_keys",
        "authority_native_pin_revocations",
        "authority_native_pin_heads",
        "authority_native_pins",
    ] {
        db.execute_batch(&format!("DROP TABLE {table};")).unwrap();
    }
    let trigger: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=6;").unwrap();
    db.execute_batch(&trigger).unwrap();
    db.pragma_update(None, "user_version", 5).unwrap();
}

#[allow(dead_code)]
pub fn restore_v6(path: &std::path::Path) {
    restore_v7(path);
    let db = rusqlite::Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    // Reconstruct only the test database; product migration never downgrades.
    for line in include_str!("../../src/store/migration_007.sql").lines() {
        if let Some(table) = line.strip_prefix("CREATE TABLE ") {
            let table = table.split_whitespace().next().unwrap();
            db.execute_batch(&format!("DROP TABLE {table};")).unwrap();
        }
    }
    let trigger: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=7;").unwrap();
    db.execute_batch(&trigger).unwrap();
    db.pragma_update(None, "user_version", 6).unwrap();
}

#[allow(dead_code)]
pub fn restore_v7(path: &std::path::Path) {
    restore_v8(path);
    let db = rusqlite::Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    // Version 8 only adds schema objects. Reconstruct the published v7 schema
    // for upgrade tests; this helper is never linked into production code.
    for line in include_str!("../../src/store/migration_008.sql").lines() {
        for kind in ["TABLE", "INDEX", "TRIGGER"] {
            if let Some(definition) = line.strip_prefix(&format!("CREATE {kind} ")) {
                let name = definition.split_whitespace().next().unwrap();
                db.execute_batch(&format!("DROP {kind} IF EXISTS {name};"))
                    .unwrap();
            }
        }
    }
    let trigger: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=8;").unwrap();
    db.execute_batch(&trigger).unwrap();
    db.pragma_update(None, "user_version", 7).unwrap();
}

#[allow(dead_code)]
pub fn restore_v8(path: &std::path::Path) {
    restore_v9(path);
    let db = rusqlite::Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    // Schema 9 adds empty provenance storage; test-only reconstruction removes
    // its objects while preserving every previously published schema object.
    for line in include_str!("../../src/store/migration_009.sql").lines() {
        for kind in ["TABLE", "INDEX", "TRIGGER"] {
            if let Some(definition) = line.strip_prefix(&format!("CREATE {kind} ")) {
                let name = definition.split_whitespace().next().unwrap();
                db.execute_batch(&format!("DROP {kind} IF EXISTS {name};"))
                    .unwrap();
            }
        }
    }
    let trigger: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=9;").unwrap();
    db.execute_batch(&trigger).unwrap();
    db.pragma_update(None, "user_version", 8).unwrap();
}

#[allow(dead_code)]
pub fn restore_v9(path: &std::path::Path) {
    restore_v10(path);
    let db = rusqlite::Connection::open(path).unwrap();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    if version == 9 {
        return;
    }
    assert_eq!(version, 10);
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    // Reconstruct only the published schema for migration tests. No retained
    // work, delivery, quota or provenance rows are changed by this helper.
    for line in include_str!("../../src/store/migration_010.sql").lines() {
        for kind in ["INDEX", "TRIGGER"] {
            if let Some(definition) = line.strip_prefix(&format!("CREATE {kind} ")) {
                let name = definition.split_whitespace().next().unwrap();
                db.execute_batch(&format!("DROP {kind} IF EXISTS {name};"))
                    .unwrap();
            }
        }
    }
    // Schema 10 broadens these indexes. Restore their exact original SQL,
    // rather than recreating an equivalent but different schema fingerprint.
    for name in [
        "authority_signing_quota_transition_root_held",
        "authority_signing_quota_transition_project_held",
    ] {
        let prefix = format!("CREATE INDEX {name} ");
        let (_, body) = include_str!("../../src/store/migration_008.sql")
            .split_once(&prefix)
            .unwrap();
        let (definition, _) = body.split_once(';').unwrap();
        db.execute_batch(&format!("{prefix}{definition};")).unwrap();
    }
    // The new identity protections also replace two v8 trigger bodies. The
    // CREATE scan above removes their v10 definitions along with new guards;
    // restore the published statements verbatim for a genuine v9 fixture.
    for name in [
        "authority_signing_quota_transition_heads_update",
        "authority_signing_quota_transitions_membership",
    ] {
        let prefix = format!("CREATE TRIGGER {name} ");
        let (_, body) = include_str!("../../src/store/migration_008.sql")
            .split_once(&prefix)
            .unwrap();
        let (definition, _) = body.split_once("END;").unwrap();
        db.execute_batch(&format!("{prefix}{definition}END;"))
            .unwrap();
    }
    let trigger: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=10;").unwrap();
    db.execute_batch(&trigger).unwrap();
    db.pragma_update(None, "user_version", 9).unwrap();
}

/// Reconstruct published schema10 metadata without changing retained source rows.
/// This is a downgrade fixture builder, not evidence from an old binary.
#[allow(dead_code)]
pub fn restore_v10(path: &std::path::Path) {
    restore_v11(path);
    let db = rusqlite::Connection::open(path).unwrap();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    if version <= 10 {
        return;
    }
    assert_eq!(version, 11);
    let reference = reference_v10();
    let triggers = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='trigger'")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for name in triggers {
        db.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
    }
    db.execute_batch("DROP TABLE IF EXISTS authority_signing_work_audits; DROP INDEX IF EXISTS authority_signing_work_audit_candidates; DROP INDEX IF EXISTS authority_signing_reservation_intent_lookup; DELETE FROM authority_schema_migrations WHERE version>10;").unwrap();
    let definitions = reference
        .prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for sql in definitions {
        db.execute_batch(&sql).unwrap();
    }
    db.pragma_update(None, "user_version", 10).unwrap();
}

fn reference_v10() -> rusqlite::Connection {
    let reference = rusqlite::Connection::open_in_memory().unwrap();
    reference
        .execute_batch(include_str!("../../src/store/schema.sql"))
        .unwrap();
    for table in [
        "authority_metadata",
        "authority_principals",
        "authority_requirements",
        "authority_requirement_roles",
        "authority_plans",
        "authority_plan_retirements",
        "authority_evidence",
        "authority_decisions",
        "authority_audit",
    ] {
        reference.execute_batch(&format!("CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'immutable authority record'); END; CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'immutable authority record'); END;")).unwrap();
    }
    for table in [
        "authority_credentials",
        "authority_roles",
        "authority_challenges",
        "authority_activations",
    ] {
        reference.execute_batch(&format!("CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'retained authority record'); END;")).unwrap();
    }
    for sql in [
        include_str!("../../src/store/migration_002.sql"),
        include_str!("../../src/store/migration_003.sql"),
        include_str!("../../src/store/migration_004.sql"),
        include_str!("../../src/store/migration_005.sql"),
    ] {
        reference.execute_batch(sql).unwrap();
    }
    for table in [
        "authority_target_keys",
        "authority_target_key_revocations",
        "authority_target_pins",
        "authority_target_challenges",
        "authority_target_metadata",
    ] {
        reference.execute_batch(&format!("CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'immutable target evidence'); END; CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'retained target evidence'); END;")).unwrap();
    }
    reference
        .execute_batch(include_str!("../../src/store/migration_006.sql"))
        .unwrap();
    for table in [
        "authority_native_pins",
        "authority_native_pin_revocations",
        "authority_native_observer_keys",
        "authority_native_observer_revocations",
        "authority_native_compilations",
        "authority_native_challenges",
        "authority_native_observations",
    ] {
        reference.execute_batch(&format!("CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'immutable native evidence'); END; CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'retained native evidence'); END;")).unwrap();
    }
    for sql in [
        include_str!("../../src/store/migration_007.sql"),
        include_str!("../../src/store/migration_008.sql"),
        include_str!("../../src/store/migration_009.sql"),
        include_str!("../../src/store/migration_010.sql"),
    ] {
        reference.execute_batch(sql).unwrap();
    }
    reference
}

/// Reverse only the three structural table changes; null-root/v2 data cannot
/// be represented in released schemas and is deliberately refused.
#[allow(dead_code)]
pub fn restore_v11(path: &std::path::Path) {
    restore_v12(path);
    let mut db = rusqlite::Connection::open(path).unwrap();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    if version <= 11 {
        return;
    }
    assert_eq!(version, 12);
    for table in [
        "authority_signing_quota_pins",
        "authority_signing_quota_reservations",
        "authority_signing_quota_transition_heads",
    ] {
        assert!(
            !db.query_row::<bool, _, _>(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE root_id IS NULL)"),
                [],
                |r| r.get(0)
            )
            .unwrap(),
            "cannot reconstruct rooted legacy schema with rootless data"
        );
    }
    let reference = reference_v10();
    reference
        .execute_batch(include_str!("../../src/store/migration_011.sql"))
        .unwrap();
    reference
        .execute_batch(include_str!(
            "../../src/store/migration_011_work_bindings.sql"
        ))
        .unwrap();
    reference
        .execute_batch(include_str!("../../src/store/migration_011_work.sql"))
        .unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    let tx = db.transaction().unwrap();
    let triggers = tx
        .prepare("SELECT name FROM sqlite_schema WHERE type='trigger'")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for name in triggers {
        tx.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
    }
    for table in [
        "authority_signing_quota_pins",
        "authority_signing_quota_reservations",
        "authority_signing_quota_transition_heads",
    ] {
        let columns = reference
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let columns = std::iter::once("rowid".to_owned())
            .chain(columns)
            .collect::<Vec<_>>()
            .join(",");
        let create: String = reference
            .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [table], |r| {
                r.get(0)
            })
            .unwrap();
        tx.execute_batch(&format!("CREATE TABLE {table}_legacy_copy AS SELECT {columns} FROM {table}; DROP TABLE {table}; {create}; INSERT INTO {table}({columns}) SELECT {columns} FROM {table}_legacy_copy; DROP TABLE {table}_legacy_copy;")).unwrap();
        let indexes=reference.prepare("SELECT sql FROM sqlite_schema WHERE type='index' AND tbl_name=? AND sql IS NOT NULL ORDER BY name").unwrap().query_map([table],|r|r.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        for sql in indexes {
            tx.execute_batch(&sql).unwrap();
        }
    }
    tx.execute(
        "DELETE FROM authority_schema_migrations WHERE version=12",
        [],
    )
    .unwrap();
    let definitions = reference
        .prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for sql in definitions {
        tx.execute_batch(&sql).unwrap();
    }
    assert!(
        !tx.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |r| r.get(0)
        )
        .unwrap()
    );
    tx.pragma_update(None, "user_version", 11).unwrap();
    tx.commit().unwrap();
    db.pragma_update(None, "foreign_keys", "ON").unwrap();
}

/// Reconstruct exact released schema12 guards and indexes around unchanged
/// retained rows. This is fixture metadata reconstruction, not an old binary.
#[allow(dead_code)]
pub fn restore_v12(path: &std::path::Path) {
    restore_v13(path);
    let mut db = rusqlite::Connection::open(path).unwrap();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    if version <= 12 {
        return;
    }
    assert_eq!(version, 13);
    let reference = reference_v10();
    for sql in [
        include_str!("../../src/store/migration_011.sql"),
        include_str!("../../src/store/migration_011_work_bindings.sql"),
        include_str!("../../src/store/migration_011_work.sql"),
    ] {
        reference.execute_batch(sql).unwrap();
    }
    let guards = reference
        .prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for (name, _) in &guards {
        reference
            .execute_batch(&format!("DROP TRIGGER {name}"))
            .unwrap();
    }
    reference
        .execute_batch(include_str!("../../src/store/migration_012.sql"))
        .unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    let tx = db.transaction().unwrap();
    let triggers = tx
        .prepare("SELECT name FROM sqlite_schema WHERE type='trigger'")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for name in triggers {
        tx.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
    }
    let indexes = tx
        .prepare("SELECT name FROM sqlite_schema WHERE type='index' AND sql IS NOT NULL")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for name in indexes {
        let retained: bool = reference
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?)",
                [&name],
                |r| r.get(0),
            )
            .unwrap();
        if !retained {
            tx.execute_batch(&format!("DROP INDEX {name}")).unwrap();
        }
    }
    tx.execute(
        "DELETE FROM authority_schema_migrations WHERE version=13",
        [],
    )
    .unwrap();
    for (name, sql) in guards {
        let sql = match name.as_str() {
            "authority_signing_quota_transition_heads_insert" => {
                sql.replace("r.root_id=NEW.root_id", "r.root_id IS NEW.root_id")
            }
            "authority_signing_quota_transition_heads_update" => {
                sql.replace("NEW.root_id!=OLD.root_id", "NEW.root_id IS NOT OLD.root_id")
            }
            _ => sql,
        };
        tx.execute_batch(&sql).unwrap();
    }
    tx.pragma_update(None, "user_version", 12).unwrap();
    tx.commit().unwrap();
    db.pragma_update(None, "foreign_keys", "ON").unwrap();
}

/// Reconstruct published schema13 around unchanged legacy rows. Removing a
/// populated window would erase new authority evidence and is never allowed.
#[allow(dead_code)]
pub fn restore_v13(path: &std::path::Path) {
    let db = rusqlite::Connection::open(path).unwrap();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    if version <= 13 {
        return;
    }
    assert_eq!(version, 14);
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM authority_core_access_lease_windows",
            [],
            |row| row.get(0),
        )
        .unwrap(),
        0,
        "cannot reconstruct schema13 while new lease-window evidence exists"
    );
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    let guard: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_schema_migrations_no_delete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TABLE authority_core_access_lease_windows; DROP TRIGGER authority_schema_migrations_no_delete; DELETE FROM authority_schema_migrations WHERE version=14;").unwrap();
    db.execute_batch(&guard).unwrap();
    db.pragma_update(None, "user_version", 13).unwrap();
    db.pragma_update(None, "foreign_keys", "ON").unwrap();
}
