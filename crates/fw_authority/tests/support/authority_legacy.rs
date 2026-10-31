//! Test-only reconstruction of the previously published schema. Product APIs
//! do not expose schema downgrade or erase authority records.
pub fn restore_v2(path: &std::path::Path) {
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
