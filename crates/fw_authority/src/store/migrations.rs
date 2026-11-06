use super::*;
use rusqlite::{
    OpenFlags,
    backup::{Backup, StepResult},
};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const MIGRATION_2: &str = include_str!("migration_002.sql");
const MIGRATION_3: &str = include_str!("migration_003.sql");
const MIGRATION_4: &str = include_str!("migration_004.sql");
const MIGRATION_5: &str = include_str!("migration_005.sql");
const MIGRATION_6: &str = include_str!("migration_006.sql");
const MIGRATION_7: &str = include_str!("migration_007.sql");
const MIGRATION_8: &str = include_str!("migration_008.sql");
const MIGRATION_9: &str = include_str!("migration_009.sql");
const MIGRATION_10: &str = include_str!("migration_010.sql");
const MIGRATION_11: &str = include_str!("migration_011.sql");
const MIGRATION_12: &str = include_str!("migration_012.sql");
const MIGRATION_13: &str = include_str!("migration_013.sql");
const MIGRATION_14: &str = include_str!("migration_014.sql");
const MIGRATION_15: &str = include_str!("migration_015.sql");
const MIGRATION_16: &str = include_str!("migration_016.sql");
#[cfg(test)]
#[path = "origin_migration_tests.rs"]
mod origin_migration_tests;

fn normalized_path(path: &Path) -> Result<std::path::PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| invalid("authority backup filename"))?;
    // A deliberately narrow maintenance profile: do not approximate a volume's
    // Unicode normalization/case rules when a destination does not exist yet.
    if !name.as_encoded_bytes().is_ascii() {
        return Err(invalid("authority migration requires ASCII filenames"));
    }
    Ok(fs::canonicalize(parent)
        .map_err(|_| invalid("authority backup directory"))?
        .join(name))
}

fn collides(left: &Path, right: &Path) -> Result<bool> {
    if !left
        .file_name()
        .unwrap()
        .as_encoded_bytes()
        .eq_ignore_ascii_case(right.file_name().unwrap().as_encoded_bytes())
    {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let left = fs::metadata(left.parent().unwrap())
            .map_err(|_| invalid("authority backup directory"))?;
        let right = fs::metadata(right.parent().unwrap())
            .map_err(|_| invalid("authority backup directory"))?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
    #[cfg(not(unix))]
    {
        // Until a native directory-identity adapter exists, reject matching
        // basenames across directories too rather than guess alias identity.
        Ok(true)
    }
}

fn database_files(path: &Path) -> Vec<std::path::PathBuf> {
    let mut paths = vec![path.to_path_buf()];
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        paths.push(name.into());
    }
    paths
}

// Run before opening either SQLite connection: recovery can change a sidecar
// even without an explicit application write. The destination's own sidecars
// must also be new; stale journal bytes must never control its first open.
fn backup_paths(path: &Path, backup: &Path) -> Result<()> {
    let source = database_files(&normalized_path(path)?);
    let mut destination = database_files(&normalized_path(backup)?);
    destination.push(normalized_path(&backup.with_extension("manifest.json"))?);
    for (index, candidate) in destination.iter().enumerate() {
        for other in source.iter().chain(&destination[..index]) {
            if collides(candidate, other)? {
                return Err(invalid("authority backup overlaps database files"));
            }
        }
    }
    // Reject all existing destination files, including dangling final symlinks,
    // before SQLite can recover the source or we create an orphan backup.
    // create_new below still enforces no-overwrite if a name appears afterward.
    for path in &destination {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(invalid(
                    "authority backup destination already exists or unavailable",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn initialize_v1(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(include_str!("schema.sql"))?;
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
        tx.execute_batch(&format!(
            "CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'immutable authority record'); END;
                         CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'immutable authority record'); END;"
        ))?;
    }
    for table in [
        "authority_credentials",
        "authority_roles",
        "authority_challenges",
        "authority_activations",
    ] {
        tx.execute_batch(&format!(
            "CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'retained authority record'); END;"
        ))?;
    }
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    tx.pragma_update(None, "user_version", 1)?;
    Ok(())
}

// Include every SQLite object, including autoindexes. Reserved-looking names
// confer no trust. The two optional ANALYZE tables have exact engine-owned
// metadata; injected objects with another type/table/SQL are rejected.
fn schema_digest(connection: &Connection) -> Result<Vec<u8>> {
    let mut stmt = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name LIMIT 4097",
    )?;
    let mut rows = stmt.query([])?;
    let mut inventory = Vec::new();
    let mut objects_seen = 0;
    let mut metadata_bytes = 0usize;
    while let Some(row) = rows.next()? {
        objects_seen += 1;
        if objects_seen > 4096 {
            return Err(invalid("authority schema object bound"));
        }
        for column in 0..4 {
            let value = row.get_ref(column)?;
            if let Ok(bytes) = value.as_bytes() {
                if bytes.len() > if column == 3 { 262144 } else { 256 } {
                    return Err(invalid("authority schema metadata bound"));
                }
                metadata_bytes = metadata_bytes
                    .checked_add(bytes.len())
                    .ok_or(invalid("authority schema metadata bound"))?;
                if metadata_bytes > 4 * 1024 * 1024 {
                    return Err(invalid("authority schema metadata bound"));
                }
            }
        }
        let object = (
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
        );
        if object.1 == "sqlite_stat1" || object.1 == "sqlite_stat4" {
            let sql = if object.1 == "sqlite_stat1" {
                "CREATE TABLE sqlite_stat1(tbl,idx,stat)"
            } else {
                "CREATE TABLE sqlite_stat4(tbl,idx,neq,nlt,ndlt,sample)"
            };
            if object.0 != "table" || object.2 != object.1 || object.3.as_deref() != Some(sql) {
                return Err(invalid("unexpected SQLite statistics object"));
            }
            continue;
        }
        inventory.push(object);
    }
    hash(&canonical_hash(&inventory).map_err(|_| invalid("authority schema manifest"))?)
}

// Migration 1's published checksum predates complete SQLite object inventories.
// Keep its historical value, independently of the stricter current comparison.
fn historical_v1_checksum() -> Result<Vec<u8>> {
    static DIGEST: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    if let Some(digest) = DIGEST.get() {
        return Ok(digest.clone());
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    let mut stmt=tx.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE lower(substr(name,1,7)) <> 'sqlite_' ORDER BY type,name")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let digest =
        hash(&canonical_hash(&rows).map_err(|_| invalid("historical authority manifest"))?)?;
    let _ = DIGEST.set(digest.clone());
    Ok(digest)
}

fn known_v1_digest() -> Result<Vec<u8>> {
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    schema_digest(&tx)
}

fn known_v2_digest() -> Result<Vec<u8>> {
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    tx.execute_batch(MIGRATION_2)?;
    schema_digest(&tx)
}

fn known_v3_digest() -> Result<Vec<u8>> {
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    tx.execute_batch(MIGRATION_2)?;
    tx.execute_batch(MIGRATION_3)?;
    schema_digest(&tx)
}

fn known_v4_digest() -> Result<Vec<u8>> {
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    tx.execute_batch(MIGRATION_2)?;
    tx.execute_batch(MIGRATION_3)?;
    tx.execute_batch(MIGRATION_4)?;
    schema_digest(&tx)
}

fn known_v5_digest() -> Result<Vec<u8>> {
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    schema_digest(&tx)
}

fn known_v6_digest() -> Result<Vec<u8>> {
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    schema_digest(&tx)
}
fn known_v7_digest() -> Result<Vec<u8>> {
    static DIGEST: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    if let Some(digest) = DIGEST.get() {
        return Ok(digest.clone());
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    let digest = schema_digest(&tx)?;
    let _ = DIGEST.set(digest.clone());
    Ok(digest)
}

fn known_v8_digest() -> Result<Vec<u8>> {
    static DIGEST: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    if let Some(digest) = DIGEST.get() {
        return Ok(digest.clone());
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    let digest = schema_digest(&tx)?;
    let _ = DIGEST.set(digest.clone());
    Ok(digest)
}

fn known_v9_digest() -> Result<Vec<u8>> {
    static DIGEST: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    if let Some(digest) = DIGEST.get() {
        return Ok(digest.clone());
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    tx.execute_batch(MIGRATION_9)?;
    let digest = schema_digest(&tx)?;
    let _ = DIGEST.set(digest.clone());
    Ok(digest)
}

struct SigningSchema {
    digest: Vec<u8>,
    guards: Vec<(String, String)>,
}

fn known_v10() -> Result<&'static SigningSchema> {
    static SCHEMA: std::sync::OnceLock<SigningSchema> = std::sync::OnceLock::new();
    if let Some(schema) = SCHEMA.get() {
        return Ok(schema);
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    tx.execute_batch(MIGRATION_9)?;
    tx.execute_batch(MIGRATION_10)?;
    let digest = schema_digest(&tx)?;
    // Keep one exact reference for schema validation and the bounded live
    // signing guard check. Never derive expected protection from the live DB.
    let mut statement = tx.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND substr(name,1,18)='authority_signing_' ORDER BY name")?;
    let guards = statement
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let _ = SCHEMA.set(SigningSchema { digest, guards });
    SCHEMA.get().ok_or(invalid("known signing schema"))
}

fn known_v10_digest() -> Result<Vec<u8>> {
    Ok(known_v10()?.digest.clone())
}

#[cfg(test)]
pub(super) fn signing_guard_definitions() -> Result<&'static [(String, String)]> {
    Ok(&known_v16()?.guards)
}

fn migration_11_checksum() -> Result<Vec<u8>> {
    let sql = [
        MIGRATION_11,
        signing_jobs::MIGRATION_WORK_BINDINGS,
        signing_jobs::MIGRATION_WORK,
    ]
    .concat();
    hash(&hash_bytes(sql.as_bytes()))
}

fn known_v11() -> Result<&'static SigningSchema> {
    static SCHEMA: std::sync::OnceLock<SigningSchema> = std::sync::OnceLock::new();
    if let Some(schema) = SCHEMA.get() {
        return Ok(schema);
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    tx.execute_batch(MIGRATION_9)?;
    tx.execute_batch(MIGRATION_10)?;
    tx.execute_batch(MIGRATION_11)?;
    signing_jobs::backfill_work_audits(&tx)?;
    tx.execute_batch(signing_jobs::MIGRATION_WORK)?;
    let digest = schema_digest(&tx)?;
    let mut stmt =
        tx.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")?;
    let guards = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let _ = SCHEMA.set(SigningSchema { digest, guards });
    SCHEMA.get().ok_or(invalid("known authority schema"))
}

/// Bounded metadata-only validation for already-open sensitive transactions.
/// Expected bytes are built once from released SQL, never from the live store.
pub(super) fn validate_live_schema(connection: &Connection) -> Result<()> {
    if schema_digest(connection)? != known_v16()?.digest {
        return Err(invalid("authority integrity guard missing or changed"));
    }
    Ok(())
}

pub(super) fn validate_reference_graph(connection: &Connection) -> Result<()> {
    let broken: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority retained foreign key graph"));
    }
    let broken: bool = connection.query_row("SELECT EXISTS(
        SELECT 1 FROM authority_signing_intents i LEFT JOIN authority_signing_jobs j
        ON j.org_id=i.org_id AND j.project_id=i.project_id AND j.job_id=i.job_id AND j.intent_id=i.intent_id
        WHERE j.job_id IS NULL UNION ALL
        SELECT 1 FROM authority_signing_jobs j LEFT JOIN authority_signing_intents i
        ON i.org_id=j.org_id AND i.project_id=j.project_id AND i.intent_id=j.intent_id AND i.job_id=j.job_id
        WHERE i.intent_id IS NULL UNION ALL
        SELECT 1 FROM authority_signing_jobs j WHERE NOT EXISTS(SELECT 1 FROM authority_signing_work_heads h
        WHERE h.org_id=j.org_id AND h.project_id=j.project_id AND h.job_id=j.job_id AND h.phase='signer')
        )", [], |r| r.get(0))?;
    if broken {
        return Err(invalid("authority signing retained reference graph"));
    }
    // FKs retain binding→event, while the inverse must also hold after an
    // out-of-band writer restores guards around a missing or changed binding.
    // Pre11 histories acquire bindings only during validated migration.
    let bound:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='authority_signing_work_audits')",[],|r|r.get(0))?;
    if bound {
        let broken:bool=connection.query_row("SELECT EXISTS(
            SELECT 1 FROM authority_signing_work_events e WHERE NOT EXISTS(
             SELECT 1 FROM authority_signing_work_audits b JOIN authority_audit a
              ON a.org_id=b.org_id AND a.project_id=b.project_id AND a.sequence=b.audit_sequence AND a.event_hash=b.audit_hash
             WHERE b.org_id=e.org_id AND b.project_id=e.project_id AND b.job_id=e.job_id AND b.phase=e.phase AND b.revision=e.revision
              AND b.kind=e.kind AND b.updated_at=e.updated_at AND a.resource_id=e.job_id
              AND a.kind='signing_'||e.phase||'_'||e.kind AND a.recorded_at=e.updated_at))",[],|r|r.get(0))?;
        if broken {
            return Err(invalid("authority signing retained audit binding"));
        }
    }
    Ok(())
}

pub(super) fn apply_v11(tx: &Transaction<'_>) -> Result<()> {
    validate_v10(tx)?;
    validate_reference_graph(tx)?;
    validate_retained_integrity(tx)?;
    tx.execute_batch(MIGRATION_11)?;
    signing_jobs::backfill_work_audits(tx)?;
    tx.execute_batch(signing_jobs::MIGRATION_WORK)?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(11,?,11,11,?)",
        params![migration_11_checksum()?, now()?],
    )?;
    tx.pragma_update(None, "user_version", 11)?;
    validate_v11(tx)
}

fn validate_retained_integrity(tx: &Transaction<'_>) -> Result<()> {
    validate_reference_graph(tx)?;
    signing_quota::validate_lifecycle_reservation_graph(tx)?;
    // Every job lifecycle below verifies both complete work histories. Keep
    // the global inverse audit check here so unknown-resource audit rows cannot
    // hide outside any job, without replaying every valid history twice.
    signing_jobs::validate_retained_work_audits(tx)?;
    validate_retained_signing_lifecycles(tx)?;
    audit_log::validate_retained_chains(tx)
}

fn validate_v11_schema(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 11)?;
    if schema_digest(connection)? != known_v11()?.digest {
        return Err(invalid("unexpected authority v11 schema"));
    }
    Ok(())
}
pub(super) fn validate_v11(connection: &Connection) -> Result<()> {
    validate_v11_schema(connection)?;
    validate_reference_graph(connection)
}

const REBUILT_QUOTA_TABLES: [&str; 3] = [
    "authority_signing_quota_pins",
    "authority_signing_quota_reservations",
    "authority_signing_quota_transition_heads",
];

fn table_fingerprint(tx: &Transaction<'_>, table: &str) -> Result<([u8; 32], u64)> {
    let mut stmt = tx.prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))?;
    let columns = stmt.column_count();
    let mut rows = stmt.query([])?;
    let mut digest = Sha256::new();
    let mut count = 0u64;
    while let Some(row) = rows.next()? {
        count = count.checked_add(1).ok_or(invalid("migration row bound"))?;
        digest.update([255]);
        for column in 0..columns {
            use rusqlite::types::ValueRef;
            match row.get_ref(column)? {
                ValueRef::Null => digest.update([0]),
                ValueRef::Integer(value) => {
                    digest.update([1]);
                    digest.update(value.to_be_bytes());
                }
                ValueRef::Real(value) => {
                    digest.update([2]);
                    digest.update(value.to_bits().to_be_bytes());
                }
                ValueRef::Text(value) => {
                    digest.update([3]);
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value);
                }
                ValueRef::Blob(value) => {
                    digest.update([4]);
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value);
                }
            }
        }
    }
    digest.update(count.to_be_bytes());
    Ok((digest.finalize().into(), count))
}

fn nullable_guard(name: &str, sql: &str) -> String {
    match name {
        "authority_signing_quota_transition_heads_insert" => {
            sql.replace("r.root_id=NEW.root_id", "r.root_id IS NEW.root_id")
        }
        "authority_signing_quota_transition_heads_update" => {
            sql.replace("NEW.root_id!=OLD.root_id", "NEW.root_id IS NOT OLD.root_id")
        }
        _ => sql.to_owned(),
    }
}

fn rebuild_v12_schema(tx: &Transaction<'_>) -> Result<()> {
    // Every definition comes from the separately constructed version11 schema.
    // Removing all guards also covers references from incoming work/audit FKs;
    // no definitions are copied from the possibly attacked maintenance source.
    let before = REBUILT_QUOTA_TABLES
        .map(|table| table_fingerprint(tx, table))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    for (name, _) in &known_v11()?.guards {
        tx.execute_batch(&format!("DROP TRIGGER {name}"))?;
    }
    migration_failpoint("guards-dropped")?;
    // Execute one statement at a time so crash/error fixtures cover the actual
    // copy/drop/recreate/copy-back boundaries, not a simulation of the rebuild.
    for statement in MIGRATION_12.split(';').filter(|sql| !sql.trim().is_empty()) {
        tx.execute_batch(&format!("{statement};"))?;
        let sql = statement.trim();
        if sql.starts_with("CREATE TABLE") && sql.contains("_retained_v12 AS") {
            migration_failpoint("rows-copied")?;
        }
        if sql.starts_with("DROP TABLE authority_signing_quota_") && !sql.contains("_retained_v12")
        {
            migration_failpoint("parent-dropped")?;
        }
        if sql.starts_with("INSERT INTO authority_signing_quota_") {
            migration_failpoint("rows-restored")?;
        }
    }
    for (name, sql) in &known_v11()?.guards {
        tx.execute_batch(&nullable_guard(name, sql))?;
    }
    migration_failpoint("guards-restored")?;
    for (table, before) in REBUILT_QUOTA_TABLES.into_iter().zip(before) {
        if table_fingerprint(tx, table)? != before {
            return Err(invalid(
                "authority migration changed retained quota bytes or rowids",
            ));
        }
    }
    Ok(())
}

fn known_v12() -> Result<&'static SigningSchema> {
    static SCHEMA: std::sync::OnceLock<SigningSchema> = std::sync::OnceLock::new();
    if let Some(schema) = SCHEMA.get() {
        return Ok(schema);
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    tx.execute_batch(MIGRATION_9)?;
    tx.execute_batch(MIGRATION_10)?;
    tx.execute_batch(MIGRATION_11)?;
    signing_jobs::backfill_work_audits(&tx)?;
    tx.execute_batch(signing_jobs::MIGRATION_WORK)?;
    // Reference construction has no application state or active FK enforcement.
    rebuild_v12_schema(&tx)?;
    let digest = schema_digest(&tx)?;
    let mut stmt =
        tx.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")?;
    let guards = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let _ = SCHEMA.set(SigningSchema { digest, guards });
    SCHEMA.get().ok_or(invalid("known authority schema12"))
}

pub(super) fn apply_v12(tx: &Transaction<'_>) -> Result<()> {
    validate_v11(tx)?;
    validate_retained_integrity(tx)?;
    let enforced: i64 = tx.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
    let populated:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_quota_reservations) OR EXISTS(SELECT 1 FROM authority_signing_quota_pins)",[],|r|r.get(0))?;
    if enforced != 0 && populated {
        return Err(invalid(
            "populated quota rebuild requires dedicated FK-disabled maintenance",
        ));
    }
    rebuild_v12_schema(tx)?;
    validate_retained_integrity(tx)?;
    let integrity: String = tx.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if integrity != "ok" {
        return Err(invalid("authority migration integrity check"));
    }
    migration_failpoint("references-verified")?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(12,?,12,12,?)",
        params![hash(&hash_bytes(MIGRATION_12.as_bytes()))?, now()?],
    )?;
    tx.pragma_update(None, "user_version", 12)?;
    migration_failpoint("version-recorded")?;
    validate_v12(tx)
}

pub(super) fn validate_v12(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 12)?;
    if schema_digest(connection)? != known_v12()?.digest {
        return Err(invalid("unexpected authority v12 schema"));
    }
    validate_reference_graph(connection)
}

fn known_v13() -> Result<&'static SigningSchema> {
    static SCHEMA: std::sync::OnceLock<SigningSchema> = std::sync::OnceLock::new();
    if let Some(schema) = SCHEMA.get() {
        return Ok(schema);
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    tx.execute_batch(MIGRATION_9)?;
    tx.execute_batch(MIGRATION_10)?;
    tx.execute_batch(MIGRATION_11)?;
    signing_jobs::backfill_work_audits(&tx)?;
    tx.execute_batch(signing_jobs::MIGRATION_WORK)?;
    rebuild_v12_schema(&tx)?;
    tx.execute_batch(MIGRATION_13)?;
    let digest = schema_digest(&tx)?;
    let mut stmt =
        tx.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")?;
    let guards = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let _ = SCHEMA.set(SigningSchema { digest, guards });
    SCHEMA.get().ok_or(invalid("known authority schema13"))
}

fn known_v14() -> Result<&'static SigningSchema> {
    static SCHEMA: std::sync::OnceLock<SigningSchema> = std::sync::OnceLock::new();
    if let Some(schema) = SCHEMA.get() {
        return Ok(schema);
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    tx.execute_batch(MIGRATION_9)?;
    tx.execute_batch(MIGRATION_10)?;
    tx.execute_batch(MIGRATION_11)?;
    signing_jobs::backfill_work_audits(&tx)?;
    tx.execute_batch(signing_jobs::MIGRATION_WORK)?;
    rebuild_v12_schema(&tx)?;
    tx.execute_batch(MIGRATION_13)?;
    tx.execute_batch(MIGRATION_14)?;
    let digest = schema_digest(&tx)?;
    let mut stmt =
        tx.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")?;
    let guards = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let _ = SCHEMA.set(SigningSchema { digest, guards });
    SCHEMA.get().ok_or(invalid("known authority schema14"))
}

fn validate_physical_integrity(connection: &Connection) -> Result<()> {
    // Schema SQL equality does not prove that an index contains every row. A
    // writable_schema/REINDEX attack can restore the exact SQL after emptying
    // its B-tree. Never repair or rebuild source indexes while validating them.
    let integrity: String = connection.query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))?;
    if integrity != "ok" {
        return Err(invalid("authority retained physical integrity"));
    }
    Ok(())
}

pub(super) fn apply_v13(tx: &Transaction<'_>) -> Result<()> {
    validate_v12(tx)?;
    validate_physical_integrity(tx)?;
    validate_retained_integrity(tx)?;
    tx.execute_batch(MIGRATION_13)?;
    migration_failpoint("schema13-guards-created")?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(13,?,13,13,?)",
        params![hash(&hash_bytes(MIGRATION_13.as_bytes()))?, now()?],
    )?;
    tx.pragma_update(None, "user_version", 13)?;
    migration_failpoint("schema13-version-recorded")?;
    validate_v13(tx)
}

/// Current full validation is read-only and may run while WAL writers commit.
/// Every check sees the same SQLite snapshot; no index is repaired.
pub(super) fn validate_v13(tx: &Transaction<'_>) -> Result<()> {
    validate_migrations(tx, 13)?;
    if schema_digest(tx)? != known_v13()?.digest {
        return Err(invalid("unexpected authority v13 schema"));
    }
    validate_physical_integrity(tx)?;
    validate_retained_integrity(tx)
}

pub(super) fn apply_v14(tx: &Transaction<'_>) -> Result<()> {
    validate_v13(tx)?;
    tx.execute_batch(MIGRATION_14)?;
    migration_failpoint("schema14-window-created")?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(14,?,14,14,?)",
        params![hash(&hash_bytes(MIGRATION_14.as_bytes()))?, now()?],
    )?;
    tx.pragma_update(None, "user_version", 14)?;
    migration_failpoint("schema14-version-recorded")?;
    validate_v14(tx)
}

pub(super) fn validate_v14(tx: &Transaction<'_>) -> Result<()> {
    validate_migrations(tx, 14)?;
    if schema_digest(tx)? != known_v14()?.digest {
        return Err(invalid("unexpected authority v14 schema"));
    }
    #[cfg(test)]
    OPEN_VALIDATION_HOOK.with(|hook| {
        let callback = hook.borrow_mut().take();
        if let Some(callback) = callback {
            callback();
        }
    });
    validate_physical_integrity(tx)?;
    validate_retained_integrity(tx)?;
    access_window::validate_retained(tx)
}

fn create_registry_schema(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(MIGRATION_15)?;
    for table in [
        "authority_registry_keys",
        "authority_registry_key_revocations",
        "authority_registry_objects",
        "authority_registry_object_revocations",
        "authority_bootstrap_proofs",
    ] {
        tx.execute_batch(&format!("CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'immutable registry record'); END; CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'retained registry record'); END;"))?;
    }
    for table in [
        "authority_registry_clocks",
        "authority_workload_heads",
        "authority_bootstrap_challenges",
        "authority_bootstrap_pending_heads",
    ] {
        tx.execute_batch(&format!("CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'retained registry projection'); END;"))?;
    }
    for (table, identity) in [
        (
            "authority_registry_keys",
            "(org_id=NEW.org_id AND project_id=NEW.project_id AND key_id=NEW.key_id) OR (org_id=NEW.org_id AND key_fingerprint=NEW.key_fingerprint)",
        ),
        (
            "authority_registry_key_revocations",
            "org_id=NEW.org_id AND project_id=NEW.project_id AND key_id=NEW.key_id",
        ),
        (
            "authority_registry_objects",
            "org_id=NEW.org_id AND project_id=NEW.project_id AND ((object_kind=NEW.object_kind AND object_id=NEW.object_id) OR content_hash=NEW.content_hash)",
        ),
        (
            "authority_registry_object_revocations",
            "org_id=NEW.org_id AND project_id=NEW.project_id AND content_hash=NEW.content_hash",
        ),
        (
            "authority_registry_clocks",
            "org_id=NEW.org_id AND project_id=NEW.project_id",
        ),
        (
            "authority_workload_heads",
            "org_id=NEW.org_id AND project_id=NEW.project_id AND principal_id=NEW.principal_id AND target_id=NEW.target_id AND workload_id=NEW.workload_id",
        ),
        (
            "authority_bootstrap_challenges",
            "org_id=NEW.org_id AND project_id=NEW.project_id AND challenge_id=NEW.challenge_id",
        ),
        (
            "authority_bootstrap_proofs",
            "org_id=NEW.org_id AND project_id=NEW.project_id AND (proof_id=NEW.proof_id OR challenge_id=NEW.challenge_id OR proof_hash=NEW.proof_hash)",
        ),
        (
            "authority_bootstrap_pending_heads",
            "org_id=NEW.org_id AND project_id=NEW.project_id AND target_id=NEW.target_id",
        ),
    ] {
        tx.execute_batch(&format!("CREATE TRIGGER {table}_no_replace BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE rowid=NEW.rowid OR ({identity})) BEGIN SELECT RAISE(ABORT,'retained registry identity'); END;"))?;
    }
    tx.execute_batch("CREATE TRIGGER authority_registry_clock_monotone BEFORE UPDATE ON authority_registry_clocks WHEN NEW.rowid!=OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.observed_at<OLD.observed_at BEGIN SELECT RAISE(ABORT,'registry clock regression'); END;
        CREATE TRIGGER authority_workload_head_monotone BEFORE UPDATE ON authority_workload_heads WHEN NEW.rowid!=OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.principal_id!=OLD.principal_id OR NEW.target_id!=OLD.target_id OR NEW.workload_id!=OLD.workload_id OR NEW.binding_epoch<=OLD.binding_epoch BEGIN SELECT RAISE(ABORT,'workload epoch regression'); END;
        CREATE TRIGGER authority_bootstrap_pending_head_monotone BEFORE UPDATE ON authority_bootstrap_pending_heads WHEN NEW.rowid!=OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.target_id!=OLD.target_id OR NEW.authority_epoch<=OLD.authority_epoch BEGIN SELECT RAISE(ABORT,'bootstrap epoch regression'); END;
        CREATE TRIGGER authority_bootstrap_challenge_transition BEFORE UPDATE ON authority_bootstrap_challenges WHEN NEW.rowid!=OLD.rowid OR NEW.org_id!=OLD.org_id OR NEW.project_id!=OLD.project_id OR NEW.challenge_id!=OLD.challenge_id OR NEW.manifest_id!=OLD.manifest_id OR NEW.principal_id!=OLD.principal_id OR NEW.credential_id!=OLD.credential_id OR NEW.membership_id!=OLD.membership_id OR NEW.credential_revision!=OLD.credential_revision OR NEW.role_revision!=OLD.role_revision OR NEW.security_revision!=OLD.security_revision OR NEW.issued_at!=OLD.issued_at OR NEW.expires_at!=OLD.expires_at OR NEW.challenge_bytes!=OLD.challenge_bytes OR NEW.state_bytes!=OLD.state_bytes OR NEW.credential_bytes!=OLD.credential_bytes OR OLD.consumed_at IS NOT NULL OR NOT ((NEW.attempts=OLD.attempts+1 AND NEW.consumed_at IS NULL) OR (NEW.attempts=OLD.attempts AND NEW.consumed_at IS NOT NULL)) BEGIN SELECT RAISE(ABORT,'invalid bootstrap challenge transition'); END;")?;
    Ok(())
}

fn known_v15() -> Result<&'static SigningSchema> {
    static SCHEMA: std::sync::OnceLock<SigningSchema> = std::sync::OnceLock::new();
    if let Some(schema) = SCHEMA.get() {
        return Ok(schema);
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    tx.execute_batch(MIGRATION_9)?;
    tx.execute_batch(MIGRATION_10)?;
    tx.execute_batch(MIGRATION_11)?;
    signing_jobs::backfill_work_audits(&tx)?;
    tx.execute_batch(signing_jobs::MIGRATION_WORK)?;
    rebuild_v12_schema(&tx)?;
    tx.execute_batch(MIGRATION_13)?;
    tx.execute_batch(MIGRATION_14)?;
    create_registry_schema(&tx)?;
    let digest = schema_digest(&tx)?;
    let mut stmt =
        tx.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")?;
    let guards = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let _ = SCHEMA.set(SigningSchema { digest, guards });
    SCHEMA.get().ok_or(invalid("known authority schema15"))
}

pub(super) fn apply_v15(tx: &Transaction<'_>) -> Result<()> {
    validate_v14(tx)?;
    create_registry_schema(tx)?;
    migration_failpoint("schema15-registry-created")?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(15,?,15,15,?)",
        params![hash(&hash_bytes(MIGRATION_15.as_bytes()))?, now()?],
    )?;
    tx.pragma_update(None, "user_version", 15)?;
    migration_failpoint("schema15-version-recorded")?;
    validate_v15(tx)
}

pub(super) fn validate_v15(tx: &Transaction<'_>) -> Result<()> {
    validate_migrations(tx, 15)?;
    if schema_digest(tx)? != known_v15()?.digest {
        return Err(invalid("unexpected authority v15 schema"));
    }
    #[cfg(test)]
    OPEN_VALIDATION_HOOK.with(|hook| {
        let callback = hook.borrow_mut().take();
        if let Some(callback) = callback {
            callback();
        }
    });
    validate_physical_integrity(tx)?;
    validate_retained_integrity(tx)?;
    access_window::validate_retained(tx)?;
    authority_registry::validate_retained(tx)
}

fn known_v16() -> Result<&'static SigningSchema> {
    static SCHEMA: std::sync::OnceLock<SigningSchema> = std::sync::OnceLock::new();
    if let Some(schema) = SCHEMA.get() {
        return Ok(schema);
    }
    let mut memory = Connection::open_in_memory()?;
    let tx = memory.transaction()?;
    initialize_v1(&tx)?;
    apply_v2(&tx)?;
    apply_v3(&tx)?;
    apply_v4(&tx)?;
    apply_v5(&tx)?;
    apply_v6(&tx)?;
    apply_v7(&tx)?;
    tx.execute_batch(MIGRATION_8)?;
    tx.execute_batch(MIGRATION_9)?;
    tx.execute_batch(MIGRATION_10)?;
    tx.execute_batch(MIGRATION_11)?;
    signing_jobs::backfill_work_audits(&tx)?;
    tx.execute_batch(signing_jobs::MIGRATION_WORK)?;
    rebuild_v12_schema(&tx)?;
    tx.execute_batch(MIGRATION_13)?;
    tx.execute_batch(MIGRATION_14)?;
    create_registry_schema(&tx)?;
    tx.execute_batch(MIGRATION_16)?;
    let digest = schema_digest(&tx)?;
    let mut statement =
        tx.prepare("SELECT name,sql FROM sqlite_schema WHERE type='trigger' ORDER BY name")?;
    let guards = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let _ = SCHEMA.set(SigningSchema { digest, guards });
    SCHEMA.get().ok_or(invalid("known authority schema16"))
}

pub(super) fn apply_v16(tx: &Transaction<'_>) -> Result<()> {
    validate_v15(tx)?;
    tx.execute_batch(MIGRATION_16)?;
    migration_failpoint("schema16-authority-created")?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(16,?,16,16,?)",
        params![hash(&hash_bytes(MIGRATION_16.as_bytes()))?, now()?],
    )?;
    tx.pragma_update(None, "user_version", 16)?;
    migration_failpoint("schema16-version-recorded")?;
    validate_v16(tx)
}

pub(super) fn validate_v16(tx: &Transaction<'_>) -> Result<()> {
    validate_migrations(tx, 16)?;
    validate_live_schema(tx)?;
    #[cfg(test)]
    OPEN_VALIDATION_HOOK.with(|hook| {
        let callback = hook.borrow_mut().take();
        if let Some(callback) = callback {
            callback();
        }
    });
    validate_physical_integrity(tx)?;
    validate_retained_integrity(tx)?;
    access_window::validate_retained(tx)?;
    authority_registry::validate_retained(tx)?;
    bootstrap_origin::validate_retained(tx)?;
    target_bootstrap_validation::validate_retained(tx)
}

#[cfg(test)]
thread_local! {
    pub(super) static OPEN_VALIDATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {std::cell::RefCell::new(None)};
}

#[cfg(not(test))]
fn migration_failpoint(_stage: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
thread_local! {
    static MIGRATION_FAILURE: std::cell::RefCell<Option<&'static str>> = const {std::cell::RefCell::new(None)};
    static MIGRATION_CRASH: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
    static MIGRATION_FK_RESTORED: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
}
#[cfg(test)]
fn migration_failpoint(stage: &str) -> Result<()> {
    if MIGRATION_FAILURE.with(|requested| {
        requested
            .borrow()
            .is_some_and(|requested| requested == stage)
    }) {
        if MIGRATION_CRASH.with(|crash| crash.get()) {
            std::process::exit(89);
        }
        return Err(invalid("injected authority migration failure"));
    }
    Ok(())
}

fn validate_retained_signing_lifecycles(tx: &Transaction<'_>) -> Result<()> {
    let mut statement = tx.prepare("SELECT CASE WHEN length(j.org_id)=36 THEN j.org_id END,CASE WHEN length(j.project_id)=36 THEN j.project_id END,CASE WHEN length(j.job_id)=36 THEN j.job_id END,(SELECT MAX(e.updated_at) FROM authority_signing_work_events e WHERE e.org_id=j.org_id AND e.project_id=j.project_id AND e.job_id=j.job_id) FROM authority_signing_jobs j")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let job: String = row.get(2)?;
        let observed: i64 = row
            .get::<_, Option<i64>>(3)?
            .ok_or(invalid("missing signing lifecycle time"))?;
        // Use the latest verified work event, never the migration wall clock
        // or an unverified delivery timestamp. Validate exact retained signer,
        // outbox and delivery bytes even when transitions already exist.
        signing_jobs::lifecycle_status(tx, &tenant, &job, observed)?;
    }
    Ok(())
}

pub(super) fn apply_v10(tx: &Transaction<'_>) -> Result<()> {
    validate_v9(tx)?;
    // Historical rows remain byte-identical, including untrusted delivery
    // claims. Migration never turns those rows into authenticated receipts.
    signing_jobs::validate_work_histories(tx)?;
    signing_quota::validate_legacy_reservations(tx)?;
    validate_retained_signing_lifecycles(tx)?;
    tx.execute_batch(MIGRATION_10)?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(10,?,10,10,?)",
        params![hash(&hash_bytes(MIGRATION_10.as_bytes()))?, now()?],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority signing history migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 10)?;
    validate_v10(tx)
}

pub(super) fn validate_v10(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 10)?;
    if schema_digest(connection)? != known_v10_digest()? {
        return Err(invalid("unexpected authority v10 schema"));
    }
    Ok(())
}

pub(super) fn apply_v9(tx: &Transaction<'_>) -> Result<()> {
    // Prior approval or signing history cannot establish core-request origin.
    // The additive schema starts empty and never synthesizes provenance.
    validate_v8(tx)?;
    tx.execute_batch(MIGRATION_9)?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(9,?,9,9,?)",
        params![hash(&hash_bytes(MIGRATION_9.as_bytes()))?, now()?],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority core provenance migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 9)?;
    validate_v9(tx)
}

pub(super) fn validate_v9(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 9)?;
    if schema_digest(connection)? != known_v9_digest()? {
        return Err(invalid("unexpected authority v9 schema"));
    }
    Ok(())
}

pub(super) fn apply_v8(tx: &Transaction<'_>) -> Result<()> {
    validate_v7(tx)?;
    if schema_digest(tx)? != known_v7_digest()? {
        return Err(invalid("unexpected authority v7 schema"));
    }
    // The quota migration verifies every retained reservation against immutable
    // lifecycle evidence. Expiry alone is never evidence of a safe refund.
    signing_quota::validate_legacy_reservations(tx)?;
    tx.execute_batch(MIGRATION_8)?;
    signing_quota::backfill_legacy_transitions(tx)?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(8,?,8,8,?)",
        params![hash(&hash_bytes(MIGRATION_8.as_bytes()))?, now()?],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority quota migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 8)?;
    validate_v8(tx)
}

pub(super) fn validate_v8(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 8)?;
    // A checksum row is not evidence that the actual guards still exist.
    if schema_digest(connection)? != known_v8_digest()? {
        return Err(invalid("unexpected authority v8 schema"));
    }
    Ok(())
}

pub(super) fn apply_v7(tx: &Transaction<'_>) -> Result<()> {
    validate_v6(tx)?;
    if schema_digest(tx)? != known_v6_digest()? {
        return Err(invalid("unexpected authority v6 schema"));
    }
    tx.execute_batch(MIGRATION_7)?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(7,?,7,7,?)",
        params![hash(&hash_bytes(MIGRATION_7.as_bytes()))?, now()?],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority signing migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 7)?;
    Ok(())
}
pub(super) fn validate_v7(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 7)
}

pub(super) fn apply_v6(tx: &Transaction<'_>) -> Result<()> {
    validate_v5(tx)?;
    if schema_digest(tx)? != known_v5_digest()? {
        return Err(invalid("unexpected authority v5 schema"));
    }
    tx.execute_batch(MIGRATION_6)?;
    for table in [
        "authority_native_pins",
        "authority_native_pin_revocations",
        "authority_native_observer_keys",
        "authority_native_observer_revocations",
        "authority_native_compilations",
        "authority_native_challenges",
        "authority_native_observations",
    ] {
        tx.execute_batch(&format!("CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'immutable native evidence'); END; CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'retained native evidence'); END;"))?;
    }
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(6,?,6,6,?)",
        params![hash(&hash_bytes(MIGRATION_6.as_bytes()))?, now()?],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority native migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 6)?;
    Ok(())
}

pub(super) fn validate_v6(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 6)
}

pub(super) fn apply_v5(tx: &Transaction<'_>) -> Result<()> {
    validate_v4(tx)?;
    if schema_digest(tx)? != known_v4_digest()? {
        return Err(invalid("unexpected authority v4 schema"));
    }
    tx.execute_batch(MIGRATION_5)?;
    for table in [
        "authority_target_keys",
        "authority_target_key_revocations",
        "authority_target_pins",
        "authority_target_challenges",
        "authority_target_metadata",
    ] {
        tx.execute_batch(&format!("CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT,'immutable target evidence'); END; CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'retained target evidence'); END;"))?;
    }
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(5,?,5,5,?)",
        params![hash(&hash_bytes(MIGRATION_5.as_bytes()))?, now()?],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority target migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 5)?;
    Ok(())
}

pub(super) fn validate_v5(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 5)
}

pub(super) fn apply_v4(tx: &Transaction<'_>) -> Result<()> {
    validate_v3(tx)?;
    if schema_digest(tx)? != known_v3_digest()? {
        return Err(invalid("unexpected authority v3 schema"));
    }
    tx.execute_batch(MIGRATION_4)?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(4,?,4,4,?)",
        params![hash(&hash_bytes(MIGRATION_4.as_bytes()))?, now()?],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority review migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 4)?;
    Ok(())
}

pub(super) fn validate_v4(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 4)
}

pub(super) fn apply_v3(tx: &Transaction<'_>) -> Result<()> {
    validate_v2(tx)?;
    if schema_digest(tx)? != known_v2_digest()? {
        return Err(invalid("unexpected authority v2 schema"));
    }
    tx.execute_batch(MIGRATION_3)?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(3,?,3,3,?)",
        params![hash(&hash_bytes(MIGRATION_3.as_bytes()))?, now()?],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority quorum migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 3)?;
    Ok(())
}

pub(super) fn validate_v3(connection: &Connection) -> Result<()> {
    validate_migrations(connection, 3)
}

fn validate_migrations(connection: &Connection, version: i64) -> Result<()> {
    let mut query=connection.prepare("SELECT version,checksum,minimum_app_schema,maximum_app_schema FROM authority_schema_migrations ORDER BY version LIMIT 17")?;
    let rows = query
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut expected = vec![
        (1, historical_v1_checksum()?, 1, 1),
        (2, hash(&hash_bytes(MIGRATION_2.as_bytes()))?, 2, 2),
        (3, hash(&hash_bytes(MIGRATION_3.as_bytes()))?, 3, 3),
    ];
    if version >= 4 {
        expected.push((4, hash(&hash_bytes(MIGRATION_4.as_bytes()))?, 4, 4));
    }
    if version >= 5 {
        expected.push((5, hash(&hash_bytes(MIGRATION_5.as_bytes()))?, 5, 5));
    }
    if version >= 6 {
        expected.push((6, hash(&hash_bytes(MIGRATION_6.as_bytes()))?, 6, 6));
    }
    if version >= 7 {
        expected.push((7, hash(&hash_bytes(MIGRATION_7.as_bytes()))?, 7, 7));
    }
    if version >= 8 {
        expected.push((8, hash(&hash_bytes(MIGRATION_8.as_bytes()))?, 8, 8));
    }
    if version >= 9 {
        expected.push((9, hash(&hash_bytes(MIGRATION_9.as_bytes()))?, 9, 9));
    }
    if version >= 10 {
        expected.push((10, hash(&hash_bytes(MIGRATION_10.as_bytes()))?, 10, 10));
    }
    if version >= 11 {
        expected.push((11, migration_11_checksum()?, 11, 11));
    }
    if version >= 12 {
        expected.push((12, hash(&hash_bytes(MIGRATION_12.as_bytes()))?, 12, 12));
    }
    if version >= 13 {
        expected.push((13, hash(&hash_bytes(MIGRATION_13.as_bytes()))?, 13, 13));
    }
    if version >= 14 {
        expected.push((14, hash(&hash_bytes(MIGRATION_14.as_bytes()))?, 14, 14));
    }
    if version >= 15 {
        expected.push((15, hash(&hash_bytes(MIGRATION_15.as_bytes()))?, 15, 15));
    }
    if version >= 16 {
        expected.push((16, hash(&hash_bytes(MIGRATION_16.as_bytes()))?, 16, 16));
    }
    if rows != expected {
        return Err(invalid("authority migration checksum or compatibility"));
    }
    Ok(())
}

fn now() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("migration clock"))?
        .as_secs();
    let value = i64::try_from(seconds).map_err(|_| invalid("migration clock"))?;
    time(value)?;
    Ok(value)
}

pub(super) fn apply_v2(tx: &Transaction<'_>) -> Result<()> {
    let original_schema = known_v1_digest()?;
    if schema_digest(tx)? != original_schema {
        return Err(invalid("unexpected authority v1 schema"));
    }
    tx.execute_batch(MIGRATION_2)?;
    // Bounded memory, one atomic migration. Includes revoked keys: a migration
    // must never erase their tombstones or choose a winner among duplicate keys.
    let mut after = (String::new(), String::new(), String::new());
    loop {
        let mut stmt=tx.prepare("SELECT org_id,project_id,credential_id,principal_id,key_fingerprint,credential_bytes
            FROM authority_credentials WHERE (org_id,project_id,credential_id)>(?,?,?) ORDER BY org_id,project_id,credential_id LIMIT 128")?;
        let batch = stmt
            .query_map(params![after.0, after.1, after.2], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        if batch.is_empty() {
            break;
        }
        for row in batch {
            let credential: Credential = decode(&row.5)?;
            if credential.id() != row.2
                || credential.principal_id() != row.3
                || hash(
                    &credential
                        .key_fingerprint()
                        .map_err(|_| invalid("invalid migration credential"))?,
                )? != row.4
            {
                return Err(invalid("migration credential projection"));
            }
            let digest = hash(
                &credential
                    .public_key_fingerprint()
                    .map_err(|_| invalid("invalid migration public key"))?,
            )?;
            insert_public_key(tx, &AuthorityTenant::new(&row.0, &row.1)?, &row.2, &digest)?;
            after = (row.0, row.1, row.2);
        }
    }
    let completed = now()?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(1,?,1,1,?)",
        params![historical_v1_checksum()?, completed],
    )?;
    tx.execute(
        "INSERT INTO authority_schema_migrations VALUES(2,?,2,2,?)",
        params![hash(&hash_bytes(MIGRATION_2.as_bytes()))?, completed],
    )?;
    let broken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    if broken {
        return Err(invalid("authority migration foreign keys"));
    }
    tx.pragma_update(None, "user_version", 2)?;
    Ok(())
}

pub(super) fn validate_v2(connection: &Connection) -> Result<()> {
    let migrations=connection.query_row("SELECT (SELECT checksum FROM authority_schema_migrations WHERE version=1),
        (SELECT checksum FROM authority_schema_migrations WHERE version=2),(SELECT count(*) FROM authority_schema_migrations),
        (SELECT minimum_app_schema FROM authority_schema_migrations WHERE version=2),
        (SELECT maximum_app_schema FROM authority_schema_migrations WHERE version=2)",[],
        |r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?)))?;
    if migrations.0 != historical_v1_checksum()?
        || migrations.1 != hash(&hash_bytes(MIGRATION_2.as_bytes()))?
        || migrations.2 != 2
        || migrations.3 != 2
        || migrations.4 != 2
    {
        return Err(invalid("authority migration checksum"));
    }
    Ok(())
}

pub(super) fn insert_public_key(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    credential_id: &str,
    digest: &[u8],
) -> Result<()> {
    match tx.execute(
        "INSERT INTO authority_public_key_registry VALUES(?,?,?,?)",
        params![tenant.org_id, tenant.project_id, digest, credential_id],
    ) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(code, _))
            if code.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(invalid("duplicate or inconsistent authority public key"))
        }
        Err(error) => Err(error.into()),
    }
}

fn new_private_file(path: &Path) -> Result<fs::File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = fs::metadata(parent).map_err(|_| invalid("authority backup directory"))?;
    if !directory.is_dir() {
        return Err(invalid("authority backup directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if directory.mode() & 0o022 != 0 {
            return Err(invalid("authority backup directory permissions"));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| invalid("authority backup destination already exists or is unavailable"))
}

fn create_backup(
    source: &Path,
    backup_path: &Path,
    original_schema: &[u8],
    version: i64,
) -> Result<()> {
    let file = new_private_file(backup_path)?;
    private_path(backup_path)?;
    let manifest_path = backup_path.with_extension("manifest.json");
    let mut manifest = new_private_file(&manifest_path)?;
    private_path(&manifest_path)?;
    migration_failpoint("backup-files-created")?;
    let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut destination = Connection::open(backup_path)?;
    {
        let backup = Backup::new(&source, &mut destination)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if Instant::now() >= deadline {
                return Err(invalid("authority backup deadline"));
            }
            match backup.step(128)? {
                StepResult::Done => break,
                StepResult::More => {}
                StepResult::Busy | StepResult::Locked => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => return Err(invalid("authority backup state")),
            }
        }
    }
    let check: String = destination.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if check != "ok" || schema_digest(&destination)? != original_schema {
        return Err(invalid("authority backup verification"));
    }
    let _: String = destination.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
    destination
        .close()
        .map_err(|(_, e)| AuthorityError::Storage(e))?;
    file.sync_all()
        .map_err(|_| invalid("authority backup durability"))?;
    let mut input = fs::File::open(backup_path).map_err(|_| invalid("authority backup digest"))?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut chunk = [0u8; 65536];
    loop {
        let count = input
            .read(&mut chunk)
            .map_err(|_| invalid("authority backup digest"))?;
        if count == 0 {
            break;
        }
        size += count as u64;
        digest.update(&chunk[..count]);
    }
    let body = bytes(
        &json!({"schema_version":"fw.authority-backup/v1","database_schema":version,
        "schema_hash":hash_string(original_schema)?,"database_hash":hash_string(&digest.finalize())?,
        "size_bytes":size,"created_at":at(now()?)?,"executor_epoch":null,"executor_generation":null,
        "scope":"authority-store-only"}),
    )?;
    manifest
        .write_all(&body)
        .and_then(|_| manifest.sync_all())
        .map_err(|_| invalid("authority backup manifest"))?;
    #[cfg(unix)]
    {
        let parent = backup_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| invalid("authority backup directory durability"))?;
    }
    Ok(())
}

impl AuthorityStore {
    /// Compatibility entry point. Upgrade a known prior schema to the current
    /// schema using the same explicit, private online-backup procedure.
    pub fn migrate_v1(path: impl AsRef<Path>, backup_path: impl AsRef<Path>) -> Result<()> {
        Self::migrate(path, backup_path)
    }
    /// Explicit maintenance upgrade of a known prior database. A new private
    /// SQLite online backup and manifest are durable before schema changes.
    /// Existing duplicate key material aborts migration; no row is deleted or
    /// silently selected as trusted. Keep the backup private and do not restore
    /// old authority state over a live deployment's revocations/counters.
    /// An interrupted backup may leave an incomplete destination/manifest pair.
    /// Retain those private files for inspection and retry with a new destination;
    /// migration never overwrites or automatically removes recovery evidence.
    pub fn migrate(path: impl AsRef<Path>, backup_path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        backup_paths(path, backup_path.as_ref())?;
        private_path(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_millis(5000))?;
        connection.set_prepared_statement_cache_capacity(256);
        // Current-version maintenance is validation, not a write operation.
        // A prior-version source is checked again after acquiring its write lock.
        {
            let tx = connection.transaction()?;
            let application: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
            let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if application == APPLICATION_ID && version == 16 {
                validate_v16(&tx)?;
                tx.commit()?;
                return Ok(());
            }
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "OFF")?;
        let migrated = (|| -> Result<()> {
            let disabled: i64 = connection.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
            if disabled != 0 {
                return Err(invalid("authority maintenance foreign key configuration"));
            }
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let application: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
            let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if application == APPLICATION_ID && version == 16 {
                // Another maintainer finished while this connection waited.
                drop(tx);
                let tx = connection.transaction()?;
                validate_v16(&tx)?;
                tx.commit()?;
                return Ok(());
            }
            if application != APPLICATION_ID || !(1..=15).contains(&version) {
                return Err(invalid("authority migration requires known prior database"));
            }
            if version == 2 {
                validate_v2(&tx)?;
            }
            if version == 3 {
                validate_v3(&tx)?;
            }
            if version == 4 {
                validate_v4(&tx)?;
            }
            if version == 5 {
                validate_v5(&tx)?;
            }
            if version == 6 {
                validate_v6(&tx)?;
            }
            if version == 7 {
                validate_v7(&tx)?;
            }
            if version == 8 {
                validate_v8(&tx)?;
            }
            if version == 9 {
                validate_v9(&tx)?;
            }
            if version == 10 {
                validate_v10(&tx)?;
            }
            if version == 11 {
                validate_v11_schema(&tx)?;
            }
            if version == 12 {
                validate_migrations(&tx, 12)?;
            }
            if version == 13 {
                validate_v13(&tx)?;
            }
            if version == 14 {
                validate_v14(&tx)?;
            }
            if version == 15 {
                validate_v15(&tx)?;
            }
            let original_schema = match version {
                1 => known_v1_digest()?,
                2 => known_v2_digest()?,
                3 => known_v3_digest()?,
                4 => known_v4_digest()?,
                5 => known_v5_digest()?,
                6 => known_v6_digest()?,
                7 => known_v7_digest()?,
                8 => known_v8_digest()?,
                9 => known_v9_digest()?,
                10 => known_v10_digest()?,
                11 => known_v11()?.digest.clone(),
                12 => known_v12()?.digest.clone(),
                13 => known_v13()?.digest.clone(),
                14 => known_v14()?.digest.clone(),
                _ => known_v15()?.digest.clone(),
            };
            if schema_digest(&tx)? != original_schema {
                return Err(invalid("unexpected authority source schema"));
            }
            // Verify source B-trees before backup or any table/index rebuild.
            // Recreating a released index must never hide preexisting physical
            // corruption by making the source appear healthy after upgrade.
            validate_physical_integrity(&tx)?;
            // A second read-only connection sees a consistent pre-migration DB;
            // this IMMEDIATE transaction prevents other writers while it is copied.
            create_backup(path, backup_path.as_ref(), &original_schema, version)?;
            if version == 1 {
                apply_v2(&tx)?;
            }
            if version < 3 {
                apply_v3(&tx)?;
            }
            if version < 4 {
                apply_v4(&tx)?;
            }
            if version < 5 {
                apply_v5(&tx)?;
            }
            if version < 6 {
                apply_v6(&tx)?;
            }
            if version < 7 {
                apply_v7(&tx)?;
            }
            if version < 8 {
                apply_v8(&tx)?;
            }
            if version < 9 {
                apply_v9(&tx)?;
            }
            if version < 10 {
                apply_v10(&tx)?;
            }
            if version < 11 {
                apply_v11(&tx)?;
            }
            if version < 12 {
                apply_v12(&tx)?;
            }
            if version < 13 {
                apply_v13(&tx)?;
            }
            if version < 14 {
                apply_v14(&tx)?;
            }
            if version < 15 {
                apply_v15(&tx)?;
            }
            apply_v16(&tx)?;
            migration_failpoint("before-commit")?;
            tx.commit()?;
            Ok(())
        })();
        // The transaction has committed or dropped and rolled back here.
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let enforced: i64 = connection.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
        if enforced != 1 {
            return Err(invalid(
                "authority maintenance failed to restore foreign keys",
            ));
        }
        #[cfg(test)]
        MIGRATION_FK_RESTORED.with(|restored| restored.set(true));
        migrated
    }
}

#[cfg(test)]
#[path = "../../tests/support/authority_legacy.rs"]
#[allow(dead_code)]
pub(super) mod legacy;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::signing_test_support::{Fixture, NOW};

    fn version(path: &Path) -> i64 {
        Connection::open(path)
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    fn snapshot(path: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
        let db = Connection::open(path).unwrap();
        let mut statement = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND lower(substr(name,1,7)) <> 'sqlite_' ORDER BY name").unwrap();
        let names = statement
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        names
            .into_iter()
            .map(|name| {
                let mut query = db
                    .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                    .unwrap();
                let columns = query.column_count();
                let rows = query
                    .query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
                    .unwrap()
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap();
                (name, rows)
            })
            .collect()
    }

    fn prepared() -> (Fixture, String, String) {
        let mut f = Fixture::new();
        let result = signing_intents::test_prepare(&mut f, NOW);
        (f, result.intent.job_id, result.intent.reservation_id)
    }

    fn claim(
        f: &mut Fixture,
        job: &str,
        phase: &'static str,
        generation: u64,
        now: i64,
    ) -> signing_jobs::SigningClaim {
        let tx = f.store.connection.transaction().unwrap();
        let claim = signing_jobs::fixture_claim(
            &tx,
            &f.tenant,
            job,
            phase,
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            generation,
            2,
            now,
        )
        .unwrap();
        tx.commit().unwrap();
        claim
    }

    fn prepared_in_state(expected: &str) -> (Fixture, String) {
        let (mut f, job, reservation) = prepared();
        match expected {
            "released" => f
                .store
                .cancel_signing_job(&f.tenant, &job, NOW + 400)
                .unwrap(),
            "issued" | "unknown" | "active" => {
                let signer = claim(&mut f, &job, "signer", 0, NOW);
                signing_intents::test_finalize(&mut f, &signer, NOW).unwrap();
                if expected == "unknown" {
                    claim(&mut f, &job, "dispatch", 0, NOW);
                    claim(&mut f, &job, "dispatch", 1, NOW + 6);
                } else if expected == "active" {
                    let dispatch = claim(&mut f, &job, "dispatch", 0, NOW);
                    let tx = f.store.connection.transaction().unwrap();
                    signing_jobs::fixture_deliver(&tx, &f.tenant, &dispatch, NOW).unwrap();
                    tx.commit().unwrap();
                }
            }
            "reserved" => {}
            _ => panic!("unsupported fixture state"),
        }
        (f, reservation)
    }

    fn assert_private_backup(backup: &Path, schema: i64) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [backup, &backup.with_extension("manifest.json")] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        let manifest: Value =
            serde_json::from_slice(&fs::read(backup.with_extension("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["database_schema"], schema);
        assert_eq!(
            manifest["database_hash"],
            hash_bytes(&fs::read(backup).unwrap())
        );
    }

    fn assert_empty_core_provenance(path: &Path) {
        let db = Connection::open(path).unwrap();
        for table in [
            "authority_core_access_requests",
            "authority_core_access_plan_bindings",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
                0,
                "migration must not invent request origin: {table}"
            );
        }
    }

    #[test]
    fn v7_populated_upgrade_preserves_every_evidence_byte_and_proven_quota_state() {
        for expected in ["reserved", "released", "issued", "unknown", "active"] {
            let (mut f, reservation) = prepared_in_state(expected);
            drop(f.store);
            legacy::restore_v7(&f.path);
            assert!(matches!(
                AuthorityStore::open(&f.path),
                Err(AuthorityError::MigrationRequired {
                    found: 7,
                    required: 16
                })
            ));
            let before = snapshot(&f.path);
            let backup = f.directory.path().join("before-v8.sqlite3");
            AuthorityStore::migrate(&f.path, &backup).unwrap();
            assert_eq!(version(&f.path), 16);
            assert_eq!(version(&backup), 7);
            assert_eq!(snapshot(&backup), before);
            let after = snapshot(&f.path);
            for (table, rows) in &before {
                let upgraded = &after.iter().find(|(name, _)| name == table).unwrap().1;
                if table == "authority_schema_migrations" {
                    assert!(upgraded.starts_with(rows));
                    assert_eq!(upgraded.len(), 16);
                } else {
                    assert_eq!(upgraded, rows, "{table}: {expected}");
                }
            }
            assert_private_backup(&backup, 7);
            assert_empty_core_provenance(&f.path);
            let unnecessary = f.directory.path().join("unnecessary.sqlite3");
            AuthorityStore::migrate(&f.path, &unnecessary).unwrap();
            assert!(!unnecessary.exists());
            f.store = AuthorityStore::open(&f.path).unwrap();
            let tx = f.store.connection.transaction().unwrap();
            let saved = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
            assert_eq!(saved.state, expected);
            assert_eq!(
                saved.held(),
                matches!(expected, "reserved" | "issued" | "unknown" | "active")
            );
        }
    }

    #[test]
    fn v8_populated_upgrade_preserves_evidence_and_adds_no_core_authority() {
        for expected in ["reserved", "released", "issued", "unknown", "active"] {
            let (mut f, reservation) = prepared_in_state(expected);
            drop(f.store);
            legacy::restore_v8(&f.path);
            assert!(matches!(
                AuthorityStore::open(&f.path),
                Err(AuthorityError::MigrationRequired {
                    found: 8,
                    required: 16
                })
            ));
            let before = snapshot(&f.path);
            let backup = f.directory.path().join("before-v9.sqlite3");
            AuthorityStore::migrate(&f.path, &backup).unwrap();
            assert_eq!(version(&f.path), 16);
            assert_eq!(version(&backup), 8);
            assert_eq!(snapshot(&backup), before);
            let after = snapshot(&f.path);
            for (table, rows) in &before {
                let upgraded = &after.iter().find(|(name, _)| name == table).unwrap().1;
                if table == "authority_schema_migrations" {
                    assert!(upgraded.starts_with(rows));
                    assert_eq!(upgraded.len(), 16);
                } else {
                    assert_eq!(upgraded, rows, "{table}: {expected}");
                }
            }
            assert_private_backup(&backup, 8);
            assert_empty_core_provenance(&f.path);
            let unnecessary = f.directory.path().join("unnecessary.sqlite3");
            AuthorityStore::migrate(&f.path, &unnecessary).unwrap();
            assert!(!unnecessary.exists());
            assert_eq!(snapshot(&f.path), after);
            f.store = AuthorityStore::open(&f.path).unwrap();
            let tx = f.store.connection.transaction().unwrap();
            let saved = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
            assert_eq!(saved.state, expected);
            assert_eq!(
                saved.held(),
                matches!(expected, "reserved" | "issued" | "unknown" | "active")
            );
        }
    }

    #[test]
    fn v9_populated_upgrade_preserves_evidence_and_holds_unverified_delivery() {
        for expected in ["reserved", "released", "issued", "unknown", "active"] {
            let (mut f, reservation) = prepared_in_state(expected);
            drop(f.store);
            legacy::restore_v9(&f.path);
            assert!(matches!(
                AuthorityStore::open(&f.path),
                Err(AuthorityError::MigrationRequired {
                    found: 9,
                    required: 16
                })
            ));
            let before = snapshot(&f.path);
            let backup = f.directory.path().join("before-v10.sqlite3");
            AuthorityStore::migrate(&f.path, &backup).unwrap();
            assert_eq!(version(&f.path), 16);
            assert_eq!(snapshot(&backup), before);
            assert_private_backup(&backup, 9);
            let after = snapshot(&f.path);
            for (table, rows) in &before {
                let upgraded = &after.iter().find(|(name, _)| name == table).unwrap().1;
                if table == "authority_schema_migrations" {
                    assert!(upgraded.starts_with(rows));
                    assert_eq!(upgraded.len(), 16);
                } else {
                    assert_eq!(upgraded, rows, "{table}: {expected}");
                }
            }
            assert_empty_core_provenance(&f.path);
            let unnecessary = f.directory.path().join("unnecessary.sqlite3");
            AuthorityStore::migrate(&f.path, &unnecessary).unwrap();
            assert!(!unnecessary.exists());
            assert_eq!(snapshot(&f.path), after);
            f.store = AuthorityStore::open(&f.path).unwrap();
            let tx = f.store.connection.transaction().unwrap();
            let saved = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
            assert_eq!(saved.state, expected);
            // Preserved unsigned delivery diagnostics never return capacity.
            assert_eq!(saved.held(), expected != "released");
        }
    }

    #[test]
    fn v9_upgrade_preserves_renewed_claims_and_expired_unissued_obligations() {
        for state in ["expired_unissued", "signer_renewed", "dispatch_renewed"] {
            let (mut f, job, reservation) = prepared();
            if state != "expired_unissued" {
                let signer = claim(&mut f, &job, "signer", 0, NOW);
                let current = if state == "dispatch_renewed" {
                    signing_intents::test_finalize(&mut f, &signer, NOW).unwrap();
                    claim(&mut f, &job, "dispatch", 0, NOW)
                } else {
                    signer
                };
                let tx = f.store.connection.transaction().unwrap();
                signing_jobs::fixture_renew(&tx, &f.tenant, &current, 10, NOW + 1).unwrap();
                tx.commit().unwrap();
            }
            drop(f.store);
            legacy::restore_v9(&f.path);
            let before = snapshot(&f.path);
            let backup = f.directory.path().join("old-claims.sqlite3");
            AuthorityStore::migrate(&f.path, &backup).unwrap();
            assert_eq!(snapshot(&backup), before);
            assert_private_backup(&backup, 9);
            let after = snapshot(&f.path);
            for (table, rows) in &before {
                let upgraded = &after.iter().find(|(name, _)| name == table).unwrap().1;
                if table == "authority_schema_migrations" {
                    assert!(upgraded.starts_with(rows));
                    assert_eq!(upgraded.len(), 16);
                } else {
                    assert_eq!(upgraded, rows, "{table}: {state}");
                }
            }
            f.store = AuthorityStore::open(&f.path).unwrap();
            let tx = f.store.connection.transaction().unwrap();
            let saved = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
            assert!(saved.held());
            let lifecycle =
                signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW + 400).unwrap();
            assert!(lifecycle.quota_held);
            assert_eq!(
                saved.state,
                if state == "dispatch_renewed" {
                    "issued"
                } else {
                    "reserved"
                }
            );
        }
    }

    #[test]
    fn v9_invalid_work_history_keeps_original_and_private_backup_without_new_guards() {
        let (f, job, _) = prepared();
        drop(f.store);
        legacy::restore_v9(&f.path);
        let db = Connection::open(&f.path).unwrap();
        // Old schema permits a duplicate creation transition whose current
        // head matches the latest row. Complete history must reject this.
        db.execute("INSERT INTO authority_signing_work_events SELECT org_id,project_id,job_id,phase,state,?,claim_generation,claim_hash,worker_id,claim_until,attempts,available_at+1,updated_at+1,kind FROM authority_signing_work_events WHERE job_id=? AND phase='signer'", params![2u64.to_be_bytes().as_slice(), job]).unwrap();
        db.execute("UPDATE authority_signing_work_heads SET revision=?,available_at=available_at+1,updated_at=updated_at+1 WHERE job_id=? AND phase='signer'", params![2u64.to_be_bytes().as_slice(), job]).unwrap();
        drop(db);
        let before = snapshot(&f.path);
        let backup = f.directory.path().join("invalid-history.sqlite3");
        assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
        assert_eq!(version(&f.path), 9);
        assert_eq!(snapshot(&f.path), before);
        assert_eq!(snapshot(&backup), before);
        assert_private_backup(&backup, 9);
        let db = Connection::open(&f.path).unwrap();
        validate_v9(&db).unwrap();
        assert!(!db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='authority_signing_work_events_sequence')", [], |r| r.get::<_,bool>(0)).unwrap());
    }

    #[test]
    fn current_schema_rejects_sqlite_lookalike_trigger_names_before_open_or_migrate() {
        for name in ["sqliteX_hidden", "SQLITEX_hidden", "ordinary_hidden"] {
            let f = Fixture::new();
            drop(f.store);
            let current = version(&f.path);
            let db = Connection::open(&f.path).unwrap();
            for reserved in ["sqlite_hidden", "SQLITE_hidden"] {
                assert!(db.execute_batch(&format!("CREATE TRIGGER {reserved} BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(IGNORE); END;")).is_err());
            }
            let trigger = format!(
                "CREATE TRIGGER {name} BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(IGNORE); END"
            );
            db.execute_batch(&trigger).unwrap();
            // This is an operative trigger, not a harmless catalogue label:
            // it suppresses an audit insert before duplicate-key checks run.
            assert_eq!(
                db.execute(
                    "INSERT INTO authority_audit SELECT * FROM authority_audit LIMIT 1",
                    []
                )
                .unwrap(),
                0
            );
            drop(db);
            let before = snapshot(&f.path);
            assert!(AuthorityStore::open(&f.path).is_err(), "{name}");
            let backup = f.directory.path().join("should-not-exist.sqlite3");
            assert!(AuthorityStore::migrate(&f.path, &backup).is_err(), "{name}");
            assert!(!backup.exists());
            assert!(!backup.with_extension("manifest.json").exists());
            assert_eq!(version(&f.path), current);
            assert_eq!(snapshot(&f.path), before);
            let retained: String = Connection::open(&f.path)
                .unwrap()
                .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [name], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(retained, trigger);
        }
    }

    #[test]
    fn legacy_schema_rejects_sqlite_lookalike_trigger_names_without_creating_backup() {
        for legacy_version in [7, 8, 9] {
            for name in ["sqliteX_hidden", "SQLITEX_hidden"] {
                let f = Fixture::new();
                drop(f.store);
                match legacy_version {
                    7 => legacy::restore_v7(&f.path),
                    8 => legacy::restore_v8(&f.path),
                    9 => legacy::restore_v9(&f.path),
                    _ => unreachable!(),
                }
                let db = Connection::open(&f.path).unwrap();
                let trigger = format!(
                    "CREATE TRIGGER {name} BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(IGNORE); END"
                );
                db.execute_batch(&trigger).unwrap();
                drop(db);
                let before = snapshot(&f.path);
                let backup = f.directory.path().join("should-not-exist.sqlite3");
                assert!(
                    AuthorityStore::migrate(&f.path, &backup).is_err(),
                    "v{legacy_version}: {name}"
                );
                assert!(!backup.exists());
                assert!(!backup.with_extension("manifest.json").exists());
                assert_eq!(version(&f.path), legacy_version);
                assert_eq!(snapshot(&f.path), before);
                let retained: String = Connection::open(&f.path)
                    .unwrap()
                    .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [name], |r| {
                        r.get(0)
                    })
                    .unwrap();
                assert_eq!(retained, trigger);
            }
        }
    }

    #[test]
    fn v8_migration_rejects_unknown_actual_schema_before_creating_backup() {
        for replace in [false, true] {
            let f = Fixture::new();
            drop(f.store);
            legacy::restore_v8(&f.path);
            let db = Connection::open(&f.path).unwrap();
            db.execute_batch("DROP TRIGGER authority_signing_quota_transitions_no_delete;")
                .unwrap();
            if replace {
                db.execute_batch("CREATE TRIGGER authority_signing_quota_transitions_no_delete BEFORE DELETE ON authority_signing_quota_transitions BEGIN SELECT 1; END;").unwrap();
            }
            drop(db);
            let before = snapshot(&f.path);
            let backup = f.directory.path().join("should-not-exist.sqlite3");
            assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
            assert!(!backup.exists());
            assert!(!backup.with_extension("manifest.json").exists());
            assert_eq!(version(&f.path), 8);
            assert_eq!(snapshot(&f.path), before);
        }
    }

    #[test]
    fn v8_inconsistent_foreign_key_rolls_back_upgrade_and_preserves_private_backup() {
        let (f, _, _) = prepared();
        drop(f.store);
        legacy::restore_v8(&f.path);
        let db = Connection::open(&f.path).unwrap();
        db.pragma_update(None, "foreign_keys", "OFF").unwrap();
        db.execute(
            "INSERT INTO authority_signing_quota_usage VALUES(?,?,?,?,?)",
            params![
                f.tenant.org_id,
                f.tenant.project_id,
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                NOW,
                vec![0u8; 32]
            ],
        )
        .unwrap();
        drop(db);
        let before = snapshot(&f.path);
        let backup = f.directory.path().join("invalid-v8.sqlite3");
        assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
        assert_eq!(version(&f.path), 8);
        assert_eq!(version(&backup), 8);
        assert_eq!(snapshot(&f.path), before);
        assert_eq!(snapshot(&backup), before);
        assert_private_backup(&backup, 8);
        assert!(!Connection::open(&f.path).unwrap().query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='authority_core_access_requests')", [], |r| r.get::<_,bool>(0)).unwrap());
    }

    #[test]
    fn v7_unproven_refund_rolls_back_upgrade_and_keeps_original_and_private_backup() {
        for issued in [false, true] {
            let (mut f, job, _) = prepared();
            if issued {
                let signer = claim(&mut f, &job, "signer", 0, NOW);
                signing_intents::test_finalize(&mut f, &signer, NOW).unwrap();
            }
            drop(f.store);
            legacy::restore_v7(&f.path);
            let db = Connection::open(&f.path).unwrap();
            db.execute("UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0", []).unwrap();
            drop(db);
            let before = snapshot(&f.path);
            let backup = f.directory.path().join("invalid-v7.sqlite3");
            assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
            assert_eq!(version(&f.path), 7);
            assert_eq!(version(&backup), 7);
            assert_eq!(snapshot(&f.path), before);
            assert_eq!(snapshot(&backup), before);
            assert!(!Connection::open(&f.path).unwrap().query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='authority_signing_quota_transitions')", [], |r| r.get::<_,bool>(0)).unwrap());
        }
    }

    #[test]
    fn v10_open_and_migration_fast_path_reject_missing_or_replaced_prior_guards() {
        for replace in [false, true] {
            let f = Fixture::new();
            drop(f.store);
            let db = Connection::open(&f.path).unwrap();
            db.execute_batch("DROP TRIGGER authority_signing_quota_reservations_no_delete;")
                .unwrap();
            if replace {
                db.execute_batch("CREATE TRIGGER authority_signing_quota_reservations_no_delete BEFORE DELETE ON authority_signing_quota_reservations BEGIN SELECT 1; END;").unwrap();
            }
            drop(db);
            assert!(AuthorityStore::open(&f.path).is_err());
            let backup = f.directory.path().join("should-not-exist.sqlite3");
            assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
            assert!(!backup.exists());
            assert_eq!(version(&f.path), 16);
        }
    }

    #[test]
    fn v10_open_and_migration_fast_path_reject_changed_core_schema() {
        for table in [
            "authority_core_access_requests",
            "authority_core_access_plan_bindings",
        ] {
            for replace in [false, true] {
                let f = Fixture::new();
                drop(f.store);
                let db = Connection::open(&f.path).unwrap();
                let guard: String = db
                    .query_row(
                        "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name=? AND sql LIKE '%BEFORE DELETE%'",
                        [table],
                        |r| r.get(0),
                    )
                    .unwrap();
                db.execute_batch(&format!("DROP TRIGGER {guard};")).unwrap();
                if replace {
                    db.execute_batch(&format!(
                        "CREATE TRIGGER {guard} BEFORE DELETE ON {table} BEGIN SELECT 1; END;"
                    ))
                    .unwrap();
                }
                drop(db);
                let before = snapshot(&f.path);
                assert!(AuthorityStore::open(&f.path).is_err());
                let backup = f.directory.path().join("should-not-exist.sqlite3");
                assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
                assert!(!backup.exists());
                assert!(!backup.with_extension("manifest.json").exists());
                assert_eq!(version(&f.path), 16);
                assert_eq!(snapshot(&f.path), before);
            }
        }
    }

    #[test]
    fn v10_open_and_migration_fast_path_reject_changed_migration_checksum() {
        let f = Fixture::new();
        drop(f.store);
        let db = Connection::open(&f.path).unwrap();
        let guard = "authority_schema_migrations_no_update";
        let trigger: String = db
            .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [guard], |r| {
                r.get(0)
            })
            .unwrap();
        db.execute_batch(&format!("DROP TRIGGER {guard};")).unwrap();
        db.execute(
            "UPDATE authority_schema_migrations SET checksum=? WHERE version=10",
            [vec![0u8; 32]],
        )
        .unwrap();
        db.execute_batch(&trigger).unwrap();
        drop(db);
        let before = snapshot(&f.path);
        assert!(AuthorityStore::open(&f.path).is_err());
        let backup = f.directory.path().join("should-not-exist.sqlite3");
        assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
        assert!(!backup.exists());
        assert!(!backup.with_extension("manifest.json").exists());
        assert_eq!(version(&f.path), 16);
        assert_eq!(snapshot(&f.path), before);
    }

    #[test]
    fn v7_migration_rejects_unknown_actual_schema_before_creating_backup() {
        let f = Fixture::new();
        drop(f.store);
        legacy::restore_v7(&f.path);
        Connection::open(&f.path)
            .unwrap()
            .execute_batch("DROP TRIGGER authority_signing_quota_usage_no_delete;")
            .unwrap();
        let backup = f.directory.path().join("should-not-exist.sqlite3");
        assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
        assert!(!backup.exists());
        assert_eq!(version(&f.path), 7);
    }

    #[test]
    fn v9_corrupted_delivery_bytes_cannot_upgrade_even_with_restored_schema() {
        for previous in [9, 8] {
            reject_corrupted_retained_delivery(previous, true);
        }
    }

    #[test]
    fn v9_corrupted_outbox_time_cannot_upgrade_even_with_restored_schema() {
        for previous in [9, 8] {
            reject_corrupted_retained_delivery(previous, false);
        }
    }

    fn reject_corrupted_retained_delivery(previous: i64, corrupt_delivery: bool) {
        let (mut f, job, _) = prepared();
        let signer = claim(&mut f, &job, "signer", 0, NOW);
        signing_intents::test_finalize(&mut f, &signer, NOW).unwrap();
        let dispatch = claim(&mut f, &job, "dispatch", 0, NOW);
        let tx = f.store.connection.transaction().unwrap();
        signing_jobs::fixture_deliver(&tx, &f.tenant, &dispatch, NOW).unwrap();
        tx.commit().unwrap();
        drop(f.store);
        match previous {
            9 => legacy::restore_v9(&f.path),
            8 => legacy::restore_v8(&f.path),
            _ => unreachable!(),
        }
        let mut db = Connection::open(&f.path).unwrap();
        let guard = if corrupt_delivery {
            "authority_signing_deliveries_immutable_update"
        } else {
            "authority_signing_outbox_immutable_update"
        };
        let trigger: String = db
            .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [guard], |r| {
                r.get(0)
            })
            .unwrap();
        db.execute_batch(&format!("DROP TRIGGER {guard}")).unwrap();
        if corrupt_delivery {
            db.execute(
                "UPDATE authority_signing_deliveries SET result_bytes=?",
                [b"corrupted receipt".as_slice()],
            )
            .unwrap();
        } else {
            db.execute(
                "UPDATE authority_signing_outbox SET created_at=?",
                [NOW + 1],
            )
            .unwrap();
        }
        db.execute_batch(&trigger).unwrap();
        let tx = db.transaction().unwrap();
        // A normal historical lifecycle read already rejects the same bytes.
        assert!(signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW).is_err());
        tx.rollback().unwrap();
        drop(db);
        let before = snapshot(&f.path);
        let backup = f.directory.path().join("invalid-retained-delivery.sqlite3");
        assert!(
            AuthorityStore::migrate(&f.path, &backup).is_err(),
            "v{previous}, corrupt_delivery={corrupt_delivery}"
        );
        assert_eq!(version(&f.path), previous);
        assert_eq!(snapshot(&f.path), before);
        assert_eq!(snapshot(&backup), before);
        assert_private_backup(&backup, previous);
        let db = Connection::open(&f.path).unwrap();
        assert!(!db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='authority_signing_work_events_sequence')", [], |r| r.get::<_,bool>(0)).unwrap());
    }

    #[test]
    fn v7_inconsistent_delivery_or_outbox_rolls_back_and_preserves_backup() {
        for corrupt_delivery in [true, false] {
            let (mut f, job, _) = prepared();
            let signer = claim(&mut f, &job, "signer", 0, NOW);
            signing_intents::test_finalize(&mut f, &signer, NOW).unwrap();
            let dispatch = claim(&mut f, &job, "dispatch", 0, NOW);
            let tx = f.store.connection.transaction().unwrap();
            signing_jobs::fixture_deliver(&tx, &f.tenant, &dispatch, NOW).unwrap();
            tx.commit().unwrap();
            drop(f.store);
            legacy::restore_v7(&f.path);
            let db = Connection::open(&f.path).unwrap();
            let guard = if corrupt_delivery {
                "authority_signing_deliveries_immutable_update"
            } else {
                "authority_signing_outbox_immutable_update"
            };
            let trigger: String = db
                .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [guard], |r| {
                    r.get(0)
                })
                .unwrap();
            db.execute_batch(&format!("DROP TRIGGER {guard}")).unwrap();
            if corrupt_delivery {
                db.execute(
                    "UPDATE authority_signing_deliveries SET result_bytes=?",
                    [b"corrupted receipt".as_slice()],
                )
                .unwrap();
            } else {
                db.execute(
                    "UPDATE authority_signing_outbox SET created_at=?",
                    [NOW + 1],
                )
                .unwrap();
            }
            // Restore the exact known schema: rejection must come from data
            // consistency, rather than detecting a deliberately missing guard.
            db.execute_batch(&trigger).unwrap();
            drop(db);
            let original = snapshot(&f.path);
            let backup = f.directory.path().join("inconsistent-delivery-v7.sqlite3");
            assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
            assert_eq!(version(&f.path), 7);
            assert_eq!(version(&backup), 7);
            assert_eq!(snapshot(&f.path), original);
            assert_eq!(snapshot(&backup), original);
            assert!(!Connection::open(&f.path).unwrap().query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='authority_signing_quota_transitions')", [], |r| r.get::<_,bool>(0)).unwrap());
        }
    }
    mod rebuild_tests {
        include!("migration_rebuild_tests.rs");
    }
    mod window_tests {
        include!("window_migration_tests.rs");
    }
}
