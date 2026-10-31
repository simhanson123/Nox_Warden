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

fn schema_digest(connection: &Connection) -> Result<Vec<u8>> {
    let mut stmt=connection.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
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
    hash(&canonical_hash(&rows).map_err(|_| invalid("authority schema manifest"))?)
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
    let mut query=connection.prepare("SELECT version,checksum,minimum_app_schema,maximum_app_schema FROM authority_schema_migrations ORDER BY version")?;
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
    let expected = vec![
        (1, known_v1_digest()?, 1, 1),
        (2, hash(&hash_bytes(MIGRATION_2.as_bytes()))?, 2, 2),
        (3, hash(&hash_bytes(MIGRATION_3.as_bytes()))?, 3, 3),
    ];
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
        params![original_schema, completed],
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
    if migrations.0 != known_v1_digest()?
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
    /// Explicit maintenance upgrade of a known v1 database. A new private
    /// SQLite online backup and manifest are durable before schema changes.
    /// Existing duplicate key material aborts migration; no row is deleted or
    /// silently selected as trusted. Keep the backup private and do not restore
    /// old authority state over a live deployment's revocations/counters.
    pub fn migrate(path: impl AsRef<Path>, backup_path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        private_path(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_millis(5000))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let application: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if application == APPLICATION_ID && version == 3 {
            validate_v3(&tx)?;
            tx.commit()?;
            return Ok(());
        }
        if application != APPLICATION_ID || ![1, 2].contains(&version) {
            return Err(invalid("authority migration requires known prior database"));
        }
        if version == 2 {
            validate_v2(&tx)?;
        }
        let original_schema = if version == 1 {
            known_v1_digest()?
        } else {
            known_v2_digest()?
        };
        if schema_digest(&tx)? != original_schema {
            return Err(invalid("unexpected authority v1 schema"));
        }
        // A second read-only connection sees a consistent pre-migration DB;
        // this IMMEDIATE transaction prevents other writers while it is copied.
        create_backup(path, backup_path.as_ref(), &original_schema, version)?;
        if version == 1 {
            apply_v2(&tx)?;
        }
        apply_v3(&tx)?;
        tx.commit()?;
        Ok(())
    }
}
