//! Durable approval admission for an authority-owned SQLite database.
//!
//! These are trusted local library operations, not controller HTTP endpoints.
//! The caller must provision this database through an independently authenticated
//! authority administrator and protect its directory from the controller OS user.
//! A different SQLite filename, on its own, does not establish that boundary.
//! Decisions here do not create approval sets, grants or signing jobs.
mod admission;
mod provision;
mod records;
mod subject;

use crate::{ApprovalChallenge, ApprovalDecision, ApprovalRole, AuthorityError, Result};
use chrono::{DateTime, Utc};
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes, parse_strict_with_limit};
use fw_webauthn::{Credential, WebAuthn};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

const SCHEMA: &str = "fw.authority-store/v1";
const APPLICATION_ID: i64 = 0x46574155;
const MAX_TIME: i64 = 253_402_300_799;
const MAX_ATTEMPTS: i64 = 10;
const MAX_OUTSTANDING: i64 = 16;

/// Tenant identity resolved by an authenticated authority boundary, never by an
/// untrusted request's organization/project claims alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityTenant {
    org_id: String,
    project_id: String,
}
impl AuthorityTenant {
    pub fn new(org_id: &str, project_id: &str) -> Result<Self> {
        identifier(org_id)?;
        identifier(project_id)?;
        Ok(Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
        })
    }
    pub fn org_id(&self) -> &str {
        &self.org_id
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
}

pub struct AuthorityStore {
    connection: Connection,
}
pub struct CredentialActivation {
    pub activation_id: String,
    pub options: Value,
}
pub struct IssuedApproval {
    pub challenge: ApprovalChallenge,
    pub options: Value,
}
/// An exact retry returns the same historical decision. `replayed` never means
/// that its credential, role or approval validity is still current.
pub struct DecisionResult {
    pub approval: Value,
    pub replayed: bool,
}
/// A retained signature and its current authority registry checks succeeded.
/// Rejections remain rejections. This is not a quorum or a dispatch grant.
pub struct RetainedDecision {
    approval: Value,
}
impl RetainedDecision {
    pub fn approval(&self) -> &Value {
        &self.approval
    }
}

impl AuthorityStore {
    /// Open a dedicated authority database. Foreign databases and unsupported
    /// schema versions are rejected before any schema or identity is changed.
    /// On Unix, the database must be a private regular single-link file in a
    /// directory without group/other write access. The caller owns ACL/OS-user
    /// isolation, encrypted backup access and safe path selection on every OS.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        private_path(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_millis(5000))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let application: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
            let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            let tables: i64 = tx.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )?;
            if tables == 0 && application == 0 && version == 0 {
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
                    // Fixed compile-time identifiers, never interpolated input.
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
            } else {
                if application != APPLICATION_ID || version != 1 {
                    return Err(invalid("foreign or unsupported authority database"));
                }
                let identity: Option<String> = tx
                    .query_row(
                        "SELECT schema_identity FROM authority_metadata WHERE singleton=1",
                        [],
                        |r| r.get(0),
                    )
                    .optional()?;
                if identity.as_deref() != Some(SCHEMA) {
                    return Err(invalid("authority database identity"));
                }
            }
            tx.commit()?;
        }
        let journal = enable_wal(&connection, Duration::from_secs(5))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
        let sync: i64 = connection.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        let busy: i64 = connection.query_row("PRAGMA busy_timeout", [], |r| r.get(0))?;
        if journal != "wal" || foreign_keys != 1 || sync != 2 || busy != 5000 {
            return Err(invalid("authority database durability configuration"));
        }
        Ok(Self { connection })
    }
}

// SQLite can return BUSY from journal-mode negotiation without invoking its busy
// handler. Bound this one initialization operation explicitly; ordinary queries
// keep the standard five-second SQLite busy timeout. Never retry other errors.
fn enable_wal(connection: &Connection, timeout: Duration) -> Result<String> {
    connection.busy_timeout(Duration::ZERO)?;
    let deadline = Instant::now() + timeout;
    let mut pause = Duration::from_millis(1);
    let outcome = loop {
        match connection.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)) {
            Ok(mode) => break Ok(mode),
            Err(error) => {
                let retryable = matches!(&error, rusqlite::Error::SqliteFailure(code, _)
                    if matches!(code.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked));
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !retryable || remaining.is_zero() {
                    break Err(error.into());
                }
                std::thread::sleep(pause.min(remaining));
                pause = (pause * 2).min(Duration::from_millis(25));
            }
        }
    };
    connection.busy_timeout(Duration::from_millis(5000))?;
    outcome
}

#[cfg(test)]
mod wal_tests {
    use super::*;
    use rusqlite::OpenFlags;

    #[test]
    fn journal_mode_retries_a_real_reader_lock_and_restores_normal_timeout() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.sqlite3");
        let blocker = Connection::open(&path).unwrap();
        blocker.execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE fixture(value INTEGER); INSERT INTO fixture VALUES(1); BEGIN; SELECT * FROM fixture;").unwrap();
        let connection = Connection::open(&path).unwrap();
        connection.busy_timeout(Duration::ZERO).unwrap();
        assert!(
            matches!(connection.query_row::<String,_,_>("PRAGMA journal_mode=WAL",[],|r|r.get(0)),
            Err(rusqlite::Error::SqliteFailure(code,_)) if code.code==rusqlite::ErrorCode::DatabaseBusy)
        );
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            blocker.execute_batch("COMMIT").unwrap();
        });
        assert_eq!(
            enable_wal(&connection, Duration::from_secs(5)).unwrap(),
            "wal"
        );
        release.join().unwrap();
        assert_eq!(
            connection
                .query_row::<i64, _, _>("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap(),
            5000
        );
        assert_eq!(
            connection
                .query_row::<String, _, _>("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap(),
            "ok"
        );
    }

    #[test]
    fn journal_mode_lock_has_a_monotonic_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.sqlite3");
        let blocker = Connection::open(&path).unwrap();
        blocker.execute_batch("CREATE TABLE fixture(value INTEGER); INSERT INTO fixture VALUES(1); BEGIN; SELECT * FROM fixture;").unwrap();
        let connection = Connection::open(&path).unwrap();
        let started = Instant::now();
        assert!(matches!(enable_wal(&connection,Duration::from_millis(40)),
            Err(AuthorityError::Storage(rusqlite::Error::SqliteFailure(code,_))) if code.code==rusqlite::ErrorCode::DatabaseBusy));
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            connection
                .query_row::<i64, _, _>("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap(),
            5000
        );
        blocker.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn journal_mode_does_not_retry_readonly_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.sqlite3");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE fixture(value INTEGER)")
            .unwrap();
        let connection =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let started = Instant::now();
        assert!(matches!(enable_wal(&connection,Duration::from_secs(5)),
            Err(AuthorityError::Storage(rusqlite::Error::SqliteFailure(code,_))) if code.code==rusqlite::ErrorCode::ReadOnly));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            connection
                .query_row::<i64, _, _>("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap(),
            5000
        );
    }
}

fn private_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = fs::metadata(parent).map_err(|_| invalid("authority storage directory"))?;
    if !directory.is_dir() {
        return Err(invalid("authority storage directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if directory.mode() & 0o022 != 0 {
            return Err(invalid("authority storage directory permissions"));
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => file
                .sync_all()
                .map_err(|_| invalid("authority storage creation"))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(invalid("authority storage path")),
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| invalid("authority storage path"))?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return Err(invalid("authority storage file permissions or links"));
        }
    }
    #[cfg(not(unix))]
    {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.is_file() {
                return Err(invalid("authority storage path"));
            }
        }
    }
    Ok(())
}

fn invalid(reason: &'static str) -> AuthorityError {
    AuthorityError::Invalid(reason)
}
fn identifier(value: &str) -> Result<()> {
    if crate::uuid_ok(value) {
        Ok(())
    } else {
        Err(invalid("authority identifier"))
    }
}
fn time(at: i64) -> Result<()> {
    if (0..=MAX_TIME).contains(&at) {
        Ok(())
    } else {
        Err(invalid("authority timestamp"))
    }
}
fn interval(not_before: i64, not_after: i64, now: i64) -> Result<()> {
    time(not_before)?;
    time(not_after)?;
    time(now)?;
    if not_before >= not_after || now >= not_after {
        return Err(AuthorityError::Time);
    }
    Ok(())
}
fn at(at: i64) -> Result<String> {
    time(at)?;
    Ok(DateTime::<Utc>::from_timestamp(at, 0)
        .ok_or(invalid("authority timestamp"))?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string())
}
fn new_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| invalid("authority randomness"))?;
    Ok(uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string())
}
fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let encoded = canonical_bytes(value).map_err(|_| invalid("authority canonical bytes"))?;
    if encoded.len() > 262144 {
        return Err(invalid("authority record too large"));
    }
    Ok(encoded)
}
fn decode<T: DeserializeOwned + Serialize>(encoded: &[u8]) -> Result<T> {
    let value: T = parse_strict_with_limit(encoded, 262144)
        .map_err(|_| invalid("authority retained bytes"))?;
    if bytes(&value)? != encoded {
        return Err(invalid("noncanonical authority record"));
    }
    Ok(value)
}
fn hash(value: &str) -> Result<Vec<u8>> {
    if !crate::hash_ok(value) {
        return Err(invalid("authority hash"));
    }
    (7..71)
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| invalid("authority hash")))
        .collect()
}
fn hash_string(value: &[u8]) -> Result<String> {
    if value.len() != 32 {
        return Err(invalid("authority stored hash"));
    }
    let mut result = String::from("sha256:");
    use std::fmt::Write;
    for byte in value {
        write!(result, "{byte:02x}").expect("string write");
    }
    Ok(result)
}
fn role_name(role: ApprovalRole) -> &'static str {
    match role {
        ApprovalRole::Owner => "owner",
        ApprovalRole::NetworkReviewer => "network_reviewer",
        ApprovalRole::ServiceReviewer => "service_reviewer",
        ApprovalRole::SecurityReviewer => "security_reviewer",
    }
}
fn decision_name(decision: ApprovalDecision) -> &'static str {
    match decision {
        ApprovalDecision::Approve => "approve",
        ApprovalDecision::Reject => "reject",
    }
}
fn plan_kind_name(kind: crate::ApprovalPlanKind) -> &'static str {
    match kind {
        crate::ApprovalPlanKind::AddAccessLease => "add_access_lease",
        crate::ApprovalPlanKind::PolicyChange => "policy_change",
    }
}
fn security_revision(tx: &Transaction<'_>, tenant: &AuthorityTenant) -> Result<i64> {
    tx.query_row(
        "SELECT security_revision FROM authority_projects WHERE org_id=? AND project_id=?",
        params![tenant.org_id, tenant.project_id],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(AuthorityError::Binding)
}
fn bump_security(tx: &Transaction<'_>, tenant: &AuthorityTenant) -> Result<()> {
    if tx.execute("UPDATE authority_projects SET security_revision=security_revision+1 WHERE org_id=? AND project_id=? AND security_revision<2147483647",
        params![tenant.org_id,tenant.project_id])? != 1 { return Err(invalid("authority security revision exhausted")); }
    Ok(())
}
fn audit(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    kind: &str,
    resource: &str,
    now: i64,
) -> Result<()> {
    let (sequence, previous): (Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT sequence,event_hash FROM authority_audit_heads WHERE org_id=? AND project_id=?",
        params![tenant.org_id, tenant.project_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let sequence = u64::from_be_bytes(
        sequence
            .try_into()
            .map_err(|_| invalid("authority audit sequence"))?,
    )
    .checked_add(1)
    .ok_or(invalid("authority audit sequence exhausted"))?;
    let event = json!({"schema_version":"fw.authority-audit/v1", "org_id":tenant.org_id,"project_id":tenant.project_id,
        "sequence":sequence.to_string(),"previous_hash":hash_string(&previous)?,"kind":kind,"resource_id":resource,"recorded_at":at(now)?});
    let canonical = bytes(&event)?;
    let digest = hash(&hash_bytes(&canonical))?;
    tx.execute(
        "INSERT INTO authority_audit VALUES(?,?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            sequence.to_be_bytes().as_slice(),
            digest,
            previous,
            kind,
            resource,
            now,
            canonical
        ],
    )?;
    tx.execute(
        "UPDATE authority_audit_heads SET sequence=?,event_hash=? WHERE org_id=? AND project_id=?",
        params![
            sequence.to_be_bytes().as_slice(),
            digest,
            tenant.org_id,
            tenant.project_id
        ],
    )?;
    Ok(())
}
