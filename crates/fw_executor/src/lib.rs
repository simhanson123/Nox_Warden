//! Durable executor fencing and immutable execution/recovery material. This crate
//! never mutates a firewall. A trusted native adapter must verify actual kernel
//! evidence before recording it. FULL commits precede native writes and one file
//! lock spans each command's lifetime. Another process can recover after owner
//! exit/death; this is not a watchdog that can preempt a hung lock owner.
mod material;
#[cfg(test)]
mod material_tests;
mod recovery;
mod secure_path;
#[cfg(test)]
fn private_test_directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Create private fixtures explicitly: tempfile's default directory mode
        // follows the runner's umask and can otherwise be 0755.
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().unwrap()
}
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use fs2::FileExt;
use fw_authority::{pae, DsseEnvelope, TrustKey, VerifiedGrant};
use fw_contracts::{canonical_bytes, parse_strict};
pub use material::{ExecutionMaterial, JournalIdentity};
pub use recovery::RecoveryAttempt;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};

const CONFIRM_TYPE: &str = "application/vnd.fw.experimental-confirm.v1+json";
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("JOURNAL_IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("JOURNAL_DB: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("REPLAY")]
    Replay,
    #[error("CONFLICT")]
    Conflict,
    #[error("INVALID_BINDING")]
    Binding,
    #[error("JOURNAL_UNRESOLVED")]
    Unresolved,
    #[error("EXPIRED")]
    Expired,
    #[error("INVALID_TRANSITION")]
    Transition,
    #[error("INVALID_SIGNATURE")]
    Signature,
}
pub type Result<T> = std::result::Result<T, ExecutorError>;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Prepared,
    Unknown,
    Verifying,
    Confirmed,
    NotApplied,
    RecoveryClaimed,
    RolledBack,
}
impl State {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "PREPARED" => Ok(Self::Prepared),
            "UNKNOWN" => Ok(Self::Unknown),
            "VERIFYING" => Ok(Self::Verifying),
            "CONFIRMED" => Ok(Self::Confirmed),
            "NOT_APPLIED" => Ok(Self::NotApplied),
            "RECOVERY_CLAIMED" => Ok(Self::RecoveryClaimed),
            "ROLLED_BACK" => Ok(Self::RolledBack),
            _ => Err(ExecutorError::Binding),
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    pub operation_id: String,
    pub grant_hash: String,
    pub generation: String,
    pub state: State,
    pub desired_state_hash: String,
    pub baseline_hash: String,
    pub issued_at: i64,
    pub not_after: i64,
    pub confirm_not_after: i64,
    pub submitted_at: Option<i64>,
    pub confirm_deadline: Option<i64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub schema_version: String,
    pub operation_id: String,
    pub org_id: String,
    pub target_id: String,
    pub authority_epoch: String,
    pub target_generation: String,
    pub grant_hash: String,
    pub state_hash: String,
    pub probe_report_hash: String,
    pub issued_at_unix: i64,
    pub not_after_unix: i64,
}

pub struct ExecutorJournal {
    connection: Connection,
    _lock: File,
    _directory: File,
}
struct Acceptance<'a> {
    org_id: &'a str,
    target_id: &'a str,
    epoch: u64,
    generation: u64,
    grant_hash: &'a str,
    baseline_hash: &'a str,
    desired_state_hash: &'a str,
    issued_at: i64,
    not_after: i64,
    confirm_not_after: i64,
}
fn lock(path: &Path) -> Result<File> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let file = secure_path::open(Path::new(&lock_path), true, false)?;
    file.try_lock_exclusive()?;
    Ok(file)
}
fn configure(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
    )?;
    Ok(())
}
fn counter(value: &str) -> Result<u64> {
    let n = value.parse().map_err(|_| ExecutorError::Binding)?;
    if format!("{n}") != value {
        return Err(ExecutorError::Binding);
    }
    Ok(n)
}
fn hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
impl ExecutorJournal {
    /// Keep the same exclusive journal lock alive in a native child even if this
    /// process dies. Only that child's exec inherits the cloned descriptor;
    /// unrelated watchdogs and subsequent commands retain CLOEXEC. The caller
    /// must install this fence before spawning every native writer.
    #[cfg(unix)]
    pub fn fence_native_command(&self, command: &mut std::process::Command) -> Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let fence = self._lock.try_clone()?;
        // SAFETY: the child closure only calls async-signal-safe fcntl. Capturing
        // the File keeps its descriptor alive until exec; clearing CLOEXEC in the
        // child cannot change the parent's descriptor flags.
        unsafe {
            command.pre_exec(move || {
                let fd = fence.as_raw_fd();
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
    /// Explicit initial enrollment only. Never silently recreates a lost journal.
    /// Epoch authorization and trusted observed baseline are supplied by bootstrap.
    pub fn create(
        path: impl AsRef<Path>,
        org_id: &str,
        target_id: &str,
        epoch: u64,
        baseline_hash: &str,
    ) -> Result<Self> {
        if !uuid(org_id) || !uuid(target_id) || !hash(baseline_hash) {
            return Err(ExecutorError::Binding);
        }
        let path = path.as_ref();
        let directory = secure_path::parent(path)?;
        let locked = lock(path)?;
        secure_path::sidecars(path)?;
        let database = secure_path::open(path, true, true)?;
        database.sync_all()?;
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        secure_path::unchanged(path, &database)?;
        configure(&connection)?;
        connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), org_id TEXT NOT NULL,target_id TEXT NOT NULL,epoch TEXT NOT NULL,highest TEXT NOT NULL,state_hash TEXT NOT NULL); CREATE TABLE operations(operation_id TEXT PRIMARY KEY, grant_hash TEXT NOT NULL UNIQUE,generation TEXT NOT NULL UNIQUE,state TEXT NOT NULL,baseline_hash TEXT NOT NULL,desired_state_hash TEXT NOT NULL,issued_at INTEGER NOT NULL,not_after INTEGER NOT NULL,confirm_not_after INTEGER NOT NULL,submitted_at INTEGER,confirm_deadline INTEGER,observed_hash TEXT,probe_hash TEXT);")?;
        connection.execute_batch(material::MATERIAL_SCHEMA)?;
        connection.execute_batch(recovery::SCHEMA)?;
        connection.execute(
            "INSERT INTO identity VALUES(1,?1,?2,?3,'0',?4)",
            params![org_id, target_id, epoch.to_string(), baseline_hash],
        )?;
        connection.execute_batch("PRAGMA user_version=3; COMMIT;")?;
        directory.sync_all()?;
        Ok(Self {
            connection,
            _lock: locked,
            _directory: directory,
        })
    }
    /// Existing durable state is mandatory. Uncertain submissions become UNKNOWN.
    /// Complete material that never crossed the durable submission boundary closes
    /// as NOT_APPLIED; its generation remains consumed and cannot be dispatched.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let directory = secure_path::parent(path)?;
        let locked = lock(path)?;
        secure_path::sidecars(path)?;
        let database = secure_path::open(path, false, false)?;
        let mut connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        secure_path::unchanged(path, &database)?;
        configure(&connection)?;
        let version: u32 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        // Legacy journals lack dispatch-time bounds; never fabricate those
        // values or reset a high-water mark to recover them.
        if ![1, 2, 3].contains(&version) {
            return Err(ExecutorError::Binding);
        }
        let integrity: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(ExecutorError::Binding);
        }
        let (epoch, highest): (String, String) = connection.query_row(
            "SELECT epoch,highest FROM identity WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        counter(&epoch)?;
        counter(&highest)?;
        if version == 1 {
            connection.execute_batch("BEGIN IMMEDIATE;")?;
            connection.execute_batch(material::MATERIAL_SCHEMA)?;
            connection.execute_batch("PRAGMA user_version=2; COMMIT;")?;
        }
        if version < 3 {
            connection.execute_batch("BEGIN IMMEDIATE;")?;
            connection.execute_batch(recovery::SCHEMA)?;
            connection.execute_batch("PRAGMA user_version=3; COMMIT;")?;
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prepared = tx.prepare("SELECT operation_id FROM operations WHERE state='PREPARED' AND operation_id IN (SELECT operation_id FROM execution_material)")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for id in prepared {
            // Validate immutable material before trusting its submission boundary.
            // No actual-device observation is fabricated by this local close.
            material::read_material(&tx, &id)?.ok_or(ExecutorError::Binding)?;
            let operation = get_operation(&tx, &id)?.ok_or(ExecutorError::Binding)?;
            if operation.submitted_at.is_some() || operation.confirm_deadline.is_some() {
                return Err(ExecutorError::Binding);
            }
            tx.execute(
                "UPDATE operations SET state='NOT_APPLIED' WHERE operation_id=?1",
                [&id],
            )?;
        }
        // Legacy PREPARED has no proven native boundary. Preserve claimed recovery
        // across crashes so late confirmation cannot win.
        tx.execute(
            "UPDATE operations SET state='UNKNOWN' WHERE state IN ('VERIFYING','PREPARED')",
            [],
        )?;
        tx.commit()?;
        Ok(Self {
            connection,
            _lock: locked,
            _directory: directory,
        })
    }
    pub fn operation(&self, id: &str) -> Result<Option<Operation>> {
        material::read_material(&self.connection, id)?;
        get_operation(&self.connection, id)
    }
    pub fn highest_generation(&self) -> Result<u64> {
        let s: String = self.connection.query_row(
            "SELECT highest FROM identity WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        counter(&s)
    }
    pub fn accept(
        &mut self,
        grant: &VerifiedGrant,
        operation_id: &str,
        now: i64,
    ) -> Result<Operation> {
        self.accept_fields(
            &Acceptance {
                org_id: grant.org_id(),
                target_id: grant.target_id(),
                epoch: grant.authority_epoch(),
                generation: grant.generation(),
                grant_hash: grant.grant_hash(),
                baseline_hash: grant.baseline_hash(),
                desired_state_hash: grant.desired_state_hash(),
                issued_at: grant.issued_at(),
                not_after: grant.not_after(),
                confirm_not_after: grant.confirm_not_after(),
            },
            operation_id,
            now,
        )
    }
    fn accept_fields(&mut self, g: &Acceptance<'_>, id: &str, now: i64) -> Result<Operation> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = accept_fields_tx(&tx, g, id, now)?;
        tx.commit()?;
        Ok(operation)
    }
    /// Commit UNKNOWN durably BEFORE submitting to a native adapter. Success here
    /// is journal preparation only; it does not mean kernel application succeeded.
    pub fn mark_submitted(&mut self, id: &str, now: i64) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let op = get_operation(&tx, id)?.ok_or(ExecutorError::Binding)?;
        if op.state != State::Prepared {
            return Err(ExecutorError::Transition);
        }
        let material: Option<Option<String>> = tx
            .query_row(
                "SELECT watchdog_ack_hash FROM execution_material WHERE operation_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if material == Some(None) {
            return Err(ExecutorError::Transition);
        }
        if material.is_some() {
            material::read_material(&tx, id)?.ok_or(ExecutorError::Binding)?;
        }
        // Idempotent acceptance returns historic state even after expiry, but
        // submission requires the persisted signed dispatch window to be current.
        if now < op.issued_at || now >= op.not_after || now >= op.confirm_not_after {
            return Err(ExecutorError::Expired);
        }
        let confirm_deadline = now
            .checked_add(60)
            .ok_or(ExecutorError::Expired)?
            .min(op.confirm_not_after);
        tx.execute(
            "UPDATE operations SET state='UNKNOWN',submitted_at=?1,confirm_deadline=?2 WHERE operation_id=?3 AND state='PREPARED'",
            params![now, confirm_deadline, id],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// A locally authenticated backend supplies its freshly read semantic hash.
    /// Readback is not ACTIVE; confirm still requires signed probes and a CAS.
    pub fn record_observation(&mut self, id: &str, observed_hash: &str, now: i64) -> Result<State> {
        if !hash(observed_hash) {
            return Err(ExecutorError::Binding);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        material::read_material(&tx, id)?;
        let op = get_operation(&tx, id)?.ok_or(ExecutorError::Binding)?;
        if op.state != State::Unknown {
            return Err(ExecutorError::Transition);
        }
        if op.submitted_at.is_some_and(|submitted| now < submitted) {
            return Err(ExecutorError::Expired);
        }
        if observed_hash == op.baseline_hash {
            let (previous_observation, previous_probe, current, recovery_evidence):
                (Option<String>, Option<String>, String, bool) = tx.query_row(
                "SELECT observed_hash,probe_hash,(SELECT state_hash FROM identity WHERE singleton=1),
                 EXISTS(SELECT 1 FROM recovery_attempts WHERE operation_id=?1)
                 OR EXISTS(SELECT 1 FROM execution_material WHERE operation_id=?1 AND (recovery_report_hash IS NOT NULL OR recovered_at IS NOT NULL))
                 FROM operations WHERE operation_id=?1", [id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            if previous_observation.is_some()
                || previous_probe.is_some()
                || recovery_evidence
                || current != op.baseline_hash
            {
                // Matching an old baseline after prior application is drift,
                // not proof that submission never applied. Preserve all history
                // and the current identity projection; never reset either.
                tx.commit()?;
                return Ok(State::Unknown);
            }
        }
        let state = if observed_hash == op.desired_state_hash
            && op.confirm_deadline.is_some_and(|deadline| now < deadline)
        {
            "VERIFYING"
        } else if observed_hash == op.baseline_hash {
            "NOT_APPLIED"
        } else {
            "UNKNOWN"
        };
        tx.execute(
            "UPDATE operations SET state=?1,observed_hash=?2 WHERE operation_id=?3",
            params![state, observed_hash, id],
        )?;
        tx.commit()?;
        State::parse(state)
    }
    /// Experimental signed confirmation wire profile, deliberately distinct from
    /// the supplied contracts. The key MUST be registry-resolved with confirm role.
    pub fn confirm(&mut self, envelope: &DsseEnvelope, key: &TrustKey, now: i64) -> Result<State> {
        if envelope.payload_type != CONFIRM_TYPE
            || key.payload_type != CONFIRM_TYPE
            || key.revoked
            || now < key.not_before
            || now >= key.not_after
            || envelope.signatures.len() != 1
        {
            return Err(ExecutorError::Signature);
        }
        if envelope.payload.len() > 88_000 || envelope.signatures[0].sig.len() != 88 {
            return Err(ExecutorError::Signature);
        }
        let payload = STANDARD
            .decode(&envelope.payload)
            .map_err(|_| ExecutorError::Signature)?;
        let confirm: Confirmation = parse_strict(&payload).map_err(|_| ExecutorError::Binding)?;
        if canonical_bytes(&confirm).map_err(|_| ExecutorError::Binding)? != payload
            || confirm.schema_version != "fw.experimental-confirm/v1"
            || !hash(&confirm.probe_report_hash)
        {
            return Err(ExecutorError::Binding);
        }
        let signature = &envelope.signatures[0];
        if signature.keyid != key.key_id {
            return Err(ExecutorError::Signature);
        }
        let signature = Signature::from_slice(
            &STANDARD
                .decode(&signature.sig)
                .map_err(|_| ExecutorError::Signature)?,
        )
        .map_err(|_| ExecutorError::Signature)?;
        VerifyingKey::from_bytes(&key.public_key)
            .map_err(|_| ExecutorError::Signature)?
            .verify_strict(&pae(CONFIRM_TYPE, &payload), &signature)
            .map_err(|_| ExecutorError::Signature)?;
        if now < confirm.issued_at_unix
            || now >= confirm.not_after_unix
            || confirm.not_after_unix > key.not_after
            || confirm.issued_at_unix < key.not_before
            || confirm
                .not_after_unix
                .checked_sub(confirm.issued_at_unix)
                .is_none_or(|duration| duration > 60)
        {
            return Err(ExecutorError::Expired);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (org, target, epoch, highest): (String, String, String, String) = tx.query_row(
            "SELECT org_id,target_id,epoch,highest FROM identity WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        if org != key.org_id
            || org != confirm.org_id
            || target != confirm.target_id
            || epoch != confirm.authority_epoch
            || highest != confirm.target_generation
        {
            return Err(ExecutorError::Binding);
        }
        let op = get_operation(&tx, &confirm.operation_id)?.ok_or(ExecutorError::Binding)?;
        material::read_material(&tx, &confirm.operation_id)?;
        if op.grant_hash != confirm.grant_hash
            || op.desired_state_hash != confirm.state_hash
            || op.generation != confirm.target_generation
        {
            return Err(ExecutorError::Binding);
        }
        let deadline = op.confirm_deadline.ok_or(ExecutorError::Transition)?;
        let submitted_at = op.submitted_at.ok_or(ExecutorError::Transition)?;
        if now >= deadline
            || confirm.not_after_unix > deadline
            || confirm.issued_at_unix < submitted_at
        {
            return Err(ExecutorError::Expired);
        }
        if op.state != State::Verifying {
            return Err(ExecutorError::Transition);
        }
        tx.execute("UPDATE operations SET state='CONFIRMED',probe_hash=?1 WHERE operation_id=?2 AND state='VERIFYING'",params![confirm.probe_report_hash,confirm.operation_id])?;
        tx.execute(
            "UPDATE identity SET state_hash=?1 WHERE singleton=1",
            [confirm.state_hash],
        )?;
        tx.commit()?;
        Ok(State::Confirmed)
    }
    /// Claims recovery once; does not execute any rollback or restore raw rules.
    pub fn claim_recovery(
        &mut self,
        id: &str,
        generation: u64,
        desired_hash: &str,
        now: i64,
    ) -> Result<State> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        material::read_material(&tx, id)?;
        let highest: String =
            tx.query_row("SELECT highest FROM identity WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        let op = get_operation(&tx, id)?.ok_or(ExecutorError::Binding)?;
        if counter(&highest)? != generation
            || counter(&op.generation)? != generation
            || op.desired_state_hash != desired_hash
        {
            return Err(ExecutorError::Binding);
        }
        let deadline = op.confirm_deadline.unwrap_or(op.confirm_not_after);
        if now < deadline || !matches!(op.state, State::Verifying | State::Unknown) {
            return Err(ExecutorError::Transition);
        }
        let recovery_limit: Option<i64> = tx
            .query_row(
                "SELECT recovery_valid_until FROM execution_material WHERE operation_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if recovery_limit.is_some_and(|limit| now >= limit) {
            return Err(ExecutorError::Expired);
        }
        tx.execute(
            "UPDATE operations SET state='RECOVERY_CLAIMED' WHERE operation_id=?1",
            [id],
        )?;
        tx.commit()?;
        Ok(State::RecoveryClaimed)
    }
}
fn accept_fields_tx(tx: &Connection, g: &Acceptance<'_>, id: &str, now: i64) -> Result<Operation> {
    if !uuid(id) {
        return Err(ExecutorError::Binding);
    }
    let (org, target, epoch, highest, current): (String, String, String, String, String) = tx
        .query_row(
            "SELECT org_id,target_id,epoch,highest,state_hash FROM identity WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
    let epoch = counter(&epoch)?;
    let highest = counter(&highest)?;
    if epoch != g.epoch || org != g.org_id || target != g.target_id {
        return Err(ExecutorError::Binding);
    }
    if g.generation < highest {
        return Err(ExecutorError::Replay);
    }
    if g.generation == highest {
        let op = get_operation(tx, id)?.ok_or(ExecutorError::Conflict)?;
        if op.grant_hash != g.grant_hash || counter(&op.generation)? != g.generation {
            return Err(ExecutorError::Conflict);
        }
        return Ok(op);
    }
    if now < g.issued_at || now >= g.not_after || now >= g.confirm_not_after {
        return Err(ExecutorError::Expired);
    }
    if current != g.baseline_hash {
        return Err(ExecutorError::Binding);
    }
    let unresolved: u64 = tx.query_row(
            "SELECT COUNT(*) FROM operations WHERE state NOT IN ('CONFIRMED','NOT_APPLIED','ROLLED_BACK')",
            [],
            |r| r.get(0),
        )?;
    if unresolved > 0 {
        return Err(ExecutorError::Unresolved);
    }
    tx.execute("INSERT INTO operations(operation_id,grant_hash,generation,state,baseline_hash,desired_state_hash,issued_at,not_after,confirm_not_after) VALUES(?1,?2,?3,'PREPARED',?4,?5,?6,?7,?8)",params![id,g.grant_hash,g.generation.to_string(),g.baseline_hash,g.desired_state_hash,g.issued_at,g.not_after,g.confirm_not_after])?;
    tx.execute(
        "UPDATE identity SET highest=?1 WHERE singleton=1",
        [g.generation.to_string()],
    )?;
    let operation = get_operation(tx, id)?.ok_or(ExecutorError::Binding)?;
    Ok(operation)
}

fn get_operation(connection: &Connection, id: &str) -> Result<Option<Operation>> {
    let row = connection.query_row(
        "SELECT operation_id,grant_hash,generation,state,desired_state_hash,baseline_hash,issued_at,not_after,confirm_not_after,submitted_at,confirm_deadline FROM operations WHERE operation_id=?1",
        [id],
        |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,i64>(6)?,r.get::<_,i64>(7)?,r.get::<_,i64>(8)?,r.get::<_,Option<i64>>(9)?,r.get::<_,Option<i64>>(10)?)),
    ).optional()?;
    row.map(
        |(
            operation_id,
            grant_hash,
            generation,
            state,
            desired_state_hash,
            baseline_hash,
            issued_at,
            not_after,
            confirm_not_after,
            submitted_at,
            confirm_deadline,
        )| {
            Ok(Operation {
                operation_id,
                grant_hash,
                generation,
                state: State::parse(&state)?,
                desired_state_hash,
                baseline_hash,
                issued_at,
                not_after,
                confirm_not_after,
                submitted_at,
                confirm_deadline,
            })
        },
    )
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    const ORG: &str = "11111111-1111-4111-8111-111111111111";
    const TARGET: &str = "22222222-2222-4222-8222-222222222222";
    const OP: &str = "33333333-3333-4333-8333-333333333333";
    fn h(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }
    fn fields() -> Acceptance<'static> {
        Acceptance {
            org_id: ORG,
            target_id: TARGET,
            epoch: 1,
            generation: 1,
            grant_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            baseline_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            desired_state_hash:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            issued_at: 90,
            not_after: 200,
            confirm_not_after: 260,
        }
    }
    #[test]
    fn restart_preserves_generation_and_unknown() {
        let d = private_test_directory();
        let p = d.path().join("journal.db");
        {
            let mut j = ExecutorJournal::create(&p, ORG, TARGET, 1, &h('b')).unwrap();
            j.accept_fields(&fields(), OP, 100).unwrap();
            assert!(ExecutorJournal::open(&p).is_err());
        }
        let mut j = ExecutorJournal::open(&p).unwrap();
        assert_eq!(j.highest_generation().unwrap(), 1);
        assert_eq!(j.operation(OP).unwrap().unwrap().state, State::Unknown);
        assert_eq!(
            j.accept_fields(&fields(), OP, 500).unwrap().state,
            State::Unknown
        );
        let mut f = fields();
        f.generation = 2;
        assert!(matches!(
            j.accept_fields(&f, "44444444-4444-4444-8444-444444444444", 100),
            Err(ExecutorError::Unresolved)
        ));
    }
    #[test]
    fn lost_journal_not_created_and_existing_not_overwritten() {
        let d = private_test_directory();
        let p = d.path().join("journal.db");
        assert!(ExecutorJournal::open(&p).is_err());
        assert!(!p.exists());
        let j = ExecutorJournal::create(&p, ORG, TARGET, 1, &h('b')).unwrap();
        drop(j);
        assert!(ExecutorJournal::create(&p, ORG, TARGET, 1, &h('b')).is_err());
    }
    #[test]
    fn replay_conflict_and_not_applied_consumes_generation() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        j.accept_fields(&fields(), OP, 100).unwrap();
        let mut f = fields();
        f.grant_hash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        assert!(matches!(
            j.accept_fields(&f, OP, 100),
            Err(ExecutorError::Conflict)
        ));
        j.mark_submitted(OP, 170).unwrap();
        assert_eq!(
            j.record_observation(OP, &h('b'), 175).unwrap(),
            State::NotApplied
        );
        assert_eq!(j.highest_generation().unwrap(), 1);
        f.generation = 0;
        assert!(matches!(
            j.accept_fields(&f, OP, 100),
            Err(ExecutorError::Replay)
        ));
    }
    fn confirmation() -> (DsseEnvelope, TrustKey) {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let c = Confirmation {
            schema_version: "fw.experimental-confirm/v1".into(),
            operation_id: OP.into(),
            org_id: ORG.into(),
            target_id: TARGET.into(),
            authority_epoch: "1".into(),
            target_generation: "1".into(),
            grant_hash: h('a'),
            state_hash: h('c'),
            probe_report_hash: h('d'),
            issued_at_unix: 180,
            not_after_unix: 230,
        };
        let bytes = canonical_bytes(&c).unwrap();
        let envelope = DsseEnvelope {
            payload_type: CONFIRM_TYPE.into(),
            payload: STANDARD.encode(&bytes),
            signatures: vec![fw_authority::DsseSignature {
                keyid: "confirm-key".into(),
                sig: STANDARD.encode(signing.sign(&pae(CONFIRM_TYPE, &bytes)).to_bytes()),
            }],
        };
        let key = TrustKey {
            key_id: "confirm-key".into(),
            org_id: ORG.into(),
            payload_type: CONFIRM_TYPE.into(),
            public_key: signing.verifying_key().to_bytes(),
            not_before: 0,
            not_after: 300,
            revoked: false,
        };
        (envelope, key)
    }
    #[test]
    fn signed_confirm_requires_observation_and_fences_watchdog() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        j.accept_fields(&fields(), OP, 100).unwrap();
        let (e, k) = confirmation();
        assert!(j.confirm(&e, &k, 200).is_err());
        j.mark_submitted(OP, 170).unwrap();
        assert_eq!(
            j.record_observation(OP, &h('c'), 170).unwrap(),
            State::Verifying
        );
        assert_eq!(j.confirm(&e, &k, 200).unwrap(), State::Confirmed);
        assert!(j.claim_recovery(OP, 1, &h('c'), 261).is_err());
    }
    #[test]
    fn recovery_wins_and_unknown_is_not_active() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        j.accept_fields(&fields(), OP, 100).unwrap();
        j.mark_submitted(OP, 170).unwrap();
        assert_eq!(
            j.record_observation(OP, &h('e'), 170).unwrap(),
            State::Unknown
        );
        assert_eq!(
            j.claim_recovery(OP, 1, &h('c'), 260).unwrap(),
            State::RecoveryClaimed
        );
        let (e, k) = confirmation();
        assert!(j.confirm(&e, &k, 200).is_err());
    }
    #[test]
    fn forged_confirm_does_not_change_state() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        j.accept_fields(&fields(), OP, 100).unwrap();
        j.mark_submitted(OP, 170).unwrap();
        j.record_observation(OP, &h('c'), 170).unwrap();
        let (mut e, k) = confirmation();
        e.signatures[0].sig = STANDARD.encode([0u8; 64]);
        assert!(matches!(
            j.confirm(&e, &k, 200),
            Err(ExecutorError::Signature)
        ));
        assert_eq!(j.operation(OP).unwrap().unwrap().state, State::Verifying);
    }
    #[test]
    fn stale_watchdog_cannot_claim_new_generation() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        j.accept_fields(&fields(), OP, 100).unwrap();
        j.mark_submitted(OP, 170).unwrap();
        j.record_observation(OP, &h('b'), 175).unwrap();
        let mut next = fields();
        next.generation = 2;
        next.grant_hash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let id = "44444444-4444-4444-8444-444444444444";
        j.accept_fields(&next, id, 180).unwrap();
        assert!(matches!(
            j.claim_recovery(OP, 1, &h('c'), 300),
            Err(ExecutorError::Binding)
        ));
        assert_eq!(j.operation(id).unwrap().unwrap().state, State::Prepared);
        assert_eq!(j.highest_generation().unwrap(), 2);
    }
    #[test]
    fn authority_epoch_transition_requires_new_enrollment() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        let mut candidate = fields();
        candidate.epoch = 2;
        assert!(matches!(
            j.accept_fields(&candidate, OP, 100),
            Err(ExecutorError::Binding)
        ));
        assert_eq!(j.highest_generation().unwrap(), 0);
    }
    #[test]
    fn expired_prepared_replay_is_read_only_and_cannot_submit() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        let accepted = j.accept_fields(&fields(), OP, 100).unwrap();
        assert_eq!(accepted.issued_at, 90);
        assert_eq!(accepted.not_after, 200);
        // Retrieving a prior result is allowed after expiry; it is not renewed authority.
        let replayed = j.accept_fields(&fields(), OP, 201).unwrap();
        assert_eq!(replayed.state, State::Prepared);
        assert!(matches!(
            j.mark_submitted(OP, 200),
            Err(ExecutorError::Expired)
        ));
        let op = j.operation(OP).unwrap().unwrap();
        assert_eq!(op.state, State::Prepared);
        assert_eq!(op.submitted_at, None);
        assert_eq!(op.confirm_deadline, None);
        assert_eq!(j.highest_generation().unwrap(), 1);
    }
    #[test]
    fn clock_rollback_cannot_accept_or_submit_before_issue() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        assert!(matches!(
            j.accept_fields(&fields(), OP, 89),
            Err(ExecutorError::Expired)
        ));
        assert_eq!(j.highest_generation().unwrap(), 0);
        j.accept_fields(&fields(), OP, 100).unwrap();
        assert!(matches!(
            j.mark_submitted(OP, 89),
            Err(ExecutorError::Expired)
        ));
        assert_eq!(j.operation(OP).unwrap().unwrap().state, State::Prepared);
    }
    #[test]
    fn confirm_after_relative_timeout_rejected_before_absolute_cap() {
        let d = private_test_directory();
        let mut j = ExecutorJournal::create(d.path().join("j"), ORG, TARGET, 1, &h('b')).unwrap();
        j.accept_fields(&fields(), OP, 100).unwrap();
        j.mark_submitted(OP, 150).unwrap();
        assert_eq!(
            j.operation(OP).unwrap().unwrap().confirm_deadline,
            Some(210)
        );
        assert_eq!(
            j.record_observation(OP, &h('c'), 160).unwrap(),
            State::Verifying
        );
        let (envelope, key) = confirmation();
        // 211 is still before signed confirm_not_after=260 and signer expiry=300.
        assert!(matches!(
            j.confirm(&envelope, &key, 211),
            Err(ExecutorError::Expired)
        ));
        assert_eq!(j.operation(OP).unwrap().unwrap().state, State::Verifying);
        assert_eq!(
            j.claim_recovery(OP, 1, &h('c'), 210).unwrap(),
            State::RecoveryClaimed
        );
    }
    #[test]
    fn restart_and_delayed_observation_do_not_extend_confirm_deadline() {
        let d = private_test_directory();
        let path = d.path().join("j");
        {
            let mut j = ExecutorJournal::create(&path, ORG, TARGET, 1, &h('b')).unwrap();
            j.accept_fields(&fields(), OP, 100).unwrap();
            j.mark_submitted(OP, 110).unwrap();
        }
        let mut j = ExecutorJournal::open(&path).unwrap();
        let op = j.operation(OP).unwrap().unwrap();
        assert_eq!(
            (
                op.issued_at,
                op.not_after,
                op.submitted_at,
                op.confirm_deadline
            ),
            (90, 200, Some(110), Some(170))
        );
        assert_eq!(
            j.record_observation(OP, &h('c'), 171).unwrap(),
            State::Unknown
        );
        assert_eq!(
            j.operation(OP).unwrap().unwrap().confirm_deadline,
            Some(170)
        );
        assert_eq!(
            j.claim_recovery(OP, 1, &h('c'), 171).unwrap(),
            State::RecoveryClaimed
        );
    }
    #[test]
    fn unknown_journal_version_is_not_assigned_fabricated_time_bounds() {
        let d = private_test_directory();
        let path = d.path().join("j");
        let j = ExecutorJournal::create(&path, ORG, TARGET, 1, &h('b')).unwrap();
        j.connection.execute_batch("PRAGMA user_version=0").unwrap();
        drop(j);
        assert!(matches!(
            ExecutorJournal::open(&path),
            Err(ExecutorError::Binding)
        ));
    }
}
