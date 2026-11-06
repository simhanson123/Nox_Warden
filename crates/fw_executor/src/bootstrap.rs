//! Separate durable target-bootstrap fence. This never opens a grant journal or
//! infers kernel success: only a separately verified target receipt can finish.
use crate::{counter, hash, lock, secure_path, uuid, ExecutorError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use fw_authority::VerifiedTargetBootstrapConfirmation;
use fw_contracts::{canonical_bytes, hash_bytes, parse_strict_with_limit};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::{Path, PathBuf},
};

const LIMIT: usize = 1024 * 1024;
const APPLICATION: i64 = 0x4657424a;
type ExistingBootstrapIntentRow = (Vec<u8>, Vec<u8>, String, Option<Vec<u8>>);
const SCHEMA: &str = "CREATE TABLE bootstrap_identity (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),journal_id TEXT NOT NULL,
 org_id TEXT NOT NULL,project_id TEXT NOT NULL,target_id TEXT NOT NULL,
 epoch TEXT NOT NULL,highest_generation TEXT NOT NULL CHECK(highest_generation='0'),
 state TEXT NOT NULL CHECK(state IN ('EMPTY','PENDING','UNKNOWN','CONFIRMED')),
 confirmation_hash TEXT,observed_at INTEGER NOT NULL CHECK(observed_at>=0)
) STRICT;
CREATE TABLE bootstrap_intents (
 manifest_id TEXT PRIMARY KEY,challenge_id TEXT NOT NULL UNIQUE,
 binding_bytes BLOB NOT NULL,material_bytes BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('PENDING','UNKNOWN','CONFIRMED')),
 accepted_at INTEGER NOT NULL CHECK(accepted_at>=0),
 receipt_bytes BLOB,receipt_hash TEXT,
 CHECK((state='CONFIRMED' AND receipt_bytes IS NOT NULL AND receipt_hash IS NOT NULL)
 OR (state!='CONFIRMED' AND receipt_bytes IS NULL AND receipt_hash IS NULL))
) STRICT;";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapIntent {
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub manifest_id: String,
    pub manifest_hash: String,
    pub authorization_hash: String,
    pub challenge_id: String,
    pub challenge_hash: String,
    pub baseline_program_hash: String,
    pub material_hash: String,
    pub old_epoch: Option<String>,
    pub new_epoch: String,
    pub highest_generation: String,
    pub previous_confirmation_hash: Option<String>,
    pub valid_until_unix: i64,
}
impl BootstrapIntent {
    fn validate(&self) -> Result<()> {
        if [
            &self.org_id,
            &self.project_id,
            &self.target_id,
            &self.manifest_id,
            &self.challenge_id,
        ]
        .iter()
        .any(|v| !uuid(v))
            || [
                &self.manifest_hash,
                &self.authorization_hash,
                &self.challenge_hash,
                &self.baseline_program_hash,
                &self.material_hash,
            ]
            .iter()
            .any(|v| !hash(v))
            || self.highest_generation != "0"
            || counter(&self.new_epoch)? == 0
            || self.valid_until_unix < 0
            || self.valid_until_unix > 253_402_300_799
            || self
                .previous_confirmation_hash
                .as_ref()
                .is_some_and(|v| !hash(v))
        {
            return Err(ExecutorError::Binding);
        }
        if let Some(old) = &self.old_epoch {
            if counter(old)? == 0
                || counter(old)? >= counter(&self.new_epoch)?
                || self.previous_confirmation_hash.is_none()
            {
                return Err(ExecutorError::Binding);
            }
        } else if self.previous_confirmation_hash.is_some() {
            return Err(ExecutorError::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapJournalHead {
    pub journal_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub authority_epoch: String,
    pub highest_generation: String,
    pub state: String,
    pub confirmation_hash: Option<String>,
    pub observed_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapPreparation {
    Pending { journal_id: String },
    Retained { receipt_bytes: Vec<u8> },
}

pub struct BootstrapRetainedConfirmation {
    pub material_bytes: Vec<u8>,
    pub receipt_bytes: Vec<u8>,
}

pub struct BootstrapJournal {
    // Drop SQLite before any other descriptor. No DB checker fd is retained.
    connection: Connection,
    _lock: File,
    _directory: File,
    path: PathBuf,
    identity: (u64, u64),
}

fn bounded(bytes: &[u8]) -> Result<()> {
    let value: serde_json::Value =
        parse_strict_with_limit(bytes, LIMIT).map_err(|_| ExecutorError::Binding)?;
    if canonical_bytes(&value).map_err(|_| ExecutorError::Binding)? != bytes {
        return Err(ExecutorError::Binding);
    }
    Ok(())
}

fn material_challenge(binding: &BootstrapIntent, bytes: &[u8]) -> Result<serde_json::Value> {
    bounded(bytes)?;
    if hash_bytes(bytes) != binding.material_hash {
        return Err(ExecutorError::Binding);
    }
    let material: serde_json::Value =
        parse_strict_with_limit(bytes, LIMIT).map_err(|_| ExecutorError::Binding)?;
    let challenge = &material["challenge"];
    let manifest = &material["manifest"];
    let authorization = &material["authorization"];
    let digest = |value: &serde_json::Value| {
        fw_contracts::canonical_hash(value).map_err(|_| ExecutorError::Binding)
    };
    let deadline = challenge["expires_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp());
    if material["schema_version"] != "fw.target-bootstrap-bundle/v1"
        || digest(challenge)? != binding.challenge_hash
        || digest(manifest)? != binding.manifest_hash
        || digest(authorization)? != binding.authorization_hash
        || challenge["org_id"] != binding.org_id
        || challenge["project_id"] != binding.project_id
        || challenge["target_id"] != binding.target_id
        || challenge["manifest_id"] != binding.manifest_id
        || challenge["challenge_id"] != binding.challenge_id
        || challenge["manifest_hash"] != binding.manifest_hash
        || challenge["authorization_hash"] != binding.authorization_hash
        || challenge["baseline_program_hash"] != binding.baseline_program_hash
        || challenge["old_epoch"]
            != serde_json::to_value(&binding.old_epoch).map_err(|_| ExecutorError::Binding)?
        || challenge["previous_confirmation_hash"]
            != serde_json::to_value(&binding.previous_confirmation_hash)
                .map_err(|_| ExecutorError::Binding)?
        || challenge["new_epoch"] != binding.new_epoch
        || challenge["highest_generation"] != binding.highest_generation
        || deadline != Some(binding.valid_until_unix)
        || manifest["manifest_id"] != binding.manifest_id
        || manifest["org_id"] != binding.org_id
        || manifest["project_id"] != binding.project_id
        || manifest["target_id"] != binding.target_id
        || manifest["old_epoch"] != challenge["old_epoch"]
        || manifest["new_epoch"] != challenge["new_epoch"]
        || authorization["payload"]["manifest_hash"] != binding.manifest_hash
        || digest(&material["baseline"])? != challenge["management_baseline_hash"]
        || digest(&material["capability"])? != challenge["capability_hash"]
        || manifest["management_baseline_hash"] != challenge["management_baseline_hash"]
        || manifest["capability_hash"] != challenge["capability_hash"]
        || !material["proofs"].is_array()
    {
        return Err(ExecutorError::Binding);
    }
    Ok(challenge.clone())
}

fn receipt_binding(
    binding: &BootstrapIntent,
    material: &[u8],
    receipt: &[u8],
    journal_id: &str,
) -> Result<()> {
    bounded(receipt)?;
    let challenge = material_challenge(binding, material)?;
    let value: serde_json::Value =
        parse_strict_with_limit(receipt, LIMIT).map_err(|_| ExecutorError::Binding)?;
    let payload = &value["payload"];
    let dsse = &value["dsse"];
    if value["schema_version"] != "fw.target-bootstrap-confirmation-envelope/v1"
        || payload["schema_version"] != "fw.target-bootstrap-confirmation/v1"
        || payload["journal_id"] != journal_id
        || payload["challenge"] != challenge
        || payload["accepted_epoch"] != binding.new_epoch
        || payload["highest_generation"] != "0"
        || dsse["payloadType"] != "application/vnd.fw.target-bootstrap-confirmation.v1+json"
        || dsse["payload"]
            != STANDARD.encode(canonical_bytes(payload).map_err(|_| ExecutorError::Binding)?)
        || dsse["signatures"].as_array().map(Vec::len) != Some(1)
        || dsse["signatures"][0]["keyid"] != challenge["key_id"]
    {
        return Err(ExecutorError::Binding);
    }
    let signature = dsse["signatures"][0]["sig"]
        .as_str()
        .ok_or(ExecutorError::Binding)?;
    let decoded = STANDARD
        .decode(signature)
        .map_err(|_| ExecutorError::Binding)?;
    if decoded.len() != 64 || STANDARD.encode(decoded) != signature {
        return Err(ExecutorError::Binding);
    }
    Ok(())
}

fn metadata(path: &Path, optional: bool) -> Result<Option<(u64, u64)>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            // SAFETY: geteuid has no arguments or pointer preconditions.
            let uid = unsafe { libc::geteuid() };
            if !meta.is_file()
                || meta.uid() != uid
                || meta.nlink() != 1
                || meta.mode() & 0o077 != 0
                || meta.mode() & 0o400 == 0
                || meta.len() > 128 * 1024 * 1024
            {
                return Err(ExecutorError::Binding);
            }
            Ok(Some((meta.dev(), meta.ino())))
        }
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

impl BootstrapJournal {
    /// Explicit fresh state only. An existing or missing retained journal is
    /// never silently initialized by open(). The adapter also owns its anchor.
    pub fn create(
        path: impl AsRef<Path>,
        org_id: &str,
        project_id: &str,
        target_id: &str,
        now: i64,
    ) -> Result<Self> {
        if !uuid(org_id)
            || !uuid(project_id)
            || !uuid(target_id)
            || !(0..=253_402_300_799).contains(&now)
        {
            return Err(ExecutorError::Binding);
        }
        let path = path.as_ref();
        let directory = secure_path::parent(path)?;
        let locked = lock(path)?;
        secure_path::sidecars(path)?;
        // Close this creation fd BEFORE SQLite opens the inode.
        {
            let file = secure_path::open(path, true, true)?;
            file.sync_all()?;
        }
        let identity = metadata(path, false)?.ok_or(ExecutorError::Binding)?;
        let lock_metadata = locked.metadata()?;
        if identity == (lock_metadata.dev(), lock_metadata.ino()) {
            return Err(ExecutorError::Binding);
        }
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;")?;
        connection.execute_batch(SCHEMA)?;
        connection.execute(
            "INSERT INTO bootstrap_identity VALUES(1,?,?,?,?, '0','0','EMPTY',NULL,?)",
            params![
                uuid::Uuid::new_v4().to_string(),
                org_id,
                project_id,
                target_id,
                now
            ],
        )?;
        connection.pragma_update(None, "application_id", APPLICATION)?;
        connection.pragma_update(None, "user_version", 1)?;
        connection.execute_batch("COMMIT;")?;
        directory.sync_all()?;
        let result = Self {
            connection,
            _lock: locked,
            _directory: directory,
            path: path.into(),
            identity,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let directory = secure_path::parent(path)?;
        let locked = lock(path)?;
        // All checker leaf descriptors are closed before SQLite opens.
        secure_path::sidecars(path)?;
        {
            let _file = secure_path::open(path, false, false)?;
        }
        let identity = metadata(path, false)?.ok_or(ExecutorError::Binding)?;
        let lock_metadata = locked.metadata()?;
        if identity == (lock_metadata.dev(), lock_metadata.ino()) {
            return Err(ExecutorError::Binding);
        }
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let application: i64 = connection.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if application != APPLICATION || version != 1 {
            return Err(ExecutorError::Binding);
        }
        connection.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        let mut result = Self {
            connection,
            _lock: locked,
            _directory: directory,
            path: path.into(),
            identity,
        };
        result.validate()?;
        // A previous owner may have written any prefix of the native batch.
        // Never retry that write or promote pending work into confirmation.
        let tx = result
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE bootstrap_intents SET state='UNKNOWN' WHERE state='PENDING'",
            [],
        )?;
        tx.execute(
            "UPDATE bootstrap_identity SET state='UNKNOWN' WHERE state='PENDING'",
            [],
        )?;
        tx.commit()?;
        result.validate()?;
        Ok(result)
    }

    fn check_backing(&self) -> Result<()> {
        let _parent = secure_path::parent(&self.path)?;
        if metadata(&self.path, false)? != Some(self.identity) {
            return Err(ExecutorError::Binding);
        }
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut path = self.path.as_os_str().to_os_string();
            path.push(suffix);
            metadata(Path::new(&path), true)?;
        }
        if metadata(&self.path, false)? != Some(self.identity) {
            return Err(ExecutorError::Binding);
        }
        Ok(())
    }

    pub fn head(&self) -> Result<BootstrapJournalHead> {
        self.check_backing()?;
        self.connection.query_row("SELECT journal_id,org_id,project_id,target_id,epoch,highest_generation,state,confirmation_hash,observed_at FROM bootstrap_identity WHERE singleton=1",[],|r|Ok(BootstrapJournalHead{journal_id:r.get(0)?,org_id:r.get(1)?,project_id:r.get(2)?,target_id:r.get(3)?,authority_epoch:r.get(4)?,highest_generation:r.get(5)?,state:r.get(6)?,confirmation_hash:r.get(7)?,observed_at:r.get(8)?})).map_err(Into::into)
    }

    fn validate(&self) -> Result<()> {
        self.check_backing()?;
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let app: i64 = self
            .connection
            .query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if version != 1 || app != APPLICATION || integrity != "ok" {
            return Err(ExecutorError::Binding);
        }
        let head = self.head()?;
        if !uuid(&head.journal_id)
            || !uuid(&head.org_id)
            || !uuid(&head.project_id)
            || !uuid(&head.target_id)
            || head.highest_generation != "0"
            || !(0..=253_402_300_799).contains(&head.observed_at)
            || counter(&head.authority_epoch).is_err()
        {
            return Err(ExecutorError::Binding);
        }
        let mut query=self.connection.prepare("SELECT manifest_id,challenge_id,binding_bytes,material_bytes,state,accepted_at,receipt_bytes,receipt_hash FROM bootstrap_intents ORDER BY rowid LIMIT 129")?;
        let mut rows = query.query([])?;
        let mut count = 0;
        let mut highest = 0;
        let mut latest = None;
        let mut last_state = "EMPTY".to_string();
        while let Some(row) = rows.next()? {
            count += 1;
            if count > 128 {
                return Err(ExecutorError::Binding);
            }
            let binding_bytes: Vec<u8> = row.get(2)?;
            let material: Vec<u8> = row.get(3)?;
            let binding: BootstrapIntent = parse_strict_with_limit(&binding_bytes, 16384)
                .map_err(|_| ExecutorError::Binding)?;
            binding.validate()?;
            material_challenge(&binding, &material)?;
            let state: String = row.get(4)?;
            let accepted: i64 = row.get(5)?;
            if canonical_bytes(&binding).map_err(|_| ExecutorError::Binding)? != binding_bytes
                || binding.manifest_id != row.get::<_, String>(0)?
                || binding.challenge_id != row.get::<_, String>(1)?
                || hash_bytes(&material) != binding.material_hash
                || binding.org_id != head.org_id
                || binding.project_id != head.project_id
                || binding.target_id != head.target_id
                || accepted < 0
                || accepted >= binding.valid_until_unix
                || accepted > head.observed_at
                || counter(&binding.new_epoch)? <= highest
            {
                return Err(ExecutorError::Binding);
            }
            if highest == 0 {
                if binding.old_epoch.is_some() || binding.previous_confirmation_hash.is_some() {
                    return Err(ExecutorError::Binding);
                }
            } else if binding.old_epoch.as_deref().map(counter).transpose()? != Some(highest)
                || binding.previous_confirmation_hash != latest
            {
                return Err(ExecutorError::Binding);
            }
            highest = counter(&binding.new_epoch)?;
            last_state = state.clone();
            let receipt: Option<Vec<u8>> = row.get(6)?;
            let receipt_hash: Option<String> = row.get(7)?;
            match (state.as_str(), receipt, receipt_hash) {
                ("CONFIRMED", Some(bytes), Some(digest)) => {
                    receipt_binding(&binding, &material, &bytes, &head.journal_id)?;
                    if hash_bytes(&bytes) != digest {
                        return Err(ExecutorError::Binding);
                    }
                    latest = Some(digest);
                }
                ("PENDING" | "UNKNOWN", None, None) => {
                    if rows.next()?.is_some() {
                        return Err(ExecutorError::Binding);
                    }
                    if head.state != state {
                        return Err(ExecutorError::Binding);
                    }
                }
                _ => return Err(ExecutorError::Binding),
            }
        }
        if head.state != last_state
            || (count == 0 && (head.authority_epoch != "0" || head.confirmation_hash.is_some()))
            || (count > 0 && counter(&head.authority_epoch)? != highest)
            || head.confirmation_hash != latest
        {
            return Err(ExecutorError::Binding);
        }
        Ok(())
    }

    fn observe(&mut self, now: i64) -> Result<()> {
        self.validate()?;
        let head = self.head()?;
        if now < head.observed_at || !(0..=253_402_300_799).contains(&now) {
            return Err(ExecutorError::Expired);
        }
        self.connection.execute(
            "UPDATE bootstrap_identity SET observed_at=? WHERE singleton=1",
            [now],
        )?;
        Ok(())
    }

    pub fn retained_material(&self, manifest_id: &str) -> Result<Option<Vec<u8>>> {
        self.validate()?;
        self.connection
            .query_row(
                "SELECT material_bytes FROM bootstrap_intents WHERE manifest_id=?",
                [manifest_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn confirmed_predecessor(&self) -> Result<Option<BootstrapRetainedConfirmation>> {
        self.validate()?;
        let head = self.head()?;
        let Some(hash) = head.confirmation_hash else {
            return Ok(None);
        };
        self.connection.query_row("SELECT material_bytes,receipt_bytes FROM bootstrap_intents WHERE state='CONFIRMED' AND receipt_hash=?",[hash],|r|Ok(BootstrapRetainedConfirmation{material_bytes:r.get(0)?,receipt_bytes:r.get(1)?})).optional().map_err(Into::into)
    }

    pub fn prepare(
        &mut self,
        binding: &BootstrapIntent,
        material: &[u8],
        now: i64,
    ) -> Result<BootstrapPreparation> {
        binding.validate()?;
        material_challenge(binding, material)?;
        self.observe(now)?;
        let binding_bytes = canonical_bytes(binding).map_err(|_| ExecutorError::Binding)?;
        let head = self.head()?;
        if (&binding.org_id, &binding.project_id, &binding.target_id)
            != (&head.org_id, &head.project_id, &head.target_id)
        {
            return Err(ExecutorError::Binding);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing:Option<ExistingBootstrapIntentRow>=tx.query_row("SELECT binding_bytes,material_bytes,state,receipt_bytes FROM bootstrap_intents WHERE manifest_id=?",[&binding.manifest_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((saved, input, state, receipt)) = existing {
            if saved != binding_bytes || input != material {
                return Err(ExecutorError::Conflict);
            }
            return if state == "CONFIRMED" {
                Ok(BootstrapPreparation::Retained {
                    receipt_bytes: receipt.ok_or(ExecutorError::Binding)?,
                })
            } else {
                Err(ExecutorError::Unresolved)
            };
        }
        if now >= binding.valid_until_unix {
            return Err(ExecutorError::Expired);
        }
        match head.state.as_str() {
            "EMPTY"
                if binding.old_epoch.is_none() && binding.previous_confirmation_hash.is_none() => {}
            "CONFIRMED"
                if binding.old_epoch.as_deref() == Some(head.authority_epoch.as_str())
                    && binding.previous_confirmation_hash == head.confirmation_hash => {}
            "PENDING" | "UNKNOWN" => return Err(ExecutorError::Unresolved),
            _ => return Err(ExecutorError::Replay),
        }
        let count: i64 =
            tx.query_row("SELECT COUNT(*) FROM bootstrap_intents", [], |r| r.get(0))?;
        if count >= 128 {
            return Err(ExecutorError::Conflict);
        }
        tx.execute(
            "INSERT INTO bootstrap_intents VALUES(?,?,?,?,'PENDING',?,NULL,NULL)",
            params![
                binding.manifest_id,
                binding.challenge_id,
                binding_bytes,
                material,
                now
            ],
        )?;
        if tx.execute("UPDATE bootstrap_identity SET epoch=?,state='PENDING' WHERE singleton=1 AND epoch=? AND state=? AND confirmation_hash IS ?",params![binding.new_epoch,head.authority_epoch,head.state,head.confirmation_hash])?!=1{return Err(ExecutorError::Conflict);}
        tx.commit()?;
        self.validate()?;
        Ok(BootstrapPreparation::Pending {
            journal_id: head.journal_id,
        })
    }

    pub fn mark_unknown(&mut self, manifest_id: &str, now: i64) -> Result<()> {
        self.observe(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count = tx.execute(
            "UPDATE bootstrap_intents SET state='UNKNOWN' WHERE manifest_id=? AND state='PENDING'",
            [manifest_id],
        )?;
        if count == 1 {
            tx.execute(
                "UPDATE bootstrap_identity SET state='UNKNOWN' WHERE singleton=1",
                [],
            )?;
        }
        tx.commit()?;
        self.validate()
    }

    pub fn confirm(
        &mut self,
        binding: &BootstrapIntent,
        receipt: &VerifiedTargetBootstrapConfirmation,
        now: i64,
    ) -> Result<()> {
        self.commit_receipt(binding, receipt.canonical_bytes(), now)
    }

    fn commit_receipt(
        &mut self,
        binding: &BootstrapIntent,
        receipt: &[u8],
        now: i64,
    ) -> Result<()> {
        bounded(receipt)?;
        self.observe(now)?;
        if now >= binding.valid_until_unix {
            return Err(ExecutorError::Expired);
        }
        let head = self.head()?;
        let material = self
            .retained_material(&binding.manifest_id)?
            .ok_or(ExecutorError::Binding)?;
        receipt_binding(binding, &material, receipt, &head.journal_id)?;
        let binding_bytes = canonical_bytes(binding).map_err(|_| ExecutorError::Binding)?;
        let digest = hash_bytes(receipt);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.execute("UPDATE bootstrap_intents SET state='CONFIRMED',receipt_bytes=?,receipt_hash=? WHERE manifest_id=? AND binding_bytes=? AND state='PENDING'",params![receipt,digest,binding.manifest_id,binding_bytes])?!=1{return Err(ExecutorError::Transition);}
        if tx.execute("UPDATE bootstrap_identity SET state='CONFIRMED',confirmation_hash=? WHERE singleton=1 AND epoch=? AND state='PENDING'",params![digest,binding.new_epoch])?!=1{return Err(ExecutorError::Transition);}
        tx.commit()?;
        self.validate()
    }

    pub fn fence_native_command(&self, command: &mut std::process::Command) -> Result<()> {
        self.validate()?;
        let fence = self._lock.try_clone()?;
        // SAFETY: only async-signal-safe fcntl runs in the child. Its copy of the
        // lock description survives exec and fences an orphan native writer.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    const NOW: i64 = 1_800_000_000;
    const ORG: &str = "11111111-1111-4111-8111-111111111111";
    const PROJECT: &str = "22222222-2222-4222-8222-222222222222";
    const TARGET: &str = "33333333-3333-4333-8333-333333333333";
    fn at(now: i64) -> String {
        chrono::DateTime::from_timestamp(now, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }
    fn material(
        epoch: u64,
        old: Option<u64>,
        previous: Option<String>,
        deadline: i64,
    ) -> (BootstrapIntent, Vec<u8>) {
        // Private durability witness only. Public confirm requires an opaque
        // cryptographically verified receipt; this fixture supplies no authority.
        let baseline = json!({"test_baseline":true});
        let capability = json!({"test_capability":true});
        let manifest_id = uuid::Uuid::new_v4().to_string();
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let manifest = json!({"manifest_id":manifest_id,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"old_epoch":old.map(|n|n.to_string()),"new_epoch":epoch.to_string(),"management_baseline_hash":fw_contracts::canonical_hash(&baseline).unwrap(),"capability_hash":fw_contracts::canonical_hash(&capability).unwrap()});
        let manifest_hash = fw_contracts::canonical_hash(&manifest).unwrap();
        let authorization = json!({"payload":{"manifest_hash":manifest_hash}});
        let authorization_hash = fw_contracts::canonical_hash(&authorization).unwrap();
        let program_hash = hash_bytes(b"private test program");
        let challenge = json!({"challenge_id":challenge_id,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"manifest_id":manifest_id,"manifest_hash":manifest_hash,"authorization_hash":authorization_hash,"management_baseline_hash":manifest["management_baseline_hash"],"capability_hash":manifest["capability_hash"],"baseline_program_hash":program_hash,"old_epoch":old.map(|n|n.to_string()),"new_epoch":epoch.to_string(),"highest_generation":"0","previous_confirmation_hash":previous,"key_id":"private-test-key","expires_at":at(deadline)});
        let bytes=canonical_bytes(&json!({"schema_version":"fw.target-bootstrap-bundle/v1","manifest":manifest,"authorization":authorization,"proofs":[],"challenge":challenge,"baseline":baseline,"capability":capability})).unwrap();
        let binding = BootstrapIntent {
            org_id: ORG.into(),
            project_id: PROJECT.into(),
            target_id: TARGET.into(),
            manifest_id,
            manifest_hash,
            authorization_hash,
            challenge_id,
            challenge_hash: fw_contracts::canonical_hash(&challenge).unwrap(),
            baseline_program_hash: program_hash,
            material_hash: hash_bytes(&bytes),
            old_epoch: old.map(|n| n.to_string()),
            new_epoch: epoch.to_string(),
            highest_generation: "0".into(),
            previous_confirmation_hash: previous,
            valid_until_unix: deadline,
        };
        (binding, bytes)
    }
    fn receipt(journal: &BootstrapJournal, binding: &BootstrapIntent, material: &[u8]) -> Vec<u8> {
        let challenge = material_challenge(binding, material).unwrap();
        let payload = json!({"schema_version":"fw.target-bootstrap-confirmation/v1","journal_id":journal.head().unwrap().journal_id,"challenge":challenge,"accepted_epoch":binding.new_epoch,"highest_generation":"0"});
        canonical_bytes(&json!({"schema_version":"fw.target-bootstrap-confirmation-envelope/v1","payload":payload,"dsse":{"payloadType":"application/vnd.fw.target-bootstrap-confirmation.v1+json","payload":STANDARD.encode(canonical_bytes(&payload).unwrap()),"signatures":[{"keyid":"private-test-key","sig":STANDARD.encode([0;64])}]}})).unwrap()
    }
    fn create(path: &Path) -> BootstrapJournal {
        BootstrapJournal::create(path, ORG, PROJECT, TARGET, NOW).unwrap()
    }

    #[test]
    fn pending_epoch_survives_reopen_expiry_and_cannot_be_reissued() {
        let dir = crate::private_test_directory();
        let path = dir.path().join("bootstrap.sqlite3");
        let mut journal = create(&path);
        let (binding, bytes) = material(1, None, None, NOW + 300);
        assert!(matches!(
            journal.prepare(&binding, &bytes, NOW).unwrap(),
            BootstrapPreparation::Pending { .. }
        ));
        assert_eq!(journal.head().unwrap().authority_epoch, "1");
        drop(journal);
        let mut journal = BootstrapJournal::open(&path).unwrap();
        assert_eq!(journal.head().unwrap().state, "UNKNOWN");
        assert!(matches!(
            journal.prepare(&binding, &bytes, NOW + 301),
            Err(ExecutorError::Unresolved)
        ));
        assert_eq!(journal.head().unwrap().authority_epoch, "1");
        assert!(matches!(
            journal.prepare(&binding, &bytes, NOW),
            Err(ExecutorError::Expired)
        ));
        assert!(BootstrapJournal::create(&path, ORG, PROJECT, TARGET, NOW + 302).is_err());
    }

    #[test]
    fn exact_confirmed_bytes_remain_history_across_expiry_and_gen_zero_rotation() {
        let dir = crate::private_test_directory();
        let path = dir.path().join("bootstrap.sqlite3");
        let mut journal = create(&path);
        let (first, first_bytes) = material(1, None, None, NOW + 300);
        journal.prepare(&first, &first_bytes, NOW).unwrap();
        let original = receipt(&journal, &first, &first_bytes);
        journal.commit_receipt(&first, &original, NOW + 1).unwrap();
        drop(journal);
        let mut journal = BootstrapJournal::open(&path).unwrap();
        assert_eq!(
            journal.prepare(&first, &first_bytes, NOW + 600).unwrap(),
            BootstrapPreparation::Retained {
                receipt_bytes: original.clone()
            }
        );
        let (second, second_bytes) = material(2, Some(1), Some(hash_bytes(&original)), NOW + 1200);
        journal.prepare(&second, &second_bytes, NOW + 601).unwrap();
        assert_eq!(
            journal.prepare(&first, &first_bytes, NOW + 602).unwrap(),
            BootstrapPreparation::Retained {
                receipt_bytes: original.clone()
            }
        );
        assert_eq!(journal.head().unwrap().authority_epoch, "2");
        let second_receipt = receipt(&journal, &second, &second_bytes);
        journal
            .commit_receipt(&second, &second_receipt, NOW + 603)
            .unwrap();
        drop(journal);
        let mut journal = BootstrapJournal::open(&path).unwrap();
        assert_eq!(journal.head().unwrap().highest_generation, "0");
        assert_eq!(
            journal.prepare(&first, &first_bytes, NOW + 1300).unwrap(),
            BootstrapPreparation::Retained {
                receipt_bytes: original
            }
        );
        assert_eq!(journal.head().unwrap().authority_epoch, "2");
    }

    #[test]
    fn late_receipt_commit_failure_rolls_back_both_receipt_and_head() {
        let dir = crate::private_test_directory();
        let path = dir.path().join("bootstrap.sqlite3");
        let mut journal = create(&path);
        let (binding, bytes) = material(1, None, None, NOW + 300);
        journal.prepare(&binding, &bytes, NOW).unwrap();
        let signed = receipt(&journal, &binding, &bytes);
        journal.connection.execute_batch("CREATE TRIGGER deny_confirmation BEFORE UPDATE ON bootstrap_identity WHEN NEW.state='CONFIRMED' BEGIN SELECT RAISE(ABORT,'test late failure'); END;").unwrap();
        assert!(journal.commit_receipt(&binding, &signed, NOW + 1).is_err());
        assert_eq!(journal.head().unwrap().state, "PENDING");
        let state: (String, Option<Vec<u8>>) = journal
            .connection
            .query_row(
                "SELECT state,receipt_bytes FROM bootstrap_intents",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, ("PENDING".into(), None));
        journal
            .connection
            .execute_batch("DROP TRIGGER deny_confirmation;")
            .unwrap();
        journal.commit_receipt(&binding, &signed, NOW + 2).unwrap();
        assert_eq!(journal.head().unwrap().state, "CONFIRMED");
    }

    #[test]
    fn malformed_head_and_retained_cross_bindings_fail_before_mutation() {
        for mutation in [
            "UPDATE bootstrap_identity SET state='EMPTY'",
            "UPDATE bootstrap_identity SET observed_at=253402300800",
            "UPDATE bootstrap_identity SET journal_id='44444444-4444-4444-8444-444444444444'",
            "UPDATE bootstrap_identity SET epoch='2'",
            "UPDATE bootstrap_intents SET material_bytes=x'7B7D'",
        ] {
            let dir = crate::private_test_directory();
            let path = dir.path().join("bootstrap.sqlite3");
            let mut journal = create(&path);
            let (binding, bytes) = material(1, None, None, NOW + 300);
            journal.prepare(&binding, &bytes, NOW).unwrap();
            let signed = receipt(&journal, &binding, &bytes);
            journal.commit_receipt(&binding, &signed, NOW + 1).unwrap();
            journal.connection.execute_batch(mutation).unwrap();
            let before: (String, String, i64) = journal
                .connection
                .query_row(
                    "SELECT state,epoch,observed_at FROM bootstrap_identity",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            let (next, next_bytes) = material(2, Some(1), Some(hash_bytes(&signed)), NOW + 300);
            assert!(
                journal.prepare(&next, &next_bytes, NOW + 2).is_err(),
                "{mutation}"
            );
            let after: (String, String, i64) = journal
                .connection
                .query_row(
                    "SELECT state,epoch,observed_at FROM bootstrap_identity",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(after, before, "{mutation}");
            drop(journal);
            assert!(BootstrapJournal::open(&path).is_err(), "{mutation}");
        }
    }

    #[test]
    fn retained_receipt_for_another_challenge_is_rejected_even_with_updated_digest() {
        let dir = crate::private_test_directory();
        let path = dir.path().join("bootstrap.sqlite3");
        let mut journal = create(&path);
        let (binding, bytes) = material(1, None, None, NOW + 300);
        journal.prepare(&binding, &bytes, NOW).unwrap();
        let signed = receipt(&journal, &binding, &bytes);
        journal.commit_receipt(&binding, &signed, NOW + 1).unwrap();
        let mut value: Value = serde_json::from_slice(&signed).unwrap();
        value["payload"]["challenge"]["challenge_id"] = json!(uuid::Uuid::new_v4().to_string());
        value["dsse"]["payload"] =
            json!(STANDARD.encode(canonical_bytes(&value["payload"]).unwrap()));
        let altered = canonical_bytes(&value).unwrap();
        journal
            .connection
            .execute(
                "UPDATE bootstrap_intents SET receipt_bytes=?,receipt_hash=?",
                params![altered, hash_bytes(&altered)],
            )
            .unwrap();
        journal
            .connection
            .execute(
                "UPDATE bootstrap_identity SET confirmation_hash=?",
                [hash_bytes(&altered)],
            )
            .unwrap();
        assert!(journal.validate().is_err());
    }
}
