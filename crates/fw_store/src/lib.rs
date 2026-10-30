//! Transactional SQLite Lite repository. No kernel state is inferred from database state.
//! All repository access is scoped by a server-authenticated [`Tenant`].
use chrono::{DateTime, SecondsFormat, Utc};
use fw_contracts::{canonical_bytes, hash_bytes};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};
use thiserror::Error;
use uuid::Uuid;

pub mod registry;
pub use registry::RegistryMutation;

const REGISTRY_MIGRATION: &str = include_str!("../migrations/0002_registry.sql");
const MIGRATION: &str = include_str!("../migrations/0001_lite.sql");
const MAX_TIME: i64 = 253_402_300_799;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("resource not found")]
    NotFound,
    #[error("IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[error("PRECONDITION_FAILED")]
    PreconditionFailed,
    #[error("registry conflict: {0}")]
    Conflict(&'static str),
    #[error("registry resource is retired")]
    Retired,
    #[error("CLAIM_STALE")]
    ClaimStale,
    #[error("database integrity verification failed: {0}")]
    Integrity(&'static str),
    #[error("canonical JSON error: {0}")]
    Contract(#[from] fw_contracts::ContractError),
    #[error("domain error: {0}")]
    Domain(#[from] fw_domain::DomainError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("store lock poisoned")]
    Poisoned,
}
pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tenant {
    pub org_id: String,
    pub project_id: String,
}
impl Tenant {
    /// Construct only after authenticating the subject and selecting its assigned project.
    pub fn new(org_id: impl Into<String>, project_id: impl Into<String>) -> Result<Self> {
        let value = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
        };
        valid_uuid(&value.org_id)?;
        valid_uuid(&value.project_id)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestRecord {
    pub request_id: String,
    pub org_id: String,
    pub project_id: String,
    pub principal_id: String,
    pub revision: i32,
    pub created_at: String,
    pub request: Value,
    pub request_hash: String,
    pub state: String,
    pub operation_id: String,
    pub plan_ref: Option<Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation_id: String,
    pub kind: String,
    pub state: String,
    pub revision: i32,
    pub request_id: String,
    pub reason_code: Option<String>,
    pub completed_at: Option<String>,
}
impl OperationRecord {
    pub fn view(&self) -> Value {
        if let Some(completed_at) = &self.completed_at {
            json!({"operation_id":self.operation_id,"kind":self.kind,"state":self.state,"reason_code":self.reason_code,"completed_at":completed_at})
        } else {
            json!({"operation_id":self.operation_id,"kind":self.kind,"state":self.state,"retry_after_seconds":5,"reason_code":self.reason_code,"last_receipt_id":null})
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Submission {
    pub request: RequestRecord,
    pub operation: OperationRecord,
    pub replayed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxClaim {
    pub event_id: String,
    pub event_kind: String,
    pub payload: Value,
    pub generation: u64,
    pub claim_until: i64,
}

pub struct Store {
    connection: Mutex<Connection>,
}
impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::initialize(Connection::open(path)?, false)
    }
    pub fn in_memory() -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?, true)
    }
    fn initialize(mut connection: Connection, memory: bool) -> Result<Self> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let foreign_keys: i64 =
            connection.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
        let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |r| r.get(0))?;
        let mode: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        if foreign_keys != 1 || synchronous != 2 || (!memory && mode != "wal") {
            return Err(StoreError::Integrity(
                "required SQLite durability pragmas unavailable",
            ));
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, app_compat_min INTEGER NOT NULL, app_compat_max INTEGER NOT NULL) STRICT;")?;
        let migrations = [MIGRATION, REGISTRY_MIGRATION];
        let installed = {
            let mut query = transaction
                .prepare("SELECT version,checksum FROM schema_migrations ORDER BY version")?;
            let rows = query
                .query_map([], |row| {
                    Ok((row.get::<_, usize>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let user_version: usize =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if installed.len() > migrations.len()
            || (user_version != installed.len() && !(user_version == 0 && installed.len() <= 1))
        {
            return Err(StoreError::Integrity("incompatible database version"));
        }
        for (index, (version, checksum)) in installed.iter().enumerate() {
            if *version != index + 1 || *checksum != hash_bytes(migrations[index].as_bytes()) {
                return Err(StoreError::Integrity(
                    "unknown migration version or checksum",
                ));
            }
        }
        for (index, migration) in migrations.iter().enumerate().skip(installed.len()) {
            transaction.execute_batch(migration)?;
            let version = index + 1;
            transaction.execute(
                "INSERT INTO schema_migrations VALUES(?1,?2,?1,?1)",
                params![version, hash_bytes(migration.as_bytes())],
            )?;
        }
        transaction.pragma_update(None, "user_version", migrations.len())?;
        transaction.commit()?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StoreError::Poisoned)
    }

    pub fn ensure_tenant(
        &self,
        org_id: &str,
        project_id: &str,
        name: &str,
        now: i64,
    ) -> Result<Tenant> {
        let tenant = Tenant::new(org_id, project_id)?;
        valid_time(now)?;
        if name.is_empty() || name.len() > 256 {
            return Err(StoreError::InvalidInput("tenant name"));
        }
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO organizations(org_id,name,created_at) VALUES(?1,?2,?3) ON CONFLICT(org_id) DO NOTHING", params![org_id,name,now])?;
        tx.execute("INSERT INTO projects(org_id,project_id,name) VALUES(?1,?2,?3) ON CONFLICT(org_id,project_id) DO NOTHING",params![org_id,project_id,name])?;
        tx.execute("INSERT INTO audit_heads(org_id,project_id,sequence) VALUES(?1,?2,?3) ON CONFLICT(org_id,project_id) DO NOTHING", params![org_id,project_id,encode_u64(0).as_slice()])?;
        tx.commit()?;
        Ok(tenant)
    }
    pub fn ensure_principal(
        &self,
        t: &Tenant,
        principal_id: &str,
        kind: &str,
        now: i64,
    ) -> Result<()> {
        valid_uuid(principal_id)?;
        valid_time(now)?;
        if !["human", "workload", "worker", "issuer", "agent"].contains(&kind) {
            return Err(StoreError::InvalidInput("principal kind"));
        }
        let c = self.connection()?;
        c.execute("INSERT INTO principals(org_id,project_id,principal_id,kind,created_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(org_id,project_id,principal_id) DO NOTHING",params![t.org_id,t.project_id,principal_id,kind,now])?;
        let actual: String = c.query_row(
            "SELECT kind FROM principals WHERE org_id=?1 AND project_id=?2 AND principal_id=?3",
            params![t.org_id, t.project_id, principal_id],
            |r| r.get(0),
        )?;
        if actual != kind {
            return Err(StoreError::PreconditionFailed);
        }
        Ok(())
    }
    /// T1: original response, immutable request, validation operation, audit and outbox commit together.
    /// Caller must validate the exact wire schema and authenticate the supplied principal first.
    pub fn submit_request(
        &self,
        t: &Tenant,
        principal_id: &str,
        kind: &str,
        body: &Value,
        idempotency_key: &str,
        now: i64,
    ) -> Result<Submission> {
        self.submit_request_inner(t, principal_id, kind, body, idempotency_key, now, false)
    }
    /// Atomic observation-only admission: no target/binding authority is available.
    /// The request and its failed validation result commit together, so a crash cannot leave runnable work.
    pub fn submit_unenrolled_request(
        &self,
        t: &Tenant,
        principal_id: &str,
        kind: &str,
        body: &Value,
        idempotency_key: &str,
        now: i64,
    ) -> Result<Submission> {
        self.submit_request_inner(t, principal_id, kind, body, idempotency_key, now, true)
    }
    #[allow(clippy::too_many_arguments)]
    fn submit_request_inner(
        &self,
        t: &Tenant,
        principal_id: &str,
        kind: &str,
        body: &Value,
        idempotency_key: &str,
        now: i64,
        unenrolled: bool,
    ) -> Result<Submission> {
        valid_uuid(principal_id)?;
        valid_uuid(idempotency_key)?;
        valid_time(now)?;
        let (kind, route) = match kind {
            "access_request" | "add_access_lease" => {
                ("add_access_lease", "/api/v1/access-requests")
            }
            "policy_change" => ("policy_change", "/api/v1/policy-change-requests"),
            _ => return Err(StoreError::InvalidInput("request kind")),
        };
        let bytes = canonical_bytes(body)?;
        if bytes.len() > 65536 {
            return Err(StoreError::InvalidInput("request exceeds 64 KiB"));
        }
        let body_hash = sha256(&bytes);
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        active_principal(&tx, t, principal_id)?;
        let existing:Option<(Vec<u8>,Vec<u8>)>=tx.query_row("SELECT body_hash,response_bytes FROM idempotency WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND method='POST' AND route=?4 AND key=?5",params![t.org_id,t.project_id,principal_id,route,idempotency_key],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((old_hash, response)) = existing {
            if old_hash != body_hash {
                return Err(StoreError::IdempotencyConflict);
            }
            let mut result: Submission = serde_json::from_slice(&response)?;
            result.replayed = true;
            return Ok(result);
        }
        let initial_state = if unenrolled {
            "needs_info"
        } else {
            "submitted"
        };
        let operation_state = if unenrolled { "failed" } else { "queued" };
        let reason_code = if unenrolled {
            "CAPABILITY_UNSUPPORTED"
        } else {
            "PENDING"
        };
        let completed_at = if unenrolled { Some(now) } else { None };
        let request_id = Uuid::new_v4().to_string();
        let operation_id = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO requests VALUES(?1,?2,?3,?4,?5,1,?6,?7)",
            params![
                t.org_id,
                t.project_id,
                request_id,
                principal_id,
                kind,
                initial_state,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO request_revisions VALUES(?1,?2,?3,1,?4,?5,?6)",
            params![
                t.org_id,
                t.project_id,
                request_id,
                body_hash.as_slice(),
                bytes,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO operations VALUES(?1,?2,?3,?4,'validate',?6,1,?5,?5,?7,?8)",
            params![
                t.org_id,
                t.project_id,
                operation_id,
                request_id,
                now,
                operation_state,
                completed_at,
                reason_code
            ],
        )?;
        let request = RequestRecord {
            request_id: request_id.clone(),
            org_id: t.org_id.clone(),
            project_id: t.project_id.clone(),
            principal_id: principal_id.to_owned(),
            revision: 1,
            created_at: timestamp(now)?,
            request: body.clone(),
            request_hash: hash_bytes(&bytes),
            state: initial_state.into(),
            operation_id: operation_id.clone(),
            plan_ref: None,
        };
        let operation = OperationRecord {
            operation_id: operation_id.clone(),
            kind: "validate".into(),
            state: operation_state.into(),
            revision: 1,
            request_id: request_id.clone(),
            reason_code: Some(reason_code.into()),
            completed_at: completed_at.map(timestamp).transpose()?,
        };
        let result = Submission {
            request,
            operation,
            replayed: false,
        };
        let response = canonical_bytes(&result)?;
        tx.execute(
            "INSERT INTO idempotency VALUES(?1,?2,?3,'POST',?4,?5,?6,?7,202,?8,?9,?10)",
            params![
                t.org_id,
                t.project_id,
                principal_id,
                route,
                idempotency_key,
                body_hash.as_slice(),
                request_id,
                response,
                now,
                now.checked_add(30 * 86400)
                    .ok_or(StoreError::InvalidInput("expiry overflow"))?
            ],
        )?;
        enqueue(
            &tx,
            t,
            "request",
            &request_id,
            1,
            if unenrolled {
                "request.validation_failed"
            } else {
                "request.submitted"
            },
            &json!({"request_id":request_id,"operation_id":operation_id}),
            now,
        )?;
        append_audit(
            &tx,
            t,
            Some(principal_id),
            "request",
            "request",
            Some(&request_id),
            Some(&operation_id),
            "accepted",
            None,
            now,
        )?;
        if unenrolled {
            append_audit(
                &tx,
                t,
                None,
                "validation",
                "request",
                Some(&request_id),
                Some(&operation_id),
                "failed",
                Some(reason_code),
                now,
            )?;
        }
        tx.commit()?;
        Ok(result)
    }
    pub fn get_request(&self, t: &Tenant, request_id: &str) -> Result<RequestRecord> {
        valid_uuid(request_id)?;
        let c = self.connection()?;
        read_request(&c, t, request_id)
    }
    /// Bounded keyset pagination; this does not provide the F-2.0 read-snapshot cursor contract yet.
    pub fn list_requests(
        &self,
        t: &Tenant,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RequestRecord>> {
        valid_limit(limit)?;
        if let Some(id) = after_id {
            valid_uuid(id)?;
        }
        let c = self.connection()?;
        let mut statement=c.prepare("SELECT request_id FROM requests WHERE org_id=?1 AND project_id=?2 AND request_id>?3 ORDER BY request_id LIMIT ?4")?;
        let ids = statement
            .query_map(
                params![t.org_id, t.project_id, after_id.unwrap_or(""), limit],
                |r| r.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.iter().map(|id| read_request(&c, t, id)).collect()
    }
    pub fn get_operation(&self, t: &Tenant, operation_id: &str) -> Result<OperationRecord> {
        valid_uuid(operation_id)?;
        let c = self.connection()?;
        read_operation(&c, t, operation_id)
    }
    pub fn list_operations(
        &self,
        t: &Tenant,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<OperationRecord>> {
        valid_limit(limit)?;
        if let Some(id) = after_id {
            valid_uuid(id)?;
        }
        let c = self.connection()?;
        let mut statement=c.prepare("SELECT operation_id FROM operations WHERE org_id=?1 AND project_id=?2 AND operation_id>?3 ORDER BY operation_id LIMIT ?4")?;
        let ids = statement
            .query_map(
                params![t.org_id, t.project_id, after_id.unwrap_or(""), limit],
                |r| r.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.iter().map(|id| read_operation(&c, t, id)).collect()
    }
    /// State changes never modify the immutable request body. `ready` requires a plan and is not exposed here.
    pub fn compare_and_swap_request_state(
        &self,
        t: &Tenant,
        request_id: &str,
        expected_revision: i32,
        next_state: &str,
        now: i64,
    ) -> Result<RequestRecord> {
        valid_uuid(request_id)?;
        valid_time(now)?;
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_request(&tx, t, request_id)?;
        if old.revision != expected_revision || expected_revision == i32::MAX {
            return Err(StoreError::PreconditionFailed);
        }
        let allowed = match old.state.as_str() {
            "submitted" => {
                ["validating", "needs_info", "rejected", "cancelled"].contains(&next_state)
            }
            "validating" => ["needs_info", "rejected", "cancelled"].contains(&next_state),
            _ => false,
        };
        if !allowed {
            return Err(StoreError::InvalidInput("request state transition"));
        }
        tx.execute("UPDATE requests SET revision=revision+1,state=?4 WHERE org_id=?1 AND project_id=?2 AND request_id=?3 AND revision=?5",params![t.org_id,t.project_id,request_id,next_state,expected_revision])?;
        let terminal = next_state != "validating";
        let reason = match next_state {
            "cancelled" => "CANCELLED",
            "needs_info" => "CAPABILITY_UNSUPPORTED",
            "rejected" => "VALIDATION_FAILED",
            _ => "PENDING",
        };
        let operation_state = if next_state == "validating" {
            "running"
        } else if next_state == "cancelled" {
            "cancelled"
        } else {
            "failed"
        };
        tx.execute("UPDATE operations SET state=?4,revision=revision+1,updated_at=?5,completed_at=?6,reason_code=?7 WHERE org_id=?1 AND project_id=?2 AND request_id=?3",params![t.org_id,t.project_id,request_id,operation_state,now,if terminal{Some(now)}else{None},reason])?;
        enqueue(
            &tx,
            t,
            "request",
            request_id,
            expected_revision + 1,
            "request.state_changed",
            &json!({"request_id":request_id,"state":next_state}),
            now,
        )?;
        append_audit(
            &tx,
            t,
            None,
            "validation",
            "request",
            Some(request_id),
            Some(&old.operation_id),
            if terminal { "failed" } else { "pending" },
            Some(reason),
            now,
        )?;
        let updated = read_request(&tx, t, request_id)?;
        tx.commit()?;
        Ok(updated)
    }
    pub fn list_audit(&self, t: &Tenant, after_sequence: u64, limit: usize) -> Result<Vec<Value>> {
        valid_limit(limit)?;
        let c = self.connection()?;
        let mut statement=c.prepare("SELECT canonical_bytes,event_hash FROM audit_events WHERE org_id=?1 AND project_id=?2 AND sequence>?3 ORDER BY sequence LIMIT ?4")?;
        let rows = statement
            .query_map(
                params![
                    t.org_id,
                    t.project_id,
                    encode_u64(after_sequence).as_slice(),
                    limit
                ],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(bytes, hash)| {
                if sha256(&bytes).as_slice() != hash {
                    return Err(StoreError::Integrity("audit event hash mismatch"));
                }
                let mut value: Value = serde_json::from_slice(&bytes)?;
                value["event_hash"] = Value::String(hex_hash(&hash));
                Ok(value)
            })
            .collect()
    }
    /// Detect corruption of content, sequence, chain links and the current head. Not protection against a privileged DB rewrite.
    pub fn verify_audit_chain(&self, t: &Tenant) -> Result<u64> {
        let c = self.connection()?;
        let mut statement=c.prepare("SELECT sequence,canonical_bytes,event_hash,previous_hash FROM audit_events WHERE org_id=?1 AND project_id=?2 ORDER BY sequence")?;
        let mut rows = statement.query(params![t.org_id, t.project_id])?;
        let mut sequence = 0u64;
        let mut previous: Option<Vec<u8>> = None;
        while let Some(row) = rows.next()? {
            let number: Vec<u8> = row.get(0)?;
            let bytes: Vec<u8> = row.get(1)?;
            let hash: Vec<u8> = row.get(2)?;
            let prev: Option<Vec<u8>> = row.get(3)?;
            sequence = sequence
                .checked_add(1)
                .ok_or(StoreError::Integrity("audit sequence exhausted"))?;
            if decode_u64(&number)? != sequence
                || prev != previous
                || sha256(&bytes).as_slice() != hash
            {
                return Err(StoreError::Integrity("audit chain mismatch"));
            }
            let event: Value = serde_json::from_slice(&bytes)?;
            let expected_sequence = sequence.to_string();
            if event["sequence"].as_str() != Some(expected_sequence.as_str())
                || event["org_id"] != t.org_id
                || event["project_id"] != t.project_id
                || event["previous_event_hash"]
                    != previous
                        .as_ref()
                        .map(|p| Value::String(hex_hash(p)))
                        .unwrap_or(Value::Null)
            {
                return Err(StoreError::Integrity("audit projection mismatch"));
            }
            previous = Some(hash);
        }
        let (head,hash):(Vec<u8>,Option<Vec<u8>>)=c.query_row("SELECT sequence,last_event_hash FROM audit_heads WHERE org_id=?1 AND project_id=?2",params![t.org_id,t.project_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(StoreError::NotFound)?;
        if decode_u64(&head)? != sequence || hash != previous {
            return Err(StoreError::Integrity("audit head mismatch"));
        }
        Ok(sequence)
    }
    pub fn claim_outbox(
        &self,
        t: &Tenant,
        now: i64,
        lease_seconds: i64,
        limit: usize,
    ) -> Result<Vec<OutboxClaim>> {
        valid_time(now)?;
        if !(1..=50).contains(&limit) || !(1..=300).contains(&lease_seconds) {
            return Err(StoreError::InvalidInput("outbox claim bounds"));
        }
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement=tx.prepare("SELECT event_id,event_kind,payload_bytes,payload_hash,claim_generation FROM outbox WHERE org_id=?1 AND project_id=?2 AND available_at<=?3 AND (state='pending' OR (state='claimed' AND claim_until<=?3)) ORDER BY available_at,event_id LIMIT ?4")?;
        let rows = statement
            .query_map(params![t.org_id, t.project_id, now, limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut claims = Vec::new();
        for (id, kind, bytes, hash, generation) in rows {
            if sha256(&bytes).as_slice() != hash {
                return Err(StoreError::Integrity("outbox content mismatch"));
            }
            let generation = decode_u64(&generation)?
                .checked_add(1)
                .ok_or(StoreError::Integrity("claim generation exhausted"))?;
            let until = now
                .checked_add(lease_seconds)
                .ok_or(StoreError::InvalidInput("claim expiry overflow"))?;
            tx.execute("UPDATE outbox SET state='claimed',claim_generation=?4,claim_until=?5,attempt=attempt+1 WHERE org_id=?1 AND project_id=?2 AND event_id=?3",params![t.org_id,t.project_id,id,encode_u64(generation).as_slice(),until])?;
            claims.push(OutboxClaim {
                event_id: id,
                event_kind: kind,
                payload: serde_json::from_slice(&bytes)?,
                generation,
                claim_until: until,
            });
        }
        tx.commit()?;
        Ok(claims)
    }
    pub fn acknowledge_outbox(
        &self,
        t: &Tenant,
        event_id: &str,
        generation: u64,
        now: i64,
    ) -> Result<()> {
        valid_uuid(event_id)?;
        valid_time(now)?;
        let changed=self.connection()?.execute("UPDATE outbox SET state='delivered',claim_until=NULL WHERE org_id=?1 AND project_id=?2 AND event_id=?3 AND claim_generation=?4 AND state='claimed' AND claim_until>?5",params![t.org_id,t.project_id,event_id,encode_u64(generation).as_slice(),now])?;
        if changed != 1 {
            return Err(StoreError::ClaimStale);
        }
        Ok(())
    }
    /// Append a denial using a server-selected tenant and a verified actor, or None.
    /// Reasons are stable codes; submitted credentials or prompts must never be passed here.
    pub fn record_denied_action(
        &self,
        t: &Tenant,
        actor: Option<&str>,
        reason_code: &str,
        now: i64,
    ) -> Result<()> {
        valid_time(now)?;
        if reason_code.is_empty()
            || reason_code.len() > 64
            || !reason_code.as_bytes()[0].is_ascii_uppercase()
            || !reason_code
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(StoreError::InvalidInput("invalid reason code"));
        }
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(actor) = actor {
            valid_uuid(actor)?;
            active_principal(&tx, t, actor)?;
        }
        append_audit(
            &tx,
            t,
            actor,
            "denied_action",
            "system",
            None,
            None,
            "denied",
            Some(reason_code),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn count_requests(&self, t: &Tenant) -> Result<u64> {
        Ok(self.connection()?.query_row(
            "SELECT count(*) FROM requests WHERE org_id=?1 AND project_id=?2",
            params![t.org_id, t.project_id],
            |r| r.get(0),
        )?)
    }
    pub fn count_operations(&self, t: &Tenant) -> Result<u64> {
        Ok(self.connection()?.query_row(
            "SELECT count(*) FROM operations WHERE org_id=?1 AND project_id=?2",
            params![t.org_id, t.project_id],
            |r| r.get(0),
        )?)
    }
    pub fn count_audit(&self, t: &Tenant, after_sequence: u64) -> Result<u64> {
        Ok(self.connection()?.query_row(
            "SELECT count(*) FROM audit_events WHERE org_id=?1 AND project_id=?2 AND sequence>?3",
            params![
                t.org_id,
                t.project_id,
                encode_u64(after_sequence).as_slice()
            ],
            |r| r.get(0),
        )?)
    }
    /// Local inventory only: registration does not attest an executor or activate protection.
    pub fn register_observe_target(
        &self,
        t: &Tenant,
        target_id: &str,
        platform: &str,
    ) -> Result<()> {
        valid_uuid(target_id)?;
        let backend = match platform {
            "linux" => "nftables",
            "windows" => "windows_wfp",
            "macos" => "macos_network_extension",
            _ => return Err(StoreError::InvalidInput("platform")),
        };
        self.connection()?.execute(
            "INSERT INTO targets VALUES(?1,?2,?3,?4,?5,'observe_only')",
            params![t.org_id, t.project_id, target_id, platform, backend],
        )?;
        Ok(())
    }
    /// Persist a draft only, never an authorization or an applied policy. Caller still needs planner/approval.
    pub fn save_policy_draft(
        &self,
        t: &Tenant,
        policy: &fw_domain::Policy,
        expected_hash: Option<&str>,
        now: i64,
    ) -> Result<String> {
        valid_time(now)?;
        let policy = policy.normalized()?;
        if policy.org_id != t.org_id || policy.project_id != t.project_id {
            return Err(StoreError::NotFound);
        }
        let bytes = canonical_bytes(&policy)?;
        let hash = sha256(&bytes);
        let wire_hash = hash_bytes(&bytes);
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        active_principal(&tx, t, &policy.owner_id)?;
        let previous:Option<(i32,Vec<u8>,Vec<u8>,String)>=tx.query_row("SELECT p.current_revision,r.policy_hash,r.canonical_bytes,p.lifecycle FROM policies p JOIN policy_revisions r ON (p.org_id=r.org_id AND p.project_id=r.project_id AND p.policy_id=r.policy_id AND p.current_revision=r.revision) WHERE p.org_id=?1 AND p.project_id=?2 AND p.policy_id=?3",params![t.org_id,t.project_id,policy.policy_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((revision, old_hash, old_bytes, lifecycle)) = previous {
            if lifecycle != "draft"
                || expected_hash != Some(hex_hash(&old_hash).as_str())
                || policy.policy_revision != revision as u32 + 1
            {
                return Err(StoreError::PreconditionFailed);
            }
            if sha256(&old_bytes).as_slice() != old_hash {
                return Err(StoreError::Integrity("policy content hash mismatch"));
            }
            let old: fw_domain::Policy = serde_json::from_slice(&old_bytes)?;
            if policy.action != old.action
                || policy.target_id != old.target_id
                || policy.owner_id != old.owner_id
            {
                return Err(StoreError::InvalidInput("policy identity/action change"));
            }
            if policy.action == fw_domain::Action::Allow
                && (!policy.scope.is_subset_of(&old.scope)?
                    || fw_domain::timestamp(policy.lifetime.not_before())?
                        < fw_domain::timestamp(old.lifetime.not_before())?
                    || fw_domain::timestamp(
                        policy
                            .lifetime
                            .expires_at()
                            .ok_or(StoreError::InvalidInput("allow expiry"))?,
                    )? > fw_domain::timestamp(
                        old.lifetime
                            .expires_at()
                            .ok_or(StoreError::Integrity("allow expiry"))?,
                    )?)
            {
                return Err(StoreError::InvalidInput(
                    "allow expansion requires new request",
                ));
            }
            tx.execute("UPDATE policies SET current_revision=?4 WHERE org_id=?1 AND project_id=?2 AND policy_id=?3",params![t.org_id,t.project_id,policy.policy_id,policy.policy_revision])?;
        } else {
            if expected_hash.is_some() || policy.policy_revision != 1 {
                return Err(StoreError::PreconditionFailed);
            }
            tx.execute(
                "INSERT INTO policies VALUES(?1,?2,?3,?4,1,'draft')",
                params![t.org_id, t.project_id, policy.policy_id, policy.target_id],
            )?;
        }
        let (expires, review) = match &policy.lifetime {
            fw_domain::Lifetime::Lease { expires_at, .. } => {
                (Some(fw_domain::timestamp(expires_at)?), None)
            }
            fw_domain::Lifetime::Review { review_at, .. } => {
                (None, Some(fw_domain::timestamp(review_at)?))
            }
        };
        tx.execute(
            "INSERT INTO policy_revisions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                t.org_id,
                t.project_id,
                policy.policy_id,
                policy.policy_revision,
                hash.as_slice(),
                if policy.action == fw_domain::Action::Allow {
                    "allow"
                } else {
                    "deny"
                },
                fw_domain::timestamp(policy.lifetime.not_before())?,
                expires,
                review,
                bytes
            ],
        )?;
        enqueue(
            &tx,
            t,
            "policy",
            &policy.policy_id,
            policy.policy_revision as i32,
            "policy.draft",
            &json!({"policy_id":policy.policy_id,"policy_hash":wire_hash}),
            now,
        )?;
        append_audit(
            &tx,
            t,
            Some(&policy.owner_id),
            "registry",
            "policy",
            Some(&policy.policy_id),
            None,
            "accepted",
            None,
            now,
        )?;
        tx.commit()?;
        Ok(wire_hash)
    }
    pub fn list_draft_policies(&self, t: &Tenant, limit: usize) -> Result<Vec<Value>> {
        valid_limit(limit)?;
        let c = self.connection()?;
        let mut statement=c.prepare("SELECT r.canonical_bytes,r.policy_hash FROM policies p JOIN policy_revisions r ON(p.org_id=r.org_id AND p.project_id=r.project_id AND p.policy_id=r.policy_id AND p.current_revision=r.revision) WHERE p.org_id=?1 AND p.project_id=?2 AND p.lifecycle='draft' ORDER BY p.policy_id LIMIT ?3")?;
        let rows = statement
            .query_map(params![t.org_id, t.project_id, limit], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(bytes, hash)| {
                if sha256(&bytes).as_slice() != hash {
                    return Err(StoreError::Integrity("policy content hash mismatch"));
                }
                Ok(serde_json::from_slice(&bytes)?)
            })
            .collect()
    }
    /// Consistent SQLite online backup. Caller owns filesystem permissions and independent trust/key backup.
    pub fn backup(&self, destination: impl AsRef<Path>) -> Result<()> {
        if destination.as_ref().exists() {
            return Err(StoreError::InvalidInput("backup destination exists"));
        }
        self.connection()?
            .backup(rusqlite::MAIN_DB, destination, None)?;
        Ok(())
    }
}

fn read_request(c: &Connection, t: &Tenant, id: &str) -> Result<RequestRecord> {
    let row=c.query_row("SELECT r.principal_id,r.revision,r.created_at,r.state,v.canonical_bytes,v.content_hash,o.operation_id FROM requests r JOIN request_revisions v ON (r.org_id=v.org_id AND r.project_id=v.project_id AND r.request_id=v.request_id AND v.revision=1) JOIN operations o ON (r.org_id=o.org_id AND r.project_id=o.project_id AND r.request_id=o.request_id) WHERE r.org_id=?1 AND r.project_id=?2 AND r.request_id=?3",params![t.org_id,t.project_id,id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i32>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,String>(6)?))).optional()?.ok_or(StoreError::NotFound)?;
    if sha256(&row.4).as_slice() != row.5 {
        return Err(StoreError::Integrity("request content hash mismatch"));
    }
    Ok(RequestRecord {
        request_id: id.to_owned(),
        org_id: t.org_id.clone(),
        project_id: t.project_id.clone(),
        principal_id: row.0,
        revision: row.1,
        created_at: timestamp(row.2)?,
        state: row.3,
        request: serde_json::from_slice(&row.4)?,
        request_hash: hex_hash(&row.5),
        operation_id: row.6,
        plan_ref: None,
    })
}
fn read_operation(c: &Connection, t: &Tenant, id: &str) -> Result<OperationRecord> {
    let row=c.query_row("SELECT kind,state,revision,request_id,reason_code,completed_at FROM operations WHERE org_id=?1 AND project_id=?2 AND operation_id=?3",params![t.org_id,t.project_id,id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i32>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<i64>>(5)?))).optional()?.ok_or(StoreError::NotFound)?;
    Ok(OperationRecord {
        operation_id: id.to_owned(),
        kind: row.0,
        state: row.1,
        revision: row.2,
        request_id: row.3,
        reason_code: row.4,
        completed_at: row.5.map(timestamp).transpose()?,
    })
}
fn active_principal(c: &Connection, t: &Tenant, id: &str) -> Result<()> {
    let present:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM principals x JOIN projects p ON (x.org_id=p.org_id AND x.project_id=p.project_id) JOIN organizations o ON x.org_id=o.org_id WHERE x.org_id=?1 AND x.project_id=?2 AND x.principal_id=?3 AND x.state='active' AND p.state='active' AND o.state='active')",params![t.org_id,t.project_id,id],|r|r.get(0))?;
    if !present {
        return Err(StoreError::NotFound);
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn enqueue(
    tx: &Transaction<'_>,
    t: &Tenant,
    aggregate_kind: &str,
    id: &str,
    revision: i32,
    event_kind: &str,
    payload: &Value,
    now: i64,
) -> Result<()> {
    let bytes = canonical_bytes(payload)?;
    let hash = sha256(&bytes);
    tx.execute(
        "INSERT INTO outbox VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,0,'pending')",
        params![
            t.org_id,
            t.project_id,
            Uuid::new_v4().to_string(),
            aggregate_kind,
            id,
            revision,
            event_kind,
            hash.as_slice(),
            bytes,
            now,
            encode_u64(0).as_slice()
        ],
    )?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn append_audit(
    tx: &Transaction<'_>,
    t: &Tenant,
    actor: Option<&str>,
    event_type: &str,
    resource_kind: &str,
    resource_id: Option<&str>,
    operation_id: Option<&str>,
    outcome: &str,
    reason: Option<&str>,
    now: i64,
) -> Result<()> {
    append_audit_with_evidence(
        tx,
        t,
        actor,
        event_type,
        resource_kind,
        resource_id,
        operation_id,
        outcome,
        reason,
        &[],
        now,
    )
}
#[allow(clippy::too_many_arguments)]
fn append_audit_with_evidence(
    tx: &Transaction<'_>,
    t: &Tenant,
    actor: Option<&str>,
    event_type: &str,
    resource_kind: &str,
    resource_id: Option<&str>,
    operation_id: Option<&str>,
    outcome: &str,
    reason: Option<&str>,
    evidence_hashes: &[String],
    now: i64,
) -> Result<()> {
    let (sequence, previous): (Vec<u8>, Option<Vec<u8>>) = tx.query_row(
        "SELECT sequence,last_event_hash FROM audit_heads WHERE org_id=?1 AND project_id=?2",
        params![t.org_id, t.project_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let latest_time: Option<i64> = tx.query_row(
        "SELECT max(recorded_at) FROM audit_events WHERE org_id=?1 AND project_id=?2",
        params![t.org_id, t.project_id],
        |r| r.get(0),
    )?;
    if latest_time.is_some_and(|latest| now < latest) {
        return Err(StoreError::InvalidInput("authority clock regressed"));
    }
    let sequence = decode_u64(&sequence)?
        .checked_add(1)
        .ok_or(StoreError::Integrity("audit sequence exhausted"))?;
    let event_id = Uuid::new_v4().to_string();
    let event = json!({"schema_version":"f.audit-event/v1","event_id":event_id,"org_id":t.org_id,"project_id":t.project_id,"sequence":sequence.to_string(),"recorded_at":timestamp(now)?,"event_type":event_type,"actor_id":actor,"resource_kind":resource_kind,"resource_id":resource_id,"operation_id":operation_id,"plan_hash":null,"outcome":outcome,"reason_code":reason,"evidence_hashes":evidence_hashes,"previous_event_hash":previous.as_ref().map(|p|hex_hash(p))});
    let bytes = canonical_bytes(&event)?;
    let hash = sha256(&bytes);
    tx.execute(
        "INSERT INTO audit_events VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            t.org_id,
            t.project_id,
            encode_u64(sequence).as_slice(),
            event_id,
            event_type,
            actor,
            resource_kind,
            resource_id,
            operation_id,
            outcome,
            previous,
            hash.as_slice(),
            now,
            bytes
        ],
    )?;
    tx.execute(
        "UPDATE audit_heads SET sequence=?3,last_event_hash=?4 WHERE org_id=?1 AND project_id=?2",
        params![
            t.org_id,
            t.project_id,
            encode_u64(sequence).as_slice(),
            hash.as_slice()
        ],
    )?;
    Ok(())
}
pub fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}
pub fn decode_u64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
        StoreError::Integrity("invalid u64 encoding")
    })?))
}
fn valid_uuid(id: &str) -> Result<()> {
    if Uuid::parse_str(id)
        .map(|u| u.to_string() == id)
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(StoreError::InvalidInput("noncanonical UUID"))
    }
}
fn valid_time(now: i64) -> Result<()> {
    if (0..=MAX_TIME).contains(&now) {
        Ok(())
    } else {
        Err(StoreError::InvalidInput("invalid UTC seconds"))
    }
}
fn valid_limit(limit: usize) -> Result<()> {
    if (1..=100).contains(&limit) {
        Ok(())
    } else {
        Err(StoreError::InvalidInput("page size must be 1..100"))
    }
}
fn timestamp(now: i64) -> Result<String> {
    valid_time(now)?;
    Ok(DateTime::<Utc>::from_timestamp(now, 0)
        .ok_or(StoreError::InvalidInput("invalid timestamp"))?
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex_hash(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
