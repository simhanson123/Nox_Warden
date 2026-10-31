//! Durable recovery attempts distinguish preparation from uncertain native writes.
//! Installations are immutable; only submission and observed outcome advance.
use super::*;
use fw_contracts::{canonical_hash, parse_strict_with_limit, MAX_INTERNAL_BYTES};
use serde_json::Value;

pub(crate) const SCHEMA: &str = "CREATE TABLE recovery_attempts (
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    material_hash TEXT NOT NULL,
    installation_hash TEXT NOT NULL,
    installation_bytes BLOB NOT NULL,
    prepared_at INTEGER NOT NULL,
    submitted_at INTEGER,
    not_applied_at INTEGER,
    not_applied_report_hash TEXT,
    PRIMARY KEY(operation_id,sequence)
);";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryAttempt {
    pub sequence: u64,
    pub material_hash: String,
    pub installation_hash: String,
    pub installation: Value,
    pub prepared_at: i64,
    pub submitted_at: Option<i64>,
    pub not_applied_at: Option<i64>,
}

pub(crate) fn latest(connection: &Connection, id: &str) -> Result<Option<RecoveryAttempt>> {
    let length: Option<i64> = connection.query_row(
        "SELECT length(installation_bytes) FROM recovery_attempts WHERE operation_id=?1 ORDER BY sequence DESC LIMIT 1",
        [id], |r| r.get(0),
    ).optional()?;
    if length.is_some_and(|size| size < 0 || size as u64 > MAX_INTERNAL_BYTES as u64) {
        return Err(ExecutorError::Binding);
    }
    let row = connection.query_row(
        "SELECT sequence,material_hash,installation_hash,installation_bytes,prepared_at,submitted_at,not_applied_at,not_applied_report_hash FROM recovery_attempts WHERE operation_id=?1 ORDER BY sequence DESC LIMIT 1", [id], |r| {
            Ok((r.get::<_,u64>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?, r.get::<_,Vec<u8>>(3)?, r.get::<_,i64>(4)?, r.get::<_,Option<i64>>(5)?, r.get::<_,Option<i64>>(6)?, r.get::<_,Option<String>>(7)?))
        }).optional()?;
    row.map(
        |(
            sequence,
            material_hash,
            installation_hash,
            bytes,
            prepared_at,
            submitted_at,
            not_applied_at,
            report,
        )| {
            let (material, expected) =
                material::read_material(connection, id)?.ok_or(ExecutorError::Binding)?;
            let operation = get_operation(connection, id)?.ok_or(ExecutorError::Binding)?;
            let until = material.signed_grant.payload["rollback_authority"]["valid_until"]
                .as_str()
                .ok_or(ExecutorError::Binding)?;
            let until = chrono::DateTime::parse_from_rfc3339(until)
                .map_err(|_| ExecutorError::Binding)?
                .timestamp();
            let installation: Value = parse_strict_with_limit(&bytes, MAX_INTERNAL_BYTES)
                .map_err(|_| ExecutorError::Binding)?;
            if sequence == 0
                || sequence > 256
                || material_hash != expected
                || !installation.is_object()
                || canonical_bytes(&installation).map_err(|_| ExecutorError::Binding)? != bytes
                || canonical_hash(&installation).map_err(|_| ExecutorError::Binding)?
                    != installation_hash
                || prepared_at < operation.confirm_deadline.ok_or(ExecutorError::Binding)?
                || prepared_at >= until
                || submitted_at.is_some_and(|at| at < prepared_at || at >= until)
                || not_applied_at
                    .is_some_and(|at| submitted_at.is_none_or(|submitted| at < submitted))
                || not_applied_at.is_some() != report.is_some()
                || report.as_ref().is_some_and(|value| !hash(value))
            {
                return Err(ExecutorError::Binding);
            }
            Ok(RecoveryAttempt {
                sequence,
                material_hash,
                installation_hash,
                installation,
                prepared_at,
                submitted_at,
                not_applied_at,
            })
        },
    )
    .transpose()
}

fn eligible(connection: &Connection, id: &str, now: i64) -> Result<String> {
    let (_, material_hash) =
        material::read_material(connection, id)?.ok_or(ExecutorError::Binding)?;
    let operation = get_operation(connection, id)?.ok_or(ExecutorError::Binding)?;
    let highest: String =
        connection.query_row("SELECT highest FROM identity WHERE singleton=1", [], |r| {
            r.get(0)
        })?;
    if operation.generation != highest || operation.submitted_at.is_none() {
        return Err(ExecutorError::Binding);
    }
    if !matches!(
        operation.state,
        State::Unknown | State::Verifying | State::RecoveryClaimed
    ) {
        return Err(ExecutorError::Transition);
    }
    let until: i64 = connection.query_row(
        "SELECT recovery_valid_until FROM execution_material WHERE operation_id=?1",
        [id],
        |r| r.get(0),
    )?;
    if now < operation.confirm_deadline.ok_or(ExecutorError::Binding)? || now >= until {
        return Err(ExecutorError::Expired);
    }
    Ok(material_hash)
}

impl ExecutorJournal {
    pub fn latest_recovery_attempt(&self, id: &str) -> Result<Option<RecoveryAttempt>> {
        latest(&self.connection, id)
    }

    /// The adapter must hold the native-writer fence and verify actual candidate
    /// state before preparing/rebinding an attempt. A submitted uncertain attempt
    /// cannot be replaced. This method never extends signed recovery authority.
    pub fn prepare_recovery_attempt(
        &mut self,
        id: &str,
        expected_material_hash: &str,
        installation: &Value,
        now: i64,
    ) -> Result<RecoveryAttempt> {
        let bytes = canonical_bytes(installation).map_err(|_| ExecutorError::Binding)?;
        if !installation.is_object() || bytes.len() > MAX_INTERNAL_BYTES {
            return Err(ExecutorError::Binding);
        }
        let installation_hash = canonical_hash(installation).map_err(|_| ExecutorError::Binding)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let material_hash = eligible(&tx, id, now)?;
        if material_hash != expected_material_hash {
            return Err(ExecutorError::Binding);
        }
        let previous = latest(&tx, id)?;
        if let Some(previous) = &previous {
            if previous.submitted_at.is_some() && previous.not_applied_at.is_none() {
                return Err(ExecutorError::Transition);
            }
            if now < previous.not_applied_at.unwrap_or(previous.prepared_at) {
                return Err(ExecutorError::Expired);
            }
            if previous.submitted_at.is_none() && previous.installation_hash == installation_hash {
                return Ok(previous.clone());
            }
        }
        let sequence = previous.map_or(1, |old| old.sequence + 1);
        // Bound storage even if a local caller repeatedly abandons preparation.
        if sequence > 256 {
            return Err(ExecutorError::Transition);
        }
        tx.execute("INSERT INTO recovery_attempts(operation_id,sequence,material_hash,installation_hash,installation_bytes,prepared_at) VALUES(?1,?2,?3,?4,?5,?6)", params![id, sequence, material_hash, installation_hash, bytes, now])?;
        tx.commit()?;
        Ok(RecoveryAttempt {
            sequence,
            material_hash,
            installation_hash,
            installation: installation.clone(),
            prepared_at: now,
            submitted_at: None,
            not_applied_at: None,
        })
    }

    /// Commit this boundary before spawning the fenced native writer. Once set,
    /// restarting is observation only until actual state resolves the attempt.
    pub fn mark_recovery_submitted(&mut self, id: &str, sequence: u64, now: i64) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        eligible(&tx, id, now)?;
        let operation = get_operation(&tx, id)?.ok_or(ExecutorError::Binding)?;
        let attempt = latest(&tx, id)?.ok_or(ExecutorError::Binding)?;
        if operation.state != State::RecoveryClaimed
            || sequence != attempt.sequence
            || attempt.submitted_at.is_some()
        {
            return Err(ExecutorError::Transition);
        }
        if now < attempt.prepared_at {
            return Err(ExecutorError::Expired);
        }
        tx.execute(
            "UPDATE recovery_attempts SET submitted_at=?1 WHERE operation_id=?2 AND sequence=?3",
            params![now, id, sequence],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Only a fresh exact candidate readback under the inherited native fence can
    /// establish this outcome. A stored hash or absence of a response is not proof.
    pub fn record_recovery_attempt_not_applied(
        &mut self,
        id: &str,
        sequence: u64,
        observed_candidate_hash: &str,
        readback_report_hash: &str,
        now: i64,
    ) -> Result<()> {
        if !hash(readback_report_hash) {
            return Err(ExecutorError::Binding);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        eligible(&tx, id, now)?;
        let operation = get_operation(&tx, id)?.ok_or(ExecutorError::Binding)?;
        let attempt = latest(&tx, id)?.ok_or(ExecutorError::Binding)?;
        if operation.desired_state_hash != observed_candidate_hash {
            return Err(ExecutorError::Binding);
        }
        if operation.state != State::RecoveryClaimed
            || sequence != attempt.sequence
            || attempt.submitted_at.is_none_or(|at| now < at)
            || attempt.not_applied_at.is_some()
        {
            return Err(ExecutorError::Transition);
        }
        tx.execute("UPDATE recovery_attempts SET not_applied_at=?1,not_applied_report_hash=?2 WHERE operation_id=?3 AND sequence=?4", params![now,readback_report_hash,id,sequence])?;
        tx.commit()?;
        Ok(())
    }
}
