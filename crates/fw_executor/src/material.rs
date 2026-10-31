//! Immutable native material storage. Hash correspondence is necessary but does
//! not replace the native adapter's semantic, scope, clock and trust checks.
use super::*;
use fw_authority::SignedGrant;
use fw_contracts::{canonical_hash, parse_strict_with_limit};
use serde_json::Value;

pub(crate) const MATERIAL_SCHEMA: &str = "CREATE TABLE execution_material (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    material_hash TEXT NOT NULL,
    material_bytes BLOB NOT NULL,
    recovery_state_hash TEXT NOT NULL,
    recovery_valid_until INTEGER NOT NULL,
    watchdog_ack_hash TEXT,
    recovery_report_hash TEXT,
    recovered_at INTEGER
);";
const MAX_MATERIAL_BYTES: usize = 16 * 1024 * 1024;

/// Complete immutable objects validated by the independent signer and native
/// adapter before acceptance. The journal checks all signed object digests.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionMaterial {
    pub signed_grant: SignedGrant,
    pub baseline_state: Value,
    pub candidate_state: Value,
    pub candidate_artifact: Value,
    pub recovery_state: Value,
    pub recovery_artifact: Value,
    pub recovery_scope: Value,
    /// The complete Installation, including its manifest and exact native batch.
    pub installation_manifest: Value,
    pub tombstone_watermark: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct JournalIdentity {
    pub org_id: String,
    pub target_id: String,
    pub authority_epoch: u64,
    pub highest_generation: u64,
    pub current_state_hash: String,
}

fn digest(value: &impl Serialize) -> Result<String> {
    canonical_hash(value).map_err(|_| ExecutorError::Binding)
}

fn signed_time(payload: &Value, key: &str) -> Result<i64> {
    let text = payload[key].as_str().ok_or(ExecutorError::Binding)?;
    let value = chrono::DateTime::parse_from_rfc3339(text).map_err(|_| ExecutorError::Binding)?;
    if value
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
        != text
    {
        return Err(ExecutorError::Binding);
    }
    Ok(value.timestamp())
}

impl ExecutionMaterial {
    pub fn content_hash(&self) -> Result<String> {
        digest(self)
    }

    fn validate(&self, grant: &VerifiedGrant) -> Result<(Vec<u8>, String)> {
        let bytes = canonical_bytes(self).map_err(|_| ExecutorError::Binding)?;
        if bytes.len() > MAX_MATERIAL_BYTES
            || digest(&self.signed_grant)? != grant.grant_hash()
            || digest(&self.baseline_state)? != grant.baseline_hash()
            || digest(&self.candidate_state)? != grant.desired_state_hash()
            || digest(&self.candidate_artifact)? != grant.artifact_hash()
            || digest(&self.recovery_artifact)? != grant.rollback_authority().artifact_hash
            || digest(&self.recovery_scope)? != grant.rollback_authority().scope_bound_hash
            || self.candidate_artifact["desired_state_hash"] != grant.desired_state_hash()
            || self.recovery_artifact["desired_state_hash"] != digest(&self.recovery_state)?
            || self.baseline_state["target_id"] != grant.target_id()
            || self.candidate_state["target_id"] != grant.target_id()
            || self.recovery_state["target_id"] != grant.target_id()
            || !self.installation_manifest.is_object()
        {
            return Err(ExecutorError::Binding);
        }
        Ok((bytes, self.content_hash()?))
    }
}

pub(crate) fn read_material(
    connection: &Connection,
    id: &str,
) -> Result<Option<(ExecutionMaterial, String)>> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(material_bytes) FROM execution_material WHERE operation_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    if length.is_some_and(|length| length < 0 || length > MAX_MATERIAL_BYTES as i64) {
        return Err(ExecutorError::Binding);
    }
    let stored: Option<(String, Vec<u8>)> = connection
        .query_row(
            "SELECT material_hash,material_bytes FROM execution_material WHERE operation_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    stored
        .map(|(expected, bytes)| {
            let material: ExecutionMaterial = parse_strict_with_limit(&bytes, MAX_MATERIAL_BYTES)
                .map_err(|_| ExecutorError::Binding)?;
            if material.content_hash()? != expected
                || canonical_bytes(&material).map_err(|_| ExecutorError::Binding)? != bytes
            {
                return Err(ExecutorError::Binding);
            }
            let operation = get_operation(connection, id)?.ok_or(ExecutorError::Binding)?;
            let payload = &material.signed_grant.payload;
            let (org, target, epoch): (String, String, String) = connection.query_row(
                "SELECT org_id,target_id,epoch FROM identity WHERE singleton=1", [],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            let (recovery_hash, recovery_until): (String, i64) = connection.query_row(
                "SELECT recovery_state_hash,recovery_valid_until FROM execution_material WHERE operation_id=?1",
                [id], |r| Ok((r.get(0)?,r.get(1)?)))?;
            if digest(&material.signed_grant)? != operation.grant_hash
                || payload["org_id"] != org || payload["target_id"] != target
                || payload["authority_epoch"] != epoch
                || payload["target_generation"] != operation.generation
                || payload["baseline_hash"] != operation.baseline_hash
                || payload["desired_state_hash"] != operation.desired_state_hash
                || signed_time(payload, "issued_at")? != operation.issued_at
                || signed_time(payload, "not_after")? != operation.not_after
                || signed_time(payload, "confirm_not_after")? != operation.confirm_not_after
                || payload["confirm_timeout_seconds"] != 60
                || digest(&material.baseline_state)? != operation.baseline_hash
                || digest(&material.candidate_state)? != operation.desired_state_hash
                || payload["artifact_hash"] != digest(&material.candidate_artifact)?
                || material.candidate_artifact["desired_state_hash"] != operation.desired_state_hash
                || payload["rollback_authority"]["baseline_hash"] != operation.baseline_hash
                || payload["rollback_authority"]["artifact_hash"] != digest(&material.recovery_artifact)?
                || payload["rollback_authority"]["scope_bound_hash"] != digest(&material.recovery_scope)?
                || signed_time(&payload["rollback_authority"], "valid_until")? != recovery_until
                || recovery_hash != digest(&material.recovery_state)?
                || material.recovery_artifact["desired_state_hash"] != recovery_hash
            {
                return Err(ExecutorError::Binding);
            }
            match operation.submitted_at {
                Some(submitted) if submitted >= operation.issued_at && submitted < operation.not_after
                    && submitted < operation.confirm_not_after => {
                    let expected_deadline = submitted.checked_add(60).ok_or(ExecutorError::Binding)?
                        .min(operation.confirm_not_after);
                    if operation.confirm_deadline != Some(expected_deadline) {
                        return Err(ExecutorError::Binding);
                    }
                }
                None if operation.confirm_deadline.is_none()
                    && matches!(operation.state, State::Prepared | State::NotApplied) => {}
                _ => return Err(ExecutorError::Binding),
            }
            Ok((material, expected))
        })
        .transpose()
}

impl ExecutorJournal {
    pub fn identity(&self) -> Result<JournalIdentity> {
        let (org_id, target_id, epoch, highest, current_state_hash): (
            String,
            String,
            String,
            String,
            String,
        ) = self.connection.query_row(
            "SELECT org_id,target_id,epoch,highest,state_hash FROM identity WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        Ok(JournalIdentity {
            org_id,
            target_id,
            authority_epoch: counter(&epoch)?,
            highest_generation: counter(&highest)?,
            current_state_hash,
        })
    }

    pub fn current_state_hash(&self) -> Result<String> {
        Ok(self.identity()?.current_state_hash)
    }

    /// Returns the operation at the durable high-water generation. Its state
    /// must be examined before treating any stored installation as current.
    pub fn latest_operation(&self) -> Result<Option<Operation>> {
        let highest = self.highest_generation()?;
        if highest == 0 {
            return Ok(None);
        }
        let id: String = self.connection.query_row(
            "SELECT operation_id FROM operations WHERE generation=?1",
            [highest.to_string()],
            |r| r.get(0),
        )?;
        self.operation(&id)
    }

    /// Native drift or an unverifiable observation withdraws a previous success
    /// and blocks new work. It grants no recovery or native-write permission.
    pub fn mark_drift(&mut self, id: &str, now: i64) -> Result<State> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = get_operation(&tx, id)?.ok_or(ExecutorError::Binding)?;
        let highest: String =
            tx.query_row("SELECT highest FROM identity WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if operation.generation != highest {
            return Err(ExecutorError::Binding);
        }
        if now < operation.issued_at {
            return Err(ExecutorError::Expired);
        }
        if !matches!(operation.state, State::Confirmed | State::RolledBack) {
            return Err(ExecutorError::Transition);
        }
        tx.execute(
            "UPDATE operations SET state='UNKNOWN' WHERE operation_id=?1",
            [id],
        )?;
        tx.commit()?;
        Ok(State::Unknown)
    }

    /// Generation consumption, grant acceptance and all recovery bytes commit
    /// together. A prior primitive-only acceptance cannot be upgraded later.
    pub fn accept_execution(
        &mut self,
        grant: &VerifiedGrant,
        id: &str,
        material: &ExecutionMaterial,
        now: i64,
    ) -> Result<Operation> {
        let (bytes, material_hash) = material.validate(grant)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old_operation = get_operation(&tx, id)?;
        if old_operation.is_some() {
            let (_, saved_hash) = read_material(&tx, id)?.ok_or(ExecutorError::Conflict)?;
            if saved_hash != material_hash {
                return Err(ExecutorError::Conflict);
            }
        }
        let operation = accept_fields_tx(
            &tx,
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
            id,
            now,
        )?;
        if old_operation.is_none() {
            tx.execute("INSERT INTO execution_material(operation_id,material_hash,material_bytes,recovery_state_hash,recovery_valid_until) VALUES(?1,?2,?3,?4,?5)",
                params![id,material_hash,bytes,digest(&material.recovery_state)?,
                    grant.rollback_authority().valid_until_unix().map_err(|_| ExecutorError::Binding)?])?;
        }
        tx.commit()?;
        Ok(operation)
    }

    pub fn execution_material(&self, id: &str) -> Result<Option<ExecutionMaterial>> {
        Ok(read_material(&self.connection, id)?.map(|(material, _)| material))
    }

    pub fn execution_material_hash(&self, id: &str) -> Result<Option<String>> {
        Ok(read_material(&self.connection, id)?.map(|(_, hash)| hash))
    }

    /// Records an immutable acknowledgement digest supplied by the trusted local
    /// supervisor. A digest alone is not proof that another process is alive.
    pub fn arm_watchdog(
        &mut self,
        id: &str,
        expected_material_hash: &str,
        acknowledgement_hash: &str,
    ) -> Result<()> {
        if !hash(acknowledgement_hash) {
            return Err(ExecutorError::Binding);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, saved_hash) = read_material(&tx, id)?.ok_or(ExecutorError::Binding)?;
        if saved_hash != expected_material_hash {
            return Err(ExecutorError::Binding);
        }
        let operation = get_operation(&tx, id)?.ok_or(ExecutorError::Binding)?;
        if operation.state != State::Prepared {
            return Err(ExecutorError::Transition);
        }
        let previous: Option<String> = tx.query_row(
            "SELECT watchdog_ack_hash FROM execution_material WHERE operation_id=?1",
            [id],
            |r| r.get(0),
        )?;
        if previous
            .as_ref()
            .is_some_and(|saved| saved != acknowledgement_hash)
        {
            return Err(ExecutorError::Conflict);
        }
        tx.execute(
            "UPDATE execution_material SET watchdog_ack_hash=?1 WHERE operation_id=?2",
            params![acknowledgement_hash, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Commit only after the native adapter independently matches actual readback
    /// to the signed recovery artifact. Failure leaves recovery claimed and blocks
    /// later generations. This cannot lower the generation high-water mark.
    #[allow(clippy::too_many_arguments)]
    pub fn record_recovery_completion(
        &mut self,
        id: &str,
        generation: u64,
        expected_candidate_hash: &str,
        expected_material_hash: &str,
        observed_recovery_state_hash: &str,
        readback_report_hash: &str,
        now: i64,
    ) -> Result<State> {
        if !hash(observed_recovery_state_hash) || !hash(readback_report_hash) {
            return Err(ExecutorError::Binding);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (material, material_hash) = read_material(&tx, id)?.ok_or(ExecutorError::Binding)?;
        let operation = get_operation(&tx, id)?.ok_or(ExecutorError::Binding)?;
        let highest: String =
            tx.query_row("SELECT highest FROM identity WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        let (recovery_hash, valid_until): (String, i64) = tx.query_row(
            "SELECT recovery_state_hash,recovery_valid_until FROM execution_material WHERE operation_id=?1",
            [id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        if counter(&highest)? != generation
            || counter(&operation.generation)? != generation
            || operation.desired_state_hash != expected_candidate_hash
            || material_hash != expected_material_hash
            || recovery_hash != observed_recovery_state_hash
            || digest(&material.recovery_state)? != recovery_hash
            || material.recovery_artifact["desired_state_hash"] != recovery_hash
        {
            return Err(ExecutorError::Binding);
        }
        if operation.state != State::RecoveryClaimed {
            return Err(ExecutorError::Transition);
        }
        if super::recovery::latest(&tx, id)?.is_some_and(|attempt| {
            attempt.submitted_at.is_none()
                || attempt.not_applied_at.is_some()
                || attempt
                    .submitted_at
                    .is_some_and(|submitted| now < submitted)
        }) {
            return Err(ExecutorError::Transition);
        }
        if now
            < operation
                .confirm_deadline
                .unwrap_or(operation.confirm_not_after)
            || now < operation.issued_at
            || now >= valid_until
        {
            return Err(ExecutorError::Expired);
        }
        tx.execute("UPDATE operations SET state='ROLLED_BACK',observed_hash=?1 WHERE operation_id=?2 AND state='RECOVERY_CLAIMED'",
            params![observed_recovery_state_hash,id])?;
        tx.execute("UPDATE execution_material SET recovery_report_hash=?1,recovered_at=?2 WHERE operation_id=?3",
            params![readback_report_hash,now,id])?;
        tx.execute(
            "UPDATE identity SET state_hash=?1 WHERE singleton=1",
            [observed_recovery_state_hash],
        )?;
        tx.commit()?;
        Ok(State::RolledBack)
    }
}
