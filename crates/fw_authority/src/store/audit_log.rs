//! Local audit consistency, without an external checkpoint or trust anchor.
use super::*;
use rusqlite::{Row, types::ValueRef};

#[cfg(test)]
#[path = "audit_atomicity_tests.rs"]
mod audit_atomicity_tests;

/// A consistent read snapshot of this tenant's locally retained audit chain.
/// This is not an external anchor, proof of completeness against full database
/// replacement, or a capability to authorize a later operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAuditVerification {
    pub event_count: u64,
    pub head_hash: String,
    pub last_recorded_at: Option<i64>,
}

// Reject oversized storage values in SQL before copying them into Rust. These
// limits also apply when an out-of-band writer bypassed the table constraints.
// Only one bounded row and constant-size chain state are retained at a time.
const COLUMNS: &str = "
    CASE WHEN length(sequence)=8 THEN sequence END,
    CASE WHEN length(event_hash)=32 THEN event_hash END,
    CASE WHEN length(previous_hash)=32 THEN previous_hash END,
    CASE WHEN length(CAST(kind AS BLOB)) BETWEEN 1 AND 16384 THEN kind END,
    CASE WHEN length(CAST(resource_id AS BLOB)) BETWEEN 1 AND 16384 THEN resource_id END,
    recorded_at,
    CASE WHEN length(canonical_bytes) BETWEEN 1 AND 16384 THEN canonical_bytes END";

fn blob<const N: usize>(row: &Row<'_>, column: usize) -> Result<[u8; N]> {
    match row.get_ref(column)? {
        ValueRef::Blob(bytes) => bytes
            .try_into()
            .map_err(|_| invalid("authority audit blob")),
        _ => Err(invalid("authority audit blob")),
    }
}

fn text<'a>(row: &'a Row<'_>, column: usize) -> Result<&'a str> {
    match row.get_ref(column)? {
        ValueRef::Text(bytes) if !bytes.is_empty() && bytes.len() <= 16384 => {
            std::str::from_utf8(bytes).map_err(|_| invalid("authority audit text"))
        }
        _ => Err(invalid("authority audit text")),
    }
}

fn head(tx: &Transaction<'_>, tenant: &AuthorityTenant) -> Result<Option<(u64, [u8; 32])>> {
    let mut statement = tx.prepare(
        "SELECT CASE WHEN length(sequence)=8 THEN sequence END,
         CASE WHEN length(event_hash)=32 THEN event_hash END
         FROM authority_audit_heads WHERE org_id=? AND project_id=?",
    )?;
    let mut rows = statement.query(params![tenant.org_id, tenant.project_id])?;
    rows.next()?
        .map(|row| Ok((u64::from_be_bytes(blob(row, 0)?), blob(row, 1)?)))
        .transpose()
}

struct Event {
    sequence: u64,
    hash: [u8; 32],
    previous: [u8; 32],
    recorded_at: i64,
}

fn event(row: &Row<'_>, tenant: &AuthorityTenant) -> Result<Event> {
    let sequence = u64::from_be_bytes(blob(row, 0)?);
    if sequence == 0 {
        return Err(invalid("authority audit sequence"));
    }
    let hash = blob(row, 1)?;
    let previous = blob(row, 2)?;
    let kind = text(row, 3)?;
    let resource = text(row, 4)?;
    let recorded_at: i64 = row.get(5)?;
    let canonical = match row.get_ref(6)? {
        ValueRef::Blob(bytes) if !bytes.is_empty() && bytes.len() <= 16384 => bytes,
        _ => return Err(invalid("authority audit bytes")),
    };
    // Reconstruct the closed event from its indexed/storage projections. Exact
    // canonical equality also rejects extra fields, duplicate keys, alternate
    // encodings, transplanted tenant identities and noncanonical timestamps.
    let expected = json!({"schema_version":"fw.authority-audit/v1",
        "org_id":tenant.org_id,"project_id":tenant.project_id,
        "sequence":sequence.to_string(),"previous_hash":hash_string(&previous)?,
        "kind":kind,"resource_id":resource,"recorded_at":at(recorded_at)?});
    if bytes(&expected)? != canonical || super::hash(&hash_bytes(canonical))? != hash {
        return Err(invalid("authority audit canonical hash or projection"));
    }
    Ok(Event {
        sequence,
        hash,
        previous,
        recorded_at,
    })
}

/// Indexed tail verification only: this deliberately does not scan or certify
/// historical entries on each write. The enclosing mutation transaction owns
/// the write lock and rolls back if this check or the later append fails.
pub(super) fn append_head(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
) -> Result<(u64, [u8; 32], Option<i64>)> {
    let (sequence, hash) = head(tx, tenant)?.ok_or(invalid("authority audit missing head"))?;
    let mut statement = tx.prepare(&format!("SELECT {COLUMNS} FROM authority_audit WHERE org_id=? AND project_id=? ORDER BY sequence DESC LIMIT 1"))?;
    let mut rows = statement.query(params![tenant.org_id, tenant.project_id])?;
    match rows.next()? {
        Some(row) => {
            let event = event(row, tenant)?;
            if event.sequence != sequence
                || event.hash != hash
                || (sequence == 1 && event.previous != [0; 32])
            {
                return Err(invalid("authority audit head mismatch"));
            }
            Ok((sequence, hash, Some(event.recorded_at)))
        }
        None if sequence == 0 && hash == [0; 32] => Ok((sequence, hash, None)),
        None => Err(invalid("authority audit missing event")),
    }
}

impl AuthorityStore {
    /// Return one tenant's verified history from a deferred read transaction.
    /// None means the tenant has no project, head or events. A
    /// known empty project requires the zero-sequence, zero-hash genesis head.
    /// Legacy backward timestamps are reported as errors and never rewritten.
    /// After external commits invalidate the connection's validated snapshot,
    /// database-wide physical and retained integrity checks precede this read.
    /// Corruption in another tenant therefore also refuses this call, including
    /// unknown-tenant lookups. The tenant scan is linear in its audit history;
    /// required snapshot revalidation additionally scans the retained database.
    /// Neither path modifies retained state.
    pub fn verify_audit_chain(
        &mut self,
        tenant: &AuthorityTenant,
    ) -> Result<Option<AuthorityAuditVerification>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        migrations::validate_live_schema(&tx)?;
        let known: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_projects WHERE org_id=? AND project_id=?)",
            params![tenant.org_id, tenant.project_id],
            |r| r.get(0),
        )?;
        let stored_head = head(&tx, tenant)?;
        if !known {
            let events: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_audit WHERE org_id=? AND project_id=?)",
                params![tenant.org_id, tenant.project_id],
                |r| r.get(0),
            )?;
            if stored_head.is_some() || events {
                return Err(invalid("authority audit orphan tenant"));
            }
            tx.commit()?;
            return Ok(None);
        }
        let stored_head = stored_head.ok_or(invalid("authority audit missing head"))?;
        let mut sequence = 0u64;
        let mut hash = [0u8; 32];
        let mut recorded_at = None;
        {
            let mut statement = tx.prepare(&format!("SELECT {COLUMNS} FROM authority_audit WHERE org_id=? AND project_id=? ORDER BY sequence"))?;
            let mut rows = statement.query(params![tenant.org_id, tenant.project_id])?;
            while let Some(row) = rows.next()? {
                let event = event(row, tenant)?;
                sequence = sequence
                    .checked_add(1)
                    .ok_or(invalid("authority audit sequence exhausted"))?;
                if event.sequence != sequence || event.previous != hash {
                    return Err(invalid("authority audit sequence or link"));
                }
                if recorded_at.is_some_and(|previous| event.recorded_at < previous) {
                    return Err(invalid("authority audit time order"));
                }
                hash = event.hash;
                recorded_at = Some(event.recorded_at);
            }
        }
        if stored_head != (sequence, hash) {
            return Err(invalid("authority audit head mismatch"));
        }
        let verified = AuthorityAuditVerification {
            event_count: sequence,
            head_hash: hash_string(&hash)?,
            last_recorded_at: recorded_at,
        };
        tx.commit()?;
        Ok(Some(verified))
    }
}

/// Verify one exact retained event without scanning the tenant's history.
pub(super) fn verify_bound_event(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    sequence: &[u8],
    expected_hash: &[u8],
    kind: &str,
    resource: &str,
    recorded: i64,
) -> Result<()> {
    let sequence_bytes: [u8; 8] = sequence
        .try_into()
        .map_err(|_| invalid("bound audit sequence"))?;
    let expected: [u8; 32] = expected_hash
        .try_into()
        .map_err(|_| invalid("bound audit hash"))?;
    let mut statement = tx.prepare_cached(&format!("SELECT {COLUMNS} FROM authority_audit WHERE org_id=? AND project_id=? AND sequence=? AND kind=? AND resource_id=? AND recorded_at=?"))?;
    let mut rows = statement.query(params![
        tenant.org_id,
        tenant.project_id,
        sequence,
        kind,
        resource,
        recorded
    ])?;
    let retained = event(
        rows.next()?.ok_or(invalid("missing bound audit event"))?,
        tenant,
    )?;
    if retained.sequence != u64::from_be_bytes(sequence_bytes) || retained.hash != expected {
        return Err(invalid("bound audit event mismatch"));
    }
    Ok(())
}

/// Upgrade-time verification streams every retained tenant chain. Missing history
/// is refused; canonical bytes and timestamps are never regenerated or repaired.
pub(super) fn validate_retained_chains(tx: &Transaction<'_>) -> Result<()> {
    let mut projects =
        tx.prepare("SELECT org_id,project_id FROM authority_projects ORDER BY org_id,project_id")?;
    let mut tenants = projects.query([])?;
    while let Some(row) = tenants.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let stored = head(tx, &tenant)?.ok_or(invalid("authority audit missing head"))?;
        let mut sequence = 0u64;
        let mut hash = [0u8; 32];
        let mut recorded_at = None;
        let mut statement=tx.prepare(&format!("SELECT {COLUMNS} FROM authority_audit WHERE org_id=? AND project_id=? ORDER BY sequence"))?;
        let mut rows = statement.query(params![tenant.org_id, tenant.project_id])?;
        while let Some(row) = rows.next()? {
            let item = event(row, &tenant)?;
            sequence = sequence
                .checked_add(1)
                .ok_or(invalid("authority audit sequence exhausted"))?;
            if item.sequence != sequence
                || item.previous != hash
                || recorded_at.is_some_and(|old| item.recorded_at < old)
            {
                return Err(invalid("authority audit retained history"));
            }
            hash = item.hash;
            recorded_at = Some(item.recorded_at);
        }
        if stored != (sequence, hash) {
            return Err(invalid("authority audit head mismatch"));
        }
    }
    Ok(())
}
