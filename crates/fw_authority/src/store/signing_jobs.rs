//! Durable worker fencing. A claim never supplies independent signer authority.
//! Public worker operations remain closed behind the protected resolver; only
//! cancellation proven to precede grant/outbox creation can release capacity.
use super::*;
use crate::{PreparedSigningJob, VerifiedSigningResult};

const MAX_SIGNER_ATTEMPTS: i64 = 3;
const MAX_DISPATCH_ATTEMPTS: i64 = 5;
const MAX_CLAIM_SECONDS: i64 = 900;
// A renewal must strictly extend a claim, and each generation has a durable cap.
const MAX_CLAIM_RENEWALS: i64 = 32;

pub(super) const MIGRATION_WORK_BINDINGS: &str = include_str!("migration_011_work_bindings.sql");
pub(super) const MIGRATION_WORK: &str = include_str!("migration_011_work.sql");

#[cfg(test)]
#[path = "signing_work_guard_tests.rs"]
mod work_guard_tests;

#[cfg(test)]
#[path = "signing_work_audit_tests.rs"]
mod work_audit_tests;

#[cfg(test)]
#[path = "signing_work_time_tests.rs"]
mod work_time_tests;

#[cfg(test)]
#[path = "signing_retention_victim_tests.rs"]
mod retention_victim_tests;

/// Opaque worker capability. Debug/serialization deliberately omit the token.
#[derive(Clone)]
pub struct SigningClaim {
    job_id: String,
    worker_id: String,
    phase: &'static str,
    generation: u64,
    token: [u8; 32],
    until: i64,
}
impl SigningClaim {
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn valid_until(&self) -> i64 {
        self.until
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SigningLifecycleStatus {
    pub job_id: String,
    pub state: String,
    pub claim_generation: u64,
    pub attempts: u32,
    pub claim_until: Option<i64>,
    pub dispatch_state: Option<String>,
    pub dispatch_attempts: u32,
    pub quota_held: bool,
}

/// Only a protected sender can obtain these exact bytes. No production HTTP or
/// CLI route exposes this object, and the current eligibility resolver refuses.
pub struct SigningDispatchClaim {
    pub claim: SigningClaim,
    pub grant_hash: String,
    pub grant_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Head {
    state: String,
    revision: u64,
    generation: u64,
    claim_hash: Option<Vec<u8>>,
    worker: Option<String>,
    until: Option<i64>,
    attempts: i64,
    available: i64,
    updated: i64,
}
// Keep invalid non-NULL optional values present as bounded sentinels. Turning
// them into NULL would hide forbidden claim metadata on inactive history rows.
const HEAD_COLUMNS: &str = "CASE WHEN length(state)<=16 THEN state END,
 CASE WHEN length(revision)=8 THEN revision END,
 CASE WHEN length(claim_generation)=8 THEN claim_generation END,
 CASE WHEN claim_hash IS NULL OR length(claim_hash)=32 THEN claim_hash ELSE X'' END,
 CASE WHEN worker_id IS NULL OR length(worker_id)=36 THEN worker_id ELSE '' END,
 claim_until,attempts,available_at,updated_at";

fn read_head(row: &rusqlite::Row<'_>) -> rusqlite::Result<Head> {
    let revision: [u8; 8] = row.get(1)?;
    let generation: [u8; 8] = row.get(2)?;
    Ok(Head {
        state: row.get(0)?,
        revision: u64::from_be_bytes(revision),
        generation: u64::from_be_bytes(generation),
        claim_hash: row.get(3)?,
        worker: row.get(4)?,
        until: row.get(5)?,
        attempts: row.get(6)?,
        available: row.get(7)?,
        updated: row.get(8)?,
    })
}

// A phase has at most five claims, 32 renewals per claim and bounded terminal
// events. Keep complete history verification bounded rather than trusting only
// the mutable head and latest event to agree.
pub(super) const MAX_WORK_EVENTS: usize = 192;

struct WorkHistory {
    current: Option<Head>,
    had_unknown: bool,
}

fn valid_head(value: &Head, phase: &str) -> Result<()> {
    let maximum = if phase == "signer" {
        MAX_SIGNER_ATTEMPTS
    } else {
        MAX_DISPATCH_ATTEMPTS
    };
    let states = if phase == "signer" {
        &["prepared", "claimed", "ready", "cancelled"][..]
    } else {
        &["queued", "claimed", "unknown", "delivered"][..]
    };
    if !matches!(phase, "signer" | "dispatch")
        || !states.contains(&value.state.as_str())
        || value.revision == 0
        || !(0..=maximum).contains(&value.attempts)
        || value.generation != value.attempts as u64
    {
        return Err(invalid("signing work projection"));
    }
    time(value.available)?;
    time(value.updated)?;
    if value.state == "claimed" {
        identifier(value.worker.as_deref().ok_or(AuthorityError::Binding)?)?;
        if value.claim_hash.as_ref().map(Vec::len) != Some(32)
            || value.until.is_none_or(|until| {
                until <= value.updated || until - value.updated > MAX_CLAIM_SECONDS
            })
        {
            return Err(invalid("signing claim projection"));
        }
    } else if value.claim_hash.is_some() || value.worker.is_some() || value.until.is_some() {
        return Err(invalid("signing inactive claim"));
    }
    Ok(())
}

fn work_history(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job: &str,
    phase: &str,
) -> Result<WorkHistory> {
    let bound_audits: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='authority_signing_work_audits')", [], |r| r.get(0))?;
    if !bound_audits && tx.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? >= 11 {
        return Err(invalid("missing signing work audit bindings"));
    }
    let dispatch_times: (Option<i64>, Option<i64>) = if phase == "dispatch" {
        tx.query_row("SELECT (SELECT created_at FROM authority_signing_outbox WHERE org_id=?1 AND project_id=?2 AND job_id=?3),(SELECT recorded_at FROM authority_signing_deliveries WHERE org_id=?1 AND project_id=?2 AND job_id=?3)", params![tenant.org_id,tenant.project_id,job], |r| Ok((r.get(0)?,r.get(1)?)))?
    } else {
        (None, None)
    };
    let current = tx.query_row(&format!("SELECT {HEAD_COLUMNS} FROM authority_signing_work_heads WHERE org_id=? AND project_id=? AND job_id=? AND phase=?"),
        params![tenant.org_id, tenant.project_id, job, phase], read_head).optional()?;
    let mut statement = tx.prepare(&format!("SELECT {HEAD_COLUMNS},CASE WHEN length(kind)<=16 THEN kind END FROM authority_signing_work_events WHERE org_id=? AND project_id=? AND job_id=? AND phase=? ORDER BY revision LIMIT {}", MAX_WORK_EVENTS + 1))?;
    let mut rows = statement.query(params![tenant.org_id, tenant.project_id, job, phase])?;
    let mut previous: Option<Head> = None;
    let mut renewals = 0;
    let mut had_unknown = false;
    let mut count = 0;
    let mut bounds = None;
    let mut previous_audit = None;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > MAX_WORK_EVENTS {
            return Err(AuthorityError::Quota);
        }
        let next = read_head(row)?;
        let kind: String = row.get(9)?;
        valid_head(&next, phase)?;
        if bound_audits {
            let sequence = verify_work_audit(tx, tenant, job, phase, &next, &kind)?;
            if previous_audit.is_some_and(|previous| previous >= sequence) {
                return Err(invalid("signing work audit order"));
            }
            previous_audit = Some(sequence);
        }
        let (created, deadline) = if let Some(value) = bounds {
            value
        } else {
            let value: (i64, i64) = tx.query_row("SELECT created_at,deadline FROM authority_signing_jobs WHERE org_id=? AND project_id=? AND job_id=?", params![tenant.org_id, tenant.project_id, job], |r| Ok((r.get(0)?, r.get(1)?)))?;
            time(value.0)?;
            time(value.1)?;
            bounds = Some(value);
            value
        };
        if next.revision != count as u64
            || next.updated < created
            || deadline <= created
            || next.until.is_some_and(|until| until > deadline)
        {
            return Err(invalid("signing work sequence"));
        }
        let legal = if let Some(old) = &previous {
            let same_counter = next.generation == old.generation && next.attempts == old.attempts;
            let same_available = next.available == old.available;
            if next.updated < old.updated {
                return Err(AuthorityError::Time);
            }
            match kind.as_str() {
                "claimed" => {
                    renewals = 0;
                    next.state == "claimed"
                        && next.generation == old.generation + 1
                        && next.attempts == old.attempts + 1
                        && same_available
                        && next.updated >= old.available
                        && next.updated < deadline
                        && ((phase == "signer" && old.state == "prepared")
                            || (phase == "dispatch"
                                && matches!(old.state.as_str(), "queued" | "unknown"))
                            || (phase == "signer"
                                && old.state == "claimed"
                                && old.until.is_some_and(|until| {
                                    next.updated >= until.saturating_add(retry_delay(old))
                                })))
                }
                "renewed" => {
                    renewals += 1;
                    old.state == "claimed"
                        && next.state == "claimed"
                        && same_counter
                        && same_available
                        && next.claim_hash == old.claim_hash
                        && next.worker == old.worker
                        && next.until > old.until
                        && old.until.is_some_and(|until| next.updated < until)
                        && renewals <= MAX_CLAIM_RENEWALS
                }
                "retried" => {
                    phase == "signer"
                        && old.state == "claimed"
                        && next.state == "prepared"
                        && same_counter
                        && old.until.is_some_and(|until| next.updated < until)
                        && next.available == next.updated.saturating_add(retry_delay(old))
                        && next.available < deadline
                }
                "unknown" => {
                    phase == "dispatch"
                        && old.state == "claimed"
                        && next.state == "unknown"
                        && same_counter
                        && (next.available
                            == next.updated.saturating_add(retry_delay(old)).min(MAX_TIME)
                            || (same_available
                                && old.until.is_some_and(|until| {
                                    next.updated >= until.saturating_add(retry_delay(old))
                                })))
                }
                "cancelled" => {
                    phase == "signer"
                        && matches!(old.state.as_str(), "prepared" | "claimed")
                        && next.state == "cancelled"
                        && same_counter
                        && same_available
                }
                "finalized" => {
                    phase == "signer"
                        && old.state == "claimed"
                        && next.state == "ready"
                        && same_counter
                        && same_available
                        && old.until.is_some_and(|until| next.updated < until)
                }
                "delivered" => {
                    phase == "dispatch"
                        && old.state == "claimed"
                        && next.state == "delivered"
                        && same_counter
                        && same_available
                        && old.until.is_some_and(|until| next.updated < until)
                        && dispatch_times.1 == Some(next.updated)
                }
                _ => false,
            }
        } else {
            kind == "created"
                && next.state
                    == if phase == "signer" {
                        "prepared"
                    } else {
                        "queued"
                    }
                && next.generation == 0
                && next.attempts == 0
                && next.available == next.updated
                && next.updated < deadline
                && if phase == "signer" {
                    next.updated == created
                } else {
                    dispatch_times.0 == Some(next.updated)
                }
        };
        if !legal {
            return Err(invalid("signing work history"));
        }
        had_unknown |= next.state == "unknown";
        previous = Some(next);
    }
    if current != previous {
        return Err(invalid("signing work head mismatch"));
    }
    if bound_audits {
        let bindings: usize = tx.query_row("SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_audits WHERE org_id=? AND project_id=? AND job_id=? AND phase=? LIMIT 193)", params![tenant.org_id,tenant.project_id,job,phase], |r| r.get(0))?;
        if bindings != count {
            return Err(invalid("signing work audit binding count"));
        }
    }
    Ok(WorkHistory {
        current,
        had_unknown,
    })
}

fn verify_work_audit(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job: &str,
    phase: &str,
    next: &Head,
    kind: &str,
) -> Result<u64> {
    type Binding = (Vec<u8>, Vec<u8>, String, i64);
    let binding: Binding = tx.query_row("SELECT CASE WHEN length(audit_sequence)=8 THEN audit_sequence END,CASE WHEN length(audit_hash)=32 THEN audit_hash END,CASE WHEN length(kind)<=16 THEN kind END,updated_at FROM authority_signing_work_audits WHERE org_id=? AND project_id=? AND job_id=? AND phase=? AND revision=?", params![tenant.org_id,tenant.project_id,job,phase,next.revision.to_be_bytes().as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if binding.2 != kind || binding.3 != next.updated {
        return Err(invalid("signing work audit projection"));
    }
    audit_log::verify_bound_event(
        tx,
        tenant,
        &binding.0,
        &binding.1,
        &format!("signing_{phase}_{kind}"),
        job,
        next.updated,
    )?;
    let sequence: [u8; 8] = binding
        .0
        .as_slice()
        .try_into()
        .map_err(|_| invalid("signing audit sequence"))?;
    Ok(u64::from_be_bytes(sequence))
}

/// Legacy audit bytes have no work revision. Only one exact historical match
/// is sufficient evidence: absent or ambiguous candidates abort the upgrade.
/// New events instead retain an explicit, immutable one-use audit identity.
pub(super) fn backfill_work_audits(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch(MIGRATION_WORK_BINDINGS)?;
    let mut statement = tx.prepare("SELECT org_id,project_id,job_id,phase,revision,kind,updated_at FROM authority_signing_work_events ORDER BY org_id,project_id,job_id,phase,revision")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let job: String = row.get(2)?;
        identifier(&job)?;
        let phase: String = row.get(3)?;
        let revision: [u8; 8] = row.get(4)?;
        let kind: String = row.get(5)?;
        let updated: i64 = row.get(6)?;
        let audit_kind = format!("signing_{phase}_{kind}");
        let mut candidates = tx.prepare("SELECT CASE WHEN length(sequence)=8 THEN sequence END,CASE WHEN length(event_hash)=32 THEN event_hash END FROM authority_audit WHERE org_id=? AND project_id=? AND resource_id=? AND kind=? AND recorded_at=? ORDER BY sequence LIMIT 2")?;
        let candidates = candidates
            .query_map(
                params![tenant.org_id, tenant.project_id, job, audit_kind, updated],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if candidates.len() != 1 {
            return Err(invalid("missing or ambiguous legacy signing work audit"));
        }
        let (sequence, digest) = &candidates[0];
        audit_log::verify_bound_event(tx, &tenant, sequence, digest, &audit_kind, &job, updated)?;
        let previous: Option<Vec<u8>> = tx.query_row("SELECT audit_sequence FROM authority_signing_work_audits WHERE org_id=? AND project_id=? AND job_id=? AND phase=? ORDER BY revision DESC LIMIT 1", params![tenant.org_id,tenant.project_id,job,phase], |r| r.get(0)).optional()?;
        if previous.as_ref().is_some_and(|old| old >= sequence) {
            return Err(invalid("legacy signing work audit order"));
        }
        tx.execute(
            "INSERT INTO authority_signing_work_audits VALUES(?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                job,
                phase,
                revision.as_slice(),
                kind,
                updated,
                sequence,
                digest
            ],
        )?;
    }
    Ok(())
}

pub(super) fn dispatch_unknown_seen(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job: &str,
) -> Result<bool> {
    Ok(work_history(tx, tenant, job, "dispatch")?.had_unknown)
}

fn head(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job: &str,
    phase: &str,
) -> Result<Option<Head>> {
    Ok(work_history(tx, tenant, job, phase)?.current)
}

/// Historical uncertainty cannot be erased by changing only a reservation or
/// by looking solely at a later claimed work head. This helper never reads quota.
pub(super) fn reservation_has_unknown_history(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    reservation: &str,
) -> Result<bool> {
    let job: Option<String> = tx.query_row("SELECT CASE WHEN length(job_id)=36 THEN job_id END FROM authority_signing_intents WHERE org_id=? AND project_id=? AND reservation_id=?", params![tenant.org_id, tenant.project_id, reservation], |r| r.get(0)).optional()?;
    job.map(|job| work_history(tx, tenant, &job, "dispatch").map(|history| history.had_unknown))
        .transpose()
        .map(|value| value.unwrap_or(false))
}

/// Maintenance checks every retained phase before adding new SQL guards. No
/// legacy work bytes or claimed delivery records are upgraded into authority.
pub(super) fn validate_work_histories(tx: &Transaction<'_>) -> Result<()> {
    let mut statement =
        tx.prepare("SELECT CASE WHEN length(org_id)=36 THEN org_id END,CASE WHEN length(project_id)=36 THEN project_id END,CASE WHEN length(job_id)=36 THEN job_id END FROM authority_signing_jobs")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let job: String = row.get(2)?;
        if work_history(tx, &tenant, &job, "signer")?.current.is_none() {
            return Err(invalid("missing signing work history"));
        }
        work_history(tx, &tenant, &job, "dispatch")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_head(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job: &str,
    phase: &str,
    old: Option<&Head>,
    mut next: Head,
    kind: &str,
    now: i64,
) -> Result<()> {
    time(now)?;
    if old.is_some_and(|h| now < h.updated) {
        return Err(AuthorityError::Time);
    }
    next.updated = now;
    next.revision = old
        .map_or(Some(1), |h| h.revision.checked_add(1))
        .ok_or(AuthorityError::Quota)?;
    audit(tx, tenant, &format!("signing_{phase}_{kind}"), job, now)?;
    tx.execute("INSERT INTO authority_signing_work_audits SELECT ?1,?2,?3,?4,?5,?6,?7,sequence,event_hash FROM authority_audit_heads WHERE org_id=?1 AND project_id=?2", params![tenant.org_id,tenant.project_id,job,phase,next.revision.to_be_bytes().as_slice(),kind,now])?;
    tx.execute(
        "INSERT INTO authority_signing_work_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            job,
            phase,
            next.state,
            next.revision.to_be_bytes().as_slice(),
            next.generation.to_be_bytes().as_slice(),
            next.claim_hash,
            next.worker,
            next.until,
            next.attempts,
            next.available,
            next.updated,
            kind
        ],
    )?;
    // The AFTER INSERT trigger projects the head in this same SQL statement.
    // A committed event-only transaction therefore cannot strand an old head.
    Ok(())
}

fn initial(state: &str, now: i64) -> Head {
    Head {
        state: state.into(),
        revision: 0,
        generation: 0,
        claim_hash: None,
        worker: None,
        until: None,
        attempts: 0,
        available: now,
        updated: now,
    }
}
fn clear_claim(value: &mut Head, state: &str) {
    value.state = state.into();
    value.claim_hash = None;
    value.worker = None;
    value.until = None;
}
fn retry_delay(value: &Head) -> i64 {
    let base = 1i64 << value.attempts.min(5);
    // Stable jitter from the random claim digest: reopening/retrying a failed
    // attempt cannot repeatedly draw a shorter wait or require another write.
    let jitter = value
        .claim_hash
        .as_ref()
        .map_or(0, |hash| i64::from(hash[0]))
        % base;
    (base + jitter).min(60)
}
fn bound_job(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    now: i64,
) -> Result<(PreparedSigningJob, signing_intents::SigningIntentRecord)> {
    bound_job_in_state(tx, tenant, job_id, now, false)
}

fn bound_job_in_state(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    now: i64,
    initializing: bool,
) -> Result<(PreparedSigningJob, signing_intents::SigningIntentRecord)> {
    identifier(job_id)?;
    time(now)?;
    let job = signing_intents::job_at(tx, tenant, job_id)?;
    let intent = signing_intents::intent_at(tx, tenant, &job.job().intent_id)?;
    let reservation = if initializing {
        signing_quota::read_initializing_job(tx, tenant, &intent.reservation_id)?
    } else {
        signing_quota::read(tx, tenant, &intent.reservation_id)?
    };
    if reservation.plan_id != intent.plan_id
        || reservation.plan_hash != intent.plan_hash
        || reservation.reserved_at != intent.created_at
        || reservation.reserved_until != intent.valid_until
    {
        return Err(AuthorityError::Binding);
    }
    if now < crate::timestamp(&intent.created_at)? {
        return Err(AuthorityError::Time);
    }
    Ok((job, intent))
}

pub(super) fn initialize_job(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    now: i64,
) -> Result<()> {
    // Only this in-transaction step precedes the first signer event/head.
    bound_job_in_state(tx, tenant, job_id, now, true)?;
    if head(tx, tenant, job_id, "signer")?.is_some() {
        return Err(AuthorityError::Conflict);
    }
    write_head(
        tx,
        tenant,
        job_id,
        "signer",
        None,
        initial("prepared", now),
        "created",
        now,
    )
}

fn claim_matches(
    head: &Head,
    claim: &SigningClaim,
    job: &str,
    phase: &str,
    now: i64,
) -> Result<()> {
    claim_identity(head, claim, job, phase)?;
    if now < head.updated || now >= claim.until {
        return Err(AuthorityError::Time);
    }
    Ok(())
}
fn claim_identity(head: &Head, claim: &SigningClaim, job: &str, phase: &str) -> Result<()> {
    let digest = hash(&hash_bytes(&claim.token))?;
    if head.state != "claimed"
        || claim.job_id != job
        || claim.phase != phase
        || claim.generation != head.generation
        || head.worker.as_deref() != Some(&claim.worker_id)
        || head.until != Some(claim.until)
        || head
            .claim_hash
            .as_ref()
            .is_none_or(|stored| !openssl::memcmp::eq(stored, &digest))
    {
        return Err(AuthorityError::Conflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn claim_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    phase: &'static str,
    worker: &str,
    expected: u64,
    lease: i64,
    now: i64,
) -> Result<SigningClaim> {
    identifier(worker)?;
    if !(1..=MAX_CLAIM_SECONDS).contains(&lease) {
        return Err(invalid("signing claim duration"));
    }
    lifecycle_status(tx, tenant, job_id, now)?;
    let (_, intent) = bound_job(tx, tenant, job_id, now)?;
    let reservation = signing_quota::read(tx, tenant, &intent.reservation_id)?;
    if (phase == "signer" && (reservation.state != "reserved" || reservation.issued_at.is_some()))
        || (phase == "dispatch"
            && (!matches!(reservation.state.as_str(), "issued" | "unknown")
                || reservation.issued_at.is_none()
                || reservation.dispatch_slots != 1))
    {
        return Err(AuthorityError::Binding);
    }
    let deadline = crate::timestamp(&intent.valid_until)?;
    let mut old = head(tx, tenant, job_id, phase)?.ok_or(AuthorityError::Binding)?;
    let eligible = if phase == "signer" {
        old.state == "prepared"
    } else {
        old.state == "queued" || old.state == "unknown"
    };
    let expired = old.state == "claimed" && old.until.is_some_and(|until| now >= until);
    if (!eligible && !expired) || expected != old.generation {
        return Err(AuthorityError::Conflict);
    }
    if now < old.updated || now < old.available || now >= deadline {
        return Err(AuthorityError::Time);
    }
    if expired
        && now
            < old
                .until
                .unwrap()
                .checked_add(retry_delay(&old))
                .ok_or(AuthorityError::Time)?
    {
        return Err(AuthorityError::Time);
    }
    let maximum = if phase == "signer" {
        MAX_SIGNER_ATTEMPTS
    } else {
        MAX_DISPATCH_ATTEMPTS
    };
    if old.attempts >= maximum {
        return Err(AuthorityError::Quota);
    }
    if phase == "dispatch" {
        outbox(tx, tenant, job_id, now)?;
        if expired {
            let mut uncertain = old.clone();
            clear_claim(&mut uncertain, "unknown");
            write_head(
                tx,
                tenant,
                job_id,
                phase,
                Some(&old),
                uncertain,
                "unknown",
                now,
            )?;
            signing_quota::mark_unknown(tx, tenant, &intent.reservation_id, now)?;
            old = head(tx, tenant, job_id, phase)?.ok_or(AuthorityError::Binding)?;
        }
    }
    let mut token = [0; 32];
    openssl::rand::rand_bytes(&mut token).map_err(|_| invalid("signing claim randomness"))?;
    let mut next = old.clone();
    next.state = "claimed".into();
    next.generation = old.generation.checked_add(1).ok_or(AuthorityError::Quota)?;
    next.claim_hash = Some(hash(&hash_bytes(&token))?);
    next.worker = Some(worker.into());
    next.until = Some(
        now.checked_add(lease)
            .ok_or(AuthorityError::Time)?
            .min(deadline),
    );
    next.attempts += 1;
    let claim = SigningClaim {
        job_id: job_id.into(),
        worker_id: worker.into(),
        phase,
        generation: next.generation,
        token,
        until: next.until.unwrap(),
    };
    write_head(tx, tenant, job_id, phase, Some(&old), next, "claimed", now)?;
    Ok(claim)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn fixture_claim(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    phase: &'static str,
    worker: &str,
    expected: u64,
    lease: i64,
    now: i64,
) -> Result<SigningClaim> {
    claim_in_tx(tx, tenant, job_id, phase, worker, expected, lease, now)
}

pub(super) fn validate_finalize_claim(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    claim: &SigningClaim,
    now: i64,
) -> Result<()> {
    let (_, intent) = bound_job(tx, tenant, job_id, now)?;
    let current = head(tx, tenant, job_id, "signer")?.ok_or(AuthorityError::Binding)?;
    claim_matches(&current, claim, job_id, "signer", now)?;
    if now >= crate::timestamp(&intent.valid_until)? {
        return Err(AuthorityError::Time);
    }
    Ok(())
}

pub(super) fn record_ready(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    claim: &SigningClaim,
    result: &VerifiedSigningResult,
    now: i64,
) -> Result<()> {
    validate_finalize_claim(tx, tenant, job_id, claim, now)?;
    let (job, intent) = bound_job(tx, tenant, job_id, now)?;
    let response = crate::parse_signer_result(result.canonical_result_bytes())?;
    if response.job_id != job_id
        || response.intent_id != intent.intent_id
        || response.payload_hash != job.job().payload_hash
    {
        return Err(AuthorityError::Binding);
    }
    let stored:(Vec<u8>,Vec<u8>,Vec<u8>)=tx.query_row("SELECT grant_hash,CASE WHEN length(grant_bytes)<=262144 THEN grant_bytes END,CASE WHEN length(result_bytes)<=262144 THEN result_bytes END FROM authority_signing_results WHERE org_id=? AND project_id=? AND intent_id=?",params![tenant.org_id,tenant.project_id,intent.intent_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    if stored.0 != hash(result.grant_hash())?
        || stored.1 != result.canonical_grant_bytes()
        || stored.2 != result.canonical_result_bytes()
    {
        return Err(AuthorityError::Binding);
    }
    tx.execute(
        "INSERT INTO authority_signing_outbox VALUES(?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            job_id,
            intent.intent_id,
            stored.0,
            stored.1,
            now
        ],
    )?;
    let old = head(tx, tenant, job_id, "signer")?.ok_or(AuthorityError::Binding)?;
    let mut next = old.clone();
    clear_claim(&mut next, "ready");
    write_head(
        tx,
        tenant,
        job_id,
        "signer",
        Some(&old),
        next,
        "finalized",
        now,
    )?;
    write_head(
        tx,
        tenant,
        job_id,
        "dispatch",
        None,
        initial("queued", now),
        "created",
        now,
    )
}

fn outbox(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    now: i64,
) -> Result<(String, Vec<u8>)> {
    let (_, intent) = bound_job(tx, tenant, job_id, now)?;
    let row:(String,Vec<u8>,Vec<u8>,i64)=tx.query_row("SELECT intent_id,grant_hash,CASE WHEN length(grant_bytes)<=262144 THEN grant_bytes END,created_at FROM authority_signing_outbox WHERE org_id=? AND project_id=? AND job_id=?",params![tenant.org_id,tenant.project_id,job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?.ok_or(AuthorityError::Binding)?;
    // Reverify the actual Ed25519 signature and exact prepared payload at every
    // dequeue, including historical retries after expiry. Hash equality alone
    // cannot authenticate an attacker-rewritten result and outbox together.
    let verified =
        signing_intents::retained_result(tx, tenant, &intent)?.ok_or(AuthorityError::Binding)?;
    let issued: i64 = tx.query_row(
        "SELECT finalized_at FROM authority_signing_results WHERE org_id=? AND project_id=? AND intent_id=?",
        params![tenant.org_id, tenant.project_id, intent.intent_id], |r| r.get(0),
    )?;
    let reservation = signing_quota::read(tx, tenant, &intent.reservation_id)?;
    if row.0 != intent.intent_id
        || row.1 != hash(verified.grant_hash())?
        || row.2 != verified.canonical_grant_bytes()
        || row.3 != issued
        || reservation.issued_at.as_deref() != Some(at(issued)?.as_str())
        || !matches!(reservation.state.as_str(), "issued" | "unknown" | "active")
        || now < issued
    {
        return Err(AuthorityError::Binding);
    }
    Ok((verified.grant_hash().to_owned(), row.2))
}

pub(super) fn lifecycle_status(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    now: i64,
) -> Result<SigningLifecycleStatus> {
    let (_, intent) = bound_job(tx, tenant, job_id, now)?;
    let signer = head(tx, tenant, job_id, "signer")?.ok_or(AuthorityError::Binding)?;
    let dispatch = head(tx, tenant, job_id, "dispatch")?;
    if now < signer.updated || dispatch.as_ref().is_some_and(|d| now < d.updated) {
        return Err(AuthorityError::Time);
    }
    let reservation = signing_quota::read(tx, tenant, &intent.reservation_id)?;
    if (signer.state == "ready") != dispatch.is_some() {
        return Err(invalid("signing dispatch state"));
    }
    let (has_result, has_outbox): (bool, bool) = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_signing_results WHERE org_id=?1 AND project_id=?2 AND intent_id=?3), EXISTS(SELECT 1 FROM authority_signing_outbox WHERE org_id=?1 AND project_id=?2 AND intent_id=?3)",
        params![tenant.org_id, tenant.project_id, intent.intent_id], |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    type DeliveryRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);
    let delivery: Option<DeliveryRow> = tx.query_row(
        "SELECT grant_hash,result_hash,CASE WHEN length(result_bytes)<=262144 THEN result_bytes END,recorded_at FROM authority_signing_deliveries WHERE org_id=? AND project_id=? AND job_id=?",
        params![tenant.org_id, tenant.project_id, job_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ).optional()?;
    if (signer.state == "ready") != has_result || has_result != has_outbox {
        return Err(invalid("signing result lifecycle"));
    }
    let compatible = match dispatch.as_ref().map(|d| d.state.as_str()) {
        None if signer.state == "cancelled" => {
            reservation.state == "released" && reservation.issued_at.is_none()
        }
        None => reservation.state == "reserved" && reservation.issued_at.is_none(),
        Some("queued") => reservation.state == "issued",
        Some("claimed") => matches!(reservation.state.as_str(), "issued" | "unknown"),
        Some("unknown") => reservation.state == "unknown",
        Some("delivered") => reservation.state == "active",
        _ => false,
    };
    if !compatible
        || dispatch.as_ref().is_some_and(|d| d.state == "delivered") != delivery.is_some()
    {
        return Err(invalid("signing quota lifecycle"));
    }
    if dispatch.is_some() {
        let (grant, _) = outbox(tx, tenant, job_id, now)?;
        if let Some((delivered_grant, result_hash, result_bytes, recorded)) = delivery
            && (delivered_grant != hash(&grant)?
                || result_hash != hash(&hash_bytes(&result_bytes))?
                || result_bytes.is_empty()
                || recorded > now
                || reservation
                    .issued_at
                    .as_deref()
                    .map(crate::timestamp)
                    .transpose()?
                    .is_none_or(|issued| recorded < issued))
        {
            return Err(invalid("signing delivery projection"));
        }
    }
    Ok(SigningLifecycleStatus {
        job_id: job_id.into(),
        state: signer.state,
        claim_generation: signer.generation,
        attempts: signer.attempts as u32,
        claim_until: signer.until,
        dispatch_state: dispatch.as_ref().map(|d| d.state.clone()),
        dispatch_attempts: dispatch.map_or(0, |d| d.attempts as u32),
        quota_held: reservation.held(),
    })
}

fn retry_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    claim: &SigningClaim,
    now: i64,
) -> Result<()> {
    lifecycle_status(tx, tenant, &claim.job_id, now)?;
    let (_, intent) = bound_job(tx, tenant, &claim.job_id, now)?;
    let old = head(tx, tenant, &claim.job_id, claim.phase)?.ok_or(AuthorityError::Binding)?;
    claim_matches(&old, claim, &claim.job_id, claim.phase, now)?;
    let available = now
        .checked_add(retry_delay(&old))
        .ok_or(AuthorityError::Time)?;
    if available >= crate::timestamp(&intent.valid_until)? {
        return Err(AuthorityError::Time);
    }
    let mut next = old.clone();
    clear_claim(
        &mut next,
        if claim.phase == "signer" {
            "prepared"
        } else {
            "unknown"
        },
    );
    next.available = available;
    write_head(
        tx,
        tenant,
        &claim.job_id,
        claim.phase,
        Some(&old),
        next,
        if claim.phase == "signer" {
            "retried"
        } else {
            "unknown"
        },
        now,
    )?;
    if claim.phase == "dispatch" {
        signing_quota::mark_unknown(tx, tenant, &intent.reservation_id, now)?;
    }
    Ok(())
}

fn renew_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    claim: &SigningClaim,
    lease_seconds: i64,
    now: i64,
) -> Result<SigningClaim> {
    lifecycle_status(tx, tenant, &claim.job_id, now)?;
    let (_, intent) = bound_job(tx, tenant, &claim.job_id, now)?;
    if !(1..=MAX_CLAIM_SECONDS).contains(&lease_seconds) {
        return Err(invalid("signing claim duration"));
    }
    let old = head(tx, tenant, &claim.job_id, claim.phase)?.ok_or(AuthorityError::Binding)?;
    claim_matches(&old, claim, &claim.job_id, claim.phase, now)?;
    let until = now
        .checked_add(lease_seconds)
        .ok_or(AuthorityError::Time)?
        .min(crate::timestamp(&intent.valid_until)?);
    if until < claim.until {
        return Err(AuthorityError::Time);
    }
    if until == claim.until {
        return Ok(claim.clone());
    }
    let renewals: i64 = tx.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM authority_signing_work_events WHERE org_id=? AND project_id=? AND job_id=? AND phase=? AND claim_generation=? AND kind='renewed' LIMIT 32)",
        params![tenant.org_id, tenant.project_id, claim.job_id, claim.phase, claim.generation.to_be_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if renewals >= MAX_CLAIM_RENEWALS {
        return Err(AuthorityError::Quota);
    }
    let mut next = old.clone();
    next.until = Some(until);
    write_head(
        tx,
        tenant,
        &claim.job_id,
        claim.phase,
        Some(&old),
        next,
        "renewed",
        now,
    )?;
    let mut renewed = claim.clone();
    renewed.until = until;
    Ok(renewed)
}

#[cfg(test)]
pub(super) fn fixture_renew(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    claim: &SigningClaim,
    lease_seconds: i64,
    now: i64,
) -> Result<SigningClaim> {
    renew_in_tx(tx, tenant, claim, lease_seconds, now)
}

fn unknown_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    claim: &SigningClaim,
    now: i64,
) -> Result<()> {
    lifecycle_status(tx, tenant, &claim.job_id, now)?;
    let (_, intent) = bound_job(tx, tenant, &claim.job_id, now)?;
    let old = head(tx, tenant, &claim.job_id, "dispatch")?.ok_or(AuthorityError::Binding)?;
    if now < old.updated {
        return Err(AuthorityError::Time);
    }
    // A timed-out sender is allowed to report uncertainty, never success. It
    // must still own this generation; a superseded worker cannot mutate it.
    if old.state == "unknown" && old.generation == claim.generation {
        let previous=tx.query_row(&format!("SELECT {HEAD_COLUMNS} FROM authority_signing_work_events WHERE org_id=? AND project_id=? AND job_id=? AND phase='dispatch' AND state='claimed' AND claim_generation=? ORDER BY revision DESC LIMIT 1"),params![tenant.org_id,tenant.project_id,claim.job_id,claim.generation.to_be_bytes().as_slice()],read_head)?;
        claim_identity(&previous, claim, &claim.job_id, "dispatch")?;
        return Ok(());
    }
    claim_identity(&old, claim, &claim.job_id, "dispatch")?;
    outbox(tx, tenant, &claim.job_id, now)?;
    let mut next = old.clone();
    clear_claim(&mut next, "unknown");
    next.available = now.saturating_add(retry_delay(&old)).min(MAX_TIME);
    write_head(
        tx,
        tenant,
        &claim.job_id,
        "dispatch",
        Some(&old),
        next,
        "unknown",
        now,
    )?;
    signing_quota::mark_unknown(tx, tenant, &intent.reservation_id, now)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture_unknown(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    claim: &SigningClaim,
    now: i64,
) -> Result<()> {
    unknown_in_tx(tx, tenant, claim, now)
}

// An unsigned delivery record is diagnostic history, not authenticated target
// evidence. It never releases issued quota. A future authenticated receipt must
// use a separate verified type and independent trust. No public completion
// endpoint or production constructor exists; only unit fixtures construct this.
#[allow(dead_code)]
pub(super) struct RecordedDelivery {
    job_id: String,
    grant_hash: String,
    result_bytes: Vec<u8>,
}
#[cfg(test)]
pub(super) fn fixture_deliver(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    claim: &SigningClaim,
    now: i64,
) -> Result<()> {
    let (grant_hash, _) = outbox(tx, tenant, &claim.job_id, now)?;
    let receipt = RecordedDelivery {
        job_id: claim.job_id.clone(),
        grant_hash: grant_hash.clone(),
        result_bytes: bytes(
            &json!({"fixture":"verified target result","job_id":claim.job_id,"grant_hash":grant_hash}),
        )?,
    };
    deliver_in_tx(tx, tenant, claim, &receipt, now)
}
#[allow(dead_code)]
pub(super) fn deliver_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    claim: &SigningClaim,
    receipt: &RecordedDelivery,
    now: i64,
) -> Result<()> {
    lifecycle_status(tx, tenant, &claim.job_id, now)?;
    let (_, intent) = bound_job(tx, tenant, &claim.job_id, now)?;
    let (grant_hash, _) = outbox(tx, tenant, &claim.job_id, now)?;
    if receipt.job_id != claim.job_id
        || receipt.grant_hash != grant_hash
        || receipt.result_bytes.is_empty()
        || receipt.result_bytes.len() > 262144
    {
        return Err(AuthorityError::Binding);
    }
    let existing:Option<(Vec<u8>,Vec<u8>,Vec<u8>)>=tx.query_row("SELECT grant_hash,result_hash,CASE WHEN length(result_bytes)<=262144 THEN result_bytes END FROM authority_signing_deliveries WHERE org_id=? AND project_id=? AND job_id=?",params![tenant.org_id,tenant.project_id,claim.job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let result_hash = hash(&hash_bytes(&receipt.result_bytes))?;
    let old = head(tx, tenant, &claim.job_id, "dispatch")?.ok_or(AuthorityError::Binding)?;
    if let Some((grant, result, bytes)) = existing {
        if old.state != "delivered"
            || grant != hash(&grant_hash)?
            || result != result_hash
            || bytes != receipt.result_bytes
        {
            return Err(AuthorityError::Conflict);
        }
        return Ok(());
    }
    claim_matches(&old, claim, &claim.job_id, "dispatch", now)?;
    tx.execute(
        "INSERT INTO authority_signing_deliveries VALUES(?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            claim.job_id,
            hash(&grant_hash)?,
            result_hash,
            receipt.result_bytes,
            now
        ],
    )?;
    let mut next = old.clone();
    clear_claim(&mut next, "delivered");
    write_head(
        tx,
        tenant,
        &claim.job_id,
        "dispatch",
        Some(&old),
        next,
        "delivered",
        now,
    )?;
    signing_quota::mark_active(tx, tenant, &intent.reservation_id, now)?;
    Ok(())
}

fn cancel_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
    now: i64,
) -> Result<()> {
    lifecycle_status(tx, tenant, job_id, now)?;
    let (_, intent) = bound_job(tx, tenant, job_id, now)?;
    let old = head(tx, tenant, job_id, "signer")?.ok_or(AuthorityError::Binding)?;
    let committed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_results WHERE org_id=?1 AND project_id=?2 AND intent_id=?3) OR EXISTS(SELECT 1 FROM authority_signing_outbox WHERE org_id=?1 AND project_id=?2 AND intent_id=?3)",params![tenant.org_id,tenant.project_id,intent.intent_id],|r|r.get(0))?;
    if committed || old.state == "ready" || head(tx, tenant, job_id, "dispatch")?.is_some() {
        return Err(AuthorityError::Conflict);
    }
    if old.state == "cancelled" {
        return signing_quota::cancel_unissued(tx, tenant, &intent.reservation_id, now);
    }
    let mut next = old.clone();
    clear_claim(&mut next, "cancelled");
    write_head(
        tx,
        tenant,
        job_id,
        "signer",
        Some(&old),
        next,
        "cancelled",
        now,
    )?;
    signing_quota::cancel_unissued(tx, tenant, &intent.reservation_id, now)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture_cancel_work(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job: &str,
    now: i64,
) -> Result<()> {
    let old = head(tx, tenant, job, "signer")?.ok_or(AuthorityError::Binding)?;
    let mut next = old.clone();
    clear_claim(&mut next, "cancelled");
    write_head(
        tx,
        tenant,
        job,
        "signer",
        Some(&old),
        next,
        "cancelled",
        now,
    )
}

impl AuthorityStore {
    pub fn claim_signing_job(
        &mut self,
        tenant: &AuthorityTenant,
        job_id: &str,
        worker: &str,
        expected_generation: u64,
        lease_seconds: i64,
        now: i64,
    ) -> Result<SigningClaim> {
        self.observe_signing_job_quota_time(tenant, job_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, intent) = bound_job(&tx, tenant, job_id, now)?;
        signing_intents::protected_job_eligibility(&tx, tenant, &intent.intent_id, now)?;
        let claim = claim_in_tx(
            &tx,
            tenant,
            job_id,
            "signer",
            worker,
            expected_generation,
            lease_seconds,
            now,
        )?;
        tx.commit()?;
        Ok(claim)
    }
    pub fn renew_signing_claim(
        &mut self,
        tenant: &AuthorityTenant,
        claim: &SigningClaim,
        lease_seconds: i64,
        now: i64,
    ) -> Result<SigningClaim> {
        self.observe_signing_job_quota_time(tenant, &claim.job_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, intent) = bound_job(&tx, tenant, &claim.job_id, now)?;
        signing_intents::protected_job_eligibility(&tx, tenant, &intent.intent_id, now)?;
        let renewed = renew_in_tx(&tx, tenant, claim, lease_seconds, now)?;
        tx.commit()?;
        Ok(renewed)
    }
    pub fn retry_signing_claim(
        &mut self,
        tenant: &AuthorityTenant,
        claim: &SigningClaim,
        now: i64,
    ) -> Result<()> {
        self.observe_signing_job_quota_time(tenant, &claim.job_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, intent) = bound_job(&tx, tenant, &claim.job_id, now)?;
        signing_intents::protected_job_eligibility(&tx, tenant, &intent.intent_id, now)?;
        retry_in_tx(&tx, tenant, claim, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn cancel_signing_job(
        &mut self,
        tenant: &AuthorityTenant,
        job_id: &str,
        now: i64,
    ) -> Result<()> {
        self.observe_signing_job_quota_time(tenant, job_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        cancel_in_tx(&tx, tenant, job_id, now)?;
        tx.commit()?;
        Ok(())
    }
    pub fn claim_signing_dispatch(
        &mut self,
        tenant: &AuthorityTenant,
        job_id: &str,
        worker: &str,
        expected_generation: u64,
        lease_seconds: i64,
        now: i64,
    ) -> Result<SigningDispatchClaim> {
        self.observe_signing_job_quota_time(tenant, job_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, intent) = bound_job(&tx, tenant, job_id, now)?;
        signing_intents::protected_job_eligibility(&tx, tenant, &intent.intent_id, now)?;
        let claim = claim_in_tx(
            &tx,
            tenant,
            job_id,
            "dispatch",
            worker,
            expected_generation,
            lease_seconds,
            now,
        )?;
        let (grant_hash, grant_bytes) = outbox(&tx, tenant, job_id, now)?;
        tx.commit()?;
        Ok(SigningDispatchClaim {
            claim,
            grant_hash,
            grant_bytes,
        })
    }
    pub fn mark_signing_dispatch_unknown(
        &mut self,
        tenant: &AuthorityTenant,
        claim: &SigningClaim,
        now: i64,
    ) -> Result<()> {
        self.observe_signing_job_quota_time(tenant, &claim.job_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, intent) = bound_job(&tx, tenant, &claim.job_id, now)?;
        signing_intents::protected_job_eligibility(&tx, tenant, &intent.intent_id, now)?;
        unknown_in_tx(&tx, tenant, claim, now)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::signing_test_support::{Fixture, NOW};
    use super::*;
    use std::sync::{Arc, Barrier};
    const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

    fn prepared() -> (Fixture, String, String) {
        let mut f = Fixture::new();
        let outcome = signing_intents::test_prepare(&mut f, NOW);
        (f, outcome.intent.job_id, outcome.intent.reservation_id)
    }
    fn claim(
        f: &mut Fixture,
        job: &str,
        phase: &'static str,
        generation: u64,
        lease: i64,
        now: i64,
    ) -> Result<SigningClaim> {
        f.store.observe_signing_quota_time(&f.tenant, now)?;
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = fixture_claim(&tx, &f.tenant, job, phase, WORKER, generation, lease, now)?;
        tx.commit()?;
        Ok(result)
    }
    fn ready() -> (Fixture, String, String) {
        let (mut f, job, reservation) = prepared();
        let c = claim(&mut f, &job, "signer", 0, 60, NOW).unwrap();
        signing_intents::test_finalize(&mut f, &c, NOW).unwrap();
        (f, job, reservation)
    }

    #[test]
    fn public_workers_remain_closed_but_proven_unissued_cancellation_is_safe() {
        let (mut f, job, reservation) = prepared();
        assert!(
            f.store
                .claim_signing_job(&f.tenant, &job, WORKER, 0, 60, NOW)
                .is_err()
        );
        assert!(
            f.store
                .claim_signing_dispatch(&f.tenant, &job, WORKER, 0, 60, NOW)
                .is_err()
        );
        let events = f.count("authority_signing_work_events");
        f.store.cancel_signing_job(&f.tenant, &job, NOW).unwrap();
        f.store.cancel_signing_job(&f.tenant, &job, NOW).unwrap();
        assert_eq!(f.count("authority_signing_work_events"), events + 1);
        assert_eq!(f.count("authority_signing_outbox"), 0);
        f.reopen();
        let tx = f.store.connection.transaction().unwrap();
        let budget = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
        assert_eq!(budget.state, "released");
        assert!(!budget.held());
        assert_eq!(
            lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap().state,
            "cancelled"
        );
        let generation: Vec<u8> = tx
            .query_row(
                "SELECT generation FROM authority_signing_target_heads",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(generation, 1u64.to_be_bytes());
        assert!(fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 0, 60, NOW).is_err());
    }

    #[test]
    fn claim_expiry_restart_token_worker_tenant_and_generation_are_fenced() {
        let (mut f, job, _) = prepared();
        let first = claim(&mut f, &job, "signer", 0, 10, NOW).unwrap();
        assert!(claim(&mut f, &job, "signer", 0, 10, NOW).is_err());
        f.reopen();
        let tx = f.store.connection.transaction().unwrap();
        let mut wrong = first.clone();
        wrong.token[0] ^= 1;
        assert!(validate_finalize_claim(&tx, &f.tenant, &job, &wrong, NOW + 1).is_err());
        wrong = first.clone();
        wrong.worker_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".into();
        assert!(validate_finalize_claim(&tx, &f.tenant, &job, &wrong, NOW + 1).is_err());
        let other = AuthorityTenant::new(f.tenant.org_id(), "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
            .unwrap();
        assert!(validate_finalize_claim(&tx, &other, &job, &first, NOW + 1).is_err());
        assert!(validate_finalize_claim(&tx, &f.tenant, &job, &first, NOW + 10).is_err());
        tx.commit().unwrap();
        assert!(claim(&mut f, &job, "signer", 1, 10, NOW + 10).is_err());
        let second = claim(&mut f, &job, "signer", 1, 10, NOW + 14).unwrap();
        assert_eq!(second.generation(), 2);
        let tx = f.store.connection.transaction().unwrap();
        assert!(validate_finalize_claim(&tx, &f.tenant, &job, &first, NOW + 14).is_err());
        validate_finalize_claim(&tx, &f.tenant, &job, &second, NOW + 14).unwrap();
    }

    #[test]
    fn heartbeat_preserves_fence_and_is_bounded_by_original_job_deadline() {
        let (mut f, job, _) = prepared();
        assert!(claim(&mut f, &job, "signer", 0, 901, NOW).is_err());
        let first = claim(&mut f, &job, "signer", 0, 10, NOW).unwrap();
        assert!(
            f.store
                .renew_signing_claim(&f.tenant, &first, 20, NOW + 1)
                .is_err()
        );
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let before = head(&tx, &f.tenant, &job, "signer").unwrap().unwrap();
        assert_eq!(before.claim_hash.as_ref().unwrap().len(), 32);
        assert_ne!(
            before.claim_hash.as_ref().unwrap().as_slice(),
            first.token.as_slice()
        );
        let renewed = renew_in_tx(&tx, &f.tenant, &first, 900, NOW + 1).unwrap();
        let (_, intent) = bound_job(&tx, &f.tenant, &job, NOW + 1).unwrap();
        assert_eq!(
            renewed.valid_until(),
            crate::timestamp(&intent.valid_until).unwrap()
        );
        assert_eq!(renewed.generation(), first.generation());
        assert!(validate_finalize_claim(&tx, &f.tenant, &job, &first, NOW + 1).is_err());
        validate_finalize_claim(&tx, &f.tenant, &job, &renewed, NOW + 1).unwrap();
        assert!(renew_in_tx(&tx, &f.tenant, &renewed, 30, renewed.valid_until()).is_err());
        assert_eq!(
            head(&tx, &f.tenant, &job, "signer")
                .unwrap()
                .unwrap()
                .attempts,
            1
        );
        tx.commit().unwrap();
    }

    #[test]
    fn heartbeat_noops_do_not_grow_history_and_renewal_cap_survives_restart() {
        let (mut f, job, _) = prepared();
        let mut c = claim(&mut f, &job, "signer", 0, 60, NOW).unwrap();
        let events = f.count("authority_signing_work_events");
        let audit = f.count("authority_audit");
        let tx = f.store.connection.transaction().unwrap();
        for _ in 0..100 {
            c = renew_in_tx(&tx, &f.tenant, &c, 60, NOW).unwrap();
        }
        tx.commit().unwrap();
        assert_eq!(f.count("authority_signing_work_events"), events);
        assert_eq!(f.count("authority_audit"), audit);
        for extension in 1..=MAX_CLAIM_RENEWALS {
            let tx = f.store.connection.transaction().unwrap();
            c = renew_in_tx(&tx, &f.tenant, &c, 60 + extension, NOW).unwrap();
            tx.commit().unwrap();
        }
        f.reopen();
        let tx = f.store.connection.transaction().unwrap();
        assert!(matches!(
            renew_in_tx(&tx, &f.tenant, &c, 93, NOW),
            Err(AuthorityError::Quota)
        ));
        assert!(renew_in_tx(&tx, &f.tenant, &c, 92, NOW).is_ok());
        tx.commit().unwrap();
        assert_eq!(
            f.count("authority_signing_work_events"),
            events + MAX_CLAIM_RENEWALS
        );
        assert_eq!(f.count("authority_audit"), audit + MAX_CLAIM_RENEWALS);
    }

    #[test]
    fn cancelling_claimed_unissued_job_invalidates_worker_across_restart() {
        let (mut f, job, reservation) = prepared();
        let c = claim(&mut f, &job, "signer", 0, 60, NOW).unwrap();
        let intent = {
            let tx = f.store.connection.transaction().unwrap();
            signing_intents::job_at(&tx, &f.tenant, &job)
                .unwrap()
                .job()
                .intent_id
                .clone()
        };
        let result = signing_intents::test_sign(&mut f, &intent, NOW);
        f.store
            .cancel_signing_job(&f.tenant, &job, NOW + 1)
            .unwrap();
        f.reopen();
        assert!(signing_intents::test_finalize_result(&mut f, &c, &result, NOW + 1).is_err());
        let tx = f.store.connection.transaction().unwrap();
        assert!(renew_in_tx(&tx, &f.tenant, &c, 60, NOW + 1).is_err());
        assert!(retry_in_tx(&tx, &f.tenant, &c, NOW + 1).is_err());
        assert!(fixture_claim(&tx, &f.tenant, &job, "signer", WORKER, 1, 60, NOW + 1).is_err());
        let status = lifecycle_status(&tx, &f.tenant, &job, NOW + 1).unwrap();
        assert_eq!(status.state, "cancelled");
        assert_eq!(status.claim_generation, 1);
        assert_eq!(status.claim_until, None);
        assert!(
            !signing_quota::read(&tx, &f.tenant, &reservation)
                .unwrap()
                .held()
        );
        tx.commit().unwrap();
        assert_eq!(f.count("authority_signing_results"), 0);
        assert_eq!(f.count("authority_signing_outbox"), 0);
        assert_eq!(f.count("authority_signing_quota_usage"), 0);
    }

    #[test]
    fn dispatch_reverifies_signature_when_result_and_outbox_hashes_are_rewritten() {
        // Include a genuinely valid signature over the wrong exact payload.
        for valid_but_rebound in [false, true] {
            let (mut f, job, _) = ready();
            let mut result = {
                let tx = f.store.connection.transaction().unwrap();
                let raw: Vec<u8> = tx
                    .query_row(
                        "SELECT result_bytes FROM authority_signing_results",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                crate::parse_signer_result(&raw).unwrap()
            };
            if valid_but_rebound {
                struct Evidence(crate::GrantContext);
                impl crate::AuthorityEvidence for Evidence {
                    fn verify_for_signing(&self, _: &Value, _: i64) -> Result<crate::GrantContext> {
                        Ok(self.0.clone())
                    }
                }
                let mut payload = result.signed_grant.payload.clone();
                payload["not_after"] =
                    at(crate::timestamp(payload["not_after"].as_str().unwrap()).unwrap() - 1)
                        .unwrap()
                        .into();
                payload["confirm_not_after"] = at(crate::timestamp(
                    payload["confirm_not_after"].as_str().unwrap(),
                )
                .unwrap()
                    - 1)
                .unwrap()
                .into();
                let context = crate::GrantContext {
                    org_id: f.tenant.org_id.clone(),
                    project_id: f.tenant.project_id.clone(),
                    target_id: payload["target_id"].as_str().unwrap().into(),
                    plan_hash: payload["plan_hash"].as_str().unwrap().into(),
                    artifact_hash: payload["artifact_hash"].as_str().unwrap().into(),
                    baseline_hash: payload["baseline_hash"].as_str().unwrap().into(),
                    desired_state_hash: payload["desired_state_hash"].as_str().unwrap().into(),
                    approval_set_hash: payload["approval_set_hash"].as_str().unwrap().into(),
                    authority_epoch: 1,
                    now_unix: NOW,
                };
                result.signed_grant = crate::sign_grant(
                    payload,
                    "fixture-signing-key",
                    &ed25519_dalek::SigningKey::from_bytes(&[81; 32]),
                    &Evidence(context),
                    NOW,
                )
                .unwrap();
            } else {
                result.signed_grant.dsse.signatures[0].sig =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
            }
            let result_bytes = bytes(&result).unwrap();
            let grant = bytes(&result.signed_grant).unwrap();
            let grant_hash = hash(&hash_bytes(&grant)).unwrap();
            f.store.connection.execute_batch("DROP TRIGGER authority_signing_results_no_update; DROP TRIGGER authority_signing_outbox_immutable_update;").unwrap();
            f.store.connection.execute("UPDATE authority_signing_results SET grant_hash=?,result_hash=?,grant_bytes=?,result_bytes=?", params![grant_hash, hash(&hash_bytes(&result_bytes)).unwrap(), grant, result_bytes]).unwrap();
            f.store
                .connection
                .execute(
                    "UPDATE authority_signing_outbox SET grant_hash=?,grant_bytes=?",
                    params![grant_hash, grant],
                )
                .unwrap();
            let tx = f.store.connection.transaction().unwrap();
            assert!(outbox(&tx, &f.tenant, &job, NOW).is_err());
            assert!(lifecycle_status(&tx, &f.tenant, &job, NOW).is_err());
            assert!(fixture_claim(&tx, &f.tenant, &job, "dispatch", WORKER, 0, 60, NOW).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires separately built fw_authority_admin; run scripts/check.sh"]
    fn cancellation_cli_preserves_commits_retries_tenants_and_issued_unknown() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let binary = std::env::var_os("NOX_TEST_AUTHORITY_ADMIN")
            .expect("set NOX_TEST_AUTHORITY_ADMIN to separately built fw_authority_admin");
        let invoke = |f: &Fixture, job: &str, tenant: &AuthorityTenant, full: bool| {
            let mut child = Command::new(&binary)
                .args(["cancel-signing-job", "--database"])
                .arg(&f.path)
                .args([
                    "--org-id",
                    tenant.org_id(),
                    "--project-id",
                    tenant.project_id(),
                ])
                .stdin(Stdio::piped())
                .stdout(if full {
                    Stdio::from(
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open("/dev/full")
                            .unwrap(),
                    )
                } else {
                    Stdio::piped()
                })
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&bytes(&json!({"job_id":job})).unwrap())
                .unwrap();
            child.wait_with_output().unwrap()
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let fixture_time = now - 600;
        let mut f = Fixture::at(fixture_time);
        let prepared = signing_intents::test_prepare(&mut f, fixture_time);
        let job = prepared.intent.job_id;
        let reservation = prepared.intent.reservation_id;
        claim(&mut f, &job, "signer", 0, 60, fixture_time).unwrap();
        let other = AuthorityTenant::new(f.tenant.org_id(), "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
            .unwrap();
        let rejected = invoke(&f, &job, &other, false);
        assert_eq!(rejected.status.code(), Some(1));
        assert_eq!(
            rejected.stderr,
            b"AUTHORITY_ADMIN code=SIGNING_CANCELLATION_REJECTED\n"
        );
        let lost = invoke(&f, &job, &f.tenant, true);
        assert_eq!(lost.status.code(), Some(1));
        assert_eq!(lost.stderr, b"AUTHORITY_ADMIN code=OUTPUT_FAILED\n");
        f.reopen();
        let audit = f.count("authority_audit");
        let events = f.count("authority_signing_work_events");
        let retry = invoke(&f, &job, &f.tenant, false);
        assert!(retry.status.success(), "{:?}", retry.stderr);
        assert_eq!(retry.stdout, bytes(&json!({"job_id":job,"status":"cancelled","signing_allowed":false,"dispatch_allowed":false})).unwrap());
        assert!(retry.stderr.is_empty());
        assert_eq!(f.count("authority_audit"), audit);
        assert_eq!(f.count("authority_signing_work_events"), events);
        let tx = f.store.connection.transaction().unwrap();
        let budget = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
        assert_eq!(budget.state, "released");
        assert_eq!(budget.issued_at, None);
        let generation: Vec<u8> = tx
            .query_row(
                "SELECT generation FROM authority_signing_target_heads",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(generation, 1u64.to_be_bytes());
        tx.commit().unwrap();

        for uncertain in [false, true] {
            let mut f = Fixture::at(fixture_time);
            let prepared = signing_intents::test_prepare(&mut f, fixture_time);
            let job = prepared.intent.job_id;
            let reservation = prepared.intent.reservation_id;
            let signer = claim(&mut f, &job, "signer", 0, 60, fixture_time).unwrap();
            signing_intents::test_finalize(&mut f, &signer, fixture_time).unwrap();
            if uncertain {
                let claim = claim(&mut f, &job, "dispatch", 0, 60, fixture_time).unwrap();
                let tx = f.store.connection.transaction().unwrap();
                unknown_in_tx(&tx, &f.tenant, &claim, fixture_time).unwrap();
                tx.commit().unwrap();
            }
            let rejected = invoke(&f, &job, &f.tenant, false);
            assert_eq!(rejected.status.code(), Some(1));
            assert_eq!(
                rejected.stderr,
                b"AUTHORITY_ADMIN code=SIGNING_CANCELLATION_REJECTED\n"
            );
            f.reopen();
            let tx = f.store.connection.transaction().unwrap();
            assert!(
                signing_quota::read(&tx, &f.tenant, &reservation)
                    .unwrap()
                    .held()
            );
            tx.commit().unwrap();
            assert_eq!(f.count("authority_signing_results"), 1);
            assert_eq!(f.count("authority_signing_outbox"), 1);
            assert_eq!(f.count("authority_signing_quota_usage"), 1);
        }
    }

    #[test]
    fn dispatch_retry_limit_cannot_be_reset_and_public_fetch_stays_closed() {
        let (mut f, job, reservation) = ready();
        assert!(
            f.store
                .claim_signing_dispatch(&f.tenant, &job, WORKER, 0, 1, NOW)
                .is_err()
        );
        for generation in 0..5 {
            let c = claim(
                &mut f,
                &job,
                "dispatch",
                generation,
                1,
                NOW + generation as i64 * 32,
            )
            .unwrap();
            assert_eq!(c.generation(), generation + 1);
            if generation == 0 {
                assert!(
                    f.store
                        .mark_signing_dispatch_unknown(&f.tenant, &c, NOW)
                        .is_err()
                );
            }
        }
        assert!(matches!(
            claim(&mut f, &job, "dispatch", 5, 1, NOW + 200),
            Err(AuthorityError::Quota)
        ));
        f.reopen();
        let tx = f.store.connection.transaction().unwrap();
        let status = lifecycle_status(&tx, &f.tenant, &job, NOW + 200).unwrap();
        assert_eq!(status.dispatch_attempts, 5);
        assert!(
            signing_quota::read(&tx, &f.tenant, &reservation)
                .unwrap()
                .held()
        );
        tx.commit().unwrap();
        assert_eq!(f.count("authority_signing_outbox"), 1);
    }

    #[test]
    fn two_connections_cannot_claim_the_same_generation() {
        let (mut f, job, _) = prepared();
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = f.path.clone();
            let tenant = f.tenant.clone();
            let job = job.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                barrier.wait();
                let tx = store
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                match fixture_claim(&tx, &tenant, &job, "signer", WORKER, 0, 60, NOW) {
                    Ok(c) => {
                        tx.commit().unwrap();
                        Some(c.generation())
                    }
                    Err(_) => None,
                }
            }));
        }
        let winners: Vec<_> = handles
            .into_iter()
            .filter_map(|h| h.join().unwrap())
            .collect();
        assert_eq!(winners, vec![1]);
        f.reopen();
        let tx = f.store.connection.transaction().unwrap();
        let status = lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap();
        assert_eq!(status.attempts, 1);
        assert_eq!(status.claim_generation, 1);
    }

    #[test]
    fn retry_backoff_is_bounded_and_does_not_change_exact_job_or_reset_attempts() {
        let (mut f, job, _) = prepared();
        let original = {
            let tx = f.store.connection.transaction().unwrap();
            signing_intents::job_at(&tx, &f.tenant, &job)
                .unwrap()
                .canonical_job_bytes()
                .to_vec()
        };
        let mut now = NOW;
        for generation in 0..3 {
            let c = claim(&mut f, &job, "signer", generation, 60, now).unwrap();
            let tx = f
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            retry_in_tx(&tx, &f.tenant, &c, now).unwrap();
            assert_eq!(
                original,
                signing_intents::job_at(&tx, &f.tenant, &job)
                    .unwrap()
                    .canonical_job_bytes()
            );
            let h = head(&tx, &f.tenant, &job, "signer").unwrap().unwrap();
            assert!((1..=60).contains(&(h.available - now)));
            assert!(
                fixture_claim(
                    &tx,
                    &f.tenant,
                    &job,
                    "signer",
                    WORKER,
                    generation + 1,
                    60,
                    now
                )
                .is_err()
            );
            now = h.available;
            tx.commit().unwrap();
        }
        assert!(matches!(
            claim(&mut f, &job, "signer", 3, 60, now),
            Err(AuthorityError::Quota)
        ));
        f.reopen();
        assert!(matches!(
            claim(&mut f, &job, "signer", 3, 60, now),
            Err(AuthorityError::Quota)
        ));
    }

    #[test]
    fn cancelling_and_finalizing_race_to_one_atomic_outcome() {
        let (mut f, job, reservation) = prepared();
        let c = claim(&mut f, &job, "signer", 0, 60, NOW).unwrap();
        let intent = {
            let tx = f.store.connection.transaction().unwrap();
            signing_intents::job_at(&tx, &f.tenant, &job)
                .unwrap()
                .job()
                .intent_id
                .clone()
        };
        let result = signing_intents::test_sign(&mut f, &intent, NOW);
        let barrier = Arc::new(Barrier::new(2));
        let other_barrier = barrier.clone();
        let path = f.path.clone();
        let tenant = f.tenant.clone();
        let other_job = job.clone();
        let cancel = std::thread::spawn(move || {
            let mut store = AuthorityStore::open(path).unwrap();
            other_barrier.wait();
            store.cancel_signing_job(&tenant, &other_job, NOW).is_ok()
        });
        barrier.wait();
        let finalized = signing_intents::test_finalize_result(&mut f, &c, &result, NOW).is_ok();
        let cancelled = cancel.join().unwrap();
        assert_ne!(finalized, cancelled);
        assert_eq!(f.count("authority_signing_results"), i64::from(finalized));
        assert_eq!(f.count("authority_signing_outbox"), i64::from(finalized));
        let tx = f.store.connection.transaction().unwrap();
        let budget = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
        assert_eq!(budget.held(), finalized);
        assert_eq!(
            lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap().state,
            if finalized { "ready" } else { "cancelled" }
        );
    }

    #[test]
    fn unknown_delivery_survives_expiry_restart_and_never_refunds_slots() {
        let (mut f, job, reservation) = ready();
        assert!(f.store.cancel_signing_job(&f.tenant, &job, NOW).is_err());
        let c = claim(&mut f, &job, "dispatch", 0, 2, NOW).unwrap();
        let bytes = {
            let tx = f.store.connection.transaction().unwrap();
            outbox(&tx, &f.tenant, &job, NOW).unwrap().1
        };
        f.store
            .observe_signing_quota_time(&f.tenant, NOW + 400)
            .unwrap();
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        unknown_in_tx(&tx, &f.tenant, &c, NOW + 400).unwrap();
        unknown_in_tx(&tx, &f.tenant, &c, NOW + 400).unwrap();
        tx.commit().unwrap();
        f.reopen();
        let tx = f.store.connection.transaction().unwrap();
        let budget = signing_quota::read(&tx, &f.tenant, &reservation).unwrap();
        assert_eq!(budget.state, "unknown");
        assert!(budget.held());
        assert_eq!(budget.dispatch_slots, 1);
        assert_eq!(outbox(&tx, &f.tenant, &job, NOW + 400).unwrap().1, bytes);
        assert_eq!(
            lifecycle_status(&tx, &f.tenant, &job, NOW + 400)
                .unwrap()
                .dispatch_state
                .as_deref(),
            Some("unknown")
        );
        tx.commit().unwrap();
        assert!(
            f.store
                .cancel_signing_job(&f.tenant, &job, NOW + 400)
                .is_err()
        );
        assert!(claim(&mut f, &job, "dispatch", 1, 60, NOW + 400).is_err());
        assert!(
            f.store
                .observe_signing_quota_time(&f.tenant, NOW + 1)
                .is_err()
        );
    }

    #[test]
    fn dispatch_retry_uses_identical_grant_and_fences_old_acknowledgement() {
        let (mut f, job, _) = ready();
        let first = claim(&mut f, &job, "dispatch", 0, 2, NOW).unwrap();
        let before = {
            let tx = f.store.connection.transaction().unwrap();
            outbox(&tx, &f.tenant, &job, NOW).unwrap()
        };
        assert!(claim(&mut f, &job, "dispatch", 1, 10, NOW + 2).is_err());
        let second = claim(&mut f, &job, "dispatch", 1, 10, NOW + 6).unwrap();
        let receipt = RecordedDelivery {
            job_id: job.clone(),
            grant_hash: before.0.clone(),
            result_bytes: bytes(
                &json!({"fixture":"verified target result","job_id":job,"grant_hash":before.0}),
            )
            .unwrap(),
        };
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(outbox(&tx, &f.tenant, &job, NOW + 6).unwrap(), before);
        assert!(deliver_in_tx(&tx, &f.tenant, &first, &receipt, NOW + 6).is_err());
        assert!(unknown_in_tx(&tx, &f.tenant, &first, NOW + 6).is_err());
        deliver_in_tx(&tx, &f.tenant, &second, &receipt, NOW + 6).unwrap();
        tx.commit().unwrap();
        let count = f.count("authority_signing_work_events");
        f.reopen();
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        deliver_in_tx(&tx, &f.tenant, &second, &receipt, NOW + 7).unwrap();
        let changed = RecordedDelivery {
            result_bytes: b"different result".to_vec(),
            ..receipt
        };
        assert!(deliver_in_tx(&tx, &f.tenant, &second, &changed, NOW + 7).is_err());
        tx.commit().unwrap();
        assert_eq!(f.count("authority_signing_work_events"), count);
        assert_eq!(f.count("authority_signing_deliveries"), 1);
    }

    #[test]
    fn audit_failure_rolls_back_claim_and_cancellation_with_quota() {
        let (mut f, job, reservation) = prepared();
        let count = f.count("authority_signing_work_events");
        f.store.connection.execute_batch("CREATE TRIGGER reject_signing_audit BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;").unwrap();
        assert!(claim(&mut f, &job, "signer", 0, 60, NOW).is_err());
        assert!(f.store.cancel_signing_job(&f.tenant, &job, NOW).is_err());
        assert_eq!(f.count("authority_signing_work_events"), count);
        let tx = f.store.connection.transaction().unwrap();
        let status = lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap();
        assert_eq!(status.state, "prepared");
        assert_eq!(status.attempts, 0);
        assert!(
            signing_quota::read(&tx, &f.tenant, &reservation)
                .unwrap()
                .held()
        );
    }

    #[test]
    fn mutable_head_tampering_and_immutable_event_edits_are_rejected() {
        let (mut f, job, _) = prepared();
        assert!(
            f.store
                .connection
                .execute("DELETE FROM authority_signing_work_events", [])
                .is_err()
        );
        assert!(
            f.store
                .connection
                .execute(
                    "UPDATE authority_signing_work_heads SET state='cancelled' WHERE job_id=?",
                    [&job],
                )
                .is_err()
        );
        f.store
            .connection
            .execute_batch("DROP TRIGGER authority_signing_work_heads_update")
            .unwrap();
        f.store
            .connection
            .execute(
                "UPDATE authority_signing_work_heads SET state='cancelled' WHERE job_id=?",
                [&job],
            )
            .unwrap();
        let tx = f.store.connection.transaction().unwrap();
        assert!(lifecycle_status(&tx, &f.tenant, &job, NOW).is_err());
    }
}
