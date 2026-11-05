//! Atomic reviewed-core admission and retained fixed absolute lease windows.
use super::*;
use crate::{CoreAccessLeaseWindow, CoreAccessProvenance, VerifiedCoreAccessLeaseWindow};
use fw_planner::{PolicyReviewEvidence, VerifiedPolicyReview};

#[derive(Clone, Debug, Serialize)]
pub struct CoreAccessLeaseWindowStatus {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub request_id: String,
    pub request_revision: u32,
    pub request_hash: String,
    pub provenance_hash: String,
    pub lease_id: String,
    pub lease_seconds: i64,
    pub window_hash: String,
    pub not_before: String,
    pub expires_at: String,
    pub admitted_at: String,
    pub checked_at: String,
    pub current: bool,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

impl AuthorityStore {
    /// Trusted-local development evidence import. The plan, original inputs,
    /// absolute window, exact review and mandatory audits commit together.
    /// No workload/delegation signature, production authority or grant is created.
    #[allow(clippy::too_many_arguments)]
    pub fn register_reviewed_core_access_plan(
        &mut self,
        tenant: &AuthorityTenant,
        plan: &Value,
        requirements: &Value,
        review: &PolicyReviewEvidence,
        provenance: &CoreAccessProvenance,
        window: &CoreAccessLeaseWindow,
        now: i64,
    ) -> Result<CoreAccessLeaseWindowStatus> {
        time(now)?;
        let verified_review = review
            .verify(plan)
            .map_err(|_| invalid("core access review"))?;
        let original = provenance.verify(plan)?;
        let verified_window = window.verify_binding(plan, &original, &verified_review)?;
        if original.org_id() != tenant.org_id || original.project_id() != tenant.project_id {
            return Err(AuthorityError::Binding);
        }
        identifier(crate::string(plan, "plan_id")?)?;
        // Persist conservative time independently of admission/audit rollback.
        // This creates no quota configuration, reservation or target generation.
        self.observe_core_window_time(tenant, original.target_id(), original.root_id(), now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Exact historical retry never renews a plan, window, proof or audit.
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_plans WHERE org_id=? AND project_id=? AND plan_id=?)",params![tenant.org_id,tenant.project_id,crate::string(plan,"plan_id")?],|r|r.get(0))?;
        if exists {
            let retained = records::retained_plan(&tx, tenant, crate::string(plan, "plan_id")?)?;
            let supplied = subject::validate_subject(
                &tenant.org_id,
                &tenant.project_id,
                plan,
                requirements,
                retained.registered_at,
            )?;
            if retained.subject.plan_bytes != supplied.plan_bytes
                || retained.subject.requirements_bytes != supplied.requirements_bytes
            {
                return Err(AuthorityError::Conflict);
            }
            let historical_at = historical_verification_time(&tx, tenant, now)?;
            if let Some(existing_review) =
                review_evidence::review_in_tx(&tx, tenant, &retained.subject, historical_at)?
            {
                if existing_review.canonical_bytes() != verified_review.canonical_bytes() {
                    return Err(AuthorityError::Conflict);
                }
                let stored =
                    retained_window_in_tx(&tx, tenant, &retained, &existing_review, historical_at)?
                        .ok_or(AuthorityError::Binding)?;
                if stored.verified.canonical_bytes() != verified_window.canonical_bytes() {
                    return Err(AuthorityError::Conflict);
                }
                let result = status(&tx, tenant, &retained, &stored, now)?;
                tx.commit()?;
                return Ok(result);
            }
        }
        let subject =
            subject::validate_subject(&tenant.org_id, &tenant.project_id, plan, requirements, now)?;
        if now < clock_floor(&tx, tenant, original.target_id(), original.root_id())? {
            return Err(AuthorityError::Time);
        }
        provision::register_plan_in_tx(&tx, tenant, &subject, now)?;
        access_provenance::register_in_tx(&tx, tenant, &subject.plan_id, provenance, now)?;
        if now < original.valid_from()
            || now >= original.valid_until()
            || now >= verified_window.expires_at()
        {
            return Err(AuthorityError::Time);
        }
        let existing: Option<Vec<u8>> = tx.query_row("SELECT CASE WHEN length(canonical_bytes)<=4096 THEN canonical_bytes END FROM authority_core_access_lease_windows WHERE org_id=? AND project_id=? AND request_id=?", params![tenant.org_id,tenant.project_id,original.request_id()], |r|r.get(0)).optional()?;
        if let Some(existing) = existing {
            if existing != verified_window.canonical_bytes() {
                return Err(AuthorityError::Conflict);
            }
        } else {
            tx.execute(
                "INSERT INTO authority_core_access_lease_windows VALUES(?,?,?,?,?,?,?,?,?,?)",
                params![
                    tenant.org_id,
                    tenant.project_id,
                    original.request_id(),
                    original.lease_id(),
                    hash(original.hash())?,
                    hash(verified_window.hash())?,
                    verified_window.not_before(),
                    verified_window.expires_at(),
                    now,
                    verified_window.canonical_bytes()
                ],
            )?;
            audit(
                &tx,
                tenant,
                "core_access_lease_window_registered",
                original.request_id(),
                now,
            )?;
        }
        tx.execute(
            "INSERT INTO authority_plan_review_evidence VALUES(?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                subject.plan_id,
                hash(verified_review.plan_hash())?,
                hash(verified_review.evidence_hash())?,
                now,
                verified_review.canonical_bytes()
            ],
        )?;
        let retained = records::retained_plan(&tx, tenant, &subject.plan_id)?;
        let checked = review_evidence::review_in_tx(&tx, tenant, &subject, now)?
            .ok_or(AuthorityError::Binding)?;
        let stored = retained_window_in_tx(&tx, tenant, &retained, &checked, now)?
            .ok_or(AuthorityError::Binding)?;
        let result = status(&tx, tenant, &retained, &stored, now)?;
        bump_security(&tx, tenant)?;
        audit(
            &tx,
            tenant,
            "plan_review_evidence_registered",
            &subject.plan_id,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    /// Bounded historical evidence. Expiry/retirement changes currentness only.
    pub fn read_core_access_lease_window(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        now: i64,
    ) -> Result<Option<CoreAccessLeaseWindowStatus>> {
        identifier(plan_id)?;
        time(now)?;
        let selected = {
            let tx = self.connection.transaction()?;
            let retained = records::retained_plan(&tx, tenant, plan_id)?;
            let historical_at = historical_verification_time(&tx, tenant, now)?;
            let selected = if let Some(review) =
                review_evidence::review_in_tx(&tx, tenant, &retained.subject, historical_at)?
            {
                retained_window_in_tx(&tx, tenant, &retained, &review, historical_at)?
                    .map(|window| (window.window.target_id, window.root_id))
            } else {
                None
            };
            tx.commit()?;
            selected
        };
        if let Some((target, root)) = selected {
            self.observe_core_window_time(tenant, &target, &root, now)?;
        }
        let tx = self.connection.transaction()?;
        let retained = records::retained_plan(&tx, tenant, plan_id)?;
        let historical_at = historical_verification_time(&tx, tenant, now)?;
        let result = if let Some(review) =
            review_evidence::review_in_tx(&tx, tenant, &retained.subject, historical_at)?
        {
            retained_window_in_tx(&tx, tenant, &retained, &review, historical_at)?
                .map(|stored| status(&tx, tenant, &retained, &stored, now))
                .transpose()?
        } else {
            None
        };
        tx.commit()?;
        Ok(result)
    }

    fn observe_core_window_time(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        root: &str,
        now: i64,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        security_revision(&tx, tenant)?;
        let floor = clock_floor(&tx, tenant, target, root)?.max(now);
        tx.execute("UPDATE authority_signing_quota_clocks SET observed_at=?3 WHERE org_id=?1 AND bucket_kind='project' AND bucket_id=?2 AND observed_at<?3",params![tenant.org_id,tenant.project_id,floor])?;
        tx.execute("INSERT INTO authority_signing_quota_clocks SELECT ?1,'project',?2,?3 WHERE NOT EXISTS(SELECT 1 FROM authority_signing_quota_clocks WHERE org_id=?1 AND bucket_kind='project' AND bucket_id=?2)",params![tenant.org_id,tenant.project_id,floor])?;
        tx.commit()?;
        Ok(())
    }
}

// A historical read can verify retained bytes after wall time rolls behind their
// admission. This time is never used for checked_at or current eligibility.
fn historical_verification_time(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    now: i64,
) -> Result<i64> {
    let observed:Option<i64>=tx.query_row("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind='project' AND bucket_id=?",params![tenant.org_id,tenant.project_id],|r|r.get(0)).optional()?;
    if let Some(observed) = observed {
        time(observed)?;
        Ok(observed.max(now))
    } else {
        Ok(now)
    }
}

fn clock_floor(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    root: &str,
) -> Result<i64> {
    let mut query=tx.prepare("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=?1 AND ((bucket_kind='project' AND bucket_id=?2) OR (bucket_kind='root' AND bucket_id=?3)) UNION ALL SELECT observed_at FROM authority_target_clocks WHERE org_id=?1 AND project_id=?2 AND target_id=?4")?;
    let mut rows = query.query(params![tenant.org_id, tenant.project_id, root, target])?;
    let mut floor = 0;
    while let Some(row) = rows.next()? {
        let observed: i64 = row.get(0)?;
        time(observed)?;
        floor = floor.max(observed);
    }
    Ok(floor)
}

struct StoredWindow {
    window: CoreAccessLeaseWindow,
    verified: VerifiedCoreAccessLeaseWindow,
    admitted_at: i64,
    provenance_valid_from: i64,
    provenance_valid_until: i64,
    root_id: String,
}

fn retained_window_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    retained: &records::RetainedPlan,
    review: &VerifiedPolicyReview,
    now: i64,
) -> Result<Option<StoredWindow>> {
    let Some(original) = access_provenance::retained_in_tx(tx, tenant, retained, now)? else {
        return Ok(None);
    };
    type Row = (String, Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>);
    let row: Option<Row> = tx.query_row("SELECT CASE WHEN length(lease_id)=36 THEN lease_id END,CASE WHEN length(provenance_hash)=32 THEN provenance_hash END,CASE WHEN length(window_hash)=32 THEN window_hash END,not_before,expires_at,admitted_at,CASE WHEN length(canonical_bytes) BETWEEN 1 AND 4096 THEN canonical_bytes END FROM authority_core_access_lease_windows WHERE org_id=? AND project_id=? AND request_id=?",params![tenant.org_id,tenant.project_id,original.verified.request_id()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
    let Some((lease, provenance_hash, window_hash, start, end, admitted_at, canonical)) = row
    else {
        return Ok(None);
    };
    let window: CoreAccessLeaseWindow = decode(&canonical)?;
    let plan: Value = decode(&retained.subject.plan_bytes)?;
    let verified = window.verify_binding(&plan, &original.verified, review)?;
    let original_admitted:i64=tx.query_row("SELECT admitted_at FROM authority_core_access_requests WHERE org_id=? AND project_id=? AND request_id=?",params![tenant.org_id,tenant.project_id,original.verified.request_id()],|r|r.get(0))?;
    let review_admitted:i64=tx.query_row("SELECT admitted_at FROM authority_plan_review_evidence WHERE org_id=? AND project_id=? AND plan_id=?",params![tenant.org_id,tenant.project_id,retained.subject.plan_id],|r|r.get(0))?;
    if canonical != verified.canonical_bytes()
        || hash(verified.hash())? != window_hash
        || hash(original.verified.hash())? != provenance_hash
        || lease != original.verified.lease_id()
        || start != verified.not_before()
        || end != verified.expires_at()
        || admitted_at < original_admitted
        || review_admitted < admitted_at
        || review_admitted < original.admitted_at
        || admitted_at < original.verified.valid_from()
        || admitted_at >= original.verified.valid_until()
        || admitted_at >= end
        || now < admitted_at
    {
        return Err(invalid("retained core access lease window"));
    }
    Ok(Some(StoredWindow {
        window,
        verified,
        admitted_at,
        provenance_valid_from: original.verified.valid_from(),
        provenance_valid_until: original.verified.valid_until(),
        root_id: original.verified.root_id().into(),
    }))
}

/// All core semantic/native readers independently recheck retained originals and
/// the one fixed window. Historical verification uses admission time separately
/// from fresh eligibility; no expired evidence gains a new lifetime.
pub(super) fn validate_review_binding(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    subject: &subject::ValidatedSubject,
    review: &VerifiedPolicyReview,
    now: i64,
) -> Result<()> {
    if review.core_binding().is_none() {
        return Ok(());
    }
    let retained = records::retained_plan(tx, tenant, &subject.plan_id)?;
    retained_window_in_tx(tx, tenant, &retained, review, now)?.ok_or(AuthorityError::Binding)?;
    Ok(())
}

fn status(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    retained: &records::RetainedPlan,
    stored: &StoredWindow,
    now: i64,
) -> Result<CoreAccessLeaseWindowStatus> {
    let w = &stored.window;
    Ok(CoreAccessLeaseWindowStatus {
        schema_version: "fw.core-access-lease-window-status/v1".into(),
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        target_id: w.target_id.clone(),
        plan_id: retained.subject.plan_id.clone(),
        plan_hash: retained.subject.plan_hash.clone(),
        request_id: w.request_id.clone(),
        request_revision: w.request_revision,
        request_hash: w.request_hash.clone(),
        provenance_hash: w.provenance_hash.clone(),
        lease_id: w.lease_id.clone(),
        lease_seconds: stored.verified.lease_seconds(),
        window_hash: stored.verified.hash().into(),
        not_before: w.not_before.clone(),
        expires_at: w.expires_at.clone(),
        admitted_at: at(stored.admitted_at)?,
        checked_at: at(now)?,
        current: !retained.retired
            && now < retained.subject.valid_until
            && now >= stored.verified.not_before()
            && now < stored.verified.expires_at()
            && now >= stored.provenance_valid_from
            && now < stored.provenance_valid_until
            && now >= clock_floor(tx, tenant, &w.target_id, &stored.root_id)?,
        signing_allowed: false,
        dispatch_allowed: false,
    })
}

/// Replay the complete retained core graph on open, maintenance and externally
/// changed live snapshots. Legacy provenance has no review/window requirement.
pub(super) fn validate_retained(tx: &Transaction<'_>) -> Result<()> {
    let orphan:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_core_access_lease_windows w WHERE NOT EXISTS(SELECT 1 FROM authority_core_access_plan_bindings b JOIN authority_plan_review_evidence e ON e.org_id=b.org_id AND e.project_id=b.project_id AND e.plan_id=b.plan_id JOIN authority_plans p ON p.org_id=e.org_id AND p.project_id=e.project_id AND p.plan_id=e.plan_id WHERE p.plan_kind='add_access_lease' AND b.org_id=w.org_id AND b.project_id=w.project_id AND b.request_id=w.request_id))",[],|r|r.get(0))?;
    if orphan {
        return Err(invalid("orphan core access lease window"));
    }
    let mut statement=tx.prepare("SELECT e.org_id,e.project_id,e.plan_id,e.admitted_at FROM authority_plan_review_evidence e JOIN authority_plans p ON p.org_id=e.org_id AND p.project_id=e.project_id AND p.plan_id=e.plan_id WHERE p.plan_kind='add_access_lease'")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let plan_id: String = row.get(2)?;
        let admitted: i64 = row.get(3)?;
        let retained = records::retained_plan(tx, &tenant, &plan_id)?;
        let review = review_evidence::review_in_tx(tx, &tenant, &retained.subject, admitted)?
            .ok_or(AuthorityError::Binding)?;
        let clock:Option<i64>=tx.query_row("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind='project' AND bucket_id=?",params![tenant.org_id,tenant.project_id],|r|r.get(0)).optional()?;
        if clock.is_none_or(|floor| floor < admitted || floor > MAX_TIME) {
            return Err(invalid("retained core access clock"));
        }
        if review.core_binding().is_none() {
            return Err(AuthorityError::Binding);
        }
    }
    Ok(())
}
