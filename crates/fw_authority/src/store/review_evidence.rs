//! Durable semantic review, separate from compiler/gate attestation or dispatch.
use super::*;
use fw_planner::{PolicyReviewEvidence, VerifiedPolicyReview};

impl AuthorityStore {
    /// Trusted local importer only. Verify full before/after composition and
    /// atomically retain plan, requirements, review bytes and mandatory audit.
    /// This never attests referenced gates, grants authority or creates a signer job.
    pub fn register_reviewed_plan(
        &mut self,
        tenant: &AuthorityTenant,
        plan: &Value,
        requirements: &Value,
        evidence: &PolicyReviewEvidence,
        now: i64,
    ) -> Result<()> {
        time(now)?;
        let subject =
            subject::validate_subject(&tenant.org_id, &tenant.project_id, plan, requirements, now)?;
        let verified = evidence
            .verify(plan)
            .map_err(|_| invalid("policy review evidence"))?;
        if verified.plan_hash() != subject.plan_hash {
            return Err(AuthorityError::Binding);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        provision::register_plan_in_tx(&tx, tenant, &subject, now)?;
        if let Some(existing) = review_in_tx(&tx, tenant, &subject, now)? {
            if existing.canonical_bytes() != verified.canonical_bytes() {
                return Err(AuthorityError::Conflict);
            }
            tx.commit()?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO authority_plan_review_evidence VALUES(?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                subject.plan_id,
                hash(verified.plan_hash())?,
                hash(verified.evidence_hash())?,
                now,
                verified.canonical_bytes()
            ],
        )?;
        // Recheck the exact durable projection before making it visible.
        review_in_tx(&tx, tenant, &subject, now)?.ok_or(AuthorityError::Binding)?;
        bump_security(&tx, tenant)?;
        audit(
            &tx,
            tenant,
            "plan_review_evidence_registered",
            &subject.plan_id,
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Current plan-bound review from one read snapshot. None means no reviewed
    /// evidence was admitted; corrupt or mismatched records are errors, not None.
    /// A verified review remains insufficient for signing or native dispatch.
    pub fn policy_review_evidence(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        now: i64,
    ) -> Result<Option<VerifiedPolicyReview>> {
        identifier(plan_id)?;
        time(now)?;
        let tx = self.connection.transaction()?;
        let subject = records::plan(&tx, tenant, plan_id, now)?;
        let result = review_in_tx(&tx, tenant, &subject, now)?;
        tx.commit()?;
        Ok(result)
    }
}

struct StoredReview {
    plan_hash: Vec<u8>,
    evidence_hash: Vec<u8>,
    admitted_at: i64,
    canonical: Vec<u8>,
    registered_at: i64,
}

pub(super) fn review_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    subject: &subject::ValidatedSubject,
    now: i64,
) -> Result<Option<VerifiedPolicyReview>> {
    let row: Option<StoredReview> = tx.query_row(
        "SELECT e.plan_hash,e.evidence_hash,e.admitted_at,e.canonical_bytes,p.registered_at FROM authority_plan_review_evidence e JOIN authority_plans p ON p.org_id=e.org_id AND p.project_id=e.project_id AND p.plan_id=e.plan_id WHERE e.org_id=? AND e.project_id=? AND e.plan_id=?",
        params![tenant.org_id,tenant.project_id,subject.plan_id],
        |r| Ok(StoredReview { plan_hash:r.get(0)?,evidence_hash:r.get(1)?,admitted_at:r.get(2)?,canonical:r.get(3)?,registered_at:r.get(4)? })).optional()?;
    let Some(StoredReview {
        plan_hash,
        evidence_hash,
        admitted_at,
        canonical,
        registered_at,
    }) = row
    else {
        return Ok(None);
    };
    if now < admitted_at
        || admitted_at < registered_at
        || admitted_at < subject.created_at
        || admitted_at >= subject.valid_until
        || plan_hash != hash(&subject.plan_hash)?
        || evidence_hash != hash(&hash_bytes(&canonical))?
        || canonical.len() > fw_planner::MAX_POLICY_REVIEW_BYTES
    {
        return Err(invalid("stored policy review projection"));
    }
    let evidence: PolicyReviewEvidence = decode(&canonical)?;
    let plan: Value = decode(&subject.plan_bytes)?;
    let verified = evidence
        .verify(&plan)
        .map_err(|_| invalid("stored policy review evidence"))?;
    if verified.plan_hash() != subject.plan_hash
        || verified.canonical_bytes() != canonical
        || hash(verified.evidence_hash())? != evidence_hash
    {
        return Err(AuthorityError::Binding);
    }
    Ok(Some(verified))
}
