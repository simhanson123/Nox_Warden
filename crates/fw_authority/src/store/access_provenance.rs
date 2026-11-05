//! Retained original access-request inputs for cost derivation. This trusted
//! local importer does not authenticate a controller or attest referenced
//! approvals, workload bindings, native gates, signing or dispatch authority.
use super::*;
use crate::{CoreAccessProvenance, MAX_CORE_ACCESS_PROVENANCE_BYTES, VerifiedCoreAccessProvenance};

/// Bounded historical binding status, without request purpose, workflow,
/// envelope scope or the original evidence bytes. `current` describes only the
/// retained plan and input lifetime, never authorization to sign or dispatch.
#[derive(Clone, Debug, Serialize)]
pub struct CoreAccessProvenanceStatus {
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
    pub root_id: String,
    pub lease_id: String,
    pub lease_seconds: i64,
    pub destination_asset_ids: Vec<String>,
    pub admitted_at: String,
    pub valid_from: String,
    pub valid_until: String,
    pub checked_at: String,
    pub current: bool,
    pub gates: Vec<String>,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

impl AuthorityStore {
    /// Trusted local importer only. Bind a registered immutable plan to the
    /// complete original request, lease, envelope and delegation. Reuse across
    /// compatible plans preserves the same immutable original request record.
    /// Exact retries return historical status and add no audit or revision.
    pub fn register_core_access_provenance(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        provenance: &CoreAccessProvenance,
        now: i64,
    ) -> Result<CoreAccessProvenanceStatus> {
        identifier(plan_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = register_in_tx(&tx, tenant, plan_id, provenance, now)?;
        tx.commit()?;
        Ok(result)
    }

    /// Verify retained inputs even after expiry. Missing evidence on an existing
    /// plan returns None; malformed stored projections always return an error.
    pub fn read_core_access_provenance(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        now: i64,
    ) -> Result<Option<CoreAccessProvenanceStatus>> {
        identifier(plan_id)?;
        time(now)?;
        let tx = self.connection.transaction()?;
        let retained = records::retained_plan(&tx, tenant, plan_id)?;
        let result = retained_in_tx(&tx, tenant, &retained, now)?
            .map(|stored| status(tenant, &retained, &stored, now))
            .transpose()?;
        tx.commit()?;
        Ok(result)
    }
}

/// Shared by the atomic reviewed-core import; all writes remain in its transaction.
pub(super) fn register_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan_id: &str,
    provenance: &CoreAccessProvenance,
    now: i64,
) -> Result<CoreAccessProvenanceStatus> {
    security_revision(tx, tenant)?;
    let retained = records::retained_plan(tx, tenant, plan_id)?;
    let plan: Value = decode(&retained.subject.plan_bytes)?;
    let verified = provenance.verify(&plan)?;
    tenant_binding(tenant, &verified)?;
    if let Some(existing) = retained_in_tx(tx, tenant, &retained, now)? {
        if existing.verified.canonical_bytes() != verified.canonical_bytes() {
            return Err(AuthorityError::Conflict);
        }
        let result = status(tenant, &retained, &existing, now)?;
        return Ok(result);
    }
    // New imports need current inputs. Retained evidence stays readable
    // when its plan or envelope/delegation expires or its plan is retired.
    if retained.retired {
        return Err(AuthorityError::Binding);
    }
    if now < retained.registered_at
        || now < retained.subject.created_at
        || now >= retained.subject.valid_until
        || now < verified.valid_from()
        || now >= verified.valid_until()
    {
        return Err(AuthorityError::Time);
    }
    if let Some(existing) = request_in_tx(tx, tenant, verified.request_id(), &plan, now)? {
        if existing.canonical_bytes() != verified.canonical_bytes() {
            return Err(AuthorityError::Conflict);
        }
    } else {
        let alias: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_core_access_requests WHERE (org_id=? AND lease_id=?) OR (org_id=? AND project_id=? AND idempotency_key=?))",
        params![tenant.org_id, verified.lease_id(), tenant.org_id, tenant.project_id, verified.idempotency_key()],
        |r| r.get(0),
        )?;
        if alias {
            return Err(AuthorityError::Conflict);
        }
        tx.execute(
            "INSERT INTO authority_core_access_requests VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                verified.request_id(),
                verified.request_revision(),
                verified.lease_id(),
                verified.root_id(),
                verified.idempotency_key(),
                hash(verified.request_hash())?,
                hash(verified.hash())?,
                now,
                verified.canonical_bytes()
            ],
        )?;
    }
    tx.execute(
        "INSERT INTO authority_core_access_plan_bindings VALUES(?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            plan_id,
            hash(&retained.subject.plan_hash)?,
            verified.request_id(),
            hash(verified.hash())?,
            now
        ],
    )?;
    // Verify the exact committed projection before audit and visibility.
    let stored = retained_in_tx(tx, tenant, &retained, now)?.ok_or(AuthorityError::Binding)?;
    let result = status(tenant, &retained, &stored, now)?;
    bump_security(tx, tenant)?;
    audit(
        tx,
        tenant,
        "core_access_provenance_registered",
        plan_id,
        now,
    )?;
    Ok(result)
}

pub(super) struct StoredProvenance {
    pub(super) verified: VerifiedCoreAccessProvenance,
    pub(super) admitted_at: i64,
}

fn tenant_binding(tenant: &AuthorityTenant, verified: &VerifiedCoreAccessProvenance) -> Result<()> {
    if tenant.org_id != verified.org_id() || tenant.project_id != verified.project_id() {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}

fn request_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    request_id: &str,
    plan: &Value,
    now: i64,
) -> Result<Option<VerifiedCoreAccessProvenance>> {
    let row = tx.query_row(
        "SELECT request_revision,CASE WHEN length(lease_id)=36 THEN lease_id ELSE NULL END,CASE WHEN length(root_id)=36 THEN root_id ELSE NULL END,CASE WHEN length(idempotency_key)=36 THEN idempotency_key ELSE NULL END,CASE WHEN length(request_hash)=32 THEN request_hash ELSE NULL END,CASE WHEN length(provenance_hash)=32 THEN provenance_hash ELSE NULL END,admitted_at,CASE WHEN length(canonical_bytes) BETWEEN 1 AND 131072 THEN canonical_bytes ELSE NULL END FROM authority_core_access_requests WHERE org_id=? AND project_id=? AND request_id=?",
        params![tenant.org_id, tenant.project_id, request_id],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, Vec<u8>>(4)?, r.get::<_, Vec<u8>>(5)?, r.get::<_, i64>(6)?, r.get::<_, Option<Vec<u8>>>(7)?)),
    ).optional()?;
    let Some((
        revision,
        lease_id,
        root_id,
        idempotency,
        request_hash,
        provenance_hash,
        admitted_at,
        canonical,
    )) = row
    else {
        return Ok(None);
    };
    let canonical = canonical.ok_or(invalid("stored core access provenance size"))?;
    if canonical.len() > MAX_CORE_ACCESS_PROVENANCE_BYTES
        || hash(&hash_bytes(&canonical))? != provenance_hash
    {
        return Err(invalid("stored core access provenance hash"));
    }
    time(admitted_at)?;
    let evidence: CoreAccessProvenance = decode(&canonical)?;
    let verified = evidence.verify(plan)?;
    tenant_binding(tenant, &verified)?;
    if request_id != verified.request_id()
        || revision != i64::from(verified.request_revision())
        || lease_id != verified.lease_id()
        || root_id != verified.root_id()
        || idempotency != verified.idempotency_key()
        || request_hash != hash(verified.request_hash())?
        || provenance_hash != hash(verified.hash())?
        || canonical != verified.canonical_bytes()
        || admitted_at < verified.valid_from()
        || admitted_at >= verified.valid_until()
        || now < admitted_at
    {
        return Err(invalid("stored core access request projection"));
    }
    Ok(Some(verified))
}

pub(super) fn retained_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    retained: &records::RetainedPlan,
    now: i64,
) -> Result<Option<StoredProvenance>> {
    let subject = &retained.subject;
    let row = tx.query_row(
        "SELECT CASE WHEN length(plan_hash)=32 THEN plan_hash ELSE NULL END,CASE WHEN length(request_id)=36 THEN request_id ELSE NULL END,CASE WHEN length(provenance_hash)=32 THEN provenance_hash ELSE NULL END,admitted_at FROM authority_core_access_plan_bindings WHERE org_id=? AND project_id=? AND plan_id=?",
        params![tenant.org_id, tenant.project_id, subject.plan_id],
        |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, i64>(3)?)),
    ).optional()?;
    let Some((plan_hash, request_id, provenance_hash, admitted_at)) = row else {
        return Ok(None);
    };
    time(admitted_at)?;
    if plan_hash != hash(&subject.plan_hash)?
        || admitted_at < retained.registered_at
        || admitted_at < subject.created_at
        || admitted_at >= subject.valid_until
        || now < admitted_at
    {
        return Err(invalid("stored core access plan binding"));
    }
    let plan: Value = decode(&subject.plan_bytes)?;
    // Using binding admission as the observation time also prevents a damaged
    // binding from predating the retained original request admission.
    let verified = request_in_tx(tx, tenant, &request_id, &plan, admitted_at)?
        .ok_or(AuthorityError::Binding)?;
    if provenance_hash != hash(verified.hash())?
        || admitted_at < verified.valid_from()
        || admitted_at >= verified.valid_until()
    {
        return Err(AuthorityError::Binding);
    }
    Ok(Some(StoredProvenance {
        verified,
        admitted_at,
    }))
}

/// Current immutable cost provenance. The caller still must bind the delegated
/// root to the currently configured quota root and independently check every
/// approval, signing and native gate before reserving or issuing anything.
pub(super) fn provenance_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    subject: &subject::ValidatedSubject,
    now: i64,
) -> Result<Option<VerifiedCoreAccessProvenance>> {
    time(now)?;
    let retained = records::retained_plan(tx, tenant, &subject.plan_id)?;
    if retained.subject.plan_hash != subject.plan_hash || retained.retired {
        return Err(AuthorityError::Binding);
    }
    if now < retained.registered_at || now < subject.created_at || now >= subject.valid_until {
        return Err(AuthorityError::Time);
    }
    let stored = retained_in_tx(tx, tenant, &retained, now)?;
    if let Some(stored) = &stored
        && (now < stored.verified.valid_from() || now >= stored.verified.valid_until())
    {
        return Err(AuthorityError::Time);
    }
    Ok(stored.map(|stored| stored.verified))
}

fn status(
    tenant: &AuthorityTenant,
    retained: &records::RetainedPlan,
    stored: &StoredProvenance,
    now: i64,
) -> Result<CoreAccessProvenanceStatus> {
    let verified = &stored.verified;
    let mut gates = vec!["CORE_SIGNING_PROFILE_UNAVAILABLE".into()];
    if retained.retired {
        gates.push("PLAN_RETIRED".into());
    }
    if now >= retained.subject.valid_until {
        gates.push("PLAN_EXPIRED".into());
    }
    if now >= verified.valid_until() {
        gates.push("CORE_ACCESS_PROVENANCE_EXPIRED".into());
    }
    Ok(CoreAccessProvenanceStatus {
        schema_version: "fw.core-access-provenance-status/v1".into(),
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        target_id: verified.target_id().into(),
        plan_id: retained.subject.plan_id.clone(),
        plan_hash: retained.subject.plan_hash.clone(),
        request_id: verified.request_id().into(),
        request_revision: verified.request_revision(),
        request_hash: verified.request_hash().into(),
        provenance_hash: verified.hash().into(),
        root_id: verified.root_id().into(),
        lease_id: verified.lease_id().into(),
        lease_seconds: verified.lease_seconds(),
        destination_asset_ids: verified.destination_asset_ids().to_vec(),
        admitted_at: at(stored.admitted_at)?,
        valid_from: at(verified.valid_from())?,
        valid_until: at(verified.valid_until())?,
        checked_at: at(now)?,
        current: gates.len() == 1,
        gates,
        signing_allowed: false,
        dispatch_allowed: false,
    })
}
