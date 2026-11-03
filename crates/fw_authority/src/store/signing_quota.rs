//! Atomic authority-owned signing budgets. Pending reservations are not issued
//! usage, and neither expiry nor UNKNOWN refunds retained slots or costs.
use super::*;
use serde::Deserialize;
use std::collections::BTreeSet;

const WINDOW: i64 = 86_400;
const MAX_ACCOUNTED_ROWS: usize = 10_000;
const MAX_ACCOUNTED_DESTINATIONS: usize = 200_000;

#[cfg(test)]
#[path = "core_access_cost_tests.rs"]
mod core_access_cost_tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningQuotaLimits {
    pub active_leases: i64,
    pub new_leases_per_day: i64,
    pub unique_destinations_per_day: i64,
    pub cumulative_seconds_per_day: i64,
    pub concurrent_deployments: i64,
}
impl SigningQuotaLimits {
    fn validate(&self) -> Result<()> {
        if !(1..=10_000).contains(&self.active_leases)
            || !(1..=100_000).contains(&self.new_leases_per_day)
            || !(1..=100_000).contains(&self.unique_destinations_per_day)
            || !(60..=i64::from(i32::MAX)).contains(&self.cumulative_seconds_per_day)
            || !(1..=10_000).contains(&self.concurrent_deployments)
        {
            return Err(invalid("signing quota limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRootQuotaPin {
    pub root_id: String,
    pub limits: SigningQuotaLimits,
    pub not_before: i64,
    pub not_after: i64,
}
/// Explicit local-administrator project configuration. A missing root selects
/// general-policy accounting and never supplies core-access authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningProjectQuotaPin {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_id: Option<String>,
    pub limits: SigningQuotaLimits,
    pub not_before: i64,
    pub not_after: i64,
}
impl From<SigningRootQuotaPin> for SigningProjectQuotaPin {
    fn from(pin: SigningRootQuotaPin) -> Self {
        Self {
            root_id: Some(pin.root_id),
            limits: pin.limits,
            not_before: pin.not_before,
            not_after: pin.not_after,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningQuotaUsage {
    pub active_leases: i64,
    pub new_leases_per_day: i64,
    pub unique_destinations_per_day: i64,
    pub cumulative_seconds_per_day: i64,
    pub concurrent_deployments: i64,
}
impl SigningQuotaUsage {
    fn within(&self, limits: &SigningQuotaLimits) -> Result<()> {
        if self.active_leases > limits.active_leases
            || self.new_leases_per_day > limits.new_leases_per_day
            || self.unique_destinations_per_day > limits.unique_destinations_per_day
            || self.cumulative_seconds_per_day > limits.cumulative_seconds_per_day
            || self.concurrent_deployments > limits.concurrent_deployments
        {
            return Err(AuthorityError::Quota);
        }
        Ok(())
    }
}

/// No public prepare API accepts a cost. Production costs are derived from
/// retained immutable inputs; the fields remain private to this module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningQuotaCost {
    plan_id: String,
    plan_hash: String,
    lease_id: Option<String>,
    lease_seconds: i64,
    destination_asset_ids: Vec<String>,
}
impl SigningQuotaCost {
    fn validate(&self) -> Result<()> {
        identifier(&self.plan_id)?;
        hash(&self.plan_hash)?;
        if let Some(id) = &self.lease_id {
            identifier(id)?;
            if !(60..=WINDOW).contains(&self.lease_seconds)
                || self.destination_asset_ids.is_empty()
                || self.destination_asset_ids.len() > 4096
            {
                return Err(invalid("signing lease quota cost"));
            }
        } else if self.lease_seconds != 0 || !self.destination_asset_ids.is_empty() {
            return Err(invalid("signing policy change quota cost"));
        }
        let mut previous: Option<&str> = None;
        for id in &self.destination_asset_ids {
            identifier(id)?;
            if previous.is_some_and(|p| p >= id.as_str()) {
                return Err(invalid("signing destination membership"));
            }
            previous = Some(id);
        }
        Ok(())
    }
    fn active(&self) -> i64 {
        i64::from(self.lease_id.is_some())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_version: Option<String>,
    org_id: String,
    bucket_kind: String,
    bucket_id: String,
    revision: String,
    pinned_at: String,
    pin: SigningProjectQuotaPin,
}
struct Pin {
    record: PinRecord,
    revision: u64,
    digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: String,
    org_id: String,
    project_id: String,
    reservation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_id: Option<String>,
    plan_id: String,
    plan_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_revision: Option<String>,
    project_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_pin_hash: Option<String>,
    project_pin_hash: String,
    reserved_at: String,
    reserved_until: String,
    window_start: String,
    window_end: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_projected: Option<SigningQuotaUsage>,
    project_projected: SigningQuotaUsage,
}

#[derive(Clone, Debug, Serialize)]
pub struct SigningBudgetReservation {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub reservation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_id: Option<String>,
    pub plan_id: String,
    pub plan_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_revision: Option<String>,
    pub project_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_pin_hash: Option<String>,
    pub project_pin_hash: String,
    pub reserved_at: String,
    pub reserved_until: String,
    pub window_start: String,
    pub window_end: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_projected: Option<SigningQuotaUsage>,
    pub project_projected: SigningQuotaUsage,
    pub cost: SigningQuotaCost,
    pub state: String,
    pub issued_at: Option<String>,
    pub active_slots: i64,
    /// Historical stored projection. An unsigned delivery may have recorded
    /// zero here; capacity remains held through `effective_dispatch_slots`.
    pub dispatch_slots: i64,
}
impl SigningBudgetReservation {
    /// No authenticated completion-receipt adapter exists in this build. Issued
    /// work therefore keeps dispatch capacity even after a delivery row exists.
    pub fn effective_dispatch_slots(&self) -> i64 {
        if self.issued_at.is_some() {
            1
        } else {
            self.dispatch_slots
        }
    }
    pub fn held(&self) -> bool {
        self.active_slots != 0 || self.effective_dispatch_slots() != 0
    }
}

fn revision(value: &str) -> Result<u64> {
    let n = value
        .parse::<u64>()
        .map_err(|_| invalid("quota pin revision"))?;
    if n == 0 || n > i32::MAX as u64 || n.to_string() != value {
        return Err(invalid("quota pin revision"));
    }
    Ok(n)
}
fn validate_pin(pin: &SigningProjectQuotaPin, now: i64) -> Result<()> {
    if let Some(root) = &pin.root_id {
        identifier(root)?;
    }
    pin.limits.validate()?;
    interval(pin.not_before, pin.not_after, now)?;
    if now < pin.not_before {
        return Err(AuthorityError::Time);
    }
    Ok(())
}
fn pin_at(tx: &Transaction<'_>, org: &str, kind: &str, id: &str, version: u64) -> Result<Pin> {
    let row: (Option<String>, i64, Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT root_id,pinned_at,pin_hash,CASE WHEN length(canonical_bytes)<=32768 THEN canonical_bytes END FROM authority_signing_quota_pins WHERE org_id=? AND bucket_kind=? AND bucket_id=? AND revision=?",
        params![org,kind,id,version], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    let record: PinRecord = decode(&row.3)?;
    let digest = hash_bytes(&row.3);
    if record.org_id != org
        || record.bucket_kind != kind
        || record.bucket_id != id
        || revision(&record.revision)? != version
        || record.pin.root_id != row.0
        || record.pinned_at != at(row.1)?
        || hash(&digest)? != row.2
        || (kind == "root" && record.pin.root_id.as_deref() != Some(id))
        || match record.schema_version.as_deref() {
            None => record.pin.root_id.is_none(),
            Some("fw.signing-project-quota-pin/v2") => {
                kind != "project" || record.pin.root_id.is_some()
            }
            Some(_) => true,
        }
    {
        return Err(invalid("signing quota pin projection"));
    }
    validate_pin(&record.pin, row.1)?;
    if kind == "project" && version > 1 {
        let anchor = pin_at(tx, org, kind, id, 1)?;
        if record.pin.root_id.is_some() && record.pin.root_id != anchor.record.pin.root_id {
            return Err(invalid("signing project quota root anchor"));
        }
    }
    Ok(Pin {
        record,
        revision: version,
        digest,
    })
}
fn pin_head(tx: &Transaction<'_>, org: &str, kind: &str, id: &str) -> Result<Option<Pin>> {
    let head: Option<u64> = tx.query_row("SELECT revision FROM authority_signing_quota_heads WHERE org_id=? AND bucket_kind=? AND bucket_id=?",params![org,kind,id],|r|r.get(0)).optional()?;
    let latest: Option<u64> = tx.query_row("SELECT MAX(revision) FROM authority_signing_quota_pins WHERE org_id=? AND bucket_kind=? AND bucket_id=?",params![org,kind,id],|r|r.get(0))?;
    if head != latest {
        return Err(invalid("signing quota pin head"));
    }
    head.map(|v| pin_at(tx, org, kind, id, v)).transpose()
}
fn revoked(tx: &Transaction<'_>, pin: &Pin) -> Result<bool> {
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_quota_revocations WHERE org_id=? AND bucket_kind=? AND bucket_id=? AND revision=?)",params![pin.record.org_id,pin.record.bucket_kind,pin.record.bucket_id,pin.revision],|r|r.get(0))?)
}
fn current(tx: &Transaction<'_>, pin: &Pin, now: i64) -> Result<bool> {
    if now < crate::timestamp(&pin.record.pinned_at)? {
        return Err(AuthorityError::Time);
    }
    Ok(now >= pin.record.pin.not_before && now < pin.record.pin.not_after && !revoked(tx, pin)?)
}
fn clock(tx: &Transaction<'_>, org: &str, kind: &str, id: &str, now: i64) -> Result<()> {
    time(now)?;
    let value: Option<i64> = tx.query_row("SELECT observed_at FROM authority_signing_quota_clocks WHERE org_id=? AND bucket_kind=? AND bucket_id=?",params![org,kind,id],|r|r.get(0)).optional()?;
    match value {
        Some(previous) if (0..=MAX_TIME).contains(&previous) && now >= previous => Ok(()),
        Some(_) => Err(AuthorityError::Time),
        None => Err(invalid("signing quota clock")),
    }
}
fn advance(tx: &Transaction<'_>, org: &str, kind: &str, id: &str, now: i64) -> Result<()> {
    clock(tx, org, kind, id, now)?;
    tx.execute("UPDATE authority_signing_quota_clocks SET observed_at=? WHERE org_id=? AND bucket_kind=? AND bucket_id=?",params![now,org,kind,id])?;
    Ok(())
}
fn configuration(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    now: i64,
) -> Result<Option<(Option<Pin>, Pin)>> {
    time(now)?;
    let Some(project) = pin_head(tx, &tenant.org_id, "project", &tenant.project_id)? else {
        return Ok(None);
    };
    clock(tx, &tenant.org_id, "project", &tenant.project_id, now)?;
    if !current(tx, &project, now)? {
        return Ok(None);
    }
    let root = if let Some(root_id) = &project.record.pin.root_id {
        let Some(root) = pin_head(tx, &tenant.org_id, "root", root_id)? else {
            return Ok(None);
        };
        clock(tx, &tenant.org_id, "root", root_id, now)?;
        if !current(tx, &root, now)? {
            return Ok(None);
        }
        Some(root)
    } else {
        None
    };
    Ok(Some((root, project)))
}
#[cfg(test)]
pub(super) fn configuration_available(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    now: i64,
) -> Result<bool> {
    Ok(configuration(tx, tenant, now)?.is_some())
}

/// Independent pins may tighten the retained delegation, but cannot attach its
/// cost to another root or silently enlarge its original budget ceilings.
pub(super) fn core_configuration_available(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    provenance: &crate::VerifiedCoreAccessProvenance,
    now: i64,
) -> Result<bool> {
    let Some((Some(root), project)) = configuration(tx, tenant, now)? else {
        return Ok(false);
    };
    let original = provenance.delegation();
    let limits = &root.record.pin.limits;
    Ok(
        root.record.pin.root_id.as_deref() == Some(provenance.root_id())
            && project.record.pin.root_id.as_deref() == Some(provenance.root_id())
            && limits.active_leases as u64 <= original.max_active_leases
            && limits.new_leases_per_day as u64 <= original.max_new_leases_per_day
            && limits.unique_destinations_per_day as u64
                <= original.max_unique_destinations_per_day
            && limits.cumulative_seconds_per_day as u64
                <= original.max_cumulative_lease_seconds_per_day
            && limits.concurrent_deployments as u64 <= original.max_concurrent_deployments,
    )
}

pub(super) fn quota_configuration_summary(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    now: i64,
) -> Result<Option<(Option<String>, i64)>> {
    Ok(configuration(tx, tenant, now)?.map(|(root, project)| {
        (
            project.record.pin.root_id,
            root.map_or(project.record.pin.not_after, |root| {
                root.record.pin.not_after.min(project.record.pin.not_after)
            }),
        )
    }))
}

impl AuthorityStore {
    fn observe_quota_bucket(
        &mut self,
        tenant: &AuthorityTenant,
        kind: &str,
        id: &str,
        now: i64,
    ) -> Result<()> {
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if pin_head(&tx, &tenant.org_id, kind, id)?.is_some() {
            advance(&tx, &tenant.org_id, kind, id, now)?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Persist root AND project observations before a possibly refused signing
    /// operation. Missing configuration grants nothing and creates no clock.
    pub fn observe_signing_quota_time(&mut self, tenant: &AuthorityTenant, now: i64) -> Result<()> {
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(project) = pin_head(&tx, &tenant.org_id, "project", &tenant.project_id)? {
            advance(&tx, &tenant.org_id, "project", &tenant.project_id, now)?;
            if let Some(root) = project.record.pin.root_id {
                advance(&tx, &tenant.org_id, "root", &root, now)?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    /// Observe the retained obligation's own scope after project cutover.
    /// This commits before the requested work can be refused or rolled back.
    pub(super) fn observe_signing_job_quota_time(
        &mut self,
        tenant: &AuthorityTenant,
        job: &str,
        now: i64,
    ) -> Result<()> {
        identifier(job)?;
        self.observe_quota_bucket(tenant, "project", &tenant.project_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let root:Option<Option<String>>=tx.query_row("SELECT r.root_id FROM authority_signing_intents i JOIN authority_signing_jobs j ON j.org_id=i.org_id AND j.project_id=i.project_id AND j.job_id=i.job_id AND j.intent_id=i.intent_id JOIN authority_signing_quota_reservations r ON r.org_id=i.org_id AND r.project_id=i.project_id AND r.reservation_id=i.reservation_id WHERE i.org_id=? AND i.project_id=? AND i.job_id=?",params![tenant.org_id,tenant.project_id,job],|r|r.get(0)).optional()?;
        if let Some(Some(root)) = root {
            advance(&tx, &tenant.org_id, "root", &root, now)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn pin_signing_root_quota(
        &mut self,
        tenant: &AuthorityTenant,
        pin: &SigningRootQuotaPin,
        expected_revision: Option<u64>,
        now: i64,
    ) -> Result<u64> {
        self.pin_quota(
            tenant,
            "root",
            &pin.root_id,
            &pin.clone().into(),
            expected_revision,
            now,
        )
    }
    pub fn pin_signing_project_quota<P: Clone + Into<SigningProjectQuotaPin>>(
        &mut self,
        tenant: &AuthorityTenant,
        pin: &P,
        expected_revision: Option<u64>,
        now: i64,
    ) -> Result<u64> {
        self.pin_quota(
            tenant,
            "project",
            &tenant.project_id,
            &pin.clone().into(),
            expected_revision,
            now,
        )
    }
    fn pin_quota(
        &mut self,
        tenant: &AuthorityTenant,
        kind: &str,
        id: &str,
        pin: &SigningProjectQuotaPin,
        expected_revision: Option<u64>,
        now: i64,
    ) -> Result<u64> {
        identifier(id)?;
        self.observe_quota_bucket(tenant, kind, id, now)?;
        validate_pin(pin, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        security_revision(&tx, tenant)?;
        if let ("project", Some(root_id)) = (kind, &pin.root_id) {
            let root =
                pin_head(&tx, &tenant.org_id, "root", root_id)?.ok_or(AuthorityError::Binding)?;
            clock(&tx, &tenant.org_id, "root", root_id, now)?;
            if !current(&tx, &root, now)? {
                return Err(AuthorityError::Time);
            }
        }
        let old = pin_head(&tx, &tenant.org_id, kind, id)?;
        if let Some(old) = &old {
            if kind == "project" {
                // The first retained pin permanently anchors the project. An
                // explicit CAS can cut A to None and restore A, never attach B;
                // a project created without a root cannot later acquire one.
                let anchor = pin_at(&tx, &tenant.org_id, kind, id, 1)?;
                if pin.root_id.is_some() && pin.root_id != anchor.record.pin.root_id {
                    return Err(AuthorityError::Binding);
                }
            }
            if old.record.pin == *pin
                && !revoked(&tx, old)?
                && expected_revision == Some(old.revision)
            {
                tx.commit()?;
                return Ok(old.revision);
            }
        }
        if old.as_ref().map(|p| p.revision) != expected_revision {
            return Err(AuthorityError::Conflict);
        }
        let next = expected_revision
            .unwrap_or(0)
            .checked_add(1)
            .filter(|v| *v <= i32::MAX as u64)
            .ok_or(AuthorityError::Quota)?;
        let record = PinRecord {
            schema_version: pin
                .root_id
                .is_none()
                .then(|| "fw.signing-project-quota-pin/v2".into()),
            org_id: tenant.org_id.clone(),
            bucket_kind: kind.into(),
            bucket_id: id.into(),
            revision: next.to_string(),
            pinned_at: at(now)?,
            pin: pin.clone(),
        };
        let canonical = bytes(&record)?;
        tx.execute(
            "INSERT INTO authority_signing_quota_pins VALUES(?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                kind,
                id,
                next,
                pin.root_id,
                now,
                hash(&hash_bytes(&canonical))?,
                canonical
            ],
        )?;
        tx.execute("UPDATE authority_signing_quota_heads SET revision=?4 WHERE org_id=?1 AND bucket_kind=?2 AND bucket_id=?3",params![tenant.org_id,kind,id,next])?;
        tx.execute("INSERT INTO authority_signing_quota_heads SELECT ?1,?2,?3,?4 WHERE NOT EXISTS(SELECT 1 FROM authority_signing_quota_heads WHERE org_id=?1 AND bucket_kind=?2 AND bucket_id=?3)",params![tenant.org_id,kind,id,next])?;
        tx.execute("UPDATE authority_signing_quota_clocks SET observed_at=?4 WHERE org_id=?1 AND bucket_kind=?2 AND bucket_id=?3",params![tenant.org_id,kind,id,now])?;
        tx.execute("INSERT INTO authority_signing_quota_clocks SELECT ?1,?2,?3,?4 WHERE NOT EXISTS(SELECT 1 FROM authority_signing_quota_clocks WHERE org_id=?1 AND bucket_kind=?2 AND bucket_id=?3)",params![tenant.org_id,kind,id,now])?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "signing_quota_pinned", id, now)?;
        tx.commit()?;
        Ok(next)
    }
    pub fn revoke_signing_root_quota(
        &mut self,
        tenant: &AuthorityTenant,
        root: &str,
        expected_revision: u64,
        now: i64,
    ) -> Result<()> {
        self.revoke_quota(tenant, "root", root, expected_revision, now)
    }
    pub fn revoke_signing_project_quota(
        &mut self,
        tenant: &AuthorityTenant,
        expected_revision: u64,
        now: i64,
    ) -> Result<()> {
        self.revoke_quota(
            tenant,
            "project",
            &tenant.project_id,
            expected_revision,
            now,
        )
    }
    fn revoke_quota(
        &mut self,
        tenant: &AuthorityTenant,
        kind: &str,
        id: &str,
        expected_revision: u64,
        now: i64,
    ) -> Result<()> {
        identifier(id)?;
        self.observe_quota_bucket(tenant, kind, id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        security_revision(&tx, tenant)?;
        let head = pin_head(&tx, &tenant.org_id, kind, id)?.ok_or(AuthorityError::Binding)?;
        if head.revision != expected_revision {
            return Err(AuthorityError::Conflict);
        }
        clock(&tx, &tenant.org_id, kind, id, now)?;
        if !revoked(&tx, &head)? {
            tx.execute(
                "INSERT INTO authority_signing_quota_revocations VALUES(?,?,?,?,?)",
                params![tenant.org_id, kind, id, expected_revision, now],
            )?;
            bump_security(&tx, tenant)?;
            audit(&tx, tenant, "signing_quota_revoked", id, now)?;
        }
        tx.commit()?;
        Ok(())
    }
}

pub(super) fn cost_for_plan(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan_id: &str,
    now: i64,
) -> Result<SigningQuotaCost> {
    let subject = records::plan(tx, tenant, plan_id, now)?;
    let plan: Value = decode(&subject.plan_bytes)?;
    if plan["change_kind"] == "add_access_lease" {
        let provenance = access_provenance::provenance_in_tx(tx, tenant, &subject, now)?
            .ok_or(AuthorityError::Binding)?;
        if !core_configuration_available(tx, tenant, &provenance, now)? {
            return Err(AuthorityError::Binding);
        }
        // The remaining plan/policy window never discounts the original lease.
        // This derives a cost only: approval and protected signing are separate.
        let cost = SigningQuotaCost {
            plan_id: subject.plan_id,
            plan_hash: subject.plan_hash,
            lease_id: Some(provenance.lease_id().into()),
            lease_seconds: provenance.lease_seconds(),
            destination_asset_ids: provenance.destination_asset_ids().to_vec(),
        };
        cost.validate()?;
        return Ok(cost);
    }
    if plan["change_kind"] != "policy_change" {
        return Err(invalid("signing plan kind"));
    }
    let verified =
        review_evidence::review_in_tx(tx, tenant, &subject, now)?.ok_or(AuthorityError::Binding)?;
    if verified.plan_hash() != subject.plan_hash
        || !matches!(
            plan["effect_summary"]["relation"].as_str(),
            Some("equivalent" | "restricting")
        )
    {
        return Err(AuthorityError::Binding);
    }
    Ok(SigningQuotaCost {
        plan_id: subject.plan_id,
        plan_hash: subject.plan_hash,
        lease_id: None,
        lease_seconds: 0,
        destination_asset_ids: Vec::new(),
    })
}

struct Stored {
    root: Option<String>,
    plan: String,
    plan_hash: Vec<u8>,
    lease: Option<String>,
    seconds: i64,
    cost_hash: Vec<u8>,
    cost: Vec<u8>,
    snapshot: Vec<u8>,
    reserved_at: i64,
    reserved_until: i64,
    state: String,
    issued_at: Option<i64>,
    active: i64,
    dispatch: i64,
}
pub(super) fn read(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<SigningBudgetReservation> {
    read_record(tx, tenant, id, true, false, false)
}
pub(super) fn read_initializing_job(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<SigningBudgetReservation> {
    // The job and intent have just been inserted, but signer-created must still
    // be appended in this transaction. This is the only caller allowed to read
    // that state; a committed job without genesis fails ordinary reads.
    let saved = read_record(tx, tenant, id, true, false, true)?;
    let advanced:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_intents i WHERE i.org_id=?1 AND i.project_id=?2 AND i.reservation_id=?3 AND (EXISTS(SELECT 1 FROM authority_signing_work_heads h WHERE h.org_id=i.org_id AND h.project_id=i.project_id AND h.job_id=i.job_id) OR EXISTS(SELECT 1 FROM authority_signing_work_audits a WHERE a.org_id=i.org_id AND a.project_id=i.project_id AND a.job_id=i.job_id) OR EXISTS(SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=i.org_id AND e.project_id=i.project_id AND e.job_id=i.job_id) OR EXISTS(SELECT 1 FROM authority_signing_results s WHERE s.org_id=i.org_id AND s.project_id=i.project_id AND s.intent_id=i.intent_id) OR EXISTS(SELECT 1 FROM authority_signing_outbox o WHERE o.org_id=i.org_id AND o.project_id=i.project_id AND o.job_id=i.job_id)))",params![tenant.org_id,tenant.project_id,id],|r|r.get(0))?;
    if saved.state != "reserved" || saved.issued_at.is_some() || advanced {
        return Err(AuthorityError::Conflict);
    }
    Ok(saved)
}
fn read_record(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    check_transition: bool,
    pending_unknown_transition: bool,
    initializing_job: bool,
) -> Result<SigningBudgetReservation> {
    identifier(id)?;
    validate_reservation_graph(tx, tenant, id, initializing_job)?;
    let row:Stored=tx.query_row("SELECT root_id,plan_id,plan_hash,lease_id,lease_seconds,cost_hash,CASE WHEN length(cost_bytes)<=262144 THEN cost_bytes END,CASE WHEN length(snapshot_bytes)<=32768 THEN snapshot_bytes END,reserved_at,reserved_until,state,issued_at,active_slots,dispatch_slots FROM authority_signing_quota_reservations WHERE org_id=? AND project_id=? AND reservation_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok(Stored{root:r.get(0)?,plan:r.get(1)?,plan_hash:r.get(2)?,lease:r.get(3)?,seconds:r.get(4)?,cost_hash:r.get(5)?,cost:r.get(6)?,snapshot:r.get(7)?,reserved_at:r.get(8)?,reserved_until:r.get(9)?,state:r.get(10)?,issued_at:r.get(11)?,active:r.get(12)?,dispatch:r.get(13)?}))?;
    let cost: SigningQuotaCost = decode(&row.cost)?;
    let snapshot: Snapshot = decode(&row.snapshot)?;
    cost.validate()?;
    if row.plan != cost.plan_id
        || row.plan_hash != hash(&cost.plan_hash)?
        || row.lease != cost.lease_id
        || row.seconds != cost.lease_seconds
        || row.cost_hash != hash(&hash_bytes(&row.cost))?
        || match snapshot.schema_version.as_str() {
            "fw.signing-budget-reservation/v1" => {
                snapshot.root_id.is_none()
                    || snapshot.root_revision.is_none()
                    || snapshot.root_pin_hash.is_none()
                    || snapshot.root_projected.is_none()
            }
            "fw.signing-budget-reservation/v2" => {
                snapshot.root_id.is_some()
                    || snapshot.root_revision.is_some()
                    || snapshot.root_pin_hash.is_some()
                    || snapshot.root_projected.is_some()
                    || cost.lease_id.is_some()
                    || row.active != 0
            }
            _ => true,
        }
        || snapshot.org_id != tenant.org_id
        || snapshot.project_id != tenant.project_id
        || snapshot.reservation_id != id
        || snapshot.root_id != row.root
        || snapshot.plan_id != row.plan
        || snapshot.plan_hash != cost.plan_hash
        || snapshot.reserved_at != at(row.reserved_at)?
        || snapshot.reserved_until != at(row.reserved_until)?
        || row.reserved_until <= row.reserved_at
        || row.reserved_until - row.reserved_at > 300
        || row.reserved_at < WINDOW
        || snapshot.window_start != at(row.reserved_at - WINDOW)?
        || snapshot.window_end != snapshot.reserved_at
    {
        return Err(invalid("signing quota reservation projection"));
    }
    let root = row
        .root
        .as_deref()
        .map(|id| {
            pin_at(
                tx,
                &tenant.org_id,
                "root",
                id,
                revision(
                    snapshot
                        .root_revision
                        .as_deref()
                        .ok_or(AuthorityError::Binding)?,
                )?,
            )
        })
        .transpose()?;
    let project = pin_at(
        tx,
        &tenant.org_id,
        "project",
        &tenant.project_id,
        revision(&snapshot.project_revision)?,
    )?;
    if root.as_ref().map(|root| &root.digest) != snapshot.root_pin_hash.as_ref()
        || project.digest != snapshot.project_pin_hash
        || project.record.pin.root_id != row.root
        || row.reserved_at < crate::timestamp(&project.record.pinned_at)?
        || row.reserved_until > project.record.pin.not_after
    {
        return Err(AuthorityError::Binding);
    }
    if let Some(root) = &root
        && (row.reserved_at < crate::timestamp(&root.record.pinned_at)?
            || row.reserved_until > root.record.pin.not_after)
    {
        return Err(AuthorityError::Binding);
    }
    for (usage, limits) in snapshot
        .root_projected
        .as_ref()
        .zip(root.as_ref())
        .map(|(usage, root)| (usage, &root.record.pin.limits))
        .into_iter()
        .chain(std::iter::once((
            &snapshot.project_projected,
            &project.record.pin.limits,
        )))
    {
        if usage.active_leases < cost.active()
            || usage.new_leases_per_day < cost.active()
            || usage.unique_destinations_per_day < cost.destination_asset_ids.len() as i64
            || usage.cumulative_seconds_per_day < cost.lease_seconds
            || usage.concurrent_deployments < 1
        {
            return Err(invalid("signing quota snapshot"));
        }
        usage.within(limits)?;
    }
    let mut statement=tx.prepare("SELECT asset_id FROM authority_signing_quota_destinations WHERE org_id=? AND project_id=? AND reservation_id=? ORDER BY asset_id LIMIT 4097")?;
    let destinations = statement
        .query_map(params![tenant.org_id, tenant.project_id, id], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if destinations != cost.destination_asset_ids {
        return Err(invalid("signing quota destination projection"));
    }
    let usage:Option<(i64,Vec<u8>)>=tx.query_row("SELECT charged_at,cost_hash FROM authority_signing_quota_usage WHERE org_id=? AND project_id=? AND reservation_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if row.issued_at.map(|n| (n, row.cost_hash.clone())) != usage
        || row
            .issued_at
            .is_some_and(|n| n < row.reserved_at || n >= row.reserved_until)
    {
        return Err(invalid("signing quota issuance projection"));
    }
    let legal = match row.state.as_str() {
        "reserved" => row.issued_at.is_none() && row.active == cost.active() && row.dispatch == 1,
        "issued" => row.issued_at.is_some() && row.active == cost.active() && row.dispatch == 1,
        "unknown" => row.active == cost.active() && row.dispatch == 1,
        "active" => row.issued_at.is_some() && row.active == cost.active() && row.dispatch == 0,
        "released" => row.issued_at.is_none() && row.active == 0 && row.dispatch == 0,
        _ => false,
    };
    if !legal {
        return Err(invalid("signing quota state projection"));
    }
    if !pending_unknown_transition
        && row.state == "issued"
        && signing_jobs::reservation_has_unknown_history(tx, tenant, id)?
    {
        return Err(invalid("signing quota uncertainty history"));
    }
    if check_transition {
        validate_transition_history(tx, tenant, id, &row)?;
        let matches: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_signing_quota_transitions t WHERE t.org_id=?1 AND t.project_id=?2 AND t.reservation_id=?3 AND t.revision=(SELECT MAX(revision) FROM authority_signing_quota_transitions WHERE org_id=?1 AND project_id=?2 AND reservation_id=?3) AND t.state=?4 AND t.issued_at IS ?5 AND t.active_slots=?6 AND t.dispatch_slots=?7 AND EXISTS(SELECT 1 FROM authority_signing_quota_transition_heads h WHERE h.org_id=t.org_id AND h.project_id=t.project_id AND h.reservation_id=t.reservation_id AND h.revision=t.revision AND h.state=t.state AND h.issued_at IS t.issued_at AND h.root_id IS ?8 AND h.lease_id IS ?9))",
            params![tenant.org_id, tenant.project_id, id, row.state, row.issued_at, row.active, row.dispatch, row.root, row.lease], |r| r.get(0))?;
        if !matches {
            return Err(invalid("signing quota transition projection"));
        }
    }
    Ok(SigningBudgetReservation {
        schema_version: snapshot.schema_version,
        org_id: snapshot.org_id,
        project_id: snapshot.project_id,
        reservation_id: snapshot.reservation_id,
        root_id: snapshot.root_id,
        plan_id: snapshot.plan_id,
        plan_hash: snapshot.plan_hash,
        root_revision: snapshot.root_revision,
        project_revision: snapshot.project_revision,
        root_pin_hash: snapshot.root_pin_hash,
        project_pin_hash: snapshot.project_pin_hash,
        reserved_at: snapshot.reserved_at,
        reserved_until: snapshot.reserved_until,
        window_start: snapshot.window_start,
        window_end: snapshot.window_end,
        root_projected: snapshot.root_projected,
        project_projected: snapshot.project_projected,
        cost,
        state: row.state,
        issued_at: row.issued_at.map(at).transpose()?,
        active_slots: row.active,
        dispatch_slots: row.dispatch,
    })
}

// A transition binds the immutable work event which authorizes its slot effect.
// The SQL evidence guard checks the corresponding issuance/outbox/delivery too.
type TransitionWitness = (String, String, Vec<u8>, i64);
fn transition_witness(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    state: &str,
) -> Result<Option<TransitionWitness>> {
    let (phase, expected) = match state {
        "issued" => ("signer", "ready"),
        "released" => ("signer", "cancelled"),
        "unknown" => ("dispatch", "unknown"),
        "active" => ("dispatch", "delivered"),
        "reserved" => ("signer", ""),
        _ => return Err(invalid("quota transition state")),
    };
    Ok(tx.query_row("SELECT e.job_id,e.phase,e.revision,e.updated_at FROM authority_signing_intents i JOIN authority_signing_work_events e ON e.org_id=i.org_id AND e.project_id=i.project_id AND e.job_id=i.job_id WHERE i.org_id=?1 AND i.project_id=?2 AND i.reservation_id=?3 AND e.phase=?4 AND (e.state=?5 OR (?5='' AND e.state IN ('prepared','claimed'))) ORDER BY e.revision DESC LIMIT 1", params![tenant.org_id,tenant.project_id,id,phase,expected], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?)
}
fn record_transition(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    saved: &SigningBudgetReservation,
    state: &str,
    issued: Option<i64>,
    now: i64,
) -> Result<()> {
    let next:i64=tx.query_row("SELECT MAX(revision)+1 FROM authority_signing_quota_transitions WHERE org_id=? AND project_id=? AND reservation_id=?",params![tenant.org_id,tenant.project_id,saved.reservation_id],|r|r.get(0))?;
    let witness = transition_witness(tx, tenant, &saved.reservation_id, state)?;
    tx.execute(
        "INSERT INTO authority_signing_quota_transitions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            saved.reservation_id,
            next,
            state,
            issued,
            if state == "released" {
                0
            } else {
                saved.cost.active()
            },
            i64::from(matches!(state, "issued" | "unknown")),
            now,
            state,
            witness.as_ref().map(|w| w.0.as_str()),
            witness.as_ref().map(|w| w.1.as_str()),
            witness.as_ref().map(|w| w.2.as_slice())
        ],
    )?;
    Ok(())
}

// Maintenance deliberately scans every legacy reservation. Expiry supplies no
// cancellation evidence, and imported rows must already agree with their work.
pub(super) fn validate_legacy_reservations(tx: &Transaction<'_>) -> Result<()> {
    let mut statement = tx.prepare(
        "SELECT org_id,project_id,reservation_id FROM authority_signing_quota_reservations",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let id: String = row.get(2)?;
        let saved = read_record(tx, &tenant, &id, false, false, false)?;
        let intent_id:String=tx.query_row("SELECT intent_id FROM authority_signing_intents WHERE org_id=? AND project_id=? AND reservation_id=?",params![tenant.org_id,tenant.project_id,id],|r|r.get(0))?;
        let intent = signing_intents::intent_at(tx, &tenant, &intent_id)?;
        signing_intents::job_at(tx, &tenant, &intent.job_id)?;
        if intent.reservation_id != id
            || intent.plan_id != saved.plan_id
            || intent.plan_hash != saved.plan_hash
        {
            return Err(AuthorityError::Binding);
        }
        let result = signing_intents::retained_result(tx, &tenant, &intent)?;
        if result.is_some() != saved.issued_at.is_some() {
            return Err(invalid("legacy quota issuance"));
        }
        // Compare the complete mutable heads with the latest immutable events.
        let mismatch:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_work_heads h WHERE h.org_id=?1 AND h.project_id=?2 AND h.job_id=?3 AND NOT EXISTS(SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=h.org_id AND e.project_id=h.project_id AND e.job_id=h.job_id AND e.phase=h.phase AND e.revision=h.revision AND e.revision=(SELECT MAX(w.revision) FROM authority_signing_work_events w WHERE w.org_id=h.org_id AND w.project_id=h.project_id AND w.job_id=h.job_id AND w.phase=h.phase) AND e.state=h.state AND e.claim_generation=h.claim_generation AND e.claim_hash IS h.claim_hash AND e.worker_id IS h.worker_id AND e.claim_until IS h.claim_until AND e.attempts=h.attempts AND e.available_at=h.available_at AND e.updated_at=h.updated_at)) OR EXISTS(SELECT 1 FROM authority_signing_work_events e WHERE e.org_id=?1 AND e.project_id=?2 AND e.job_id=?3 AND NOT EXISTS(SELECT 1 FROM authority_signing_work_heads h WHERE h.org_id=e.org_id AND h.project_id=e.project_id AND h.job_id=e.job_id AND h.phase=e.phase))",params![tenant.org_id,tenant.project_id,intent.job_id],|r|r.get(0))?;
        if mismatch {
            return Err(invalid("legacy signing work projection"));
        }
        let signer:String=tx.query_row("SELECT state FROM authority_signing_work_heads WHERE org_id=? AND project_id=? AND job_id=? AND phase='signer'",params![tenant.org_id,tenant.project_id,intent.job_id],|r|r.get(0))?;
        let dispatch:Option<String>=tx.query_row("SELECT state FROM authority_signing_work_heads WHERE org_id=? AND project_id=? AND job_id=? AND phase='dispatch'",params![tenant.org_id,tenant.project_id,intent.job_id],|r|r.get(0)).optional()?;
        let legal = match saved.state.as_str() {
            "reserved" => matches!(signer.as_str(), "prepared" | "claimed") && dispatch.is_none(),
            "released" => signer == "cancelled" && dispatch.is_none() && saved.issued_at.is_none(),
            "issued" => {
                signer == "ready" && matches!(dispatch.as_deref(), Some("queued" | "claimed"))
            }
            "unknown" => {
                signer == "ready"
                    && matches!(dispatch.as_deref(), Some("unknown" | "claimed"))
                    && saved.issued_at.is_some()
            }
            "active" => signer == "ready" && dispatch.as_deref() == Some("delivered"),
            _ => false,
        };
        if !legal || transition_witness(tx, &tenant, &id, &saved.state)?.is_none() {
            return Err(invalid("legacy quota work evidence"));
        }
    }
    Ok(())
}
pub(super) fn backfill_legacy_transitions(tx: &Transaction<'_>) -> Result<()> {
    let mut statement = tx.prepare(
        "SELECT org_id,project_id,reservation_id FROM authority_signing_quota_reservations",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let id: String = row.get(2)?;
        let saved = read_record(tx, &tenant, &id, false, false, false)?;
        let witness =
            transition_witness(tx, &tenant, &id, &saved.state)?.ok_or(AuthorityError::Binding)?;
        tx.execute("INSERT INTO authority_signing_quota_transitions VALUES(?,?,?,0,?,?,?,?,?,'imported',?,?,?)",params![tenant.org_id,tenant.project_id,id,saved.state,saved.issued_at.as_deref().map(crate::timestamp).transpose()?,saved.active_slots,saved.dispatch_slots,witness.3,witness.0,witness.1,witness.2])?;
        read(tx, &tenant, &id)?;
        // Only commit imports after the normal complete lifecycle verifier has
        // checked retained signatures, exact outbox bytes and delivery hashes.
        // Use the latest retained work time, not migration wall time or an
        // unverified delivery timestamp, so historical data is not refreshed.
        let now:i64=tx.query_row("SELECT MAX(updated_at) FROM authority_signing_work_events WHERE org_id=? AND project_id=? AND job_id=?", params![tenant.org_id,tenant.project_id,witness.0], |r|r.get(0))?;
        signing_jobs::lifecycle_status(tx, &tenant, &witness.0, now)?;
    }
    Ok(())
}

fn add(value: &mut i64, cost: i64) -> Result<()> {
    *value = value.checked_add(cost).ok_or(AuthorityError::Quota)?;
    Ok(())
}
#[derive(Clone, Copy)]
enum AccountingScope<'a> {
    Root(&'a str),
    Project,
}
fn account(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    scope: AccountingScope<'_>,
    now: i64,
    prospective: Option<&SigningQuotaCost>,
) -> Result<SigningQuotaUsage> {
    migrations::validate_live_schema(tx)
        .map_err(|_| invalid("quota accounting guard missing or changed"))?;
    // The complete independently constructed schema inventory also covers
    // audit dependencies and rejects unexpected internal-named objects.
    // Two bounded indexed scans: live slots (including expired UNKNOWN), then
    // released history inside the exact rolling interval. Never truncate and
    // claim admission; excess work returns Quota for the entire transaction.
    let (key, index_kind, bucket) = match scope {
        AccountingScope::Root(root) => ("root_id", "root", root),
        AccountingScope::Project => ("project_id", "project", tenant.project_id.as_str()),
    };
    let sql = format!(
        "SELECT project_id,reservation_id FROM authority_signing_quota_transition_heads INDEXED BY authority_signing_quota_transition_{index_kind}_held WHERE org_id=?1 AND {key}=?2 AND state IN ('reserved','issued','unknown','active') UNION ALL SELECT project_id,reservation_id FROM authority_signing_quota_transition_heads INDEXED BY authority_signing_quota_transition_{index_kind}_accounting WHERE org_id=?1 AND {key}=?2 AND state='released' AND lease_id IS NOT NULL AND issued_at>?3 AND issued_at<=?4 LIMIT {}",
        MAX_ACCOUNTED_ROWS + 1
    );
    let mut statement = tx.prepare(&sql)?;
    let mut rows = statement.query(params![tenant.org_id, bucket, now - WINDOW, now])?;
    let mut result = SigningQuotaUsage::default();
    let mut destinations = BTreeSet::new();
    let mut rows_seen = 0;
    let mut destinations_seen = 0usize;
    while let Some(row) = rows.next()? {
        rows_seen += 1;
        if rows_seen > MAX_ACCOUNTED_ROWS {
            return Err(AuthorityError::Quota);
        }
        let project: String = row.get(0)?;
        let id: String = row.get(1)?;
        let row_tenant = AuthorityTenant::new(&tenant.org_id, &project)?;
        let saved = read(tx, &row_tenant, &id)?;
        if matches!(scope,AccountingScope::Root(root) if saved.root_id.as_deref()!=Some(root)) {
            return Err(AuthorityError::Binding);
        }
        if crate::timestamp(&saved.reserved_at)? > now
            || saved
                .issued_at
                .as_deref()
                .map(crate::timestamp)
                .transpose()?
                .is_some_and(|n| n > now)
        {
            return Err(AuthorityError::Time);
        }
        add(&mut result.active_leases, saved.active_slots)?;
        add(
            &mut result.concurrent_deployments,
            saved.effective_dispatch_slots(),
        )?;
        let charged = match &saved.issued_at {
            Some(at) => crate::timestamp(at)? > now - WINDOW,
            None => saved.state != "released",
        };
        if charged {
            add(&mut result.new_leases_per_day, saved.cost.active())?;
            add(
                &mut result.cumulative_seconds_per_day,
                saved.cost.lease_seconds,
            )?;
            destinations_seen = destinations_seen
                .checked_add(saved.cost.destination_asset_ids.len())
                .ok_or(AuthorityError::Quota)?;
            if destinations_seen > MAX_ACCOUNTED_DESTINATIONS {
                return Err(AuthorityError::Quota);
            }
            destinations.extend(saved.cost.destination_asset_ids);
        }
    }
    if let Some(cost) = prospective {
        if destinations_seen.saturating_add(cost.destination_asset_ids.len())
            > MAX_ACCOUNTED_DESTINATIONS
        {
            return Err(AuthorityError::Quota);
        }
        add(&mut result.active_leases, cost.active())?;
        add(&mut result.concurrent_deployments, 1)?;
        add(&mut result.new_leases_per_day, cost.active())?;
        add(&mut result.cumulative_seconds_per_day, cost.lease_seconds)?;
        destinations.extend(cost.destination_asset_ids.iter().cloned());
    }
    result.unique_destinations_per_day =
        i64::try_from(destinations.len()).map_err(|_| AuthorityError::Quota)?;
    Ok(result)
}

include!("signing_quota_validation.rs");
fn observed(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    root: Option<&str>,
    now: i64,
) -> Result<()> {
    advance(tx, &tenant.org_id, "project", &tenant.project_id, now)?;
    if let Some(root) = root {
        advance(tx, &tenant.org_id, "root", root, now)?;
    }
    Ok(())
}

pub(super) fn reserve(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    cost: &SigningQuotaCost,
    reserved_until: i64,
    now: i64,
) -> Result<SigningBudgetReservation> {
    identifier(id)?;
    cost.validate()?;
    time(now)?;
    time(reserved_until)?;
    if now < WINDOW || reserved_until <= now || reserved_until - now > 300 {
        return Err(AuthorityError::Time);
    }
    let (root, project) = configuration(tx, tenant, now)?.ok_or(AuthorityError::Binding)?;
    observed(tx, tenant, project.record.pin.root_id.as_deref(), now)?;
    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_quota_reservations WHERE org_id=? AND project_id=? AND reservation_id=?)",params![tenant.org_id,tenant.project_id,id],|r|r.get(0))?;
    if exists {
        let saved = read(tx, tenant, id)?;
        if saved.cost != *cost
            || saved.state != "reserved"
            || saved.root_id != project.record.pin.root_id
            || saved.root_revision != root.as_ref().map(|root| root.revision.to_string())
            || saved.project_revision != project.revision.to_string()
            || now >= crate::timestamp(&saved.reserved_until)?
        {
            return Err(AuthorityError::Conflict);
        }
        return Ok(saved);
    }
    if reserved_until
        > root.as_ref().map_or(project.record.pin.not_after, |root| {
            root.record.pin.not_after.min(project.record.pin.not_after)
        })
    {
        return Err(AuthorityError::Time);
    }
    if let Some(lease) = &cost.lease_id {
        let existing:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_quota_reservations WHERE org_id=? AND lease_id=?)",params![tenant.org_id,lease],|r|r.get(0))?;
        if existing {
            return Err(AuthorityError::Conflict);
        }
    }
    if root.is_none() && cost.lease_id.is_some() {
        return Err(AuthorityError::Binding);
    }
    let root_projected = root
        .as_ref()
        .map(|root| {
            let usage = account(
                tx,
                tenant,
                AccountingScope::Root(
                    root.record
                        .pin
                        .root_id
                        .as_deref()
                        .ok_or(AuthorityError::Binding)?,
                ),
                now,
                Some(cost),
            )?;
            usage.within(&root.record.pin.limits)?;
            Ok::<_, AuthorityError>(usage)
        })
        .transpose()?;
    let project_projected = account(tx, tenant, AccountingScope::Project, now, Some(cost))?;
    project_projected.within(&project.record.pin.limits)?;
    let snapshot = Snapshot {
        schema_version: if root.is_some() {
            "fw.signing-budget-reservation/v1"
        } else {
            "fw.signing-budget-reservation/v2"
        }
        .into(),
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        reservation_id: id.into(),
        root_id: project.record.pin.root_id.clone(),
        plan_id: cost.plan_id.clone(),
        plan_hash: cost.plan_hash.clone(),
        root_revision: root.as_ref().map(|root| root.revision.to_string()),
        project_revision: project.revision.to_string(),
        root_pin_hash: root.as_ref().map(|root| root.digest.clone()),
        project_pin_hash: project.digest,
        reserved_at: at(now)?,
        reserved_until: at(reserved_until)?,
        window_start: at(now - WINDOW)?,
        window_end: at(now)?,
        root_projected,
        project_projected,
    };
    let canonical = bytes(cost)?;
    tx.execute("INSERT INTO authority_signing_quota_reservations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'reserved',NULL,?,1)",params![tenant.org_id,tenant.project_id,id,snapshot.root_id,cost.plan_id,hash(&cost.plan_hash)?,cost.lease_id,cost.lease_seconds,hash(&hash_bytes(&canonical))?,canonical,bytes(&snapshot)?,now,reserved_until,cost.active()])?;
    for destination in &cost.destination_asset_ids {
        tx.execute(
            "INSERT INTO authority_signing_quota_destinations VALUES(?,?,?,?)",
            params![tenant.org_id, tenant.project_id, id, destination],
        )?;
    }
    read(tx, tenant, id)
}

pub(super) fn finalize(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
) -> Result<SigningBudgetReservation> {
    let saved = finalize_admission(tx, tenant, id, now)?;
    record_issuance(tx, tenant, id, now, saved)
}

fn finalize_admission(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
) -> Result<SigningBudgetReservation> {
    let saved = read(tx, tenant, id)?;
    observed(tx, tenant, saved.root_id.as_deref(), now)?;
    if saved.issued_at.is_some() {
        return Ok(saved);
    }
    if saved.state != "reserved" {
        return Err(AuthorityError::Conflict);
    }
    if now >= crate::timestamp(&saved.reserved_until)? {
        return Err(AuthorityError::Time);
    }
    let (root, project) = configuration(tx, tenant, now)?.ok_or(AuthorityError::Binding)?;
    if project.record.pin.root_id != saved.root_id
        || root.as_ref().map(|root| root.revision.to_string()) != saved.root_revision
        || project.revision.to_string() != saved.project_revision
        || root.as_ref().map(|root| &root.digest) != saved.root_pin_hash.as_ref()
        || project.digest != saved.project_pin_hash
    {
        return Err(AuthorityError::Binding);
    }
    // The reservation is already included once; changing it into issued usage
    // must not add its prospective cost a second time.
    if let Some(root) = root {
        account(
            tx,
            tenant,
            AccountingScope::Root(saved.root_id.as_deref().ok_or(AuthorityError::Binding)?),
            now,
            None,
        )?
        .within(&root.record.pin.limits)?;
    }
    account(tx, tenant, AccountingScope::Project, now, None)?.within(&project.record.pin.limits)?;
    Ok(saved)
}

fn record_issuance(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
    saved: SigningBudgetReservation,
) -> Result<SigningBudgetReservation> {
    if saved.issued_at.is_some() {
        return Ok(saved);
    }
    let canonical = bytes(&saved.cost)?;
    tx.execute(
        "INSERT INTO authority_signing_quota_usage VALUES(?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            id,
            now,
            hash(&hash_bytes(&canonical))?
        ],
    )?;
    record_transition(tx, tenant, &saved, "issued", Some(now), now)?;
    if tx.execute("UPDATE authority_signing_quota_reservations SET state='issued',issued_at=? WHERE org_id=? AND project_id=? AND reservation_id=? AND state='reserved' AND issued_at IS NULL",params![now,tenant.org_id,tenant.project_id,id])?!=1 {return Err(AuthorityError::Conflict)}
    read(tx, tenant, id)
}

pub(super) fn cancel_unissued(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
) -> Result<()> {
    let saved = read(tx, tenant, id)?;
    observed(tx, tenant, saved.root_id.as_deref(), now)?;
    if saved.state == "released" && saved.issued_at.is_none() {
        return Ok(());
    }
    if saved.state != "reserved" || saved.issued_at.is_some() {
        return Err(AuthorityError::Conflict);
    }
    record_transition(tx, tenant, &saved, "released", None, now)?;
    tx.execute("UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0 WHERE org_id=? AND project_id=? AND reservation_id=?",params![tenant.org_id,tenant.project_id,id])?;
    Ok(())
}
pub(super) fn mark_unknown(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
) -> Result<()> {
    // The matching UNKNOWN work event is written first in this transaction.
    // Its quota projection has not advanced yet. Only this transition may read
    // that intermediate issued state; the SQL evidence guard below must still
    // bind the exact latest UNKNOWN witness and timestamp before committing.
    let saved = read_record(tx, tenant, id, true, true, false)?;
    observed(tx, tenant, saved.root_id.as_deref(), now)?;
    if saved.state == "unknown" {
        return Ok(());
    }
    if !matches!(saved.state.as_str(), "reserved" | "issued") {
        return Err(AuthorityError::Conflict);
    }
    record_transition(
        tx,
        tenant,
        &saved,
        "unknown",
        saved
            .issued_at
            .as_deref()
            .map(crate::timestamp)
            .transpose()?,
        now,
    )?;
    tx.execute("UPDATE authority_signing_quota_reservations SET state='unknown' WHERE org_id=? AND project_id=? AND reservation_id=?",params![tenant.org_id,tenant.project_id,id])?;
    Ok(())
}
pub(super) fn mark_active(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
) -> Result<()> {
    let saved = read(tx, tenant, id)?;
    observed(tx, tenant, saved.root_id.as_deref(), now)?;
    if saved.state == "active" {
        return Ok(());
    }
    if !matches!(saved.state.as_str(), "issued" | "unknown") || saved.issued_at.is_none() {
        return Err(AuthorityError::Conflict);
    }
    record_transition(
        tx,
        tenant,
        &saved,
        "active",
        saved
            .issued_at
            .as_deref()
            .map(crate::timestamp)
            .transpose()?,
        now,
    )?;
    tx.execute("UPDATE authority_signing_quota_reservations SET state='active',dispatch_slots=0 WHERE org_id=? AND project_id=? AND reservation_id=?",params![tenant.org_id,tenant.project_id,id])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    thread_local! {
        // Only arithmetic fixtures omit cryptographic jobs. Real guarded
        // lifecycle and attack fixtures always run the production witness path.
        pub(super) static PRIMITIVE_QUOTA_FIXTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    struct PrimitiveQuotaFixture;
    impl Drop for PrimitiveQuotaFixture {
        fn drop(&mut self) {
            PRIMITIVE_QUOTA_FIXTURE.set(false);
        }
    }
    mod history_tests {
        include!("signing_quota_history_tests.rs");
    }
    mod integrity_tests {
        include!("signing_quota_integrity_tests.rs");
    }
    mod rootless_lifecycle_tests {
        include!("signing_rootless_lifecycle_tests.rs");
    }
    mod version_tests {
        include!("signing_quota_version_tests.rs");
    }
    mod retention_tests {
        include!("signing_quota_retention_tests.rs");
    }
    const NOW: i64 = 1_800_000_000;
    fn id(n: u128) -> String {
        uuid::Uuid::from_u128(n).to_string()
    }
    fn limits() -> SigningQuotaLimits {
        SigningQuotaLimits {
            active_leases: 100,
            new_leases_per_day: 100,
            unique_destinations_per_day: 100,
            cumulative_seconds_per_day: 100_000,
            concurrent_deployments: 100,
        }
    }
    fn pin(limits: SigningQuotaLimits) -> SigningRootQuotaPin {
        SigningRootQuotaPin {
            root_id: id(10),
            limits,
            not_before: NOW - 1,
            not_after: NOW + 500_000,
        }
    }
    fn lease(n: u128, destinations: &[u128]) -> SigningQuotaCost {
        SigningQuotaCost {
            plan_id: id(1000 + n),
            plan_hash: hash_bytes(&n.to_be_bytes()),
            lease_id: Some(id(2000 + n)),
            lease_seconds: 60,
            destination_asset_ids: destinations.iter().map(|n| id(*n)).collect(),
        }
    }
    fn change(n: u128) -> SigningQuotaCost {
        SigningQuotaCost {
            plan_id: id(1000 + n),
            plan_hash: hash_bytes(&n.to_be_bytes()),
            lease_id: None,
            lease_seconds: 0,
            destination_asset_ids: Vec::new(),
        }
    }

    // Primitive accounting fixtures have no signer/work records. Admission
    // still runs every production guard check; only the synthetic transition
    // itself temporarily omits its work witness, within the same transaction.
    fn primitive_transition<T>(
        tx: &Transaction<'_>,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let guard: String = tx.query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_signing_quota_transitions_evidence'",
            [],
            |r| r.get(0),
        )?;
        tx.execute_batch("DROP TRIGGER authority_signing_quota_transitions_evidence")?;
        let result = operation();
        tx.execute_batch(&guard)?;
        result
    }

    fn primitive_finalize(
        tx: &Transaction<'_>,
        tenant: &AuthorityTenant,
        id: &str,
        now: i64,
    ) -> Result<SigningBudgetReservation> {
        let saved = finalize_admission(tx, tenant, id, now)?;
        primitive_transition(tx, || record_issuance(tx, tenant, id, now, saved))
    }
    struct Fixture {
        _primitive: PrimitiveQuotaFixture,
        _directory: tempfile::TempDir,
        store: AuthorityStore,
        tenant: AuthorityTenant,
    }
    impl Fixture {
        fn new(root: SigningQuotaLimits, project: SigningQuotaLimits) -> Self {
            assert!(!PRIMITIVE_QUOTA_FIXTURE.replace(true));
            let primitive = PrimitiveQuotaFixture;
            let mut builder = tempfile::Builder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                builder.permissions(std::fs::Permissions::from_mode(0o700));
            }
            let directory = builder.tempdir().unwrap();
            let mut store =
                AuthorityStore::open(directory.path().join("authority.sqlite3")).unwrap();
            let tenant = AuthorityTenant::new(&id(1), &id(2)).unwrap();
            store
                .provision_target_metadata_project(&tenant, NOW)
                .unwrap();
            store
                .pin_signing_root_quota(&tenant, &pin(root), None, NOW)
                .unwrap();
            store
                .pin_signing_project_quota(&tenant, &pin(project), None, NOW)
                .unwrap();
            Self {
                _primitive: primitive,
                _directory: directory,
                store,
                tenant,
            }
        }
        fn reserve(
            &mut self,
            n: u128,
            cost: &SigningQuotaCost,
            now: i64,
        ) -> Result<SigningBudgetReservation> {
            self.store.observe_signing_quota_time(&self.tenant, now)?;
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let saved = reserve(&tx, &self.tenant, &id(n), cost, now + 300, now)?;
            tx.commit()?;
            Ok(saved)
        }
        fn finalize(&mut self, n: u128, now: i64) -> Result<SigningBudgetReservation> {
            self.store.observe_signing_quota_time(&self.tenant, now)?;
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let saved = primitive_finalize(&tx, &self.tenant, &id(n), now)?;
            tx.commit()?;
            Ok(saved)
        }
        fn cancel(&mut self, n: u128, now: i64) -> Result<()> {
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            primitive_transition(&tx, || cancel_unissued(&tx, &self.tenant, &id(n), now))?;
            tx.commit()?;
            Ok(())
        }
        fn active(&mut self, n: u128, now: i64) {
            let tx = self
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            primitive_transition(&tx, || mark_active(&tx, &self.tenant, &id(n), now)).unwrap();
            tx.commit().unwrap();
        }
        fn count(&self, table: &str) -> i64 {
            self.store
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        }
    }

    fn real_reservation(state: &str) -> (signing_test_support::Fixture, String, String) {
        let mut f = signing_test_support::Fixture::new();
        signing_intents::test_initialize(&mut f, NOW);
        let mut cap = limits();
        cap.concurrent_deployments = 1;
        let pin = SigningRootQuotaPin {
            root_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            limits: cap,
            not_before: NOW,
            not_after: NOW + 7200,
        };
        f.store
            .pin_signing_root_quota(&f.tenant, &pin, Some(1), NOW)
            .unwrap();
        f.store
            .pin_signing_project_quota(&f.tenant, &pin, Some(1), NOW)
            .unwrap();
        let outcome = signing_intents::test_prepare(&mut f, NOW);
        let job = outcome.intent.job_id;
        let id = outcome.intent.reservation_id;
        if state != "reserved" {
            let tx = f.store.connection.transaction().unwrap();
            let claim = signing_jobs::fixture_claim(
                &tx,
                &f.tenant,
                &job,
                "signer",
                &self::id(90),
                0,
                60,
                NOW,
            )
            .unwrap();
            tx.commit().unwrap();
            signing_intents::test_finalize(&mut f, &claim, NOW).unwrap();
            if state == "unknown" {
                let tx = f.store.connection.transaction().unwrap();
                signing_jobs::fixture_claim(
                    &tx,
                    &f.tenant,
                    &job,
                    "dispatch",
                    &self::id(90),
                    0,
                    1,
                    NOW,
                )
                .unwrap();
                signing_jobs::fixture_claim(
                    &tx,
                    &f.tenant,
                    &job,
                    "dispatch",
                    &self::id(90),
                    1,
                    60,
                    NOW + 6,
                )
                .unwrap();
                tx.commit().unwrap();
            }
        }
        (f, job, id)
    }
    #[test]
    fn pr18_original_issued_release_counterexample() {
        let (mut f, job, id) = real_reservation("issued");
        {
            let tx = f.store.connection.transaction().unwrap();
            assert!(matches!(
                reserve(&tx, &f.tenant, &self::id(21), &change(2), NOW + 300, NOW),
                Err(AuthorityError::Quota)
            ));
        }
        assert!(f.store.connection.execute("UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0 WHERE reservation_id=?", [&id]).is_err());
        let tx = f.store.connection.transaction().unwrap();
        assert!(matches!(
            reserve(&tx, &f.tenant, &self::id(21), &change(2), NOW + 300, NOW),
            Err(AuthorityError::Quota)
        ));
        let status = signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW).unwrap();
        assert_eq!(status.state, "ready");
        assert_eq!(status.dispatch_state.as_deref(), Some("queued"));
        assert!(status.quota_held);
    }
    #[test]
    fn intact_guards_reject_state_slot_and_accounting_head_bypasses() {
        for state in ["reserved", "issued", "unknown"] {
            let (mut f, job, id) = real_reservation(state);
            for sql in [
                "UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0",
                "UPDATE authority_signing_quota_reservations SET state='active',dispatch_slots=0",
                "UPDATE authority_signing_quota_reservations SET dispatch_slots=0",
                "UPDATE authority_signing_quota_reservations SET state='reserved'",
                "UPDATE authority_signing_quota_transition_heads SET state='released'",
                "UPDATE authority_signing_quota_transition_heads SET revision=0,state='reserved',issued_at=NULL",
                "DELETE FROM authority_signing_quota_transition_heads",
                "DELETE FROM authority_signing_quota_transitions",
                "UPDATE authority_signing_quota_transitions SET state='released'",
            ] {
                if state == "reserved"
                    && (sql == "UPDATE authority_signing_quota_reservations SET state='reserved'"
                        || sql
                            == "UPDATE authority_signing_quota_transition_heads SET revision=0,state='reserved',issued_at=NULL")
                {
                    continue;
                }
                assert!(
                    f.store.connection.execute_batch(sql).is_err(),
                    "{state}: {sql}"
                );
            }
            let tx = f.store.connection.transaction().unwrap();
            assert_eq!(read(&tx, &f.tenant, &id).unwrap().state, state);
            assert!(
                signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW + 10)
                    .unwrap()
                    .quota_held
            );
        }
    }
    #[test]
    fn damaged_reservation_cannot_hide_from_transition_accounting_membership() {
        let (mut f, job, id) = real_reservation("issued");
        let guard:String=f.store.connection.query_row("SELECT sql FROM sqlite_schema WHERE name='authority_signing_quota_reservations_projection'",[],|r|r.get(0)).unwrap();
        f.store.connection.execute_batch("DROP TRIGGER authority_signing_quota_reservations_projection; UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0;").unwrap();
        f.store.connection.execute_batch(&guard).unwrap();
        let tx = f.store.connection.transaction().unwrap();
        assert!(read(&tx, &f.tenant, &id).is_err());
        assert!(signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW).is_err());
        assert!(matches!(
            reserve(&tx, &f.tenant, &self::id(21), &change(2), NOW + 300, NOW),
            Err(AuthorityError::Invalid(_))
        ));
    }
    #[test]
    fn removed_or_changed_live_membership_guards_cannot_admit_an_extra_reservation() {
        for mutation in [
            "DROP TRIGGER authority_signing_quota_transition_heads_no_delete; DELETE FROM authority_signing_quota_transition_heads;",
            "DROP TRIGGER authority_signing_quota_transition_heads_update; UPDATE authority_signing_quota_transition_heads SET state='released';",
            "DROP TRIGGER authority_signing_quota_transitions_membership; CREATE TRIGGER authority_signing_quota_transitions_membership AFTER INSERT ON authority_signing_quota_transitions BEGIN SELECT 1; END;",
        ] {
            let (mut f, _, _) = real_reservation("issued");
            f.store.connection.execute_batch(mutation).unwrap();
            let tx = f.store.connection.transaction().unwrap();
            assert!(
                matches!(
                    reserve(&tx, &f.tenant, &id(21), &change(2), NOW + 300, NOW),
                    Err(AuthorityError::Invalid(_))
                ),
                "{mutation}"
            );
        }
    }
    #[test]
    fn failed_transition_rolls_back_cancellation_and_issuance_with_work_evidence() {
        for finalize in [false, true] {
            let (mut f, job, id) = real_reservation("reserved");
            let claim = {
                let tx = f.store.connection.transaction().unwrap();
                let claim = signing_jobs::fixture_claim(
                    &tx,
                    &f.tenant,
                    &job,
                    "signer",
                    &self::id(90),
                    0,
                    60,
                    NOW,
                )
                .unwrap();
                tx.commit().unwrap();
                claim
            };
            let events = f.count("authority_signing_work_events");
            let audit = f.count("authority_audit");
            f.store.connection.execute_batch("CREATE TRIGGER reject_quota_transition BEFORE INSERT ON authority_signing_quota_transitions BEGIN SELECT RAISE(ABORT,'injected transition failure'); END").unwrap();
            if finalize {
                assert!(signing_intents::test_finalize(&mut f, &claim, NOW).is_err());
            } else {
                assert!(f.store.cancel_signing_job(&f.tenant, &job, NOW).is_err());
            }
            assert_eq!(f.count("authority_signing_work_events"), events);
            assert_eq!(f.count("authority_audit"), audit);
            assert_eq!(f.count("authority_signing_quota_usage"), 0);
            assert_eq!(f.count("authority_signing_results"), 0);
            assert_eq!(f.count("authority_signing_outbox"), 0);
            assert_eq!(f.count("authority_signing_quota_transitions"), 1);
            let tx = f.store.connection.transaction().unwrap();
            assert_eq!(read(&tx, &f.tenant, &id).unwrap().state, "reserved");
            assert_eq!(
                signing_jobs::lifecycle_status(&tx, &f.tenant, &job, NOW)
                    .unwrap()
                    .state,
                "claimed"
            );
        }
    }
    #[test]
    fn policy_changes_charge_dispatch_only_and_retries_do_not_extend_deadlines() {
        let mut cap = limits();
        cap.active_leases = 1;
        cap.new_leases_per_day = 1;
        cap.unique_destinations_per_day = 1;
        cap.cumulative_seconds_per_day = 60;
        cap.concurrent_deployments = 2;
        let mut f = Fixture::new(cap.clone(), cap);
        let first = f.reserve(20, &change(1), NOW).unwrap();
        let replay = f.reserve(20, &change(1), NOW + 1).unwrap();
        assert_eq!(first.reserved_until, replay.reserved_until);
        let second = f.reserve(21, &change(2), NOW + 1).unwrap();
        assert_eq!(
            second.root_projected,
            Some(SigningQuotaUsage {
                concurrent_deployments: 2,
                ..SigningQuotaUsage::default()
            })
        );
        assert!(matches!(
            f.reserve(22, &change(3), NOW + 1),
            Err(AuthorityError::Quota)
        ));
        f.cancel(20, NOW + 1).unwrap();
        f.reserve(22, &change(3), NOW + 1).unwrap();
        assert_eq!(f.count("authority_signing_quota_usage"), 0);
    }
    #[test]
    fn both_buckets_are_checked_before_any_reservation_rows_are_written() {
        let mut project = limits();
        project.concurrent_deployments = 1;
        let mut f = Fixture::new(limits(), project);
        f.reserve(20, &change(1), NOW).unwrap();
        assert!(matches!(
            f.reserve(21, &change(2), NOW),
            Err(AuthorityError::Quota)
        ));
        assert_eq!(f.count("authority_signing_quota_reservations"), 1);
        assert_eq!(f.count("authority_signing_quota_destinations"), 0);
        f.cancel(20, NOW).unwrap();
        assert_eq!(
            f.reserve(21, &change(2), NOW)
                .unwrap()
                .root_projected
                .unwrap()
                .concurrent_deployments,
            1
        );
    }
    #[test]
    fn organization_root_quota_competes_across_distinct_projects() {
        let mut root = limits();
        root.concurrent_deployments = 1;
        let mut f = Fixture::new(root, limits());
        let other = AuthorityTenant::new(&id(1), &id(3)).unwrap();
        f.store
            .provision_target_metadata_project(&other, NOW)
            .unwrap();
        f.store
            .pin_signing_project_quota(&other, &pin(limits()), None, NOW)
            .unwrap();
        f.reserve(20, &change(1), NOW).unwrap();
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(matches!(
            reserve(&tx, &other, &id(21), &change(2), NOW + 300, NOW),
            Err(AuthorityError::Quota)
        ));
        drop(tx);
        assert_eq!(f.count("authority_signing_quota_reservations"), 1);
    }
    #[test]
    fn pending_cost_is_separate_and_rolling_usage_starts_at_actual_issuance() {
        let mut cap = limits();
        cap.new_leases_per_day = 1;
        cap.cumulative_seconds_per_day = 60;
        let mut f = Fixture::new(cap.clone(), cap);
        f.reserve(20, &lease(1, &[1]), NOW).unwrap();
        assert_eq!(f.count("authority_signing_quota_usage"), 0);
        let issued = f.finalize(20, NOW + 250).unwrap();
        assert_eq!(issued.issued_at, Some(at(NOW + 250).unwrap()));
        f.active(20, NOW + 250);
        let replay = f.finalize(20, NOW + 251).unwrap();
        assert_eq!(replay.issued_at, issued.issued_at);
        assert_eq!(f.count("authority_signing_quota_usage"), 1);
        assert!(matches!(
            f.reserve(21, &lease(2, &[2]), NOW + WINDOW),
            Err(AuthorityError::Quota)
        ));
        assert!(matches!(
            f.reserve(21, &lease(2, &[2]), NOW + WINDOW + 249),
            Err(AuthorityError::Quota)
        ));
        let next = f.reserve(21, &lease(2, &[2]), NOW + WINDOW + 250).unwrap();
        assert_eq!(next.root_projected.as_ref().unwrap().new_leases_per_day, 1);
        assert_eq!(
            next.root_projected
                .as_ref()
                .unwrap()
                .cumulative_seconds_per_day,
            60
        );
        assert_eq!(next.root_projected.as_ref().unwrap().active_leases, 2);
    }
    #[test]
    fn impossible_unissued_unknown_cannot_admit_finalize_or_cancel() {
        let mut cap = limits();
        cap.new_leases_per_day = 1;
        let mut f = Fixture::new(cap.clone(), cap);
        f.reserve(20, &lease(1, &[1]), NOW).unwrap();
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        primitive_transition(&tx, || mark_unknown(&tx, &f.tenant, &id(20), NOW + 1)).unwrap();
        tx.commit().unwrap();
        assert!(f.cancel(20, NOW + WINDOW + 100).is_err());
        assert!(f.finalize(20, NOW + WINDOW + 100).is_err());
        assert!(f.reserve(21, &lease(2, &[2]), NOW + WINDOW + 100).is_err());
        assert_eq!(f.count("authority_signing_quota_usage"), 0);
    }
    #[test]
    fn distinct_asset_memberships_are_unioned_across_pending_and_issued_costs() {
        let mut cap = limits();
        cap.unique_destinations_per_day = 3;
        let mut f = Fixture::new(cap.clone(), cap);
        f.reserve(20, &lease(1, &[1, 2]), NOW).unwrap();
        f.finalize(20, NOW).unwrap();
        f.active(20, NOW);
        let next = f.reserve(21, &lease(2, &[2, 3]), NOW).unwrap();
        assert_eq!(
            next.root_projected
                .as_ref()
                .unwrap()
                .unique_destinations_per_day,
            3
        );
        assert_eq!(next.project_projected.unique_destinations_per_day, 3);
        assert!(matches!(
            f.reserve(22, &lease(3, &[3, 4]), NOW),
            Err(AuthorityError::Quota)
        ));
        let mut bad = lease(4, &[1, 1]);
        assert!(f.reserve(23, &bad, NOW).is_err());
        bad.destination_asset_ids = (0..4097).map(id).collect();
        assert!(f.reserve(23, &bad, NOW).is_err());
        assert_eq!(f.count("authority_signing_quota_reservations"), 2);
    }
    #[test]
    fn repeated_lease_or_changed_reservation_cannot_charge_again() {
        let mut f = Fixture::new(limits(), limits());
        let cost = lease(1, &[1]);
        f.reserve(20, &cost, NOW).unwrap();
        assert!(matches!(
            f.reserve(21, &cost, NOW),
            Err(AuthorityError::Conflict)
        ));
        assert!(matches!(
            f.reserve(20, &lease(2, &[2]), NOW),
            Err(AuthorityError::Conflict)
        ));
        f.finalize(20, NOW + 1).unwrap();
        assert!(matches!(
            f.cancel(20, NOW + 1),
            Err(AuthorityError::Conflict)
        ));
        f.finalize(20, NOW + 2).unwrap();
        assert_eq!(f.count("authority_signing_quota_usage"), 1);
    }
    #[test]
    fn unissued_cancellation_releases_projected_cost_but_never_issued_usage() {
        let mut cap = limits();
        cap.new_leases_per_day = 1;
        cap.cumulative_seconds_per_day = 60;
        let mut f = Fixture::new(cap.clone(), cap);
        f.reserve(20, &lease(1, &[1]), NOW).unwrap();
        f.cancel(20, NOW).unwrap();
        f.cancel(20, NOW).unwrap();
        f.reserve(21, &lease(2, &[2]), NOW).unwrap();
        f.finalize(21, NOW).unwrap();
        f.active(21, NOW);
        assert!(f.cancel(21, NOW).is_err());
        assert!(matches!(
            f.reserve(22, &lease(3, &[3]), NOW),
            Err(AuthorityError::Quota)
        ));
        assert_eq!(f.count("authority_signing_quota_usage"), 1);
    }
    #[test]
    fn config_revisions_lifetimes_revocation_and_permanent_project_binding_are_enforced() {
        let mut f = Fixture::new(limits(), limits());
        assert!(matches!(
            f.store
                .pin_signing_root_quota(&f.tenant, &pin(limits()), None, NOW),
            Err(AuthorityError::Conflict)
        ));
        let before = f.count("authority_audit");
        assert_eq!(
            f.store
                .pin_signing_root_quota(&f.tenant, &pin(limits()), Some(1), NOW)
                .unwrap(),
            1
        );
        assert_eq!(f.count("authority_audit"), before);
        f.reserve(20, &change(1), NOW).unwrap();
        let mut next = pin(limits());
        next.limits.concurrent_deployments = 99;
        assert_eq!(
            f.store
                .pin_signing_root_quota(&f.tenant, &next, Some(1), NOW + 1)
                .unwrap(),
            2
        );
        assert!(matches!(
            f.finalize(20, NOW + 1),
            Err(AuthorityError::Binding)
        ));
        f.cancel(20, NOW + 1).unwrap();
        let mut other = pin(limits());
        other.root_id = id(11);
        f.store
            .pin_signing_root_quota(&f.tenant, &other, None, NOW + 1)
            .unwrap();
        assert!(matches!(
            f.store
                .pin_signing_project_quota(&f.tenant, &other, Some(1), NOW + 1),
            Err(AuthorityError::Binding)
        ));
        f.store
            .revoke_signing_root_quota(&f.tenant, &id(10), 2, NOW + 1)
            .unwrap();
        assert!(matches!(
            f.reserve(21, &change(2), NOW + 1),
            Err(AuthorityError::Binding)
        ));
        assert_eq!(f.count("authority_signing_quota_revocations"), 1);
        let tx = f.store.connection.transaction().unwrap();
        assert!(!configuration_available(&tx, &f.tenant, NOW + 1).unwrap());
    }
    #[test]
    fn future_observation_fences_other_projects_without_lowering_clocks() {
        let mut f = Fixture::new(limits(), limits());
        let other = AuthorityTenant::new(&id(1), &id(3)).unwrap();
        f.store
            .provision_target_metadata_project(&other, NOW)
            .unwrap();
        f.store
            .pin_signing_project_quota(&other, &pin(limits()), None, NOW)
            .unwrap();
        f.store
            .observe_signing_quota_time(&f.tenant, NOW + 1000)
            .unwrap();
        assert!(matches!(
            f.store.observe_signing_quota_time(&other, NOW + 999),
            Err(AuthorityError::Time)
        ));
        let tx = f.store.connection.transaction().unwrap();
        assert!(matches!(
            configuration_available(&tx, &other, NOW + 999),
            Err(AuthorityError::Time)
        ));
        assert!(configuration_available(&tx, &other, NOW + 1000).unwrap());
    }
    #[test]
    fn audit_failure_rolls_back_pin_reservation_and_actual_issuance_as_one_unit() {
        let mut f = Fixture::new(limits(), limits());
        f.store.connection.execute_batch("CREATE TRIGGER quota_test_no_audit BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
        let mut changed = pin(limits());
        changed.limits.concurrent_deployments = 99;
        assert!(
            f.store
                .pin_signing_root_quota(&f.tenant, &changed, Some(1), NOW + 1)
                .is_err()
        );
        assert_eq!(f.count("authority_signing_quota_pins"), 2);
        f.store
            .connection
            .execute_batch("DROP TRIGGER quota_test_no_audit")
            .unwrap();
        {
            let tx = f
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            reserve(&tx, &f.tenant, &id(20), &lease(1, &[1]), NOW + 301, NOW + 1).unwrap();
            tx.execute_batch("CREATE TRIGGER quota_test_no_audit BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
            assert!(audit(&tx, &f.tenant, "signing_intent_prepared", &id(20), NOW + 1).is_err());
        }
        assert_eq!(f.count("authority_signing_quota_reservations"), 0);
        assert_eq!(f.count("authority_signing_quota_destinations"), 0);
        f.reserve(20, &lease(1, &[1]), NOW + 1).unwrap();
        {
            let tx = f
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            primitive_finalize(&tx, &f.tenant, &id(20), NOW + 2).unwrap();
            tx.execute_batch("CREATE TRIGGER quota_test_no_audit BEFORE INSERT ON authority_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
            assert!(audit(&tx, &f.tenant, "signing_finalized", &id(20), NOW + 2).is_err());
        }
        assert_eq!(f.count("authority_signing_quota_usage"), 0);
        let tx = f.store.connection.transaction().unwrap();
        assert_eq!(read(&tx, &f.tenant, &id(20)).unwrap().state, "reserved");
    }
    #[test]
    fn corrupt_cost_destination_or_issuance_projection_cannot_create_credit() {
        for sql in [
            "UPDATE authority_signing_quota_reservations SET lease_seconds=61",
            "DELETE FROM authority_signing_quota_destinations",
            "UPDATE authority_signing_quota_usage SET charged_at=charged_at+1",
            "UPDATE authority_signing_quota_reservations SET dispatch_slots=0",
        ] {
            let mut f = Fixture::new(limits(), limits());
            f.reserve(20, &lease(1, &[1]), NOW).unwrap();
            f.finalize(20, NOW).unwrap();
            // Simulate storage corruption after bypassing the append-only SQL
            // guards; ordinary callers cannot perform these mutations.
            f.store.connection.execute_batch("DROP TRIGGER authority_signing_quota_reservations_projection; DROP TRIGGER authority_signing_quota_reservations_immutable; DROP TRIGGER authority_signing_quota_destinations_no_delete; DROP TRIGGER authority_signing_quota_usage_no_update;").unwrap();
            f.store.connection.execute_batch(sql).unwrap();
            assert!(f.reserve(21, &lease(2, &[2]), NOW).is_err(), "{sql}");
        }
    }
    #[test]
    fn immutable_quota_inputs_usage_and_clock_guards_reject_direct_rewrites() {
        let mut f = Fixture::new(limits(), limits());
        f.reserve(20, &lease(1, &[1]), NOW).unwrap();
        f.finalize(20, NOW).unwrap();
        for sql in [
            "UPDATE authority_signing_quota_pins SET root_id=root_id",
            "DELETE FROM authority_signing_quota_pins",
            "UPDATE authority_signing_quota_reservations SET cost_hash=cost_hash",
            "DELETE FROM authority_signing_quota_reservations",
            "UPDATE authority_signing_quota_reservations SET issued_at=issued_at",
            "DELETE FROM authority_signing_quota_destinations",
            "UPDATE authority_signing_quota_usage SET charged_at=charged_at+1",
            "DELETE FROM authority_signing_quota_usage",
            "UPDATE authority_signing_quota_clocks SET observed_at=observed_at-1",
            "DELETE FROM authority_signing_quota_clocks",
        ] {
            assert!(f.store.connection.execute_batch(sql).is_err(), "{sql}");
        }
        f.active(20, NOW);
        let tx = f.store.connection.transaction().unwrap();
        assert_eq!(read(&tx, &f.tenant, &id(20)).unwrap().state, "active");
    }
    #[test]
    fn long_terminal_zero_cost_history_uses_bounded_partial_index_scans() {
        let mut f = Fixture::new(limits(), limits());
        f.reserve(20, &change(1), NOW).unwrap();
        f.cancel(20, NOW).unwrap();
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        // Primitive accounting history is terminal only when it was cancelled
        // before issuance. Unsigned active delivery is still a live obligation.
        // Cloned snapshot identifiers remain internally consistent; no usage or
        // issued timestamp is fabricated for these unissued cancellation rows.
        primitive_transition(&tx, || {
            tx.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10001)
          INSERT INTO authority_signing_quota_reservations SELECT org_id,project_id,printf('00000000-0000-0000-0001-%012x',n.x),root_id,plan_id,plan_hash,lease_id,lease_seconds,cost_hash,cost_bytes,CAST(json_set(CAST(snapshot_bytes AS TEXT),'$.reservation_id',printf('00000000-0000-0000-0001-%012x',n.x)) AS BLOB),reserved_at,reserved_until,'reserved',NULL,active_slots,1 FROM authority_signing_quota_reservations,n WHERE reservation_id='00000000-0000-0000-0000-000000000014';
          INSERT INTO authority_signing_quota_transitions SELECT org_id,project_id,reservation_id,1,'released',NULL,0,0,reserved_at,'released',NULL,NULL,NULL FROM authority_signing_quota_reservations WHERE reservation_id LIKE '00000000-0000-0000-0001-%';
          UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0 WHERE reservation_id LIKE '00000000-0000-0000-0001-%';")?;
            Ok(())
        }).unwrap();
        assert_eq!(
            tx.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM authority_signing_quota_usage",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            tx.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM authority_signing_quota_reservations",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            10002
        );
        let remaining = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1000));
        let counter = remaining.clone();
        tx.progress_handler(
            100,
            Some(move || counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed) == 0),
        );
        let result = reserve(&tx, &f.tenant, &id(999), &change(999), NOW + 300, NOW);
        tx.progress_handler(0, None::<fn() -> bool>);
        let saved = result.unwrap();
        assert_eq!(
            saved
                .root_projected
                .as_ref()
                .unwrap()
                .concurrent_deployments,
            1
        );
        assert_eq!(saved.project_projected.new_leases_per_day, 0);
        assert!(remaining.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }
    #[test]
    fn separate_connections_and_projects_cannot_oversubscribe_one_root() {
        use std::sync::{Arc, Barrier};
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir().unwrap();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let mut root = limits();
        root.concurrent_deployments = 1;
        for p in 2..10 {
            let tenant = AuthorityTenant::new(&id(1), &id(p)).unwrap();
            store
                .provision_target_metadata_project(&tenant, NOW)
                .unwrap();
            if p == 2 {
                store
                    .pin_signing_root_quota(&tenant, &pin(root.clone()), None, NOW)
                    .unwrap();
            }
            store
                .pin_signing_project_quota(&tenant, &pin(limits()), None, NOW)
                .unwrap();
        }
        drop(store);
        let barrier = Arc::new(Barrier::new(8));
        let handles = (2..10)
            .map(|p| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut store = AuthorityStore::open(path).unwrap();
                    let tenant = AuthorityTenant::new(&id(1), &id(p)).unwrap();
                    barrier.wait();
                    let tx = store
                        .connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .unwrap();
                    if reserve(&tx, &tenant, &id(100 + p), &change(p), NOW + 300, NOW).is_ok() {
                        tx.commit().unwrap();
                        true
                    } else {
                        false
                    }
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>(),
            1
        );
        let mut reopened = AuthorityStore::open(&path).unwrap();
        let tenant = AuthorityTenant::new(&id(1), &id(2)).unwrap();
        let tx = reopened
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(matches!(
            reserve(&tx, &tenant, &id(999), &change(999), NOW + 300, NOW),
            Err(AuthorityError::Quota)
        ));
    }
}
