use super::*;
use super::{admission::verify_retained_in_tx, records};
use crate::{ApprovalContext, ApprovalPlanRef, ProofVerifier, verify_human_approval_set};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_CANDIDATES: usize = 64;

/// Trusted local registry input. It is never populated from a plan's claims and
/// does not attest that a production bootstrap/manifest signature was checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityBasis {
    pub epoch: u64,
    pub role_policy_hash: String,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AggregationOutcome {
    /// Historical decision predates aggregation; replay never reevaluates it.
    NotEvaluated,
    AuthorityUnavailable,
    Pending,
    BlockedByDissent,
    Approved {
        approval_set_id: String,
        approval_set_hash: String,
    },
    Stale,
}

/// Immutable content verified in a read snapshot, not a signing capability.
/// A future signing transaction must resolve and verify the current records again.
pub struct StoredApprovalSet {
    content: Value,
    hash: String,
    valid_until: i64,
}
impl StoredApprovalSet {
    pub fn content(&self) -> &Value {
        &self.content
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }
}

struct BasisRecord {
    id: String,
    basis: AuthorityBasis,
    pinned_at: i64,
}
impl BasisRecord {
    fn matches(&self, subject: &subject::ValidatedSubject, now: i64) -> bool {
        now >= self.pinned_at
            && now >= self.basis.not_before
            && now < self.basis.not_after
            && self.basis.epoch == subject.authority_epoch
            && self.basis.role_policy_hash == subject.role_policy_hash
    }
}
fn basis_value(
    tenant: &AuthorityTenant,
    id: &str,
    basis: &AuthorityBasis,
    now: i64,
) -> Result<Value> {
    Ok(
        json!({"schema_version":"fw.authority-basis-pin/v1","org_id":tenant.org_id,"project_id":tenant.project_id,
        "basis_id":id,"epoch":basis.epoch.to_string(),"role_policy_hash":basis.role_policy_hash,
        "not_before":at(basis.not_before)?,"not_after":at(basis.not_after)?,"pinned_at":at(now)?}),
    )
}
fn current_basis(tx: &Transaction<'_>, tenant: &AuthorityTenant) -> Result<Option<BasisRecord>> {
    let row=tx.query_row("SELECT p.basis_id,p.epoch,p.role_policy_hash,p.not_before,p.not_after,p.pinned_at,p.content_hash,p.canonical_bytes
        FROM authority_basis_heads h JOIN authority_basis_pins p ON h.org_id=p.org_id AND h.project_id=p.project_id AND h.basis_id=p.basis_id
        WHERE h.org_id=? AND h.project_id=?",params![tenant.org_id,tenant.project_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,
        r.get::<_,Vec<u8>>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?,r.get::<_,Vec<u8>>(6)?,r.get::<_,Vec<u8>>(7)?))).optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    identifier(&row.0)?;
    let epoch = u64::from_be_bytes(
        row.1
            .try_into()
            .map_err(|_| invalid("authority epoch projection"))?,
    );
    let basis = AuthorityBasis {
        epoch,
        role_policy_hash: hash_string(&row.2)?,
        not_before: row.3,
        not_after: row.4,
    };
    interval(basis.not_before, basis.not_after, row.5)?;
    let canonical = bytes(&basis_value(tenant, &row.0, &basis, row.5)?)?;
    if row.7 != canonical || row.6 != hash(&hash_bytes(&canonical))? {
        return Err(invalid("authority basis projection"));
    }
    Ok(Some(BasisRecord {
        id: row.0,
        basis,
        pinned_at: row.5,
    }))
}
fn human(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    principal: &str,
    now: i64,
) -> Result<Option<String>> {
    let row:Option<(String,i64)>=tx.query_row("SELECT human_id,bound_at FROM authority_human_bindings WHERE org_id=? AND project_id=? AND principal_id=?",
        params![tenant.org_id,tenant.project_id,principal],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((id, bound)) = row else {
        return Ok(None);
    };
    identifier(&id)?;
    time(bound)?;
    if now < bound {
        return Ok(None);
    }
    Ok(Some(id))
}

impl AuthorityStore {
    /// Pin current epoch and role policy through the trusted authority operator.
    /// Changes require a strictly greater epoch; same-epoch changes and rollback
    /// are rejected. This does not implement manifest verification or recovery.
    pub fn provision_authority_basis(
        &mut self,
        tenant: &AuthorityTenant,
        basis: &AuthorityBasis,
        now: i64,
    ) -> Result<String> {
        interval(basis.not_before, basis.not_after, now)?;
        hash(&basis.role_policy_hash)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        security_revision(&tx, tenant)?;
        if let Some(current) = current_basis(&tx, tenant)? {
            if now < current.pinned_at {
                return Err(AuthorityError::Time);
            }
            if current.basis == *basis {
                tx.commit()?;
                return Ok(current.id);
            }
            if basis.epoch <= current.basis.epoch {
                return Err(AuthorityError::Conflict);
            }
        }
        let id = new_id()?;
        let canonical = bytes(&basis_value(tenant, &id, basis, now)?)?;
        tx.execute(
            "INSERT INTO authority_basis_pins VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                id,
                basis.epoch.to_be_bytes().as_slice(),
                hash(&basis.role_policy_hash)?,
                basis.not_before,
                basis.not_after,
                now,
                hash(&hash_bytes(&canonical))?,
                canonical
            ],
        )?;
        tx.execute(
            "INSERT INTO authority_basis_heads VALUES(?,?,?,1) ON CONFLICT(org_id,project_id)
            DO UPDATE SET basis_id=excluded.basis_id,revision=authority_basis_heads.revision+1",
            params![tenant.org_id, tenant.project_id, id],
        )?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "authority_basis_pinned", &id, now)?;
        tx.commit()?;
        Ok(id)
    }

    /// Bind a verified external identity to an independently established person.
    /// Known aliases must use the same human ID. The library cannot discover
    /// physical identity from UV or issuer strings, and never imports mappings.
    pub fn bind_human_identity(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        human_id: &str,
        now: i64,
    ) -> Result<()> {
        identifier(principal)?;
        identifier(human_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        records::principal(&tx, tenant, principal, now)?;
        let prior:Option<(String,i64)>=tx.query_row("SELECT human_id,bound_at FROM authority_human_bindings WHERE org_id=? AND project_id=? AND principal_id=?",
            params![tenant.org_id,tenant.project_id,principal],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((prior, bound)) = prior {
            if now < bound {
                return Err(AuthorityError::Time);
            }
            if prior != human_id {
                return Err(AuthorityError::Conflict);
            }
            tx.commit()?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO authority_human_bindings VALUES(?,?,?,?,?)",
            params![tenant.org_id, tenant.project_id, principal, human_id, now],
        )?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "human_identity_bound", principal, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Current read-snapshot eligibility. Retained sets remain immutable when
    /// this returns None; there is no fallback to an older set after revocation.
    pub fn current_approval_set(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<Option<StoredApprovalSet>> {
        identifier(plan_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let result = current_set(&tx, tenant, plan_id, verifier, now)?;
        tx.commit()?;
        Ok(result)
    }

    /// Return current review status and its verified set from one read snapshot.
    /// This never assembles a set or changes an original admission receipt.
    pub fn approval_review_status(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<(AggregationOutcome, Option<StoredApprovalSet>)> {
        identifier(plan_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        // Unknown plans remain an error; inactive known plans have stale authority.
        let (created, registered, expires, retired): (i64, i64, i64, bool) = tx
            .query_row("SELECT p.created_at,p.registered_at,p.valid_until,EXISTS(SELECT 1 FROM authority_plan_retirements r
                WHERE r.org_id=p.org_id AND r.project_id=p.project_id AND r.plan_id=p.plan_id)
                FROM authority_plans p WHERE p.org_id=? AND p.project_id=? AND p.plan_id=?",
                params![tenant.org_id,tenant.project_id,plan_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))
            .optional()?.ok_or(AuthorityError::Binding)?;
        let result = if dissent(&tx, tenant, plan_id)? {
            (AggregationOutcome::BlockedByDissent, None)
        } else if now < created || now < registered || now >= expires || retired {
            (AggregationOutcome::Stale, None)
        } else {
            let subject = records::plan(&tx, tenant, plan_id, now)?;
            match current_basis(&tx, tenant)? {
                None => (AggregationOutcome::AuthorityUnavailable, None),
                Some(basis) if !basis.matches(&subject, now) => (AggregationOutcome::Stale, None),
                Some(_) if human(&tx, tenant, &subject.author_id, now)?.is_none() => {
                    (AggregationOutcome::AuthorityUnavailable, None)
                }
                Some(_) => {
                    if let Some(set) = current_set(&tx, tenant, plan_id, verifier, now)? {
                        (
                            AggregationOutcome::Approved {
                                approval_set_id: set.content["approval_set_id"]
                                    .as_str()
                                    .ok_or(invalid("set identifier"))?
                                    .into(),
                                approval_set_hash: set.hash.clone(),
                            },
                            Some(set),
                        )
                    } else if unmapped_reviewers(&tx, tenant, plan_id, now)? {
                        (AggregationOutcome::AuthorityUnavailable, None)
                    } else {
                        let revoked: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_set_heads h
                            JOIN authority_set_revocations r ON r.org_id=h.org_id AND r.project_id=h.project_id AND r.approval_set_id=h.approval_set_id
                            WHERE h.org_id=? AND h.project_id=? AND h.plan_id=?)",
                            params![tenant.org_id,tenant.project_id,plan_id], |r| r.get(0))?;
                        (
                            if revoked {
                                AggregationOutcome::Stale
                            } else {
                                // Eligible plans can receive fresh human reviews after
                                // old member proofs expire or lose current authority.
                                // The historical set remains unchanged and unusable.
                                AggregationOutcome::Pending
                            },
                            None,
                        )
                    }
                }
            }
        };
        tx.commit()?;
        Ok(result)
    }

    /// Trusted local withdrawal. It does not assert that a dispatched policy was
    /// removed. New grants must independently recheck this retained tombstone.
    pub fn revoke_decision(
        &mut self,
        tenant: &AuthorityTenant,
        approval_id: &str,
        actor: &str,
        now: i64,
    ) -> Result<()> {
        identifier(approval_id)?;
        identifier(actor)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        records::principal(&tx, tenant, actor, now)?;
        let decision = records::decision(&tx, tenant, approval_id)?;
        if now < decision.created_at {
            return Err(AuthorityError::Time);
        }
        if tx.execute("INSERT OR IGNORE INTO authority_decision_revocations VALUES(?,?,?,?,'operator_withdrawal',?)",
            params![tenant.org_id,tenant.project_id,approval_id,actor,now])?==1 {
            bump_security(&tx,tenant)?; audit(&tx,tenant,"approval_decision_revoked",approval_id,now)?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Reject known author aliases at issuance/admission when identity mappings are
/// available. Missing independent identity never becomes a quorum member.
pub(super) fn check_author_alias(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    subject: &subject::ValidatedSubject,
    principal: &str,
    now: i64,
) -> Result<()> {
    if subject.author_may_approve {
        return Ok(());
    }
    if let (Some(author), Some(reviewer)) = (
        human(tx, tenant, &subject.author_id, now)?,
        human(tx, tenant, principal, now)?,
    ) && author == reviewer
    {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}
fn dissent(tx: &Transaction<'_>, tenant: &AuthorityTenant, plan_id: &str) -> Result<bool> {
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_decisions WHERE org_id=? AND project_id=? AND plan_id=? AND decision='reject')",
        params![tenant.org_id,tenant.project_id,plan_id],|r|r.get(0))?)
}
fn unmapped_reviewers(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan_id: &str,
    now: i64,
) -> Result<bool> {
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_decisions d
        JOIN authority_credentials c ON c.org_id=d.org_id AND c.project_id=d.project_id AND c.credential_id=d.credential_id
        JOIN authority_roles r ON r.org_id=d.org_id AND r.project_id=d.project_id AND r.membership_id=d.membership_id
        WHERE d.org_id=? AND d.project_id=? AND d.plan_id=? AND d.decision='approve' AND d.created_at<=? AND d.expires_at>?
        AND c.state='active' AND c.revoked_at IS NULL AND c.not_before<=? AND c.not_after>?
        AND r.revoked_at IS NULL AND r.not_before<=? AND r.not_after>?
        AND NOT EXISTS(SELECT 1 FROM authority_decision_revocations v WHERE v.org_id=d.org_id AND v.project_id=d.project_id AND v.approval_id=d.approval_id)
        AND NOT EXISTS(SELECT 1 FROM authority_human_bindings h WHERE h.org_id=d.org_id AND h.project_id=d.project_id AND h.principal_id=d.principal_id AND h.bound_at<=?))",
        params![tenant.org_id,tenant.project_id,plan_id,now,now,now,now,now,now,now], |r|r.get(0))?)
}
fn revoked_decision(tx: &Transaction<'_>, tenant: &AuthorityTenant, id: &str) -> Result<bool> {
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_decision_revocations WHERE org_id=? AND project_id=? AND approval_id=?)",
        params![tenant.org_id,tenant.project_id,id],|r|r.get(0))?)
}
struct Candidate {
    decision: records::DecisionRecord,
    human: String,
    role: ApprovalRole,
}
fn candidate(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    subject: &subject::ValidatedSubject,
    verifier: &WebAuthn,
    now: i64,
) -> Result<Option<Candidate>> {
    let decision = records::decision(tx, tenant, id)?;
    if decision.approval["decision"] != "approve" || decision.plan_id != subject.plan_id {
        return Err(invalid("approval candidate binding"));
    }
    if now < decision.created_at || now >= decision.expires_at || revoked_decision(tx, tenant, id)?
    {
        return Ok(None);
    }
    let credential = records::credential(tx, tenant, &decision.credential_id)?;
    let role = records::role(tx, tenant, &decision.membership_id)?;
    if credential.state != "active"
        || credential.revoked_at.is_some()
        || now < credential.not_before
        || now >= credential.not_after
        || role.revoked_at.is_some()
        || now < role.not_before
        || now >= role.not_after
    {
        return Ok(None);
    }
    let Some(person) = human(tx, tenant, &decision.principal_id, now)? else {
        return Ok(None);
    };
    let Some(author) = human(tx, tenant, &subject.author_id, now)? else {
        return Ok(None);
    };
    if !subject.author_may_approve && person == author {
        return Ok(None);
    }
    if !subject.required_roles.contains(&role.role) {
        return Ok(None);
    }
    let verified = verify_retained_in_tx(tx, tenant, id, verifier, now)?;
    if verified.decision() != ApprovalDecision::Approve || verified.approval() != &decision.approval
    {
        return Err(AuthorityError::Binding);
    }
    Ok(Some(Candidate {
        decision,
        human: person,
        role: role.role,
    }))
}

// The adapter has no public constructor. Its map contains originals verified
// against the current registry under this caller's still-open transaction.
struct TransactionProofs<'a> {
    values: BTreeMap<&'a str, &'a Value>,
    now: i64,
}
impl ProofVerifier for TransactionProofs<'_> {
    fn verify_webauthn_and_current_role(&self, approval: &Value, now: i64) -> Result<()> {
        let id = approval["approval_id"]
            .as_str()
            .ok_or(AuthorityError::Binding)?;
        if now != self.now || self.values.get(id).copied() != Some(approval) {
            return Err(AuthorityError::Binding);
        }
        Ok(())
    }
}
fn proofs<'a>(candidates: &[&'a Candidate], now: i64) -> TransactionProofs<'a> {
    TransactionProofs {
        values: candidates
            .iter()
            .map(|c| (c.decision.id.as_str(), &c.decision.approval))
            .collect(),
        now,
    }
}
fn context(
    tenant: &AuthorityTenant,
    subject: &subject::ValidatedSubject,
    now: i64,
) -> ApprovalContext {
    ApprovalContext {
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        author_id: subject.author_id.clone(),
        plan_id: subject.plan_id.clone(),
        plan_hash: subject.plan_hash.clone(),
        plan_kind: plan_kind_name(subject.plan_kind).into(),
        plan_valid_until: subject.valid_until,
        authority_epoch: subject.authority_epoch,
        now_unix: now,
    }
}
fn set_value(
    tenant: &AuthorityTenant,
    id: &str,
    subject: &subject::ValidatedSubject,
    members: &[&Candidate],
    created: i64,
    expires: i64,
) -> Result<Value> {
    Ok(
        json!({"schema_version":"f.approval-set/v1","approval_set_id":id,"org_id":tenant.org_id,"project_id":tenant.project_id,
        "plan_ref":ApprovalPlanRef{plan_kind:subject.plan_kind,plan_id:subject.plan_id.clone(),plan_hash:subject.plan_hash.clone()},
        "requirements_hash":subject.requirements_hash,"created_at":at(created)?,"valid_until":at(expires)?,"authority_epoch":subject.authority_epoch.to_string(),
        "kind":"human","approvals":members.iter().map(|c|&c.decision.approval).collect::<Vec<_>>(),"role_policy_hash":subject.role_policy_hash}),
    )
}
fn selection_hash(
    subject: &subject::ValidatedSubject,
    basis: &BasisRecord,
    members: &[&Candidate],
) -> Result<String> {
    canonical_hash(&json!({"schema_version":"fw.approval-selection/v1","plan_hash":subject.plan_hash,"requirements_hash":subject.requirements_hash,
        "basis_id":basis.id,"members":members.iter().map(|c|json!({"approval_id":c.decision.id,"human_id":c.human})).collect::<Vec<_>>()}))
        .map_err(|_|invalid("approval selection hash"))
}
fn expiry(subject: &subject::ValidatedSubject, basis: &BasisRecord, members: &[&Candidate]) -> i64 {
    members
        .iter()
        .map(|c| c.decision.expires_at)
        .fold(subject.valid_until.min(basis.basis.not_after), i64::min)
}

fn current_set(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan_id: &str,
    verifier: &WebAuthn,
    now: i64,
) -> Result<Option<StoredApprovalSet>> {
    let id:Option<String>=tx.query_row("SELECT approval_set_id FROM authority_set_heads WHERE org_id=? AND project_id=? AND plan_id=?",
        params![tenant.org_id,tenant.project_id,plan_id],|r|r.get(0)).optional()?;
    let Some(id) = id else {
        return Ok(None);
    };
    let plan_active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_plans p WHERE org_id=? AND project_id=? AND plan_id=?
        AND created_at<=? AND registered_at<=? AND valid_until>? AND NOT EXISTS(SELECT 1 FROM authority_plan_retirements r
        WHERE r.org_id=p.org_id AND r.project_id=p.project_id AND r.plan_id=p.plan_id))",params![tenant.org_id,tenant.project_id,plan_id,now,now,now],|r|r.get(0))?;
    if !plan_active || dissent(tx, tenant, plan_id)? {
        return Ok(None);
    }
    let subject = records::plan(tx, tenant, plan_id, now)?;
    let Some(basis) = current_basis(tx, tenant)? else {
        return Ok(None);
    };
    if !basis.matches(&subject, now) {
        return Ok(None);
    }
    let revoked:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_set_revocations WHERE org_id=? AND project_id=? AND approval_set_id=?)",
        params![tenant.org_id,tenant.project_id,id],|r|r.get(0))?;
    if revoked {
        return Ok(None);
    }
    let row=tx.query_row("SELECT plan_id,plan_hash,requirements_hash,basis_id,epoch,role_policy_hash,selection_hash,content_hash,created_at,valid_until,canonical_bytes
        FROM authority_approval_sets WHERE org_id=? AND project_id=? AND approval_set_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((
        r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,String>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,
        r.get::<_,Vec<u8>>(6)?,r.get::<_,Vec<u8>>(7)?,r.get::<_,i64>(8)?,r.get::<_,i64>(9)?,r.get::<_,Vec<u8>>(10)?)))?;
    let content: Value = decode(&row.10)?;
    if row.0 != plan_id
        || row.1 != hash(&subject.plan_hash)?
        || row.2 != hash(&subject.requirements_hash)?
        || row.4 != subject.authority_epoch.to_be_bytes()
        || row.5 != hash(&subject.role_policy_hash)?
        || row.7 != hash(&hash_bytes(&row.10))?
    {
        return Err(invalid("approval set projection"));
    }
    if row.3 != basis.id || now < row.8 || now >= row.9 {
        return Ok(None);
    }
    let mut statement=tx.prepare("SELECT approval_id,principal_id,human_id,credential_id,membership_id,role,position FROM authority_approval_set_members
        WHERE org_id=? AND project_id=? AND approval_set_id=? ORDER BY position")?;
    let rows = statement
        .query_map(params![tenant.org_id, tenant.project_id, id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.is_empty() || rows.len() > 3 {
        return Err(invalid("approval set membership count"));
    }
    let mut members = Vec::new();
    for (position, row) in rows.into_iter().enumerate() {
        let Some(member) = candidate(tx, tenant, &row.0, &subject, verifier, now)? else {
            return Ok(None);
        };
        if member.decision.principal_id != row.1
            || member.human != row.2
            || member.decision.credential_id != row.3
            || member.decision.membership_id != row.4
            || role_name(member.role) != row.5
            || row.6 != position as i64
        {
            return Err(invalid("approval member projection"));
        }
        members.push(member);
    }
    let refs = members.iter().collect::<Vec<_>>();
    if refs
        .windows(2)
        .any(|p| p[0].decision.id >= p[1].decision.id)
        || refs.iter().map(|c| &c.human).collect::<BTreeSet<_>>().len() != refs.len()
        || hash(&selection_hash(&subject, &basis, &refs)?)? != row.6
        || expiry(&subject, &basis, &refs) != row.9
        || set_value(tenant, &id, &subject, &refs, row.8, row.9)? != content
    {
        return Err(invalid("approval set canonical membership"));
    }
    let requirements: Value = decode(&subject.requirements_bytes)?;
    let verified = verify_human_approval_set(
        &content,
        &requirements,
        &context(tenant, &subject, now),
        &proofs(&refs, now),
    )?;
    Ok(Some(StoredApprovalSet {
        hash: verified.hash().into(),
        valid_until: verified.valid_until(),
        content,
    }))
}

// At most three roles and 64 candidates. Deterministic matching handles a person
// who can fill either role without greedily blocking the only other reviewer.
fn choose<'a>(
    roles: &[ApprovalRole],
    candidates: &'a [Candidate],
    used: &mut BTreeSet<&'a str>,
    selected: &mut Vec<&'a Candidate>,
) -> bool {
    if roles.is_empty() {
        return true;
    }
    for candidate in candidates.iter().filter(|c| c.role == roles[0]) {
        if !used.insert(candidate.human.as_str()) {
            continue;
        }
        selected.push(candidate);
        if choose(&roles[1..], candidates, used, selected) {
            return true;
        }
        selected.pop();
        used.remove(candidate.human.as_str());
    }
    false
}

pub(super) fn aggregate(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan_id: &str,
    verifier: &WebAuthn,
    now: i64,
) -> Result<AggregationOutcome> {
    if dissent(tx, tenant, plan_id)? {
        return Ok(AggregationOutcome::BlockedByDissent);
    }
    let subject = records::plan(tx, tenant, plan_id, now)?;
    let Some(basis) = current_basis(tx, tenant)? else {
        return Ok(AggregationOutcome::AuthorityUnavailable);
    };
    if !basis.matches(&subject, now) {
        return Ok(AggregationOutcome::Stale);
    }
    if human(tx, tenant, &subject.author_id, now)?.is_none() {
        return Ok(AggregationOutcome::AuthorityUnavailable);
    }
    if let Some(existing) = current_set(tx, tenant, plan_id, verifier, now)? {
        return Ok(AggregationOutcome::Approved {
            approval_set_id: existing.content["approval_set_id"]
                .as_str()
                .ok_or(invalid("set identifier"))?
                .into(),
            approval_set_hash: existing.hash,
        });
    }
    let mut statement=tx.prepare("SELECT approval_id FROM authority_decisions WHERE org_id=? AND project_id=? AND plan_id=? AND decision='approve'
        AND created_at<=? AND expires_at>? ORDER BY approval_id LIMIT ?")?;
    let ids = statement
        .query_map(
            params![
                tenant.org_id,
                tenant.project_id,
                plan_id,
                now,
                now,
                (MAX_CANDIDATES + 1) as i64
            ],
            |r| r.get::<_, String>(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ids.len() > MAX_CANDIDATES {
        return Err(AuthorityError::Quota);
    }
    let mut candidates = Vec::new();
    for id in ids {
        if let Some(candidate) = candidate(tx, tenant, &id, &subject, verifier, now)? {
            candidates.push(candidate);
        }
    }
    let mut roles = subject.required_roles.clone();
    roles.sort_by_key(|r| role_name(*r));
    let mut members = Vec::new();
    if !choose(&roles, &candidates, &mut BTreeSet::new(), &mut members) {
        return Ok(if unmapped_reviewers(tx, tenant, plan_id, now)? {
            AggregationOutcome::AuthorityUnavailable
        } else {
            AggregationOutcome::Pending
        });
    }
    members.sort_by(|a, b| a.decision.id.cmp(&b.decision.id));
    let selection = hash(&selection_hash(&subject, &basis, &members)?)?;
    let used:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_approval_sets WHERE org_id=? AND project_id=? AND selection_hash=?)",
        params![tenant.org_id,tenant.project_id,selection],|r|r.get(0))?;
    if used {
        return Ok(AggregationOutcome::Stale);
    }
    let id = new_id()?;
    let valid_until = expiry(&subject, &basis, &members);
    let content = set_value(tenant, &id, &subject, &members, now, valid_until)?;
    let requirements: Value = decode(&subject.requirements_bytes)?;
    let verified = verify_human_approval_set(
        &content,
        &requirements,
        &context(tenant, &subject, now),
        &proofs(&members, now),
    )?;
    let canonical = bytes(&content)?;
    tx.execute(
        "INSERT INTO authority_approval_sets VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            id,
            plan_id,
            hash(&subject.plan_hash)?,
            hash(&subject.requirements_hash)?,
            basis.id,
            subject.authority_epoch.to_be_bytes().as_slice(),
            hash(&subject.role_policy_hash)?,
            selection,
            hash(verified.hash())?,
            now,
            valid_until,
            canonical
        ],
    )?;
    for (position, member) in members.iter().enumerate() {
        tx.execute(
            "INSERT INTO authority_approval_set_members VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                id,
                member.decision.id,
                plan_id,
                member.decision.principal_id,
                member.human,
                member.decision.credential_id,
                member.decision.membership_id,
                role_name(member.role),
                "approve",
                position as i64
            ],
        )?;
    }
    tx.execute("INSERT INTO authority_set_heads VALUES(?,?,?,?,1) ON CONFLICT(org_id,project_id,plan_id)
        DO UPDATE SET approval_set_id=excluded.approval_set_id,revision=authority_set_heads.revision+1",params![tenant.org_id,tenant.project_id,plan_id,id])?;
    audit(tx, tenant, "approval_set_recorded", &id, now)?;
    Ok(AggregationOutcome::Approved {
        approval_set_id: id,
        approval_set_hash: verified.hash().into(),
    })
}

pub(super) fn persist_result(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    approval_id: &str,
    outcome: &AggregationOutcome,
) -> Result<()> {
    let canonical = bytes(outcome)?;
    tx.execute(
        "INSERT INTO authority_admission_results VALUES(?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            approval_id,
            hash(&hash_bytes(&canonical))?,
            canonical
        ],
    )?;
    Ok(())
}
pub(super) fn retained_result(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    approval_id: &str,
) -> Result<AggregationOutcome> {
    let row:Option<(Vec<u8>,Vec<u8>)>=tx.query_row("SELECT content_hash,canonical_bytes FROM authority_admission_results WHERE org_id=? AND project_id=? AND approval_id=?",
        params![tenant.org_id,tenant.project_id,approval_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((digest, canonical)) = row else {
        return Ok(AggregationOutcome::NotEvaluated);
    };
    if digest != hash(&hash_bytes(&canonical))? {
        return Err(invalid("historical aggregation result hash"));
    }
    decode(&canonical)
}
