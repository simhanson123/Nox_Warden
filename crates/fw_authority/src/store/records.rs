use super::*;
use crate::{
    ApprovalChallengeContext, ApprovalChallengeSubject, ApprovalPlanRef, ApprovalProofState,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) struct CredentialRecord {
    pub id: String,
    pub principal_id: String,
    pub fingerprint: String,
    pub canonical: Vec<u8>,
    pub credential: Credential,
    pub revision: i64,
    pub state: String,
    pub not_before: i64,
    pub not_after: i64,
    pub pinned_at: i64,
    pub activated_at: Option<i64>,
    pub revoked_at: Option<i64>,
}
impl CredentialRecord {
    pub fn require(&self, principal: &str, state: &str, now: i64) -> Result<()> {
        time(now)?;
        if self.principal_id != principal || self.state != state || self.revoked_at.is_some() {
            return Err(AuthorityError::Binding);
        }
        if now < self.not_before
            || now >= self.not_after
            || now < self.pinned_at
            || self.activated_at.is_some_and(|at| now < at)
        {
            return Err(AuthorityError::Time);
        }
        Ok(())
    }
    pub fn snapshot(&self, tenant: &AuthorityTenant) -> Result<Value> {
        Ok(
            json!({"schema_version":"fw.authority-credential-snapshot/v1","org_id":tenant.org_id,
            "project_id":tenant.project_id,"credential_id":self.id,"principal_id":self.principal_id,
            "key_fingerprint":self.fingerprint,"revision":self.revision,"state":self.state,
            "not_before":at(self.not_before)?,"not_after":at(self.not_after)?,"pinned_at":at(self.pinned_at)?,
            "activated_at":self.activated_at.map(at).transpose()?,"revoked_at":self.revoked_at.map(at).transpose()?,
            "credential":serde_json::to_value(&self.credential).map_err(|_| invalid("credential snapshot"))?}),
        )
    }
}

pub(super) fn credential(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<CredentialRecord> {
    let row = tx.query_row(
        "SELECT principal_id,key_fingerprint,credential_bytes,revision,state,not_before,not_after,pinned_at,activated_at,revoked_at
         FROM authority_credentials WHERE org_id=? AND project_id=? AND credential_id=?",
        params![tenant.org_id,tenant.project_id,id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,
            r.get::<_,i64>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?,r.get::<_,i64>(6)?,r.get::<_,i64>(7)?,
            r.get::<_,Option<i64>>(8)?,r.get::<_,Option<i64>>(9)?))
    ).optional()?.ok_or(AuthorityError::Binding)?;
    let stored: Credential = decode(&row.2)?;
    let fingerprint = stored
        .key_fingerprint()
        .map_err(|_| invalid("authority credential key"))?;
    let public_key: Vec<u8> = tx.query_row("SELECT public_key_hash FROM authority_public_key_registry WHERE org_id=? AND project_id=? AND credential_id=?",
        params![tenant.org_id,tenant.project_id,id],|r|r.get(0)).optional()?.ok_or(invalid("authority public key registry"))?;
    if stored.id() != id
        || stored.principal_id() != row.0
        || hash(&fingerprint)? != row.1
        || hash(
            &stored
                .public_key_fingerprint()
                .map_err(|_| invalid("authority public key"))?,
        )? != public_key
    {
        return Err(invalid("authority credential projection"));
    }
    Ok(CredentialRecord {
        id: id.into(),
        principal_id: row.0,
        fingerprint,
        canonical: row.2,
        credential: stored,
        revision: row.3,
        state: row.4,
        not_before: row.5,
        not_after: row.6,
        pinned_at: row.7,
        activated_at: row.8,
        revoked_at: row.9,
    })
}

pub(super) struct RoleRecord {
    pub id: String,
    pub principal_id: String,
    pub role: ApprovalRole,
    pub not_before: i64,
    pub not_after: i64,
    pub revision: i64,
    pub granted_at: i64,
    pub revoked_at: Option<i64>,
}
impl RoleRecord {
    pub fn require(&self, principal: &str, role: ApprovalRole, now: i64) -> Result<()> {
        time(now)?;
        if self.principal_id != principal || self.role != role || self.revoked_at.is_some() {
            return Err(AuthorityError::Binding);
        }
        if now < self.not_before || now >= self.not_after || now < self.granted_at {
            return Err(AuthorityError::Time);
        }
        Ok(())
    }
    pub fn snapshot(&self, tenant: &AuthorityTenant) -> Result<Value> {
        Ok(
            json!({"schema_version":"fw.authority-role-snapshot/v1","org_id":tenant.org_id,"project_id":tenant.project_id,
            "membership_id":self.id,"principal_id":self.principal_id,"role":self.role,"revision":self.revision,
            "not_before":at(self.not_before)?,"not_after":at(self.not_after)?,"granted_at":at(self.granted_at)?,
            "revoked_at":self.revoked_at.map(at).transpose()?}),
        )
    }
}
pub(super) fn role(tx: &Transaction<'_>, tenant: &AuthorityTenant, id: &str) -> Result<RoleRecord> {
    let r = tx.query_row("SELECT principal_id,role,not_before,not_after,revision,granted_at,revoked_at FROM authority_roles
        WHERE org_id=? AND project_id=? AND membership_id=?",params![tenant.org_id,tenant.project_id,id], |r| Ok((
        r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?,
        r.get::<_,i64>(5)?,r.get::<_,Option<i64>>(6)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let kind = serde_json::from_value::<ApprovalRole>(Value::String(r.1))
        .map_err(|_| invalid("authority role"))?;
    Ok(RoleRecord {
        id: id.into(),
        principal_id: r.0,
        role: kind,
        not_before: r.2,
        not_after: r.3,
        revision: r.4,
        granted_at: r.5,
        revoked_at: r.6,
    })
}
pub(super) fn current_role(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    principal: &str,
    kind: ApprovalRole,
    now: i64,
) -> Result<RoleRecord> {
    let id: String = tx.query_row("SELECT membership_id FROM authority_roles WHERE org_id=? AND project_id=? AND principal_id=? AND role=? AND revoked_at IS NULL",
        params![tenant.org_id,tenant.project_id,principal,role_name(kind)],|r|r.get(0)).optional()?.ok_or(AuthorityError::Binding)?;
    let row = role(tx, tenant, &id)?;
    row.require(principal, kind, now)?;
    Ok(row)
}

pub(super) fn principal(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
) -> Result<Value> {
    let (issuer,subject,created_at): (String,String,i64) = tx.query_row("SELECT issuer,subject,created_at FROM authority_principals WHERE org_id=? AND project_id=? AND principal_id=?",
        params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(AuthorityError::Binding)?;
    if now < created_at {
        return Err(AuthorityError::Time);
    }
    Ok(json!({"principal_id":id,"issuer":issuer,"subject":subject,"authentication_time":at(now)?}))
}

pub(super) fn plan(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
) -> Result<subject::ValidatedSubject> {
    let r = tx.query_row("SELECT p.plan_kind,p.plan_hash,p.requirements_hash,p.author_id,p.created_at,p.valid_until,p.registered_at,p.canonical_bytes,
        r.profile,r.max_age,r.author_may_approve,r.canonical_bytes FROM authority_plans p JOIN authority_requirements r
        ON p.org_id=r.org_id AND p.project_id=r.project_id AND p.requirements_hash=r.requirements_hash
        WHERE p.org_id=? AND p.project_id=? AND p.plan_id=?",
        params![tenant.org_id,tenant.project_id,id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,
            r.get::<_,String>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?,r.get::<_,i64>(6)?,r.get::<_,Vec<u8>>(7)?,
            r.get::<_,String>(8)?,r.get::<_,i64>(9)?,r.get::<_,bool>(10)?,r.get::<_,Vec<u8>>(11)?)))
        .optional()?.ok_or(AuthorityError::Binding)?;
    let plan: Value = decode(&r.7)?;
    let requirements: Value = decode(&r.11)?;
    let checked = subject::validate_subject(
        &tenant.org_id,
        &tenant.project_id,
        &plan,
        &requirements,
        r.6,
    )?;
    if checked.plan_id != id
        || plan_kind_name(checked.plan_kind) != r.0
        || hash(&checked.plan_hash)? != r.1
        || hash(&checked.requirements_hash)? != r.2
        || checked.author_id != r.3
        || checked.created_at != r.4
        || checked.valid_until != r.5
        || checked.profile != r.8
        || checked.max_approval_age_seconds != r.9
        || checked.author_may_approve != r.10
    {
        return Err(invalid("authority plan projection"));
    }
    let mut roles = tx.prepare("SELECT role FROM authority_requirement_roles WHERE org_id=? AND project_id=? AND requirements_hash=? ORDER BY role")?;
    let projected = roles
        .query_map(params![tenant.org_id, tenant.project_id, r.2], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut expected = checked
        .required_roles
        .iter()
        .map(|r| role_name(*r).to_string())
        .collect::<Vec<_>>();
    expected.sort();
    if projected != expected {
        return Err(invalid("authority requirements role projection"));
    }
    let retired: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_plan_retirements WHERE org_id=? AND project_id=? AND plan_id=?)",
        params![tenant.org_id,tenant.project_id,id],|r|r.get(0))?;
    if retired {
        return Err(AuthorityError::Binding);
    }
    if now < checked.created_at || now < r.6 || now >= checked.valid_until {
        return Err(AuthorityError::Time);
    }
    Ok(checked)
}
pub(super) fn context(
    tenant: &AuthorityTenant,
    principal: &str,
    subject: &subject::ValidatedSubject,
    role: ApprovalRole,
    decision: ApprovalDecision,
) -> Result<ApprovalChallengeContext> {
    if !subject.required_roles.contains(&role)
        || (!subject.author_may_approve && subject.author_id == principal)
    {
        return Err(AuthorityError::Binding);
    }
    Ok(ApprovalChallengeContext {
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        principal_id: principal.into(),
        subject: ApprovalChallengeSubject::Plan {
            plan_ref: ApprovalPlanRef {
                plan_kind: subject.plan_kind,
                plan_id: subject.plan_id.clone(),
                plan_hash: subject.plan_hash.clone(),
            },
        },
        requirements_hash: subject.requirements_hash.clone(),
        decision,
        role,
        subject_valid_until: subject.valid_until,
    })
}

pub(super) struct ChallengeRecord {
    pub challenge: ApprovalChallenge,
    pub state: ApprovalProofState,
    pub state_bytes: Vec<u8>,
    pub credential_bytes: Vec<u8>,
    pub credential_id: String,
    pub membership_id: String,
    pub credential_revision: i64,
    pub role_revision: i64,
    pub security_revision: i64,
    pub attempts: i64,
    pub consumed_at: Option<i64>,
}
pub(super) fn challenge(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<ChallengeRecord> {
    let r = tx.query_row("SELECT principal_id,plan_id,credential_id,membership_id,role_revision,credential_revision,security_revision,
        role,decision,challenge_hash,nonce_hash,payload_hash,payload_bytes,state_bytes,credential_bytes,issued_at,expires_at,attempts,consumed_at
        FROM authority_challenges WHERE org_id=? AND project_id=? AND challenge_id=?",
        params![tenant.org_id,tenant.project_id,id], |r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,
            r.get::<_,i64>(4)?,r.get::<_,i64>(5)?,r.get::<_,i64>(6)?,r.get::<_,String>(7)?,r.get::<_,String>(8)?,r.get::<_,Vec<u8>>(9)?,
            r.get::<_,Vec<u8>>(10)?,r.get::<_,Vec<u8>>(11)?,r.get::<_,Vec<u8>>(12)?,r.get::<_,Vec<u8>>(13)?,r.get::<_,Vec<u8>>(14)?,
            r.get::<_,i64>(15)?,r.get::<_,i64>(16)?,r.get::<_,i64>(17)?,r.get::<_,Option<i64>>(18)?)))
        .optional()?.ok_or(AuthorityError::Binding)?;
    let challenge = ApprovalChallenge::from_json(&r.12)?;
    let crate::ApprovalChallengeSubject::Plan { plan_ref } = challenge.subject() else {
        return Err(invalid("unsupported stored authority subject"));
    };
    let payload: Value = decode(&r.12)?;
    let nonce = URL_SAFE_NO_PAD
        .decode(
            payload["nonce"]
                .as_str()
                .ok_or(invalid("challenge nonce"))?,
        )
        .map_err(|_| invalid("challenge nonce"))?;
    if challenge.challenge_id() != id
        || challenge.org_id() != tenant.org_id
        || challenge.project_id() != tenant.project_id
        || challenge.principal_id() != r.0
        || plan_ref.plan_id != r.1
        || challenge.canonical_payload() != r.12
        || role_name(challenge.role()) != r.7
        || decision_name(challenge.decision()) != r.8
        || challenge.challenge_bytes().as_slice() != r.9
        || hash(&hash_bytes(&nonce))? != r.10
        || hash(challenge.payload_hash())? != r.11
        || challenge.issued_at() != r.15
        || challenge.expires_at() != r.16
    {
        return Err(invalid("authority challenge projection"));
    }
    let state = ApprovalProofState::from_json(&r.13)?;
    if bytes(&state)? != r.13 {
        return Err(invalid("approval proof state canonical bytes"));
    }
    let pinned: Credential = decode(&r.14)?;
    if pinned.id() != r.2 || pinned.principal_id() != challenge.principal_id() {
        return Err(invalid("challenge credential snapshot"));
    }
    Ok(ChallengeRecord {
        challenge,
        state,
        state_bytes: r.13,
        credential_bytes: r.14,
        credential_id: r.2,
        membership_id: r.3,
        role_revision: r.4,
        credential_revision: r.5,
        security_revision: r.6,
        attempts: r.17,
        consumed_at: r.18,
    })
}

pub(super) struct DecisionRecord {
    pub id: String,
    pub principal_id: String,
    pub challenge_id: String,
    pub plan_id: String,
    pub credential_id: String,
    pub membership_id: String,
    pub idempotency_key: String,
    pub request_hash: Vec<u8>,
    pub evidence_hash: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
    pub approval: Value,
}
pub(super) fn decision(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<DecisionRecord> {
    let r = tx.query_row("SELECT principal_id,challenge_id,plan_id,credential_id,membership_id,decision,idempotency_key,request_hash,
        evidence_hash,content_hash,created_at,expires_at,canonical_bytes FROM authority_decisions WHERE org_id=? AND project_id=? AND approval_id=?",
        params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,
            r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,Vec<u8>>(7)?,r.get::<_,Vec<u8>>(8)?,r.get::<_,Vec<u8>>(9)?,
            r.get::<_,i64>(10)?,r.get::<_,i64>(11)?,r.get::<_,Vec<u8>>(12)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let approval: Value = decode(&r.12)?;
    if hash(&hash_bytes(&r.12))? != r.9
        || approval["approval_id"] != id
        || approval["principal"]["principal_id"] != r.0
        || approval["challenge_id"] != r.1
        || approval["plan_ref"]["plan_id"] != r.2
        || approval["decision"] != r.5
        || approval["assertion_evidence"]["object_hash"] != hash_string(&r.8)?
        || approval["created_at"] != at(r.10)?
        || approval["expires_at"] != at(r.11)?
    {
        return Err(invalid("authority decision projection"));
    }
    Ok(DecisionRecord {
        id: id.into(),
        principal_id: r.0,
        challenge_id: r.1,
        plan_id: r.2,
        credential_id: r.3,
        membership_id: r.4,
        idempotency_key: r.6,
        request_hash: r.7,
        evidence_hash: r.8,
        created_at: r.10,
        expires_at: r.11,
        approval,
    })
}
