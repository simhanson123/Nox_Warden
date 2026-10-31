//! Read/authentication adapter for an independent authority review process.
//! Callers must keep login state private, one-use and bounded. The database
//! transaction additionally rejects changed credential/security snapshots.
use super::*;
use fw_webauthn::{AuthenticationResponse, AuthenticationState};

pub struct ReviewProfile {
    pub state: String,
    pub roles: Vec<ApprovalRole>,
    pub security_revision: i64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLogin {
    pub options: Value,
    state: AuthenticationState,
    org_id: String,
    project_id: String,
    expected_state: String,
    principal: String,
    credential_id: String,
    credential_revision: i64,
    security_revision: i64,
    issued_at: i64,
    expires_at: i64,
}
#[derive(Serialize)]
pub struct ReviewPlan {
    pub plan: Value,
    pub requirements: Value,
    pub plan_hash: String,
    pub requirements_hash: String,
    pub roles: Vec<ApprovalRole>,
}

fn roles(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    principal: &str,
    now: i64,
) -> Result<Vec<ApprovalRole>> {
    records::principal(tx, tenant, principal, now)?;
    let mut found = Vec::new();
    for role in [
        ApprovalRole::Owner,
        ApprovalRole::NetworkReviewer,
        ApprovalRole::ServiceReviewer,
        ApprovalRole::SecurityReviewer,
    ] {
        match records::current_role(tx, tenant, principal, role, now) {
            Ok(_) => found.push(role),
            Err(AuthorityError::Binding | AuthorityError::Time) => {}
            Err(error) => return Err(error),
        }
    }
    if found.is_empty() {
        return Err(AuthorityError::Binding);
    }
    Ok(found)
}
impl AuthorityStore {
    pub fn review_profile(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        credential_id: &str,
        now: i64,
    ) -> Result<ReviewProfile> {
        let tx = self.connection.transaction()?;
        let current = records::credential(&tx, tenant, credential_id)?;
        if current.state != "active" && current.state != "pending" {
            return Err(AuthorityError::Binding);
        }
        current.require(principal, &current.state, now)?;
        let result = ReviewProfile {
            state: current.state,
            roles: roles(&tx, tenant, principal, now)?,
            security_revision: security_revision(&tx, tenant)?,
        };
        tx.commit()?;
        Ok(result)
    }
    pub fn begin_review_login(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        credential_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<ReviewLogin> {
        let tx = self.connection.transaction()?;
        let current = records::credential(&tx, tenant, credential_id)?;
        if current.state != "active" && current.state != "pending" {
            return Err(AuthorityError::Binding);
        }
        current.require(principal, &current.state, now)?;
        roles(&tx, tenant, principal, now)?;
        let ceremony = verifier
            .begin_authentication(principal, &[current.credential])
            .map_err(|_| AuthorityError::Signature)?;
        let login = ReviewLogin {
            options: ceremony.options,
            state: ceremony.state,
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            expected_state: current.state,
            principal: principal.into(),
            credential_id: credential_id.into(),
            credential_revision: current.revision,
            security_revision: security_revision(&tx, tenant)?,
            issued_at: now,
            expires_at: (now + 300).min(current.not_after),
        };
        tx.commit()?;
        Ok(login)
    }
    pub fn finish_review_login(
        &mut self,
        tenant: &AuthorityTenant,
        login: &ReviewLogin,
        assertion: &AuthenticationResponse,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<()> {
        self.finish_review_login_sampled(tenant, login, assertion, verifier, now, true)
    }
    /// The trusted HTTP boundary may sample failed-proof audit writes. This
    /// flag never suppresses successful-proof audit or weakens verification.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_review_login_sampled(
        &mut self,
        tenant: &AuthorityTenant,
        login: &ReviewLogin,
        assertion: &AuthenticationResponse,
        verifier: &WebAuthn,
        now: i64,
        record_failure: bool,
    ) -> Result<()> {
        if tenant.org_id != login.org_id
            || tenant.project_id != login.project_id
            || now < login.issued_at
            || now >= login.expires_at
        {
            return Err(AuthorityError::Binding);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = records::credential(&tx, tenant, &login.credential_id)?;
        if login.expected_state != "pending" && login.expected_state != "active" {
            return Err(AuthorityError::Binding);
        }
        current.require(&login.principal, &login.expected_state, now)?;
        roles(&tx, tenant, &login.principal, now)?;
        if current.revision != login.credential_revision
            || security_revision(&tx, tenant)? != login.security_revision
        {
            return Err(AuthorityError::Binding);
        }
        let updated =
            match verifier.finish_authentication(&login.state, assertion, &current.credential) {
                Ok(updated) => updated,
                Err(_) => {
                    if record_failure {
                        audit(
                            &tx,
                            tenant,
                            "review_login_failed",
                            &login.credential_id,
                            now,
                        )?;
                    }
                    tx.commit()?;
                    return Err(AuthorityError::Signature);
                }
            };
        if updated
            .key_fingerprint()
            .map_err(|_| AuthorityError::Signature)?
            != current.fingerprint
        {
            return Err(AuthorityError::Binding);
        }
        if login.expected_state == "pending" {
            // Public option issuance reserves no durable capacity. Only a real
            // verified proof creates and consumes the retained activation record.
            let activation_id = new_id()?;
            tx.execute("INSERT INTO authority_activations(org_id,project_id,activation_id,credential_id,credential_revision,state_bytes,issued_at,expires_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                params![tenant.org_id,tenant.project_id,activation_id,login.credential_id,current.revision,bytes(&login.state)?,login.issued_at,login.expires_at,now])?;
            tx.execute("UPDATE authority_credentials SET credential_bytes=?,revision=revision+1,state='active',activated_at=? WHERE org_id=? AND project_id=? AND credential_id=?",
                params![bytes(&updated)?,now,tenant.org_id,tenant.project_id,login.credential_id])?;
            bump_security(&tx, tenant)?;
            audit(
                &tx,
                tenant,
                "credential_activated",
                &login.credential_id,
                now,
            )?;
        } else {
            tx.execute("UPDATE authority_credentials SET credential_bytes=?,revision=revision+1 WHERE org_id=? AND project_id=? AND credential_id=?", params![bytes(&updated)?,tenant.org_id,tenant.project_id,login.credential_id])?;
        }
        audit(
            &tx,
            tenant,
            "review_login_verified",
            &login.credential_id,
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn review_plan(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        plan_id: &str,
        now: i64,
    ) -> Result<ReviewPlan> {
        let tx = self.connection.transaction()?;
        let current_roles = roles(&tx, tenant, principal, now)?;
        let checked = records::plan(&tx, tenant, plan_id, now)?;
        let eligible = current_roles
            .into_iter()
            .filter(|role| {
                checked.required_roles.contains(role)
                    && (checked.author_may_approve || checked.author_id != principal)
            })
            .collect();
        let result = ReviewPlan {
            plan: decode(&checked.plan_bytes)?,
            requirements: decode(&checked.requirements_bytes)?,
            plan_hash: checked.plan_hash,
            requirements_hash: checked.requirements_hash,
            roles: eligible,
        };
        tx.commit()?;
        Ok(result)
    }
    /// Bounded newest-first live plan identifiers for the authenticated tenant.
    pub fn review_plan_ids(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        now: i64,
    ) -> Result<Vec<String>> {
        let tx = self.connection.transaction()?;
        roles(&tx, tenant, principal, now)?;
        let ids = {
            let mut query = tx.prepare("SELECT p.plan_id FROM authority_plans p WHERE p.org_id=? AND p.project_id=? AND p.created_at<=? AND p.registered_at<=? AND p.valid_until>? AND NOT EXISTS(SELECT 1 FROM authority_plan_retirements r WHERE r.org_id=p.org_id AND r.project_id=p.project_id AND r.plan_id=p.plan_id) ORDER BY p.created_at DESC,p.plan_id LIMIT 100")?;
            query
                .query_map(
                    params![tenant.org_id, tenant.project_id, now, now, now],
                    |r| r.get(0),
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        tx.commit()?;
        Ok(ids)
    }
}

impl AuthorityStore {
    /// Resolve a bound challenge from authority storage before HTTP admission.
    /// This is not an authorization decision; admission rechecks atomically.
    pub fn review_challenge(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        credential_id: &str,
        challenge_id: &str,
    ) -> Result<ApprovalChallenge> {
        let tx = self.connection.transaction()?;
        let record = records::challenge(&tx, tenant, challenge_id)?;
        if record.challenge.principal_id() != principal || record.credential_id != credential_id {
            return Err(AuthorityError::Binding);
        }
        tx.commit()?;
        Ok(record.challenge)
    }
    /// Bounded own-principal history. Current validity is a read-time hint;
    /// signing must reverify in its independent reservation transaction.
    pub fn review_decisions(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        plan_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<Value> {
        let retained = {
            let tx = self.connection.transaction()?;
            roles(&tx, tenant, principal, now)?;
            records::plan(&tx, tenant, plan_id, now)?;
            let ids = {
                let mut query=tx.prepare("SELECT approval_id FROM authority_decisions WHERE org_id=? AND project_id=? AND principal_id=? AND plan_id=? ORDER BY created_at DESC,approval_id LIMIT 100")?;
                query
                    .query_map(
                        params![tenant.org_id, tenant.project_id, principal, plan_id],
                        |r| r.get::<_, String>(0),
                    )?
                    .collect::<std::result::Result<Vec<_>, _>>()?
            };
            let mut retained = Vec::new();
            for id in ids {
                let record = records::decision(&tx, tenant, &id)?;
                if record.principal_id != principal || record.plan_id != plan_id {
                    return Err(AuthorityError::Binding);
                }
                retained.push((id, record.approval));
            }
            tx.commit()?;
            retained
        };
        let mut result = Vec::new();
        for (id, approval) in retained {
            let current_valid = match self.verify_retained_decision(tenant, &id, verifier, now) {
                Ok(_) => true,
                Err(AuthorityError::Storage(error)) => return Err(AuthorityError::Storage(error)),
                Err(_) => false,
            };
            result.push(json!({"approval":approval,"current_valid":current_valid}));
        }
        Ok(Value::Array(result))
    }
}
