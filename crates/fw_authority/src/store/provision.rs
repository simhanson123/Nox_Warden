//! Privileged local provisioning primitives. The embedding authority must
//! authenticate its administrator; these methods are never controller routes.
use super::records;
use super::*;
use fw_webauthn::{AuthenticationResponse, AuthenticationState};

impl AuthorityStore {
    /// Pin an externally established human identity. A second principal cannot
    /// alias the same issuer/subject inside this tenant to manufacture a quorum.
    pub fn provision_principal(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        issuer: &str,
        subject: &str,
        now: i64,
    ) -> Result<()> {
        identifier(principal)?;
        time(now)?;
        for (value, limit) in [(issuer, 2048), (subject, 512)] {
            if value.is_empty()
                || value.chars().count() > limit
                || value.chars().any(char::is_control)
            {
                return Err(invalid("authority principal identity"));
            }
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO authority_projects VALUES(?,?,1)",
            params![tenant.org_id, tenant.project_id],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO authority_audit_heads VALUES(?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                [0u8; 8].as_slice(),
                [0u8; 32].as_slice()
            ],
        )?;
        let existing: Option<(String,String)> = tx.query_row(
            "SELECT issuer,subject FROM authority_principals WHERE org_id=? AND project_id=? AND principal_id=?",
            params![tenant.org_id,tenant.project_id,principal], |r| Ok((r.get(0)?,r.get(1)?))
        ).optional()?;
        if let Some(existing) = existing {
            if existing != (issuer.into(), subject.into()) {
                return Err(AuthorityError::Conflict);
            }
            tx.commit()?;
            return Ok(());
        }
        let alias: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_principals WHERE org_id=? AND project_id=? AND issuer=? AND subject=?)",
            params![tenant.org_id,tenant.project_id,issuer,subject], |r| r.get(0)
        )?;
        if alias {
            return Err(AuthorityError::Conflict);
        }
        tx.execute(
            "INSERT INTO authority_principals VALUES(?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                principal,
                issuer,
                subject,
                now
            ],
        )?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "principal_provisioned", principal, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Store a pending public key after independent trusted enrollment. A
    /// controller credential, registration response or session is not enrollment.
    pub fn pin_credential(
        &mut self,
        tenant: &AuthorityTenant,
        credential: &Credential,
        not_before: i64,
        not_after: i64,
        now: i64,
    ) -> Result<()> {
        interval(not_before, not_after, now)?;
        identifier(credential.principal_id())?;
        let fingerprint = credential
            .key_fingerprint()
            .map_err(|_| invalid("authority credential key"))?;
        let public_key_hash = hash(
            &credential
                .public_key_fingerprint()
                .map_err(|_| invalid("authority public key"))?,
        )?;
        let canonical = bytes(credential)?;
        if canonical.len() > 65536 {
            return Err(invalid("authority credential size"));
        }
        let id = credential.id();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        records::principal(&tx, tenant, credential.principal_id(), now)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_credentials WHERE org_id=? AND project_id=? AND credential_id=?)",
            params![tenant.org_id,tenant.project_id,id], |r| r.get(0)
        )?;
        if exists {
            return Err(AuthorityError::Conflict);
        }
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM authority_credentials WHERE org_id=? AND project_id=? AND principal_id=? AND state!='revoked'",
            params![tenant.org_id,tenant.project_id,credential.principal_id()], |r| r.get(0)
        )?;
        if count >= fw_webauthn::MAX_CREDENTIALS as i64 {
            return Err(AuthorityError::Quota);
        }
        tx.execute(
            "INSERT INTO authority_credentials(org_id,project_id,credential_id,principal_id,key_fingerprint,credential_bytes,revision,state,not_before,not_after,pinned_at)
             VALUES(?,?,?,?,?,?,1,'pending',?,?,?)",
            params![tenant.org_id,tenant.project_id,id,credential.principal_id(),hash(&fingerprint)?,canonical,not_before,not_after,now]
        )?;
        migrations::insert_public_key(&tx, tenant, &id, &public_key_hash)?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "credential_pinned", &id, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Start a distinct authority-owned possession proof for a pending key.
    pub fn begin_credential_activation(
        &mut self,
        tenant: &AuthorityTenant,
        credential_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<CredentialActivation> {
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = records::credential(&tx, tenant, credential_id)?;
        current.require(&current.principal_id, "pending", now)?;
        if now < current.pinned_at {
            return Err(AuthorityError::Time);
        }
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM authority_activations WHERE org_id=? AND project_id=? AND credential_id=? AND consumed_at IS NULL AND expires_at>?",
            params![tenant.org_id,tenant.project_id,credential_id,now], |r| r.get(0)
        )?;
        if count >= MAX_OUTSTANDING {
            return Err(AuthorityError::Quota);
        }
        let ceremony = verifier
            .begin_authentication(
                &current.principal_id,
                std::slice::from_ref(&current.credential),
            )
            .map_err(|_| invalid("authority credential activation"))?;
        let activation_id = new_id()?;
        let expires_at = (now + fw_webauthn::CEREMONY_SECONDS).min(current.not_after);
        tx.execute(
            "INSERT INTO authority_activations(org_id,project_id,activation_id,credential_id,credential_revision,state_bytes,issued_at,expires_at)
             VALUES(?,?,?,?,?,?,?,?)",
            params![tenant.org_id,tenant.project_id,activation_id,credential_id,current.revision,bytes(&ceremony.state)?,now,expires_at]
        )?;
        audit(
            &tx,
            tenant,
            "credential_activation_issued",
            &activation_id,
            now,
        )?;
        tx.commit()?;
        Ok(CredentialActivation {
            activation_id,
            options: ceremony.options,
        })
    }

    /// Atomically verify possession, update the counter and activate the pinned
    /// key. Invalid signatures consume an attempt, never a successful ceremony.
    pub fn finish_credential_activation(
        &mut self,
        tenant: &AuthorityTenant,
        activation_id: &str,
        response: &AuthenticationResponse,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<()> {
        identifier(activation_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (credential_id,revision,state_bytes,issued_at,expires_at,attempts,consumed_at):
            (String,i64,Vec<u8>,i64,i64,i64,Option<i64>) = tx.query_row(
            "SELECT credential_id,credential_revision,state_bytes,issued_at,expires_at,attempts,consumed_at
             FROM authority_activations WHERE org_id=? AND project_id=? AND activation_id=?",
            params![tenant.org_id,tenant.project_id,activation_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))
        ).optional()?.ok_or(AuthorityError::Binding)?;
        if consumed_at.is_some() {
            return Err(AuthorityError::Conflict);
        }
        if now < issued_at || now >= expires_at {
            return Err(AuthorityError::Time);
        }
        if attempts >= MAX_ATTEMPTS {
            return Err(AuthorityError::Quota);
        }
        let current = records::credential(&tx, tenant, &credential_id)?;
        current.require(&current.principal_id, "pending", now)?;
        if current.revision != revision || now < current.pinned_at {
            return Err(AuthorityError::Binding);
        }
        let state: AuthenticationState = decode(&state_bytes)?;
        let updated = match verifier.finish_authentication(&state, response, &current.credential) {
            Ok(updated) => updated,
            Err(_) => {
                tx.execute("UPDATE authority_activations SET attempts=attempts+1 WHERE org_id=? AND project_id=? AND activation_id=?",
                    params![tenant.org_id,tenant.project_id,activation_id])?;
                audit(
                    &tx,
                    tenant,
                    "credential_activation_failed",
                    activation_id,
                    now,
                )?;
                tx.commit()?;
                return Err(AuthorityError::Signature);
            }
        };
        if updated
            .key_fingerprint()
            .map_err(|_| invalid("authority credential key"))?
            != current.fingerprint
        {
            return Err(AuthorityError::Binding);
        }
        tx.execute(
            "UPDATE authority_credentials SET credential_bytes=?,revision=revision+1,state='active',activated_at=?
             WHERE org_id=? AND project_id=? AND credential_id=?",
            params![bytes(&updated)?,now,tenant.org_id,tenant.project_id,credential_id]
        )?;
        tx.execute("UPDATE authority_activations SET consumed_at=? WHERE org_id=? AND project_id=? AND activation_id=?",
            params![now,tenant.org_id,tenant.project_id,activation_id])?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "credential_activated", &credential_id, now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn grant_role(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        role: ApprovalRole,
        not_before: i64,
        not_after: i64,
        now: i64,
    ) -> Result<String> {
        identifier(principal)?;
        interval(not_before, not_after, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        records::principal(&tx, tenant, principal, now)?;
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_roles WHERE org_id=? AND project_id=? AND principal_id=? AND role=? AND revoked_at IS NULL)",
            params![tenant.org_id,tenant.project_id,principal,role_name(role)], |r| r.get(0)
        )?;
        if current {
            return Err(AuthorityError::Conflict);
        }
        let membership_id = new_id()?;
        tx.execute(
            "INSERT INTO authority_roles VALUES(?,?,?,?,?,?,?,?,?,NULL)",
            params![
                tenant.org_id,
                tenant.project_id,
                membership_id,
                principal,
                role_name(role),
                not_before,
                not_after,
                1,
                now
            ],
        )?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "role_granted", &membership_id, now)?;
        tx.commit()?;
        Ok(membership_id)
    }

    pub fn revoke_role(
        &mut self,
        tenant: &AuthorityTenant,
        membership_id: &str,
        now: i64,
    ) -> Result<()> {
        identifier(membership_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let role = records::role(&tx, tenant, membership_id)?;
        if now < role.granted_at {
            return Err(AuthorityError::Time);
        }
        if role.revoked_at.is_none() {
            tx.execute("UPDATE authority_roles SET revoked_at=?,revision=revision+1 WHERE org_id=? AND project_id=? AND membership_id=?",
                params![now,tenant.org_id,tenant.project_id,membership_id])?;
            bump_security(&tx, tenant)?;
            audit(&tx, tenant, "role_revoked", membership_id, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn revoke_credential(
        &mut self,
        tenant: &AuthorityTenant,
        credential_id: &str,
        now: i64,
    ) -> Result<()> {
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = records::credential(&tx, tenant, credential_id)?;
        if now < current.pinned_at || current.activated_at.is_some_and(|at| now < at) {
            return Err(AuthorityError::Time);
        }
        if current.state != "revoked" {
            tx.execute("UPDATE authority_credentials SET state='revoked',revoked_at=?,revision=revision+1 WHERE org_id=? AND project_id=? AND credential_id=?",
                params![now,tenant.org_id,tenant.project_id,credential_id])?;
            bump_security(&tx, tenant)?;
            audit(&tx, tenant, "credential_revoked", credential_id, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Register complete immutable objects obtained by a trusted importer.
    /// This checks contracts and binding, not the truth of referenced gates.
    pub fn register_plan(
        &mut self,
        tenant: &AuthorityTenant,
        plan: &Value,
        requirements: &Value,
        now: i64,
    ) -> Result<()> {
        time(now)?;
        let validated =
            subject::validate_subject(&tenant.org_id, &tenant.project_id, plan, requirements, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        security_revision(&tx, tenant)?;
        let existing: Option<Vec<u8>> = tx.query_row(
            "SELECT canonical_bytes FROM authority_plans WHERE org_id=? AND project_id=? AND plan_id=?",
            params![tenant.org_id,tenant.project_id,validated.plan_id], |r| r.get(0)
        ).optional()?;
        if let Some(existing) = existing {
            let resolved = records::plan(&tx, tenant, &validated.plan_id, now)?;
            if existing != validated.plan_bytes
                || resolved.requirements_bytes != validated.requirements_bytes
            {
                return Err(AuthorityError::Conflict);
            }
            tx.commit()?;
            return Ok(());
        }
        let requirements_hash = hash(&validated.requirements_hash)?;
        let existing: Option<Vec<u8>> = tx.query_row(
            "SELECT canonical_bytes FROM authority_requirements WHERE org_id=? AND project_id=? AND requirements_hash=?",
            params![tenant.org_id,tenant.project_id,requirements_hash], |r| r.get(0)
        ).optional()?;
        if let Some(existing) = existing {
            if existing != validated.requirements_bytes {
                return Err(AuthorityError::Conflict);
            }
        } else {
            tx.execute(
                "INSERT INTO authority_requirements VALUES(?,?,?,?,?,?,?)",
                params![
                    tenant.org_id,
                    tenant.project_id,
                    requirements_hash,
                    validated.profile,
                    validated.max_approval_age_seconds,
                    validated.author_may_approve,
                    validated.requirements_bytes
                ],
            )?;
            for role in &validated.required_roles {
                tx.execute(
                    "INSERT INTO authority_requirement_roles VALUES(?,?,?,?)",
                    params![
                        tenant.org_id,
                        tenant.project_id,
                        requirements_hash,
                        role_name(*role)
                    ],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO authority_plans VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                validated.plan_id,
                plan_kind_name(validated.plan_kind),
                hash(&validated.plan_hash)?,
                requirements_hash,
                validated.author_id,
                validated.created_at,
                validated.valid_until,
                now,
                validated.plan_bytes
            ],
        )?;
        // Repeat normalization checks against the inserted rows before commit.
        records::plan(&tx, tenant, &validated.plan_id, now)?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "plan_registered", &validated.plan_id, now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn retire_plan(&mut self, tenant: &AuthorityTenant, plan_id: &str, now: i64) -> Result<()> {
        identifier(plan_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let registered_at: i64 = tx.query_row(
            "SELECT registered_at FROM authority_plans WHERE org_id=? AND project_id=? AND plan_id=?",
            params![tenant.org_id,tenant.project_id,plan_id], |r| r.get(0)
        ).optional()?.ok_or(AuthorityError::Binding)?;
        if now < registered_at {
            return Err(AuthorityError::Time);
        }
        if tx.execute(
            "INSERT OR IGNORE INTO authority_plan_retirements VALUES(?,?,?,?)",
            params![tenant.org_id, tenant.project_id, plan_id, now],
        )? == 1
        {
            bump_security(&tx, tenant)?;
            audit(&tx, tenant, "plan_retired", plan_id, now)?;
        }
        tx.commit()?;
        Ok(())
    }
}
