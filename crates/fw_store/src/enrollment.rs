//! Durable, tenant-bound transport enrollment. No method grants firewall authority.
use super::*;
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug)]
pub struct EnrollmentAttempt {
    pub token_hash: String,
    pub csr_hash: String,
    pub key_fingerprint: String,
    pub platform: String,
    pub request_id: String,
    pub nonce: String,
    pub agent_version: String,
}
#[derive(Clone, Debug)]
pub struct EnrollmentReservation {
    pub tenant: Tenant,
    pub target_id: String,
    pub token_id: String,
    pub job_id: String,
    pub name: String,
    pub platform: String,
    pub key_fingerprint: String,
    pub csr_hash: String,
    pub request_id: String,
    pub nonce: String,
    pub agent_version: String,
    pub issued_at: i64,
    pub token_expires_at: i64,
    pub response: Option<Value>,
}
/// Produced from a verified TLS peer certificate fingerprint, then rechecked on writes.
#[derive(Clone, Debug)]
pub struct EnrollmentIdentity {
    pub tenant: Tenant,
    pub target_id: String,
    pub key_fingerprint: String,
    pub certificate_fingerprint: String,
    pub certificate_expires_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenInput {
    name: String,
    platform: String,
    expected_key_fingerprint: String,
    token_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateResponse {
    schema_version: String,
    request_id: String,
    target_id: String,
    certificate_chain_pem: String,
    trust_bundle_hash: String,
    authority_epoch: String,
    issued_at: String,
    expires_at: String,
    renew_after: String,
    mode: String,
}
struct TokenRow {
    tenant: Tenant,
    token_id: String,
    target_id: String,
    principal: String,
    name: String,
    platform: String,
    key_fingerprint: String,
    created_at: i64,
    expires_at: i64,
    state: String,
}

impl Store {
    pub fn create_enrollment_token(
        &self,
        t: &Tenant,
        principal: &str,
        body: &Value,
        key: &str,
        now: i64,
    ) -> Result<RegistryMutation> {
        valid_uuid(principal)?;
        valid_uuid(key)?;
        valid_time(now)?;
        let expires = now
            .checked_add(600)
            .filter(|x| *x <= MAX_TIME)
            .ok_or(StoreError::InvalidInput("token expiry"))?;
        let mut body: TokenInput = serde_json::from_value(body.clone())?;
        body.name = body.name.nfc().collect();
        text(&body.name, 128)?;
        backend(&body.platform)?;
        digest(&body.expected_key_fingerprint)?;
        digest(&body.token_hash)?;
        let body_hash = hash_bytes(&canonical_bytes(&body)?);
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        active_principal(&tx, t, principal)?;
        let old: Option<(String, Vec<u8>)> = tx.query_row(
            "SELECT body_hash,response_bytes FROM enrollment_tokens WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND idempotency_key=?4",
            params![t.org_id,t.project_id,principal,key], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        if let Some((old_hash, response)) = old {
            if old_hash != body_hash {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(RegistryMutation {
                value: serde_json::from_slice(&response)?,
                replayed: true,
            });
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM enrollment_tokens WHERE token_hash=?1)",
            [&body.token_hash],
            |r| r.get(0),
        )?;
        if exists {
            return Err(StoreError::Conflict("TOKEN_ALREADY_REGISTERED"));
        }
        let target_id = Uuid::new_v4().to_string();
        let token_id = Uuid::new_v4().to_string();
        let value = json!({"target_id":target_id,"token_id":token_id,"expires_at":timestamp(expires)?,"status":"unused"});
        let response = canonical_bytes(&value)?;
        tx.execute("INSERT INTO enrollment_tokens VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'unused',?12,?13,?14)",
            params![t.org_id,t.project_id,token_id,target_id,principal,body.name,body.platform,body.expected_key_fingerprint,body.token_hash,now,expires,key,body_hash,response])?;
        append_audit(
            &tx,
            t,
            Some(principal),
            "administration",
            "target",
            Some(&target_id),
            None,
            "success",
            Some("ENROLLMENT_TOKEN_REGISTERED"),
            now,
        )?;
        enqueue(
            &tx,
            t,
            "target",
            &target_id,
            1,
            "target.enrollment_authorized",
            &value,
            now,
        )?;
        tx.commit()?;
        Ok(RegistryMutation {
            value,
            replayed: false,
        })
    }

    /// The caller must cryptographically validate the CSR and supply its DER/public-key hashes.
    /// No token, certificate private key, or CSR private material is accepted by this repository.
    pub fn reserve_enrollment(
        &self,
        attempt: &EnrollmentAttempt,
        now: i64,
    ) -> Result<EnrollmentReservation> {
        valid_time(now)?;
        digest(&attempt.token_hash)?;
        digest(&attempt.csr_hash)?;
        digest(&attempt.key_fingerprint)?;
        backend(&attempt.platform)?;
        valid_uuid(&attempt.request_id)?;
        text(&attempt.agent_version, 256)?;
        if attempt.nonce.len() != 64
            || !attempt
                .nonce
                .bytes()
                .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
        {
            return Err(StoreError::InvalidInput("enrollment nonce"));
        }
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let token = read_token(&tx, &attempt.token_hash)?;
        active_principal(&tx, &token.tenant, &token.principal)?;
        if token.state == "revoked" {
            return Err(StoreError::Conflict("ENROLLMENT_UNAVAILABLE"));
        }
        if now < token.created_at {
            return Err(StoreError::Conflict("ENROLLMENT_CLOCK_REGRESSED"));
        }
        if now >= token.expires_at {
            return Err(StoreError::Conflict("ENROLLMENT_EXPIRED"));
        }
        if attempt.platform != token.platform || attempt.key_fingerprint != token.key_fingerprint {
            return Err(StoreError::Conflict("ENROLLMENT_BINDING_MISMATCH"));
        }
        let job = read_job_for_token(&tx, &token)?;
        if let Some(job) = job {
            if now < job.issued_at {
                return Err(StoreError::Conflict("ENROLLMENT_CLOCK_REGRESSED"));
            }
            if job.csr_hash != attempt.csr_hash
                || job.request_id != attempt.request_id
                || job.nonce != attempt.nonce
                || job.agent_version != attempt.agent_version
            {
                return Err(StoreError::IdempotencyConflict);
            }
            if job.response.is_some() {
                let available: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM target_enrollments WHERE job_id=?1 AND revoked_at IS NULL AND certificate_expires_at>?2)",params![job.job_id,now],|r|r.get(0))?;
                if !available {
                    return Err(StoreError::Conflict("ENROLLMENT_UNAVAILABLE"));
                }
            }
            return Ok(job);
        }
        if token.state != "unused" {
            return Err(StoreError::Integrity("enrollment job missing"));
        }
        let job_id = Uuid::new_v4().to_string();
        let changed=tx.execute("UPDATE enrollment_tokens SET state='reserved' WHERE org_id=?1 AND project_id=?2 AND token_id=?3 AND state='unused'",params![token.tenant.org_id,token.tenant.project_id,token.token_id])?;
        if changed != 1 {
            return Err(StoreError::Conflict("ENROLLMENT_RESERVED"));
        }
        tx.execute(
            "INSERT INTO enrollment_jobs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,NULL)",
            params![
                job_id,
                token.tenant.org_id,
                token.tenant.project_id,
                token.token_id,
                attempt.csr_hash,
                attempt.request_id,
                attempt.nonce,
                attempt.agent_version,
                now
            ],
        )?;
        append_audit(
            &tx,
            &token.tenant,
            Some(&token.principal),
            "authentication",
            "target",
            Some(&token.target_id),
            None,
            "success",
            Some("ENROLLMENT_RESERVED"),
            now,
        )?;
        let result = read_job_for_token(&tx, &token)?
            .ok_or(StoreError::Integrity("enrollment reservation"))?;
        tx.commit()?;
        Ok(result)
    }

    /// Commits a cryptographically verified CA result; repeated issuance never creates another target.
    pub fn complete_enrollment(
        &self,
        job_id: &str,
        certificate_fingerprint: &str,
        response: &Value,
        now: i64,
    ) -> Result<Value> {
        valid_uuid(job_id)?;
        digest(certificate_fingerprint)?;
        valid_time(now)?;
        let response: CertificateResponse = serde_json::from_value(response.clone())?;
        let response_bytes = canonical_bytes(&response)?;
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let token_hash:String=tx.query_row("SELECT t.token_hash FROM enrollment_jobs j JOIN enrollment_tokens t USING(org_id,project_id,token_id) WHERE j.job_id=?1",[job_id],|r|r.get(0)).optional()?.ok_or(StoreError::NotFound)?;
        let token = read_token(&tx, &token_hash)?;
        active_principal(&tx, &token.tenant, &token.principal)?;
        let job =
            read_job_for_token(&tx, &token)?.ok_or(StoreError::Integrity("enrollment job"))?;
        if token.state == "revoked" {
            return Err(StoreError::Conflict("ENROLLMENT_UNAVAILABLE"));
        }
        if now < job.issued_at {
            return Err(StoreError::Conflict("ENROLLMENT_CLOCK_REGRESSED"));
        }
        if now >= token.expires_at {
            return Err(StoreError::Conflict("ENROLLMENT_EXPIRED"));
        }
        let issued = parse_time(&response.issued_at)?;
        let expires = parse_time(&response.expires_at)?;
        let renew = parse_time(&response.renew_after)?;
        if response.schema_version != "f.enrollment-response/v1"
            || response.request_id != job.request_id
            || response.target_id != token.target_id
            || response.mode != "observe"
            || response.authority_epoch != "0"
            || issued != job.issued_at
            || expires <= now
            || expires > issued + 86400
            || renew <= issued
            || renew >= expires
        {
            return Err(StoreError::InvalidInput("enrollment response binding"));
        }
        digest(&response.trust_bundle_hash)?;
        if !(128..=32768).contains(&response.certificate_chain_pem.len())
            || !response
                .certificate_chain_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
            || response.certificate_chain_pem.contains("PRIVATE KEY")
        {
            return Err(StoreError::InvalidInput("certificate chain"));
        }
        if let Some(old) = job.response {
            let old_fp: String = tx.query_row(
                "SELECT certificate_fingerprint FROM enrollment_jobs WHERE job_id=?1",
                [job_id],
                |r| r.get(0),
            )?;
            let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM target_enrollments WHERE job_id=?1 AND revoked_at IS NULL AND certificate_expires_at>?2)",params![job_id,now],|r|r.get(0))?;
            if !active {
                return Err(StoreError::Conflict("ENROLLMENT_UNAVAILABLE"));
            }
            if old_fp != certificate_fingerprint || canonical_bytes(&old)? != response_bytes {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(old);
        }
        if token.state != "reserved" {
            return Err(StoreError::Conflict("ENROLLMENT_NOT_RESERVED"));
        }
        tx.execute(
            "INSERT INTO targets VALUES(?1,?2,?3,?4,?5,'observe_only')",
            params![
                token.tenant.org_id,
                token.tenant.project_id,
                token.target_id,
                token.platform,
                backend(&token.platform)?
            ],
        )?;
        tx.execute("UPDATE enrollment_jobs SET certificate_fingerprint=?2,response_bytes=?3 WHERE job_id=?1 AND response_bytes IS NULL",params![job_id,certificate_fingerprint,response_bytes])?;
        tx.execute(
            "INSERT INTO target_enrollments VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL)",
            params![
                token.tenant.org_id,
                token.tenant.project_id,
                token.target_id,
                job_id,
                token.name,
                token.key_fingerprint,
                certificate_fingerprint,
                response.certificate_chain_pem,
                issued,
                expires
            ],
        )?;
        tx.execute("UPDATE enrollment_tokens SET state='consumed' WHERE org_id=?1 AND project_id=?2 AND token_id=?3 AND state='reserved'",params![token.tenant.org_id,token.tenant.project_id,token.token_id])?;
        append_audit(
            &tx,
            &token.tenant,
            Some(&token.principal),
            "registry",
            "target",
            Some(&token.target_id),
            None,
            "success",
            Some("TARGET_ENROLLED"),
            now,
        )?;
        enqueue(
            &tx,
            &token.tenant,
            "target",
            &token.target_id,
            1,
            "target.enrolled",
            &json!({"target_id":token.target_id,"state":"observe_only"}),
            now,
        )?;
        super::collections::capture_enrollment(&tx, &token.tenant, &token.target_id, now)?;
        tx.commit()?;
        Ok(serde_json::to_value(response)?)
    }

    pub fn authenticate_enrollment(
        &self,
        certificate_fingerprint: &str,
        now: i64,
    ) -> Result<EnrollmentIdentity> {
        digest(certificate_fingerprint)?;
        valid_time(now)?;
        let c = self.connection()?;
        authenticate(&c, certificate_fingerprint, now)
    }
    pub fn list_enrollments(&self, t: &Tenant, limit: usize, now: i64) -> Result<Vec<Value>> {
        valid_limit(limit)?;
        valid_time(now)?;
        let c = self.connection()?;
        let mut query=c.prepare("SELECT e.target_id FROM target_enrollments e WHERE e.org_id=?1 AND e.project_id=?2 ORDER BY e.target_id LIMIT ?3")?;
        let ids = query
            .query_map(params![t.org_id, t.project_id, limit + 1], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if ids.len() > limit {
            return Err(StoreError::InvalidInput("RESULT_TOO_LARGE"));
        }
        ids.iter()
            .map(|id| enrollment_view(&c, t, id, now))
            .collect()
    }
    pub fn get_enrollment(&self, t: &Tenant, target_id: &str, now: i64) -> Result<Value> {
        valid_uuid(target_id)?;
        valid_time(now)?;
        let c = self.connection()?;
        enrollment_view(&c, t, target_id, now)
    }
    pub fn count_enrollments(&self, t: &Tenant) -> Result<u64> {
        Ok(self.connection()?.query_row(
            "SELECT count(*) FROM target_enrollments WHERE org_id=?1 AND project_id=?2",
            params![t.org_id, t.project_id],
            |r| r.get(0),
        )?)
    }
    pub fn revoke_enrollment(
        &self,
        t: &Tenant,
        principal: &str,
        target_id: &str,
        now: i64,
    ) -> Result<Value> {
        valid_uuid(target_id)?;
        valid_time(now)?;
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        active_principal(&tx, t, principal)?;
        let old = enrollment_view(&tx, t, target_id, now)?;
        if old["revoked"] == true {
            return Ok(old);
        }
        tx.execute("UPDATE target_enrollments SET revoked_at=?4 WHERE org_id=?1 AND project_id=?2 AND target_id=?3 AND revoked_at IS NULL",params![t.org_id,t.project_id,target_id,now])?;
        tx.execute("UPDATE enrollment_tokens SET state='revoked' WHERE org_id=?1 AND project_id=?2 AND target_id=?3",params![t.org_id,t.project_id,target_id])?;
        append_audit(
            &tx,
            t,
            Some(principal),
            "revocation",
            "target",
            Some(target_id),
            None,
            "success",
            Some("NETWORK_REVOCATION_UNCONFIRMED"),
            now,
        )?;
        enqueue(
            &tx,
            t,
            "target",
            target_id,
            2,
            "target.transport_revoked",
            &json!({"target_id":target_id,"network_revoked":false}),
            now,
        )?;
        super::collections::capture_enrollment(&tx, t, target_id, now)?;
        let result = enrollment_view(&tx, t, target_id, now)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn save_target_capability(
        &self,
        identity: &EnrollmentIdentity,
        capability: &Value,
        now: i64,
    ) -> Result<Value> {
        valid_time(now)?;
        let bytes = canonical_bytes(capability)?;
        if bytes.len() > 65536 {
            return Err(StoreError::InvalidInput("capability size"));
        }
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = authenticate(&tx, &identity.certificate_fingerprint, now)?;
        if current.tenant != identity.tenant
            || current.target_id != identity.target_id
            || current.key_fingerprint != identity.key_fingerprint
        {
            return Err(StoreError::NotFound);
        }
        let platform: String = tx.query_row(
            "SELECT platform FROM targets WHERE org_id=?1 AND project_id=?2 AND target_id=?3",
            params![
                current.tenant.org_id,
                current.tenant.project_id,
                current.target_id
            ],
            |r| r.get(0),
        )?;
        let (checked, until) = validate_capability(
            capability,
            &current.target_id,
            &platform,
            now,
            current.certificate_expires_at,
        )?;
        let hash = hash_bytes(&bytes);
        let old:Option<(String,i64)>=tx.query_row("SELECT e.capability_hash,c.checked_at FROM target_enrollments e JOIN enrolled_capabilities c ON (e.org_id=c.org_id AND e.project_id=c.project_id AND e.target_id=c.target_id AND e.capability_hash=c.capability_hash) WHERE e.org_id=?1 AND e.project_id=?2 AND e.target_id=?3",params![current.tenant.org_id,current.tenant.project_id,current.target_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((old_hash, old_at)) = old {
            if checked < old_at || (checked == old_at && old_hash != hash) {
                return Err(StoreError::Conflict("STALE_CAPABILITY"));
            }
            if old_hash == hash {
                return target_view(&tx, &current.tenant, &current.target_id, now);
            }
        }
        tx.execute(
            "INSERT INTO enrolled_capabilities VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                current.tenant.org_id,
                current.tenant.project_id,
                current.target_id,
                hash,
                checked,
                until,
                bytes
            ],
        )?;
        tx.execute("UPDATE target_enrollments SET capability_hash=?4 WHERE org_id=?1 AND project_id=?2 AND target_id=?3",params![current.tenant.org_id,current.tenant.project_id,current.target_id,hash])?;
        append_audit_with_evidence(
            &tx,
            &current.tenant,
            None,
            "registry",
            "target",
            Some(&current.target_id),
            None,
            "success",
            Some("CAPABILITY_UNVERIFIED"),
            std::slice::from_ref(&hash),
            now,
        )?;
        // A target can renew its report many times. Each immutable capability
        // needs a distinct outbox revision; replays return before this insert.
        // enrolled_capabilities forbids UPDATE and DELETE, so this count is a
        // durable monotonic sequence under the current IMMEDIATE transaction.
        let report_count: i64 = tx.query_row("SELECT count(*) FROM enrolled_capabilities WHERE org_id=?1 AND project_id=?2 AND target_id=?3",params![current.tenant.org_id,current.tenant.project_id,current.target_id],|r|r.get(0))?;
        let report_revision = i32::try_from(report_count)
            .map_err(|_| StoreError::Integrity("capability revision exhausted"))?;
        enqueue(
            &tx,
            &current.tenant,
            "target",
            &current.target_id,
            report_revision,
            "target.capability_reported",
            &json!({"target_id":current.target_id,"capability_hash":hash,"state":"observe_only"}),
            now,
        )?;
        super::collections::capture_enrollment(&tx, &current.tenant, &current.target_id, now)?;
        let result = target_view(&tx, &current.tenant, &current.target_id, now)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn list_targets(&self, t: &Tenant, limit: usize, now: i64) -> Result<Vec<Value>> {
        valid_limit(limit)?;
        valid_time(now)?;
        let c = self.connection()?;
        let mut query=c.prepare("SELECT target_id FROM target_enrollments WHERE org_id=?1 AND project_id=?2 AND capability_hash IS NOT NULL ORDER BY target_id LIMIT ?3")?;
        let ids = query
            .query_map(params![t.org_id, t.project_id, limit + 1], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if ids.len() > limit {
            return Err(StoreError::InvalidInput("RESULT_TOO_LARGE"));
        }
        ids.iter().map(|id| target_view(&c, t, id, now)).collect()
    }
    pub fn get_target(&self, t: &Tenant, target_id: &str, now: i64) -> Result<Value> {
        valid_uuid(target_id)?;
        valid_time(now)?;
        let c = self.connection()?;
        target_view(&c, t, target_id, now)
    }
    pub fn count_targets(&self, t: &Tenant) -> Result<u64> {
        Ok(self.connection()?.query_row("SELECT count(*) FROM target_enrollments WHERE org_id=?1 AND project_id=?2 AND capability_hash IS NOT NULL",params![t.org_id,t.project_id],|r|r.get(0))?)
    }
}

fn read_token(c: &Connection, token_hash: &str) -> Result<TokenRow> {
    c.query_row("SELECT org_id,project_id,token_id,target_id,principal_id,name,platform,key_fingerprint,created_at,expires_at,state FROM enrollment_tokens WHERE token_hash=?1",[token_hash],|r|Ok(TokenRow {tenant:Tenant {org_id:r.get(0)?,project_id:r.get(1)?},token_id:r.get(2)?,target_id:r.get(3)?,principal:r.get(4)?,name:r.get(5)?,platform:r.get(6)?,key_fingerprint:r.get(7)?,created_at:r.get(8)?,expires_at:r.get(9)?,state:r.get(10)?})).optional()?.ok_or(StoreError::NotFound)
}
fn read_job_for_token(c: &Connection, token: &TokenRow) -> Result<Option<EnrollmentReservation>> {
    struct StoredJob {
        job_id: String,
        csr_hash: String,
        request_id: String,
        nonce: String,
        agent_version: String,
        issued_at: i64,
        response_bytes: Option<Vec<u8>>,
    }
    let row = c.query_row(
        "SELECT job_id,csr_hash,request_id,nonce,agent_version,issued_at,response_bytes FROM enrollment_jobs WHERE org_id=?1 AND project_id=?2 AND token_id=?3",
        params![token.tenant.org_id, token.tenant.project_id, token.token_id],
        |r| Ok(StoredJob {
            job_id: r.get(0)?, csr_hash: r.get(1)?, request_id: r.get(2)?,
            nonce: r.get(3)?, agent_version: r.get(4)?, issued_at: r.get(5)?,
            response_bytes: r.get(6)?,
        }),
    ).optional()?;
    row.map(|r| {
        Ok(EnrollmentReservation {
            tenant: token.tenant.clone(),
            target_id: token.target_id.clone(),
            token_id: token.token_id.clone(),
            job_id: r.job_id,
            name: token.name.clone(),
            platform: token.platform.clone(),
            key_fingerprint: token.key_fingerprint.clone(),
            csr_hash: r.csr_hash,
            request_id: r.request_id,
            nonce: r.nonce,
            agent_version: r.agent_version,
            issued_at: r.issued_at,
            token_expires_at: token.expires_at,
            response: r
                .response_bytes
                .map(|b| serde_json::from_slice(&b))
                .transpose()?,
        })
    })
    .transpose()
}

fn authenticate(c: &Connection, fp: &str, now: i64) -> Result<EnrollmentIdentity> {
    c.query_row("SELECT e.org_id,e.project_id,e.target_id,e.key_fingerprint,e.certificate_expires_at FROM target_enrollments e JOIN projects p ON (e.org_id=p.org_id AND e.project_id=p.project_id) JOIN organizations o ON e.org_id=o.org_id WHERE e.certificate_fingerprint=?1 AND e.revoked_at IS NULL AND e.enrolled_at<=?2 AND e.certificate_expires_at>?2 AND p.state='active' AND o.state='active'",params![fp,now],|r|Ok(EnrollmentIdentity {tenant:Tenant {org_id:r.get(0)?,project_id:r.get(1)?},target_id:r.get(2)?,key_fingerprint:r.get(3)?,certificate_fingerprint:fp.into(),certificate_expires_at:r.get(4)?})).optional()?.ok_or(StoreError::NotFound)
}
pub(super) fn enrollment_view(c: &Connection, t: &Tenant, id: &str, now: i64) -> Result<Value> {
    let row:(String,String,String,i64,i64,Option<i64>,Option<String>)=c.query_row("SELECT e.name,t.platform,e.key_fingerprint,e.enrolled_at,e.certificate_expires_at,e.revoked_at,e.capability_hash FROM target_enrollments e JOIN targets t USING(org_id,project_id,target_id) WHERE e.org_id=?1 AND e.project_id=?2 AND e.target_id=?3",params![t.org_id,t.project_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?.ok_or(StoreError::NotFound)?;
    Ok(
        json!({"target_id":id,"name":row.0,"platform":row.1,"state":if row.5.is_some() || row.4<=now || row.3>now {"quarantined"} else {"observe_only"},"key_fingerprint":row.2,"enrolled_at":timestamp(row.3)?,"certificate_expires_at":timestamp(row.4)?,"revoked":row.5.is_some(),"capability_hash":row.6}),
    )
}
pub(super) fn target_view(c: &Connection, t: &Tenant, id: &str, now: i64) -> Result<Value> {
    let enrollment = enrollment_view(c, t, id, now)?;
    let hash = enrollment["capability_hash"]
        .as_str()
        .ok_or(StoreError::NotFound)?;
    let row:(Vec<u8>,i64,i64)=c.query_row("SELECT canonical_bytes,checked_at,valid_until FROM enrolled_capabilities WHERE org_id=?1 AND project_id=?2 AND target_id=?3 AND capability_hash=?4",params![t.org_id,t.project_id,id,hash],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(StoreError::Integrity("missing target capability"))?;
    if hash_bytes(&row.0) != hash {
        return Err(StoreError::Integrity("capability digest"));
    }
    let capability: Value = serde_json::from_slice(&row.0)?;
    if capability["target_id"] != id
        || capability["platform"] != enrollment["platform"]
        || parse_time(field(&capability, "checked_at")?)? != row.1
        || parse_time(field(&capability, "valid_until")?)? != row.2
    {
        return Err(StoreError::Integrity("capability projection"));
    }
    Ok(
        json!({"target_id":id,"name":enrollment["name"],"platform":enrollment["platform"],"enforcement_backend":capability["enforcement_backend"],"capability_version":"f.target-capability/v1","profile":"host","state":if row.2<=now || row.1>now {"quarantined"} else {enrollment["state"].as_str().unwrap_or("quarantined")},"desired_state_hash":null,"observed_state_hash":null,"capability_hash":hash,"authority_epoch":"0","generation":"0","observed_at":null}),
    )
}
fn digest(s: &str) -> Result<()> {
    if s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
    {
        Ok(())
    } else {
        Err(StoreError::InvalidInput("SHA-256 digest"))
    }
}
fn text(s: &str, max: usize) -> Result<()> {
    if s.trim().is_empty() || s.len() > max || s.chars().any(char::is_control) {
        Err(StoreError::InvalidInput("text bounds"))
    } else {
        Ok(())
    }
}
fn backend(platform: &str) -> Result<&'static str> {
    match platform {
        "linux" => Ok("nftables"),
        "windows" => Ok("windows_wfp"),
        "macos" => Ok("macos_network_extension"),
        _ => Err(StoreError::InvalidInput("platform")),
    }
}
fn parse_time(s: &str) -> Result<i64> {
    let value = DateTime::parse_from_rfc3339(s)
        .map_err(|_| StoreError::InvalidInput("timestamp"))?
        .timestamp();
    if timestamp(value)? != s {
        return Err(StoreError::InvalidInput("canonical UTC timestamp"));
    }
    Ok(value)
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or(StoreError::InvalidInput("string field"))
}
fn closed(v: &Value, keys: &[&str]) -> Result<()> {
    let o = v.as_object().ok_or(StoreError::InvalidInput("object"))?;
    if o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)) {
        return Err(StoreError::InvalidInput("closed object fields"));
    }
    Ok(())
}
fn string_set(v: &Value, allowed: &[&str], max: usize) -> Result<()> {
    let items = v.as_array().ok_or(StoreError::InvalidInput("set"))?;
    let mut seen = BTreeSet::new();
    if items.len() > max {
        return Err(StoreError::InvalidInput("set bounds"));
    }
    for item in items {
        let s = item.as_str().ok_or(StoreError::InvalidInput("set item"))?;
        if !allowed.contains(&s) || !seen.insert(s) {
            return Err(StoreError::InvalidInput("set item"));
        }
    }
    Ok(())
}
fn validate_capability(
    v: &Value,
    target: &str,
    platform: &str,
    now: i64,
    certificate_expiry: i64,
) -> Result<(i64, i64)> {
    closed(
        v,
        &[
            "schema_version",
            "target_id",
            "platform",
            "enforcement_backend",
            "capability_version",
            "os_version",
            "backend_version",
            "executor_build_hash",
            "checked_at",
            "valid_until",
            "profiles",
            "families",
            "directions",
            "protocols",
            "binding_kinds",
            "features",
            "max_policies",
            "max_rules",
            "max_artifact_bytes",
            "qualification_profiles",
            "interfaces",
        ],
    )?;
    if v["schema_version"] != "f.target-capability/v1"
        || v["capability_version"] != "f.target-capability/v1"
        || v["target_id"] != target
        || v["platform"] != platform
        || v["enforcement_backend"] != backend(platform)?
    {
        return Err(StoreError::InvalidInput("capability identity"));
    }
    text(field(v, "os_version")?, 128)?;
    text(field(v, "backend_version")?, 128)?;
    digest(field(v, "executor_build_hash")?)?;
    let checked = parse_time(field(v, "checked_at")?)?;
    let until = parse_time(field(v, "valid_until")?)?;
    if checked > now
        || checked < now - 300
        || until <= now
        || until > certificate_expiry
        || until > checked + 86400
    {
        return Err(StoreError::InvalidInput("capability validity"));
    }
    // Reporting a transport identity does not qualify any enforcement profile.
    string_set(&v["profiles"], &[], 0)?;
    string_set(&v["families"], &["ipv4", "ipv6"], 2)?;
    string_set(&v["directions"], &["input", "output"], 2)?;
    string_set(&v["protocols"], &["tcp", "udp", "icmp", "icmpv6"], 4)?;
    let kinds = match platform {
        "linux" => vec!["host", "vm", "network_namespace"],
        "windows" => vec!["host", "vm", "windows_app_identity"],
        _ => vec!["macos_host"],
    };
    string_set(&v["binding_kinds"], &kinds, 5)?;
    string_set(&v["qualification_profiles"], &[], 0)?;
    let features = [
        "timed_allow",
        "persistent_deny",
        "strict_current_union",
        "atomic_apply",
        "semantic_readback",
        "writer_fencing",
        "independent_watchdog",
        "new_management_probe",
        "interface_scope",
        "process_binding",
        "independent_expiry",
        "boot_guard",
        "crash_fail_closed",
        "absolute_deadline_guard",
    ];
    closed(&v["features"], &features)?;
    for name in features {
        let f = &v["features"][name];
        closed(f, &["state", "reason_code", "evidence_hash"])?;
        if f["state"] != "unverified" && f["state"] != "unsupported" {
            return Err(StoreError::InvalidInput(
                "unqualified capability support claim",
            ));
        }
        let reason = field(f, "reason_code")?;
        if reason.is_empty()
            || reason.len() > 64
            || !reason.as_bytes()[0].is_ascii_uppercase()
            || !reason
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
        {
            return Err(StoreError::InvalidInput("capability reason"));
        }
        if !f["evidence_hash"].is_null() {
            digest(field(f, "evidence_hash")?)?;
        }
    }
    for (key, max) in [
        ("max_policies", 4096),
        ("max_rules", 100000),
        ("max_artifact_bytes", 16777216),
    ] {
        if !v[key].as_u64().is_some_and(|n| n >= 1 && n <= max) {
            return Err(StoreError::InvalidInput("capability limit"));
        }
    }
    let interfaces = v["interfaces"]
        .as_array()
        .ok_or(StoreError::InvalidInput("interfaces"))?;
    if interfaces.len() > 64 {
        return Err(StoreError::InvalidInput("interfaces limit"));
    }
    let mut seen = BTreeSet::new();
    for i in interfaces {
        closed(
            i,
            &[
                "logical_name",
                "native_id",
                "native_identity_hash",
                "direction",
                "present",
            ],
        )?;
        let name = field(i, "logical_name")?;
        let direction = field(i, "direction")?;
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || !["input", "output"].contains(&direction)
            || !seen.insert((name, direction))
        {
            return Err(StoreError::InvalidInput("interface identity"));
        }
        text(field(i, "native_id")?, 256)?;
        digest(field(i, "native_identity_hash")?)?;
        if !i["present"].is_boolean() {
            return Err(StoreError::InvalidInput("interface present"));
        }
    }
    Ok((checked, until))
}

/// Catalogue suitability only: enrollment and current report confer no policy authority.
pub(super) fn target_eligible(c: &Connection, t: &Tenant, id: &str, now: i64) -> Result<bool> {
    match target_view(c, t, id, now) {
        Ok(v) => Ok(v["state"] == "observe_only"),
        Err(StoreError::NotFound) => Ok(false),
        Err(e) => Err(e),
    }
}
pub(super) fn snapshot_target_eligible(
    c: &Connection,
    t: &Tenant,
    v: &Value,
    now: i64,
) -> Result<bool> {
    let id = field(v, "target_id")?;
    if v["state"] != "observe_only" || enrollment_view(c, t, id, now)?["state"] != "observe_only" {
        return Ok(false);
    }
    let hash = field(v, "capability_hash")?;
    let (bytes,checked,until):(Vec<u8>,i64,i64)=c.query_row("SELECT canonical_bytes,checked_at,valid_until FROM enrolled_capabilities WHERE org_id=?1 AND project_id=?2 AND target_id=?3 AND capability_hash=?4",params![t.org_id,t.project_id,id,hash],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let cap: Value = serde_json::from_slice(&bytes)?;
    if hash_bytes(&bytes) != hash
        || cap["target_id"] != id
        || parse_time(field(&cap, "checked_at")?)? != checked
        || parse_time(field(&cap, "valid_until")?)? != until
    {
        return Err(StoreError::Integrity("snapshot capability projection"));
    }
    Ok(checked <= now && now < until)
}
