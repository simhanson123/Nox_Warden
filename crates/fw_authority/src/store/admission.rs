use super::records;
use super::*;
use crate::{ApprovalChallengeSubject, begin_approval_proof, finish_approval_proof};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fw_webauthn::AuthenticationResponse;

impl AuthorityStore {
    /// Issue from the authority's pinned key, current role and immutable full
    /// plan. Persist the private proof state before exposing browser options.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_challenge(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        credential_id: &str,
        plan_id: &str,
        role: ApprovalRole,
        decision: ApprovalDecision,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<IssuedApproval> {
        identifier(principal)?;
        identifier(plan_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let security = security_revision(&tx, tenant)?;
        let credential = records::credential(&tx, tenant, credential_id)?;
        credential.require(principal, "active", now)?;
        let membership = records::current_role(&tx, tenant, principal, role, now)?;
        let subject = records::plan(&tx, tenant, plan_id, now)?;
        let context = records::context(tenant, principal, &subject, role, decision)?;
        let outstanding: i64 = tx.query_row("SELECT count(*) FROM authority_challenges WHERE org_id=? AND project_id=? AND principal_id=?
            AND consumed_at IS NULL AND expires_at>?",params![tenant.org_id,tenant.project_id,principal,now],|r|r.get(0))?;
        if outstanding >= MAX_OUTSTANDING {
            return Err(AuthorityError::Quota);
        }
        let challenge = ApprovalChallenge::issue(&context, verifier, now)?;
        let ceremony = begin_approval_proof(
            verifier,
            &challenge,
            &context,
            std::slice::from_ref(&credential.credential),
            now,
        )?;
        let state = bytes(&ceremony.state)?;
        let payload: Value = decode(challenge.canonical_payload())?;
        let nonce = URL_SAFE_NO_PAD
            .decode(
                payload["nonce"]
                    .as_str()
                    .ok_or(invalid("challenge nonce"))?,
            )
            .map_err(|_| invalid("challenge nonce"))?;
        tx.execute("INSERT INTO authority_challenges(org_id,project_id,challenge_id,principal_id,plan_id,credential_id,membership_id,
            role_revision,credential_revision,security_revision,role,decision,challenge_hash,nonce_hash,payload_hash,payload_bytes,
            state_bytes,credential_bytes,issued_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![tenant.org_id,tenant.project_id,challenge.challenge_id(),principal,plan_id,credential_id,membership.id,membership.revision,
                credential.revision,security,role_name(role),decision_name(decision),challenge.challenge_bytes().as_slice(),
                hash(&hash_bytes(&nonce))?,hash(challenge.payload_hash())?,challenge.canonical_payload(),state,credential.canonical,now,challenge.expires_at()])?;
        audit(
            &tx,
            tenant,
            "approval_challenge_issued",
            challenge.challenge_id(),
            now,
        )?;
        tx.commit()?;
        Ok(IssuedApproval {
            challenge,
            options: ceremony.options,
        })
    }

    /// Verify and atomically retain one human decision. This method performs no
    /// external calls under its IMMEDIATE transaction: only bounded local proof
    /// verification and SQLite writes. It creates no quorum, grant or outbox.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_decision(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        challenge_id: &str,
        idempotency_key: &str,
        assertion: &AuthenticationResponse,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<DecisionResult> {
        identifier(principal)?;
        identifier(challenge_id)?;
        identifier(idempotency_key)?;
        time(now)?;
        let assertion_bytes = bytes(assertion)?;
        if assertion_bytes.len() > 65536 {
            return Err(invalid("approval assertion too large"));
        }
        let request_hash = hash(
            &canonical_hash(&json!({"challenge_id":challenge_id,"assertion":assertion}))
                .map_err(|_| invalid("approval request canonicalization"))?,
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<String> = tx.query_row("SELECT approval_id FROM authority_decisions WHERE org_id=? AND project_id=? AND principal_id=? AND idempotency_key=?",
            params![tenant.org_id,tenant.project_id,principal,idempotency_key],|r|r.get(0)).optional()?;
        if let Some(id) = prior {
            let previous = records::decision(&tx, tenant, &id)?;
            if previous.principal_id != principal
                || previous.challenge_id != challenge_id
                || previous.request_hash != request_hash
                || previous.idempotency_key != idempotency_key
            {
                return Err(AuthorityError::Conflict);
            }
            // A replay acknowledges history even if it is no longer eligible.
            // No timestamp, state, counter or audit record is renewed here.
            tx.commit()?;
            return Ok(DecisionResult {
                approval: previous.approval,
                replayed: true,
            });
        }
        let challenge = records::challenge(&tx, tenant, challenge_id)?;
        if challenge.challenge.principal_id() != principal {
            return Err(AuthorityError::Binding);
        }
        if challenge.consumed_at.is_some() {
            return Err(AuthorityError::Conflict);
        }
        if challenge.attempts >= MAX_ATTEMPTS {
            return Err(AuthorityError::Quota);
        }
        challenge.challenge.validate_now(now)?;
        let ApprovalChallengeSubject::Plan { plan_ref } = challenge.challenge.subject() else {
            return Err(invalid("unsupported approval subject"));
        };
        let subject = records::plan(&tx, tenant, &plan_ref.plan_id, now)?;
        let context = records::context(
            tenant,
            principal,
            &subject,
            challenge.challenge.role(),
            challenge.challenge.decision(),
        )?;
        let credential = records::credential(&tx, tenant, &challenge.credential_id)?;
        credential.require(principal, "active", now)?;
        let membership = records::role(&tx, tenant, &challenge.membership_id)?;
        membership.require(principal, challenge.challenge.role(), now)?;
        if security_revision(&tx, tenant)? != challenge.security_revision
            || credential.revision != challenge.credential_revision
            || membership.revision != challenge.role_revision
            || credential.canonical != challenge.credential_bytes
        {
            return Err(AuthorityError::Binding);
        }
        let verified = match finish_approval_proof(
            verifier,
            &challenge.state,
            &challenge.challenge,
            &context,
            assertion,
            &credential.credential,
            now,
        ) {
            Ok(result) => result,
            Err(error) => {
                tx.execute("UPDATE authority_challenges SET attempts=attempts+1 WHERE org_id=? AND project_id=? AND challenge_id=? AND attempts<? AND consumed_at IS NULL",
                    params![tenant.org_id,tenant.project_id,challenge_id,MAX_ATTEMPTS])?;
                audit(&tx, tenant, "approval_proof_rejected", challenge_id, now)?;
                tx.commit()?;
                return Err(error);
            }
        };
        let updated = verified.updated_credential();
        if verified.challenge().payload_hash() != challenge.challenge.payload_hash()
            || verified.verified_at() != now
            || updated.id() != credential.id
            || updated.principal_id() != principal
            || updated
                .key_fingerprint()
                .map_err(|_| invalid("verified approval key"))?
                != credential.fingerprint
        {
            return Err(AuthorityError::Binding);
        }
        let post = bytes(updated)?;
        let registry = credential.snapshot(tenant)?;
        let role_snapshot = membership.snapshot(tenant)?;
        let evidence = evidence_value(
            &challenge,
            &credential.credential,
            updated,
            assertion,
            &registry,
            &role_snapshot,
            now,
        )?;
        let evidence_bytes = bytes(&evidence)?;
        let evidence_hash = hash_bytes(&evidence_bytes);
        let approval_id = new_id()?;
        let expires_at = (now + subject.max_approval_age_seconds)
            .min(subject.valid_until)
            .min(credential.not_after)
            .min(membership.not_after);
        if expires_at <= now {
            return Err(AuthorityError::Time);
        }
        let approval = approval_value(
            &tx,
            tenant,
            &approval_id,
            &challenge.challenge,
            &registry,
            &role_snapshot,
            &evidence_hash,
            evidence_bytes.len(),
            now,
            expires_at,
        )?;
        let canonical = bytes(&approval)?;
        if tx.execute("UPDATE authority_credentials SET credential_bytes=?,revision=revision+1 WHERE org_id=? AND project_id=? AND credential_id=? AND revision=? AND revision<2147483647 AND state='active'",
            params![post,tenant.org_id,tenant.project_id,credential.id,credential.revision])? != 1 { return Err(AuthorityError::Conflict); }
        if tx.execute("UPDATE authority_challenges SET consumed_at=? WHERE org_id=? AND project_id=? AND challenge_id=? AND consumed_at IS NULL AND attempts<?",
            params![now,tenant.org_id,tenant.project_id,challenge_id,MAX_ATTEMPTS])? != 1 { return Err(AuthorityError::Conflict); }
        tx.execute("INSERT INTO authority_evidence(org_id,project_id,evidence_hash,challenge_id,credential_id,membership_id,pre_credential_bytes,post_credential_bytes,
            assertion_bytes,proof_state_bytes,credential_registry_bytes,role_membership_bytes,admitted_at,canonical_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![tenant.org_id,tenant.project_id,hash(&evidence_hash)?,challenge_id,credential.id,membership.id,credential.canonical,post,
                assertion_bytes,challenge.state_bytes,bytes(&registry)?,bytes(&role_snapshot)?,now,evidence_bytes])?;
        tx.execute("INSERT INTO authority_decisions(org_id,project_id,approval_id,principal_id,challenge_id,plan_id,credential_id,membership_id,decision,
            idempotency_key,request_hash,evidence_hash,content_hash,created_at,expires_at,canonical_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![tenant.org_id,tenant.project_id,approval_id,principal,challenge_id,subject.plan_id,credential.id,membership.id,
                decision_name(challenge.challenge.decision()),idempotency_key,request_hash,hash(&evidence_hash)?,hash(&hash_bytes(&canonical))?,now,expires_at,canonical])?;
        audit(&tx, tenant, "approval_decision_recorded", &approval_id, now)?;
        tx.commit()?;
        Ok(DecisionResult {
            approval,
            replayed: false,
        })
    }

    /// Reverify the original assertion at its recorded admission time against
    /// the saved pre-authentication credential. Then independently check current
    /// key identity/revocation, current role, immutable plan and approval expiry.
    /// A later legitimate credential counter is not the original proof counter.
    pub fn verify_retained_decision(
        &mut self,
        tenant: &AuthorityTenant,
        approval_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<RetainedDecision> {
        identifier(approval_id)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let decision = records::decision(&tx, tenant, approval_id)?;
        if now < decision.created_at || now >= decision.expires_at {
            return Err(AuthorityError::Time);
        }
        let challenge = records::challenge(&tx, tenant, &decision.challenge_id)?;
        if challenge.consumed_at != Some(decision.created_at)
            || challenge.credential_id != decision.credential_id
            || challenge.membership_id != decision.membership_id
            || challenge.challenge.principal_id() != decision.principal_id
        {
            return Err(invalid("retained decision consumption"));
        }
        let subject = records::plan(&tx, tenant, &decision.plan_id, now)?;
        let context = records::context(
            tenant,
            &decision.principal_id,
            &subject,
            challenge.challenge.role(),
            challenge.challenge.decision(),
        )?;
        let current_credential = records::credential(&tx, tenant, &decision.credential_id)?;
        current_credential.require(&decision.principal_id, "active", now)?;
        let current_role = records::role(&tx, tenant, &decision.membership_id)?;
        current_role.require(&decision.principal_id, challenge.challenge.role(), now)?;
        let evidence = tx.query_row("SELECT challenge_id,credential_id,membership_id,pre_credential_bytes,post_credential_bytes,assertion_bytes,
            proof_state_bytes,credential_registry_bytes,role_membership_bytes,admitted_at,canonical_bytes FROM authority_evidence
            WHERE org_id=? AND project_id=? AND evidence_hash=?",params![tenant.org_id,tenant.project_id,decision.evidence_hash],|r|Ok((
            r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,
            r.get::<_,Vec<u8>>(6)?,r.get::<_,Vec<u8>>(7)?,r.get::<_,Vec<u8>>(8)?,r.get::<_,i64>(9)?,r.get::<_,Vec<u8>>(10)?)))
            .optional()?.ok_or(AuthorityError::Binding)?;
        if evidence.0 != decision.challenge_id
            || evidence.1 != decision.credential_id
            || evidence.2 != decision.membership_id
            || evidence.3 != challenge.credential_bytes
            || evidence.6 != challenge.state_bytes
            || evidence.9 != decision.created_at
            || hash(&hash_bytes(&evidence.10))? != decision.evidence_hash
        {
            return Err(invalid("retained evidence projection"));
        }
        let before: Credential = decode(&evidence.3)?;
        let after: Credential = decode(&evidence.4)?;
        let assertion: AuthenticationResponse = decode(&evidence.5)?;
        if hash(
            &canonical_hash(&json!({"challenge_id":decision.challenge_id,"assertion":assertion}))
                .map_err(|_| invalid("retained approval request"))?,
        )? != decision.request_hash
        {
            return Err(invalid("retained approval request hash"));
        }
        let registry: Value = decode(&evidence.7)?;
        let role_snapshot: Value = decode(&evidence.8)?;
        let canonical: Value = decode(&evidence.10)?;
        if canonical
            != evidence_value(
                &challenge,
                &before,
                &after,
                &assertion,
                &registry,
                &role_snapshot,
                decision.created_at,
            )?
        {
            return Err(invalid("retained evidence canonical projection"));
        }
        if before
            .key_fingerprint()
            .map_err(|_| invalid("retained credential key"))?
            != current_credential.fingerprint
            || after
                .key_fingerprint()
                .map_err(|_| invalid("retained result key"))?
                != current_credential.fingerprint
            || current_credential.revision <= challenge.credential_revision
            || current_role.revision != challenge.role_revision
        {
            return Err(AuthorityError::Binding);
        }
        let mut expected_registry = current_credential.snapshot(tenant)?;
        expected_registry["revision"] = json!(challenge.credential_revision);
        expected_registry["credential"] =
            serde_json::to_value(&before).map_err(|_| invalid("retained credential snapshot"))?;
        if registry != expected_registry || role_snapshot != current_role.snapshot(tenant)? {
            return Err(AuthorityError::Binding);
        }
        let expected_expiry = (decision.created_at + subject.max_approval_age_seconds)
            .min(subject.valid_until)
            .min(current_credential.not_after)
            .min(current_role.not_after);
        if decision.expires_at != expected_expiry {
            return Err(AuthorityError::Binding);
        }
        let expected_approval = approval_value(
            &tx,
            tenant,
            &decision.id,
            &challenge.challenge,
            &registry,
            &role_snapshot,
            &hash_string(&decision.evidence_hash)?,
            evidence.10.len(),
            decision.created_at,
            decision.expires_at,
        )?;
        if decision.approval != expected_approval {
            return Err(invalid("retained approval projection"));
        }
        let verified = finish_approval_proof(
            verifier,
            &challenge.state,
            &challenge.challenge,
            &context,
            &assertion,
            &before,
            decision.created_at,
        )?;
        if bytes(verified.updated_credential())? != evidence.4 {
            return Err(AuthorityError::Binding);
        }
        tx.commit()?;
        Ok(RetainedDecision {
            approval: decision.approval,
        })
    }
}

fn evidence_value(
    challenge: &records::ChallengeRecord,
    before: &Credential,
    after: &Credential,
    assertion: &AuthenticationResponse,
    registry: &Value,
    role: &Value,
    now: i64,
) -> Result<Value> {
    Ok(
        json!({"schema_version":"fw.authority-approval-evidence/v1","challenge":challenge.challenge,
        "proof_state":challenge.state,"credential_before":before,"credential_after":after,"assertion":assertion,
        "credential_registry":registry,"role_membership":role,"admitted_at":at(now)?}),
    )
}

#[allow(clippy::too_many_arguments)]
fn approval_value(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    challenge: &ApprovalChallenge,
    registry: &Value,
    membership: &Value,
    evidence_hash: &str,
    size: usize,
    now: i64,
    expiry: i64,
) -> Result<Value> {
    let ApprovalChallengeSubject::Plan { plan_ref } = challenge.subject() else {
        return Err(invalid("unsupported approval subject"));
    };
    Ok(
        json!({"approval_id":id,"principal":records::principal(tx,tenant,challenge.principal_id(),now)?,"role":challenge.role(),
        "decision":challenge.decision(),"plan_ref":plan_ref,"requirements_hash":challenge.requirements_hash(),
        "challenge_id":challenge.challenge_id(),"assertion_evidence":{"store_id":"authority_proofs","object_hash":evidence_hash,
        "media_type":"application/json","size_bytes":size},"credential_registry_hash":canonical_hash(registry).map_err(|_|invalid("registry snapshot hash"))?,
        "role_membership_hash":canonical_hash(membership).map_err(|_|invalid("role snapshot hash"))?,"created_at":at(now)?,"expires_at":at(expiry)?}),
    )
}
