//! Durable local-owner passkeys and single-use authentication ceremonies.
//!
//! A trusted caller supplies the maintained WebAuthn verifier as a bounded,
//! side-effect-free callback. It runs against the current credential records
//! inside the same write transaction that consumes the challenge. HTTP values
//! alone never become a credential or authentication result. This controller
//! store is not an independent signer's credential or policy authority.
use super::*;
use unicode_normalization::UnicodeNormalization;

const MAX_CREDENTIALS: usize = 8;
const MAX_CEREMONIES_PER_WINDOW: u64 = 16;
const MAX_FAILURES: u32 = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum PasskeyAuthority {
    Bootstrap,
    Passkey {
        credential_id: String,
        authenticated_at: i64,
    },
}

#[derive(Clone, Debug)]
pub struct PasskeyChallengeInput {
    pub kind: String,
    /// Hash of the server-controlled browser/session binding, never its secret.
    pub session_binding: String,
    pub authority: Option<PasskeyAuthority>,
    pub name: Option<String>,
    /// Only the original client request, excluding randomly generated options.
    pub request: Value,
    pub options: Value,
    pub state: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyChallenge {
    pub challenge_id: String,
    pub kind: String,
    pub options: Value,
    /// Private WebAuthn library state: do not expose in the HTTP projection.
    pub state: Value,
    pub created_at: i64,
    pub expires_at: i64,
    pub session_binding: String,
    pub name: Option<String>,
    pub authority: Option<PasskeyAuthority>,
    org_id: String,
    project_id: String,
    principal_id: String,
}

#[derive(Clone, Debug)]
pub struct PasskeyCredential {
    pub credential_id: String,
    pub name: String,
    /// Library credential state; callers project metadata separately for HTTP.
    pub credential: Value,
    /// Changes on counter updates; session validity uses revocation, not this.
    pub revision: u64,
    pub created_at: i64,
    /// Set only by a successful signed authentication, not an attestation-none registration.
    pub verified_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// Produced by the trusted WebAuthn verifier, never deserialized from HTTP.
#[derive(Clone, Debug)]
pub struct VerifiedPasskey {
    pub credential_id: String,
    pub credential: Value,
}

#[derive(Clone, Debug)]
pub struct PasskeyCompletion {
    pub credential_id: String,
    pub kind: String,
    /// A replay is evidence of an earlier result, not a fresh authentication.
    /// Only a still-live original session may be returned for this result.
    pub replayed: bool,
}

/// Login-only state authenticated and decrypted by the trusted HTTP boundary.
/// This value is never deserialized directly from an unauthenticated request.
pub struct PasskeyLoginInput {
    pub challenge_id: String,
    pub session_binding: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub state: Value,
}

impl Store {
    /// Audit only the public handoff identifier and fixed lifecycle event. The
    /// device code, bearer token, browser assertion and credential remain private.
    pub fn record_passkey_cli_event(
        &self,
        t: &Tenant,
        principal: &str,
        request_id: &str,
        event: &str,
        now: i64,
    ) -> Result<()> {
        valid_uuid(request_id)?;
        valid_time(now)?;
        let reason = match event {
            "cli_login_requested" => "CLI_LOGIN_REQUESTED",
            "cli_login_approved" => "CLI_LOGIN_APPROVED",
            "cli_login_exchanged" => "CLI_LOGIN_EXCHANGED",
            _ => return Err(StoreError::InvalidInput("CLI login event")),
        };
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        human(&tx, t, principal)?;
        let actor = if event == "cli_login_requested" {
            None
        } else {
            Some(principal)
        };
        append_audit(
            &tx,
            t,
            actor,
            "administration",
            "system",
            Some(request_id),
            None,
            "success",
            Some(reason),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn passkey_owner_enrolled(&self, t: &Tenant, principal: &str) -> Result<bool> {
        let c = self.connection()?;
        human(&c, t, principal)?;
        let owner = owner(&c, t)?;
        if owner.as_ref().is_some_and(|id| id != principal) {
            return Err(StoreError::NotFound);
        }
        Ok(owner.is_some())
    }

    pub fn list_passkeys(&self, t: &Tenant, principal: &str) -> Result<Vec<PasskeyCredential>> {
        let c = self.connection()?;
        human(&c, t, principal)?;
        credentials(&c, t, principal)
    }

    pub fn active_passkey(
        &self,
        t: &Tenant,
        principal: &str,
        credential_id: &str,
    ) -> Result<PasskeyCredential> {
        let c = self.connection()?;
        human(&c, t, principal)?;
        active_credential(&c, t, principal, credential_id)
    }

    pub fn begin_passkey_challenge(
        &self,
        t: &Tenant,
        principal: &str,
        input: &PasskeyChallengeInput,
        key: &str,
        now: i64,
    ) -> Result<PasskeyChallenge> {
        valid_uuid(key)?;
        valid_time(now)?;
        binding(&input.session_binding)?;
        kind(&input.kind)?;
        let name = input
            .name
            .as_ref()
            .map(|value| value.nfc().collect::<String>());
        match input.kind.as_str() {
            "registration" => {
                label(
                    name.as_deref()
                        .ok_or(StoreError::InvalidInput("passkey name"))?,
                )?;
                if input.authority.is_none() {
                    return Err(StoreError::Conflict("PASSKEY_AUTHORIZATION_REQUIRED"));
                }
            }
            "authentication" if input.authority.is_none() && name.is_none() => {}
            _ => return Err(StoreError::InvalidInput("ceremony fields")),
        }
        bounded(&input.options)?;
        bounded(&input.state)?;
        bounded(&input.request)?;
        let request_hash = sha256(&canonical_bytes(&json!({
            "kind": input.kind, "name": name, "session_binding": input.session_binding,
            "authority": input.authority, "request": input.request
        }))?);
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        human(&tx, t, principal)?;
        let previous: Option<(String, Vec<u8>)> = tx.query_row(
            "SELECT challenge_id,request_hash FROM passkey_challenges WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND kind=?4 AND idempotency_key=?5",
            params![t.org_id,t.project_id,principal,input.kind,key],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        if let Some((id, expected)) = previous {
            if expected != request_hash {
                return Err(StoreError::IdempotencyConflict);
            }
            let saved = challenge(&tx, t, principal, &id)?;
            validate_window(&saved.challenge, now)?;
            return Ok(saved.challenge);
        }
        match &input.authority {
            Some(authority) => authorize_registration(&tx, t, principal, authority, now)?,
            None => {
                if owner(&tx, t)?.as_deref() != Some(principal) {
                    return Err(StoreError::Conflict("PASSKEY_OWNER_NOT_ENROLLED"));
                }
                if active_count(&tx, t, principal)? == 0 {
                    return Err(StoreError::Conflict("PASSKEY_UNAVAILABLE"));
                }
            }
        }
        let recent: u64 = tx.query_row(
            "SELECT count(*) FROM passkey_challenges WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND kind=?4 AND created_at>?5",
            params![t.org_id,t.project_id,principal,input.kind,now - 300], |row| row.get(0),
        )?;
        if recent >= MAX_CEREMONIES_PER_WINDOW {
            return Err(StoreError::Conflict("PASSKEY_CHALLENGE_LIMIT"));
        }
        let expires_at = now
            .checked_add(300)
            .filter(|n| *n <= MAX_TIME)
            .ok_or(StoreError::InvalidInput("ceremony expiry"))?;
        let value = PasskeyChallenge {
            challenge_id: Uuid::new_v4().to_string(),
            kind: input.kind.clone(),
            options: input.options.clone(),
            state: input.state.clone(),
            created_at: now,
            expires_at,
            session_binding: input.session_binding.clone(),
            name,
            authority: input.authority.clone(),
            org_id: t.org_id.clone(),
            project_id: t.project_id.clone(),
            principal_id: principal.into(),
        };
        let bytes = canonical_bytes(&value)?;
        tx.execute(
            "INSERT INTO passkey_challenges(org_id,project_id,principal_id,challenge_id,kind,idempotency_key,request_hash,challenge_bytes,challenge_hash,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![t.org_id,t.project_id,principal,value.challenge_id,value.kind,key,request_hash.as_slice(),bytes,sha256(&bytes).as_slice(),now,expires_at],
        )?;
        audit(
            &tx,
            t,
            (input.kind == "registration").then_some(principal),
            "pending",
            "PASSKEY_CHALLENGE_CREATED",
            now,
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Admit a successful login whose state came from an authenticated encrypted
    /// ticket. Public issuance creates no database rows. Verification, the
    /// current credential update, durable replay marker, original proof and audit
    /// commit together. Failed proofs leave no persistent per-request state;
    /// the HTTP boundary records bounded denial summaries instead.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_passkey_login<F>(
        &self,
        t: &Tenant,
        principal: &str,
        input: &PasskeyLoginInput,
        proof: &Value,
        key: &str,
        now: i64,
        verify: F,
    ) -> Result<PasskeyCompletion>
    where
        F: FnOnce(&Value, &[PasskeyCredential]) -> Result<VerifiedPasskey>,
    {
        valid_uuid(&input.challenge_id)?;
        valid_uuid(key)?;
        valid_time(now)?;
        valid_time(input.created_at)?;
        valid_time(input.expires_at)?;
        binding(&input.session_binding)?;
        if input.expires_at.checked_sub(input.created_at) != Some(300)
            || now < input.created_at
            || now >= input.expires_at
        {
            return Err(StoreError::Conflict("PASSKEY_CHALLENGE_EXPIRED"));
        }
        bounded(&input.state)?;
        let proof_bytes = bounded(proof)?;
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        human(&tx, t, principal)?;
        if owner(&tx, t)?.as_deref() != Some(principal) {
            return Err(StoreError::Conflict("PASSKEY_OWNER_NOT_ENROLLED"));
        }
        let consumed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM passkey_challenges WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND challenge_id=?4)",
            params![t.org_id,t.project_id,principal,input.challenge_id], |row| row.get(0),
        )?;
        if consumed {
            return Err(StoreError::Conflict("CEREMONY_ALREADY_USED"));
        }
        let active: Vec<_> = credentials(&tx, t, principal)?
            .into_iter()
            .filter(|credential| credential.revoked_at.is_none())
            .collect();
        // A registered pending key still needs this first real signed login.
        let verified = verify(&input.state, &active)
            .map_err(|_| StoreError::Conflict("PASSKEY_PROOF_REJECTED"))?;
        credential_id(&verified.credential_id)?;
        let current = active
            .iter()
            .find(|c| c.credential_id == verified.credential_id)
            .ok_or(StoreError::NotFound)?;
        if current.revision >= i32::MAX as u64 {
            return Err(StoreError::Conflict("PASSKEY_REVISION_EXHAUSTED"));
        }
        let credential_bytes = bounded(&verified.credential)?;
        let challenge = PasskeyChallenge {
            challenge_id: input.challenge_id.clone(),
            kind: "authentication".into(),
            options: json!({}),
            state: input.state.clone(),
            created_at: input.created_at,
            expires_at: input.expires_at,
            session_binding: input.session_binding.clone(),
            name: None,
            authority: None,
            org_id: t.org_id.clone(),
            project_id: t.project_id.clone(),
            principal_id: principal.into(),
        };
        let challenge_bytes = canonical_bytes(&challenge)?;
        if tx.execute(
            "UPDATE passkey_credentials SET credential_bytes=?2,credential_hash=?3,revision=revision+1,verified_at=COALESCE(verified_at,?4),last_used_at=?4 WHERE credential_id=?1 AND revoked_at IS NULL AND revision=?5",
            params![verified.credential_id,credential_bytes,sha256(&credential_bytes).as_slice(),now,current.revision],
        )? != 1 { return Err(StoreError::Conflict("PASSKEY_CREDENTIAL_STALE")); }
        tx.execute(
            "INSERT INTO passkey_challenges(org_id,project_id,principal_id,challenge_id,kind,idempotency_key,request_hash,challenge_bytes,challenge_hash,created_at,expires_at,completed_at,completion_key,proof_bytes,proof_hash,credential_id) VALUES(?1,?2,?3,?4,'authentication',?4,?5,?6,?5,?7,?8,?9,?10,?11,?12,?13)",
            params![t.org_id,t.project_id,principal,input.challenge_id,sha256(&challenge_bytes).as_slice(),challenge_bytes,
                input.created_at,input.expires_at,now,key,proof_bytes,sha256(&proof_bytes).as_slice(),verified.credential_id],
        )?;
        audit(
            &tx,
            t,
            Some(principal),
            "success",
            "PASSKEY_AUTHENTICATED",
            now,
        )?;
        tx.commit()?;
        Ok(PasskeyCompletion {
            credential_id: verified.credential_id,
            kind: "authentication".into(),
            replayed: false,
        })
    }

    /// Verification and challenge consumption share the same write transaction.
    /// The callback must perform bounded local verification only: no I/O, store
    /// re-entry, secret logging, or externally visible side effects.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_passkey_challenge<F>(
        &self,
        t: &Tenant,
        principal: &str,
        challenge_id: &str,
        expected_kind: &str,
        session_binding: &str,
        proof: &Value,
        key: &str,
        now: i64,
        verify: F,
    ) -> Result<PasskeyCompletion>
    where
        F: FnOnce(&PasskeyChallenge, &[PasskeyCredential]) -> Result<VerifiedPasskey>,
    {
        valid_uuid(challenge_id)?;
        valid_uuid(key)?;
        valid_time(now)?;
        binding(session_binding)?;
        kind(expected_kind)?;
        let proof_bytes = bounded(proof)?;
        let proof_hash = sha256(&proof_bytes);
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        human(&tx, t, principal)?;
        let saved = challenge(&tx, t, principal, challenge_id)?;
        if saved.challenge.kind != expected_kind
            || saved.challenge.session_binding != session_binding
        {
            return Err(StoreError::NotFound);
        }
        // A successful retry only returns the earlier result. It cannot rerun
        // the verifier, update a counter, or authorize issuance of a new session.
        if let Some(completed_at) = saved.completed_at {
            if now < completed_at
                || saved.completion_key.as_deref() != Some(key)
                || saved.proof_hash.as_deref() != Some(proof_hash.as_slice())
            {
                return Err(StoreError::IdempotencyConflict);
            }
            let credential_id = saved
                .credential_id
                .ok_or(StoreError::Integrity("completion credential"))?;
            unrevoked_credential(&tx, t, principal, &credential_id)?;
            return Ok(PasskeyCompletion {
                credential_id,
                kind: expected_kind.into(),
                replayed: true,
            });
        }
        validate_window(&saved.challenge, now)?;
        if saved.failures >= MAX_FAILURES {
            return Err(StoreError::Conflict("PASSKEY_CHALLENGE_LOCKED"));
        }
        if let Some(authority) = &saved.challenge.authority {
            authorize_registration(&tx, t, principal, authority, now)?;
        } else if owner(&tx, t)?.as_deref() != Some(principal) {
            return Err(StoreError::Conflict("PASSKEY_OWNER_NOT_ENROLLED"));
        }
        let active: Vec<_> = credentials(&tx, t, principal)?
            .into_iter()
            .filter(|credential| credential.revoked_at.is_none())
            .collect();
        let verified = match verify(&saved.challenge, &active) {
            Ok(value) => value,
            Err(_) => {
                tx.execute(
                    "UPDATE passkey_challenges SET failures=failures+1 WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND challenge_id=?4",
                    params![t.org_id,t.project_id,principal,challenge_id],
                )?;
                audit(
                    &tx,
                    t,
                    (expected_kind == "registration").then_some(principal),
                    "denied",
                    "PASSKEY_PROOF_REJECTED",
                    now,
                )?;
                tx.commit()?;
                return Err(StoreError::Conflict("PASSKEY_PROOF_REJECTED"));
            }
        };
        credential_id(&verified.credential_id)?;
        let credential_bytes = bounded(&verified.credential)?;
        match expected_kind {
            "registration" => {
                if active.len() >= MAX_CREDENTIALS {
                    return Err(StoreError::Conflict("PASSKEY_CREDENTIAL_LIMIT"));
                }
                let exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE credential_id=?1)",
                    [&verified.credential_id],
                    |row| row.get(0),
                )?;
                if exists {
                    return Err(StoreError::Conflict(
                        "PASSKEY_CREDENTIAL_ALREADY_REGISTERED",
                    ));
                }
                if owner(&tx, t)?.is_none() {
                    tx.execute(
                        "INSERT INTO passkey_owners VALUES(?1,?2,?3,'owner',?4)",
                        params![t.org_id, t.project_id, principal, now],
                    )?;
                }
                tx.execute(
                    "INSERT INTO passkey_credentials VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,NULL,NULL,NULL)",
                    params![
                        verified.credential_id,
                        t.org_id,
                        t.project_id,
                        principal,
                        saved
                            .challenge
                            .name
                            .as_deref()
                            .ok_or(StoreError::Integrity("registration name"))?,
                        credential_bytes,
                        sha256(&credential_bytes).as_slice(),
                        now
                    ],
                )?;
            }
            "authentication" => {
                let current = active
                    .iter()
                    .find(|entry| entry.credential_id == verified.credential_id)
                    .ok_or(StoreError::NotFound)?;
                if current.revision >= i32::MAX as u64 {
                    return Err(StoreError::Conflict("PASSKEY_REVISION_EXHAUSTED"));
                }
                tx.execute(
                    "UPDATE passkey_credentials SET credential_bytes=?2,credential_hash=?3,revision=revision+1,verified_at=COALESCE(verified_at,?4),last_used_at=?4 WHERE credential_id=?1 AND revoked_at IS NULL",
                    params![verified.credential_id,credential_bytes,sha256(&credential_bytes).as_slice(),now],
                )?;
            }
            _ => return Err(StoreError::InvalidInput("ceremony kind")),
        }
        tx.execute(
            "UPDATE passkey_challenges SET completed_at=?5,completion_key=?6,proof_bytes=?7,proof_hash=?8,credential_id=?9 WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND challenge_id=?4 AND completed_at IS NULL",
            params![t.org_id,t.project_id,principal,challenge_id,now,key,proof_bytes,proof_hash.as_slice(),verified.credential_id],
        )?;
        let reason = if expected_kind == "registration" {
            "PASSKEY_REGISTERED"
        } else {
            "PASSKEY_AUTHENTICATED"
        };
        audit(&tx, t, Some(principal), "success", reason, now)?;
        tx.commit()?;
        Ok(PasskeyCompletion {
            credential_id: verified.credential_id,
            kind: expected_kind.into(),
            replayed: false,
        })
    }

    pub fn revoke_passkey(
        &self,
        t: &Tenant,
        principal: &str,
        id: &str,
        authority: &PasskeyAuthority,
        key: &str,
        now: i64,
    ) -> Result<RegistryMutation> {
        valid_uuid(key)?;
        valid_time(now)?;
        credential_id(id)?;
        let digest = sha256(&canonical_bytes(
            &json!({"credential_id":id,"authority":authority}),
        )?);
        let mut c = self.connection()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        human(&tx, t, principal)?;
        let previous: Option<(Vec<u8>,Vec<u8>)> = tx.query_row(
            "SELECT request_hash,response_bytes FROM passkey_revocations WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND idempotency_key=?4",
            params![t.org_id,t.project_id,principal,key], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        if let Some((expected, response)) = previous {
            if expected != digest {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(RegistryMutation {
                value: serde_json::from_slice(&response)?,
                replayed: true,
            });
        }
        authorize_existing(&tx, t, principal, authority, now)?;
        let target = unrevoked_credential(&tx, t, principal, id)?;
        if target.verified_at.is_some() && verified_count(&tx, t, principal)? <= 1 {
            return Err(StoreError::Conflict("PASSKEY_LAST_CREDENTIAL"));
        }
        tx.execute("UPDATE passkey_credentials SET revoked_at=?2 WHERE credential_id=?1 AND revoked_at IS NULL", params![id,now])?;
        let value = json!({"credential_id":id,"revoked_at":timestamp(now)?});
        tx.execute(
            "INSERT INTO passkey_revocations VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                t.org_id,
                t.project_id,
                principal,
                key,
                digest.as_slice(),
                id,
                now,
                canonical_bytes(&value)?
            ],
        )?;
        audit(&tx, t, Some(principal), "success", "PASSKEY_REVOKED", now)?;
        tx.commit()?;
        Ok(RegistryMutation {
            value,
            replayed: false,
        })
    }
}

fn human(c: &Connection, t: &Tenant, principal: &str) -> Result<()> {
    valid_uuid(principal)?;
    active_principal(c, t, principal)?;
    let is_human: bool = c.query_row(
        "SELECT kind='human' FROM principals WHERE org_id=?1 AND project_id=?2 AND principal_id=?3",
        params![t.org_id, t.project_id, principal],
        |row| row.get(0),
    )?;
    if !is_human {
        return Err(StoreError::NotFound);
    }
    Ok(())
}
fn owner(c: &Connection, t: &Tenant) -> Result<Option<String>> {
    Ok(c.query_row(
        "SELECT principal_id FROM passkey_owners WHERE org_id=?1 AND project_id=?2",
        params![t.org_id, t.project_id],
        |row| row.get(0),
    )
    .optional()?)
}
fn active_count(c: &Connection, t: &Tenant, principal: &str) -> Result<u64> {
    Ok(c.query_row("SELECT count(*) FROM passkey_credentials WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND revoked_at IS NULL", params![t.org_id,t.project_id,principal], |row| row.get(0))?)
}
fn credentials(c: &Connection, t: &Tenant, principal: &str) -> Result<Vec<PasskeyCredential>> {
    let mut query = c.prepare("SELECT credential_id,name,credential_bytes,credential_hash,revision,created_at,verified_at,last_used_at,revoked_at FROM passkey_credentials WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 ORDER BY created_at,credential_id")?;
    let rows = query
        .query_map(params![t.org_id, t.project_id, principal], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(
            |(
                id,
                name,
                bytes,
                hash,
                revision,
                created_at,
                verified_at,
                last_used_at,
                revoked_at,
            )| {
                if sha256(&bytes).as_slice() != hash {
                    return Err(StoreError::Integrity("passkey credential content"));
                }
                Ok(PasskeyCredential {
                    credential_id: id,
                    name,
                    credential: serde_json::from_slice(&bytes)?,
                    revision,
                    created_at,
                    verified_at,
                    last_used_at,
                    revoked_at,
                })
            },
        )
        .collect()
}
fn active_credential(
    c: &Connection,
    t: &Tenant,
    principal: &str,
    id: &str,
) -> Result<PasskeyCredential> {
    let credential = unrevoked_credential(c, t, principal, id)?;
    if credential.verified_at.is_none() {
        return Err(StoreError::Conflict("PASSKEY_NOT_ACTIVATED"));
    }
    Ok(credential)
}
fn unrevoked_credential(
    c: &Connection,
    t: &Tenant,
    principal: &str,
    id: &str,
) -> Result<PasskeyCredential> {
    credential_id(id)?;
    credentials(c, t, principal)?
        .into_iter()
        .find(|entry| entry.credential_id == id && entry.revoked_at.is_none())
        .ok_or(StoreError::NotFound)
}
fn verified_count(c: &Connection, t: &Tenant, principal: &str) -> Result<u64> {
    Ok(c.query_row("SELECT count(*) FROM passkey_credentials WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND revoked_at IS NULL AND verified_at IS NOT NULL", params![t.org_id,t.project_id,principal], |row| row.get(0))?)
}
fn authorize_registration(
    c: &Connection,
    t: &Tenant,
    principal: &str,
    authority: &PasskeyAuthority,
    now: i64,
) -> Result<()> {
    match authority {
        PasskeyAuthority::Bootstrap => {
            if owner(c, t)?.is_some() {
                return Err(StoreError::Conflict("PASSKEY_OWNER_ALREADY_ENROLLED"));
            }
            Ok(())
        }
        _ => authorize_existing(c, t, principal, authority, now),
    }
}
fn authorize_existing(
    c: &Connection,
    t: &Tenant,
    principal: &str,
    authority: &PasskeyAuthority,
    now: i64,
) -> Result<()> {
    let PasskeyAuthority::Passkey {
        credential_id,
        authenticated_at,
    } = authority
    else {
        return Err(StoreError::Conflict("PASSKEY_AUTHENTICATION_REQUIRED"));
    };
    valid_time(*authenticated_at)?;
    if owner(c, t)?.as_deref() != Some(principal)
        || *authenticated_at > now
        || now - *authenticated_at >= 300
    {
        return Err(StoreError::Conflict(
            "PASSKEY_FRESH_AUTHENTICATION_REQUIRED",
        ));
    }
    let credential = active_credential(c, t, principal, credential_id)?;
    if credential
        .verified_at
        .is_none_or(|first| *authenticated_at < first)
        || credential
            .last_used_at
            .is_none_or(|last| *authenticated_at > last)
    {
        return Err(StoreError::Conflict(
            "PASSKEY_FRESH_AUTHENTICATION_REQUIRED",
        ));
    }
    Ok(())
}
fn binding(value: &str) -> Result<()> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StoreError::InvalidInput("session binding"));
    }
    Ok(())
}
fn credential_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 2048
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(StoreError::InvalidInput("credential identifier"));
    }
    Ok(())
}
fn label(value: &str) -> Result<()> {
    if value.trim() != value
        || value.is_empty()
        || value.chars().count() > 80
        || value.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidInput("passkey name"));
    }
    Ok(())
}
fn kind(value: &str) -> Result<()> {
    if !matches!(value, "registration" | "authentication") {
        return Err(StoreError::InvalidInput("ceremony kind"));
    }
    Ok(())
}
fn bounded(value: &Value) -> Result<Vec<u8>> {
    let bytes = canonical_bytes(value)?;
    if bytes.len() > 65536 {
        return Err(StoreError::InvalidInput("passkey object size"));
    }
    Ok(bytes)
}
fn validate_window(challenge: &PasskeyChallenge, now: i64) -> Result<()> {
    if now < challenge.created_at || now >= challenge.expires_at {
        return Err(StoreError::Conflict("PASSKEY_CHALLENGE_EXPIRED"));
    }
    Ok(())
}
struct StoredChallenge {
    challenge: PasskeyChallenge,
    failures: u32,
    completed_at: Option<i64>,
    completion_key: Option<String>,
    proof_hash: Option<Vec<u8>>,
    credential_id: Option<String>,
}
fn challenge(c: &Connection, t: &Tenant, principal: &str, id: &str) -> Result<StoredChallenge> {
    let row = c.query_row(
        "SELECT challenge_bytes,challenge_hash,kind,created_at,expires_at,failures,completed_at,completion_key,proof_hash,credential_id FROM passkey_challenges WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND challenge_id=?4",
        params![t.org_id,t.project_id,principal,id], |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,String>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,u32>(5)?,row.get::<_,Option<i64>>(6)?,row.get::<_,Option<String>>(7)?,row.get::<_,Option<Vec<u8>>>(8)?,row.get::<_,Option<String>>(9)?)),
    ).optional()?.ok_or(StoreError::NotFound)?;
    if sha256(&row.0).as_slice() != row.1 {
        return Err(StoreError::Integrity("passkey challenge content"));
    }
    let value: PasskeyChallenge = serde_json::from_slice(&row.0)?;
    if value.challenge_id != id
        || value.org_id != t.org_id
        || value.project_id != t.project_id
        || value.principal_id != principal
        || value.kind != row.2
        || value.created_at != row.3
        || value.expires_at != row.4
    {
        return Err(StoreError::Integrity("passkey challenge binding"));
    }
    Ok(StoredChallenge {
        challenge: value,
        failures: row.5,
        completed_at: row.6,
        completion_key: row.7,
        proof_hash: row.8,
        credential_id: row.9,
    })
}
fn audit(
    tx: &Transaction<'_>,
    t: &Tenant,
    actor: Option<&str>,
    outcome: &str,
    reason: &str,
    now: i64,
) -> Result<()> {
    append_audit(
        tx,
        t,
        actor,
        "administration",
        "system",
        None,
        None,
        outcome,
        Some(reason),
        now,
    )
}
