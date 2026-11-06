//! Protected-local identity pins and exact retained bootstrap inputs.
//!
//! A verified workload identity and a human bootstrap decision are useful
//! authority evidence, but cannot qualify native enforcement or open dispatch.
use super::*;
use crate::AuthorityGate as Gate;
use crate::{
    AccessEnvelope, AuthorityBootstrapManifest, BootstrapApprovalProof, BootstrapAuthorization,
    Delegation, RegistryTrustKey, WorkloadBinding, validate_access_envelope, validate_delegation,
    verify_bootstrap_authorization, verify_workload_binding,
};
use fw_webauthn::AuthenticationResponse;

const MAX_OBJECT: usize = 262144;

#[derive(Clone, Debug, Serialize)]
pub struct AuthorityRegistryStatus {
    pub schema_version: String,
    pub object_kind: String,
    pub object_id: String,
    pub state: String,
    pub content_hash: String,
    pub target_id: String,
    pub admitted_at: String,
    pub checked_at: String,
    /// True only for a current cryptographically checked workload identity.
    /// Bootstrap inputs remain staged until target confirmation is implemented.
    pub current: bool,
    pub revoked: bool,
    pub gates: Vec<String>,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct BootstrapProofResult {
    pub proof: BootstrapApprovalProof,
    pub proof_hash: String,
    pub replayed: bool,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthorizedBootstrapResult {
    pub authorization: BootstrapAuthorization,
    pub status: AuthorityRegistryStatus,
}

struct Object {
    kind: String,
    id: String,
    hash: String,
    target: String,
    admitted: i64,
    canonical: Vec<u8>,
    revoked: bool,
}

pub(super) struct RetainedBootstrapMaterial {
    pub manifest: AuthorityBootstrapManifest,
    pub authorization: BootstrapAuthorization,
    pub proofs: Vec<BootstrapApprovalProof>,
    pub root: RegistryTrustKey,
    pub authorization_hash: String,
    pub valid_until: i64,
}

/// Target confirmation consumes retained protected authority, never submitted
/// proof objects or a controller's boolean. Historical reads retain old bytes.
pub(super) fn bootstrap_material_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    manifest_id: &str,
    now: i64,
    current: bool,
) -> Result<RetainedBootstrapMaterial> {
    let (manifest_object, manifest) = manifest_at(tx, tenant, manifest_id)?;
    let object = object_at(tx, tenant, "bootstrap_authorization", manifest_id)?
        .ok_or(AuthorityError::Binding)?;
    validate_authorization_record(tx, tenant, &object)?;
    let authorization: BootstrapAuthorization = decode(&object.canonical)?;
    let valid_until = if current {
        current_authorization(tx, tenant, &object, now)?
    } else {
        crate::timestamp(&authorization.payload.not_after)?
    };
    if current && manifest_object.revoked {
        return Err(AuthorityError::Binding);
    }
    let mut root = key_at(tx, tenant, &authorization.payload.signer_key_id)?;
    if !current {
        root.revoked = false;
    }
    let mut proofs = Vec::new();
    for digest in &authorization.payload.approval_proof_hashes {
        let id:String=tx.query_row("SELECT proof_id FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND proof_hash=?",params![tenant.org_id,tenant.project_id,hash(digest)?],|row|row.get(0)).optional()?.ok_or(AuthorityError::Binding)?;
        proofs.push(verify_bootstrap_proof_record(tx, tenant, &id, None, false)?);
    }
    Ok(RetainedBootstrapMaterial {
        manifest,
        authorization,
        proofs,
        root,
        authorization_hash: object.hash,
        valid_until,
    })
}

/// Current root authorization for this exact retained plan, in its caller's
/// validated snapshot. A short authorization is not persistent target state.
pub(super) fn bootstrap_for_plan_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan: &Value,
    now: i64,
) -> Result<Option<(String, i64)>> {
    require_registry_time(tx, tenant, now)?;
    let retained = records::retained_plan(tx, tenant, crate::string(plan, "plan_id")?)?;
    if retained.subject.plan_bytes != bytes(plan)? {
        return Err(AuthorityError::Binding);
    }
    let Some(review) = review_evidence::review_in_tx(tx, tenant, &retained.subject, now)? else {
        return Ok(None);
    };
    let target = crate::string(plan, "target_id")?;
    let epoch = crate::counter(crate::string(plan, "authority_epoch")?)?;
    let digest:Option<Vec<u8>>=tx.query_row("SELECT authorization_hash FROM authority_bootstrap_pending_heads WHERE org_id=? AND project_id=? AND target_id=? AND authority_epoch=?",params![tenant.org_id,tenant.project_id,target,epoch.to_be_bytes().as_slice()],|row|row.get(0)).optional()?;
    let Some(digest) = digest else {
        return Ok(None);
    };
    let object = object_hash_at(tx, tenant, &hash_string(&digest)?)?;
    let (_, manifest) = manifest_at(tx, tenant, &object.id)?;
    if manifest.management_baseline_hash != review.evidence().before.management_baseline_hash
        || manifest.capability_hash != crate::string(plan, "target_capability_hash")?
    {
        return Ok(None);
    }
    if plan["change_kind"] == "add_access_lease"
        && (!manifest
            .envelope_hashes
            .iter()
            .any(|hash| plan["envelope_hash"] == *hash)
            || !manifest
                .delegation_hashes
                .iter()
                .any(|hash| plan["delegation_hash"] == *hash))
    {
        return Ok(None);
    }
    match current_authorization(tx, tenant, &object, now) {
        Ok(until) => Ok(Some((object.hash, until))),
        Err(AuthorityError::Time | AuthorityError::Binding | AuthorityError::Conflict) => Ok(None),
        Err(error) => Err(error),
    }
}

fn binding(tenant: &AuthorityTenant, org: &str, project: &str) -> Result<()> {
    if tenant.org_id != org || tenant.project_id != project {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}

pub(super) fn object_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(chunk.len())
                .ok_or_else(|| std::io::Error::other("registry object size"))?;
            Ok(chunk.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(MAX_OBJECT), value)
        .map_err(|_| invalid("registry object size"))?;
    let result = bytes(value)?;
    if result.len() > MAX_OBJECT {
        return Err(invalid("registry object size"));
    }
    Ok(result)
}

fn key_at(tx: &Transaction<'_>, tenant: &AuthorityTenant, key: &str) -> Result<RegistryTrustKey> {
    type RegistryKeyRow = (
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        Vec<u8>,
        bool,
    );
    let row: RegistryKeyRow = tx.query_row(
        "SELECT target_id,payload_type,CASE WHEN length(public_key)=32 THEN public_key END,CASE WHEN length(key_fingerprint)=32 THEN key_fingerprint END,not_before,not_after,pinned_at,CASE WHEN length(canonical_bytes)<=8192 THEN canonical_bytes END,EXISTS(SELECT 1 FROM authority_registry_key_revocations r WHERE r.org_id=k.org_id AND r.project_id=k.project_id AND r.key_id=k.key_id) FROM authority_registry_keys k WHERE org_id=? AND project_id=? AND key_id=?",
        params![tenant.org_id,tenant.project_id,key], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))
    ).optional()?.ok_or(AuthorityError::Binding)?;
    let mut result: RegistryTrustKey = decode(&row.7)?;
    if result.key_id != key
        || result.org_id != tenant.org_id
        || result.project_id != tenant.project_id
        || result.target_id != row.0
        || result.payload_type != row.1
        || result.public_key.as_slice() != row.2
        || hash(&hash_bytes(&row.2))? != row.3
        || result.not_before != row.4
        || result.not_after != row.5
        || result.revoked
        || bytes(&result)? != row.7
    {
        return Err(invalid("registry key projection"));
    }
    result.validate(row.6)?;
    result.revoked = row.8;
    Ok(result)
}

fn object_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    kind: &str,
    id: &str,
) -> Result<Option<Object>> {
    type RegistryObjectRow = (Vec<u8>, String, i64, Vec<u8>, bool);
    let result:Option<RegistryObjectRow>=tx.query_row(
        "SELECT CASE WHEN length(content_hash)=32 THEN content_hash END,target_id,admitted_at,CASE WHEN length(canonical_bytes) BETWEEN 1 AND 262144 THEN canonical_bytes END,EXISTS(SELECT 1 FROM authority_registry_object_revocations r WHERE r.org_id=o.org_id AND r.project_id=o.project_id AND r.content_hash=o.content_hash) FROM authority_registry_objects o WHERE org_id=? AND project_id=? AND object_kind=? AND object_id=?",
        params![tenant.org_id,tenant.project_id,kind,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))
    ).optional()?;
    result
        .map(|(digest, target, admitted, canonical, revoked)| {
            identifier(&target)?;
            time(admitted)?;
            if hash(&hash_bytes(&canonical))? != digest {
                return Err(invalid("registry object hash"));
            }
            Ok(Object {
                kind: kind.into(),
                id: id.into(),
                hash: hash_string(&digest)?,
                target,
                admitted,
                canonical,
                revoked,
            })
        })
        .transpose()
}

fn object_hash_at(tx: &Transaction<'_>, tenant: &AuthorityTenant, digest: &str) -> Result<Object> {
    let (kind,id):(String,String)=tx.query_row("SELECT object_kind,object_id FROM authority_registry_objects WHERE org_id=? AND project_id=? AND content_hash=?",params![tenant.org_id,tenant.project_id,hash(digest)?],|r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(AuthorityError::Binding)?;
    object_at(tx, tenant, &kind, &id)?.ok_or(AuthorityError::Binding)
}

fn insert_object(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    kind: &str,
    id: &str,
    target: &str,
    canonical: &[u8],
    now: i64,
) -> Result<Object> {
    if let Some(existing) = object_at(tx, tenant, kind, id)? {
        if existing.canonical != canonical || existing.target != target {
            return Err(AuthorityError::Conflict);
        }
        return Ok(existing);
    }
    tx.execute(
        "INSERT INTO authority_registry_objects VALUES(?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            kind,
            id,
            hash(&hash_bytes(canonical))?,
            target,
            now,
            canonical
        ],
    )?;
    bump_security(tx, tenant)?;
    audit(tx, tenant, &format!("registry_{kind}_admitted"), id, now)?;
    object_at(tx, tenant, kind, id)?.ok_or(AuthorityError::Binding)
}

fn status(
    object: &Object,
    now: i64,
    current: bool,
    gates: Vec<String>,
) -> Result<AuthorityRegistryStatus> {
    Ok(AuthorityRegistryStatus {
        schema_version: "fw.authority-registry-status/v1".into(),
        object_kind: object.kind.clone(),
        object_id: object.id.clone(),
        state: if object.revoked {
            "revoked"
        } else if current {
            "current"
        } else if object.kind == "workload_binding" {
            "historical"
        } else if object.kind == "bootstrap_authorization" {
            "authorized_pending_target_confirmation"
        } else {
            "staged"
        }
        .into(),
        content_hash: object.hash.clone(),
        target_id: object.target.clone(),
        admitted_at: at(object.admitted)?,
        checked_at: at(now)?,
        current: current && !object.revoked,
        revoked: object.revoked,
        gates,
        signing_allowed: false,
        dispatch_allowed: false,
    })
}

fn clock_floor(tx: &Transaction<'_>, tenant: &AuthorityTenant) -> Result<i64> {
    Ok(tx
        .query_row(
            "SELECT observed_at FROM authority_registry_clocks WHERE org_id=? AND project_id=?",
            params![tenant.org_id, tenant.project_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

pub(super) fn require_registry_time(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    now: i64,
) -> Result<()> {
    time(now)?;
    if now < clock_floor(tx, tenant)? {
        return Err(AuthorityError::Time);
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    pub(super) static AFTER_OBSERVATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {std::cell::RefCell::new(None)};
}

impl AuthorityStore {
    /// Purpose-specific signer entry point. Resolve every input from this
    /// protected store; the caller can select only a retained manifest and pin.
    /// Signing occurs outside SQLite's writer transaction, and import repeats
    /// every current proof/key/input check before committing exact signed bytes.
    pub fn authorize_retained_bootstrap(
        &mut self,
        tenant: &AuthorityTenant,
        manifest_id: &str,
        key_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<AuthorizedBootstrapResult> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use ed25519_dalek::Signer;
        identifier(manifest_id)?;
        self.observe_registry_time(tenant, now)?;
        let payload = {
            let tx = self.connection.transaction()?;
            require_registry_time(&tx, tenant, now)?;
            let origin = bootstrap_origin::current_origin(&tx, tenant, now)?;
            bootstrap_origin::require_verifier(&origin, verifier)?;
            let key = key_at(&tx, tenant, key_id)?;
            if key.payload_type != crate::BOOTSTRAP_AUTHORIZATION_TYPE
                || key.public_key != signing_key.verifying_key().to_bytes()
            {
                return Err(AuthorityError::Signature);
            }
            if let Some(existing) = object_at(&tx, tenant, "bootstrap_authorization", manifest_id)?
            {
                let authorization: BootstrapAuthorization = decode(&existing.canonical)?;
                if authorization.payload.signer_key_id != key_id {
                    return Err(AuthorityError::Conflict);
                }
                validate_authorization_record(&tx, tenant, &existing)?;
                let result = AuthorizedBootstrapResult {
                    authorization,
                    status: object_status(&tx, tenant, &existing, now)?,
                };
                tx.commit()?;
                return Ok(result);
            }
            key.validate(now)?;
            let (object, manifest) = manifest_at(&tx, tenant, manifest_id)?;
            if object.revoked {
                return Err(AuthorityError::Binding);
            }
            require_manifest_inputs(&tx, tenant, &manifest, now)?;
            require_bootstrap_epoch(&tx, tenant, &manifest)?;
            if canonical_hash(&key).map_err(|_| invalid("bootstrap root pin"))?
                != manifest.trust_root_hash
            {
                return Err(AuthorityError::Binding);
            }
            let mut statement=tx.prepare("SELECT proof_id FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND manifest_id=? AND admitted_at<=? AND expires_at>? ORDER BY proof_hash LIMIT 17")?;
            let ids = statement
                .query_map(
                    params![tenant.org_id, tenant.project_id, manifest_id, now, now],
                    |r| r.get::<_, String>(0),
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if ids.len() > 16 {
                return Err(AuthorityError::Quota);
            }
            // One current owner is the fixed initial bootstrap profile. Never
            // infer distinct people from multiple credentials or aliases.
            let mut selected = None;
            for id in ids {
                match verify_bootstrap_proof_record(&tx, tenant, &id, Some((verifier, now)), true) {
                    Ok(proof) => {
                        selected = Some(proof);
                        break;
                    }
                    Err(AuthorityError::Time | AuthorityError::Binding) => {}
                    Err(error) => return Err(error),
                }
            }
            let proof = selected.ok_or(AuthorityError::Binding)?;
            let payload = crate::BootstrapAuthorizationPayload {
                schema_version: "f.bootstrap-authorization/v1".into(),
                manifest_hash: manifest.hash()?,
                approval_proof_hashes: vec![proof.hash()?],
                signer_key_id: key_id.into(),
                issued_at: at(now)?,
                not_after: at(crate::timestamp(&manifest.expires_at)?
                    .min(crate::timestamp(&proof.valid_until)?)
                    .min(key.not_after)
                    .min(now + 300))?,
            };
            drop(statement);
            tx.commit()?;
            payload
        };
        let payload_bytes = bytes(&payload)?;
        let signature = signing_key.sign(&crate::pae(
            crate::BOOTSTRAP_AUTHORIZATION_TYPE,
            &payload_bytes,
        ));
        let authorization = BootstrapAuthorization {
            schema_version: "f.bootstrap-authorization-envelope/v1".into(),
            payload,
            dsse: crate::DsseEnvelope {
                payload_type: crate::BOOTSTRAP_AUTHORIZATION_TYPE.into(),
                payload: STANDARD.encode(&payload_bytes),
                signatures: vec![crate::DsseSignature {
                    keyid: key_id.into(),
                    sig: STANDARD.encode(signature.to_bytes()),
                }],
            },
        };
        let status =
            self.admit_bootstrap_authorization(tenant, manifest_id, &authorization, verifier, now)?;
        Ok(AuthorizedBootstrapResult {
            authorization,
            status,
        })
    }

    /// Persist time before admission so a rejected/expired input cannot revive
    /// after clock rollback. This does not reserve quota or a target generation.
    pub(super) fn observe_registry_time(
        &mut self,
        tenant: &AuthorityTenant,
        now: i64,
    ) -> Result<()> {
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        security_revision(&tx, tenant)?;
        let floor = clock_floor(&tx, tenant)?;
        if now < floor {
            return Err(AuthorityError::Time);
        }
        retained_projection(
            &tx,
            "UPDATE authority_registry_clocks SET observed_at=?3 WHERE org_id=?1 AND project_id=?2",
            "INSERT INTO authority_registry_clocks VALUES(?1,?2,?3)",
            params![tenant.org_id, tenant.project_id, now],
        )?;
        tx.commit()?;
        #[cfg(test)]
        AFTER_OBSERVATION_HOOK.with(|hook| {
            let callback = hook.borrow_mut().take();
            if let Some(callback) = callback {
                callback();
            }
        });
        Ok(())
    }

    /// Independently authenticated local administrator only. Pinning a public
    /// key is the OOB trust decision; no self-signed input provisions this pin.
    pub fn pin_registry_trust_key(
        &mut self,
        tenant: &AuthorityTenant,
        key: &RegistryTrustKey,
        now: i64,
    ) -> Result<()> {
        key.validate(now)?;
        binding(tenant, &key.org_id, &key.project_id)?;
        if key.revoked {
            return Err(AuthorityError::Binding);
        }
        let canonical = object_bytes(key)?;
        if canonical.len() > 8192 {
            return Err(invalid("registry key size"));
        }
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        security_revision(&tx, tenant)?;
        if now < clock_floor(&tx, tenant)? {
            return Err(AuthorityError::Time);
        }
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_registry_keys WHERE org_id=? AND project_id=? AND key_id=?)",params![tenant.org_id,tenant.project_id,key.key_id],|r|r.get(0))?;
        if exists {
            let previous = key_at(&tx, tenant, &key.key_id)?;
            if previous.revoked {
                return Err(AuthorityError::Conflict);
            }
            if bytes(&previous)? != canonical {
                return Err(AuthorityError::Conflict);
            }
            tx.commit()?;
            return Ok(());
        }
        let fingerprint = hash(&hash_bytes(&key.public_key))?;
        // Purpose separation extends existing target transport/observer pins.
        // Fingerprint encodings differ between registry (raw Ed25519) and
        // transport/observer (SPKI). Purpose ownership follows the key bytes.
        let alias:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_target_keys WHERE org_id=? AND public_key=?) OR EXISTS(SELECT 1 FROM authority_native_observer_keys WHERE org_id=? AND public_key=?) OR EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins WHERE org_id=? AND public_key=?)",params![tenant.org_id,key.public_key.as_slice(),tenant.org_id,key.public_key.as_slice(),tenant.org_id,key.public_key.as_slice()],|r|r.get(0))?;
        if alias {
            return Err(AuthorityError::Conflict);
        }
        tx.execute(
            "INSERT INTO authority_registry_keys VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                key.key_id,
                key.target_id,
                key.payload_type,
                key.public_key.as_slice(),
                fingerprint,
                key.not_before,
                key.not_after,
                now,
                canonical
            ],
        )?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "registry_trust_key_pinned", &key.key_id, now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn revoke_registry_trust_key(
        &mut self,
        tenant: &AuthorityTenant,
        key_id: &str,
        now: i64,
    ) -> Result<()> {
        if key_id.is_empty() || key_id.chars().count() > 256 || key_id.chars().any(char::is_control)
        {
            return Err(invalid("registry key identity"));
        }
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        let key = key_at(&tx, tenant, key_id)?;
        if !key.revoked {
            tx.execute(
                "INSERT INTO authority_registry_key_revocations VALUES(?,?,?,?)",
                params![tenant.org_id, tenant.project_id, key_id, now],
            )?;
            bump_security(&tx, tenant)?;
            audit(&tx, tenant, "registry_trust_key_revoked", key_id, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn admit_workload_binding(
        &mut self,
        tenant: &AuthorityTenant,
        binding_value: &WorkloadBinding,
        now: i64,
    ) -> Result<AuthorityRegistryStatus> {
        binding_value.validate_shape()?;
        let canonical = object_bytes(binding_value)?;
        // Validate closed structure/signature before changing durable time.
        {
            let tx = self.connection.transaction()?;
            require_registry_time(&tx, tenant, now)?;
            let mut key = key_at(&tx, tenant, &binding_value.payload.issuer_key_id)?;
            key.revoked = false;
            // A real historical signature may be checked before observing an
            // expired current input. Malformed/forged input cannot move time.
            verify_workload_binding(
                binding_value,
                &key,
                crate::timestamp(&binding_value.payload.not_before)?.max(key.not_before),
            )?;
            tx.commit()?;
        }
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        if let Some(existing) = object_at(
            &tx,
            tenant,
            "workload_binding",
            &binding_value.payload.binding_id,
        )? {
            if existing.canonical != canonical {
                return Err(AuthorityError::Conflict);
            }
            let result = object_status(&tx, tenant, &existing, now)?;
            tx.commit()?;
            return Ok(result);
        }
        binding_value.validate_current_admission_profile()?;
        let key = key_at(&tx, tenant, &binding_value.payload.issuer_key_id)?;
        let verified = verify_workload_binding(binding_value, &key, now)?;
        binding(
            tenant,
            &binding_value.payload.org_id,
            &binding_value.payload.project_id,
        )?;
        let object = insert_object(
            &tx,
            tenant,
            "workload_binding",
            verified.binding_id(),
            verified.target_id(),
            &canonical,
            now,
        )?;
        if object.revoked {
            return Err(AuthorityError::Binding);
        }
        let epoch = verified.binding_epoch().to_be_bytes();
        let previous:Option<(String,Vec<u8>,Vec<u8>)>=tx.query_row("SELECT binding_id,binding_epoch,content_hash FROM authority_workload_heads WHERE org_id=? AND project_id=? AND principal_id=? AND target_id=? AND workload_id=?",params![tenant.org_id,tenant.project_id,verified.principal_id(),verified.target_id(),binding_value.payload.workload_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((old_id, old_epoch, old_hash)) = &previous {
            if old_id == verified.binding_id() && old_hash == &hash(verified.hash())? {
                let result = status(&object, now, true, vec![])?;
                tx.commit()?;
                return Ok(result);
            }
            if old_epoch.as_slice() >= epoch.as_slice() {
                return Err(AuthorityError::Conflict);
            }
        }
        retained_projection(
            &tx,
            "UPDATE authority_workload_heads SET binding_id=?6,binding_epoch=?7,content_hash=?8 WHERE org_id=?1 AND project_id=?2 AND principal_id=?3 AND target_id=?4 AND workload_id=?5",
            "INSERT INTO authority_workload_heads VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                tenant.org_id,
                tenant.project_id,
                verified.principal_id(),
                verified.target_id(),
                binding_value.payload.workload_id,
                verified.binding_id(),
                epoch.as_slice(),
                hash(verified.hash())?
            ],
        )?;
        let result = status(&object, now, true, vec![])?;
        tx.commit()?;
        Ok(result)
    }

    /// Exact original objects are staged, without fabricated approval or grants.
    pub fn stage_access_envelope(
        &mut self,
        tenant: &AuthorityTenant,
        envelope: &AccessEnvelope,
        now: i64,
    ) -> Result<AuthorityRegistryStatus> {
        validate_access_envelope(envelope)?;
        binding(tenant, &envelope.org_id, &envelope.project_id)?;
        let canonical = object_bytes(envelope)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        let object = insert_object(
            &tx,
            tenant,
            "envelope",
            &format!("{}:{}", envelope.envelope_id, envelope.revision),
            &envelope.target_id,
            &canonical,
            now,
        )?;
        let result = status(
            &object,
            now,
            false,
            vec![Gate::BootstrapAuthorizationRequired.code().into()],
        )?;
        tx.commit()?;
        Ok(result)
    }

    pub fn stage_delegation(
        &mut self,
        tenant: &AuthorityTenant,
        delegation: &Delegation,
        now: i64,
    ) -> Result<AuthorityRegistryStatus> {
        binding(tenant, &delegation.org_id, &delegation.project_id)?;
        let canonical = object_bytes(delegation)?;
        time(now)?;
        {
            let tx = self.connection.transaction()?;
            require_registry_time(&tx, tenant, now)?;
            let original = object_hash_at(&tx, tenant, &delegation.envelope_hash)?;
            if original.kind != "envelope" {
                return Err(AuthorityError::Binding);
            }
            validate_delegation(delegation, &decode::<AccessEnvelope>(&original.canonical)?)?;
            tx.commit()?;
        }
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        let object_id = format!("{}:{}", delegation.root_id, delegation.revision);
        if let Some(existing) = object_at(&tx, tenant, "delegation", &object_id)? {
            if existing.canonical != canonical {
                return Err(AuthorityError::Conflict);
            }
            let result = object_status(&tx, tenant, &existing, now)?;
            tx.commit()?;
            return Ok(result);
        }
        let original = object_hash_at(&tx, tenant, &delegation.envelope_hash)?;
        if original.revoked || original.kind != "envelope" {
            return Err(AuthorityError::Binding);
        }
        validate_delegation(delegation, &decode::<AccessEnvelope>(&original.canonical)?)?;
        let object = insert_object(
            &tx,
            tenant,
            "delegation",
            &format!("{}:{}", delegation.root_id, delegation.revision),
            &delegation.target_id,
            &canonical,
            now,
        )?;
        let result = status(
            &object,
            now,
            false,
            vec![Gate::BootstrapAuthorizationRequired.code().into()],
        )?;
        tx.commit()?;
        Ok(result)
    }

    pub fn stage_bootstrap_manifest(
        &mut self,
        tenant: &AuthorityTenant,
        manifest: &AuthorityBootstrapManifest,
        now: i64,
    ) -> Result<AuthorityRegistryStatus> {
        manifest.validate()?;
        binding(tenant, &manifest.org_id, &manifest.project_id)?;
        let canonical = object_bytes(manifest)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        if let Some(existing) = object_at(&tx, tenant, "bootstrap_manifest", &manifest.manifest_id)?
        {
            if existing.canonical != canonical {
                return Err(AuthorityError::Conflict);
            }
            let result = object_status(&tx, tenant, &existing, now)?;
            tx.commit()?;
            return Ok(result);
        }
        require_manifest_inputs(&tx, tenant, manifest, now)?;
        let object = insert_object(
            &tx,
            tenant,
            "bootstrap_manifest",
            &manifest.manifest_id,
            &manifest.target_id,
            &canonical,
            now,
        )?;
        let result = status(
            &object,
            now,
            false,
            vec![
                Gate::OwnerProofRequired.code().into(),
                Gate::BootstrapAuthorizationRequired.code().into(),
                Gate::TargetEpochConfirmationRequired.code().into(),
            ],
        )?;
        tx.commit()?;
        Ok(result)
    }

    pub fn revoke_registry_object(
        &mut self,
        tenant: &AuthorityTenant,
        digest: &str,
        now: i64,
    ) -> Result<()> {
        hash(digest)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        let object = object_hash_at(&tx, tenant, digest)?;
        if !object.revoked {
            tx.execute(
                "INSERT INTO authority_registry_object_revocations VALUES(?,?,?,?)",
                params![tenant.org_id, tenant.project_id, hash(digest)?, now],
            )?;
            bump_security(&tx, tenant)?;
            audit(&tx, tenant, "registry_object_revoked", digest, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn read_registry_object(
        &mut self,
        tenant: &AuthorityTenant,
        kind: &str,
        id: &str,
        now: i64,
    ) -> Result<Option<AuthorityRegistryStatus>> {
        if id.is_empty()
            || id.len() > 128
            || ![
                "workload_binding",
                "envelope",
                "delegation",
                "bootstrap_manifest",
                "bootstrap_authorization",
            ]
            .contains(&kind)
        {
            return Err(invalid("registry object identity"));
        }
        if ["envelope", "delegation"].contains(&kind) {
            let (uuid, revision) = id
                .split_once(':')
                .ok_or(invalid("registry revision identity"))?;
            identifier(uuid)?;
            let number: u32 = revision
                .parse()
                .map_err(|_| invalid("registry revision identity"))?;
            if number == 0 || number > i32::MAX as u32 || number.to_string() != revision {
                return Err(invalid("registry revision identity"));
            }
        } else {
            identifier(id)?;
        }
        self.observe_registry_time(tenant, now)?;
        let tx = self.connection.transaction()?;
        require_registry_time(&tx, tenant, now)?;
        let result = object_at(&tx, tenant, kind, id)?
            .map(|object| object_status(&tx, tenant, &object, now))
            .transpose()?;
        tx.commit()?;
        Ok(result)
    }
}

fn require_manifest_inputs(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    manifest: &AuthorityBootstrapManifest,
    now: i64,
) -> Result<()> {
    require_manifest_inputs_at(tx, tenant, manifest, now, false)
}

fn require_manifest_inputs_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    manifest: &AuthorityBootstrapManifest,
    now: i64,
    historical: bool,
) -> Result<()> {
    if now < crate::timestamp(&manifest.created_at)?
        || now >= crate::timestamp(&manifest.expires_at)?
    {
        return Err(AuthorityError::Time);
    }
    for (kind, hashes) in [
        ("envelope", &manifest.envelope_hashes),
        ("delegation", &manifest.delegation_hashes),
    ] {
        for digest in hashes {
            let object = object_hash_at(tx, tenant, digest)?;
            if object.kind != kind
                || object.target != manifest.target_id
                || (object.revoked && !historical)
                || object.admitted > now
            {
                return Err(AuthorityError::Binding);
            }
            let (start, end) = if kind == "envelope" {
                let value: AccessEnvelope = decode(&object.canonical)?;
                (
                    crate::timestamp(&value.valid_from)?,
                    crate::timestamp(&value.valid_until)?,
                )
            } else {
                let value: Delegation = decode(&object.canonical)?;
                if !manifest.envelope_hashes.contains(&value.envelope_hash) {
                    return Err(AuthorityError::Binding);
                }
                (
                    crate::timestamp(&value.valid_from)?,
                    crate::timestamp(&value.valid_until)?,
                )
            };
            if now < start || now >= end || crate::timestamp(&manifest.expires_at)? > end {
                return Err(AuthorityError::Time);
            }
        }
    }
    let mut statement=tx.prepare("SELECT key_id FROM authority_registry_keys WHERE org_id=? AND project_id=? AND target_id=? AND payload_type=? AND pinned_at<=?")?;
    let mut rows = statement.query(params![
        tenant.org_id,
        tenant.project_id,
        manifest.target_id,
        crate::BOOTSTRAP_AUTHORIZATION_TYPE,
        now
    ])?;
    let mut found = false;
    while let Some(row) = rows.next()? {
        let mut key = key_at(tx, tenant, &row.get::<_, String>(0)?)?;
        if historical {
            key.revoked = false;
        }
        if key.validate(now).is_ok()
            && canonical_hash(&key).map_err(|_| invalid("bootstrap root pin"))?
                == manifest.trust_root_hash
        {
            found = true;
            break;
        }
    }
    if !found {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}

fn object_status(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    object: &Object,
    now: i64,
) -> Result<AuthorityRegistryStatus> {
    if object.kind != "workload_binding" {
        let mut result = status(
            object,
            now,
            false,
            vec![
                Gate::TargetEpochConfirmationRequired.code().into(),
                Gate::NativeQualificationRequired.code().into(),
                Gate::PolicySignerKeyRequired.code().into(),
            ],
        )?;
        let approval_verifier =
            if ["bootstrap_manifest", "bootstrap_authorization"].contains(&object.kind.as_str()) {
                match bootstrap_origin::current_verifier(tx, tenant, now) {
                    Ok(verifier) => Some(verifier),
                    Err(AuthorityError::Time | AuthorityError::Binding) => {
                        result
                            .gates
                            .push(Gate::BootstrapApprovalOriginRequired.code().into());
                        None
                    }
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
        if object.kind == "bootstrap_authorization" {
            match current_authorization(tx, tenant, object, now) {
                Ok(_) => {}
                Err(AuthorityError::Time | AuthorityError::Binding) => {
                    if !object.revoked {
                        result.state = "historical".into();
                    }
                    result
                        .gates
                        .push(Gate::BootstrapAuthorizationNotCurrent.code().into());
                }
                Err(error) => return Err(error),
            }
            if let Some(target) =
                target_bootstrap::target_status_in_tx(tx, tenant, &object.target, now)?
                && target.authorization_hash == object.hash
            {
                result.state = "target_confirmed_pending_qualification".into();
                if target.current_confirmation_eligibility {
                    result
                        .gates
                        .retain(|gate| gate != Gate::TargetEpochConfirmationRequired.code());
                }
            }
        }
        if object.kind == "bootstrap_manifest"
            && !object.revoked
            && let Some(verifier) = approval_verifier.as_ref()
            && require_manifest_inputs(
                tx,
                tenant,
                &decode::<AuthorityBootstrapManifest>(&object.canonical)?,
                now,
            )
            .is_ok()
        {
            let mut statement=tx.prepare("SELECT proof_id FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND manifest_id=? AND admitted_at<=? AND expires_at>? LIMIT 17")?;
            let mut rows = statement.query(params![
                tenant.org_id,
                tenant.project_id,
                object.id,
                now,
                now
            ])?;
            while let Some(row) = rows.next()? {
                if verify_bootstrap_proof_record(
                    tx,
                    tenant,
                    &row.get::<_, String>(0)?,
                    Some((verifier, now)),
                    true,
                )
                .is_ok()
                {
                    result.state = "owner_approved".into();
                    break;
                }
            }
            if result.state == "staged" {
                result.gates.push(Gate::OwnerProofRequired.code().into());
            }
            result
                .gates
                .push(Gate::BootstrapAuthorizationRequired.code().into());
        }
        return Ok(result);
    }
    let workload: WorkloadBinding = decode(&object.canonical)?;
    let key = key_at(tx, tenant, &workload.payload.issuer_key_id)?;
    let head:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_workload_heads WHERE org_id=? AND project_id=? AND principal_id=? AND target_id=? AND workload_id=? AND binding_id=? AND content_hash=?)",params![tenant.org_id,tenant.project_id,workload.payload.principal_id,object.target,workload.payload.workload_id,object.id,hash(&object.hash)?],|r|r.get(0))?;
    let current = !object.revoked
        && !key.revoked
        && now >= object.admitted
        && now >= clock_floor(tx, tenant)?
        && head
        && workload.validate_current_admission_profile().is_ok()
        && verify_workload_binding(&workload, &key, now).is_ok();
    status(
        object,
        now,
        current,
        if current {
            vec![]
        } else {
            vec![Gate::WorkloadBindingNotCurrent.code().into()]
        },
    )
}

pub(super) fn validate_retained(tx: &Transaction<'_>) -> Result<()> {
    validate_registry_projections(tx)?;
    let mut statement =
        tx.prepare("SELECT org_id,project_id,key_id FROM authority_registry_keys")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        key_at(tx, &tenant, &row.get::<_, String>(2)?)?;
    }
    let mut statement = tx.prepare(
        "SELECT org_id,project_id,object_kind,object_id FROM authority_registry_objects",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let object = object_at(
            tx,
            &tenant,
            &row.get::<_, String>(2)?,
            &row.get::<_, String>(3)?,
        )?
        .ok_or(AuthorityError::Binding)?;
        match object.kind.as_str() {
            "workload_binding" => {
                let workload: WorkloadBinding = decode(&object.canonical)?;
                let mut key = key_at(tx, &tenant, &workload.payload.issuer_key_id)?;
                key.revoked = false;
                let verified = verify_workload_binding(&workload, &key, object.admitted)?;
                let available:bool=tx.query_row("SELECT pinned_at<=? FROM authority_registry_keys WHERE org_id=? AND project_id=? AND key_id=?",params![object.admitted,tenant.org_id,tenant.project_id,key.key_id],|row|row.get(0))?;
                if !available {
                    return Err(invalid("workload predates issuer pin"));
                }
                if verified.binding_id() != object.id
                    || verified.target_id() != object.target
                    || verified.hash() != object.hash
                {
                    return Err(invalid("workload registry projection"));
                }
            }
            "envelope" => {
                let envelope: AccessEnvelope = decode(&object.canonical)?;
                validate_access_envelope(&envelope)?;
                binding(&tenant, &envelope.org_id, &envelope.project_id)?;
                if format!("{}:{}", envelope.envelope_id, envelope.revision) != object.id
                    || envelope.target_id != object.target
                {
                    return Err(AuthorityError::Binding);
                }
            }
            "delegation" => {
                let delegation: Delegation = decode(&object.canonical)?;
                let envelope = object_hash_at(tx, &tenant, &delegation.envelope_hash)?;
                if envelope.kind != "envelope" {
                    return Err(AuthorityError::Binding);
                }
                validate_delegation(&delegation, &decode(&envelope.canonical)?)?;
                if format!("{}:{}", delegation.root_id, delegation.revision) != object.id
                    || delegation.target_id != object.target
                {
                    return Err(AuthorityError::Binding);
                }
            }
            "bootstrap_manifest" => {
                let manifest: AuthorityBootstrapManifest = decode(&object.canonical)?;
                manifest.validate()?;
                binding(&tenant, &manifest.org_id, &manifest.project_id)?;
                if manifest.manifest_id != object.id || manifest.target_id != object.target {
                    return Err(AuthorityError::Binding);
                }
                require_manifest_inputs_at(tx, &tenant, &manifest, object.admitted, true)?;
            }
            "bootstrap_authorization" => validate_authorization_record(tx, &tenant, &object)?,
            _ => return Err(invalid("registry object kind")),
        }
    }
    validate_workload_heads(tx)?;
    validate_bootstrap_pending_heads(tx)?;
    validate_bootstrap_proofs(tx)?;
    validate_registry_audits(tx)
}

fn validate_registry_projections(tx: &Transaction<'_>) -> Result<()> {
    let alias:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_registry_keys k JOIN authority_target_keys t ON t.org_id=k.org_id AND t.key_fingerprint=k.key_fingerprint) OR EXISTS(SELECT 1 FROM authority_registry_keys k JOIN authority_native_observer_keys n ON n.org_id=k.org_id AND n.key_fingerprint=k.key_fingerprint)",[],|r|r.get(0))?;
    if alias {
        return Err(invalid("registry key purpose alias"));
    }
    let invalid_time:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_registry_key_revocations r JOIN authority_registry_keys k USING(org_id,project_id,key_id) WHERE r.revoked_at<k.pinned_at) OR EXISTS(SELECT 1 FROM authority_registry_object_revocations r JOIN authority_registry_objects o USING(org_id,project_id,content_hash) WHERE r.revoked_at<o.admitted_at)",[],|r|r.get(0))?;
    if invalid_time {
        return Err(invalid("registry revocation time"));
    }
    let missing_floor:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM (
        SELECT org_id,project_id,pinned_at AS witnessed FROM authority_registry_keys
        UNION ALL SELECT org_id,project_id,admitted_at FROM authority_registry_objects
        UNION ALL SELECT org_id,project_id,revoked_at FROM authority_registry_key_revocations
        UNION ALL SELECT org_id,project_id,revoked_at FROM authority_registry_object_revocations
        UNION ALL SELECT org_id,project_id,issued_at FROM authority_bootstrap_challenges
        UNION ALL SELECT org_id,project_id,admitted_at FROM authority_bootstrap_proofs
        ) w LEFT JOIN authority_registry_clocks c USING(org_id,project_id) WHERE c.observed_at IS NULL OR c.observed_at<w.witnessed OR c.observed_at>253402300799)",[],|r|r.get(0))?;
    if missing_floor {
        return Err(invalid("registry observation floor"));
    }
    Ok(())
}

fn validate_registry_audits(tx: &Transaction<'_>) -> Result<()> {
    type AuditIdentity = (String, String, String, String, i64);
    let mut expected = std::collections::BTreeSet::<AuditIdentity>::new();
    let mut statement=tx.prepare("SELECT org_id,project_id,'registry_trust_key_pinned',key_id,pinned_at FROM authority_registry_keys
        UNION ALL SELECT org_id,project_id,'registry_trust_key_revoked',key_id,revoked_at FROM authority_registry_key_revocations
        UNION ALL SELECT org_id,project_id,'registry_'||object_kind||'_admitted',object_id,admitted_at FROM authority_registry_objects
        UNION ALL SELECT org_id,project_id,'registry_object_revoked','sha256:'||lower(hex(content_hash)),revoked_at FROM authority_registry_object_revocations
        UNION ALL SELECT org_id,project_id,'bootstrap_challenge_issued',challenge_id,issued_at FROM authority_bootstrap_challenges
        UNION ALL SELECT org_id,project_id,'bootstrap_owner_proof_admitted',proof_id,admitted_at FROM authority_bootstrap_proofs")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let event = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        );
        if !expected.insert(event) {
            return Err(invalid("duplicate registry audit obligation"));
        }
    }
    let mut statement=tx.prepare("SELECT org_id,project_id,kind,resource_id,recorded_at FROM authority_audit WHERE substr(kind,1,9)='registry_' OR kind IN ('bootstrap_challenge_issued','bootstrap_owner_proof_admitted')")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let event = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        );
        if !expected.remove(&event) {
            return Err(invalid("registry audit has no retained event"));
        }
    }
    if !expected.is_empty() {
        return Err(invalid("registry event audit missing"));
    }
    Ok(())
}

fn validate_workload_heads(tx: &Transaction<'_>) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    type WorkloadIdentity = (String, String, String, String, String);
    type Head = (u64, String, Vec<u8>);
    // Visit immutable objects once. A target-level existence check cannot detect
    // deletion of one principal/workload head when another head shares a target.
    let mut expected: BTreeMap<WorkloadIdentity, Head> = BTreeMap::new();
    let mut seen_epochs = BTreeSet::new();
    let mut statement = tx.prepare("SELECT org_id,project_id,object_id,target_id,content_hash,CASE WHEN length(canonical_bytes) BETWEEN 1 AND 262144 THEN canonical_bytes END FROM authority_registry_objects WHERE object_kind='workload_binding'")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let object_id: String = row.get(2)?;
        let target: String = row.get(3)?;
        let digest: Vec<u8> = row.get(4)?;
        let canonical: Vec<u8> = row.get(5)?;
        let workload: WorkloadBinding = decode(&canonical)?;
        workload.payload.validate()?;
        let p = &workload.payload;
        binding(&tenant, &p.org_id, &p.project_id)?;
        if p.binding_id != object_id
            || p.target_id != target
            || hash(&hash_bytes(&canonical))? != digest
            || bytes(&workload)? != canonical
        {
            return Err(invalid("workload history projection"));
        }
        let identity = (
            tenant.org_id,
            tenant.project_id,
            p.principal_id.clone(),
            target,
            p.workload_id.clone(),
        );
        let candidate = (crate::counter(&p.binding_epoch)?, object_id, digest);
        if !seen_epochs.insert((identity.clone(), candidate.0)) {
            return Err(invalid("duplicate workload history epoch"));
        }
        match expected.get(&identity) {
            Some(old) if candidate.0 == old.0 && candidate != *old => {
                return Err(invalid("duplicate workload history epoch"));
            }
            Some(old) if candidate.0 < old.0 => {}
            _ => {
                expected.insert(identity, candidate);
            }
        }
    }
    let mut statement = tx.prepare("SELECT org_id,project_id,principal_id,target_id,workload_id,binding_id,binding_epoch,content_hash FROM authority_workload_heads")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let identity = (
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        );
        let expected_head = expected
            .remove(&identity)
            .ok_or_else(|| invalid("orphan workload head"))?;
        let epoch: Vec<u8> = row.get(6)?;
        if expected_head.0.to_be_bytes().as_slice() != epoch
            || expected_head.1 != row.get::<_, String>(5)?
            || expected_head.2 != row.get::<_, Vec<u8>>(7)?
        {
            return Err(invalid("workload head is not latest"));
        }
    }
    if !expected.is_empty() {
        return Err(invalid("workload registry head missing"));
    }
    Ok(())
}

fn validate_bootstrap_pending_heads(tx: &Transaction<'_>) -> Result<()> {
    use std::collections::BTreeMap;
    type Target = (String, String, String);
    type Transition = (Option<u64>, i64, Vec<u8>, Vec<u8>);
    // Retained authorizations are the epoch history. Neither a mutable head nor
    // a revoked/latest object may hide a previously authorized transition.
    let mut chains: BTreeMap<Target, BTreeMap<u64, Transition>> = BTreeMap::new();
    let mut statement = tx.prepare("SELECT org_id,project_id,object_id FROM authority_registry_objects WHERE object_kind='bootstrap_authorization'")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let manifest_id: String = row.get(2)?;
        let authorization = object_at(tx, &tenant, "bootstrap_authorization", &manifest_id)?
            .ok_or(AuthorityError::Binding)?;
        let (manifest_object, manifest) = manifest_at(tx, &tenant, &manifest_id)?;
        if authorization.target != manifest.target_id
            || manifest_object.admitted > authorization.admitted
        {
            return Err(invalid("bootstrap epoch history binding"));
        }
        let next = crate::counter(&manifest.new_epoch)?;
        let previous = manifest
            .old_epoch
            .as_ref()
            .map(|value| crate::counter(value))
            .transpose()?;
        let identity = (tenant.org_id, tenant.project_id, manifest.target_id);
        let transition = (
            previous,
            authorization.admitted,
            hash(&manifest_object.hash)?,
            hash(&authorization.hash)?,
        );
        if chains
            .entry(identity)
            .or_default()
            .insert(next, transition)
            .is_some()
        {
            return Err(invalid("duplicate bootstrap epoch history"));
        }
    }
    let mut expected: BTreeMap<Target, (u64, Vec<u8>, Vec<u8>)> = BTreeMap::new();
    for (identity, chain) in chains {
        let mut previous_epoch = None;
        let mut previous_time = 0;
        for (epoch, (old, admitted, manifest_hash, authorization_hash)) in chain {
            if old != previous_epoch || admitted < previous_time {
                return Err(invalid("bootstrap epoch history discontinuity"));
            }
            previous_epoch = Some(epoch);
            previous_time = admitted;
            expected.insert(identity.clone(), (epoch, manifest_hash, authorization_hash));
        }
    }
    let mut statement = tx.prepare("SELECT org_id,project_id,target_id,authority_epoch,manifest_hash,authorization_hash FROM authority_bootstrap_pending_heads")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let identity = (
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        );
        let retained = expected
            .remove(&identity)
            .ok_or_else(|| invalid("orphan bootstrap pending head"))?;
        if retained.0.to_be_bytes().as_slice() != row.get::<_, Vec<u8>>(3)?
            || retained.1 != row.get::<_, Vec<u8>>(4)?
            || retained.2 != row.get::<_, Vec<u8>>(5)?
        {
            return Err(invalid("bootstrap pending head is not latest"));
        }
    }
    if !expected.is_empty() {
        return Err(invalid("bootstrap pending head missing"));
    }
    Ok(())
}

fn manifest_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<(Object, AuthorityBootstrapManifest)> {
    let object = object_at(tx, tenant, "bootstrap_manifest", id)?.ok_or(AuthorityError::Binding)?;
    let manifest: AuthorityBootstrapManifest = decode(&object.canonical)?;
    manifest.validate()?;
    binding(tenant, &manifest.org_id, &manifest.project_id)?;
    if manifest.manifest_id != id || manifest.target_id != object.target {
        return Err(AuthorityError::Binding);
    }
    Ok((object, manifest))
}

fn bootstrap_context(
    tenant: &AuthorityTenant,
    principal: &str,
    manifest: &AuthorityBootstrapManifest,
) -> Result<crate::ApprovalChallengeContext> {
    Ok(crate::ApprovalChallengeContext {
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        principal_id: principal.into(),
        subject: crate::ApprovalChallengeSubject::AuthorityBootstrap {
            manifest_id: manifest.manifest_id.clone(),
            subject_hash: manifest.hash()?,
        },
        requirements_hash: hash_bytes(b"fw.bootstrap.require-current-owner.v1"),
        decision: ApprovalDecision::Approve,
        role: ApprovalRole::Owner,
        subject_valid_until: crate::timestamp(&manifest.expires_at)?,
    })
}

fn require_human(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    principal: &str,
    now: i64,
) -> Result<String> {
    let result:Option<(String,i64)>=tx.query_row("SELECT human_id,bound_at FROM authority_human_bindings WHERE org_id=? AND project_id=? AND principal_id=?",params![tenant.org_id,tenant.project_id,principal],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let (id, bound) = result.ok_or(AuthorityError::Binding)?;
    identifier(&id)?;
    if now < bound {
        return Err(AuthorityError::Time);
    }
    Ok(id)
}

struct BootstrapChallengeRecord {
    manifest_id: String,
    principal: String,
    credential_id: String,
    membership_id: String,
    credential_revision: i64,
    role_revision: i64,
    security_revision: i64,
    issued: i64,
    expires: i64,
    attempts: i64,
    consumed: Option<i64>,
    challenge: ApprovalChallenge,
    state: crate::ApprovalProofState,
    credential: Credential,
}

fn bootstrap_challenge_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<BootstrapChallengeRecord> {
    let result=tx.query_row("SELECT manifest_id,principal_id,credential_id,membership_id,credential_revision,role_revision,security_revision,issued_at,expires_at,attempts,consumed_at,CASE WHEN length(challenge_bytes)<=8192 THEN challenge_bytes END,CASE WHEN length(state_bytes)<=65536 THEN state_bytes END,CASE WHEN length(credential_bytes)<=65536 THEN credential_bytes END FROM authority_bootstrap_challenges WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?,r.get::<_,i64>(6)?,r.get::<_,i64>(7)?,r.get::<_,i64>(8)?,r.get::<_,i64>(9)?,r.get::<_,Option<i64>>(10)?,r.get::<_,Vec<u8>>(11)?,r.get::<_,Vec<u8>>(12)?,r.get::<_,Vec<u8>>(13)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let challenge: ApprovalChallenge = decode(&result.11)?;
    let credential: Credential = decode(&result.13)?;
    let state = crate::ApprovalProofState::from_json(&result.12)?;
    let (_, manifest) = manifest_at(tx, tenant, &result.0)?;
    let verifier =
        WebAuthn::new(challenge.origin()).map_err(|_| invalid("bootstrap verifier origin"))?;
    let context = bootstrap_context(tenant, &result.1, &manifest)?;
    challenge.validate_context(&context, &verifier, result.7)?;
    if challenge.challenge_id() != id
        || challenge.issued_at() != result.7
        || challenge.expires_at() != result.8
        || credential.id() != result.2
        || credential.principal_id() != result.1
        || bytes(&challenge)? != result.11
        || bytes(&credential)? != result.13
        || result.4 <= 0
        || result.5 <= 0
        || result.6 <= 0
        || !(0..=MAX_ATTEMPTS).contains(&result.9)
        || result.10.is_some_and(|at| at < result.7 || at >= result.8)
    {
        return Err(invalid("bootstrap challenge projection"));
    }
    Ok(BootstrapChallengeRecord {
        manifest_id: result.0,
        principal: result.1,
        credential_id: result.2,
        membership_id: result.3,
        credential_revision: result.4,
        role_revision: result.5,
        security_revision: result.6,
        issued: result.7,
        expires: result.8,
        attempts: result.9,
        consumed: result.10,
        challenge,
        state,
        credential,
    })
}

impl AuthorityStore {
    #[allow(clippy::too_many_arguments)]
    pub fn issue_bootstrap_challenge(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        credential_id: &str,
        manifest_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<IssuedApproval> {
        identifier(principal)?;
        identifier(manifest_id)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        let (object, manifest) = manifest_at(&tx, tenant, manifest_id)?;
        if object.revoked {
            return Err(AuthorityError::Binding);
        }
        require_manifest_inputs(&tx, tenant, &manifest, now)?;
        let origin = bootstrap_origin::current_origin(&tx, tenant, now)?;
        bootstrap_origin::require_verifier(&origin, verifier)?;
        let security = security_revision(&tx, tenant)?;
        require_human(&tx, tenant, principal, now)?;
        let credential = records::credential(&tx, tenant, credential_id)?;
        credential.require(principal, "active", now)?;
        let membership = records::current_role(&tx, tenant, principal, ApprovalRole::Owner, now)?;
        let outstanding:i64=tx.query_row("SELECT COUNT(*) FROM authority_bootstrap_challenges WHERE org_id=? AND project_id=? AND principal_id=? AND consumed_at IS NULL AND expires_at>?",params![tenant.org_id,tenant.project_id,principal,now],|r|r.get(0))?;
        if outstanding >= MAX_OUTSTANDING {
            return Err(AuthorityError::Quota);
        }
        let context = bootstrap_context(tenant, principal, &manifest)?;
        let challenge = ApprovalChallenge::issue(&context, verifier, now)?;
        let ceremony = crate::begin_approval_proof(
            verifier,
            &challenge,
            &context,
            std::slice::from_ref(&credential.credential),
            now,
        )?;
        tx.execute("INSERT INTO authority_bootstrap_challenges(org_id,project_id,challenge_id,manifest_id,principal_id,credential_id,membership_id,credential_revision,role_revision,security_revision,issued_at,expires_at,challenge_bytes,state_bytes,credential_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",params![tenant.org_id,tenant.project_id,challenge.challenge_id(),manifest_id,principal,credential.id,membership.id,credential.revision,membership.revision,security,now,challenge.expires_at(),challenge.canonical_payload(),bytes(&ceremony.state)?,credential.canonical])?;
        bootstrap_origin::bind_challenge(&tx, tenant, &challenge, &origin)?;
        audit(
            &tx,
            tenant,
            "bootstrap_challenge_issued",
            challenge.challenge_id(),
            now,
        )?;
        tx.commit()?;
        Ok(IssuedApproval {
            challenge,
            options: ceremony.options,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_bootstrap_proof(
        &mut self,
        tenant: &AuthorityTenant,
        principal: &str,
        challenge_id: &str,
        assertion: &AuthenticationResponse,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<BootstrapProofResult> {
        identifier(principal)?;
        identifier(challenge_id)?;
        let assertion_bytes = object_bytes(assertion)?;
        if assertion_bytes.len() > 65536 {
            return Err(invalid("bootstrap assertion size"));
        }
        let request_hash = hash_bytes(&bytes(
            &json!({"challenge_id":challenge_id,"principal_id":principal,"assertion":assertion}),
        )?);
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        let challenge = bootstrap_challenge_at(&tx, tenant, challenge_id)?;
        if challenge.principal != principal {
            return Err(AuthorityError::Binding);
        }
        let existing:Option<(String,Vec<u8>,Vec<u8>)>=tx.query_row("SELECT proof_id,proof_bytes,request_hash FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,challenge_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((id, canonical, stored_request)) = existing {
            if stored_request != hash(&request_hash)? {
                return Err(AuthorityError::Conflict);
            }
            let proof = verify_bootstrap_proof_record(&tx, tenant, &id, None, false)?;
            if bytes(&proof)? != canonical {
                return Err(AuthorityError::Binding);
            }
            let proof_hash = proof.hash()?;
            tx.commit()?;
            return Ok(BootstrapProofResult {
                proof,
                proof_hash,
                replayed: true,
                signing_allowed: false,
                dispatch_allowed: false,
            });
        }
        let origin = bootstrap_origin::require_challenge_origin(
            &tx,
            tenant,
            &challenge.challenge,
            verifier,
            now,
        )?;
        if challenge.consumed.is_some() {
            return Err(AuthorityError::Conflict);
        }
        if challenge.attempts >= MAX_ATTEMPTS {
            return Err(AuthorityError::Quota);
        }
        if now < challenge.issued || now >= challenge.expires {
            return Err(AuthorityError::Time);
        }
        let (object, manifest) = manifest_at(&tx, tenant, &challenge.manifest_id)?;
        if object.revoked || security_revision(&tx, tenant)? != challenge.security_revision {
            return Err(AuthorityError::Binding);
        }
        require_manifest_inputs(&tx, tenant, &manifest, now)?;
        require_human(&tx, tenant, principal, now)?;
        let credential = records::credential(&tx, tenant, &challenge.credential_id)?;
        credential.require(principal, "active", now)?;
        let membership = records::role(&tx, tenant, &challenge.membership_id)?;
        membership.require(principal, ApprovalRole::Owner, now)?;
        if membership.revision != challenge.role_revision
            || credential.revision != challenge.credential_revision
            || credential.canonical != bytes(&challenge.credential)?
        {
            return Err(AuthorityError::Binding);
        }
        let context = bootstrap_context(tenant, principal, &manifest)?;
        let verified = match crate::finish_approval_proof(
            verifier,
            &challenge.state,
            &challenge.challenge,
            &context,
            assertion,
            &credential.credential,
            now,
        ) {
            Ok(value) => value,
            Err(error) => {
                tx.execute("UPDATE authority_bootstrap_challenges SET attempts=attempts+1 WHERE org_id=? AND project_id=? AND challenge_id=? AND consumed_at IS NULL AND attempts<?",params![tenant.org_id,tenant.project_id,challenge_id,MAX_ATTEMPTS])?;
                tx.commit()?;
                return Err(error);
            }
        };
        let role = membership.snapshot(tenant)?;
        let proof = BootstrapApprovalProof {
            schema_version: "f.bootstrap-approval-proof/v1".into(),
            proof_id: new_id()?,
            subject_type: "authority_bootstrap".into(),
            subject_hash: manifest.hash()?,
            approver_id: principal.into(),
            webauthn_assertion_hash: hash_bytes(&assertion_bytes),
            role_snapshot_hash: hash_bytes(&bytes(&role)?),
            approved_at: at(now)?,
            valid_until: at((now + crate::APPROVAL_CHALLENGE_SECONDS)
                .min(crate::timestamp(&manifest.expires_at)?)
                .min(credential.not_after)
                .min(membership.not_after)
                .min(origin.not_after))?,
        };
        proof.validate(&manifest, now)?;
        let canonical = bytes(&proof)?;
        let proof_hash = proof.hash()?;
        if tx.execute("UPDATE authority_credentials SET credential_bytes=?,revision=revision+1 WHERE org_id=? AND project_id=? AND credential_id=? AND revision=? AND revision<2147483647 AND state='active'",params![bytes(verified.updated_credential())?,tenant.org_id,tenant.project_id,credential.id,credential.revision])?!=1 {return Err(AuthorityError::Conflict);}
        if tx.execute("UPDATE authority_bootstrap_challenges SET consumed_at=? WHERE org_id=? AND project_id=? AND challenge_id=? AND consumed_at IS NULL",params![now,tenant.org_id,tenant.project_id,challenge_id])?!=1 {return Err(AuthorityError::Conflict);}
        tx.execute(
            "INSERT INTO authority_bootstrap_proofs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                proof.proof_id,
                challenge_id,
                manifest.manifest_id,
                principal,
                hash(&proof_hash)?,
                hash(&request_hash)?,
                now,
                crate::timestamp(&proof.valid_until)?,
                canonical,
                assertion_bytes,
                bytes(&role)?
            ],
        )?;
        audit(
            &tx,
            tenant,
            "bootstrap_owner_proof_admitted",
            &proof.proof_id,
            now,
        )?;
        tx.commit()?;
        Ok(BootstrapProofResult {
            proof,
            proof_hash,
            replayed: false,
            signing_allowed: false,
            dispatch_allowed: false,
        })
    }

    pub fn admit_bootstrap_authorization(
        &mut self,
        tenant: &AuthorityTenant,
        manifest_id: &str,
        authorization: &BootstrapAuthorization,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<AuthorityRegistryStatus> {
        identifier(manifest_id)?;
        authorization.validate_shape()?;
        let canonical = object_bytes(authorization)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_registry_time(&tx, tenant, now)?;
        let (manifest_object, manifest) = manifest_at(&tx, tenant, manifest_id)?;
        let id = manifest.manifest_id.clone();
        if let Some(existing) = object_at(&tx, tenant, "bootstrap_authorization", &id)? {
            if existing.canonical != canonical {
                return Err(AuthorityError::Conflict);
            }
            validate_authorization_record(&tx, tenant, &existing)?;
            let result = object_status(&tx, tenant, &existing, now)?;
            tx.commit()?;
            return Ok(result);
        }
        authorization.validate_current_admission_profile()?;
        let origin = bootstrap_origin::current_origin(&tx, tenant, now)?;
        bootstrap_origin::require_verifier(&origin, verifier)?;
        if manifest_object.revoked {
            return Err(AuthorityError::Binding);
        }
        require_manifest_inputs(&tx, tenant, &manifest, now)?;
        let key = key_at(&tx, tenant, &authorization.payload.signer_key_id)?;
        // A trust root is the exact independently provisioned scoped pin, not
        // the new key advertised by the incoming authorization itself.
        let mut pinned = key.clone();
        pinned.revoked = false;
        if canonical_hash(&pinned).map_err(|_| invalid("bootstrap root pin"))?
            != manifest.trust_root_hash
        {
            return Err(AuthorityError::Binding);
        }
        let mut proofs = Vec::new();
        let mut humans = std::collections::BTreeSet::new();
        for digest in &authorization.payload.approval_proof_hashes {
            let proof_id:String=tx.query_row("SELECT proof_id FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND proof_hash=?",params![tenant.org_id,tenant.project_id,hash(digest)?],|r|r.get(0)).optional()?.ok_or(AuthorityError::Binding)?;
            let proof =
                verify_bootstrap_proof_record(&tx, tenant, &proof_id, Some((verifier, now)), true)?;
            if !humans.insert(require_human(&tx, tenant, &proof.approver_id, now)?) {
                return Err(AuthorityError::Binding);
            }
            proofs.push(proof);
        }
        let verified =
            verify_bootstrap_authorization(authorization, &manifest, &proofs, &key, now)?;
        require_bootstrap_epoch(&tx, tenant, &manifest)?;
        let next = crate::counter(&manifest.new_epoch)?;
        let object = insert_object(
            &tx,
            tenant,
            "bootstrap_authorization",
            &id,
            &manifest.target_id,
            verified.canonical_bytes(),
            now,
        )?;
        retained_projection(
            &tx,
            "UPDATE authority_bootstrap_pending_heads SET authority_epoch=?4,manifest_hash=?5,authorization_hash=?6 WHERE org_id=?1 AND project_id=?2 AND target_id=?3",
            "INSERT INTO authority_bootstrap_pending_heads VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                tenant.org_id,
                tenant.project_id,
                manifest.target_id,
                next.to_be_bytes().as_slice(),
                hash(&manifest.hash()?)?,
                hash(verified.hash())?
            ],
        )?;
        let result = status(
            &object,
            now,
            false,
            vec![
                Gate::TargetEpochConfirmationRequired.code().into(),
                Gate::NativeQualificationRequired.code().into(),
                Gate::PolicySignerKeyRequired.code().into(),
            ],
        )?;
        tx.commit()?;
        Ok(result)
    }
}

fn verify_bootstrap_proof_record(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    current: Option<(&WebAuthn, i64)>,
    require_current: bool,
) -> Result<BootstrapApprovalProof> {
    let row=tx.query_row("SELECT challenge_id,manifest_id,principal_id,CASE WHEN length(proof_hash)=32 THEN proof_hash END,CASE WHEN length(request_hash)=32 THEN request_hash END,admitted_at,expires_at,CASE WHEN length(proof_bytes)<=8192 THEN proof_bytes END,CASE WHEN length(assertion_bytes)<=65536 THEN assertion_bytes END,CASE WHEN length(role_bytes)<=8192 THEN role_bytes END FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND proof_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,i64>(5)?,r.get::<_,i64>(6)?,r.get::<_,Vec<u8>>(7)?,r.get::<_,Vec<u8>>(8)?,r.get::<_,Vec<u8>>(9)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let proof: BootstrapApprovalProof = decode(&row.7)?;
    let assertion: AuthenticationResponse = decode(&row.8)?;
    let role: Value = decode(&row.9)?;
    let challenge = bootstrap_challenge_at(tx, tenant, &row.0)?;
    let (_, manifest) = manifest_at(tx, tenant, &row.1)?;
    let retained_verifier = WebAuthn::new(challenge.challenge.origin())
        .map_err(|_| invalid("bootstrap proof origin"))?;
    let context = bootstrap_context(tenant, &row.2, &manifest)?;
    proof.validate(&manifest, row.5)?;
    crate::finish_approval_proof(
        &retained_verifier,
        &challenge.state,
        &challenge.challenge,
        &context,
        &assertion,
        &challenge.credential,
        row.5,
    )?;
    if proof.proof_id != id
        || proof.approver_id != row.2
        || proof.subject_hash != manifest.hash()?
        || proof.hash()? != hash_string(&row.3)?
        || proof.webauthn_assertion_hash != hash_bytes(&row.8)
        || proof.role_snapshot_hash != hash_bytes(&row.9)
        || crate::timestamp(&proof.approved_at)? != row.5
        || crate::timestamp(&proof.valid_until)? != row.6
        || challenge.consumed != Some(row.5)
        || challenge.manifest_id != row.1
        || challenge.principal != row.2
        || hash(&hash_bytes(&bytes(
            &json!({"challenge_id":row.0,"principal_id":row.2,"assertion":assertion}),
        )?))?
            != row.4
        || bytes(&proof)? != row.7
        || bytes(&assertion)? != row.8
        || role["membership_id"] != challenge.membership_id
        || role["principal_id"] != proof.approver_id
        || role["role"] != "owner"
        || role["revision"] != challenge.role_revision
    {
        return Err(invalid("bootstrap proof projection"));
    }
    // Saved cryptography must always belong to the independently pinned stable
    // key and membership. Later counters/revocations do not rewrite history.
    let credential = records::credential(tx, tenant, &challenge.credential_id)?;
    let membership = records::role(tx, tenant, &challenge.membership_id)?;
    let mut original_role = membership.snapshot(tenant)?;
    original_role["revision"] = challenge.role_revision.into();
    original_role["revoked_at"] = Value::Null;
    if credential.principal_id != proof.approver_id
        || credential.fingerprint
            != challenge
                .credential
                .key_fingerprint()
                .map_err(|_| invalid("bootstrap retained credential"))?
        || credential.revision <= challenge.credential_revision
        || credential.pinned_at > challenge.issued
        || credential
            .activated_at
            .is_none_or(|at| at > challenge.issued)
        || credential.revoked_at.is_some_and(|at| at < row.5)
        || membership.principal_id != proof.approver_id
        || membership.role != ApprovalRole::Owner
        || membership.revision < challenge.role_revision
        || membership.granted_at > challenge.issued
        || membership.not_before > row.5
        || membership.not_after <= row.5
        || membership.revoked_at.is_some_and(|at| at < row.5)
        || bytes(&original_role)? != row.9
        || row.6
            > credential
                .not_after
                .min(membership.not_after)
                .min(row.5 + crate::APPROVAL_CHALLENGE_SECONDS)
    {
        return Err(invalid("bootstrap retained authority snapshot"));
    }
    require_human(tx, tenant, &proof.approver_id, row.5)?;
    if require_current {
        let (verifier, now) = current.ok_or(AuthorityError::Binding)?;
        bootstrap_origin::require_challenge_origin(
            tx,
            tenant,
            &challenge.challenge,
            verifier,
            now,
        )?;
        if verifier.origin() != challenge.challenge.origin()
            || now < row.5
            || now >= row.6
            || now < clock_floor(tx, tenant)?
        {
            return Err(AuthorityError::Time);
        }
        credential.require(&proof.approver_id, "active", now)?;
        membership.require(&proof.approver_id, ApprovalRole::Owner, now)?;
        if credential
            .credential
            .key_fingerprint()
            .map_err(|_| invalid("bootstrap credential"))?
            != challenge
                .credential
                .key_fingerprint()
                .map_err(|_| invalid("bootstrap credential"))?
            || membership.revision != challenge.role_revision
        {
            return Err(AuthorityError::Binding);
        }
        require_human(tx, tenant, &proof.approver_id, now)?;
    }
    Ok(proof)
}

fn validate_bootstrap_proofs(tx: &Transaction<'_>) -> Result<()> {
    let mut statement =
        tx.prepare("SELECT org_id,project_id,challenge_id FROM authority_bootstrap_challenges")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let challenge = bootstrap_challenge_at(tx, &tenant, &row.get::<_, String>(2)?)?;
        let has_proof:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND challenge_id=?)",params![tenant.org_id,tenant.project_id,challenge.challenge.challenge_id()],|r|r.get(0))?;
        if challenge.consumed.is_some() != has_proof {
            return Err(invalid("bootstrap consumption proof missing"));
        }
    }
    let mut statement =
        tx.prepare("SELECT org_id,project_id,proof_id FROM authority_bootstrap_proofs")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        verify_bootstrap_proof_record(tx, &tenant, &row.get::<_, String>(2)?, None, false)?;
    }
    Ok(())
}

fn validate_authorization_record(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    object: &Object,
) -> Result<()> {
    let authorization: BootstrapAuthorization = decode(&object.canonical)?;
    let (_, manifest) = manifest_at(tx, tenant, &object.id)?;
    let mut key = key_at(tx, tenant, &authorization.payload.signer_key_id)?;
    key.revoked = false;
    if canonical_hash(&key).map_err(|_| invalid("bootstrap root pin"))? != manifest.trust_root_hash
    {
        return Err(AuthorityError::Binding);
    }
    let mut proofs = Vec::new();
    for digest in &authorization.payload.approval_proof_hashes {
        let proof_id:String=tx.query_row("SELECT proof_id FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND proof_hash=?",params![tenant.org_id,tenant.project_id,hash(digest)?],|r|r.get(0)).optional()?.ok_or(AuthorityError::Binding)?;
        proofs.push(verify_bootstrap_proof_record(
            tx, tenant, &proof_id, None, false,
        )?);
    }
    let verified =
        verify_bootstrap_authorization(&authorization, &manifest, &proofs, &key, object.admitted)?;
    if verified.hash() != object.hash || manifest.target_id != object.target {
        return Err(invalid("bootstrap authorization projection"));
    }
    Ok(())
}

fn current_authorization(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    object: &Object,
    now: i64,
) -> Result<i64> {
    validate_authorization_record(tx, tenant, object)?;
    let authorization: BootstrapAuthorization = decode(&object.canonical)?;
    if authorization.validate_current_admission_profile().is_err() {
        return Err(AuthorityError::Binding);
    }
    let (manifest_object, manifest) = manifest_at(tx, tenant, &object.id)?;
    if object.revoked
        || manifest_object.revoked
        || now < object.admitted
        || now < clock_floor(tx, tenant)?
    {
        return Err(AuthorityError::Binding);
    }
    require_manifest_inputs(tx, tenant, &manifest, now)?;
    let key = key_at(tx, tenant, &authorization.payload.signer_key_id)?;
    if key.revoked {
        return Err(AuthorityError::Binding);
    }
    let verifier = bootstrap_origin::current_verifier(tx, tenant, now)?;
    let mut proofs = Vec::new();
    for digest in &authorization.payload.approval_proof_hashes {
        let id:String=tx.query_row("SELECT proof_id FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND proof_hash=?",params![tenant.org_id,tenant.project_id,hash(digest)?],|row|row.get(0)).optional()?.ok_or(AuthorityError::Binding)?;
        proofs.push(verify_bootstrap_proof_record(
            tx,
            tenant,
            &id,
            Some((&verifier, now)),
            true,
        )?);
    }
    let verified = verify_bootstrap_authorization(&authorization, &manifest, &proofs, &key, now)?;
    let head:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_bootstrap_pending_heads WHERE org_id=? AND project_id=? AND target_id=? AND manifest_hash=? AND authorization_hash=?)",params![tenant.org_id,tenant.project_id,object.target,hash(&manifest.hash()?)?,hash(&object.hash)?],|r|r.get(0))?;
    if !head {
        return Err(AuthorityError::Binding);
    }
    Ok(verified.not_after())
}

fn require_bootstrap_epoch(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    manifest: &AuthorityBootstrapManifest,
) -> Result<()> {
    let previous:Option<Vec<u8>>=tx.query_row("SELECT authority_epoch FROM authority_bootstrap_pending_heads WHERE org_id=? AND project_id=? AND target_id=?",params![tenant.org_id,tenant.project_id,manifest.target_id],|row|row.get(0)).optional()?;
    if previous.is_none() {
        let existing_target:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_target_heads WHERE org_id=? AND project_id=? AND target_id=?)",params![tenant.org_id,tenant.project_id,manifest.target_id],|row|row.get(0))?;
        if existing_target {
            return Err(AuthorityError::Conflict);
        }
    }
    let next = crate::counter(&manifest.new_epoch)?;
    match previous {
        None if manifest.old_epoch.is_none() => Ok(()),
        Some(epoch)
            if manifest
                .old_epoch
                .as_ref()
                .map(|old| crate::counter(old))
                .transpose()?
                .is_some_and(|old| {
                    old.to_be_bytes().as_slice() == epoch.as_slice() && next > old
                }) =>
        {
            Ok(())
        }
        _ => Err(AuthorityError::Conflict),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CoreRegistryStatus {
    pub valid_until: i64,
    pub workload_binding_hash: String,
    pub envelope_hash: String,
    pub delegation_hash: String,
    pub bootstrap_authorization_hash: Option<String>,
    pub gates: Vec<String>,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

impl AuthorityStore {
    pub fn read_core_authority_status(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        now: i64,
    ) -> Result<CoreRegistryStatus> {
        identifier(plan_id)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self.connection.transaction()?;
        require_registry_time(&tx, tenant, now)?;
        let retained = records::retained_plan(&tx, tenant, plan_id)?;
        let plan: Value = decode(&retained.subject.plan_bytes)?;
        let result = core_registry_in_tx(&tx, tenant, &plan, now)?;
        tx.commit()?;
        Ok(result)
    }
}

pub(super) fn core_registry_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan: &Value,
    now: i64,
) -> Result<CoreRegistryStatus> {
    require_registry_time(tx, tenant, now)?;
    let retained = records::retained_plan(tx, tenant, crate::string(plan, "plan_id")?)?;
    let original = access_provenance::retained_in_tx(tx, tenant, &retained, now)?
        .ok_or(AuthorityError::Binding)?;
    let provenance: crate::CoreAccessProvenance = decode(original.verified.canonical_bytes())?;
    let workload = object_at(
        tx,
        tenant,
        "workload_binding",
        &provenance.request.workload_binding_id,
    )?
    .ok_or(AuthorityError::Binding)?;
    let current = object_status(tx, tenant, &workload, now)?;
    let identity: WorkloadBinding = decode(&workload.canonical)?;
    let identity_until = crate::timestamp(&identity.payload.expires_at)?;
    if !current.current
        || identity.payload.principal_id != original.verified.principal_id()
        || identity.payload.target_id != original.verified.target_id()
        || !provenance
            .request
            .source_asset_ids
            .iter()
            .all(|id| identity.payload.asset_ids.contains(id))
        || crate::string(plan, "workload_binding_hash")? != workload.hash
        || crate::timestamp(crate::string(plan, "workload_binding_valid_until")?)? != identity_until
        || original
            .window
            .as_ref()
            .is_some_and(|window| window.expires_at() > identity_until)
    {
        return Err(AuthorityError::Binding);
    }
    let envelope_hash =
        canonical_hash(&provenance.envelope).map_err(|_| invalid("registry provenance"))?;
    let delegation_hash =
        canonical_hash(&provenance.delegation).map_err(|_| invalid("registry provenance"))?;
    for (kind, digest) in [
        ("envelope", &envelope_hash),
        ("delegation", &delegation_hash),
    ] {
        let object = object_hash_at(tx, tenant, digest)?;
        if object.kind != kind || object.revoked {
            return Err(AuthorityError::Binding);
        }
    }
    let mut valid_until = original.verified.valid_until().min(identity_until);
    let mut authorization_hash = None;
    let review = review_evidence::review_in_tx(tx, tenant, &retained.subject, now)?
        .ok_or(AuthorityError::Binding)?;
    let pending:Option<Vec<u8>>=tx.query_row("SELECT authorization_hash FROM authority_bootstrap_pending_heads WHERE org_id=? AND project_id=? AND target_id=? AND authority_epoch=?",params![tenant.org_id,tenant.project_id,original.verified.target_id(),crate::counter(crate::string(plan,"authority_epoch")?)?.to_be_bytes().as_slice()],|r|r.get(0)).optional()?;
    if let Some(digest) = pending {
        let authorization = object_hash_at(tx, tenant, &hash_string(&digest)?)?;
        let (_, manifest) = manifest_at(tx, tenant, &authorization.id)?;
        if manifest.envelope_hashes.contains(&envelope_hash)
            && manifest.delegation_hashes.contains(&delegation_hash)
            && manifest.management_baseline_hash
                == review.evidence().before.management_baseline_hash
            && manifest.capability_hash == crate::string(plan, "target_capability_hash")?
            && let Ok(until) = current_authorization(tx, tenant, &authorization, now)
        {
            valid_until = valid_until.min(until);
            authorization_hash = Some(authorization.hash);
        }
    }
    let confirmation =
        target_bootstrap::target_status_in_tx(tx, tenant, original.verified.target_id(), now)?;
    let plan_epoch = crate::string(plan, "authority_epoch")?;
    let plan_capability = crate::string(plan, "target_capability_hash")?;
    let confirmed = confirmation.as_ref().is_some_and(|target| {
        target.current_confirmation_eligibility
            && target.accepted_epoch == plan_epoch
            && authorization_hash.as_ref() == Some(&target.authorization_hash)
            && target.management_baseline_hash == review.evidence().before.management_baseline_hash
            && target.capability_hash == plan_capability
    });
    if confirmed && let Some(target) = confirmation.as_ref() {
        valid_until = valid_until.min(crate::timestamp(&target.valid_until)?);
    }
    let mut gates = vec![
        Gate::BuildIdentityRequired.code().into(),
        Gate::NativeQualificationRequired.code().into(),
        Gate::PolicySignerKeyRequired.code().into(),
    ];
    if !confirmed {
        gates.insert(0, Gate::TargetEpochConfirmationRequired.code().into());
    }
    if authorization_hash.is_none() {
        gates.push(Gate::BootstrapAuthorizationRequired.code().into());
    }
    // The issuer's declaration has not independently mapped each asset revision
    // to the immutable source snapshot or qualified packet identity on the OS.
    gates.push(Gate::WorkloadSourceAttestationRequired.code().into());
    Ok(CoreRegistryStatus {
        valid_until,
        workload_binding_hash: workload.hash,
        envelope_hash,
        delegation_hash,
        bootstrap_authorization_hash: authorization_hash,
        gates,
        signing_allowed: false,
        dispatch_allowed: false,
    })
}
