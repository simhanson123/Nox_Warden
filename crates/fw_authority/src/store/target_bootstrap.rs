//! Retained isolated-target bootstrap jobs and actual signed confirmations.
//! Accepted epochs are durable history. Eligibility is checked separately and
//! never supplies policy signing, quota release or production qualification.
use super::*;
use crate::{
    AuthorityGate as Gate, SignedTargetBootstrapConfirmation, TARGET_BOOTSTRAP_CHALLENGE_SCHEMA,
    TargetBootstrapBundle, TargetBootstrapChallenge, TargetBootstrapKeyPin,
    VerifiedTargetBootstrapConfirmation, validate_target_bootstrap_material,
    verify_target_bootstrap_confirmation,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use fw_backend_linux::{
    BootstrapCapabilitySnapshot, BootstrapManagementBaseline, compile_bootstrap_baseline,
};

#[derive(Clone, Debug, Serialize)]
pub struct TargetBootstrapKeyStatus {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub key_id: String,
    pub revision: String,
    pub pin_hash: String,
    pub key_fingerprint: String,
    pub pinned_at: String,
    pub not_before: String,
    pub not_after: String,
    pub checked_at: String,
    pub current: bool,
    pub revoked: bool,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetBootstrapStatus {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub state: String,
    pub confirmation_revision: String,
    pub accepted_epoch: String,
    pub highest_generation: String,
    pub confirmation_hash: String,
    pub challenge_hash: String,
    pub manifest_hash: String,
    pub authorization_hash: String,
    pub management_baseline_hash: String,
    pub capability_hash: String,
    pub journal_id: String,
    pub observed_at: String,
    pub admitted_at: String,
    pub valid_until: String,
    pub checked_at: String,
    pub current_confirmation_eligibility: bool,
    pub replayed: bool,
    pub gates: Vec<String>,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

pub(super) struct KeyRecord {
    pub pin: TargetBootstrapKeyPin,
    pub revision: u64,
    pub pinned_at: i64,
    pub revoked_at: Option<i64>,
    canonical: Vec<u8>,
}
pub(super) struct ChallengeRecord {
    pub challenge: TargetBootstrapChallenge,
    pub baseline: BootstrapManagementBaseline,
    pub capability: BootstrapCapabilitySnapshot,
    pub origin_revision: u64,
    pub expected_target_revision: Option<u64>,
}
pub(super) struct ConfirmationRecord {
    pub receipt: SignedTargetBootstrapConfirmation,
    pub verified: VerifiedTargetBootstrapConfirmation,
    pub revision: u64,
    pub admitted_at: i64,
}
pub(super) struct ConfirmationHead {
    pub revision: u64,
    pub epoch: u64,
    pub generation: u64,
    pub hash: String,
    pub observed_at: i64,
}

fn number(raw: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        raw.try_into()
            .map_err(|_| invalid("target bootstrap counter"))?,
    ))
}
fn unavailable<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(AuthorityError::Time | AuthorityError::Binding | AuthorityError::Conflict) => Ok(None),
        Err(error) => Err(error),
    }
}
fn scope(tenant: &AuthorityTenant, org: &str, project: &str, target: &str) -> Result<()> {
    identifier(target)?;
    if tenant.org_id != org || tenant.project_id != project {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}
fn bytes_bounded<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    fw_contracts::canonical_bytes_with_limit(value, maximum)
        .map_err(|_| invalid("target bootstrap material bound"))
}
fn policy_head_exists(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
) -> Result<bool> {
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_target_heads WHERE org_id=? AND project_id=? AND target_id=?)",params![tenant.org_id,tenant.project_id,target],|row|row.get(0))?)
}
fn key_head(tx: &Transaction<'_>, tenant: &AuthorityTenant, target: &str) -> Result<Option<u64>> {
    let value:Option<Vec<u8>>=tx.query_row("SELECT CASE WHEN length(revision)=8 THEN revision END FROM authority_target_bootstrap_key_heads WHERE org_id=? AND project_id=? AND target_id=?",params![tenant.org_id,tenant.project_id,target],|row|row.get(0)).optional()?;
    value.map(|raw| number(&raw)).transpose()
}

pub(super) fn key_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    revision: u64,
) -> Result<KeyRecord> {
    type KeyRow = (
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<i64>,
    );
    let row:KeyRow=tx.query_row("SELECT key_id,CASE WHEN length(public_key)=32 THEN public_key END,CASE WHEN length(key_fingerprint)=32 THEN key_fingerprint END,not_before,not_after,pinned_at,CASE WHEN length(pin_hash)=32 THEN pin_hash END,CASE WHEN length(canonical_bytes) BETWEEN 1 AND 8192 THEN canonical_bytes END,(SELECT revoked_at FROM authority_target_bootstrap_key_revocations r WHERE r.org_id=p.org_id AND r.project_id=p.project_id AND r.target_id=p.target_id AND r.revision=p.revision) FROM authority_target_bootstrap_key_pins p WHERE org_id=? AND project_id=? AND target_id=? AND revision=?",params![tenant.org_id,tenant.project_id,target,revision.to_be_bytes().as_slice()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let pin: TargetBootstrapKeyPin = decode(&row.7)?;
    pin.validate(row.5)?;
    scope(tenant, &pin.org_id, &pin.project_id, &pin.target_id)?;
    if pin.target_id != target
        || crate::counter(&pin.revision)? != revision
        || pin.key_id != row.0
        || pin.public_key.as_slice() != row.1
        || hash(&pin.fingerprint())? != row.2
        || crate::timestamp(&pin.not_before)? != row.3
        || crate::timestamp(&pin.not_after)? != row.4
        || hash(&pin.hash()?)? != row.6
        || row
            .8
            .is_some_and(|at| at < row.5 || !(0..=MAX_TIME).contains(&at))
    {
        return Err(invalid("target bootstrap key projection"));
    }
    Ok(KeyRecord {
        pin,
        revision,
        pinned_at: row.5,
        revoked_at: row.8,
        canonical: row.7,
    })
}
fn current_key(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    now: i64,
) -> Result<KeyRecord> {
    authority_registry::require_registry_time(tx, tenant, now)?;
    let record = key_at(
        tx,
        tenant,
        target,
        key_head(tx, tenant, target)?.ok_or(AuthorityError::Binding)?,
    )?;
    if record.revoked_at.is_some() {
        return Err(AuthorityError::Binding);
    }
    if now < record.pinned_at {
        return Err(AuthorityError::Time);
    }
    record.pin.validate(now)?;
    Ok(record)
}
fn key_status(record: &KeyRecord, now: i64, current: bool) -> Result<TargetBootstrapKeyStatus> {
    Ok(TargetBootstrapKeyStatus {
        schema_version: "fw.target-bootstrap-key-status/v1".into(),
        org_id: record.pin.org_id.clone(),
        project_id: record.pin.project_id.clone(),
        target_id: record.pin.target_id.clone(),
        key_id: record.pin.key_id.clone(),
        revision: record.pin.revision.clone(),
        pin_hash: record.pin.hash()?,
        key_fingerprint: record.pin.fingerprint(),
        pinned_at: at(record.pinned_at)?,
        not_before: record.pin.not_before.clone(),
        not_after: record.pin.not_after.clone(),
        checked_at: at(now)?,
        current: current
            && record.revoked_at.is_none()
            && now >= record.pinned_at
            && record.pin.validate(now).is_ok(),
        revoked: record.revoked_at.is_some(),
        signing_allowed: false,
        dispatch_allowed: false,
    })
}

pub(super) fn head_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
) -> Result<Option<ConfirmationHead>> {
    type HeadRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);
    let row:Option<HeadRow>=tx.query_row("SELECT revision,accepted_epoch,highest_generation,confirmation_hash,observed_at FROM authority_target_bootstrap_confirmation_heads WHERE org_id=? AND project_id=? AND target_id=?",params![tenant.org_id,tenant.project_id,target],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).optional()?;
    row.map(|row| {
        time(row.4)?;
        Ok(ConfirmationHead {
            revision: number(&row.0)?,
            epoch: number(&row.1)?,
            generation: number(&row.2)?,
            hash: hash_string(&row.3)?,
            observed_at: row.4,
        })
    })
    .transpose()
}

pub(super) fn challenge_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<ChallengeRecord> {
    type ChallengeRow = (
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );
    let row:ChallengeRow=tx.query_row("SELECT target_id,manifest_id,manifest_hash,authorization_hash,challenge_hash,key_revision,origin_revision,expected_target_revision,previous_confirmation_hash,new_epoch,highest_generation,issued_at,expires_at,CASE WHEN length(canonical_bytes) BETWEEN 1 AND 8192 THEN canonical_bytes END,CASE WHEN length(baseline_bytes) BETWEEN 1 AND 65536 THEN baseline_bytes END,CASE WHEN length(capability_bytes) BETWEEN 1 AND 8192 THEN capability_bytes END FROM authority_target_bootstrap_challenges WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let challenge: TargetBootstrapChallenge = decode(&row.13)?;
    challenge.validate_shape()?;
    let baseline: BootstrapManagementBaseline = decode(&row.14)?;
    let capability: BootstrapCapabilitySnapshot = decode(&row.15)?;
    let key = key_at(tx, tenant, &row.0, number(&row.5)?)?;
    let origin_revision = number(&row.6)?;
    let origin = bootstrap_origin::record_at(tx, tenant, origin_revision)?;
    scope(
        tenant,
        &challenge.org_id,
        &challenge.project_id,
        &challenge.target_id,
    )?;
    let expected_target_revision = row.7.as_deref().map(number).transpose()?;
    let previous = row.8.as_deref().map(hash_string).transpose()?;
    if challenge.challenge_id != id
        || challenge.target_id != row.0
        || challenge.manifest_id != row.1
        || hash(&challenge.manifest_hash)? != row.2
        || hash(&challenge.authorization_hash)? != row.3
        || hash(&challenge.hash()?)? != row.4
        || crate::counter(&challenge.key_revision)? != key.revision
        || challenge.key_id != key.pin.key_id
        || challenge.key_fingerprint != key.pin.fingerprint()
        || challenge.previous_confirmation_hash != previous
        || crate::counter(&challenge.new_epoch)? != number(&row.9)?
        || crate::counter(&challenge.highest_generation)? != number(&row.10)?
        || crate::timestamp(&challenge.issued_at)? != row.11
        || crate::timestamp(&challenge.expires_at)? != row.12
        || key.pinned_at > row.11
        || origin.pinned_at > row.11
        || origin.not_before > row.11
        || origin.not_after < row.12
        || crate::timestamp(&key.pin.not_before)? > row.11
        || crate::timestamp(&key.pin.not_after)? < row.12
        || expected_target_revision.is_some() != challenge.previous_confirmation_hash.is_some()
    {
        return Err(invalid("target bootstrap challenge projection"));
    }
    let material = authority_registry::bootstrap_material_in_tx(
        tx,
        tenant,
        &challenge.manifest_id,
        row.11,
        false,
    )?;
    validate_target_bootstrap_material(
        &challenge,
        &material.manifest,
        &material.authorization,
        &material.proofs,
        &material.root,
        &baseline,
        &capability,
        row.11,
    )?;
    for proof in &material.proofs {
        let revision:Option<Vec<u8>>=tx.query_row("SELECT b.origin_revision FROM authority_bootstrap_proofs p JOIN authority_bootstrap_challenge_origin_bindings b ON b.org_id=p.org_id AND b.project_id=p.project_id AND b.challenge_id=p.challenge_id WHERE p.org_id=? AND p.project_id=? AND p.proof_id=?",params![tenant.org_id,tenant.project_id,proof.proof_id],|row|row.get(0)).optional()?.ok_or(AuthorityError::Binding)?;
        if revision.as_deref() != Some(origin_revision.to_be_bytes().as_slice()) {
            return Err(invalid("target bootstrap origin history"));
        }
    }
    Ok(ChallengeRecord {
        challenge,
        baseline,
        capability,
        origin_revision,
        expected_target_revision,
    })
}

pub(super) fn confirmation_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    digest: &str,
) -> Result<ConfirmationRecord> {
    type ConfirmationRow = (
        String,
        Vec<u8>,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        i64,
        i64,
        i64,
        Vec<u8>,
    );
    let row:ConfirmationRow=tx.query_row("SELECT challenge_id,challenge_hash,target_id,revision,accepted_epoch,highest_generation,journal_id,observed_at,admitted_at,valid_until,CASE WHEN length(canonical_bytes) BETWEEN 1 AND 262144 THEN canonical_bytes END FROM authority_target_bootstrap_confirmations WHERE org_id=? AND project_id=? AND confirmation_hash=?",params![tenant.org_id,tenant.project_id,hash(digest)?],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let receipt: SignedTargetBootstrapConfirmation = decode(&row.10)?;
    let challenge = challenge_at(tx, tenant, &row.0)?;
    let key = key_at(
        tx,
        tenant,
        &row.2,
        crate::counter(&challenge.challenge.key_revision)?,
    )?;
    let verified = verify_target_bootstrap_confirmation(
        &receipt,
        &challenge.challenge,
        &key.pin,
        &challenge.baseline,
        &challenge.capability,
        row.8,
    )?;
    let revision = number(&row.3)?;
    if verified.hash() != digest
        || hash(verified.challenge_hash())? != row.1
        || receipt.payload.challenge.target_id != row.2
        || revision
            != challenge
                .expected_target_revision
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(AuthorityError::Conflict)?
        || verified.accepted_epoch() != number(&row.4)?
        || verified.highest_generation() != number(&row.5)?
        || verified.journal_id() != row.6
        || verified.observed_at() != row.7
        || verified.valid_until() != row.9
        || key.pinned_at > row.8
    {
        return Err(invalid("target bootstrap confirmation projection"));
    }
    time(row.8)?;
    Ok(ConfirmationRecord {
        receipt,
        verified,
        revision,
        admitted_at: row.8,
    })
}

fn require_transition(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    challenge: &TargetBootstrapChallenge,
    expected: Option<u64>,
) -> Result<()> {
    if policy_head_exists(tx, tenant, &challenge.target_id)? {
        return Err(invalid(
            "target bootstrap policy-generation reconciliation unavailable",
        ));
    }
    let head = head_at(tx, tenant, &challenge.target_id)?;
    match head {
        None if expected.is_none()
            && challenge.old_epoch.is_none()
            && challenge.previous_confirmation_hash.is_none() =>
        {
            Ok(())
        }
        Some(head)
            if expected == Some(head.revision)
                && challenge
                    .old_epoch
                    .as_ref()
                    .map(|value| crate::counter(value))
                    .transpose()?
                    == Some(head.epoch)
                && challenge.previous_confirmation_hash.as_ref() == Some(&head.hash)
                && crate::counter(&challenge.new_epoch)? > head.epoch
                && head.generation == 0 =>
        {
            Ok(())
        }
        _ => Err(AuthorityError::Conflict),
    }
}
fn bundle(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    record: &ChallengeRecord,
) -> Result<TargetBootstrapBundle> {
    let material = authority_registry::bootstrap_material_in_tx(
        tx,
        tenant,
        &record.challenge.manifest_id,
        crate::timestamp(&record.challenge.issued_at)?,
        false,
    )?;
    Ok(TargetBootstrapBundle {
        schema_version: "fw.target-bootstrap-bundle/v1".into(),
        manifest: material.manifest,
        authorization: material.authorization,
        proofs: material.proofs,
        challenge: record.challenge.clone(),
        baseline: record.baseline.clone(),
        capability: record.capability.clone(),
    })
}

impl AuthorityStore {
    pub fn pin_target_bootstrap_key(
        &mut self,
        tenant: &AuthorityTenant,
        pin: &TargetBootstrapKeyPin,
        expected_revision: Option<u64>,
        now: i64,
    ) -> Result<TargetBootstrapKeyStatus> {
        pin.validate_shape()?;
        scope(tenant, &pin.org_id, &pin.project_id, &pin.target_id)?;
        let canonical = bytes_bounded(pin, 8192)?;
        let revision = crate::counter(&pin.revision)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authority_registry::require_registry_time(&tx, tenant, now)?;
        let previous = key_head(&tx, tenant, &pin.target_id)?;
        if let Some(number) = previous {
            let old = key_at(&tx, tenant, &pin.target_id, number)?;
            if number == revision && old.canonical == canonical {
                if old.revoked_at.is_some() {
                    return Err(AuthorityError::Conflict);
                }
                if expected_revision == Some(number)
                    || expected_revision == number.checked_sub(1).filter(|number| *number > 0)
                    || (number == 1 && expected_revision.is_none())
                {
                    let result = key_status(&old, now, true)?;
                    tx.commit()?;
                    return Ok(result);
                }
            }
        }
        if previous != expected_revision
            || revision
                != previous
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(AuthorityError::Conflict)?
        {
            return Err(AuthorityError::Conflict);
        }
        pin.validate(now)?;
        let fingerprint = hash(&pin.fingerprint())?;
        // Raw-key and SPKI fingerprints are both retained in older roles.
        // Their byte encodings cannot be compared to establish key separation.
        let alias:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_registry_keys WHERE org_id=? AND public_key=?) OR EXISTS(SELECT 1 FROM authority_target_keys WHERE org_id=? AND public_key=?) OR EXISTS(SELECT 1 FROM authority_native_observer_keys WHERE org_id=? AND public_key=?) OR EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins WHERE org_id=? AND public_key=?)",params![tenant.org_id,pin.public_key.as_slice(),tenant.org_id,pin.public_key.as_slice(),tenant.org_id,pin.public_key.as_slice(),tenant.org_id,pin.public_key.as_slice()],|row|row.get(0))?;
        if alias {
            return Err(AuthorityError::Conflict);
        }
        tx.execute(
            "INSERT INTO authority_target_bootstrap_key_pins VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                pin.target_id,
                revision.to_be_bytes().as_slice(),
                pin.key_id,
                pin.public_key.as_slice(),
                fingerprint,
                crate::timestamp(&pin.not_before)?,
                crate::timestamp(&pin.not_after)?,
                now,
                hash(&pin.hash()?)?,
                canonical
            ],
        )?;
        retained_projection(
            &tx,
            "UPDATE authority_target_bootstrap_key_heads SET revision=?4 WHERE org_id=?1 AND project_id=?2 AND target_id=?3",
            "INSERT INTO authority_target_bootstrap_key_heads VALUES(?1,?2,?3,?4)",
            params![
                tenant.org_id,
                tenant.project_id,
                pin.target_id,
                revision.to_be_bytes().as_slice()
            ],
        )?;
        bump_security(&tx, tenant)?;
        audit(
            &tx,
            tenant,
            "target_bootstrap_key_pinned",
            &format!("{}:{}", pin.target_id, pin.revision),
            now,
        )?;
        let result = key_status(&key_at(&tx, tenant, &pin.target_id, revision)?, now, true)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn revoke_target_bootstrap_key(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        revision: u64,
        now: i64,
    ) -> Result<()> {
        identifier(target)?;
        if revision == 0 {
            return Err(invalid("target bootstrap key revision"));
        }
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authority_registry::require_registry_time(&tx, tenant, now)?;
        let key = key_at(&tx, tenant, target, revision)?;
        if key.revoked_at.is_none() {
            tx.execute(
                "INSERT INTO authority_target_bootstrap_key_revocations VALUES(?,?,?,?,?)",
                params![
                    tenant.org_id,
                    tenant.project_id,
                    target,
                    revision.to_be_bytes().as_slice(),
                    now
                ],
            )?;
            bump_security(&tx, tenant)?;
            audit(
                &tx,
                tenant,
                "target_bootstrap_key_revoked",
                &format!("{target}:{revision}"),
                now,
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_target_bootstrap_challenge(
        &mut self,
        tenant: &AuthorityTenant,
        manifest_id: &str,
        expected_target_revision: Option<u64>,
        baseline: &BootstrapManagementBaseline,
        capability: &BootstrapCapabilitySnapshot,
        now: i64,
    ) -> Result<TargetBootstrapBundle> {
        identifier(manifest_id)?;
        baseline
            .validate()
            .map_err(|_| invalid("target bootstrap baseline"))?;
        capability
            .validate()
            .map_err(|_| invalid("target bootstrap capability"))?;
        scope(
            tenant,
            &baseline.org_id,
            &baseline.project_id,
            &baseline.target_id,
        )?;
        let baseline_bytes = bytes_bounded(baseline, 65536)?;
        let capability_bytes = bytes_bounded(capability, 8192)?;
        let program = compile_bootstrap_baseline(baseline, capability)
            .map_err(|_| invalid("target bootstrap compiler"))?;
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authority_registry::require_registry_time(&tx, tenant, now)?;
        let previous:Option<String>=tx.query_row("SELECT challenge_id FROM authority_target_bootstrap_challenges WHERE org_id=? AND project_id=? AND manifest_id=?",params![tenant.org_id,tenant.project_id,manifest_id],|row|row.get(0)).optional()?;
        if let Some(id) = previous {
            let retained = challenge_at(&tx, tenant, &id)?;
            if retained.expected_target_revision != expected_target_revision
                || bytes(&retained.baseline)? != baseline_bytes
                || bytes(&retained.capability)? != capability_bytes
            {
                return Err(AuthorityError::Conflict);
            }
            let result = bundle(&tx, tenant, &retained)?;
            tx.commit()?;
            return Ok(result);
        }
        let material =
            authority_registry::bootstrap_material_in_tx(&tx, tenant, manifest_id, now, true)?;
        let origin = bootstrap_origin::current_origin(&tx, tenant, now)?;
        let key = current_key(&tx, tenant, &material.manifest.target_id, now)?;
        if key.pin.public_key == material.root.public_key
            || key.pin.public_key == baseline.peer_probe_public_key
        {
            return Err(AuthorityError::Signature);
        }
        let previous = head_at(&tx, tenant, &material.manifest.target_id)?;
        let previous_hash = previous.as_ref().map(|head| head.hash.clone());
        let mut nonce = [0u8; 32];
        openssl::rand::rand_bytes(&mut nonce).map_err(|_| invalid("target bootstrap nonce"))?;
        let end = (now + 300)
            .min(material.valid_until)
            .min(crate::timestamp(&key.pin.not_after)?)
            .min(origin.not_after);
        if end <= now {
            return Err(AuthorityError::Time);
        }
        let challenge = TargetBootstrapChallenge {
            schema_version: TARGET_BOOTSTRAP_CHALLENGE_SCHEMA.into(),
            challenge_id: new_id()?,
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            target_id: material.manifest.target_id.clone(),
            manifest_id: manifest_id.into(),
            manifest_hash: material.manifest.hash()?,
            authorization_hash: material.authorization_hash.clone(),
            management_baseline_hash: material.manifest.management_baseline_hash.clone(),
            capability_hash: material.manifest.capability_hash.clone(),
            baseline_program_hash: program
                .hash()
                .map_err(|_| invalid("target bootstrap program"))?,
            old_epoch: material.manifest.old_epoch.clone(),
            new_epoch: material.manifest.new_epoch.clone(),
            highest_generation: "0".into(),
            previous_confirmation_hash: previous_hash,
            key_id: key.pin.key_id.clone(),
            key_revision: key.pin.revision.clone(),
            key_fingerprint: key.pin.fingerprint(),
            nonce: STANDARD.encode(nonce),
            issued_at: at(now)?,
            expires_at: at(end)?,
        };
        require_transition(&tx, tenant, &challenge, expected_target_revision)?;
        validate_target_bootstrap_material(
            &challenge,
            &material.manifest,
            &material.authorization,
            &material.proofs,
            &material.root,
            baseline,
            capability,
            now,
        )?;
        let result = TargetBootstrapBundle {
            schema_version: "fw.target-bootstrap-bundle/v1".into(),
            manifest: material.manifest,
            authorization: material.authorization,
            proofs: material.proofs,
            challenge: challenge.clone(),
            baseline: baseline.clone(),
            capability: capability.clone(),
        };
        bytes_bounded(&result, crate::MAX_TARGET_BOOTSTRAP_BYTES)?;
        tx.execute("INSERT INTO authority_target_bootstrap_challenges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",params![tenant.org_id,tenant.project_id,challenge.challenge_id,challenge.target_id,manifest_id,hash(&challenge.manifest_hash)?,hash(&challenge.authorization_hash)?,hash(&challenge.hash()?)?,key.revision.to_be_bytes().as_slice(),origin.revision.to_be_bytes().as_slice(),expected_target_revision.map(u64::to_be_bytes).as_ref().map(|value|value.as_slice()),challenge.previous_confirmation_hash.as_deref().map(hash).transpose()?,crate::counter(&challenge.new_epoch)?.to_be_bytes().as_slice(),[0u8;8].as_slice(),now,end,challenge.canonical_bytes()?,baseline_bytes,capability_bytes])?;
        audit(
            &tx,
            tenant,
            "target_bootstrap_challenge_issued",
            &challenge.challenge_id,
            now,
        )?;
        tx.commit()?;
        Ok(result)
    }

    pub fn admit_target_bootstrap_confirmation(
        &mut self,
        tenant: &AuthorityTenant,
        receipt: &SignedTargetBootstrapConfirmation,
        now: i64,
    ) -> Result<TargetBootstrapStatus> {
        receipt.payload.challenge.validate_shape()?;
        scope(
            tenant,
            &receipt.payload.challenge.org_id,
            &receipt.payload.challenge.project_id,
            &receipt.payload.challenge.target_id,
        )?;
        let canonical = bytes_bounded(receipt, crate::MAX_TARGET_BOOTSTRAP_BYTES)?;
        let digest = hash_bytes(&canonical);
        {
            let tx = self.connection.transaction()?;
            authority_registry::require_registry_time(&tx, tenant, now)?;
            let challenge = challenge_at(&tx, tenant, &receipt.payload.challenge.challenge_id)?;
            let previous:Option<Vec<u8>>=tx.query_row("SELECT confirmation_hash FROM authority_target_bootstrap_confirmations WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,challenge.challenge.challenge_id],|row|row.get(0)).optional()?;
            if let Some(previous) = previous {
                if previous != hash(&digest)? {
                    return Err(AuthorityError::Conflict);
                }
                confirmation_at(&tx, tenant, &digest)?;
            } else {
                let key = key_at(
                    &tx,
                    tenant,
                    &challenge.challenge.target_id,
                    crate::counter(&challenge.challenge.key_revision)?,
                )?;
                let historical = crate::timestamp(&receipt.payload.observation_finished_at)?;
                verify_target_bootstrap_confirmation(
                    receipt,
                    &challenge.challenge,
                    &key.pin,
                    &challenge.baseline,
                    &challenge.capability,
                    historical,
                )?;
            }
            tx.commit()?;
        }
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authority_registry::require_registry_time(&tx, tenant, now)?;
        let challenge = challenge_at(&tx, tenant, &receipt.payload.challenge.challenge_id)?;
        let previous:Option<Vec<u8>>=tx.query_row("SELECT confirmation_hash FROM authority_target_bootstrap_confirmations WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,challenge.challenge.challenge_id],|row|row.get(0)).optional()?;
        if let Some(previous) = previous {
            if previous != hash(&digest)? {
                return Err(AuthorityError::Conflict);
            }
            let retained = confirmation_at(&tx, tenant, &digest)?;
            let result = status_for_confirmation(&tx, tenant, &retained, now, true)?;
            tx.commit()?;
            return Ok(result);
        }
        let material = authority_registry::bootstrap_material_in_tx(
            &tx,
            tenant,
            &challenge.challenge.manifest_id,
            now,
            true,
        )?;
        if material.authorization_hash != challenge.challenge.authorization_hash {
            return Err(AuthorityError::Binding);
        }
        let origin = bootstrap_origin::current_origin(&tx, tenant, now)?;
        if origin.revision != challenge.origin_revision {
            return Err(AuthorityError::Binding);
        }
        let key = current_key(&tx, tenant, &challenge.challenge.target_id, now)?;
        if key.revision != crate::counter(&challenge.challenge.key_revision)? {
            return Err(AuthorityError::Binding);
        }
        require_transition(
            &tx,
            tenant,
            &challenge.challenge,
            challenge.expected_target_revision,
        )?;
        let verified = verify_target_bootstrap_confirmation(
            receipt,
            &challenge.challenge,
            &key.pin,
            &challenge.baseline,
            &challenge.capability,
            now,
        )?;
        if let Some(previous) = head_at(&tx, tenant, &challenge.challenge.target_id)? {
            let retained = confirmation_at(&tx, tenant, &previous.hash)?;
            if retained.verified.journal_id() != verified.journal_id() {
                return Err(AuthorityError::Binding);
            }
        }
        let revision = challenge
            .expected_target_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(AuthorityError::Conflict)?;
        tx.execute("INSERT INTO authority_target_bootstrap_confirmations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",params![tenant.org_id,tenant.project_id,hash(verified.hash())?,challenge.challenge.challenge_id,hash(verified.challenge_hash())?,challenge.challenge.target_id,revision.to_be_bytes().as_slice(),verified.accepted_epoch().to_be_bytes().as_slice(),verified.highest_generation().to_be_bytes().as_slice(),verified.journal_id(),verified.observed_at(),now,verified.valid_until(),verified.canonical_bytes()])?;
        retained_projection(
            &tx,
            "UPDATE authority_target_bootstrap_confirmation_heads SET revision=?4,accepted_epoch=?5,highest_generation=?6,confirmation_hash=?7,observed_at=?8 WHERE org_id=?1 AND project_id=?2 AND target_id=?3",
            "INSERT INTO authority_target_bootstrap_confirmation_heads VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                tenant.org_id,
                tenant.project_id,
                challenge.challenge.target_id,
                revision.to_be_bytes().as_slice(),
                verified.accepted_epoch().to_be_bytes().as_slice(),
                verified.highest_generation().to_be_bytes().as_slice(),
                hash(verified.hash())?,
                verified.observed_at()
            ],
        )?;
        bump_security(&tx, tenant)?;
        audit(
            &tx,
            tenant,
            "target_bootstrap_confirmed",
            verified.hash(),
            now,
        )?;
        let retained = ConfirmationRecord {
            receipt: receipt.clone(),
            verified,
            revision,
            admitted_at: now,
        };
        let result = status_for_confirmation(&tx, tenant, &retained, now, false)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn read_target_bootstrap_status(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        now: i64,
    ) -> Result<Option<TargetBootstrapStatus>> {
        identifier(target)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self.connection.transaction()?;
        authority_registry::require_registry_time(&tx, tenant, now)?;
        let result = target_status_in_tx(&tx, tenant, target, now)?;
        tx.commit()?;
        Ok(result)
    }
}

fn status_for_confirmation(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    record: &ConfirmationRecord,
    now: i64,
    replayed: bool,
) -> Result<TargetBootstrapStatus> {
    authority_registry::require_registry_time(tx, tenant, now)?;
    let challenge = challenge_at(tx, tenant, &record.receipt.payload.challenge.challenge_id)?;
    let target = &challenge.challenge.target_id;
    let head = head_at(tx, tenant, target)?
        .ok_or(invalid("target bootstrap confirmation head missing"))?;
    let mut eligible = head.hash == record.verified.hash()
        && head.revision == record.revision
        && now >= record.admitted_at
        && now < record.verified.valid_until()
        && !policy_head_exists(tx, tenant, target)?;
    let mut gates = vec![
        Gate::BuildIdentityRequired.code().into(),
        Gate::NativeQualificationRequired.code().into(),
        Gate::WorkloadSourceAttestationRequired.code().into(),
        Gate::PolicySignerKeyRequired.code().into(),
    ];
    let origin = unavailable(bootstrap_origin::current_origin(tx, tenant, now))?;
    if origin
        .as_ref()
        .is_none_or(|origin| origin.revision != challenge.origin_revision)
    {
        eligible = false;
        gates.push(Gate::BootstrapApprovalOriginRequired.code().into());
    }
    let material = unavailable(authority_registry::bootstrap_material_in_tx(
        tx,
        tenant,
        &challenge.challenge.manifest_id,
        now,
        true,
    ))?;
    if material.as_ref().is_none_or(|material| {
        material.authorization_hash != challenge.challenge.authorization_hash
    }) {
        eligible = false;
        gates.push(Gate::BootstrapAuthorizationRequired.code().into());
    }
    let key = unavailable(current_key(tx, tenant, target, now))?;
    if key
        .as_ref()
        .is_none_or(|key| key.pin.revision != challenge.challenge.key_revision)
    {
        eligible = false;
    }
    if !eligible {
        gates.push(Gate::TargetEpochConfirmationRequired.code().into());
    }
    Ok(TargetBootstrapStatus {
        schema_version: "fw.target-bootstrap-status/v1".into(),
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        target_id: target.clone(),
        state: "target_confirmed_pending_qualification".into(),
        confirmation_revision: record.revision.to_string(),
        accepted_epoch: record.verified.accepted_epoch().to_string(),
        highest_generation: record.verified.highest_generation().to_string(),
        confirmation_hash: record.verified.hash().into(),
        challenge_hash: record.verified.challenge_hash().into(),
        manifest_hash: challenge.challenge.manifest_hash,
        authorization_hash: challenge.challenge.authorization_hash,
        management_baseline_hash: challenge.challenge.management_baseline_hash,
        capability_hash: challenge.challenge.capability_hash,
        journal_id: record.verified.journal_id().into(),
        observed_at: at(record.verified.observed_at())?,
        admitted_at: at(record.admitted_at)?,
        valid_until: at(record.verified.valid_until())?,
        checked_at: at(now)?,
        current_confirmation_eligibility: eligible,
        replayed,
        gates,
        signing_allowed: false,
        dispatch_allowed: false,
    })
}

pub(super) fn target_status_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    now: i64,
) -> Result<Option<TargetBootstrapStatus>> {
    authority_registry::require_registry_time(tx, tenant, now)?;
    let Some(head) = head_at(tx, tenant, target)? else {
        return Ok(None);
    };
    let record = confirmation_at(tx, tenant, &head.hash)?;
    status_for_confirmation(tx, tenant, &record, now, false).map(Some)
}
