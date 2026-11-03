//! Independently pinned device metadata. No report is native qualification,
//! installed-state evidence, an approval, a signing reservation or a grant.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fw_target_evidence::{SignedMetadataReport, TargetMetadataChallenge};
use serde::{Deserialize, Serialize};

const MAX_LIVE_CHALLENGES: i64 = 4;

/// Trusted-local administrator input. These scalar values are an independently
/// established key/certificate trust pin, not the result of X.509 chain checking.
/// Never populate them automatically from a controller or submitted report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetTransportPin {
    pub target_id: String,
    pub public_key: [u8; 32],
    pub certificate_fingerprint: String,
    pub platform: String,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    schema_version: String,
    org_id: String,
    project_id: String,
    revision: String,
    pinned_at: String,
    pin: TargetTransportPin,
}

/// Immutable historical receipt. Even a successfully replayed receipt conveys
/// no current authority; obtain a fresh current_target_metadata snapshot instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetMetadataReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub challenge_id: String,
    pub key_revision: String,
    pub sequence: String,
    pub key_fingerprint: String,
    pub certificate_fingerprint: String,
    pub report_hash: String,
    pub proof_hash: String,
    pub admitted_at: String,
    pub checked_at: String,
    pub valid_until: String,
    pub assurance: String,
    pub enforcement_status: String,
}
#[derive(Debug, Serialize)]
pub struct TargetMetadataAdmission {
    pub receipt: TargetMetadataReceipt,
    pub replayed: bool,
}
/// Revalidated device-authenticated metadata snapshot; no native state or gate
/// claim is provided. The device can sign false metadata about its own machine.
#[derive(Debug, Serialize)]
pub struct CurrentTargetMetadata {
    pub receipt: TargetMetadataReceipt,
    pub report: Value,
    pub enforcement_status: &'static str,
}

fn evidence_error(_: fw_target_evidence::EvidenceError) -> AuthorityError {
    invalid("target metadata proof")
}
fn revision(text: &str) -> Result<u64> {
    let value = text
        .parse::<u64>()
        .map_err(|_| invalid("target pin revision"))?;
    if value == 0 || value.to_string() != text {
        return Err(invalid("target pin revision"));
    }
    Ok(value)
}
fn revision_bytes(value: &[u8]) -> Result<u64> {
    let value = u64::from_be_bytes(
        value
            .try_into()
            .map_err(|_| invalid("target pin revision"))?,
    );
    if value == 0 {
        return Err(invalid("target pin revision"));
    }
    Ok(value)
}
fn validate_pin(pin: &TargetTransportPin, now: i64) -> Result<String> {
    identifier(&pin.target_id)?;
    interval(pin.not_before, pin.not_after, now)?;
    if now < pin.not_before || !matches!(pin.platform.as_str(), "linux" | "windows" | "macos") {
        return Err(AuthorityError::Binding);
    }
    hash(&pin.certificate_fingerprint)?;
    fw_target_evidence::fingerprint(&pin.public_key).map_err(evidence_error)
}

struct Pin {
    record: PinRecord,
    revision: u64,
    fingerprint: String,
}
struct PinRow {
    key_hash: Vec<u8>,
    cert_hash: Vec<u8>,
    digest: Vec<u8>,
    pinned_at: i64,
    canonical: Vec<u8>,
}
fn pin_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    version: u64,
) -> Result<Pin> {
    let row: Option<PinRow> = tx.query_row(
        "SELECT key_fingerprint,certificate_fingerprint,pin_hash,pinned_at,CASE WHEN length(canonical_bytes)<=8192 THEN canonical_bytes END FROM authority_target_pins WHERE org_id=? AND project_id=? AND target_id=? AND revision=?",
        params![tenant.org_id,tenant.project_id,target,version.to_be_bytes().as_slice()],
        |r|Ok(PinRow{key_hash:r.get(0)?,cert_hash:r.get(1)?,digest:r.get(2)?,pinned_at:r.get(3)?,canonical:r.get(4)?})).optional()?;
    let Some(PinRow {
        key_hash,
        cert_hash,
        digest,
        pinned_at,
        canonical,
    }) = row
    else {
        return Err(AuthorityError::Binding);
    };
    let record: PinRecord = decode(&canonical)?;
    if record.schema_version != "fw.authority-target-pin/v1"
        || record.org_id != tenant.org_id
        || record.project_id != tenant.project_id
        || record.pin.target_id != target
        || revision(&record.revision)? != version
        || record.pinned_at != at(pinned_at)?
        || digest != hash(&hash_bytes(&canonical))?
        || cert_hash != hash(&record.pin.certificate_fingerprint)?
    {
        return Err(invalid("stored target pin projection"));
    }
    let fingerprint = validate_pin(&record.pin, pinned_at)?;
    if key_hash != hash(&fingerprint)? {
        return Err(AuthorityError::Binding);
    }
    let owner:Option<(String,String,Vec<u8>,i64)>=tx.query_row("SELECT project_id,target_id,public_key,registered_at FROM authority_target_keys WHERE org_id=? AND key_fingerprint=?",params![tenant.org_id,key_hash],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    if owner.as_ref().is_none_or(|(project, id, key, registered)| {
        project != &tenant.project_id
            || id != target
            || key.as_slice() != record.pin.public_key
            || *registered > pinned_at
            || *registered < 0
    }) {
        return Err(invalid("target key ownership"));
    }
    Ok(Pin {
        record,
        revision: version,
        fingerprint,
    })
}
fn current_pin(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
) -> Result<Option<Pin>> {
    let head:Option<Vec<u8>>=tx.query_row("SELECT revision FROM authority_target_pin_heads WHERE org_id=? AND project_id=? AND target_id=?",params![tenant.org_id,tenant.project_id,target],|r|r.get(0)).optional()?;
    let latest:Option<Vec<u8>>=tx.query_row("SELECT revision FROM authority_target_pins WHERE org_id=? AND project_id=? AND target_id=? ORDER BY revision DESC LIMIT 1",params![tenant.org_id,tenant.project_id,target],|r|r.get(0)).optional()?;
    if head != latest {
        return Err(invalid("target pin head"));
    }
    head.map(|value| pin_at(tx, tenant, target, revision_bytes(&value)?))
        .transpose()
}
fn revoked(tx: &Transaction<'_>, tenant: &AuthorityTenant, fingerprint: &str) -> Result<bool> {
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_target_key_revocations WHERE org_id=? AND key_fingerprint=?)",params![tenant.org_id,hash(fingerprint)?],|r|r.get(0))?)
}
fn pin_current(tx: &Transaction<'_>, tenant: &AuthorityTenant, pin: &Pin, now: i64) -> Result<()> {
    if now < pin.record.pin.not_before
        || now < fw_target_evidence::parse_time(&pin.record.pinned_at).map_err(evidence_error)?
        || now >= pin.record.pin.not_after
        || revoked(tx, tenant, &pin.fingerprint)?
    {
        return Err(AuthorityError::Time);
    }
    Ok(())
}
pub(super) fn clock(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    now: i64,
) -> Result<()> {
    let observed:Option<i64>=tx.query_row("SELECT observed_at FROM authority_target_clocks WHERE org_id=? AND project_id=? AND target_id=?",params![tenant.org_id,tenant.project_id,target],|r|r.get(0)).optional()?;
    match observed {
        Some(previous) if (0..=MAX_TIME).contains(&previous) && now >= previous => Ok(()),
        Some(_) => Err(AuthorityError::Time),
        None => Err(invalid("target observation clock")),
    }
}

impl AuthorityStore {
    /// Privileged local namespace initialization for metadata maintenance. This
    /// creates no human principal, role, authority basis, target key or approval.
    pub fn provision_target_metadata_project(
        &mut self,
        tenant: &AuthorityTenant,
        now: i64,
    ) -> Result<()> {
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_projects WHERE org_id=? AND project_id=?)",
            params![tenant.org_id, tenant.project_id],
            |r| r.get(0),
        )?;
        if exists {
            security_revision(&tx, tenant)?;
            audit_log::append_head(&tx, tenant)?;
        } else {
            tx.execute(
                "INSERT INTO authority_projects VALUES(?,?,1)",
                params![tenant.org_id, tenant.project_id],
            )?;
            tx.execute(
                "INSERT INTO authority_audit_heads VALUES(?,?,?,?)",
                params![
                    tenant.org_id,
                    tenant.project_id,
                    [0u8; 8].as_slice(),
                    [0u8; 32].as_slice()
                ],
            )?;
            audit(
                &tx,
                tenant,
                "target_metadata_namespace_initialized",
                &tenant.project_id,
                now,
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // Persist the observed clock before the mutation transaction. Even a later
    // expired/invalid-proof refusal must prevent resurrection after rollback.
    // This intentional security-state write never consumes a challenge or
    // appends report/audit/head state. The mutation rechecks the floor too.
    pub(super) fn observe_target_time(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        now: i64,
    ) -> Result<bool> {
        identifier(target)?;
        time(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_target_pin_heads WHERE org_id=? AND project_id=? AND target_id=?)",params![tenant.org_id,tenant.project_id,target],|r|r.get(0))?;
        if exists {
            clock(&tx, tenant, target, now)?;
            tx.execute("UPDATE authority_target_clocks SET observed_at=? WHERE org_id=? AND project_id=? AND target_id=?",params![now,tenant.org_id,tenant.project_id,target])?;
        }
        tx.commit()?;
        Ok(exists)
    }

    /// Privileged independent provisioning. `None` creates the first pin;
    /// `Some(revision)` is an exact CAS for renewal/rotation. Exact current-pin
    /// retry retains the original revision and expiry. Revoked/rotated keys can
    /// never be reinstated under a new target or project in the same organization.
    pub fn pin_target_transport(
        &mut self,
        tenant: &AuthorityTenant,
        pin: &TargetTransportPin,
        expected_revision: Option<u64>,
        now: i64,
    ) -> Result<u64> {
        identifier(&pin.target_id)?;
        time(now)?;
        self.observe_target_time(tenant, &pin.target_id, now)?;
        let fingerprint = validate_pin(pin, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        security_revision(&tx, tenant)?;
        // Purpose ownership is bidirectional and retained after revocation.
        // A lab observer key must never later become a transport identity.
        let observer_key: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_native_observer_keys WHERE org_id=? AND key_fingerprint=?)",
            params![tenant.org_id, hash(&fingerprint)?],
            |r| r.get(0),
        )?;
        if observer_key {
            return Err(AuthorityError::Binding);
        }
        let previous = current_pin(&tx, tenant, &pin.target_id)?;
        if previous.is_some() {
            clock(&tx, tenant, &pin.target_id, now)?;
        }
        if let Some(current) = &previous
            && current.record.pin == *pin
            && !revoked(&tx, tenant, &fingerprint)?
            && (expected_revision == Some(current.revision)
                || expected_revision == current.revision.checked_sub(1).filter(|v| *v > 0)
                || (current.revision == 1 && expected_revision.is_none()))
        {
            tx.commit()?;
            return Ok(current.revision);
        }
        if previous.as_ref().map(|p| p.revision) != expected_revision {
            return Err(AuthorityError::Conflict);
        }
        if revoked(&tx, tenant, &fingerprint)? {
            return Err(AuthorityError::Binding);
        }
        let key_hash = hash(&fingerprint)?;
        let owner:Option<(String,String,Vec<u8>)>=tx.query_row("SELECT project_id,target_id,public_key FROM authority_target_keys WHERE org_id=? AND key_fingerprint=?",params![tenant.org_id,key_hash],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((project, target, key)) = &owner
            && (project != &tenant.project_id
                || target != &pin.target_id
                || key.as_slice() != pin.public_key)
        {
            return Err(AuthorityError::Conflict);
        }
        let certificate_exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_target_pins WHERE org_id=? AND certificate_fingerprint=?)",params![tenant.org_id,hash(&pin.certificate_fingerprint)?],|r|r.get(0))?;
        if certificate_exists {
            return Err(AuthorityError::Conflict);
        }
        let next = expected_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(invalid("target pin revision exhausted"))?;
        if owner.is_none() {
            tx.execute(
                "INSERT INTO authority_target_keys VALUES(?,?,?,?,?,?)",
                params![
                    tenant.org_id,
                    key_hash,
                    tenant.project_id,
                    pin.target_id,
                    pin.public_key.as_slice(),
                    now
                ],
            )?;
        }
        if let Some(old) = &previous
            && old.fingerprint != fingerprint
        {
            tx.execute(
                "INSERT INTO authority_target_key_revocations SELECT ?1,?2,?3,'rotated' WHERE NOT EXISTS(SELECT 1 FROM authority_target_key_revocations WHERE org_id=?1 AND key_fingerprint=?2)",
                params![tenant.org_id, hash(&old.fingerprint)?, now],
            )?;
        }
        let record = PinRecord {
            schema_version: "fw.authority-target-pin/v1".into(),
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            revision: next.to_string(),
            pinned_at: at(now)?,
            pin: pin.clone(),
        };
        let canonical = bytes(&record)?;
        if canonical.len() > 8192 {
            return Err(invalid("target pin size"));
        }
        tx.execute(
            "INSERT INTO authority_target_pins VALUES(?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                pin.target_id,
                next.to_be_bytes().as_slice(),
                key_hash,
                hash(&pin.certificate_fingerprint)?,
                hash(&hash_bytes(&canonical))?,
                now,
                canonical
            ],
        )?;
        retained_projection(
            &tx,
            "UPDATE authority_target_pin_heads SET revision=?4 WHERE org_id=?1 AND project_id=?2 AND target_id=?3",
            "INSERT INTO authority_target_pin_heads VALUES(?1,?2,?3,?4)",
            params![
                tenant.org_id,
                tenant.project_id,
                pin.target_id,
                next.to_be_bytes().as_slice()
            ],
        )?;
        retained_projection(
            &tx,
            "UPDATE authority_target_clocks SET observed_at=?4 WHERE org_id=?1 AND project_id=?2 AND target_id=?3",
            "INSERT INTO authority_target_clocks VALUES(?1,?2,?3,?4)",
            params![tenant.org_id, tenant.project_id, pin.target_id, now],
        )?;
        bump_security(&tx, tenant)?;
        audit(&tx, tenant, "target_transport_pinned", &pin.target_id, now)?;
        tx.commit()?;
        Ok(next)
    }

    pub fn revoke_target_transport(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        expected_revision: u64,
        now: i64,
    ) -> Result<()> {
        self.observe_target_time(tenant, target, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock(&tx, tenant, target, now)?;
        let pin = current_pin(&tx, tenant, target)?.ok_or(AuthorityError::Binding)?;
        if pin.revision != expected_revision {
            return Err(AuthorityError::Conflict);
        }
        if !revoked(&tx, tenant, &pin.fingerprint)? {
            tx.execute(
                "INSERT INTO authority_target_key_revocations VALUES(?,?,?,'revoked')",
                params![tenant.org_id, hash(&pin.fingerprint)?, now],
            )?;
            bump_security(&tx, tenant)?;
            audit(&tx, tenant, "target_transport_revoked", target, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Trusted-local challenge issuance only; anonymous controller requests must
    /// never expose this method. At most four live challenges per current pin.
    pub fn issue_target_report_challenge(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        now: i64,
    ) -> Result<TargetMetadataChallenge> {
        self.observe_target_time(tenant, target, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock(&tx, tenant, target, now)?;
        let pin = current_pin(&tx, tenant, target)?.ok_or(AuthorityError::Binding)?;
        pin_current(&tx, tenant, &pin, now)?;
        let outstanding:i64=tx.query_row("SELECT count(*) FROM (SELECT 1 FROM authority_target_challenges c WHERE c.org_id=? AND c.project_id=? AND c.target_id=? AND c.pin_revision=? AND c.expires_at>? AND NOT EXISTS(SELECT 1 FROM authority_target_metadata m WHERE m.org_id=c.org_id AND m.project_id=c.project_id AND m.challenge_id=c.challenge_id) LIMIT 4)",params![tenant.org_id,tenant.project_id,target,pin.revision.to_be_bytes().as_slice(),now],|r|r.get(0))?;
        if outstanding >= MAX_LIVE_CHALLENGES {
            return Err(AuthorityError::Quota);
        }
        let mut nonce = [0; 32];
        openssl::rand::rand_bytes(&mut nonce).map_err(|_| invalid("authority randomness"))?;
        let challenge = TargetMetadataChallenge {
            schema_version: fw_target_evidence::CHALLENGE_SCHEMA.into(),
            challenge_id: new_id()?,
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            target_id: target.into(),
            key_revision: pin.revision.to_string(),
            key_fingerprint: pin.fingerprint,
            certificate_fingerprint: pin.record.pin.certificate_fingerprint,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            issued_at: at(now)?,
            expires_at: at(now.saturating_add(300).min(pin.record.pin.not_after))?,
        };
        let window = challenge.validate(now).map_err(evidence_error)?;
        let canonical = challenge.canonical_bytes().map_err(evidence_error)?;
        tx.execute(
            "INSERT INTO authority_target_challenges VALUES(?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                target,
                challenge.challenge_id,
                pin.revision.to_be_bytes().as_slice(),
                hash(&hash_bytes(&canonical))?,
                window.issued_at,
                window.expires_at,
                canonical
            ],
        )?;
        audit(
            &tx,
            tenant,
            "target_report_challenge_issued",
            &challenge.challenge_id,
            now,
        )?;
        tx.commit()?;
        Ok(challenge)
    }

    /// Signature verification, one-use challenge consumption, original proof,
    /// report/current head and mandatory audit commit atomically. Exact retries
    /// acknowledge the old receipt even if its metadata is no longer current.
    pub fn admit_target_report(
        &mut self,
        tenant: &AuthorityTenant,
        proof: &SignedMetadataReport,
        now: i64,
    ) -> Result<TargetMetadataAdmission> {
        identifier(&proof.challenge.challenge_id)?;
        identifier(&proof.challenge.target_id)?;
        if proof.challenge.org_id != tenant.org_id
            || proof.challenge.project_id != tenant.project_id
        {
            return Err(AuthorityError::Binding);
        }
        let proof_bytes = proof.canonical_bytes().map_err(evidence_error)?;
        let proof_hash = hash_bytes(&proof_bytes);
        let target = &proof.challenge.target_id;
        self.observe_target_time(tenant, target, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock(&tx, tenant, target, now)?;
        let expected = challenge_in_tx(&tx, tenant, &proof.challenge.challenge_id)?;
        if expected != proof.challenge {
            return Err(AuthorityError::Binding);
        }
        if let Some(id)=tx.query_row("SELECT receipt_id FROM authority_target_metadata WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,expected.challenge_id],|r|r.get::<_,String>(0)).optional()? {
            let saved=metadata_in_tx(&tx,tenant,&id)?;
            if saved.receipt.proof_hash!=proof_hash || saved.proof_bytes!=proof_bytes { return Err(AuthorityError::Conflict); }
            tx.commit()?; return Ok(TargetMetadataAdmission{receipt:saved.receipt,replayed:true});
        }
        let pin = current_pin(&tx, tenant, target)?.ok_or(AuthorityError::Binding)?;
        pin_current(&tx, tenant, &pin, now)?;
        if expected.key_revision != pin.revision.to_string()
            || expected.key_fingerprint != pin.fingerprint
            || expected.certificate_fingerprint != pin.record.pin.certificate_fingerprint
        {
            return Err(AuthorityError::Binding);
        }
        let verified = fw_target_evidence::verify_report(
            &expected,
            proof,
            &pin.record.pin.public_key,
            &pin.record.pin.platform,
            now,
            pin.record.pin.not_after,
        )
        .map_err(evidence_error)?;
        let previous = metadata_head(&tx, tenant, target)?;
        let next = if let Some(old) = &previous {
            let checked =
                fw_target_evidence::parse_time(&old.receipt.checked_at).map_err(evidence_error)?;
            if verified.checked_at() < checked
                || (verified.checked_at() == checked
                    && verified.report_hash() != old.receipt.report_hash)
            {
                return Err(AuthorityError::Conflict);
            }
            revision(&old.receipt.sequence)?
                .checked_add(1)
                .ok_or(invalid("target metadata sequence exhausted"))?
        } else {
            1
        };
        let receipt = TargetMetadataReceipt {
            schema_version: "fw.authority-target-metadata-receipt/v1".into(),
            receipt_id: new_id()?,
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            target_id: target.clone(),
            challenge_id: expected.challenge_id.clone(),
            key_revision: pin.revision.to_string(),
            sequence: next.to_string(),
            key_fingerprint: pin.fingerprint,
            certificate_fingerprint: pin.record.pin.certificate_fingerprint,
            report_hash: verified.report_hash().into(),
            proof_hash,
            admitted_at: at(now)?,
            checked_at: at(verified.checked_at())?,
            valid_until: at(verified.valid_until())?,
            assurance: "authenticated_metadata_only".into(),
            enforcement_status: "unverified".into(),
        };
        let receipt_bytes = bytes(&receipt)?;
        tx.execute(
            "INSERT INTO authority_target_metadata VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                target,
                receipt.receipt_id,
                expected.challenge_id,
                pin.revision.to_be_bytes().as_slice(),
                next.to_be_bytes().as_slice(),
                hash(&receipt.report_hash)?,
                hash(&receipt.proof_hash)?,
                now,
                verified.checked_at(),
                verified.valid_until(),
                proof_bytes,
                receipt_bytes
            ],
        )?;
        retained_projection(
            &tx,
            "UPDATE authority_target_metadata_heads SET receipt_id=?4 WHERE org_id=?1 AND project_id=?2 AND target_id=?3",
            "INSERT INTO authority_target_metadata_heads VALUES(?1,?2,?3,?4)",
            params![tenant.org_id, tenant.project_id, target, receipt.receipt_id],
        )?;
        audit(
            &tx,
            tenant,
            "target_metadata_admitted",
            &receipt.receipt_id,
            now,
        )?;
        tx.commit()?;
        Ok(TargetMetadataAdmission {
            receipt,
            replayed: false,
        })
    }

    /// Reads persist a conservative observation clock. Returning None for expiry
    /// cannot be undone by later clock rollback. No report authorizes enforcement.
    pub fn current_target_metadata(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        now: i64,
    ) -> Result<Option<CurrentTargetMetadata>> {
        let exists = self.observe_target_time(tenant, target, now)?;
        if !exists {
            return Ok(None);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock(&tx, tenant, target, now)?;
        let result = current_metadata_in_tx(&tx, tenant, target, now)?;
        tx.commit()?;
        Ok(result)
    }
}

struct ChallengeRow {
    target: String,
    pin_revision: Vec<u8>,
    digest: Vec<u8>,
    issued: i64,
    expires: i64,
    canonical: Vec<u8>,
}
fn challenge_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<TargetMetadataChallenge> {
    let row:Option<ChallengeRow>=tx.query_row("SELECT target_id,pin_revision,challenge_hash,issued_at,expires_at,CASE WHEN length(canonical_bytes)<=4096 THEN canonical_bytes END FROM authority_target_challenges WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok(ChallengeRow{target:r.get(0)?,pin_revision:r.get(1)?,digest:r.get(2)?,issued:r.get(3)?,expires:r.get(4)?,canonical:r.get(5)?})).optional()?;
    let Some(ChallengeRow {
        target,
        pin_revision,
        digest,
        issued,
        expires,
        canonical,
    }) = row
    else {
        return Err(AuthorityError::Binding);
    };
    let challenge: TargetMetadataChallenge = decode(&canonical)?;
    let window = challenge.validate(issued).map_err(evidence_error)?;
    if challenge.org_id != tenant.org_id
        || challenge.project_id != tenant.project_id
        || challenge.challenge_id != id
        || challenge.target_id != target
        || challenge.key_revision != revision_bytes(&pin_revision)?.to_string()
        || window.issued_at != issued
        || window.expires_at != expires
        || digest != hash(&hash_bytes(&canonical))?
    {
        return Err(invalid("stored target challenge projection"));
    }
    let pin = pin_at(tx, tenant, &target, revision_bytes(&pin_revision)?)?;
    if challenge.key_fingerprint != pin.fingerprint
        || challenge.certificate_fingerprint != pin.record.pin.certificate_fingerprint
        || issued < pin.record.pin.not_before
        || expires > pin.record.pin.not_after
        || issued < fw_target_evidence::parse_time(&pin.record.pinned_at).map_err(evidence_error)?
    {
        return Err(AuthorityError::Binding);
    }
    Ok(challenge)
}
struct Metadata {
    receipt: TargetMetadataReceipt,
    proof_bytes: Vec<u8>,
    report_bytes: Vec<u8>,
}
struct MetadataRow {
    target: String,
    challenge: String,
    pin_revision: Vec<u8>,
    sequence: Vec<u8>,
    report_hash: Vec<u8>,
    proof_hash: Vec<u8>,
    admitted: i64,
    checked: i64,
    valid: i64,
    proof: Vec<u8>,
    receipt: Vec<u8>,
}
fn metadata_in_tx(tx: &Transaction<'_>, tenant: &AuthorityTenant, id: &str) -> Result<Metadata> {
    let row:MetadataRow=tx.query_row("SELECT target_id,challenge_id,pin_revision,sequence,report_hash,proof_hash,admitted_at,checked_at,valid_until,CASE WHEN length(proof_bytes)<=131072 THEN proof_bytes END,CASE WHEN length(receipt_bytes)<=8192 THEN receipt_bytes END FROM authority_target_metadata WHERE org_id=? AND project_id=? AND receipt_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok(MetadataRow{target:r.get(0)?,challenge:r.get(1)?,pin_revision:r.get(2)?,sequence:r.get(3)?,report_hash:r.get(4)?,proof_hash:r.get(5)?,admitted:r.get(6)?,checked:r.get(7)?,valid:r.get(8)?,proof:r.get(9)?,receipt:r.get(10)?}))?;
    let receipt: TargetMetadataReceipt = decode(&row.receipt)?;
    let expected = challenge_in_tx(tx, tenant, &row.challenge)?;
    let pin = pin_at(tx, tenant, &row.target, revision_bytes(&row.pin_revision)?)?;
    if expected.target_id != row.target
        || expected.key_revision != pin.revision.to_string()
        || expected.key_fingerprint != pin.fingerprint
        || expected.certificate_fingerprint != pin.record.pin.certificate_fingerprint
    {
        return Err(AuthorityError::Binding);
    }
    let proof: SignedMetadataReport = decode(&row.proof)?;
    if row.admitted < pin.record.pin.not_before
        || row.admitted
            < fw_target_evidence::parse_time(&pin.record.pinned_at).map_err(evidence_error)?
        || row.admitted >= pin.record.pin.not_after
    {
        return Err(AuthorityError::Time);
    }
    let verified = fw_target_evidence::verify_report(
        &expected,
        &proof,
        &pin.record.pin.public_key,
        &pin.record.pin.platform,
        row.admitted,
        pin.record.pin.not_after,
    )
    .map_err(evidence_error)?;
    let rebuilt = TargetMetadataReceipt {
        schema_version: "fw.authority-target-metadata-receipt/v1".into(),
        receipt_id: id.into(),
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        target_id: row.target,
        challenge_id: row.challenge,
        key_revision: pin.revision.to_string(),
        sequence: revision_bytes(&row.sequence)?.to_string(),
        key_fingerprint: pin.fingerprint,
        certificate_fingerprint: pin.record.pin.certificate_fingerprint,
        report_hash: verified.report_hash().into(),
        proof_hash: hash_bytes(&row.proof),
        admitted_at: at(row.admitted)?,
        checked_at: at(verified.checked_at())?,
        valid_until: at(verified.valid_until())?,
        assurance: "authenticated_metadata_only".into(),
        enforcement_status: "unverified".into(),
    };
    if receipt != rebuilt
        || row.report_hash != hash(&receipt.report_hash)?
        || row.proof_hash != hash(&receipt.proof_hash)?
        || row.checked != verified.checked_at()
        || row.valid != verified.valid_until()
    {
        return Err(invalid("stored target metadata projection"));
    }
    Ok(Metadata {
        receipt,
        proof_bytes: row.proof,
        report_bytes: verified.report_bytes().into(),
    })
}
fn metadata_head(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
) -> Result<Option<Metadata>> {
    let head:Option<String>=tx.query_row("SELECT receipt_id FROM authority_target_metadata_heads WHERE org_id=? AND project_id=? AND target_id=?",params![tenant.org_id,tenant.project_id,target],|r|r.get(0)).optional()?;
    let latest:Option<String>=tx.query_row("SELECT receipt_id FROM authority_target_metadata WHERE org_id=? AND project_id=? AND target_id=? ORDER BY sequence DESC LIMIT 1",params![tenant.org_id,tenant.project_id,target],|r|r.get(0)).optional()?;
    if head != latest {
        return Err(invalid("target metadata head"));
    }
    head.map(|id| metadata_in_tx(tx, tenant, &id)).transpose()
}

pub(super) fn current_metadata_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    now: i64,
) -> Result<Option<CurrentTargetMetadata>> {
    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_target_pin_heads WHERE org_id=? AND project_id=? AND target_id=?)",params![tenant.org_id,tenant.project_id,target],|r|r.get(0))?;
    if !exists {
        return Ok(None);
    }
    clock(tx, tenant, target, now)?;
    let pin = current_pin(tx, tenant, target)?.ok_or(AuthorityError::Binding)?;
    let metadata = metadata_head(tx, tenant, target)?;
    let current = match pin_current(tx, tenant, &pin, now) {
        Ok(()) => true,
        Err(AuthorityError::Time) => false,
        Err(error) => return Err(error),
    };
    let result = if let Some(saved) = metadata {
        if now
            < fw_target_evidence::parse_time(&saved.receipt.admitted_at).map_err(evidence_error)?
        {
            return Err(AuthorityError::Time);
        }
        if !current
            || saved.receipt.key_revision != pin.revision.to_string()
            || now
                >= fw_target_evidence::parse_time(&saved.receipt.valid_until)
                    .map_err(evidence_error)?
        {
            None
        } else {
            Some(CurrentTargetMetadata {
                receipt: saved.receipt,
                report: fw_contracts::parse_strict_with_limit(&saved.report_bytes, 65536)
                    .map_err(|_| invalid("target report bytes"))?,
                enforcement_status: "unverified",
            })
        }
    } else {
        None
    };
    Ok(result)
}

pub(super) fn retained_metadata_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<CurrentTargetMetadata> {
    let saved = metadata_in_tx(tx, tenant, id)?;
    Ok(CurrentTargetMetadata {
        receipt: saved.receipt,
        report: parse_strict_with_limit(&saved.report_bytes, 65536)
            .map_err(|_| invalid("retained metadata report"))?,
        enforcement_status: "unverified",
    })
}
