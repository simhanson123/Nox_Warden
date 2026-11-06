//! Reconstruct immutable target history without granting current readiness.
use super::target_bootstrap::{challenge_at, confirmation_at, head_at, key_at};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

type Scope = (String, String, String);
type AuditEvent = (String, String, String, String, i64);
fn number(bytes: Vec<u8>) -> Result<u64> {
    Ok(u64::from_be_bytes(bytes.as_slice().try_into().map_err(
        |_| invalid("target bootstrap counter projection"),
    )?))
}
fn scope(tenant: &AuthorityTenant, target: &str) -> Scope {
    (
        tenant.org_id.clone(),
        tenant.project_id.clone(),
        target.into(),
    )
}
fn event(
    events: &mut BTreeSet<AuditEvent>,
    tenant: &AuthorityTenant,
    kind: &str,
    resource: String,
    at: i64,
) -> Result<()> {
    if !(0..=MAX_TIME).contains(&at)
        || !events.insert((
            tenant.org_id.clone(),
            tenant.project_id.clone(),
            kind.into(),
            resource,
            at,
        ))
    {
        return Err(invalid("target bootstrap audit obligation"));
    }
    Ok(())
}

fn validate_keys(tx: &Transaction<'_>, events: &mut BTreeSet<AuditEvent>) -> Result<()> {
    let mut latest = BTreeMap::<Scope, (u64, i64)>::new();
    let mut statement = tx.prepare("SELECT org_id,project_id,target_id,revision FROM authority_target_bootstrap_key_pins ORDER BY org_id,project_id,target_id,revision")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let target: String = row.get(2)?;
        let revision = number(row.get(3)?)?;
        let record = key_at(tx, &tenant, &target, revision)?;
        if record.revision != revision
            || record.pin.target_id != target
            || latest
                .insert(scope(&tenant, &target), (revision, record.pinned_at))
                .map(|(old, at)| old.checked_add(1) != Some(revision) || at > record.pinned_at)
                .unwrap_or(revision != 1)
        {
            return Err(invalid("target bootstrap key history"));
        }
        event(
            events,
            &tenant,
            "target_bootstrap_key_pinned",
            format!("{target}:{revision}"),
            record.pinned_at,
        )?;
    }
    let mut statement = tx.prepare(
        "SELECT org_id,project_id,target_id,revision FROM authority_target_bootstrap_key_heads",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let identity: Scope = (row.get(0)?, row.get(1)?, row.get(2)?);
        let (revision, _) = latest
            .remove(&identity)
            .ok_or(invalid("target bootstrap key head without history"))?;
        if number(row.get(3)?)? != revision {
            return Err(invalid("target bootstrap key head is not latest"));
        }
    }
    if !latest.is_empty() {
        return Err(invalid("target bootstrap key head missing"));
    }
    let mut statement = tx.prepare("SELECT org_id,project_id,target_id,revision,revoked_at FROM authority_target_bootstrap_key_revocations")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let target: String = row.get(2)?;
        let revision = number(row.get(3)?)?;
        let revoked_at: i64 = row.get(4)?;
        let record = key_at(tx, &tenant, &target, revision)?;
        if record.revoked_at != Some(revoked_at) || revoked_at < record.pinned_at {
            return Err(invalid("target bootstrap key revocation history"));
        }
        event(
            events,
            &tenant,
            "target_bootstrap_key_revoked",
            format!("{target}:{revision}"),
            revoked_at,
        )?;
    }
    // Fingerprints use different historic encodings (raw Ed25519 bytes versus
    // SPKI DER). Compare the independently validated public keys themselves.
    let alias: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins b JOIN authority_registry_keys k ON k.org_id=b.org_id AND k.public_key=b.public_key) OR EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins b JOIN authority_target_keys k ON k.org_id=b.org_id AND k.public_key=b.public_key) OR EXISTS(SELECT 1 FROM authority_target_bootstrap_key_pins b JOIN authority_native_observer_keys k ON k.org_id=b.org_id AND k.public_key=b.public_key) OR EXISTS(SELECT 1 FROM authority_registry_keys r JOIN authority_target_keys k ON k.org_id=r.org_id AND k.public_key=r.public_key) OR EXISTS(SELECT 1 FROM authority_registry_keys r JOIN authority_native_observer_keys k ON k.org_id=r.org_id AND k.public_key=r.public_key) OR EXISTS(SELECT 1 FROM authority_target_keys t JOIN authority_native_observer_keys k ON k.org_id=t.org_id AND k.public_key=t.public_key)", [], |row| row.get(0))?;
    if alias {
        return Err(invalid("authority key purpose alias"));
    }
    Ok(())
}

fn validate_challenges(tx: &Transaction<'_>, events: &mut BTreeSet<AuditEvent>) -> Result<()> {
    let mut statement = tx.prepare(
        "SELECT org_id,project_id,challenge_id FROM authority_target_bootstrap_challenges",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let id: String = row.get(2)?;
        // This helper checks original authorization/proofs, origin and target
        // pins, B/capability/program and all projections at issuance time.
        let record = challenge_at(tx, &tenant, &id)?;
        let challenge = &record.challenge;
        let issued_at = crate::timestamp(&challenge.issued_at)?;
        let sequence = audit_sequence(tx, &tenant, "target_bootstrap_challenge_issued", &id)?;
        validate_authority_at_sequence(tx, &tenant, &record, sequence)?;
        match (
            &challenge.previous_confirmation_hash,
            record.expected_target_revision,
        ) {
            (None, None) if challenge.old_epoch.is_none() => {}
            (Some(hash), Some(revision)) => {
                let previous = confirmation_at(tx, &tenant, hash)?;
                if previous.revision != revision
                    || previous.receipt.payload.challenge.target_id != challenge.target_id
                    || challenge.old_epoch.as_deref()
                        != Some(previous.receipt.payload.accepted_epoch.as_str())
                    || previous.admitted_at > issued_at
                {
                    return Err(invalid("target bootstrap challenge predecessor"));
                }
            }
            _ => return Err(invalid("target bootstrap challenge predecessor")),
        }
        event(
            events,
            &tenant,
            "target_bootstrap_challenge_issued",
            id,
            issued_at,
        )?;
    }
    Ok(())
}

struct Confirmed {
    revision: u64,
    epoch: u64,
    generation: u64,
    hash: String,
    journal: String,
    observed_at: i64,
    admitted_at: i64,
}

fn audit_sequence(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    kind: &str,
    resource: &str,
) -> Result<u64> {
    let raw: Vec<u8> = tx.query_row("SELECT sequence FROM authority_audit WHERE org_id=? AND project_id=? AND kind=? AND resource_id=?", params![tenant.org_id,tenant.project_id,kind,resource], |row|row.get(0))?;
    number(raw)
}

fn validate_authority_at_sequence(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    record: &target_bootstrap::ChallengeRecord,
    sequence: u64,
) -> Result<()> {
    let challenge = &record.challenge;
    let key_resource = format!("{}:{}", challenge.target_id, challenge.key_revision);
    let latest_key: Option<String> = tx.query_row("SELECT resource_id FROM authority_audit WHERE org_id=? AND project_id=? AND kind='target_bootstrap_key_pinned' AND substr(resource_id,1,37)=? AND sequence<? ORDER BY sequence DESC LIMIT 1", params![tenant.org_id,tenant.project_id,format!("{}:", challenge.target_id),sequence.to_be_bytes().as_slice()], |row|row.get(0)).optional()?;
    let latest_origin: Option<String> = tx.query_row("SELECT resource_id FROM authority_audit WHERE org_id=? AND project_id=? AND kind='bootstrap_approval_origin_pinned' AND sequence<? ORDER BY sequence DESC LIMIT 1", params![tenant.org_id,tenant.project_id,sequence.to_be_bytes().as_slice()], |row|row.get(0)).optional()?;
    let revoked: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_audit WHERE org_id=? AND project_id=? AND kind='target_bootstrap_key_revoked' AND resource_id=? AND sequence<?)", params![tenant.org_id,tenant.project_id,key_resource,sequence.to_be_bytes().as_slice()], |row|row.get(0))?;
    if latest_key.as_deref() != Some(key_resource.as_str())
        || latest_origin != Some(record.origin_revision.to_string())
        || revoked
    {
        return Err(invalid(
            "target bootstrap authority was not current at event",
        ));
    }
    let predecessor: Option<String> = tx.query_row("SELECT a.resource_id FROM authority_audit a JOIN authority_target_bootstrap_confirmations c ON c.org_id=a.org_id AND c.project_id=a.project_id AND a.resource_id='sha256:'||lower(hex(c.confirmation_hash)) WHERE a.org_id=? AND a.project_id=? AND a.kind='target_bootstrap_confirmed' AND c.target_id=? AND a.sequence<? ORDER BY a.sequence DESC LIMIT 1", params![tenant.org_id,tenant.project_id,challenge.target_id,sequence.to_be_bytes().as_slice()], |row|row.get(0)).optional()?;
    if predecessor != challenge.previous_confirmation_hash {
        return Err(invalid(
            "target bootstrap predecessor was not current at event",
        ));
    }
    validate_registry_authority_at_sequence(tx, tenant, record, sequence)?;
    Ok(())
}

fn revoked_before(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    kind: &str,
    resource: &str,
    sequence: u64,
) -> Result<bool> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_audit WHERE org_id=? AND project_id=? AND kind=? AND resource_id=? AND sequence<?)", params![tenant.org_id,tenant.project_id,kind,resource,sequence.to_be_bytes().as_slice()], |row|row.get(0)).map_err(Into::into)
}

fn validate_registry_authority_at_sequence(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    record: &target_bootstrap::ChallengeRecord,
    sequence: u64,
) -> Result<()> {
    let challenge = &record.challenge;
    let material = authority_registry::bootstrap_material_in_tx(
        tx,
        tenant,
        &challenge.manifest_id,
        crate::timestamp(&challenge.issued_at)?,
        false,
    )?;
    if audit_sequence(
        tx,
        tenant,
        "registry_trust_key_pinned",
        &material.root.key_id,
    )? >= sequence
        || revoked_before(
            tx,
            tenant,
            "registry_trust_key_revoked",
            &material.root.key_id,
            sequence,
        )?
    {
        return Err(invalid("target bootstrap root was not current at event"));
    }
    let pending: Option<Vec<u8>> = tx.query_row("SELECT o.content_hash FROM authority_audit a JOIN authority_registry_objects o ON o.org_id=a.org_id AND o.project_id=a.project_id AND o.object_id=a.resource_id AND o.object_kind='bootstrap_authorization' WHERE a.org_id=? AND a.project_id=? AND a.kind='registry_bootstrap_authorization_admitted' AND o.target_id=? AND a.sequence<? ORDER BY a.sequence DESC LIMIT 1", params![tenant.org_id,tenant.project_id,challenge.target_id,sequence.to_be_bytes().as_slice()], |row|row.get(0)).optional()?;
    if pending.as_deref() != Some(hash(&challenge.authorization_hash)?.as_slice()) {
        return Err(invalid(
            "target bootstrap authorization was not current at event",
        ));
    }
    for digest in std::iter::once(&challenge.manifest_hash)
        .chain(std::iter::once(&challenge.authorization_hash))
        .chain(material.manifest.envelope_hashes.iter())
        .chain(material.manifest.delegation_hashes.iter())
    {
        let (kind,id): (String,String) = tx.query_row("SELECT object_kind,object_id FROM authority_registry_objects WHERE org_id=? AND project_id=? AND content_hash=?", params![tenant.org_id,tenant.project_id,hash(digest)?], |row|Ok((row.get(0)?,row.get(1)?)))?;
        if audit_sequence(tx, tenant, &format!("registry_{kind}_admitted"), &id)? >= sequence
            || revoked_before(tx, tenant, "registry_object_revoked", digest, sequence)?
        {
            return Err(invalid("target bootstrap input was not current at event"));
        }
    }
    for proof in material.proofs {
        let (credential,membership): (String,String) = tx.query_row("SELECT c.credential_id,c.membership_id FROM authority_bootstrap_proofs p JOIN authority_bootstrap_challenges c ON c.org_id=p.org_id AND c.project_id=p.project_id AND c.challenge_id=p.challenge_id WHERE p.org_id=? AND p.project_id=? AND p.proof_id=?", params![tenant.org_id,tenant.project_id,proof.proof_id], |row|Ok((row.get(0)?,row.get(1)?)))?;
        if audit_sequence(
            tx,
            tenant,
            "bootstrap_owner_proof_admitted",
            &proof.proof_id,
        )? >= sequence
            || revoked_before(tx, tenant, "credential_revoked", &credential, sequence)?
            || revoked_before(tx, tenant, "role_revoked", &membership, sequence)?
        {
            return Err(invalid(
                "target bootstrap owner proof was not current at event",
            ));
        }
    }
    Ok(())
}
fn validate_confirmations(tx: &Transaction<'_>, events: &mut BTreeSet<AuditEvent>) -> Result<()> {
    let mut latest = BTreeMap::<Scope, Confirmed>::new();
    let mut statement = tx.prepare("SELECT org_id,project_id,confirmation_hash FROM authority_target_bootstrap_confirmations ORDER BY org_id,project_id,target_id,revision")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let hash = hash_string(&row.get::<_, Vec<u8>>(2)?)?;
        // Independently checks signature and observations against their saved
        // pin/challenge at original admission, ignoring later loss of eligibility.
        let record = confirmation_at(tx, &tenant, &hash)?;
        let payload = &record.receipt.payload;
        let challenge = &payload.challenge;
        let accepted = Confirmed {
            revision: record.revision,
            epoch: record.verified.accepted_epoch(),
            generation: record.verified.highest_generation(),
            hash: hash.clone(),
            journal: record.verified.journal_id().into(),
            observed_at: record.verified.observed_at(),
            admitted_at: record.admitted_at,
        };
        if accepted.hash != record.verified.hash() || accepted.generation != 0 {
            return Err(invalid("target bootstrap confirmation projection"));
        }
        let expected = challenge_at(tx, &tenant, &challenge.challenge_id)?;
        let sequence = audit_sequence(tx, &tenant, "target_bootstrap_confirmed", &hash)?;
        validate_authority_at_sequence(tx, &tenant, &expected, sequence)?;
        if audit_sequence(
            tx,
            &tenant,
            "target_bootstrap_challenge_issued",
            &challenge.challenge_id,
        )? >= sequence
        {
            return Err(invalid("target bootstrap confirmation precedes challenge"));
        }
        if let Some(previous) = latest.get(&scope(&tenant, &challenge.target_id)) {
            if previous.revision.checked_add(1) != Some(accepted.revision)
                || expected.expected_target_revision != Some(previous.revision)
                || challenge
                    .old_epoch
                    .as_deref()
                    .map(crate::counter)
                    .transpose()?
                    != Some(previous.epoch)
                || challenge.previous_confirmation_hash.as_deref() != Some(previous.hash.as_str())
                || accepted.epoch <= previous.epoch
                || accepted.journal != previous.journal
                || accepted.observed_at < previous.observed_at
                || accepted.admitted_at < previous.admitted_at
            {
                return Err(invalid("target bootstrap confirmation chain"));
            }
        } else if accepted.revision != 1
            || expected.expected_target_revision.is_some()
            || challenge.old_epoch.is_some()
            || challenge.previous_confirmation_hash.is_some()
        {
            return Err(invalid("target bootstrap confirmation genesis"));
        }
        latest.insert(scope(&tenant, &challenge.target_id), accepted);
        event(
            events,
            &tenant,
            "target_bootstrap_confirmed",
            hash,
            record.admitted_at,
        )?;
    }
    let mut statement = tx.prepare(
        "SELECT org_id,project_id,target_id FROM authority_target_bootstrap_confirmation_heads",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let target: String = row.get(2)?;
        let expected = latest.remove(&scope(&tenant, &target)).ok_or(invalid(
            "target bootstrap confirmation head without history",
        ))?;
        let head = head_at(tx, &tenant, &target)?
            .ok_or(invalid("target bootstrap confirmation head missing"))?;
        if head.revision != expected.revision
            || head.epoch != expected.epoch
            || head.generation != expected.generation
            || head.hash != expected.hash
            || head.observed_at != expected.observed_at
        {
            return Err(invalid("target bootstrap confirmation head is not latest"));
        }
    }
    if !latest.is_empty() {
        return Err(invalid("target bootstrap confirmation head missing"));
    }
    Ok(())
}

pub(super) fn validate_retained(tx: &Transaction<'_>) -> Result<()> {
    let mut events = BTreeSet::new();
    validate_keys(tx, &mut events)?;
    validate_challenges(tx, &mut events)?;
    validate_confirmations(tx, &mut events)?;
    let missing_floor: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM (SELECT org_id,project_id,pinned_at witnessed FROM authority_target_bootstrap_key_pins UNION ALL SELECT org_id,project_id,revoked_at FROM authority_target_bootstrap_key_revocations UNION ALL SELECT org_id,project_id,issued_at FROM authority_target_bootstrap_challenges UNION ALL SELECT org_id,project_id,admitted_at FROM authority_target_bootstrap_confirmations) w LEFT JOIN authority_registry_clocks c USING(org_id,project_id) WHERE c.observed_at IS NULL OR c.observed_at<w.witnessed OR c.observed_at<0 OR c.observed_at>253402300799)", [], |row| row.get(0))?;
    if missing_floor {
        return Err(invalid("target bootstrap observation floor"));
    }
    let mut statement = tx.prepare("SELECT org_id,project_id,kind,resource_id,recorded_at FROM authority_audit WHERE kind IN ('target_bootstrap_key_pinned','target_bootstrap_key_revoked','target_bootstrap_challenge_issued','target_bootstrap_confirmed')")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let saved = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        );
        if !events.remove(&saved) {
            return Err(invalid("target bootstrap audit without history"));
        }
    }
    if !events.is_empty() {
        return Err(invalid("target bootstrap audit missing"));
    }
    Ok(())
}
