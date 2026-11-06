//! Explicit protected project approval-origin trust. An origin observed in an
//! old challenge or supplied by a caller is never an independently pinned root.
use super::*;
use serde::Deserialize;

const PIN_SCHEMA: &str = "fw.bootstrap-approval-origin-pin/v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapApprovalOriginPin {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub revision: String,
    pub origin: String,
    pub rp_id: String,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BootstrapApprovalOriginStatus {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub revision: String,
    pub origin: String,
    pub rp_id: String,
    pub pin_hash: String,
    pub pinned_at: String,
    pub not_before: String,
    pub not_after: String,
    pub checked_at: String,
    pub current: bool,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
}

pub(super) struct OriginRecord {
    pub pin: BootstrapApprovalOriginPin,
    pub revision: u64,
    pub not_before: i64,
    pub not_after: i64,
    pub pinned_at: i64,
    hash: String,
    canonical: Vec<u8>,
}

fn validate_pin(
    tenant: &AuthorityTenant,
    pin: &BootstrapApprovalOriginPin,
) -> Result<(u64, i64, i64)> {
    if pin.schema_version != PIN_SCHEMA
        || pin.org_id != tenant.org_id
        || pin.project_id != tenant.project_id
        || pin.origin.is_empty()
        || pin.origin.len() > 2048
        || pin.rp_id.is_empty()
        || pin.rp_id.len() > 253
    {
        return Err(invalid("bootstrap approval origin pin"));
    }
    let revision = crate::counter(&pin.revision)?;
    if revision == 0 {
        return Err(invalid("bootstrap approval origin revision"));
    }
    let verifier = WebAuthn::new(&pin.origin).map_err(|_| invalid("bootstrap approval origin"))?;
    if verifier.origin() != pin.origin || verifier.rp_id() != pin.rp_id {
        return Err(AuthorityError::Binding);
    }
    let start = crate::timestamp(&pin.not_before)?;
    let end = crate::timestamp(&pin.not_after)?;
    time(start)?;
    time(end)?;
    if end <= start {
        return Err(AuthorityError::Time);
    }
    if bytes(pin)?.len() > 8192 {
        return Err(invalid("bootstrap approval origin pin size"));
    }
    Ok((revision, start, end))
}

pub(super) fn record_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    revision: u64,
) -> Result<OriginRecord> {
    type OriginRow = (String, String, i64, i64, i64, Vec<u8>, Vec<u8>);
    let row: OriginRow = tx.query_row(
        "SELECT origin,rp_id,not_before,not_after,pinned_at,CASE WHEN length(pin_hash)=32 THEN pin_hash END,CASE WHEN length(canonical_bytes) BETWEEN 1 AND 8192 THEN canonical_bytes END FROM authority_bootstrap_approval_origin_pins WHERE org_id=? AND project_id=? AND revision=?",
        params![tenant.org_id, tenant.project_id, revision.to_be_bytes().as_slice()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
    ).optional()?.ok_or(AuthorityError::Binding)?;
    let pin: BootstrapApprovalOriginPin = decode(&row.6)?;
    let (number, start, end) = validate_pin(tenant, &pin)?;
    if number != revision
        || pin.origin != row.0
        || pin.rp_id != row.1
        || start != row.2
        || end != row.3
        || row.4 < start
        || row.4 >= end
        || hash(&hash_bytes(&row.6))? != row.5
    {
        return Err(invalid("bootstrap approval origin projection"));
    }
    Ok(OriginRecord {
        pin,
        revision,
        not_before: start,
        not_after: end,
        pinned_at: row.4,
        hash: hash_string(&row.5)?,
        canonical: row.6,
    })
}

fn head(tx: &Transaction<'_>, tenant: &AuthorityTenant) -> Result<Option<u64>> {
    let revision: Option<Vec<u8>> = tx.query_row(
        "SELECT CASE WHEN length(revision)=8 THEN revision END FROM authority_bootstrap_approval_origin_heads WHERE org_id=? AND project_id=?",
        params![tenant.org_id,tenant.project_id], |row|row.get(0),
    ).optional()?;
    revision
        .map(|bytes| {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| invalid("bootstrap approval origin head"))?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()
}

pub(super) fn current_origin(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    now: i64,
) -> Result<OriginRecord> {
    authority_registry::require_registry_time(tx, tenant, now)?;
    let record = record_at(
        tx,
        tenant,
        head(tx, tenant)?.ok_or(AuthorityError::Binding)?,
    )?;
    if now < record.not_before || now < record.pinned_at || now >= record.not_after {
        return Err(AuthorityError::Time);
    }
    Ok(record)
}

pub(super) fn require_verifier(record: &OriginRecord, verifier: &WebAuthn) -> Result<()> {
    if verifier.origin() != record.pin.origin || verifier.rp_id() != record.pin.rp_id {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}

pub(super) fn current_verifier(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    now: i64,
) -> Result<WebAuthn> {
    let record = current_origin(tx, tenant, now)?;
    WebAuthn::new(&record.pin.origin).map_err(|_| invalid("bootstrap approval origin"))
}

pub(super) fn bind_challenge(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    challenge: &ApprovalChallenge,
    record: &OriginRecord,
) -> Result<()> {
    if challenge.origin() != record.pin.origin
        || challenge.rp_id() != record.pin.rp_id
        || challenge.issued_at() < record.pinned_at
        || challenge.issued_at() < record.not_before
        || challenge.issued_at() >= record.not_after
    {
        return Err(AuthorityError::Binding);
    }
    tx.execute(
        "INSERT INTO authority_bootstrap_challenge_origin_bindings VALUES(?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            challenge.challenge_id(),
            record.revision.to_be_bytes().as_slice()
        ],
    )?;
    Ok(())
}

pub(super) fn require_challenge_origin(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    challenge: &ApprovalChallenge,
    verifier: &WebAuthn,
    now: i64,
) -> Result<OriginRecord> {
    let record = current_origin(tx, tenant, now)?;
    require_verifier(&record, verifier)?;
    let revision: Option<Vec<u8>> = tx.query_row(
        "SELECT origin_revision FROM authority_bootstrap_challenge_origin_bindings WHERE org_id=? AND project_id=? AND challenge_id=?",
        params![tenant.org_id,tenant.project_id,challenge.challenge_id()], |row|row.get(0),
    ).optional()?.ok_or(AuthorityError::Binding)?;
    if revision.as_deref() != Some(record.revision.to_be_bytes().as_slice())
        || challenge.origin() != record.pin.origin
        || challenge.rp_id() != record.pin.rp_id
        || challenge.issued_at() < record.pinned_at
        || challenge.issued_at() < record.not_before
        || challenge.issued_at() >= record.not_after
    {
        return Err(AuthorityError::Binding);
    }
    Ok(record)
}

fn status(record: &OriginRecord, now: i64, is_head: bool) -> Result<BootstrapApprovalOriginStatus> {
    Ok(BootstrapApprovalOriginStatus {
        schema_version: "fw.bootstrap-approval-origin-status/v1".into(),
        org_id: record.pin.org_id.clone(),
        project_id: record.pin.project_id.clone(),
        revision: record.pin.revision.clone(),
        origin: record.pin.origin.clone(),
        rp_id: record.pin.rp_id.clone(),
        pin_hash: record.hash.clone(),
        pinned_at: at(record.pinned_at)?,
        not_before: record.pin.not_before.clone(),
        not_after: record.pin.not_after.clone(),
        checked_at: at(now)?,
        current: is_head
            && now >= record.pinned_at
            && now >= record.not_before
            && now < record.not_after,
        signing_allowed: false,
        dispatch_allowed: false,
    })
}

impl AuthorityStore {
    /// Explicit protected-local/OOB provisioning only. Neither a supplied
    /// verifier nor retained WebAuthn history establishes this project pin.
    pub fn pin_bootstrap_approval_origin(
        &mut self,
        tenant: &AuthorityTenant,
        pin: &BootstrapApprovalOriginPin,
        expected_revision: Option<u64>,
        now: i64,
    ) -> Result<BootstrapApprovalOriginStatus> {
        let (revision, start, end) = validate_pin(tenant, pin)?;
        let canonical = bytes(pin)?;
        self.observe_registry_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authority_registry::require_registry_time(&tx, tenant, now)?;
        let previous = head(&tx, tenant)?;
        if let Some(current) = previous {
            let retained = record_at(&tx, tenant, current)?;
            if current == revision
                && retained.canonical == canonical
                && (expected_revision == Some(current)
                    || current.checked_sub(1).filter(|value| *value > 0) == expected_revision
                    || (current == 1 && expected_revision.is_none()))
            {
                let result = status(&retained, now, true)?;
                tx.commit()?;
                return Ok(result);
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
        if now < start || now >= end {
            return Err(AuthorityError::Time);
        }
        tx.execute(
            "INSERT INTO authority_bootstrap_approval_origin_pins VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                revision.to_be_bytes().as_slice(),
                pin.origin,
                pin.rp_id,
                start,
                end,
                now,
                hash(&hash_bytes(&canonical))?,
                canonical
            ],
        )?;
        retained_projection(
            &tx,
            "UPDATE authority_bootstrap_approval_origin_heads SET revision=?3 WHERE org_id=?1 AND project_id=?2",
            "INSERT INTO authority_bootstrap_approval_origin_heads VALUES(?1,?2,?3)",
            params![
                tenant.org_id,
                tenant.project_id,
                revision.to_be_bytes().as_slice()
            ],
        )?;
        bump_security(&tx, tenant)?;
        audit(
            &tx,
            tenant,
            "bootstrap_approval_origin_pinned",
            &pin.revision,
            now,
        )?;
        let result = status(&record_at(&tx, tenant, revision)?, now, true)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn read_bootstrap_approval_origin(
        &mut self,
        tenant: &AuthorityTenant,
        now: i64,
    ) -> Result<Option<BootstrapApprovalOriginStatus>> {
        self.observe_registry_time(tenant, now)?;
        let tx = self.connection.transaction()?;
        authority_registry::require_registry_time(&tx, tenant, now)?;
        let result = head(&tx, tenant)?
            .map(|revision| status(&record_at(&tx, tenant, revision)?, now, true))
            .transpose()?;
        tx.commit()?;
        Ok(result)
    }
}

pub(super) fn validate_retained(tx: &Transaction<'_>) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut expected = BTreeMap::new();
    let mut expected_audits = BTreeSet::new();
    let mut statement = tx.prepare("SELECT org_id,project_id,revision FROM authority_bootstrap_approval_origin_pins ORDER BY org_id,project_id,revision")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let raw: Vec<u8> = row.get(2)?;
        let revision = u64::from_be_bytes(
            raw.as_slice()
                .try_into()
                .map_err(|_| invalid("bootstrap approval origin revision"))?,
        );
        let record = record_at(tx, &tenant, revision)?;
        let identity = (tenant.org_id.clone(), tenant.project_id.clone());
        let previous = expected.insert(identity, (revision, record.pinned_at));
        if previous
            .map(|(number, at)| number.checked_add(1) != Some(revision) || at > record.pinned_at)
            .unwrap_or(revision != 1)
        {
            return Err(invalid("bootstrap approval origin history"));
        }
        let observed: Option<i64> = tx
            .query_row(
                "SELECT observed_at FROM authority_registry_clocks WHERE org_id=? AND project_id=?",
                params![tenant.org_id, tenant.project_id],
                |row| row.get(0),
            )
            .optional()?;
        if observed.is_none_or(|at| !(0..=MAX_TIME).contains(&at) || at < record.pinned_at) {
            return Err(invalid("bootstrap approval origin observation floor"));
        }
        expected_audits.insert((
            tenant.org_id,
            tenant.project_id,
            revision.to_string(),
            record.pinned_at,
        ));
    }
    let mut statement = tx.prepare(
        "SELECT org_id,project_id,revision FROM authority_bootstrap_approval_origin_heads",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let identity = (row.get::<_, String>(0)?, row.get::<_, String>(1)?);
        let (revision, _) = expected
            .remove(&identity)
            .ok_or(invalid("bootstrap approval origin head without history"))?;
        if row.get::<_, Vec<u8>>(2)? != revision.to_be_bytes() {
            return Err(invalid("bootstrap approval origin head is not latest"));
        }
    }
    if !expected.is_empty() {
        return Err(invalid("bootstrap approval origin head missing"));
    }
    let mut statement=tx.prepare("SELECT org_id,project_id,resource_id,recorded_at FROM authority_audit WHERE kind='bootstrap_approval_origin_pinned'")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if !expected_audits.remove(&(row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)) {
            return Err(invalid("bootstrap approval origin audit without history"));
        }
    }
    if !expected_audits.is_empty() {
        return Err(invalid("bootstrap approval origin audit missing"));
    }
    let incomplete:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_bootstrap_challenges c WHERE NOT EXISTS(SELECT 1 FROM authority_bootstrap_challenge_origin_bindings b WHERE b.org_id=c.org_id AND b.project_id=c.project_id AND b.challenge_id=c.challenge_id))",[],|row|row.get(0))?;
    if incomplete {
        return Err(invalid("bootstrap challenge origin classification missing"));
    }
    let mut statement=tx.prepare("SELECT org_id,project_id,challenge_id,origin_revision FROM authority_bootstrap_challenge_origin_bindings")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let tenant = AuthorityTenant::new(&row.get::<_, String>(0)?, &row.get::<_, String>(1)?)?;
        let challenge_id: String = row.get(2)?;
        let revision: Option<Vec<u8>> = row.get(3)?;
        if let Some(raw) = revision {
            let number = u64::from_be_bytes(
                raw.as_slice()
                    .try_into()
                    .map_err(|_| invalid("bootstrap challenge origin revision"))?,
            );
            let record = record_at(tx, &tenant, number)?;
            let canonical:Vec<u8>=tx.query_row("SELECT challenge_bytes FROM authority_bootstrap_challenges WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,challenge_id],|row|row.get(0))?;
            let challenge: ApprovalChallenge = decode(&canonical)?;
            if challenge.origin() != record.pin.origin
                || challenge.rp_id() != record.pin.rp_id
                || challenge.issued_at() < record.pinned_at
                || challenge.issued_at() < record.not_before
                || challenge.issued_at() >= record.not_after
            {
                return Err(invalid("bootstrap challenge origin binding"));
            }
            let overlong:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_bootstrap_proofs WHERE org_id=? AND project_id=? AND challenge_id=? AND expires_at>?)",params![tenant.org_id,tenant.project_id,challenge_id,record.not_after],|row|row.get(0))?;
            if overlong {
                return Err(invalid("bootstrap owner proof exceeds origin pin"));
            }
        }
    }
    Ok(())
}
