//! Independently provisioned development evidence. Signatures authenticate a
//! lab producer's claims; they do not establish protected kernel collection.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fw_backend_linux::{Comparison, Installation, LabReferences};
use fw_native_evidence::{
    ArtifactRole, NativeObservationChallenge, SignedNativeObservation, VerifiedCompilation,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeReferencePin {
    pub target_id: String,
    pub references: LabReferences,
    pub not_before: i64,
    pub not_after: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeObserverPin {
    pub target_id: String,
    pub public_key: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCompilationReceipt {
    pub schema_version: String,
    pub compilation_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub sequence: String,
    pub evidence_hash: String,
    pub reference_revision: String,
    pub references_hash: String,
    pub metadata_receipt_id: String,
    pub metadata_receipt_hash: String,
    pub metadata_report_hash: String,
    pub baseline_artifact_hash: String,
    pub candidate_artifact_hash: String,
    pub admitted_at: String,
    pub valid_until: String,
    pub production_qualified: bool,
    pub dispatch_allowed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeObservationReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub plan_id: String,
    pub challenge_id: String,
    pub compilation_id: String,
    pub sequence: String,
    pub compilation_hash: String,
    pub observer_revision: String,
    pub observer_key_fingerprint: String,
    pub proof_hash: String,
    pub payload_hash: String,
    pub readback_hash: String,
    pub authority_epoch: String,
    pub generation: String,
    pub artifact_role: ArtifactRole,
    pub comparison: String,
    pub observed_state_hash: Option<String>,
    pub signature_valid: bool,
    pub provenance: String,
    pub checked_at: String,
    pub admitted_at: String,
    pub valid_until: String,
    pub production_qualified: bool,
    pub dispatch_allowed: bool,
}
#[derive(Debug, Serialize)]
pub struct NativeObservationAdmission {
    pub receipt: NativeObservationReceipt,
    pub receipt_hash: String,
    pub replayed: bool,
}
#[derive(Debug, Serialize)]
pub struct NativeCompilationStatus {
    pub evidence_hash: String,
    pub reference_revision: String,
    pub metadata_receipt_hash: String,
    pub baseline_artifact_hash: String,
    pub candidate_artifact_hash: String,
    pub admitted_at: String,
    pub valid_until: String,
    pub current: bool,
}
#[derive(Debug, Serialize)]
pub struct NativeObservationStatus {
    pub receipt_hash: String,
    pub compilation_hash: String,
    pub observer_revision: String,
    pub artifact_role: ArtifactRole,
    pub comparison: String,
    pub observed_state_hash: Option<String>,
    pub signature_valid: bool,
    pub provenance: String,
    pub checked_at: String,
    pub admitted_at: String,
    pub valid_until: String,
    pub current: bool,
}
#[derive(Debug, Serialize)]
pub struct NativeEvidenceStatus {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub checked_at: String,
    pub production_qualified: bool,
    pub dispatch_allowed: bool,
    pub reasons: Vec<String>,
    pub compilation: Option<NativeCompilationStatus>,
    pub observation: Option<NativeObservationStatus>,
    pub observation_head_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    schema_version: String,
    org_id: String,
    project_id: String,
    target_id: String,
    kind: String,
    revision: String,
    pinned_at: String,
    not_before: i64,
    not_after: i64,
    pin: Value,
}
struct Pin {
    record: PinRecord,
    version: u64,
}
struct Compilation {
    receipt: NativeCompilationReceipt,
    verified: VerifiedCompilation,
}
struct Observation {
    receipt: NativeObservationReceipt,
    receipt_hash: String,
    proof: Vec<u8>,
}

fn evidence_error(_: fw_native_evidence::EvidenceError) -> AuthorityError {
    invalid("native development evidence")
}
fn number(text: &str) -> Result<u64> {
    let n = text.parse::<u64>().map_err(|_| invalid("native counter"))?;
    if n.to_string() != text {
        return Err(invalid("native counter"));
    }
    Ok(n)
}
fn revision(raw: &[u8]) -> Result<u64> {
    let n = u64::from_be_bytes(raw.try_into().map_err(|_| invalid("native revision"))?);
    if n == 0 {
        return Err(invalid("native revision"));
    }
    Ok(n)
}
fn moment(value: &str) -> Result<i64> {
    fw_target_evidence::parse_time(value).map_err(|_| invalid("native timestamp"))
}
fn receipt_hash<T: Serialize>(value: &T) -> Result<String> {
    canonical_hash(value).map_err(|_| invalid("native receipt hash"))
}
fn bound_decode<T: DeserializeOwned + Serialize>(value: &[u8], limit: usize) -> Result<T> {
    let parsed: T =
        parse_strict_with_limit(value, limit).map_err(|_| invalid("native retained bytes"))?;
    if canonical_bytes(&parsed).map_err(|_| invalid("native canonical bytes"))? != value {
        return Err(invalid("native canonical bytes"));
    }
    Ok(parsed)
}

fn pin_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    kind: &str,
    version: u64,
) -> Result<Pin> {
    let row:(Vec<u8>,i64,i64,i64,Vec<u8>)=tx.query_row("SELECT content_hash,pinned_at,not_before,not_after,CASE WHEN length(canonical_bytes)<=262144 THEN canonical_bytes END FROM authority_native_pins WHERE org_id=? AND project_id=? AND target_id=? AND kind=? AND revision=?",params![tenant.org_id,tenant.project_id,target,kind,version.to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let record: PinRecord = decode(&row.4)?;
    if record.schema_version != "fw.authority-lab-native-pin/v1"
        || record.org_id != tenant.org_id
        || record.project_id != tenant.project_id
        || record.target_id != target
        || record.kind != kind
        || record.revision != version.to_string()
        || record.pinned_at != at(row.1)?
        || record.not_before != row.2
        || record.not_after != row.3
        || row.0 != hash(&receipt_hash(&record.pin)?)?
    {
        return Err(invalid("native pin projection"));
    }
    validate_pin(tenant, &record, row.1)?;
    if kind == "observer" {
        let pin: NativeObserverPin =
            serde_json::from_value(record.pin.clone()).map_err(|_| invalid("observer pin"))?;
        let fingerprint = fw_native_evidence::fingerprint(&pin.public_key)
            .map_err(|_| invalid("observer key"))?;
        let owner:(String,String,Vec<u8>,i64)=tx.query_row("SELECT project_id,target_id,public_key,registered_at FROM authority_native_observer_keys WHERE org_id=? AND key_fingerprint=?",params![tenant.org_id,hash(&fingerprint)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?.ok_or(AuthorityError::Binding)?;
        if owner.0 != tenant.project_id
            || owner.1 != target
            || owner.2 != pin.public_key
            || owner.3 < 0
            || owner.3 > row.1
        {
            return Err(invalid("observer key ownership"));
        }
    }
    Ok(Pin { record, version })
}
fn pin_head(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
    kind: &str,
) -> Result<Option<Pin>> {
    let head:Option<Vec<u8>>=tx.query_row("SELECT revision FROM authority_native_pin_heads WHERE org_id=? AND project_id=? AND target_id=? AND kind=?",params![tenant.org_id,tenant.project_id,target,kind],|r|r.get(0)).optional()?;
    let latest:Option<Vec<u8>>=tx.query_row("SELECT revision FROM authority_native_pins WHERE org_id=? AND project_id=? AND target_id=? AND kind=? ORDER BY revision DESC LIMIT 1",params![tenant.org_id,tenant.project_id,target,kind],|r|r.get(0)).optional()?;
    if head != latest {
        return Err(invalid("native pin head"));
    }
    head.map(|r| pin_at(tx, tenant, target, kind, revision(&r)?))
        .transpose()
}
fn validate_pin(tenant: &AuthorityTenant, record: &PinRecord, now: i64) -> Result<()> {
    identifier(&record.target_id)?;
    interval(record.not_before, record.not_after, now)?;
    if now < record.not_before {
        return Err(AuthorityError::Time);
    }
    match record.kind.as_str() {
        "references" => {
            let p: NativeReferencePin = serde_json::from_value(record.pin.clone())
                .map_err(|_| invalid("native reference pin"))?;
            if p.target_id != record.target_id
                || p.not_before != record.not_before
                || p.not_after != record.not_after
                || p.references.scope.org_id != tenant.org_id
                || p.references.scope.project_id != tenant.project_id
                || p.references.scope.target_id != record.target_id
            {
                return Err(AuthorityError::Binding);
            }
            // Complete semantics are revalidated against both immutable states
            // during compilation. Provisioning cannot itself claim qualification.
            if p.references.capability.production_qualified {
                return Err(AuthorityError::Binding);
            }
        }
        "observer" => {
            let p: NativeObserverPin = serde_json::from_value(record.pin.clone())
                .map_err(|_| invalid("native observer pin"))?;
            if p.target_id != record.target_id
                || p.not_before != record.not_before
                || p.not_after != record.not_after
            {
                return Err(AuthorityError::Binding);
            }
            fw_native_evidence::fingerprint(&p.public_key).map_err(|_| invalid("observer key"))?;
        }
        _ => return Err(AuthorityError::Binding),
    }
    Ok(())
}
fn pin_current(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    pin: &Pin,
    now: i64,
) -> Result<bool> {
    if now < moment(&pin.record.pinned_at)? || now < pin.record.not_before {
        return Err(AuthorityError::Time);
    }
    let revoked:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_native_pin_revocations WHERE org_id=? AND project_id=? AND target_id=? AND kind=? AND revision=?)",params![tenant.org_id,tenant.project_id,pin.record.target_id,pin.record.kind,pin.version.to_be_bytes().as_slice()],|r|r.get(0))?;
    let mut current = now < pin.record.not_after && !revoked;
    if pin.record.kind == "observer" {
        let p: NativeObserverPin =
            serde_json::from_value(pin.record.pin.clone()).map_err(|_| invalid("observer pin"))?;
        let fp = hash(
            &fw_native_evidence::fingerprint(&p.public_key).map_err(|_| invalid("observer key"))?,
        )?;
        let conflict:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_native_observer_revocations WHERE org_id=? AND key_fingerprint=?) OR EXISTS(SELECT 1 FROM authority_target_keys WHERE org_id=? AND key_fingerprint=?)",params![tenant.org_id,fp,tenant.org_id,fp],|r|r.get(0))?;
        current &= !conflict;
    }
    Ok(current)
}

impl AuthorityStore {
    pub fn pin_native_references(
        &mut self,
        tenant: &AuthorityTenant,
        pin: &NativeReferencePin,
        expected_revision: Option<u64>,
        now: i64,
    ) -> Result<u64> {
        self.pin_native(
            tenant,
            &pin.target_id,
            "references",
            serde_json::to_value(pin).map_err(|_| invalid("reference pin"))?,
            pin.not_before,
            pin.not_after,
            expected_revision,
            now,
        )
    }
    pub fn pin_native_observer(
        &mut self,
        tenant: &AuthorityTenant,
        pin: &NativeObserverPin,
        expected_revision: Option<u64>,
        now: i64,
    ) -> Result<u64> {
        self.pin_native(
            tenant,
            &pin.target_id,
            "observer",
            serde_json::to_value(pin).map_err(|_| invalid("observer pin"))?,
            pin.not_before,
            pin.not_after,
            expected_revision,
            now,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn pin_native(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        kind: &str,
        pin: Value,
        not_before: i64,
        not_after: i64,
        expected: Option<u64>,
        now: i64,
    ) -> Result<u64> {
        if !self.observe_target_time(tenant, target, now)? {
            return Err(AuthorityError::Binding);
        }
        let mut record = PinRecord {
            schema_version: "fw.authority-lab-native-pin/v1".into(),
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            target_id: target.into(),
            kind: kind.into(),
            revision: "1".into(),
            pinned_at: at(now)?,
            not_before,
            not_after,
            pin,
        };
        validate_pin(tenant, &record, now)?;
        let _ = bytes(&record)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        target_metadata::clock(&tx, tenant, target, now)?;
        let current = pin_head(&tx, tenant, target, kind)?;
        if let Some(old) = &current
            && old.record.pin == record.pin
            && pin_current(&tx, tenant, old, now)?
            && (expected == Some(old.version)
                || expected == old.version.checked_sub(1).filter(|v| *v > 0)
                || expected.is_none() && old.version == 1)
        {
            tx.commit()?;
            return Ok(old.version);
        }
        if expected != current.as_ref().map(|p| p.version) {
            return Err(AuthorityError::Conflict);
        }
        let version = current
            .as_ref()
            .map_or(Some(1), |p| p.version.checked_add(1))
            .ok_or(invalid("native pin revision exhausted"))?;
        record.revision = version.to_string();
        if kind == "observer" {
            let p: NativeObserverPin =
                serde_json::from_value(record.pin.clone()).map_err(|_| invalid("observer pin"))?;
            let fingerprint = fw_native_evidence::fingerprint(&p.public_key)
                .map_err(|_| invalid("observer key"))?;
            let fp = hash(&fingerprint)?;
            let forbidden:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_native_observer_revocations WHERE org_id=? AND key_fingerprint=?) OR EXISTS(SELECT 1 FROM authority_target_keys WHERE org_id=? AND key_fingerprint=?)",params![tenant.org_id,fp,tenant.org_id,fp],|r|r.get(0))?;
            if forbidden {
                return Err(AuthorityError::Binding);
            }
            let owner:Option<(String,String,Vec<u8>)>=tx.query_row("SELECT project_id,target_id,public_key FROM authority_native_observer_keys WHERE org_id=? AND key_fingerprint=?",params![tenant.org_id,fp],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some(owner) = owner {
                if owner.0 != tenant.project_id || owner.1 != target || owner.2 != p.public_key {
                    return Err(AuthorityError::Conflict);
                }
            } else {
                tx.execute(
                    "INSERT INTO authority_native_observer_keys VALUES(?,?,?,?,?,?)",
                    params![
                        tenant.org_id,
                        fp,
                        tenant.project_id,
                        target,
                        p.public_key.as_slice(),
                        now
                    ],
                )?;
            }
            if let Some(old) = &current {
                let previous: NativeObserverPin = serde_json::from_value(old.record.pin.clone())
                    .map_err(|_| invalid("observer pin"))?;
                if previous.public_key != p.public_key {
                    let old_fp = fw_native_evidence::fingerprint(&previous.public_key)
                        .map_err(|_| invalid("observer key"))?;
                    tx.execute(
                        "INSERT OR IGNORE INTO authority_native_observer_revocations VALUES(?,?,?)",
                        params![tenant.org_id, hash(&old_fp)?, now],
                    )?;
                }
            }
        }
        tx.execute(
            "INSERT INTO authority_native_pins VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                target,
                kind,
                version.to_be_bytes().as_slice(),
                hash(&receipt_hash(&record.pin)?)?,
                now,
                not_before,
                not_after,
                bytes(&record)?
            ],
        )?;
        tx.execute("INSERT INTO authority_native_pin_heads VALUES(?,?,?,?,?) ON CONFLICT(org_id,project_id,target_id,kind) DO UPDATE SET revision=excluded.revision",params![tenant.org_id,tenant.project_id,target,kind,version.to_be_bytes().as_slice()])?;
        bump_security(&tx, tenant)?;
        audit(
            &tx,
            tenant,
            if kind == "observer" {
                "native_observer_pinned"
            } else {
                "native_references_pinned"
            },
            target,
            now,
        )?;
        tx.commit()?;
        Ok(version)
    }
    pub fn revoke_native_references(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        expected_revision: u64,
        now: i64,
    ) -> Result<()> {
        self.revoke_native(tenant, target, "references", expected_revision, now)
    }
    pub fn revoke_native_observer(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        expected_revision: u64,
        now: i64,
    ) -> Result<()> {
        self.revoke_native(tenant, target, "observer", expected_revision, now)
    }
    fn revoke_native(
        &mut self,
        tenant: &AuthorityTenant,
        target: &str,
        kind: &str,
        expected: u64,
        now: i64,
    ) -> Result<()> {
        if !self.observe_target_time(tenant, target, now)? {
            return Err(AuthorityError::Binding);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        target_metadata::clock(&tx, tenant, target, now)?;
        let pin = pin_head(&tx, tenant, target, kind)?.ok_or(AuthorityError::Binding)?;
        if pin.version != expected {
            return Err(AuthorityError::Conflict);
        }
        if now < moment(&pin.record.pinned_at)? {
            return Err(AuthorityError::Time);
        }
        let changed = tx.execute(
            "INSERT OR IGNORE INTO authority_native_pin_revocations VALUES(?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                target,
                kind,
                expected.to_be_bytes().as_slice(),
                now
            ],
        )?;
        if changed > 0 {
            if kind == "observer" {
                let p: NativeObserverPin =
                    serde_json::from_value(pin.record.pin).map_err(|_| invalid("observer pin"))?;
                tx.execute(
                    "INSERT OR IGNORE INTO authority_native_observer_revocations VALUES(?,?,?)",
                    params![
                        tenant.org_id,
                        hash(
                            &fw_native_evidence::fingerprint(&p.public_key)
                                .map_err(|_| invalid("observer key"))?
                        )?,
                        now
                    ],
                )?;
            }
            bump_security(&tx, tenant)?;
            audit(
                &tx,
                tenant,
                if kind == "observer" {
                    "native_observer_revoked"
                } else {
                    "native_references_revoked"
                },
                target,
                now,
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn recompile(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan_id: &str,
    pin: &Pin,
    at: i64,
) -> Result<VerifiedCompilation> {
    let retained = records::retained_plan(tx, tenant, plan_id)?;
    if at < retained.registered_at
        || at < retained.subject.created_at
        || at >= retained.subject.valid_until
    {
        return Err(AuthorityError::Time);
    }
    let review = review_evidence::review_in_tx(tx, tenant, &retained.subject, at)?
        .ok_or(AuthorityError::Binding)?;
    let references: NativeReferencePin = serde_json::from_value(pin.record.pin.clone())
        .map_err(|_| invalid("native reference pin"))?;
    let plan: Value = decode(&retained.subject.plan_bytes)?;
    fw_native_evidence::compile_evidence(&plan, review.evidence(), &references.references)
        .map_err(evidence_error)
}
fn compilation_at(tx: &Transaction<'_>, tenant: &AuthorityTenant, id: &str) -> Result<Compilation> {
    type Row = (
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
    );
    let r:Row=tx.query_row("SELECT target_id,plan_id,sequence,reference_revision,metadata_receipt_id,evidence_hash,admitted_at,valid_until,CASE WHEN length(evidence_bytes)<=1048576 THEN evidence_bytes END,CASE WHEN length(receipt_bytes)<=16384 THEN receipt_bytes END FROM authority_native_compilations WHERE org_id=? AND project_id=? AND compilation_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let receipt: NativeCompilationReceipt = decode(&r.9)?;
    let pin = pin_at(tx, tenant, &r.0, "references", revision(&r.3)?)?;
    let metadata = target_metadata::retained_metadata_in_tx(tx, tenant, &r.4)?;
    if metadata.report["platform"] != "linux"
        || metadata.report["enforcement_backend"] != "nftables"
    {
        return Err(AuthorityError::Binding);
    }
    let metadata = metadata.receipt;
    let retained = records::retained_plan(tx, tenant, &r.1)?;
    let deadline = pin
        .record
        .not_after
        .min(moment(&metadata.valid_until)?)
        .min(retained.subject.valid_until);
    if r.6 < moment(&pin.record.pinned_at)?
        || r.6 < pin.record.not_before
        || r.6 < moment(&metadata.admitted_at)?
        || r.6 >= deadline
        || metadata.target_id != r.0
    {
        return Err(AuthorityError::Binding);
    }
    let verified = recompile(tx, tenant, &r.1, &pin, r.6)?;
    let expected = NativeCompilationReceipt {
        schema_version: "fw.authority-lab-compilation-receipt/v1".into(),
        compilation_id: id.into(),
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        target_id: r.0,
        plan_id: r.1,
        plan_hash: verified.plan_hash().into(),
        sequence: revision(&r.2)?.to_string(),
        evidence_hash: verified.evidence_hash().into(),
        reference_revision: pin.version.to_string(),
        references_hash: verified.references_hash().into(),
        metadata_receipt_id: metadata.receipt_id.clone(),
        metadata_receipt_hash: receipt_hash(&metadata)?,
        metadata_report_hash: metadata.report_hash,
        baseline_artifact_hash: verified
            .baseline()
            .artifact_hash()
            .map_err(|_| invalid("native artifact"))?,
        candidate_artifact_hash: verified
            .candidate()
            .artifact_hash()
            .map_err(|_| invalid("native artifact"))?,
        admitted_at: at(r.6)?,
        valid_until: at(deadline)?,
        production_qualified: false,
        dispatch_allowed: false,
    };
    if receipt != expected
        || r.5 != hash(verified.evidence_hash())?
        || r.7 != deadline
        || r.8 != verified.canonical_bytes()
    {
        return Err(invalid("native compilation projection"));
    }
    Ok(Compilation { receipt, verified })
}
fn compilation_head(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan: &str,
) -> Result<Option<Compilation>> {
    let head:Option<String>=tx.query_row("SELECT compilation_id FROM authority_native_compilation_heads WHERE org_id=? AND project_id=? AND plan_id=?",params![tenant.org_id,tenant.project_id,plan],|r|r.get(0)).optional()?;
    let latest:Option<String>=tx.query_row("SELECT compilation_id FROM authority_native_compilations WHERE org_id=? AND project_id=? AND plan_id=? ORDER BY sequence DESC LIMIT 1",params![tenant.org_id,tenant.project_id,plan],|r|r.get(0)).optional()?;
    if head != latest {
        return Err(invalid("native compilation head"));
    }
    head.map(|id| compilation_at(tx, tenant, &id)).transpose()
}
fn compilation_current(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    c: &Compilation,
    now: i64,
) -> Result<bool> {
    if now < moment(&c.receipt.admitted_at)? {
        return Err(AuthorityError::Time);
    }
    let retained = records::retained_plan(tx, tenant, &c.receipt.plan_id)?;
    let pin =
        pin_head(tx, tenant, &c.receipt.target_id, "references")?.ok_or(AuthorityError::Binding)?;
    let metadata = target_metadata::current_metadata_in_tx(tx, tenant, &c.receipt.target_id, now)?;
    Ok(!retained.retired
        && now < retained.subject.valid_until
        && now < moment(&c.receipt.valid_until)?
        && pin.version.to_string() == c.receipt.reference_revision
        && pin_current(tx, tenant, &pin, now)?
        && metadata.is_some_and(|m| {
            m.receipt.receipt_id == c.receipt.metadata_receipt_id
                && receipt_hash(&m.receipt).is_ok_and(|h| h == c.receipt.metadata_receipt_hash)
        }))
}

impl AuthorityStore {
    /// Independently recompile from retained reviewed states, then recheck exact
    /// current trust inside the committing transaction. This creates no grant.
    pub fn register_native_compilation(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        expected_reference_revision: u64,
        now: i64,
    ) -> Result<NativeCompilationReceipt> {
        identifier(plan_id)?;
        time(now)?;
        self.observe_native_plan_time(tenant, plan_id, now)?;
        let (target, reference, metadata, plan, review) = {
            let tx = self.connection.transaction()?;
            let subject = records::plan(&tx, tenant, plan_id, now)?;
            let plan: Value = decode(&subject.plan_bytes)?;
            let target = plan["target_id"]
                .as_str()
                .ok_or(AuthorityError::Binding)?
                .to_owned();
            let reference =
                pin_head(&tx, tenant, &target, "references")?.ok_or(AuthorityError::Binding)?;
            if reference.version != expected_reference_revision
                || !pin_current(&tx, tenant, &reference, now)?
            {
                return Err(AuthorityError::Conflict);
            }
            let metadata = target_metadata::current_metadata_in_tx(&tx, tenant, &target, now)?
                .ok_or(AuthorityError::Binding)?;
            if metadata.report["platform"] != "linux"
                || metadata.report["enforcement_backend"] != "nftables"
            {
                return Err(AuthorityError::Binding);
            }
            let review = review_evidence::review_in_tx(&tx, tenant, &subject, now)?
                .ok_or(AuthorityError::Binding)?;
            tx.commit()?;
            (target, reference, metadata.receipt, plan, review)
        };
        // Observe expiry even if later computation or admission fails.
        self.observe_target_time(tenant, &target, now)?;
        let refs: NativeReferencePin = serde_json::from_value(reference.record.pin.clone())
            .map_err(|_| invalid("reference pin"))?;
        let compiled =
            fw_native_evidence::compile_evidence(&plan, review.evidence(), &refs.references)
                .map_err(evidence_error)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        target_metadata::clock(&tx, tenant, &target, now)?;
        let subject = records::plan(&tx, tenant, plan_id, now)?;
        let live_pin =
            pin_head(&tx, tenant, &target, "references")?.ok_or(AuthorityError::Binding)?;
        let live_metadata = target_metadata::current_metadata_in_tx(&tx, tenant, &target, now)?
            .ok_or(AuthorityError::Binding)?;
        if live_pin.version != reference.version
            || !pin_current(&tx, tenant, &live_pin, now)?
            || live_metadata.receipt != metadata
            || subject.plan_hash != compiled.plan_hash()
        {
            return Err(AuthorityError::Conflict);
        }
        let retained_review = review_evidence::review_in_tx(&tx, tenant, &subject, now)?
            .ok_or(AuthorityError::Binding)?;
        if retained_review.evidence_hash() != compiled.review_hash()
            || receipt_hash(&refs.references)? != compiled.references_hash()
            || live_pin.record.pin != reference.record.pin
        {
            return Err(AuthorityError::Binding);
        }
        let previous = compilation_head(&tx, tenant, plan_id)?;
        if let Some(previous) = &previous
            && previous.receipt.reference_revision == reference.version.to_string()
            && previous.receipt.metadata_receipt_id == metadata.receipt_id
        {
            if previous.verified.canonical_bytes() != compiled.canonical_bytes() {
                return Err(AuthorityError::Conflict);
            }
            let receipt = previous.receipt.clone();
            tx.commit()?;
            return Ok(receipt);
        }
        let sequence = previous.as_ref().map_or(Ok(1), |p| {
            number(&p.receipt.sequence)?
                .checked_add(1)
                .ok_or(invalid("native compilation sequence exhausted"))
        })?;
        let deadline = reference
            .record
            .not_after
            .min(moment(&metadata.valid_until)?)
            .min(subject.valid_until);
        let receipt = NativeCompilationReceipt {
            schema_version: "fw.authority-lab-compilation-receipt/v1".into(),
            compilation_id: new_id()?,
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            target_id: target.clone(),
            plan_id: plan_id.into(),
            plan_hash: compiled.plan_hash().into(),
            sequence: sequence.to_string(),
            evidence_hash: compiled.evidence_hash().into(),
            reference_revision: reference.version.to_string(),
            references_hash: compiled.references_hash().into(),
            metadata_receipt_id: metadata.receipt_id.clone(),
            metadata_receipt_hash: receipt_hash(&metadata)?,
            metadata_report_hash: metadata.report_hash,
            baseline_artifact_hash: compiled
                .baseline()
                .artifact_hash()
                .map_err(|_| invalid("native artifact"))?,
            candidate_artifact_hash: compiled
                .candidate()
                .artifact_hash()
                .map_err(|_| invalid("native artifact"))?,
            admitted_at: at(now)?,
            valid_until: at(deadline)?,
            production_qualified: false,
            dispatch_allowed: false,
        };
        tx.execute(
            "INSERT INTO authority_native_compilations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                target,
                plan_id,
                receipt.compilation_id,
                sequence.to_be_bytes().as_slice(),
                reference.version.to_be_bytes().as_slice(),
                receipt.metadata_receipt_id,
                hash(&receipt.evidence_hash)?,
                now,
                deadline,
                compiled.canonical_bytes(),
                bytes(&receipt)?
            ],
        )?;
        tx.execute("INSERT INTO authority_native_compilation_heads VALUES(?,?,?,?) ON CONFLICT(org_id,project_id,plan_id) DO UPDATE SET compilation_id=excluded.compilation_id",params![tenant.org_id,tenant.project_id,plan_id,receipt.compilation_id])?;
        audit(
            &tx,
            tenant,
            "native_compilation_admitted",
            &receipt.compilation_id,
            now,
        )?;
        tx.commit()?;
        Ok(receipt)
    }
}

fn comparison_name(c: Comparison) -> &'static str {
    match c {
        Comparison::Match => "match",
        Comparison::Mismatch => "mismatch",
        Comparison::Unknown => "unknown",
    }
}
fn expected_binding(ch: &NativeObservationChallenge, c: &Compilation) -> Result<()> {
    let artifact = c.verified.artifact(ch.artifact_role);
    if ch.org_id != c.receipt.org_id
        || ch.project_id != c.receipt.project_id
        || ch.target_id != c.receipt.target_id
        || ch.compilation_hash != c.receipt.evidence_hash
        || ch.reference_revision != c.receipt.reference_revision
        || ch.metadata_receipt_hash != c.receipt.metadata_receipt_hash
        || ch.metadata_report_hash != c.receipt.metadata_report_hash
        || ch.baseline_state_hash != c.verified.baseline().desired_state_hash
        || ch.artifact_hash
            != artifact
                .artifact_hash()
                .map_err(|_| invalid("native artifact"))?
        || moment(&ch.issued_at)? < moment(&c.receipt.admitted_at)?
        || moment(&ch.expires_at)? > moment(&c.receipt.valid_until)?
    {
        return Err(AuthorityError::Binding);
    }
    Ok(())
}
struct Challenge {
    challenge: NativeObservationChallenge,
    compilation: Compilation,
    pin: Pin,
}
fn challenge_at(tx: &Transaction<'_>, tenant: &AuthorityTenant, id: &str) -> Result<Challenge> {
    type Row = (String, String, String, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
    let r:Row=tx.query_row("SELECT target_id,plan_id,compilation_id,observer_revision,challenge_hash,issued_at,expires_at,CASE WHEN length(canonical_bytes)<=4096 THEN canonical_bytes END FROM authority_native_challenges WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let challenge: NativeObservationChallenge = decode(&r.7)?;
    challenge.validate(r.5).map_err(evidence_error)?;
    if challenge.challenge_id != id
        || challenge.target_id != r.0
        || challenge.observer_revision != revision(&r.3)?.to_string()
        || challenge.issued_at != at(r.5)?
        || challenge.expires_at != at(r.6)?
        || r.4 != hash(&hash_bytes(&r.7))?
    {
        return Err(invalid("native challenge projection"));
    }
    let compilation = compilation_at(tx, tenant, &r.2)?;
    if compilation.receipt.plan_id != r.1 {
        return Err(AuthorityError::Binding);
    }
    expected_binding(&challenge, &compilation)?;
    let retained = records::retained_plan(tx, tenant, &compilation.receipt.plan_id)?;
    let plan: Value = decode(&retained.subject.plan_bytes)?;
    if challenge.authority_epoch != retained.subject.authority_epoch.to_string()
        || plan["target_generation"] != challenge.generation
    {
        return Err(AuthorityError::Binding);
    }
    let pin = pin_at(tx, tenant, &r.0, "observer", revision(&r.3)?)?;
    let observer: NativeObserverPin =
        serde_json::from_value(pin.record.pin.clone()).map_err(|_| invalid("observer pin"))?;
    if challenge.observer_key_fingerprint
        != fw_native_evidence::fingerprint(&observer.public_key)
            .map_err(|_| invalid("observer key"))?
        || r.5 < pin.record.not_before
        || r.5 < moment(&pin.record.pinned_at)?
        || r.6 > pin.record.not_after
    {
        return Err(AuthorityError::Binding);
    }
    Ok(Challenge {
        challenge,
        compilation,
        pin,
    })
}
fn build_observation_receipt(
    id: &str,
    sequence: u64,
    ch: &Challenge,
    proof: &SignedNativeObservation,
    proof_bytes: &[u8],
    admitted: i64,
) -> Result<NativeObservationReceipt> {
    let observer: NativeObserverPin =
        serde_json::from_value(ch.pin.record.pin.clone()).map_err(|_| invalid("observer pin"))?;
    let verified = fw_native_evidence::verify_observation(
        &ch.challenge,
        proof,
        &observer.public_key,
        ch.compilation.verified.artifact(ch.challenge.artifact_role),
        admitted,
        observer.not_after,
    )
    .map_err(evidence_error)?;
    Ok(NativeObservationReceipt {
        schema_version: "fw.authority-lab-observation-receipt/v1".into(),
        receipt_id: id.into(),
        org_id: ch.challenge.org_id.clone(),
        project_id: ch.challenge.project_id.clone(),
        target_id: ch.challenge.target_id.clone(),
        plan_id: ch.compilation.receipt.plan_id.clone(),
        challenge_id: ch.challenge.challenge_id.clone(),
        compilation_id: ch.compilation.receipt.compilation_id.clone(),
        sequence: sequence.to_string(),
        compilation_hash: ch.compilation.receipt.evidence_hash.clone(),
        observer_revision: ch.pin.version.to_string(),
        observer_key_fingerprint: ch.challenge.observer_key_fingerprint.clone(),
        proof_hash: hash_bytes(proof_bytes),
        payload_hash: verified.payload_hash().into(),
        readback_hash: verified.readback_hash().into(),
        authority_epoch: ch.challenge.authority_epoch.clone(),
        generation: ch.challenge.generation.clone(),
        artifact_role: ch.challenge.artifact_role,
        comparison: comparison_name(verified.comparison()).into(),
        observed_state_hash: verified.observed_state_hash().map(str::to_owned),
        signature_valid: true,
        provenance: "signed_lab_observer_claim".into(),
        checked_at: at(verified.checked_at())?,
        admitted_at: at(admitted)?,
        valid_until: at(verified.valid_until())?,
        production_qualified: false,
        dispatch_allowed: false,
    })
}
fn observation_at(tx: &Transaction<'_>, tenant: &AuthorityTenant, id: &str) -> Result<Observation> {
    type Row = (
        String,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
    );
    let r:Row=tx.query_row("SELECT target_id,plan_id,challenge_id,compilation_id,sequence,proof_hash,receipt_hash,admitted_at,valid_until,CASE WHEN length(proof_bytes)<=3145728 THEN proof_bytes END,CASE WHEN length(receipt_bytes)<=16384 THEN receipt_bytes END FROM authority_native_observations WHERE org_id=? AND project_id=? AND receipt_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let proof: SignedNativeObservation = bound_decode(&r.9, fw_native_evidence::MAX_PROOF_BYTES)?;
    let receipt: NativeObservationReceipt = decode(&r.10)?;
    let challenge = challenge_at(tx, tenant, &r.2)?;
    let expected = build_observation_receipt(id, revision(&r.4)?, &challenge, &proof, &r.9, r.7)?;
    if receipt != expected
        || receipt.target_id != r.0
        || receipt.plan_id != r.1
        || receipt.compilation_id != r.3
        || r.5 != hash(&receipt.proof_hash)?
        || r.6 != hash(&hash_bytes(&r.10))?
        || r.8 != moment(&receipt.valid_until)?
    {
        return Err(invalid("native observation projection"));
    }
    let sequence = revision(&r.4)?;
    if sequence == 1 {
        if challenge.challenge.expected_head.is_some() {
            return Err(AuthorityError::Binding);
        }
    } else {
        let previous:(Vec<u8>,Vec<u8>)=tx.query_row("SELECT receipt_hash,CASE WHEN length(receipt_bytes)<=16384 THEN receipt_bytes END FROM authority_native_observations WHERE org_id=? AND project_id=? AND target_id=? AND sequence=?",params![tenant.org_id,tenant.project_id,receipt.target_id,(sequence-1).to_be_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(AuthorityError::Binding)?;
        let previous_hash = hash_bytes(&previous.1);
        let previous_receipt: NativeObservationReceipt = decode(&previous.1)?;
        if previous.0 != hash(&previous_hash)?
            || challenge.challenge.expected_head.as_ref() != Some(&previous_hash)
            || previous_receipt.org_id != tenant.org_id
            || previous_receipt.project_id != tenant.project_id
            || previous_receipt.target_id != receipt.target_id
            || previous_receipt.sequence != (sequence - 1).to_string()
            || moment(&previous_receipt.checked_at)? > moment(&receipt.checked_at)?
            || (
                number(&previous_receipt.authority_epoch)?,
                number(&previous_receipt.generation)?,
            ) > (
                number(&receipt.authority_epoch)?,
                number(&receipt.generation)?,
            )
        {
            return Err(invalid("native observation predecessor"));
        }
    }
    Ok(Observation {
        receipt,
        receipt_hash: hash_bytes(&r.10),
        proof: r.9,
    })
}
fn observation_head(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
) -> Result<Option<Observation>> {
    let head:Option<String>=tx.query_row("SELECT receipt_id FROM authority_native_observation_heads WHERE org_id=? AND project_id=? AND target_id=?",params![tenant.org_id,tenant.project_id,target],|r|r.get(0)).optional()?;
    let latest:Option<String>=tx.query_row("SELECT receipt_id FROM authority_native_observations WHERE org_id=? AND project_id=? AND target_id=? ORDER BY sequence DESC LIMIT 1",params![tenant.org_id,tenant.project_id,target],|r|r.get(0)).optional()?;
    if head != latest {
        return Err(invalid("native observation head"));
    }
    head.map(|id| observation_at(tx, tenant, &id)).transpose()
}
fn epoch_generation(head: &Option<Observation>, epoch: u64, generation: u64) -> Result<()> {
    if let Some(old) = head {
        let previous = (
            number(&old.receipt.authority_epoch)?,
            number(&old.receipt.generation)?,
        );
        if (epoch, generation) < previous {
            return Err(AuthorityError::Conflict);
        }
    }
    Ok(())
}

impl AuthorityStore {
    fn observe_native_plan_time(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        now: i64,
    ) -> Result<String> {
        identifier(plan_id)?;
        time(now)?;
        let target = {
            let tx = self.connection.transaction()?;
            let p = records::retained_plan(&tx, tenant, plan_id)?;
            let v: Value = decode(&p.subject.plan_bytes)?;
            let target = v["target_id"]
                .as_str()
                .ok_or(AuthorityError::Binding)?
                .to_owned();
            tx.commit()?;
            target
        };
        self.observe_target_time(tenant, &target, now)?;
        Ok(target)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn challenge_native_observation(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        artifact_role: ArtifactRole,
        installation: &Installation,
        expected_head: Option<&str>,
        authority_epoch: u64,
        generation: u64,
        now: i64,
    ) -> Result<NativeObservationChallenge> {
        let target = self.observe_native_plan_time(tenant, plan_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        target_metadata::clock(&tx, tenant, &target, now)?;
        let compilation = compilation_head(&tx, tenant, plan_id)?.ok_or(AuthorityError::Binding)?;
        let retained = records::retained_plan(&tx, tenant, plan_id)?;
        let plan: Value = decode(&retained.subject.plan_bytes)?;
        if authority_epoch != retained.subject.authority_epoch
            || number(
                plan["target_generation"]
                    .as_str()
                    .ok_or(AuthorityError::Binding)?,
            )? != generation
        {
            return Err(AuthorityError::Binding);
        }
        if !compilation_current(&tx, tenant, &compilation, now)? {
            return Err(AuthorityError::Time);
        }
        let pin = pin_head(&tx, tenant, &target, "observer")?.ok_or(AuthorityError::Binding)?;
        if !pin_current(&tx, tenant, &pin, now)? {
            return Err(AuthorityError::Time);
        }
        let observer: NativeObserverPin =
            serde_json::from_value(pin.record.pin.clone()).map_err(|_| invalid("observer pin"))?;
        let previous = observation_head(&tx, tenant, &target)?;
        if previous.as_ref().map(|p| p.receipt_hash.as_str()) != expected_head {
            return Err(AuthorityError::Conflict);
        }
        epoch_generation(&previous, authority_epoch, generation)?;
        let artifact = compilation.verified.artifact(artifact_role);
        fw_backend_linux::validate_installation(artifact, installation)
            .map_err(|_| invalid("native installation"))?;
        let count:i64=tx.query_row("SELECT count(*) FROM (SELECT 1 FROM authority_native_challenges c WHERE c.org_id=? AND c.project_id=? AND c.target_id=? AND c.observer_revision=? AND c.expires_at>? AND NOT EXISTS(SELECT 1 FROM authority_native_observations o WHERE o.org_id=c.org_id AND o.project_id=c.project_id AND o.challenge_id=c.challenge_id) LIMIT 4)",params![tenant.org_id,tenant.project_id,target,pin.version.to_be_bytes().as_slice(),now],|r|r.get(0))?;
        if count >= 4 {
            return Err(AuthorityError::Quota);
        }
        let mut nonce = [0; 32];
        openssl::rand::rand_bytes(&mut nonce).map_err(|_| invalid("native randomness"))?;
        let challenge = NativeObservationChallenge {
            schema_version: fw_native_evidence::CHALLENGE_SCHEMA.into(),
            challenge_id: new_id()?,
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            target_id: target.clone(),
            observer_revision: pin.version.to_string(),
            observer_key_fingerprint: fw_native_evidence::fingerprint(&observer.public_key)
                .map_err(|_| invalid("observer key"))?,
            reference_revision: compilation.receipt.reference_revision.clone(),
            compilation_hash: compilation.receipt.evidence_hash.clone(),
            metadata_receipt_hash: compilation.receipt.metadata_receipt_hash.clone(),
            metadata_report_hash: compilation.receipt.metadata_report_hash.clone(),
            baseline_state_hash: compilation.verified.baseline().desired_state_hash.clone(),
            expected_head: expected_head.map(str::to_owned),
            authority_epoch: authority_epoch.to_string(),
            generation: generation.to_string(),
            artifact_role,
            artifact_hash: artifact
                .artifact_hash()
                .map_err(|_| invalid("native artifact"))?,
            installation_hash: receipt_hash(installation)?,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            issued_at: at(now)?,
            expires_at: at(now
                .saturating_add(300)
                .min(observer.not_after)
                .min(moment(&compilation.receipt.valid_until)?))?,
        };
        let encoded = challenge.canonical_bytes().map_err(evidence_error)?;
        tx.execute(
            "INSERT INTO authority_native_challenges VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                target,
                plan_id,
                challenge.challenge_id,
                compilation.receipt.compilation_id,
                pin.version.to_be_bytes().as_slice(),
                hash(&hash_bytes(&encoded))?,
                now,
                moment(&challenge.expires_at)?,
                encoded
            ],
        )?;
        audit(
            &tx,
            tenant,
            "native_observation_challenge_issued",
            &challenge.challenge_id,
            now,
        )?;
        tx.commit()?;
        Ok(challenge)
    }
    pub fn admit_native_observation(
        &mut self,
        tenant: &AuthorityTenant,
        proof: &SignedNativeObservation,
        now: i64,
    ) -> Result<NativeObservationAdmission> {
        if proof.challenge.org_id != tenant.org_id
            || proof.challenge.project_id != tenant.project_id
        {
            return Err(AuthorityError::Binding);
        }
        if !self.observe_target_time(tenant, &proof.challenge.target_id, now)? {
            return Err(AuthorityError::Binding);
        }
        let encoded = proof.canonical_bytes().map_err(evidence_error)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        target_metadata::clock(&tx, tenant, &proof.challenge.target_id, now)?;
        let ch = challenge_at(&tx, tenant, &proof.challenge.challenge_id)?;
        if proof.challenge != ch.challenge {
            return Err(AuthorityError::Binding);
        }
        if let Some(id)=tx.query_row("SELECT receipt_id FROM authority_native_observations WHERE org_id=? AND project_id=? AND challenge_id=?",params![tenant.org_id,tenant.project_id,ch.challenge.challenge_id],|r|r.get::<_,String>(0)).optional()? {
            let old=observation_at(&tx,tenant,&id)?;
            if old.proof!=encoded {return Err(AuthorityError::Conflict);}
            tx.commit()?;return Ok(NativeObservationAdmission{receipt:old.receipt,receipt_hash:old.receipt_hash,replayed:true});
        }
        let current = compilation_head(&tx, tenant, &ch.compilation.receipt.plan_id)?
            .ok_or(AuthorityError::Binding)?;
        if current.receipt != ch.compilation.receipt
            || !compilation_current(&tx, tenant, &current, now)?
        {
            return Err(AuthorityError::Time);
        }
        let pin = pin_head(&tx, tenant, &proof.challenge.target_id, "observer")?
            .ok_or(AuthorityError::Binding)?;
        if pin.version != ch.pin.version || !pin_current(&tx, tenant, &pin, now)? {
            return Err(AuthorityError::Time);
        }
        let previous = observation_head(&tx, tenant, &proof.challenge.target_id)?;
        if previous.as_ref().map(|p| &p.receipt_hash) != ch.challenge.expected_head.as_ref() {
            return Err(AuthorityError::Conflict);
        }
        epoch_generation(
            &previous,
            number(&ch.challenge.authority_epoch)?,
            number(&ch.challenge.generation)?,
        )?;
        let sequence = previous.as_ref().map_or(Ok(1), |p| {
            number(&p.receipt.sequence)?
                .checked_add(1)
                .ok_or(invalid("native observation sequence exhausted"))
        })?;
        let receipt = build_observation_receipt(&new_id()?, sequence, &ch, proof, &encoded, now)?;
        if let Some(previous) = &previous
            && moment(&receipt.checked_at)? < moment(&previous.receipt.checked_at)?
        {
            return Err(AuthorityError::Time);
        }
        let receipt_bytes = bytes(&receipt)?;
        let digest = hash_bytes(&receipt_bytes);
        tx.execute(
            "INSERT INTO authority_native_observations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                receipt.target_id,
                receipt.plan_id,
                receipt.receipt_id,
                receipt.challenge_id,
                receipt.compilation_id,
                sequence.to_be_bytes().as_slice(),
                hash(&receipt.proof_hash)?,
                hash(&digest)?,
                now,
                moment(&receipt.valid_until)?,
                encoded,
                receipt_bytes
            ],
        )?;
        tx.execute("INSERT INTO authority_native_observation_heads VALUES(?,?,?,?) ON CONFLICT(org_id,project_id,target_id) DO UPDATE SET receipt_id=excluded.receipt_id",params![tenant.org_id,tenant.project_id,receipt.target_id,receipt.receipt_id])?;
        audit(
            &tx,
            tenant,
            "native_observation_admitted",
            &receipt.receipt_id,
            now,
        )?;
        tx.commit()?;
        Ok(NativeObservationAdmission {
            receipt,
            receipt_hash: digest,
            replayed: false,
        })
    }
}

impl AuthorityStore {
    /// Bounded authenticated presentation of retained history and present
    /// eligibility. No raw capture or mutable caller-supplied gate is returned.
    pub fn native_evidence_status(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        now: i64,
    ) -> Result<NativeEvidenceStatus> {
        self.observe_native_plan_time(tenant, plan_id, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = native_status_in_tx(&tx, tenant, plan_id, now)?;
        tx.commit()?;
        Ok(result)
    }
}

// Same-snapshot reuse by signing coordination. Retained records are still fully
// recomputed and verified; this does not upgrade lab evidence to qualification.
pub(super) fn native_status_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan_id: &str,
    now: i64,
) -> Result<NativeEvidenceStatus> {
    let retained = records::retained_plan(tx, tenant, plan_id)?;
    let plan: Value = decode(&retained.subject.plan_bytes)?;
    let target = plan["target_id"].as_str().ok_or(AuthorityError::Binding)?;
    if now < retained.registered_at || now < retained.subject.created_at {
        return Err(AuthorityError::Time);
    }
    let compilation = compilation_head(tx, tenant, plan_id)?;
    let current = compilation
        .as_ref()
        .map(|c| compilation_current(tx, tenant, c, now))
        .transpose()?
        .unwrap_or(false);
    let head = observation_head(tx, tenant, target)?;
    let observation_head_hash = head.as_ref().map(|h| h.receipt_hash.clone());
    // Present the selected plan's retained history, while keeping the
    // target-global head as the sole current/CAS authority. Never promote
    // an older per-plan receipt merely because a different plan took over.
    let observation = match head {
        Some(head) if head.receipt.plan_id == plan_id => Some(head),
        _ => {
            let id: Option<String> = tx.query_row(
                    "SELECT receipt_id FROM authority_native_observations WHERE org_id=? AND project_id=? AND plan_id=? ORDER BY sequence DESC LIMIT 1",
                    params![tenant.org_id,tenant.project_id,plan_id],
                    |r| r.get(0),
                ).optional()?;
            id.map(|id| observation_at(tx, tenant, &id)).transpose()?
        }
    };
    let observation_current = if let Some(obs) = &observation {
        if now < moment(&obs.receipt.admitted_at)? {
            return Err(AuthorityError::Time);
        }
        let pin = pin_head(tx, tenant, target, "observer")?.ok_or(AuthorityError::Binding)?;
        current
            && observation_head_hash.as_ref() == Some(&obs.receipt_hash)
            && compilation
                .as_ref()
                .is_some_and(|c| c.receipt.compilation_id == obs.receipt.compilation_id)
            && now < moment(&obs.receipt.valid_until)?
            && pin.version.to_string() == obs.receipt.observer_revision
            && pin_current(tx, tenant, &pin, now)?
    } else {
        false
    };
    let mut reasons = vec![
        "NATIVE_QUALIFICATION_REQUIRED".into(),
        "SIGNER_DISPATCH_UNAVAILABLE".into(),
    ];
    if compilation.is_none() {
        reasons.push("COMPILATION_MISSING".into());
    } else if !current {
        reasons.push("COMPILATION_STALE".into());
    }
    if observation.is_none() {
        reasons.push("OBSERVATION_MISSING".into());
    } else if !observation_current {
        reasons.push("OBSERVATION_STALE".into());
    }
    if let Some(obs) = &observation {
        match obs.receipt.comparison.as_str() {
            "mismatch" => reasons.push("OBSERVATION_MISMATCH".into()),
            "unknown" => reasons.push("OBSERVATION_UNKNOWN".into()),
            "match" => {}
            _ => return Err(AuthorityError::Binding),
        }
    }
    let result = NativeEvidenceStatus {
        schema_version: "fw.native-evidence-status/v1".into(),
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        target_id: target.into(),
        plan_id: plan_id.into(),
        plan_hash: retained.subject.plan_hash,
        checked_at: at(now)?,
        production_qualified: false,
        dispatch_allowed: false,
        reasons,
        compilation: compilation.map(|c| NativeCompilationStatus {
            evidence_hash: c.receipt.evidence_hash,
            reference_revision: c.receipt.reference_revision,
            metadata_receipt_hash: c.receipt.metadata_receipt_hash,
            baseline_artifact_hash: c.receipt.baseline_artifact_hash,
            candidate_artifact_hash: c.receipt.candidate_artifact_hash,
            admitted_at: c.receipt.admitted_at,
            valid_until: c.receipt.valid_until,
            current,
        }),
        observation: observation.map(|o| NativeObservationStatus {
            receipt_hash: o.receipt_hash,
            compilation_hash: o.receipt.compilation_hash,
            observer_revision: o.receipt.observer_revision,
            artifact_role: o.receipt.artifact_role,
            comparison: o.receipt.comparison,
            observed_state_hash: o.receipt.observed_state_hash,
            signature_valid: true,
            provenance: "signed_lab_observer_claim".into(),
            checked_at: o.receipt.checked_at,
            admitted_at: o.receipt.admitted_at,
            valid_until: o.receipt.valid_until,
            current: observation_current,
        }),
        observation_head_hash,
    };
    Ok(result)
}

// The lab receipt's generation binds the reviewed plan proposal. It is not a
// protected executor journal high-water. Signing checks the independent target
// generation separately and cannot promote this claim to native qualification.
pub(super) fn baseline_binding_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    plan_id: &str,
) -> Result<Option<NativeObservationReceipt>> {
    let retained = records::retained_plan(tx, tenant, plan_id)?;
    let plan: Value = decode(&retained.subject.plan_bytes)?;
    let target = plan["target_id"].as_str().ok_or(AuthorityError::Binding)?;
    let Some(observation) = observation_head(tx, tenant, target)? else {
        return Ok(None);
    };
    if observation.receipt.plan_id != plan_id
        || observation.receipt.artifact_role != ArtifactRole::Baseline
        || observation.receipt.comparison != "match"
        || observation
            .receipt
            .observed_state_hash
            .as_ref()
            .is_none_or(|h| plan["baseline_hash"] != *h)
        || observation.receipt.authority_epoch != plan["authority_epoch"]
        || observation.receipt.generation != plan["target_generation"]
    {
        return Ok(None);
    }
    Ok(Some(observation.receipt))
}
