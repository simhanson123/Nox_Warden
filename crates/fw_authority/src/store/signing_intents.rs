//! Durable two-phase signing coordination. Production preparation is closed
//! until protected bootstrap, build identity and native qualification exist.
//! Test-only witnesses exercise transactions; no public lab bypass is provided.
use super::*;
use crate::{
    GrantContext, PreparedSigningJob, SIGNING_JOB_SCHEMA, SignerResult, SigningJob, TrustKey,
    validate_signing_job, verify_signer_result,
};
use serde::Deserialize;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub request_id: String,
    pub plan_id: String,
    pub expected_plan_hash: String,
    pub expected_approval_set_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningIntentStatus {
    pub intent_id: String,
    pub request_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub approval_set_hash: String,
    pub authority_epoch: String,
    pub target_generation: String,
    pub payload_hash: String,
    pub job_id: String,
    pub reservation_id: String,
    pub created_at: String,
    pub valid_until: String,
    pub state: String,
    pub dispatch_state: Option<String>,
    pub reservation_state: String,
    pub reservation_held: bool,
    pub current_eligible: bool,
    pub grant_hash: Option<String>,
    pub dispatch_allowed: bool,
}
#[derive(Debug, Serialize)]
pub struct SigningIntentOutcome {
    pub intent: SigningIntentStatus,
    pub replayed: bool,
}
#[derive(Debug, Serialize)]
pub struct SigningReadiness {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub checked_at: String,
    pub valid_until: String,
    pub signing_allowed: bool,
    pub dispatch_allowed: bool,
    pub reasons: Vec<String>,
    pub approval_set_hash: Option<String>,
    pub quota_configured: bool,
    pub target_generation: Option<String>,
    pub latest_intent: Option<SigningIntentStatus>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct SigningIntentRecord {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub intent_id: String,
    pub request_id: String,
    pub target_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub approval_set_hash: String,
    pub authority_epoch: String,
    pub target_generation: String,
    pub reservation_id: String,
    pub job_id: String,
    pub created_at: String,
    pub valid_until: String,
    pub payload_hash: String,
    pub inputs_hash: String,
    pub request: SigningRequest,
    pub signer_key: RetainedSignerKey,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedSignerKey {
    key_id: String,
    org_id: String,
    payload_type: String,
    public_key: [u8; 32],
    not_before: i64,
    not_after: i64,
}
impl RetainedSignerKey {
    fn from_trust(key: &TrustKey) -> Self {
        Self {
            key_id: key.key_id.clone(),
            org_id: key.org_id.clone(),
            payload_type: key.payload_type.clone(),
            public_key: key.public_key,
            not_before: key.not_before,
            not_after: key.not_after,
        }
    }
    fn trust(&self) -> TrustKey {
        TrustKey {
            key_id: self.key_id.clone(),
            org_id: self.org_id.clone(),
            payload_type: self.payload_type.clone(),
            public_key: self.public_key,
            not_before: self.not_before,
            not_after: self.not_after,
            revoked: false,
        }
    }
}
struct SigningSnapshot {
    plan: Value,
    inputs_hash: String,
    valid_until: i64,
    approval_set_hash: String,
}
// This type has no public constructor. The real resolver intentionally refuses
// all records while protected qualification/bootstrap/build identity are absent.
struct ProtectedSigningAuthority {
    trust: TrustKey,
}
fn protected_authority(
    _tx: &Transaction<'_>,
    _tenant: &AuthorityTenant,
    _plan_id: &str,
    _now: i64,
) -> Result<ProtectedSigningAuthority> {
    Err(invalid("protected signing authority unavailable"))
}
pub(super) fn protected_job_eligibility(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    intent_id: &str,
    now: i64,
) -> Result<()> {
    let intent = intent_at(tx, tenant, intent_id)?;
    protected_authority(tx, tenant, &intent.plan_id, now).map(|_| ())
}
fn request_valid(request: &SigningRequest) -> Result<()> {
    identifier(&request.request_id)?;
    identifier(&request.plan_id)?;
    hash(&request.expected_plan_hash)?;
    hash(&request.expected_approval_set_hash)?;
    Ok(())
}
fn number(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| invalid("signing counter projection"))?,
    ))
}
fn plan_target(tx: &Transaction<'_>, tenant: &AuthorityTenant, plan_id: &str) -> Result<String> {
    let retained = records::retained_plan(tx, tenant, plan_id)?;
    let plan: Value = decode(&retained.subject.plan_bytes)?;
    Ok(crate::string(&plan, "target_id")?.into())
}
fn target_head(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    target: &str,
) -> Result<Option<(u64, u64)>> {
    type HeadRow = (Vec<u8>, Vec<u8>, Option<String>, i64);
    let row: Option<HeadRow> = tx.query_row(
        "SELECT epoch,generation,last_intent_id,updated_at FROM authority_signing_target_heads WHERE org_id=? AND project_id=? AND target_id=?",
        params![tenant.org_id,tenant.project_id,target], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    // The mutable projection cannot erase or move behind immutable generation
    // history. The target/epoch/generation UNIQUE index bounds this lookup; BLOB
    // counters preserve unsigned ordering across the complete u64 range.
    let latest:Option<String>=tx.query_row(
        "SELECT intent_id FROM authority_signing_intents WHERE org_id=? AND project_id=? AND target_id=? ORDER BY epoch DESC,generation DESC LIMIT 1",
        params![tenant.org_id,tenant.project_id,target],|r|r.get(0)).optional()?;
    let Some((epoch, generation, intent, updated)) = row else {
        return if latest.is_none() {
            Ok(None)
        } else {
            Err(invalid("missing signing target head"))
        };
    };
    if intent != latest {
        return Err(invalid("signing target head history"));
    }
    let value = (number(&epoch)?, number(&generation)?);
    time(updated)?;
    if let Some(id) = intent {
        let intent = intent_at(tx, tenant, &id)?;
        if intent.target_id != target
            || crate::counter(&intent.authority_epoch)? != value.0
            || crate::counter(&intent.target_generation)? != value.1
            || crate::timestamp(&intent.created_at)? != updated
        {
            return Err(invalid("signing target head"));
        }
    } else if value.1 != 0 {
        return Err(invalid("uninitialized signing generation"));
    }
    Ok(Some(value))
}
pub(super) fn intent_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
) -> Result<SigningIntentRecord> {
    type Row = (
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
        i64,
        i64,
        Vec<u8>,
    );
    let row:Row=tx.query_row("SELECT request_id,target_id,plan_id,plan_hash,approval_set_hash,inputs_hash,epoch,generation,reservation_id,job_id,created_at,valid_until,CASE WHEN length(canonical_bytes)<=131072 THEN canonical_bytes END FROM authority_signing_intents WHERE org_id=? AND project_id=? AND intent_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let record: SigningIntentRecord = decode(&row.12)?;
    request_valid(&record.request)?;
    for id in [
        &record.intent_id,
        &record.target_id,
        &record.reservation_id,
        &record.job_id,
    ] {
        identifier(id)?;
    }
    if record.schema_version != "fw.signing-intent/v1"
        || record.org_id != tenant.org_id
        || record.project_id != tenant.project_id
        || record.intent_id != id
        || record.request_id != row.0
        || record.target_id != row.1
        || record.plan_id != row.2
        || hash(&record.plan_hash)? != row.3
        || hash(&record.approval_set_hash)? != row.4
        || hash(&record.inputs_hash)? != row.5
        || crate::counter(&record.authority_epoch)? != number(&row.6)?
        || crate::counter(&record.target_generation)? != number(&row.7)?
        || record.reservation_id != row.8
        || record.job_id != row.9
        || crate::timestamp(&record.created_at)? != row.10
        || crate::timestamp(&record.valid_until)? != row.11
        || row.11 <= row.10
        || row.11 - row.10 > 300
        || record.request.request_id != record.request_id
        || record.request.plan_id != record.plan_id
        || record.request.expected_plan_hash != record.plan_hash
        || record.request.expected_approval_set_hash != record.approval_set_hash
    {
        return Err(invalid("signing intent projection"));
    }
    hash(&record.payload_hash)?;
    if record.signer_key.org_id != tenant.org_id
        || record.signer_key.payload_type != crate::POLICY_CHANGE_GRANT_TYPE
        || record.signer_key.not_before > row.10
        || record.signer_key.not_after < row.11
    {
        return Err(invalid("retained signer binding"));
    }
    let plan = records::retained_plan(tx, tenant, &record.plan_id)?;
    if plan.subject.plan_hash != record.plan_hash
        || row.10 < plan.registered_at
        || row.11 > plan.subject.valid_until
    {
        return Err(AuthorityError::Binding);
    }
    Ok(record)
}
pub(super) fn job_at(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    job_id: &str,
) -> Result<PreparedSigningJob> {
    let row:(String,Vec<u8>,i64,i64,Vec<u8>)=tx.query_row("SELECT intent_id,payload_hash,created_at,deadline,CASE WHEN length(canonical_bytes)<=131072 THEN canonical_bytes END FROM authority_signing_jobs WHERE org_id=? AND project_id=? AND job_id=?",params![tenant.org_id,tenant.project_id,job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?.ok_or(AuthorityError::Binding)?;
    let job = crate::parse_signing_job(&row.4)?;
    let intent = intent_at(tx, tenant, &row.0)?;
    if job.canonical_job_bytes() != row.4
        || job.job().job_id != job_id
        || job.job().intent_id != intent.intent_id
        || intent.job_id != job_id
        || job.job().payload_hash != intent.payload_hash
        || hash(&job.job().payload_hash)? != row.1
        || crate::timestamp(&intent.created_at)? != row.2
        || crate::timestamp(&intent.valid_until)? != row.3
        || job.job().payload["plan_hash"] != intent.plan_hash
        || job.job().payload["approval_set_hash"] != intent.approval_set_hash
        || job.job().payload["authority_epoch"] != intent.authority_epoch
        || job.job().payload["target_generation"] != intent.target_generation
        || job.job().payload["dispatch_reservation_id"] != intent.reservation_id
    {
        return Err(invalid("signing job projection"));
    }
    let retained = records::retained_plan(tx, tenant, &intent.plan_id)?;
    let plan: Value = decode(&retained.subject.plan_bytes)?;
    let payload = &job.job().payload;
    for field in [
        "artifact_hash",
        "baseline_hash",
        "desired_state_hash",
        "request_patch_hash",
        "principal_id",
        "rollback_authority",
    ] {
        if payload[field] != plan[field] {
            return Err(invalid("signing job plan binding"));
        }
    }
    if payload["org_id"] != tenant.org_id
        || payload["project_id"] != tenant.project_id
        || payload["target_id"] != intent.target_id
        || payload["plan_id"] != intent.plan_id
        || payload["issued_at"] != intent.created_at
        || payload["not_after"] != intent.valid_until
        || payload["confirm_not_after"] != at(row.3.checked_add(60).ok_or(AuthorityError::Time)?)?
    {
        return Err(invalid("signing job authority binding"));
    }
    Ok(job)
}
fn snapshot(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    verifier: &WebAuthn,
    request: &SigningRequest,
    now: i64,
) -> Result<SigningSnapshot> {
    let subject = records::plan(tx, tenant, &request.plan_id, now)?;
    let plan: Value = decode(&subject.plan_bytes)?;
    if plan["change_kind"] != "policy_change" {
        return Err(invalid("core request authority unavailable"));
    }
    if subject.plan_hash != request.expected_plan_hash {
        return Err(AuthorityError::Binding);
    }
    let review =
        review_evidence::review_in_tx(tx, tenant, &subject, now)?.ok_or(AuthorityError::Binding)?;
    let approval = sets::current_set(tx, tenant, &request.plan_id, verifier, now)?
        .ok_or(AuthorityError::Binding)?;
    if approval.hash() != request.expected_approval_set_hash {
        return Err(AuthorityError::Binding);
    }
    let target = crate::string(&plan, "target_id")?;
    let metadata = target_metadata::current_metadata_in_tx(tx, tenant, target, now)?
        .ok_or(AuthorityError::Binding)?;
    let native = native_evidence::native_status_in_tx(tx, tenant, &request.plan_id, now)?;
    let compilation = native
        .compilation
        .as_ref()
        .filter(|c| c.current)
        .ok_or(AuthorityError::Binding)?;
    let baseline = native
        .observation
        .as_ref()
        .filter(|o| {
            o.current
                && o.comparison == "match"
                && o.artifact_role == fw_native_evidence::ArtifactRole::Baseline
                && o.observed_state_hash
                    .as_ref()
                    .is_some_and(|h| plan["baseline_hash"] == *h)
        })
        .ok_or(AuthorityError::Binding)?;
    native_evidence::baseline_binding_in_tx(tx, tenant, &request.plan_id)?
        .ok_or(AuthorityError::Binding)?;
    let metadata_hash = canonical_hash(&metadata.receipt).map_err(|_| invalid("metadata hash"))?;
    let inputs = json!({"schema_version":"fw.signing-inputs/v1","plan_hash":subject.plan_hash,"approval_set_hash":approval.hash(),"review_hash":review.evidence_hash(),"metadata_hash":metadata_hash,"native_compilation_hash":compilation.evidence_hash,"native_observation_hash":baseline.receipt_hash,"security_revision":security_revision(tx,tenant)?.to_string()});
    let valid_until = subject
        .valid_until
        .min(approval.valid_until())
        .min(crate::timestamp(&metadata.receipt.valid_until)?)
        .min(crate::timestamp(&compilation.valid_until)?)
        .min(crate::timestamp(&baseline.valid_until)?);
    Ok(SigningSnapshot {
        plan,
        inputs_hash: canonical_hash(&inputs).map_err(|_| invalid("signing input hash"))?,
        valid_until,
        approval_set_hash: approval.hash().into(),
    })
}
impl AuthorityStore {
    fn observe_signing_plan_time(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        now: i64,
    ) -> Result<String> {
        identifier(plan_id)?;
        time(now)?;
        let target = {
            let tx = self.connection.transaction()?;
            let target = plan_target(&tx, tenant, plan_id)?;
            tx.commit()?;
            target
        };
        self.observe_target_time(tenant, &target, now)?;
        Ok(target)
    }
    /// Resolve the production signing boundary before creating any intent.
    /// This build always refuses: protected bootstrap, build identity and native
    /// qualification are not implemented. Security clock observations persist.
    pub fn prepare_signing_intent(
        &mut self,
        tenant: &AuthorityTenant,
        verifier: &WebAuthn,
        request: &SigningRequest,
        now: i64,
    ) -> Result<SigningIntentOutcome> {
        request_valid(request)?;
        self.observe_signing_plan_time(tenant, &request.plan_id, now)?;
        self.observe_signing_quota_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority = protected_authority(&tx, tenant, &request.plan_id, now)?;
        let result = prepare_in_tx(&tx, tenant, verifier, request, &authority, now)?;
        tx.commit()?;
        Ok(result)
    }
    /// Revalidate bounded immutable history and its reservation projection.
    /// Retained signatures and held quota never imply current signing authority.
    pub fn read_signing_intent(
        &mut self,
        tenant: &AuthorityTenant,
        intent_id: &str,
        now: i64,
    ) -> Result<Option<SigningIntentStatus>> {
        identifier(intent_id)?;
        time(now)?;
        let tx = self.connection.transaction()?;
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_intents WHERE org_id=? AND project_id=? AND intent_id=?)",params![tenant.org_id,tenant.project_id,intent_id],|r|r.get(0))?;
        let result = if exists {
            Some(status_in_tx(&tx, tenant, intent_id, now)?)
        } else {
            None
        };
        tx.commit()?;
        Ok(result)
    }
    /// Current diagnostic snapshot with a short server deadline. This advances
    /// existing rollback fences but creates no reservation, generation or job.
    /// Both production permission flags remain false in this build.
    pub fn signing_readiness(
        &mut self,
        tenant: &AuthorityTenant,
        plan_id: &str,
        verifier: &WebAuthn,
        now: i64,
    ) -> Result<SigningReadiness> {
        let target = self.observe_signing_plan_time(tenant, plan_id, now)?;
        self.observe_signing_quota_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let retained = records::retained_plan(&tx, tenant, plan_id)?;
        if now < retained.registered_at || now < retained.subject.created_at {
            return Err(AuthorityError::Time);
        }
        let plan: Value = decode(&retained.subject.plan_bytes)?;
        let mut reasons: Vec<String> = [
            "PROTECTED_BOOTSTRAP_REQUIRED",
            "BUILD_IDENTITY_REQUIRED",
            "NATIVE_QUALIFICATION_REQUIRED",
            "PROTECTED_SIGNER_UNAVAILABLE",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let active = !retained.retired && now < retained.subject.valid_until;
        if !active {
            reasons.push("PLAN_STALE".into());
        }
        if review_evidence::review_in_tx(&tx, tenant, &retained.subject, now)?.is_none() {
            reasons.push("REVIEW_EVIDENCE_MISSING".into());
        }
        if plan["change_kind"] != "policy_change" {
            reasons.push("CORE_REQUEST_BINDING_UNAVAILABLE".into());
        }
        let approval = sets::current_set(&tx, tenant, plan_id, verifier, now)?;
        if approval.is_none() {
            reasons.push("APPROVAL_SET_MISSING".into());
        }
        let metadata = target_metadata::current_metadata_in_tx(&tx, tenant, &target, now)?;
        if metadata.is_none() {
            reasons.push("TARGET_METADATA_MISSING".into());
        }
        let native = native_evidence::native_status_in_tx(&tx, tenant, plan_id, now)?;
        let native_good = native.compilation.as_ref().is_some_and(|c| c.current)
            && native.observation.as_ref().is_some_and(|o| {
                o.current
                    && o.comparison == "match"
                    && o.artifact_role == fw_native_evidence::ArtifactRole::Baseline
                    && o.observed_state_hash
                        .as_ref()
                        .is_some_and(|h| plan["baseline_hash"] == *h)
            });
        let native_good =
            native_good && native_evidence::baseline_binding_in_tx(&tx, tenant, plan_id)?.is_some();
        if !native_good {
            reasons.push("NATIVE_BASELINE_UNAVAILABLE".into());
        }
        let quota_configured = signing_quota::configuration_available(&tx, tenant, now)?;
        if !quota_configured {
            reasons.push("QUOTA_CONFIGURATION_MISSING".into());
        }
        let quota_valid_until = signing_quota::configuration_valid_until(&tx, tenant, now)?;
        let head = target_head(&tx, tenant, &target)?;
        if head.is_none() {
            reasons.push("TARGET_GENERATION_UNINITIALIZED".into());
        }
        let mut valid_until = retained
            .subject
            .valid_until
            .min(now.checked_add(60).ok_or(AuthorityError::Time)?);
        if let Some(deadline) = quota_valid_until {
            valid_until = valid_until.min(deadline);
        }
        if let Some(a) = &approval {
            valid_until = valid_until.min(a.valid_until());
        }
        if let Some(m) = &metadata {
            valid_until = valid_until.min(crate::timestamp(&m.receipt.valid_until)?);
        }
        if let Some(c) = native.compilation.as_ref().filter(|c| c.current) {
            valid_until = valid_until.min(crate::timestamp(&c.valid_until)?);
        }
        if let Some(o) = native.observation.as_ref().filter(|o| o.current) {
            valid_until = valid_until.min(crate::timestamp(&o.valid_until)?);
        }
        let last:Option<String>=tx.query_row("SELECT intent_id FROM authority_signing_intents WHERE org_id=? AND project_id=? AND plan_id=? ORDER BY created_at DESC,intent_id DESC LIMIT 1",params![tenant.org_id,tenant.project_id,plan_id],|r|r.get(0)).optional()?;
        let latest_intent = last
            .map(|id| status_in_tx(&tx, tenant, &id, now))
            .transpose()?;
        let result = SigningReadiness {
            schema_version: "fw.signing-readiness/v1".into(),
            org_id: tenant.org_id.clone(),
            project_id: tenant.project_id.clone(),
            target_id: target,
            plan_id: plan_id.into(),
            plan_hash: retained.subject.plan_hash,
            checked_at: at(now)?,
            valid_until: at(valid_until)?,
            signing_allowed: false,
            dispatch_allowed: false,
            reasons,
            approval_set_hash: approval.map(|a| a.hash().to_owned()),
            quota_configured,
            target_generation: head.map(|(_, generation)| generation.to_string()),
            latest_intent,
        };
        tx.commit()?;
        Ok(result)
    }
}

fn prepare_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    verifier: &WebAuthn,
    request: &SigningRequest,
    authority: &ProtectedSigningAuthority,
    now: i64,
) -> Result<SigningIntentOutcome> {
    request_valid(request)?;
    time(now)?;
    let old:Option<String>=tx.query_row("SELECT intent_id FROM authority_signing_intents WHERE org_id=? AND project_id=? AND request_id=?",params![tenant.org_id,tenant.project_id,request.request_id],|r|r.get(0)).optional()?;
    if let Some(id) = old {
        let old = intent_at(tx, tenant, &id)?;
        if old.request != *request {
            return Err(AuthorityError::Conflict);
        }
        return Ok(SigningIntentOutcome {
            intent: status_in_tx(tx, tenant, &id, now)?,
            replayed: true,
        });
    }
    let snapshot = snapshot(tx, tenant, verifier, request, now)?;
    let target = crate::string(&snapshot.plan, "target_id")?;
    let epoch = crate::counter(crate::string(&snapshot.plan, "authority_epoch")?)?;
    let generation = crate::counter(crate::string(&snapshot.plan, "target_generation")?)?;
    let Some((current_epoch, current_generation)) = target_head(tx, tenant, target)? else {
        return Err(AuthorityError::Binding);
    };
    if epoch != current_epoch || current_generation.checked_add(1) != Some(generation) {
        return Err(AuthorityError::Conflict);
    }
    let until = snapshot
        .valid_until
        .min(now.checked_add(300).ok_or(AuthorityError::Time)?);
    if until <= now
        || authority.trust.revoked
        || authority.trust.not_before > now
        || authority.trust.not_after < until
    {
        return Err(AuthorityError::Time);
    }
    if authority.trust.org_id != tenant.org_id
        || authority.trust.payload_type != crate::POLICY_CHANGE_GRANT_TYPE
    {
        return Err(AuthorityError::Binding);
    }
    let intent_id = new_id()?;
    let job_id = new_id()?;
    let reservation_id = new_id()?;
    let grant_id = new_id()?;
    let cost = signing_quota::cost_for_plan(tx, tenant, &request.plan_id, now)?;
    signing_quota::reserve(tx, tenant, &reservation_id, &cost, until, now)?;
    let plan = &snapshot.plan;
    let payload = json!({"schema_version":"f.policy-change-grant/v1","grant_id":grant_id,"plan_id":request.plan_id,"plan_hash":request.expected_plan_hash,"org_id":tenant.org_id,"project_id":tenant.project_id,"target_id":target,"principal_id":plan["principal_id"],"approval_set_hash":snapshot.approval_set_hash,"authority_epoch":epoch.to_string(),"target_generation":generation.to_string(),"issued_at":at(now)?,"not_after":at(until)?,"artifact_hash":plan["artifact_hash"],"baseline_hash":plan["baseline_hash"],"confirm_timeout_seconds":60,"confirm_not_after":at(until.checked_add(60).ok_or(AuthorityError::Time)?)?,"rollback_authority":plan["rollback_authority"],"change_kind":"policy_change","request_patch_hash":plan["request_patch_hash"],"desired_state_hash":plan["desired_state_hash"],"dispatch_reservation_id":reservation_id});
    let job = SigningJob {
        schema_version: SIGNING_JOB_SCHEMA.into(),
        job_id: job_id.clone(),
        intent_id: intent_id.clone(),
        payload_hash: canonical_hash(&payload).map_err(|_| invalid("signing payload"))?,
        payload,
    };
    let prepared = validate_signing_job(&job)?;
    let record = SigningIntentRecord {
        schema_version: "fw.signing-intent/v1".into(),
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        intent_id: intent_id.clone(),
        request_id: request.request_id.clone(),
        target_id: target.into(),
        plan_id: request.plan_id.clone(),
        plan_hash: request.expected_plan_hash.clone(),
        approval_set_hash: snapshot.approval_set_hash,
        authority_epoch: epoch.to_string(),
        target_generation: generation.to_string(),
        reservation_id,
        job_id: job_id.clone(),
        created_at: at(now)?,
        valid_until: at(until)?,
        payload_hash: job.payload_hash.clone(),
        inputs_hash: snapshot.inputs_hash,
        request: request.clone(),
        signer_key: RetainedSignerKey::from_trust(&authority.trust),
    };
    tx.execute(
        "INSERT INTO authority_signing_intents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            intent_id,
            request.request_id,
            target,
            request.plan_id,
            hash(&record.plan_hash)?,
            hash(&record.approval_set_hash)?,
            hash(&record.inputs_hash)?,
            epoch.to_be_bytes().as_slice(),
            generation.to_be_bytes().as_slice(),
            record.reservation_id,
            job_id,
            now,
            until,
            bytes(&record)?
        ],
    )?;
    tx.execute(
        "INSERT INTO authority_signing_jobs VALUES(?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            job_id,
            intent_id,
            hash(&job.payload_hash)?,
            now,
            until,
            prepared.canonical_job_bytes()
        ],
    )?;
    let changed=tx.execute("UPDATE authority_signing_target_heads SET generation=?,last_intent_id=?,updated_at=? WHERE org_id=? AND project_id=? AND target_id=? AND epoch=? AND generation=?",params![generation.to_be_bytes().as_slice(),intent_id,now,tenant.org_id,tenant.project_id,target,epoch.to_be_bytes().as_slice(),current_generation.to_be_bytes().as_slice()])?;
    if changed != 1 {
        return Err(AuthorityError::Conflict);
    }
    signing_jobs::initialize_job(tx, tenant, &job_id, now)?;
    audit(tx, tenant, "signing_intent_prepared", &intent_id, now)?;
    Ok(SigningIntentOutcome {
        intent: status_in_tx(tx, tenant, &intent_id, now)?,
        replayed: false,
    })
}

fn status_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    id: &str,
    now: i64,
) -> Result<SigningIntentStatus> {
    let intent = intent_at(tx, tenant, id)?;
    if now < crate::timestamp(&intent.created_at)? {
        return Err(AuthorityError::Time);
    }
    job_at(tx, tenant, &intent.job_id)?;
    let reservation = signing_quota::read(tx, tenant, &intent.reservation_id)?;
    if reservation.plan_id != intent.plan_id || reservation.plan_hash != intent.plan_hash {
        return Err(AuthorityError::Binding);
    }
    let lifecycle = signing_jobs::lifecycle_status(tx, tenant, &intent.job_id, now)?;
    type ResultRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let result:Option<ResultRow>=tx.query_row("SELECT grant_hash,result_hash,CASE WHEN length(grant_bytes)<=262144 THEN grant_bytes END,CASE WHEN length(result_bytes)<=262144 THEN result_bytes END FROM authority_signing_results WHERE org_id=? AND project_id=? AND intent_id=?",params![tenant.org_id,tenant.project_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let grant_hash = if let Some((gh, rh, grant, result)) = result {
        let parsed = crate::parse_signer_result(&result)?;
        if hash(&hash_bytes(&grant))? != gh
            || hash(&hash_bytes(&result))? != rh
            || bytes(&parsed)? != result
            || bytes(&parsed.signed_grant)? != grant
            || parsed.job_id != intent.job_id
            || parsed.intent_id != intent.intent_id
            || parsed.payload_hash != intent.payload_hash
        {
            return Err(invalid("signing result projection"));
        }
        let plan = records::retained_plan(tx, tenant, &intent.plan_id)?;
        let historical = SigningSnapshot {
            plan: decode(&plan.subject.plan_bytes)?,
            inputs_hash: intent.inputs_hash.clone(),
            valid_until: crate::timestamp(&intent.valid_until)?,
            approval_set_hash: intent.approval_set_hash.clone(),
        };
        let verified = verify_signer_result(
            &job_at(tx, tenant, &intent.job_id)?,
            &parsed,
            &intent.signer_key.trust(),
            &grant_context(tenant, &historical, crate::timestamp(&intent.created_at)?)?,
        )?;
        if verified.canonical_grant_bytes() != grant || verified.canonical_result_bytes() != result
        {
            return Err(invalid("retained signature bytes"));
        }
        Some(hash_string(&gh)?)
    } else {
        None
    };
    Ok(SigningIntentStatus {
        intent_id: intent.intent_id,
        request_id: intent.request_id,
        plan_id: intent.plan_id,
        plan_hash: intent.plan_hash,
        approval_set_hash: intent.approval_set_hash,
        authority_epoch: intent.authority_epoch,
        target_generation: intent.target_generation,
        payload_hash: intent.payload_hash,
        job_id: intent.job_id,
        reservation_id: intent.reservation_id,
        created_at: intent.created_at,
        valid_until: intent.valid_until,
        state: lifecycle.state,
        dispatch_state: lifecycle.dispatch_state,
        reservation_state: reservation.state.clone(),
        reservation_held: reservation.held(),
        current_eligible: false,
        grant_hash,
        dispatch_allowed: false,
    })
}
fn grant_context(
    tenant: &AuthorityTenant,
    snapshot: &SigningSnapshot,
    now: i64,
) -> Result<GrantContext> {
    let plan = &snapshot.plan;
    Ok(GrantContext {
        org_id: tenant.org_id.clone(),
        project_id: tenant.project_id.clone(),
        target_id: crate::string(plan, "target_id")?.into(),
        plan_hash: canonical_hash(plan).map_err(|_| invalid("plan hash"))?,
        artifact_hash: crate::string(plan, "artifact_hash")?.into(),
        baseline_hash: crate::string(plan, "baseline_hash")?.into(),
        desired_state_hash: crate::string(plan, "desired_state_hash")?.into(),
        approval_set_hash: snapshot.approval_set_hash.clone(),
        authority_epoch: crate::counter(crate::string(plan, "authority_epoch")?)?,
        now_unix: now,
    })
}
impl AuthorityStore {
    /// Commit an independently verified signer reply only after protected
    /// authority resolution. Like preparation, this build fails closed.
    pub fn finalize_signing_intent(
        &mut self,
        tenant: &AuthorityTenant,
        verifier: &WebAuthn,
        claim: &signing_jobs::SigningClaim,
        result: &SignerResult,
        now: i64,
    ) -> Result<SigningIntentOutcome> {
        identifier(&result.intent_id)?;
        time(now)?;
        let plan_id = {
            let tx = self.connection.transaction()?;
            let intent = intent_at(&tx, tenant, &result.intent_id)?;
            tx.commit()?;
            intent.plan_id
        };
        self.observe_signing_plan_time(tenant, &plan_id, now)?;
        self.observe_signing_quota_time(tenant, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority = protected_authority(&tx, tenant, &plan_id, now)?;
        let outcome = finalize_in_tx(&tx, tenant, verifier, claim, result, &authority, now)?;
        tx.commit()?;
        Ok(outcome)
    }
}
fn finalize_in_tx(
    tx: &Transaction<'_>,
    tenant: &AuthorityTenant,
    verifier: &WebAuthn,
    claim: &signing_jobs::SigningClaim,
    result: &SignerResult,
    authority: &ProtectedSigningAuthority,
    now: i64,
) -> Result<SigningIntentOutcome> {
    let intent = intent_at(tx, tenant, &result.intent_id)?;
    let prepared = job_at(tx, tenant, &intent.job_id)?;
    // Bound typed input before canonical allocation even on the historical retry
    // path, and reverify the exact stored signer purpose at original issuance.
    let retained = records::retained_plan(tx, tenant, &intent.plan_id)?;
    let historical = SigningSnapshot {
        plan: decode(&retained.subject.plan_bytes)?,
        inputs_hash: intent.inputs_hash.clone(),
        valid_until: crate::timestamp(&intent.valid_until)?,
        approval_set_hash: intent.approval_set_hash.clone(),
    };
    let checked = verify_signer_result(
        &prepared,
        result,
        &intent.signer_key.trust(),
        &grant_context(tenant, &historical, crate::timestamp(&intent.created_at)?)?,
    )?;
    // Exact historical replay acknowledges the retained result. It never emits
    // another outbox row, moves generation or refreshes an expired authority.
    let existing:Option<Vec<u8>>=tx.query_row("SELECT CASE WHEN length(result_bytes)<=262144 THEN result_bytes END FROM authority_signing_results WHERE org_id=? AND project_id=? AND intent_id=?",params![tenant.org_id,tenant.project_id,intent.intent_id],|r|r.get(0)).optional()?;
    if let Some(old) = existing {
        if checked.canonical_result_bytes() != old {
            return Err(AuthorityError::Conflict);
        }
        return Ok(SigningIntentOutcome {
            intent: status_in_tx(tx, tenant, &intent.intent_id, now)?,
            replayed: true,
        });
    }
    if now >= crate::timestamp(&intent.valid_until)? {
        return Err(AuthorityError::Time);
    }
    signing_jobs::validate_finalize_claim(tx, tenant, &intent.job_id, claim, now)?;
    let snapshot = snapshot(tx, tenant, verifier, &intent.request, now)?;
    if snapshot.inputs_hash != intent.inputs_hash
        || target_head(tx, tenant, &intent.target_id)?
            != Some((
                crate::counter(&intent.authority_epoch)?,
                crate::counter(&intent.target_generation)?,
            ))
    {
        return Err(AuthorityError::Conflict);
    }
    if RetainedSignerKey::from_trust(&authority.trust) != intent.signer_key {
        return Err(AuthorityError::Binding);
    }
    let verified = verify_signer_result(
        &prepared,
        result,
        &authority.trust,
        &grant_context(tenant, &snapshot, now)?,
    )?;
    signing_quota::finalize(tx, tenant, &intent.reservation_id, now)?;
    tx.execute(
        "INSERT INTO authority_signing_results VALUES(?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            intent.intent_id,
            hash(verified.grant_hash())?,
            hash(&hash_bytes(verified.canonical_result_bytes()))?,
            now,
            verified.canonical_grant_bytes(),
            verified.canonical_result_bytes()
        ],
    )?;
    signing_jobs::record_ready(tx, tenant, &intent.job_id, claim, &verified, now)?;
    audit(
        tx,
        tenant,
        "signing_result_finalized",
        &intent.intent_id,
        now,
    )?;
    Ok(SigningIntentOutcome {
        intent: status_in_tx(tx, tenant, &intent.intent_id, now)?,
        replayed: false,
    })
}

#[cfg(test)]
fn test_authority() -> ProtectedSigningAuthority {
    ProtectedSigningAuthority {
        trust: TrustKey {
            key_id: "fixture-signing-key".into(),
            org_id: signing_test_support::native::ORG.into(),
            payload_type: crate::POLICY_CHANGE_GRANT_TYPE.into(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[81; 32])
                .verifying_key()
                .to_bytes(),
            not_before: signing_test_support::NOW,
            not_after: signing_test_support::NOW + 7200,
            revoked: false,
        },
    }
}
#[cfg(test)]
pub(super) fn test_request(f: &signing_test_support::Fixture) -> SigningRequest {
    SigningRequest {
        request_id: new_id().unwrap(),
        plan_id: f.plan["plan_id"].as_str().unwrap().into(),
        expected_plan_hash: canonical_hash(&f.plan).unwrap(),
        expected_approval_set_hash: f.current_approval_hash.clone(),
    }
}
#[cfg(test)]
pub(super) fn test_initialize(f: &mut signing_test_support::Fixture, now: i64) {
    let limits = SigningQuotaLimits {
        active_leases: 10,
        new_leases_per_day: 10,
        unique_destinations_per_day: 10,
        cumulative_seconds_per_day: 864000,
        concurrent_deployments: 10,
    };
    let root = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string();
    let has:bool=f.store.connection.query_row("SELECT EXISTS(SELECT 1 FROM authority_signing_quota_heads WHERE org_id=? AND bucket_kind='project' AND bucket_id=?)",params![f.tenant.org_id,f.tenant.project_id],|r|r.get(0)).unwrap();
    if !has {
        f.store
            .pin_signing_root_quota(
                &f.tenant,
                &SigningRootQuotaPin {
                    root_id: root.clone(),
                    limits: limits.clone(),
                    not_before: signing_test_support::NOW,
                    not_after: signing_test_support::NOW + 7200,
                },
                None,
                now,
            )
            .unwrap();
        f.store
            .pin_signing_project_quota(
                &f.tenant,
                &SigningProjectQuotaPin {
                    root_id: root,
                    limits,
                    not_before: signing_test_support::NOW,
                    not_after: signing_test_support::NOW + 7200,
                },
                None,
                now,
            )
            .unwrap();
    }
    // This test-only seed is deliberately not exposed as a production API.
    // Existing lab metadata never initializes the independent generation head.
    f.store
        .connection
        .execute(
            "INSERT OR IGNORE INTO authority_signing_target_heads VALUES(?,?,?,?,?,NULL,?)",
            params![
                f.tenant.org_id,
                f.tenant.project_id,
                f.plan["target_id"].as_str().unwrap(),
                1u64.to_be_bytes().as_slice(),
                0u64.to_be_bytes().as_slice(),
                now
            ],
        )
        .unwrap();
}
#[cfg(test)]
pub(super) fn test_prepare(
    f: &mut signing_test_support::Fixture,
    now: i64,
) -> SigningIntentOutcome {
    test_initialize(f, now);
    let request = test_request(f);
    let tx = f
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let result = prepare_in_tx(
        &tx,
        &f.tenant,
        &f.verifier,
        &request,
        &test_authority(),
        now,
    )
    .unwrap();
    tx.commit().unwrap();
    result
}
#[cfg(test)]
pub(super) fn test_sign(
    f: &mut signing_test_support::Fixture,
    intent_id: &str,
    now: i64,
) -> SignerResult {
    struct Evidence(GrantContext);
    impl crate::AuthorityEvidence for Evidence {
        fn verify_for_signing(&self, _: &Value, _: i64) -> Result<GrantContext> {
            Ok(self.0.clone())
        }
    }
    let tx = f.store.connection.transaction().unwrap();
    let intent = intent_at(&tx, &f.tenant, intent_id).unwrap();
    let job = job_at(&tx, &f.tenant, &intent.job_id).unwrap();
    let retained = records::retained_plan(&tx, &f.tenant, &intent.plan_id).unwrap();
    let snapshot = SigningSnapshot {
        plan: decode(&retained.subject.plan_bytes).unwrap(),
        inputs_hash: intent.inputs_hash.clone(),
        valid_until: crate::timestamp(&intent.valid_until).unwrap(),
        approval_set_hash: intent.approval_set_hash.clone(),
    };
    let signed = crate::sign_grant(
        job.job().payload.clone(),
        "fixture-signing-key",
        &ed25519_dalek::SigningKey::from_bytes(&[81; 32]),
        &Evidence(grant_context(&f.tenant, &snapshot, now).unwrap()),
        now,
    )
    .unwrap();
    let result = SignerResult {
        schema_version: crate::SIGNER_RESULT_SCHEMA.into(),
        job_id: intent.job_id,
        intent_id: intent.intent_id,
        payload_hash: intent.payload_hash,
        signed_grant: signed,
    };
    tx.commit().unwrap();
    result
}
#[cfg(test)]
pub(super) fn test_finalize_result(
    f: &mut signing_test_support::Fixture,
    claim: &signing_jobs::SigningClaim,
    result: &SignerResult,
    now: i64,
) -> Result<SigningIntentOutcome> {
    let tx = f
        .store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = finalize_in_tx(
        &tx,
        &f.tenant,
        &f.verifier,
        claim,
        result,
        &test_authority(),
        now,
    )?;
    tx.commit()?;
    Ok(outcome)
}
#[cfg(test)]
pub(super) fn test_finalize(
    f: &mut signing_test_support::Fixture,
    claim: &signing_jobs::SigningClaim,
    now: i64,
) -> Result<SigningIntentOutcome> {
    let intent = {
        let tx = f.store.connection.transaction()?;
        let job = job_at(&tx, &f.tenant, claim.job_id())?;
        let id = job.job().intent_id.clone();
        tx.commit()?;
        id
    };
    let result = test_sign(f, &intent, now);
    test_finalize_result(f, claim, &result, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use signing_test_support::{Fixture, NOW};
    fn claim(f: &mut Fixture, job: &str, now: i64) -> signing_jobs::SigningClaim {
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let claim = signing_jobs::fixture_claim(
            &tx,
            &f.tenant,
            job,
            "signer",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            0,
            30,
            now,
        )
        .unwrap();
        tx.commit().unwrap();
        claim
    }
    #[test]
    fn private_two_phase_mechanics_reopen_exact_retry_and_no_expiry_refund() {
        let mut f = Fixture::new();
        let prepared = test_prepare(&mut f, NOW);
        assert!(!prepared.replayed);
        assert_eq!(prepared.intent.target_generation, "1");
        assert_eq!(prepared.intent.reservation_state, "reserved");
        assert!(prepared.intent.reservation_held);
        for table in [
            "authority_signing_results",
            "authority_signing_outbox",
            "authority_signing_quota_usage",
        ] {
            assert_eq!(f.count(table), 0);
        }
        let claim = claim(&mut f, &prepared.intent.job_id, NOW);
        let result = test_sign(&mut f, &prepared.intent.intent_id, NOW);
        let finalized = test_finalize_result(&mut f, &claim, &result, NOW).unwrap();
        assert_eq!(finalized.intent.state, "ready");
        assert_eq!(finalized.intent.dispatch_state.as_deref(), Some("queued"));
        assert_eq!(finalized.intent.reservation_state, "issued");
        for table in [
            "authority_signing_results",
            "authority_signing_outbox",
            "authority_signing_quota_usage",
        ] {
            assert_eq!(f.count(table), 1);
        }
        f.reopen();
        let replay = test_finalize_result(&mut f, &claim, &result, NOW + 400).unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.intent.grant_hash, finalized.intent.grant_hash);
        assert!(replay.intent.reservation_held);
        assert!(!replay.intent.current_eligible);
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let saved = intent_at(&tx, &f.tenant, &prepared.intent.intent_id).unwrap();
        let replay = prepare_in_tx(
            &tx,
            &f.tenant,
            &f.verifier,
            &saved.request,
            &test_authority(),
            NOW + 400,
        )
        .unwrap();
        assert!(replay.replayed);
        let mut changed = saved.request;
        changed.expected_plan_hash = hash_bytes(b"changed");
        assert!(matches!(
            prepare_in_tx(
                &tx,
                &f.tenant,
                &f.verifier,
                &changed,
                &test_authority(),
                NOW + 400
            ),
            Err(AuthorityError::Conflict)
        ));
        tx.commit().unwrap();
        assert_eq!(f.count("authority_signing_intents"), 1);
        assert_eq!(f.count("authority_signing_outbox"), 1);
        let request = test_request(&f);
        let public = f
            .store
            .prepare_signing_intent(&f.tenant, &f.verifier, &request, NOW + 400);
        assert!(public.is_err());
    }
    #[test]
    fn approval_revocation_between_phases_retains_reservation_without_dispatch() {
        let mut f = Fixture::new();
        let prepared = test_prepare(&mut f, NOW);
        let claim = claim(&mut f, &prepared.intent.job_id, NOW);
        let result = test_sign(&mut f, &prepared.intent.intent_id, NOW);
        f.store
            .revoke_credential(&f.tenant, &f.credential_id, NOW + 1)
            .unwrap();
        assert!(test_finalize_result(&mut f, &claim, &result, NOW + 1).is_err());
        assert_eq!(f.count("authority_signing_results"), 0);
        assert_eq!(f.count("authority_signing_outbox"), 0);
        assert_eq!(f.count("authority_signing_quota_usage"), 0);
        let status = f
            .store
            .read_signing_intent(&f.tenant, &prepared.intent.intent_id, NOW + 1)
            .unwrap()
            .unwrap();
        assert!(status.reservation_held);
        assert_eq!(status.target_generation, "1");
    }
    #[test]
    fn prepare_and_finalize_audit_failures_roll_back_all_composed_writes() {
        let mut f = Fixture::new();
        test_initialize(&mut f, NOW);
        let request = test_request(&f);
        f.store.connection.execute_batch("CREATE TRIGGER signing_audit_fail BEFORE INSERT ON authority_audit WHEN NEW.kind='signing_intent_prepared' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;").unwrap();
        {
            let tx = f
                .store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            assert!(
                prepare_in_tx(
                    &tx,
                    &f.tenant,
                    &f.verifier,
                    &request,
                    &test_authority(),
                    NOW
                )
                .is_err()
            );
        }
        for table in [
            "authority_signing_intents",
            "authority_signing_jobs",
            "authority_signing_quota_reservations",
            "authority_signing_work_heads",
        ] {
            assert_eq!(f.count(table), 0);
        }
        f.store
            .connection
            .execute_batch("DROP TRIGGER signing_audit_fail;")
            .unwrap();
        let prepared = test_prepare(&mut f, NOW);
        let claim = claim(&mut f, &prepared.intent.job_id, NOW);
        let result = test_sign(&mut f, &prepared.intent.intent_id, NOW);
        f.store.connection.execute_batch("CREATE TRIGGER signing_audit_fail BEFORE INSERT ON authority_audit WHEN NEW.kind='signing_result_finalized' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;").unwrap();
        assert!(test_finalize_result(&mut f, &claim, &result, NOW).is_err());
        for table in [
            "authority_signing_results",
            "authority_signing_outbox",
            "authority_signing_quota_usage",
        ] {
            assert_eq!(f.count(table), 0);
        }
        f.store
            .connection
            .execute_batch("DROP TRIGGER signing_audit_fail;")
            .unwrap();
        test_finalize_result(&mut f, &claim, &result, NOW).unwrap();
        assert_eq!(f.count("authority_signing_outbox"), 1);
    }
    #[test]
    fn separate_connections_compete_for_one_generation_and_retain_one_intent() {
        let mut f = Fixture::new();
        test_initialize(&mut f, NOW);
        let request = test_request(&f);
        let other = SigningRequest {
            request_id: new_id().unwrap(),
            ..request.clone()
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let handles = [request, other]
                .into_iter()
                .map(|request| {
                    let path = f.path.clone();
                    let tenant = f.tenant.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let mut store = AuthorityStore::open(path).unwrap();
                        let verifier =
                            WebAuthn::new(signing_test_support::authenticator::ORIGIN).unwrap();
                        barrier.wait();
                        let tx = store
                            .connection
                            .transaction_with_behavior(TransactionBehavior::Immediate)
                            .unwrap();
                        let result = prepare_in_tx(
                            &tx,
                            &tenant,
                            &verifier,
                            &request,
                            &test_authority(),
                            NOW,
                        );
                        match result {
                            Ok(value) => {
                                tx.commit().unwrap();
                                Ok(value.intent.intent_id)
                            }
                            Err(error) => Err(error),
                        }
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .any(|r| matches!(r, Err(AuthorityError::Conflict)))
        );
        assert_eq!(f.count("authority_signing_intents"), 1);
        assert_eq!(f.count("authority_signing_quota_reservations"), 1);
    }
    #[test]
    fn stored_signature_and_generation_projection_corruption_is_refused() {
        let mut f = Fixture::new();
        let prepared = test_prepare(&mut f, NOW);
        let claim = claim(&mut f, &prepared.intent.job_id, NOW);
        let result = test_sign(&mut f, &prepared.intent.intent_id, NOW);
        test_finalize_result(&mut f, &claim, &result, NOW).unwrap();
        f.store
            .connection
            .execute_batch("DROP TRIGGER authority_signing_results_no_update;")
            .unwrap();
        let mut corrupt = result;
        corrupt.signed_grant.dsse.signatures[0].sig =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
        let encoded = bytes(&corrupt).unwrap();
        let grant = bytes(&corrupt.signed_grant).unwrap();
        f.store.connection.execute("UPDATE authority_signing_results SET grant_hash=?,result_hash=?,grant_bytes=?,result_bytes=?",params![hash(&hash_bytes(&grant)).unwrap(),hash(&hash_bytes(&encoded)).unwrap(),grant,encoded]).unwrap();
        assert!(
            f.store
                .read_signing_intent(&f.tenant, &prepared.intent.intent_id, NOW)
                .is_err()
        );
        f.store
            .connection
            .execute(
                "UPDATE authority_signing_target_heads SET generation=?",
                [2u64.to_be_bytes().as_slice()],
            )
            .unwrap();
        assert!(
            f.store
                .signing_readiness(
                    &f.tenant,
                    signing_test_support::native::PLAN,
                    &f.verifier,
                    NOW
                )
                .is_err()
        );
    }
    #[test]
    fn candidate_match_is_not_accepted_as_the_prechange_baseline() {
        let mut f = Fixture::new();
        test_initialize(&mut f, NOW);
        let compiled =
            fw_native_evidence::compile_evidence(&f.plan, &f.review, &f.references).unwrap();
        let installation =
            signing_test_support::native::installation(compiled.candidate(), NOW + 1);
        let challenge = f
            .store
            .challenge_native_observation(
                &f.tenant,
                signing_test_support::native::PLAN,
                fw_native_evidence::ArtifactRole::Candidate,
                &installation,
                Some(&f.baseline_receipt_hash),
                1,
                1,
                NOW + 1,
            )
            .unwrap();
        let proof = signing_test_support::native::proof(
            &challenge,
            installation.clone(),
            signing_test_support::native::snapshot(&installation.native),
            NOW + 1,
        );
        let observation = f
            .store
            .admit_native_observation(&f.tenant, &proof, NOW + 1)
            .unwrap();
        assert_eq!(observation.receipt.comparison, "match");
        let request = test_request(&f);
        let tx = f
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(matches!(
            prepare_in_tx(
                &tx,
                &f.tenant,
                &f.verifier,
                &request,
                &test_authority(),
                NOW + 1
            ),
            Err(AuthorityError::Binding)
        ));
        tx.commit().unwrap();
        assert_eq!(f.count("authority_signing_intents"), 0);
        let readiness = f
            .store
            .signing_readiness(
                &f.tenant,
                signing_test_support::native::PLAN,
                &f.verifier,
                NOW + 1,
            )
            .unwrap();
        assert!(
            readiness
                .reasons
                .iter()
                .any(|r| r == "NATIVE_BASELINE_UNAVAILABLE")
        );
    }
    #[test]
    fn metadata_and_native_observer_revocation_each_block_a_pending_signature() {
        for observer in [false, true] {
            let mut f = Fixture::new();
            let prepared = test_prepare(&mut f, NOW);
            let claim = claim(&mut f, &prepared.intent.job_id, NOW);
            let result = test_sign(&mut f, &prepared.intent.intent_id, NOW);
            if observer {
                f.store
                    .revoke_native_observer(
                        &f.tenant,
                        signing_test_support::native::TARGET,
                        1,
                        NOW + 1,
                    )
                    .unwrap();
            } else {
                f.store
                    .revoke_target_transport(
                        &f.tenant,
                        signing_test_support::native::TARGET,
                        1,
                        NOW + 1,
                    )
                    .unwrap();
            }
            assert!(test_finalize_result(&mut f, &claim, &result, NOW + 1).is_err());
            assert_eq!(f.count("authority_signing_results"), 0);
            assert_eq!(f.count("authority_signing_outbox"), 0);
            assert_eq!(f.count("authority_signing_quota_usage"), 0);
        }
    }
    #[test]
    fn retained_generation_history_rejects_reset_and_missing_heads_after_reopen() {
        for delete in [false, true] {
            let mut f = Fixture::new();
            // A genuinely empty target may have no head, or a privately seeded
            // initial zero head. Neither case creates production authority.
            assert!(
                f.store
                    .signing_readiness(
                        &f.tenant,
                        signing_test_support::native::PLAN,
                        &f.verifier,
                        NOW
                    )
                    .unwrap()
                    .target_generation
                    .is_none()
            );
            test_initialize(&mut f, NOW);
            assert_eq!(
                f.store
                    .signing_readiness(
                        &f.tenant,
                        signing_test_support::native::PLAN,
                        &f.verifier,
                        NOW
                    )
                    .unwrap()
                    .target_generation
                    .as_deref(),
                Some("0")
            );
            let prepared = test_prepare(&mut f, NOW);
            if delete {
                f.store
                    .connection
                    .execute("DELETE FROM authority_signing_target_heads", [])
                    .unwrap();
            } else {
                f.store.connection.execute("UPDATE authority_signing_target_heads SET generation=?,last_intent_id=NULL",[0u64.to_be_bytes().as_slice()]).unwrap();
            }
            f.reopen();
            assert!(matches!(
                f.store.signing_readiness(
                    &f.tenant,
                    signing_test_support::native::PLAN,
                    &f.verifier,
                    NOW
                ),
                Err(AuthorityError::Invalid(_))
            ));
            assert_eq!(f.count("authority_signing_intents"), 1);
            assert_eq!(f.count("authority_signing_jobs"), 1);
            let retained = f
                .store
                .read_signing_intent(&f.tenant, &prepared.intent.intent_id, NOW)
                .unwrap()
                .unwrap();
            assert_eq!(retained.target_generation, "1");
            assert!(retained.reservation_held);
            assert!(!retained.current_eligible);
        }
    }
    #[test]
    fn newest_prepared_generation_rejects_an_otherwise_valid_older_intent_head() {
        let mut f = Fixture::new();
        let first = test_prepare(&mut f, NOW);
        let mut next = f.plan.clone();
        next["plan_id"] = new_id().unwrap().into();
        next["target_generation"] = "2".into();
        let next_id = next["plan_id"].as_str().unwrap().to_owned();
        f.store
            .register_reviewed_plan(&f.tenant, &next, &f.requirements, &f.review, NOW + 1)
            .unwrap();
        f.store
            .register_native_compilation(&f.tenant, &next_id, 1, NOW + 1)
            .unwrap();
        let compiled =
            fw_native_evidence::compile_evidence(&next, &f.review, &f.references).unwrap();
        let installation = signing_test_support::native::installation(compiled.baseline(), NOW + 1);
        let challenge = f
            .store
            .challenge_native_observation(
                &f.tenant,
                &next_id,
                fw_native_evidence::ArtifactRole::Baseline,
                &installation,
                Some(&f.baseline_receipt_hash),
                1,
                2,
                NOW + 1,
            )
            .unwrap();
        let proof = signing_test_support::native::proof(
            &challenge,
            installation.clone(),
            signing_test_support::native::snapshot(&installation.native),
            NOW + 1,
        );
        let observation = f
            .store
            .admit_native_observation(&f.tenant, &proof, NOW + 1)
            .unwrap();
        assert_eq!(observation.receipt.comparison, "match");
        f.plan = next;
        f.baseline_receipt_hash = observation.receipt_hash;
        f.current_approval_hash = f.approve(&next_id, NOW + 1);
        let second = test_prepare(&mut f, NOW + 1);
        assert_eq!(second.intent.target_generation, "2");
        let current = f
            .store
            .signing_readiness(&f.tenant, &next_id, &f.verifier, NOW + 1)
            .unwrap();
        assert_eq!(current.target_generation.as_deref(), Some("2"));
        // No immutable trigger is removed: this is an ordinary mutation of the
        // mutable head to a genuine historical intent with matching projections.
        f.store.connection.execute("UPDATE authority_signing_target_heads SET epoch=?,generation=?,last_intent_id=?,updated_at=?",params![1u64.to_be_bytes().as_slice(),1u64.to_be_bytes().as_slice(),first.intent.intent_id,NOW]).unwrap();
        f.reopen();
        assert!(matches!(
            f.store
                .signing_readiness(&f.tenant, &next_id, &f.verifier, NOW + 1),
            Err(AuthorityError::Invalid(_))
        ));
        assert_eq!(f.count("authority_signing_intents"), 2);
        assert_eq!(f.count("authority_signing_jobs"), 2);
        assert_eq!(f.count("authority_signing_quota_reservations"), 2);
        assert_eq!(
            f.store
                .read_signing_intent(&f.tenant, &second.intent.intent_id, NOW + 1)
                .unwrap()
                .unwrap()
                .target_generation,
            "2"
        );
    }
}
