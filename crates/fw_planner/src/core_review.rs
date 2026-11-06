//! Full-state core review without interpreting structural bindings as authority.
use crate::{
    CoreAccessEffectSummary, PlanError, PolicyReviewEvidence, Result, compose_access_patch,
    core_access_effect_summary,
};
use fw_contracts::canonical_hash;
use fw_domain::{Action, Policy, timestamp, validate_uuid};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Correspondence established by a complete core review. No field proves a
/// workload signature, delegation approval, current authority or quota.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreAccessReviewBinding {
    lease_id: String,
    request_id: String,
    authority_basis_hash: String,
    not_before: i64,
    expires_at: i64,
}
impl CoreAccessReviewBinding {
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn authority_basis_hash(&self) -> &str {
        &self.authority_basis_hash
    }
    pub fn not_before(&self) -> i64 {
        self.not_before
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub fn lease_seconds(&self) -> i64 {
        self.expires_at - self.not_before
    }
}

/// Noncircular authority-basis digest for core associations. These are original
/// approval requirements and envelope/delegation hashes, never a final approval
/// set or a claim that its referenced authorities have been authenticated.
pub fn core_access_authority_basis_hash(plan: &Value) -> Result<String> {
    if plan["schema_version"] != "f.plan/v1" || plan["change_kind"] != "add_access_lease" {
        return Err(invalid());
    }
    for key in [
        "approval_requirements_hash",
        "envelope_hash",
        "delegation_hash",
    ] {
        if plan[key].as_str().is_none_or(|s| !crate::hash_valid(s)) {
            return Err(invalid());
        }
    }
    canonical_hash(&json!({
        "schema_version":"f.policy-authority-basis/v1",
        "approval_requirements_hash":plan["approval_requirements_hash"],
        "envelope_hash":plan["envelope_hash"],
        "delegation_hash":plan["delegation_hash"]
    }))
    .map_err(|_| invalid())
}

fn invalid() -> PlanError {
    PlanError("core access review evidence unavailable")
}

/// Shared state normalization/hash/tenant checks run in PolicyReviewEvidence.
pub(crate) fn verify_core(
    evidence: &PolicyReviewEvidence,
    plan: &Value,
) -> Result<CoreAccessReviewBinding> {
    for key in [
        "plan_id",
        "request_id",
        "principal_id",
        "workload_binding_id",
    ] {
        if plan[key].as_str().is_none_or(|s| validate_uuid(s).is_err()) {
            return Err(invalid());
        }
    }
    if plan["normalization_version"] != "f.normalize/nfc-v1"
        || !plan["request_revision"]
            .as_u64()
            .is_some_and(|revision| (1..=i32::MAX as u64).contains(&revision))
    {
        return Err(invalid());
    }
    let values = plan["requested_policies"]
        .as_array()
        .filter(|values| !values.is_empty() && values.len() <= 256)
        .ok_or_else(invalid)?;
    let policies: Vec<Policy> =
        serde_json::from_value(plan["requested_policies"].clone()).map_err(|_| invalid())?;
    let mut hashes = BTreeSet::new();
    let mut previous_id = None;
    let mut window = None;
    for policy in &policies {
        if policy.normalized().map_err(|_| invalid())? != *policy
            || policy.action != Action::Allow
            || policy.policy_revision != 1
            || previous_id.is_some_and(|id| id >= policy.policy_id.as_str())
        {
            return Err(invalid());
        }
        previous_id = Some(policy.policy_id.as_str());
        hashes.insert(canonical_hash(policy).map_err(|_| invalid())?);
        let interval = (
            timestamp(policy.lifetime.not_before()).map_err(|_| invalid())?,
            timestamp(policy.lifetime.expires_at().ok_or_else(invalid)?).map_err(|_| invalid())?,
        );
        // The original core profile realizes one requested duration with every
        // branch. A shorter or shifted policy cannot create another lease clock.
        if window.is_some_and(|old| old != interval) {
            return Err(invalid());
        }
        window = Some(interval);
    }
    let expected_hashes = hashes
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    if plan["requested_policy_hashes"] != Value::Array(expected_hashes)
        || plan["request_patch_hash"] != canonical_hash(values).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let (not_before, expires_at) = window.ok_or_else(invalid)?;
    if !expires_at
        .checked_sub(not_before)
        .is_some_and(|seconds| (60..=86_400).contains(&seconds))
    {
        return Err(invalid());
    }
    let created = plan["created_at"].as_str().ok_or_else(invalid)?;
    let until = plan["valid_until"].as_str().ok_or_else(invalid)?;
    let workload_until = plan["workload_binding_valid_until"]
        .as_str()
        .ok_or_else(invalid)?;
    if timestamp(created).map_err(|_| invalid())? >= timestamp(until).map_err(|_| invalid())?
        || timestamp(until).map_err(|_| invalid())? > expires_at
        || timestamp(workload_until).map_err(|_| invalid())? < expires_at
    {
        return Err(invalid());
    }
    let basis_hash = core_access_authority_basis_hash(plan)?;
    let associations = evidence
        .after
        .associations
        .iter()
        .filter(|association| hashes.contains(&association.policy_hash))
        .cloned()
        .collect::<Vec<_>>();
    let mut lease_id = None;
    for association in &associations {
        let lease = association.lease_id.as_deref().ok_or_else(invalid)?;
        if association.request_id != plan["request_id"]
            || association.authority_basis_hash != basis_hash
            || lease_id.is_some_and(|old| old != lease)
        {
            return Err(invalid());
        }
        lease_id = Some(lease);
    }
    let lease_id = lease_id.ok_or_else(invalid)?;
    let candidate =
        compose_access_patch(&evidence.before, &policies, &associations, &BTreeSet::new())
            .map_err(|_| invalid())?;
    let effect: CoreAccessEffectSummary =
        serde_json::from_value(plan["effect_summary"].clone()).map_err(|_| invalid())?;
    if candidate.baseline_hash != plan["baseline_hash"]
        || candidate.desired_state_hash != plan["desired_state_hash"]
        || candidate.request_patch_hash != plan["request_patch_hash"]
        || !candidate.semantic_complete
        || effect != core_access_effect_summary(&evidence.before, &evidence.after)?
    {
        return Err(invalid());
    }
    Ok(CoreAccessReviewBinding {
        lease_id: lease_id.to_owned(),
        request_id: plan["request_id"].as_str().ok_or_else(invalid)?.to_owned(),
        authority_basis_hash: basis_hash,
        not_before,
        expires_at,
    })
}
