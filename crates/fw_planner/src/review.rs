use crate::{PlanError, Result};
use crate::{PolicyMutation, StateIr, compose_policy_change};
use fw_contracts::canonical_hash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// Administrator-provided snapshots. Merely deserializing one grants nothing:
/// every display and approve request rechecks it against the authority plan.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReviewEvidence {
    pub before: StateIr,
    pub after: StateIr,
}
impl PolicyReviewEvidence {
    pub fn verify(&self, plan: &Value) -> Result<VerifiedPolicyReview> {
        let invalid = || PlanError("policy review evidence unavailable");
        // Values may be constructed directly rather than parsed with strict
        // depth limits. Bound traversal before entering serde's recursive writer.
        let mut remaining_nodes = MAX_POLICY_REVIEW_BYTES;
        check_plan_depth(plan, 0, &mut remaining_nodes)?;
        // Bound serialization before allocating canonical bytes or cloning states.
        // This is a review-size bound, not an assertion about compiler/gate truth.
        let mut bound = BoundedWriter {
            remaining: MAX_POLICY_REVIEW_BYTES,
        };
        #[derive(Serialize)]
        struct Review<'a> {
            plan: &'a Value,
            before: &'a StateIr,
            after: &'a StateIr,
        }
        serde_json::to_writer(
            &mut bound,
            &Review {
                plan,
                before: &self.before,
                after: &self.after,
            },
        )
        .map_err(|_| invalid())?;
        if plan["schema_version"] != "f.policy-change-plan/v1"
            || plan["change_kind"] != "policy_change"
            || plan["org_id"]
                .as_str()
                .is_none_or(|s| fw_domain::validate_uuid(s).is_err())
            || plan["project_id"]
                .as_str()
                .is_none_or(|s| fw_domain::validate_uuid(s).is_err())
        {
            return Err(invalid());
        }
        self.before.validate().map_err(|_| invalid())?;
        self.after.validate().map_err(|_| invalid())?;
        if canonical_hash(&self.before).map_err(|_| invalid())?
            != self.before.state_hash().map_err(|_| invalid())?
            || canonical_hash(&self.after).map_err(|_| invalid())?
                != self.after.state_hash().map_err(|_| invalid())?
            || plan["baseline_hash"] != self.before.state_hash().map_err(|_| invalid())?
            || plan["desired_state_hash"] != self.after.state_hash().map_err(|_| invalid())?
            || plan["candidate_state_ref"]["object_hash"] != plan["desired_state_hash"]
            || plan["candidate_state_ref"]["size_bytes"].as_u64()
                != Some(
                    fw_contracts::canonical_bytes(&self.after)
                        .map_err(|_| invalid())?
                        .len() as u64,
                )
            || plan["target_id"] != self.before.target_id
            || self.before.target_id != self.after.target_id
            || plan["source_snapshot_hash"] != self.before.source_snapshot_hash
            || plan["target_capability_hash"] != self.before.target_capability_hash
        {
            return Err(invalid());
        }
        for policy in self
            .before
            .policies
            .iter()
            .chain(self.after.policies.iter())
        {
            if plan["org_id"] != policy.org_id || plan["project_id"] != policy.project_id {
                return Err(invalid());
            }
        }
        let operations: Vec<PolicyMutation> =
            serde_json::from_value(plan["operations"].clone()).map_err(|_| invalid())?;
        let associations = self
            .after
            .associations
            .iter()
            .filter(|a| {
                !self
                    .before
                    .associations
                    .iter()
                    .any(|old| old.policy_hash == a.policy_hash)
            })
            .cloned()
            .collect::<Vec<_>>();
        let candidate =
            compose_policy_change(&self.before, &operations, &associations, &BTreeSet::new())
                .map_err(|_| invalid())?;
        if candidate.baseline_hash != plan["baseline_hash"]
            || candidate.desired_state_hash != plan["desired_state_hash"]
            || candidate.request_patch_hash != plan["request_patch_hash"]
            || !candidate.semantic_complete
            || serde_json::to_value(candidate.relation).map_err(|_| invalid())?
                != plan["effect_summary"]["relation"]
            || plan["effect_summary"]["complete"] != true
            || plan["effect_summary"]["newly_allowed_region_hash"]
                != candidate.semantic_diff.newly_allowed_region_hash
            || plan["effect_summary"]["removed_region_hash"]
                != candidate.semantic_diff.removed_region_hash
        {
            return Err(invalid());
        }
        let canonical = fw_contracts::canonical_bytes(self).map_err(|_| invalid())?;
        Ok(VerifiedPolicyReview {
            plan_hash: canonical_hash(plan).map_err(|_| invalid())?,
            evidence_hash: fw_contracts::hash_bytes(&canonical),
            evidence: self.clone(),
            canonical,
        })
    }
}

/// A verified semantic review is not compiler/gate attestation, a current
/// approval, a quota reservation or permission to sign/dispatch native changes.
pub struct VerifiedPolicyReview {
    plan_hash: String,
    evidence_hash: String,
    evidence: PolicyReviewEvidence,
    canonical: Vec<u8>,
}
impl VerifiedPolicyReview {
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
    pub fn evidence_hash(&self) -> &str {
        &self.evidence_hash
    }
    pub fn evidence(&self) -> &PolicyReviewEvidence {
        &self.evidence
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}
pub const MAX_POLICY_REVIEW_BYTES: usize = 128 * 1024;
fn check_plan_depth(value: &Value, depth: usize, remaining: &mut usize) -> Result<()> {
    if depth >= fw_contracts::MAX_DEPTH || *remaining == 0 {
        return Err(PlanError("policy review input bounds"));
    }
    *remaining -= 1;
    match value {
        Value::Array(values) => {
            for value in values {
                check_plan_depth(value, depth + 1, remaining)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                check_plan_depth(value, depth + 1, remaining)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct BoundedWriter {
    remaining: usize,
}
impl std::io::Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(buffer.len())
            .ok_or_else(|| std::io::Error::other("policy review size limit"))?;
        Ok(buffer.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
