use crate::{Failure, Result};
use fw_contracts::canonical_hash;
use fw_planner::{PolicyMutation, StateIr, compose_policy_change};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Administrator-provided snapshots. Merely deserializing one grants nothing:
/// every display and approve request rechecks it against the authority plan.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvidence {
    pub before: StateIr,
    pub after: StateIr,
}
impl ReviewEvidence {
    pub(crate) fn verify(&self, plan: &Value) -> Result<Value> {
        let invalid = || Failure::ReviewUnavailable;
        // Reserve response space for requirements and decision metadata. Full
        // reviewed content is never truncated to make an approval fit.
        if serde_json::to_vec(&json!({"plan":plan,"before":self.before,"after":self.after}))
            .map_err(|_| invalid())?
            .len()
            > 128 * 1024
        {
            return Err(invalid());
        }
        if plan["change_kind"] != "policy_change" {
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
        Ok(json!({"available":true,"before":self.before,"after":self.after}))
    }
}
