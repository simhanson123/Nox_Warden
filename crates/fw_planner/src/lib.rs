//! Deterministic composition primitives. Full semantic-region proofs are not
//! inferred from operation names. Unproved changes remain UNKNOWN and cannot dispatch.
mod semantic;
use fw_contracts::canonical_hash;
use fw_domain::{Action, Policy, timestamp, validate_uuid};
pub use semantic::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PlanError(pub &'static str);
pub type Result<T> = std::result::Result<T, PlanError>;
fn hash<T: Serialize>(v: &T) -> Result<String> {
    canonical_hash(v).map_err(|_| PlanError("canonicalization failed"))
}
fn hash_valid(s: &str) -> bool {
    s.len() == 71
        && s.starts_with("sha256:")
        && s[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyAssociation {
    pub policy_hash: String,
    pub lease_id: Option<String>,
    pub request_id: String,
    pub authority_basis_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateIr {
    pub schema_version: String,
    pub target_id: String,
    pub platform: String,
    pub profile: String,
    pub management_baseline_hash: String,
    pub policies: Vec<Policy>,
    pub associations: Vec<PolicyAssociation>,
    pub tombstone_hashes: Vec<String>,
    pub source_snapshot_hash: String,
    pub target_capability_hash: String,
    pub normalization_version: String,
}
impl StateIr {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "f.state-ir/v1"
            || self.normalization_version != "f.normalize/nfc-v1"
            || !["linux", "windows", "macos"].contains(&self.platform.as_str())
            || !["lab", "host", "routed_gateway"].contains(&self.profile.as_str())
        {
            return Err(PlanError("unsupported StateIR schema or profile"));
        }
        validate_uuid(&self.target_id).map_err(|_| PlanError("invalid target"))?;
        if self.profile == "routed_gateway" && self.platform != "linux" {
            return Err(PlanError("unsupported routed gateway"));
        }
        for h in [
            &self.management_baseline_hash,
            &self.source_snapshot_hash,
            &self.target_capability_hash,
        ] {
            if !hash_valid(h) {
                return Err(PlanError("invalid state hash"));
            }
        }
        if self.policies.len() > 4096
            || self.associations.len() != self.policies.len()
            || self.tombstone_hashes.len() > 4096
        {
            return Err(PlanError("state cardinality"));
        }
        let mut ids = BTreeSet::new();
        let mut hashes = BTreeMap::new();
        let mut tenant = None;
        for p in &self.policies {
            p.validate().map_err(|_| PlanError("invalid policy"))?;
            if p.target_id != self.target_id || !ids.insert(&p.policy_id) {
                return Err(PlanError("duplicate policy or wrong target"));
            }
            let t = (&p.org_id, &p.project_id);
            if tenant.is_some_and(|old| old != t) {
                return Err(PlanError("cross tenant state"));
            }
            tenant = Some(t);
            hashes.insert(hash(p)?, p);
        }
        let mut associated = BTreeSet::new();
        for a in &self.associations {
            let p = hashes
                .get(&a.policy_hash)
                .ok_or(PlanError("dangling association"))?;
            if !associated.insert(&a.policy_hash)
                || !hash_valid(&a.authority_basis_hash)
                || validate_uuid(&a.request_id).is_err()
            {
                return Err(PlanError("invalid association"));
            }
            if (p.action == Action::Allow) != a.lease_id.is_some()
                || a.lease_id
                    .as_ref()
                    .is_some_and(|id| validate_uuid(id).is_err())
            {
                return Err(PlanError("action/lease association mismatch"));
            }
        }
        if self.tombstone_hashes.iter().any(|h| !hash_valid(h))
            || self.tombstone_hashes.iter().collect::<BTreeSet<_>>().len()
                != self.tombstone_hashes.len()
        {
            return Err(PlanError("invalid tombstones"));
        }
        Ok(())
    }
    pub fn normalized(&self) -> Result<Self> {
        self.validate()?;
        let mut state = self.clone();
        state.policies = state
            .policies
            .iter()
            .map(|p| p.normalized().map_err(|_| PlanError("normalization")))
            .collect::<Result<_>>()?;
        // Associations refer to exact normalized policy bytes. Reject rather than
        // silently rebind authority to a different policy representation.
        state.policies.sort_by(|a, b| {
            (&a.policy_id, a.policy_revision).cmp(&(&b.policy_id, b.policy_revision))
        });
        state
            .associations
            .sort_by(|a, b| a.policy_hash.cmp(&b.policy_hash));
        state.tombstone_hashes.sort();
        state.validate()?;
        Ok(state)
    }
    pub fn state_hash(&self) -> Result<String> {
        hash(&self.normalized()?)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyMutation {
    AddDeny {
        policy: Box<Policy>,
    },
    ReplacePolicy {
        policy_id: String,
        expected_revision: u32,
        expected_policy_hash: String,
        replacement: Box<Policy>,
    },
    RemovePolicy {
        policy_id: String,
        expected_revision: u32,
        expected_policy_hash: String,
    },
}
impl PolicyMutation {
    fn id(&self) -> &str {
        match self {
            Self::AddDeny { policy } => &policy.policy_id,
            Self::ReplacePolicy { policy_id, .. } | Self::RemovePolicy { policy_id, .. } => {
                policy_id
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Relation {
    Equivalent,
    Restricting,
    Expanding,
    Mixed,
    Unknown,
}
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub baseline_hash: String,
    pub request_patch_hash: String,
    pub desired_state_hash: String,
    pub state: StateIr,
    pub relation: Relation,
    pub semantic_complete: bool,
    pub semantic_diff: SemanticDiff,
}

/// Apply a patch to the full state; untouched deny and allow policies survive.
/// Associations must be supplied only for added/replaced revisions, pre-bound to
/// immutable authority-basis hashes. Tombstoned policy IDs are authority input.
pub fn compose_policy_change(
    baseline: &StateIr,
    operations: &[PolicyMutation],
    associations: &[PolicyAssociation],
    tombstoned_ids: &BTreeSet<String>,
) -> Result<Candidate> {
    baseline.validate()?;
    if operations.is_empty() || operations.len() > 256 {
        return Err(PlanError("patch size"));
    }
    let mut ops = operations.to_vec();
    ops.sort_by(|a, b| a.id().cmp(b.id()));
    if ops.windows(2).any(|w| w[0].id() == w[1].id()) {
        return Err(PlanError("multiple operations for same policy"));
    }
    let baseline_hash = baseline.state_hash()?;
    let mut state = baseline.normalized()?;
    let mut policy_map: BTreeMap<_, _> = state
        .policies
        .iter()
        .map(|p| (p.policy_id.clone(), p.clone()))
        .collect();
    let mut assoc_map: BTreeMap<_, _> = state
        .associations
        .iter()
        .map(|a| (a.policy_hash.clone(), a.clone()))
        .collect();
    let supplied: BTreeMap<_, _> = associations
        .iter()
        .map(|a| (a.policy_hash.clone(), a.clone()))
        .collect();
    if supplied.len() != associations.len() {
        return Err(PlanError("duplicate supplied association"));
    }
    let mut used = BTreeSet::new();
    for op in &ops {
        match op {
            PolicyMutation::AddDeny { policy } => {
                if policy.action != Action::Deny
                    || policy.policy_revision != 1
                    || policy_map.contains_key(&policy.policy_id)
                    || tombstoned_ids.contains(&policy.policy_id)
                {
                    return Err(PlanError(
                        "add_deny cannot add allow, reuse, or revive policy",
                    ));
                }
                let h = hash(policy)?;
                let a = supplied
                    .get(&h)
                    .ok_or(PlanError("missing authority association"))?;
                used.insert(h.clone());
                assoc_map.insert(h, a.clone());
                policy_map.insert(policy.policy_id.clone(), *policy.clone());
            }
            PolicyMutation::ReplacePolicy {
                policy_id,
                expected_revision,
                expected_policy_hash,
                replacement,
            } => {
                let old = policy_map
                    .get(policy_id)
                    .ok_or(PlanError("missing policy"))?;
                let old_hash = hash(old)?;
                if old.policy_revision != *expected_revision || old_hash != *expected_policy_hash {
                    return Err(PlanError("stale baseline policy"));
                }
                if replacement.policy_id != old.policy_id
                    || replacement.policy_revision
                        != old
                            .policy_revision
                            .checked_add(1)
                            .ok_or(PlanError("revision overflow"))?
                    || replacement.org_id != old.org_id
                    || replacement.project_id != old.project_id
                    || replacement.target_id != old.target_id
                    || replacement.owner_id != old.owner_id
                    || replacement.action != old.action
                {
                    return Err(PlanError("replacement identity/action mismatch"));
                }
                if old.action == Action::Allow
                    && (!replacement
                        .scope
                        .is_subset_of(&old.scope)
                        .map_err(|_| PlanError("scope"))?
                        || timestamp(replacement.lifetime.not_before())
                            .map_err(|_| PlanError("time"))?
                            < timestamp(old.lifetime.not_before())
                                .map_err(|_| PlanError("time"))?
                        || replacement
                            .lifetime
                            .expires_at()
                            .ok_or(PlanError("lease"))?
                            > old.lifetime.expires_at().ok_or(PlanError("lease"))?)
                {
                    return Err(PlanError("general route cannot expand allow"));
                }
                let h = hash(replacement)?;
                let a = supplied.get(&h).ok_or(PlanError("missing association"))?;
                if a.lease_id
                    != assoc_map
                        .get(&old_hash)
                        .ok_or(PlanError("old association"))?
                        .lease_id
                {
                    return Err(PlanError("replacement cannot change lease"));
                }
                used.insert(h.clone());
                assoc_map.remove(&old_hash);
                assoc_map.insert(h, a.clone());
                policy_map.insert(policy_id.clone(), *replacement.clone());
            }
            PolicyMutation::RemovePolicy {
                policy_id,
                expected_revision,
                expected_policy_hash,
            } => {
                let p = policy_map
                    .get(policy_id)
                    .ok_or(PlanError("missing policy"))?;
                let h = hash(p)?;
                if p.policy_revision != *expected_revision || h != *expected_policy_hash {
                    return Err(PlanError("stale removal"));
                }
                assoc_map.remove(&h);
                policy_map.remove(policy_id);
            }
        }
    }
    if used.len() != supplied.len() {
        return Err(PlanError("unused association"));
    }
    state.policies = policy_map.into_values().collect();
    state.associations = assoc_map.into_values().collect();
    state = state.normalized()?;
    let desired_state_hash = state.state_hash()?;
    // Prove business-packet regions by exhaustive finite partition. Native
    // conntrack/reply and management-baseline qualification remain separate gates.
    let proof = semantic_diff(baseline, &state, DEFAULT_MAX_CELLS)?;
    Ok(Candidate {
        baseline_hash,
        request_patch_hash: hash(&ops)?,
        desired_state_hash,
        state,
        relation: proof.relation.clone(),
        semantic_complete: proof.complete,
        semantic_diff: proof,
    })
}

pub fn compose_access_patch(
    baseline: &StateIr,
    policies: &[Policy],
    associations: &[PolicyAssociation],
    tombstoned_ids: &BTreeSet<String>,
) -> Result<Candidate> {
    baseline.validate()?;
    if policies.is_empty() || policies.len() > 256 || associations.len() != policies.len() {
        return Err(PlanError("access patch cardinality"));
    }
    let mut state = baseline.normalized()?;
    let mut ids: BTreeSet<_> = state.policies.iter().map(|p| p.policy_id.clone()).collect();
    let mut patch = policies.to_vec();
    patch.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
    for p in &patch {
        if p.action != Action::Allow
            || p.policy_revision != 1
            || !ids.insert(p.policy_id.clone())
            || tombstoned_ids.contains(&p.policy_id)
        {
            return Err(PlanError("invalid access patch policy"));
        }
        p.validate().map_err(|_| PlanError("invalid allow"))?;
    }
    state.policies.extend(patch.iter().cloned());
    state.associations.extend_from_slice(associations);
    state = state.normalized()?;
    let proof = semantic_diff(baseline, &state, DEFAULT_MAX_CELLS)?;
    Ok(Candidate {
        baseline_hash: baseline.state_hash()?,
        request_patch_hash: hash(&patch)?,
        desired_state_hash: state.state_hash()?,
        state,
        relation: proof.relation.clone(),
        semantic_complete: proof.complete,
        semantic_diff: proof,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub gate_id: String,
    pub required: bool,
    pub result: String,
    pub evidence_hash: String,
}
pub fn ensure_dispatchable(gates: &[Gate], relation: &Relation, complete: bool) -> Result<()> {
    let required = [
        "schema",
        "identity",
        "scope",
        "quota",
        "semantic",
        "expiry",
        "capability",
        "baseline",
    ];
    if !complete || *relation == Relation::Unknown || gates.len() != required.len() {
        return Err(PlanError("incomplete semantic proof or gates"));
    }
    let mut seen = BTreeSet::new();
    for gate in gates {
        if !required.contains(&gate.gate_id.as_str())
            || !seen.insert(&gate.gate_id)
            || !gate.required
            || gate.result != "PASS"
            || !hash_valid(&gate.evidence_hash)
        {
            return Err(PlanError("required gate is not PASS"));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests;
