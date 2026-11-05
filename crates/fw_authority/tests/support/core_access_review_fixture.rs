//! Structural core review fixtures. No workload, bootstrap or signing authority.
#![allow(dead_code)]

#[path = "core_access_fixture.rs"]
pub mod core;

use fw_authority::{CoreAccessLeaseWindow, CoreAccessProvenance};
use fw_contracts::{canonical_hash, hash_bytes};
use fw_domain::Policy;
use fw_planner::{PolicyAssociation, PolicyReviewEvidence, StateIr, compose_access_patch};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const NOW: i64 = core::NOW;

pub fn fixture() -> (
    Value,
    Value,
    PolicyReviewEvidence,
    CoreAccessProvenance,
    CoreAccessLeaseWindow,
) {
    fixture_at(NOW, 0)
}

pub fn fixture_at(
    now: i64,
    shift: i64,
) -> (
    Value,
    Value,
    PolicyReviewEvidence,
    CoreAccessProvenance,
    CoreAccessLeaseWindow,
) {
    let (mut plan, mut provenance) = core::fixture_at(now);
    for policy in plan["requested_policies"].as_array_mut().unwrap() {
        policy["lifetime"]["not_before"] = core::at(now + shift).into();
        policy["lifetime"]["expires_at"] =
            core::at(now + shift + provenance.request.lease_seconds as i64).into();
        let normalized: Policy = serde_json::from_value(policy.clone()).unwrap();
        *policy = serde_json::to_value(normalized.normalized().unwrap()).unwrap();
    }
    core::rehash(&mut plan, &mut provenance);
    let review = rebuild(&mut plan, &provenance);
    let window = window(&plan, &provenance);
    (plan, core::requirements(), review, provenance, window)
}

pub fn rebuild(plan: &mut Value, provenance: &CoreAccessProvenance) -> PolicyReviewEvidence {
    let before: StateIr = serde_json::from_value(json!({
        "schema_version":"f.state-ir/v1", "target_id":plan["target_id"],
        "platform":"linux", "profile":"lab",
        "management_baseline_hash":hash_bytes(b"fixed-window test management baseline"),
        "policies":[], "associations":[], "tombstone_hashes":[],
        "source_snapshot_hash":plan["source_snapshot_hash"],
        "target_capability_hash":plan["target_capability_hash"],
        "normalization_version":"f.normalize/nfc-v1"
    }))
    .unwrap();
    let before = before.normalized().unwrap();
    let policies: Vec<Policy> = serde_json::from_value(plan["requested_policies"].clone()).unwrap();
    let basis = fw_planner::core_access_authority_basis_hash(plan).unwrap();
    let associations = policies
        .iter()
        .map(|policy| PolicyAssociation {
            policy_hash: canonical_hash(policy).unwrap(),
            lease_id: Some(provenance.lease_id.clone()),
            request_id: provenance.request_id.clone(),
            authority_basis_hash: basis.clone(),
        })
        .collect::<Vec<_>>();
    let candidate =
        compose_access_patch(&before, &policies, &associations, &BTreeSet::new()).unwrap();
    plan["baseline_hash"] = candidate.baseline_hash.into();
    plan["desired_state_hash"] = candidate.desired_state_hash.into();
    plan["request_patch_hash"] = candidate.request_patch_hash.into();
    plan["rollback_authority"]["baseline_hash"] = plan["baseline_hash"].clone();
    plan["effect_summary"] = serde_json::to_value(
        fw_planner::core_access_effect_summary(&before, &candidate.state).unwrap(),
    )
    .unwrap();
    PolicyReviewEvidence {
        before,
        after: candidate.state,
    }
}

pub fn window(plan: &Value, provenance: &CoreAccessProvenance) -> CoreAccessLeaseWindow {
    serde_json::from_value(json!({
        "schema_version":"fw.core-access-lease-window/v1",
        "org_id":plan["org_id"], "project_id":plan["project_id"],
        "target_id":plan["target_id"], "request_id":provenance.request_id,
        "request_revision":provenance.request_revision,
        "request_hash":canonical_hash(&provenance.request).unwrap(),
        "provenance_hash":canonical_hash(provenance).unwrap(),
        "lease_id":provenance.lease_id,
        "not_before":plan["requested_policies"][0]["lifetime"]["not_before"],
        "expires_at":plan["requested_policies"][0]["lifetime"]["expires_at"]
    }))
    .unwrap()
}
