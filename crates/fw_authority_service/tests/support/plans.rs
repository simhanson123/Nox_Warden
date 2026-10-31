use super::authenticator::PRINCIPAL;
use serde_json::{Value, json};
pub const ORG: &str = "22222222-2222-4222-8222-222222222222";
pub const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
pub const PLAN: &str = "44444444-4444-4444-8444-444444444444";
pub const OTHER: &str = "99999999-9999-4999-8999-999999999999";

fn time(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

pub fn requirements() -> Value {
    json!({
        "schema_version": "f.approval-requirements/v1",
        "profile": "lab_owner", "minimum_humans": 1,
        "required_roles": ["owner"], "distinct_principals": true,
        "author_may_approve": true, "max_approval_age_seconds": 3600,
        "require_webauthn": true,
        "role_policy_hash": fw_contracts::hash_bytes(b"independently configured role policy")
    })
}

fn plan(requirements: &Value, now: i64) -> Value {
    let hash = fw_contracts::hash_bytes(b"synthetic immutable plan evidence");
    let operations = json!([{
        "op": "remove_policy", "policy_id": OTHER, "expected_revision": 1,
        "expected_policy_hash": hash
    }]);
    let gates: Vec<Value> = [
        "schema",
        "identity",
        "scope",
        "quota",
        "semantic",
        "expiry",
        "capability",
        "baseline",
    ]
    .into_iter()
    .map(|gate| {
        json!({
            "gate_id": gate, "required": true, "result": "PASS", "evidence_hash": hash
        })
    })
    .collect();
    json!({
        "schema_version": "f.policy-change-plan/v1", "change_kind": "policy_change",
        "plan_id": PLAN, "request_id": OTHER, "request_revision": 1, "request_hash": hash,
        "org_id": ORG, "project_id": PROJECT, "target_id": OTHER, "principal_id": PRINCIPAL,
        "created_at": time(now), "valid_until": time(now + 3600),
        "request_patch_hash": fw_contracts::canonical_hash(&operations).unwrap(),
        "operations": operations,
        "baseline_hash": hash, "desired_state_hash": hash,
        "candidate_state_ref": {
            "store_id": "authority_test", "object_hash": hash,
            "media_type": "application/json", "size_bytes": 128
        },
        "source_snapshot_hash": hash, "target_capability_hash": hash,
        "guardrail_hash": hash, "compiler_hash": hash, "validator_hash": hash,
        "artifact_hash": hash, "validation_report_hash": hash,
        "effect_summary": {
            "relation": "restricting", "newly_allowed_region_hash": hash,
            "removed_region_hash": hash, "counterexample_hashes": [],
            "analysis_profile": "native-union-minus-deny/v1", "complete": true
        },
        "gates": gates,
        "approval_requirements_hash": fw_contracts::canonical_hash(requirements).unwrap(),
        "probe_spec_hash": hash, "authority_epoch": "1", "target_generation": "1",
        "confirm_timeout_seconds": 60,
        "rollback_authority": {
            "profile": "preserve-current-restrictions", "scope_bound_hash": hash,
            "baseline_hash": hash, "artifact_hash": hash, "valid_until": time(now + 3600)
        },
        "normalization_version": "f.normalize/nfc-v1"
    })
}

pub fn complete_plan(now: i64) -> (Value, Value, fw_authority_service::ReviewEvidence) {
    let requirements = requirements();
    let mut plan = plan(&requirements, now);
    let original: Value = serde_json::from_str(include_str!(
        "../../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap();
    let mut policy = original["requested_policies"][0].clone();
    policy["policy_id"] = json!(OTHER);
    policy["org_id"] = json!(ORG);
    policy["project_id"] = json!(PROJECT);
    policy["target_id"] = json!(OTHER);
    policy["owner_id"] = json!(PRINCIPAL);
    policy["reason"] = json!("Isolated authority review demonstration");
    policy["lifetime"] = json!({"kind":"lease","not_before":time(now),"expires_at":time(now+1800)});
    let hash =
        fw_contracts::hash_bytes(b"synthetic local review artifact; not native qualification");
    let before:fw_planner::StateIr=serde_json::from_value(json!({
        "schema_version":"f.state-ir/v1","target_id":OTHER,"platform":"linux","profile":"lab",
        "management_baseline_hash":hash,"policies":[policy],
        "associations":[{"policy_hash":fw_contracts::canonical_hash(&policy).unwrap(),"lease_id":PLAN,"request_id":OTHER,"authority_basis_hash":hash}],
        "tombstone_hashes":[],"source_snapshot_hash":hash,"target_capability_hash":hash,
        "normalization_version":"f.normalize/nfc-v1"
    })).unwrap();
    let before = before.normalized().unwrap();
    plan["operations"] = json!([{"op":"remove_policy","policy_id":OTHER,"expected_revision":1,"expected_policy_hash":fw_contracts::canonical_hash(&policy).unwrap()}]);
    let operations: Vec<fw_planner::PolicyMutation> =
        serde_json::from_value(plan["operations"].clone()).unwrap();
    let result = fw_planner::compose_policy_change(
        &before,
        &operations,
        &[],
        &std::collections::BTreeSet::new(),
    )
    .unwrap();
    assert!(result.semantic_complete);
    plan["baseline_hash"] = json!(result.baseline_hash);
    plan["desired_state_hash"] = json!(result.desired_state_hash);
    plan["request_patch_hash"] = json!(result.request_patch_hash);
    plan["source_snapshot_hash"] = json!(hash);
    plan["target_capability_hash"] = json!(hash);
    plan["candidate_state_ref"]["object_hash"] = json!(result.desired_state_hash);
    plan["candidate_state_ref"]["size_bytes"] =
        json!(fw_contracts::canonical_bytes(&result.state).unwrap().len());
    plan["rollback_authority"]["baseline_hash"] = plan["baseline_hash"].clone();
    plan["effect_summary"]["relation"] = serde_json::to_value(result.relation).unwrap();
    plan["effect_summary"]["newly_allowed_region_hash"] =
        json!(result.semantic_diff.newly_allowed_region_hash);
    plan["effect_summary"]["removed_region_hash"] = json!(result.semantic_diff.removed_region_hash);
    (
        plan,
        requirements,
        fw_authority_service::ReviewEvidence {
            before,
            after: result.state,
        },
    )
}
