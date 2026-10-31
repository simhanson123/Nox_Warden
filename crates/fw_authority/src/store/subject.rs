//! Closed, bounded admission of immutable plan and requirements bytes.
//!
//! These checks bind a decision to a complete plan, not to an unverified hash.
//! They do not establish the truth of referenced compiler/gate evidence or a
//! baseline/candidate snapshot. Only a trusted authority importer may register
//! plans; dispatch must independently resolve those objects and semantic proof.
use crate::{
    ApprovalPlanKind, ApprovalRole, AuthorityError, Result, closed, counter, hash_ok, string,
    timestamp, uuid_ok,
};
use fw_contracts::{canonical_bytes, canonical_hash};
use fw_domain::{Action, Policy};
use serde_json::Value;
use std::collections::BTreeSet;

const PLAN_LIMIT: usize = 256 * 1024;
const REQUIREMENTS_LIMIT: usize = 8192;
const GATES: [&str; 8] = [
    "schema",
    "identity",
    "scope",
    "quota",
    "semantic",
    "expiry",
    "capability",
    "baseline",
];

pub(super) struct ValidatedSubject {
    pub plan_id: String,
    pub plan_kind: ApprovalPlanKind,
    pub plan_hash: String,
    pub requirements_hash: String,
    pub author_id: String,
    pub created_at: i64,
    pub valid_until: i64,
    pub max_approval_age_seconds: i64,
    pub author_may_approve: bool,
    pub required_roles: Vec<ApprovalRole>,
    pub profile: String,
    pub authority_epoch: u64,
    pub role_policy_hash: String,
    pub plan_bytes: Vec<u8>,
    pub requirements_bytes: Vec<u8>,
}

fn invalid() -> AuthorityError {
    AuthorityError::Invalid("immutable approval subject")
}

// A caller can construct Value without the bounded JSON parser. Check an upper
// bound before serde copies it; do not allocate an unbounded canonical buffer.
fn bound(value: &Value, remaining: &mut usize, depth: usize) -> Result<()> {
    if depth >= fw_contracts::MAX_DEPTH {
        return Err(invalid());
    }
    let cost = match value {
        Value::String(s) => s.len().checked_mul(6).and_then(|n| n.checked_add(2)),
        Value::Array(v) => v.len().checked_add(2),
        Value::Object(v) => v.len().checked_mul(2).and_then(|n| n.checked_add(2)),
        _ => Some(24),
    }
    .ok_or_else(invalid)?;
    *remaining = remaining.checked_sub(cost).ok_or_else(invalid)?;
    match value {
        Value::Array(values) => {
            for v in values {
                bound(v, remaining, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for (k, v) in values {
                if !k.is_ascii() {
                    return Err(invalid());
                }
                *remaining = remaining
                    .checked_sub(k.len().checked_mul(6).ok_or_else(invalid)?)
                    .ok_or_else(invalid)?;
                bound(v, remaining, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn bounded_canonical(value: &Value, max: usize) -> Result<Vec<u8>> {
    // The conservative preflight budget permits at most max bytes of actual
    // strings/keys while accounting for worst-case escaping before allocating.
    bound(value, &mut max.saturating_mul(6), 0)?;
    let bytes = canonical_bytes(value).map_err(|_| invalid())?;
    if bytes.len() > max {
        return Err(invalid());
    }
    Ok(bytes)
}

fn hash(value: &Value) -> Result<String> {
    canonical_hash(value).map_err(|_| invalid())
}

fn hash_field(value: &Value, field: &str) -> Result<()> {
    if !hash_ok(string(value, field)?) {
        return Err(invalid());
    }
    Ok(())
}

fn integer(value: &Value, field: &str, min: u64, max: u64) -> Result<u64> {
    value[field]
        .as_u64()
        .filter(|n| (min..=max).contains(n))
        .ok_or_else(invalid)
}

fn array(value: &Value, min: usize, max: usize) -> Result<&Vec<Value>> {
    value
        .as_array()
        .filter(|v| (min..=max).contains(&v.len()))
        .ok_or_else(invalid)
}

fn hash_array(value: &Value, min: usize, max: usize) -> Result<BTreeSet<String>> {
    let mut hashes = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for item in array(value, min, max)? {
        let s = item.as_str().filter(|s| hash_ok(s)).ok_or_else(invalid)?;
        if previous.is_some_and(|p| p >= s) || !hashes.insert(s.to_string()) {
            return Err(invalid());
        }
        previous = Some(s);
    }
    Ok(hashes)
}

fn validate_requirements(value: &Value) -> Result<(Vec<ApprovalRole>, i64, bool, String)> {
    closed(
        value,
        &[
            "schema_version",
            "profile",
            "minimum_humans",
            "required_roles",
            "distinct_principals",
            "author_may_approve",
            "max_approval_age_seconds",
            "require_webauthn",
            "role_policy_hash",
        ],
    )?;
    if value["schema_version"] != "f.approval-requirements/v1" || value["require_webauthn"] != true
    {
        return Err(invalid());
    }
    hash_field(value, "role_policy_hash")?;
    let minimum = integer(value, "minimum_humans", 1, 3)?;
    let max_age = integer(value, "max_approval_age_seconds", 60, 86400)? as i64;
    let author = value["author_may_approve"].as_bool().ok_or_else(invalid)?;
    let distinct = value["distinct_principals"].as_bool().ok_or_else(invalid)?;
    let profile = string(value, "profile")?;
    let mut names = BTreeSet::new();
    let mut roles = Vec::new();
    for role in array(&value["required_roles"], 1, 3)? {
        let name = role.as_str().ok_or_else(invalid)?;
        if !names.insert(name) {
            return Err(invalid());
        }
        roles.push(serde_json::from_value(role.clone()).map_err(|_| invalid())?);
    }
    let accepted = match profile {
        "lab_owner" => minimum == 1 && names == BTreeSet::from(["owner"]),
        "team_dual" => {
            minimum == 2
                && names.len() == 2
                && names.contains("network_reviewer")
                && (names.contains("service_reviewer") || names.contains("security_reviewer"))
                && distinct
                && !author
        }
        "team_high_risk" => {
            minimum == 3
                && names
                    == BTreeSet::from(["network_reviewer", "service_reviewer", "security_reviewer"])
                && distinct
                && !author
        }
        _ => false,
    };
    if !accepted {
        return Err(invalid());
    }
    Ok((roles, max_age, author, profile.into()))
}

fn policy(value: &Value, org: &str, project: &str, target: &str) -> Result<Policy> {
    let policy: Policy = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    policy.validate().map_err(|_| invalid())?;
    if policy.org_id != org
        || policy.project_id != project
        || policy.target_id != target
        || policy.normalized().map_err(|_| invalid())? != policy
    {
        return Err(AuthorityError::Binding);
    }
    Ok(policy)
}

fn validate_gates(value: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for gate in array(value, 8, 8)? {
        closed(gate, &["gate_id", "required", "result", "evidence_hash"])?;
        let id = string(gate, "gate_id")?;
        if !GATES.contains(&id)
            || !seen.insert(id)
            || gate["required"] != true
            || gate["result"] != "PASS"
        {
            return Err(invalid());
        }
        hash_field(gate, "evidence_hash")?;
    }
    Ok(())
}

fn validate_core(
    plan: &Value,
    org: &str,
    project: &str,
    target: &str,
    valid_until: i64,
) -> Result<()> {
    if !uuid_ok(string(plan, "workload_binding_id")?) {
        return Err(invalid());
    }
    for field in ["envelope_hash", "delegation_hash", "workload_binding_hash"] {
        hash_field(plan, field)?;
    }
    if timestamp(string(plan, "workload_binding_valid_until")?)? < valid_until {
        return Err(AuthorityError::Time);
    }
    let values = array(&plan["requested_policies"], 1, 256)?;
    let mut prior_id: Option<String> = None;
    let mut hashes = BTreeSet::new();
    for value in values {
        let p = policy(value, org, project, target)?;
        if p.action != Action::Allow
            || p.policy_revision != 1
            || prior_id.as_ref().is_some_and(|id| id >= &p.policy_id)
            || timestamp(p.lifetime.expires_at().ok_or_else(invalid)?)? < valid_until
        {
            return Err(invalid());
        }
        prior_id = Some(p.policy_id);
        hashes.insert(hash(value)?);
    }
    if hashes != hash_array(&plan["requested_policy_hashes"], 1, 256)?
        || plan["request_patch_hash"] != hash(&plan["requested_policies"])?
    {
        return Err(AuthorityError::Binding);
    }
    let effect = &plan["effect_summary"];
    closed(
        effect,
        &[
            "newly_allowed_flow_count",
            "removed_flow_count",
            "effect_hash",
        ],
    )?;
    integer(effect, "newly_allowed_flow_count", 0, i32::MAX as u64)?;
    integer(effect, "removed_flow_count", 0, i32::MAX as u64)?;
    hash_field(effect, "effect_hash")
}

fn validate_change(plan: &Value, org: &str, project: &str, target: &str) -> Result<()> {
    let mut prior_id: Option<String> = None;
    for operation in array(&plan["operations"], 1, 256)? {
        let id = match string(operation, "op")? {
            "add_deny" => {
                closed(operation, &["op", "policy"])?;
                let p = policy(&operation["policy"], org, project, target)?;
                if p.action != Action::Deny || p.policy_revision != 1 {
                    return Err(invalid());
                }
                p.policy_id
            }
            "replace_policy" | "remove_policy" => {
                let replace = operation["op"] == "replace_policy";
                let mut keys = vec![
                    "op",
                    "policy_id",
                    "expected_revision",
                    "expected_policy_hash",
                ];
                if replace {
                    keys.push("replacement");
                }
                closed(operation, &keys)?;
                let id = string(operation, "policy_id")?;
                if !uuid_ok(id) {
                    return Err(invalid());
                }
                let revision = integer(operation, "expected_revision", 1, i32::MAX as u64)?;
                hash_field(operation, "expected_policy_hash")?;
                if replace {
                    let p = policy(&operation["replacement"], org, project, target)?;
                    if p.policy_id != id || u64::from(p.policy_revision) != revision + 1 {
                        return Err(AuthorityError::Binding);
                    }
                }
                id.into()
            }
            _ => return Err(invalid()),
        };
        if prior_id.as_ref().is_some_and(|p| p >= &id) {
            return Err(invalid());
        }
        prior_id = Some(id);
    }
    if plan["request_patch_hash"] != hash(&plan["operations"])? {
        return Err(AuthorityError::Binding);
    }
    let evidence = &plan["candidate_state_ref"];
    closed(
        evidence,
        &["store_id", "object_hash", "media_type", "size_bytes"],
    )?;
    let store_id = string(evidence, "store_id")?;
    if store_id.is_empty()
        || store_id.len() > 64
        || !store_id.as_bytes()[0].is_ascii_lowercase()
        || !store_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        || evidence["object_hash"] != plan["desired_state_hash"]
        || evidence["media_type"] != "application/json"
    {
        return Err(AuthorityError::Binding);
    }
    integer(
        evidence,
        "size_bytes",
        1,
        fw_contracts::MAX_INTERNAL_BYTES as u64,
    )?;
    let effect = &plan["effect_summary"];
    closed(
        effect,
        &[
            "relation",
            "newly_allowed_region_hash",
            "removed_region_hash",
            "counterexample_hashes",
            "analysis_profile",
            "complete",
        ],
    )?;
    if !["equivalent", "restricting", "expanding", "mixed"].contains(&string(effect, "relation")?)
        || effect["complete"] != true
        || effect["analysis_profile"] != "native-union-minus-deny/v1"
    {
        return Err(invalid());
    }
    hash_field(effect, "newly_allowed_region_hash")?;
    hash_field(effect, "removed_region_hash")?;
    hash_array(&effect["counterexample_hashes"], 0, 64)?;
    Ok(())
}

/// `org_id`, `project_id` and `now` must come from the authority, never from an
/// HTTP assertion. `principal_id` in the registered plan is its immutable author;
/// a trusted importer must establish that identity before this function is used.
pub(super) fn validate_subject(
    org_id: &str,
    project_id: &str,
    plan: &Value,
    requirements: &Value,
    now: i64,
) -> Result<ValidatedSubject> {
    let plan_bytes = bounded_canonical(plan, PLAN_LIMIT)?;
    let requirements_bytes = bounded_canonical(requirements, REQUIREMENTS_LIMIT)?;
    let (required_roles, max_approval_age_seconds, author_may_approve, profile) =
        validate_requirements(requirements)?;
    let requirements_hash = fw_contracts::hash_bytes(&requirements_bytes);
    let kind = match (
        string(plan, "schema_version")?,
        string(plan, "change_kind")?,
    ) {
        ("f.plan/v1", "add_access_lease") => ApprovalPlanKind::AddAccessLease,
        ("f.policy-change-plan/v1", "policy_change") => ApprovalPlanKind::PolicyChange,
        _ => return Err(invalid()),
    };
    let mut keys = vec![
        "schema_version",
        "change_kind",
        "plan_id",
        "request_id",
        "request_revision",
        "request_hash",
        "org_id",
        "project_id",
        "target_id",
        "principal_id",
        "created_at",
        "valid_until",
        "request_patch_hash",
        "baseline_hash",
        "desired_state_hash",
        "source_snapshot_hash",
        "target_capability_hash",
        "guardrail_hash",
        "compiler_hash",
        "validator_hash",
        "artifact_hash",
        "validation_report_hash",
        "effect_summary",
        "gates",
        "approval_requirements_hash",
        "probe_spec_hash",
        "authority_epoch",
        "target_generation",
        "confirm_timeout_seconds",
        "rollback_authority",
        "normalization_version",
    ];
    match kind {
        ApprovalPlanKind::AddAccessLease => keys.extend([
            "workload_binding_id",
            "requested_policy_hashes",
            "envelope_hash",
            "delegation_hash",
            "requested_policies",
            "workload_binding_hash",
            "workload_binding_valid_until",
        ]),
        ApprovalPlanKind::PolicyChange => keys.extend(["operations", "candidate_state_ref"]),
    }
    closed(plan, &keys)?;
    for key in [
        "plan_id",
        "request_id",
        "org_id",
        "project_id",
        "target_id",
        "principal_id",
    ] {
        if !uuid_ok(string(plan, key)?) {
            return Err(invalid());
        }
    }
    if !uuid_ok(org_id)
        || !uuid_ok(project_id)
        || plan["org_id"] != org_id
        || plan["project_id"] != project_id
    {
        return Err(AuthorityError::Binding);
    }
    for key in [
        "request_hash",
        "request_patch_hash",
        "baseline_hash",
        "desired_state_hash",
        "source_snapshot_hash",
        "target_capability_hash",
        "guardrail_hash",
        "compiler_hash",
        "validator_hash",
        "artifact_hash",
        "validation_report_hash",
        "approval_requirements_hash",
        "probe_spec_hash",
    ] {
        hash_field(plan, key)?;
    }
    if plan["approval_requirements_hash"] != requirements_hash
        || plan["confirm_timeout_seconds"] != 60
        || plan["normalization_version"] != "f.normalize/nfc-v1"
    {
        return Err(AuthorityError::Binding);
    }
    integer(plan, "request_revision", 1, i32::MAX as u64)?;
    counter(string(plan, "authority_epoch")?)?;
    counter(string(plan, "target_generation")?)?;
    let created_at = timestamp(string(plan, "created_at")?)?;
    let valid_until = timestamp(string(plan, "valid_until")?)?;
    if created_at < 0 || created_at > now || now >= valid_until || valid_until > 253_402_300_799 {
        return Err(AuthorityError::Time);
    }
    validate_gates(&plan["gates"])?;
    let rollback = &plan["rollback_authority"];
    closed(
        rollback,
        &[
            "profile",
            "scope_bound_hash",
            "baseline_hash",
            "artifact_hash",
            "valid_until",
        ],
    )?;
    if !["preserve-current-restrictions", "preapproved-scope"]
        .contains(&string(rollback, "profile")?)
        || rollback["baseline_hash"] != plan["baseline_hash"]
        || timestamp(string(rollback, "valid_until")?)? < valid_until
    {
        return Err(AuthorityError::Binding);
    }
    for field in ["scope_bound_hash", "baseline_hash", "artifact_hash"] {
        hash_field(rollback, field)?;
    }
    let target = string(plan, "target_id")?;
    match kind {
        ApprovalPlanKind::AddAccessLease => {
            validate_core(plan, org_id, project_id, target, valid_until)?
        }
        ApprovalPlanKind::PolicyChange => {
            validate_change(plan, org_id, project_id, target)?;
            // A general change can expand the allow union by removing/narrowing
            // a deny. Team approval then needs all three reviewer roles. This
            // necessary check does not replace trusted high-risk classification:
            // critical targets and management-adjacent changes also require it.
            if matches!(
                plan["effect_summary"]["relation"].as_str(),
                Some("expanding" | "mixed")
            ) && profile == "team_dual"
            {
                return Err(invalid());
            }
        }
    }
    Ok(ValidatedSubject {
        plan_id: string(plan, "plan_id")?.into(),
        plan_kind: kind,
        plan_hash: fw_contracts::hash_bytes(&plan_bytes),
        requirements_hash,
        author_id: string(plan, "principal_id")?.into(),
        created_at,
        valid_until,
        max_approval_age_seconds,
        author_may_approve,
        required_roles,
        profile,
        authority_epoch: counter(string(plan, "authority_epoch")?)?,
        role_policy_hash: string(requirements, "role_policy_hash")?.into(),
        plan_bytes,
        requirements_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixtures() -> (Value, Value, i64) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
        ))
        .unwrap();
        let mut plan = fixture["plan"].clone();
        let requirements = json!({
            "schema_version": "f.approval-requirements/v1", "profile": "lab_owner",
            "minimum_humans": 1, "required_roles": ["owner"], "distinct_principals": true,
            "author_may_approve": true, "max_approval_age_seconds": 300,
            "require_webauthn": true, "role_policy_hash": fw_contracts::hash_bytes(b"test role policy")
        });
        plan["approval_requirements_hash"] = hash(&requirements).unwrap().into();
        plan["request_patch_hash"] = hash(&plan["requested_policies"]).unwrap().into();
        let now = timestamp(string(&plan, "created_at").unwrap()).unwrap();
        (plan, requirements, now)
    }

    fn check(plan: &Value, requirements: &Value, now: i64) -> Result<ValidatedSubject> {
        validate_subject(
            plan["org_id"].as_str().unwrap(),
            plan["project_id"].as_str().unwrap(),
            plan,
            requirements,
            now,
        )
    }

    fn change_fixture() -> (Value, Value, i64) {
        let (mut plan, requirements, now) = fixtures();
        let operations = json!([{
            "op": "remove_policy", "policy_id": plan["requested_policies"][0]["policy_id"],
            "expected_revision": 1, "expected_policy_hash": plan["requested_policy_hashes"][0]
        }]);
        for field in [
            "workload_binding_id",
            "requested_policy_hashes",
            "envelope_hash",
            "delegation_hash",
            "requested_policies",
            "workload_binding_hash",
            "workload_binding_valid_until",
        ] {
            plan.as_object_mut().unwrap().remove(field);
        }
        plan["schema_version"] = "f.policy-change-plan/v1".into();
        plan["change_kind"] = "policy_change".into();
        plan["request_patch_hash"] = hash(&operations).unwrap().into();
        plan["operations"] = operations;
        plan["candidate_state_ref"] = json!({
            "store_id": "authority_evidence", "object_hash": plan["desired_state_hash"],
            "media_type": "application/json", "size_bytes": 1024
        });
        plan["effect_summary"] = json!({
            "relation": "restricting", "newly_allowed_region_hash": fw_contracts::hash_bytes(b"none"),
            "removed_region_hash": fw_contracts::hash_bytes(b"synthetic region"),
            "counterexample_hashes": [], "analysis_profile": "native-union-minus-deny/v1", "complete": true
        });
        (plan, requirements, now)
    }

    #[test]
    fn full_core_and_change_plans_are_locally_hashed_and_projected() {
        // Independently computed with Python json.dumps(sort_keys=True,
        // ensure_ascii=False,separators=(',',':')) + hashlib.sha256. These full
        // objects also pass the preserved original JSON schemas.
        let expected_hashes = [
            "sha256:754bd0480a19282498d3b8c7ba7fc653b6155d657a2d57cb4201ff7b59bc7a5b",
            "sha256:b0d4372317b3346163f117bafac425b968d7611e5e7a3b77d51ee5ef3352335e",
        ];
        for ((plan, requirements, now), expected) in [fixtures(), change_fixture()]
            .into_iter()
            .zip(expected_hashes)
        {
            let subject = check(&plan, &requirements, now).unwrap();
            assert_eq!(subject.plan_hash, expected);
            assert_eq!(
                subject.requirements_hash,
                "sha256:532ed7ca9ddf56a933992ce6f2882e44a0dac76242b37d1f03cda5f5d2adfaa2"
            );
            assert_eq!(subject.plan_hash, hash(&plan).unwrap());
            assert_eq!(subject.requirements_hash, hash(&requirements).unwrap());
            assert_eq!(subject.plan_bytes, canonical_bytes(&plan).unwrap());
            assert_eq!(
                subject.requirements_bytes,
                canonical_bytes(&requirements).unwrap()
            );
            assert_eq!(subject.author_id, plan["principal_id"]);
            assert_eq!(subject.profile, "lab_owner");
            assert_eq!(subject.max_approval_age_seconds, 300);
            assert_eq!(subject.required_roles, [ApprovalRole::Owner]);
        }
    }

    #[test]
    fn incomplete_unknown_and_unbound_subjects_fail() {
        let (plan, requirements, now) = fixtures();
        for field in plan.as_object().unwrap().keys() {
            let mut missing = plan.clone();
            missing.as_object_mut().unwrap().remove(field);
            // Missing tenant fields cannot be supplied by the test wrapper.
            assert!(
                validate_subject(
                    plan["org_id"].as_str().unwrap(),
                    plan["project_id"].as_str().unwrap(),
                    &missing,
                    &requirements,
                    now
                )
                .is_err(),
                "{field}"
            );
        }
        let mut extra = plan.clone();
        extra["approved"] = true.into();
        assert!(check(&extra, &requirements, now).is_err());
        let mut changed = requirements.clone();
        changed["max_approval_age_seconds"] = 400.into();
        assert!(check(&plan, &changed, now).is_err());
        let mut changed = plan.clone();
        changed["requested_policies"][0]["reason"] = "altered policy".into();
        assert!(check(&changed, &requirements, now).is_err());
        assert!(
            validate_subject(
                "99999999-9999-4999-8999-999999999999",
                plan["project_id"].as_str().unwrap(),
                &plan,
                &requirements,
                now
            )
            .is_err()
        );
    }

    #[test]
    fn nested_policies_require_closed_shape_normalization_and_tenant_binding() {
        let (plan, requirements, now) = fixtures();
        for (pointer, value) in [
            ("/requested_policies/0/scope/extra", json!(true)),
            (
                "/requested_policies/0/org_id",
                json!("99999999-9999-4999-8999-999999999999"),
            ),
            ("/requested_policies/0/action", json!("deny")),
            ("/requested_policies/0/reason", json!("e\u{301}")),
            ("/requested_policies/0/policy_revision", json!(2)),
        ] {
            let mut changed = plan.clone();
            if let Some(slot) = changed.pointer_mut(pointer) {
                *slot = value;
            } else {
                changed["requested_policies"][0]["scope"]["extra"] = value;
            }
            changed["request_patch_hash"] = hash(&changed["requested_policies"]).unwrap().into();
            changed["requested_policy_hashes"] =
                json!([hash(&changed["requested_policies"][0]).unwrap()]);
            assert!(check(&changed, &requirements, now).is_err(), "{pointer}");
        }
    }

    #[test]
    fn mandatory_gates_time_and_safe_counters_are_enforced() {
        let (plan, requirements, now) = fixtures();
        for field in ["required", "result", "gate_id", "evidence_hash"] {
            let mut changed = plan.clone();
            changed["gates"][0][field] = match field {
                "required" => false.into(),
                "result" => "UNKNOWN".into(),
                "gate_id" => changed["gates"][1]["gate_id"].clone(),
                _ => "not a hash".into(),
            };
            assert!(check(&changed, &requirements, now).is_err());
        }
        assert!(check(&plan, &requirements, now - 1).is_err());
        assert!(
            check(
                &plan,
                &requirements,
                timestamp(string(&plan, "valid_until").unwrap()).unwrap()
            )
            .is_err()
        );
        for value in ["01", "18446744073709551616", "-1"] {
            let mut changed = plan.clone();
            changed["authority_epoch"] = value.into();
            assert!(check(&changed, &requirements, now).is_err());
        }
    }

    #[test]
    fn requirement_profiles_enforce_independent_human_roles() {
        let (_, mut requirements, _) = fixtures();
        requirements["profile"] = "team_dual".into();
        requirements["minimum_humans"] = 2.into();
        requirements["required_roles"] = json!(["network_reviewer", "security_reviewer"]);
        requirements["author_may_approve"] = false.into();
        assert!(validate_requirements(&requirements).is_ok());
        for field in [
            "author_may_approve",
            "distinct_principals",
            "require_webauthn",
        ] {
            let mut bad = requirements.clone();
            bad[field] = (!bad[field].as_bool().unwrap()).into();
            assert!(validate_requirements(&bad).is_err());
        }
        requirements["profile"] = "team_high_risk".into();
        assert!(validate_requirements(&requirements).is_err());
        requirements["minimum_humans"] = 3.into();
        requirements["required_roles"] =
            json!(["network_reviewer", "service_reviewer", "security_reviewer"]);
        assert!(validate_requirements(&requirements).is_ok());
        requirements["required_roles"] =
            json!(["network_reviewer", "network_reviewer", "security_reviewer"]);
        assert!(validate_requirements(&requirements).is_err());
    }

    #[test]
    fn policy_change_binds_operations_and_full_candidate_reference() {
        let (plan, requirements, now) = change_fixture();
        for pointer in [
            "/operations/0/expected_policy_hash",
            "/candidate_state_ref/object_hash",
        ] {
            let mut changed = plan.clone();
            *changed.pointer_mut(pointer).unwrap() = fw_contracts::hash_bytes(b"tampered").into();
            assert!(check(&changed, &requirements, now).is_err());
        }
        let mut changed = plan.clone();
        changed["operations"]
            .as_array_mut()
            .unwrap()
            .push(plan["operations"][0].clone());
        changed["request_patch_hash"] = hash(&changed["operations"]).unwrap().into();
        assert!(check(&changed, &requirements, now).is_err());
        for (field, value) in [("complete", json!(false)), ("relation", json!("unknown"))] {
            let mut changed = plan.clone();
            changed["effect_summary"][field] = value;
            assert!(check(&changed, &requirements, now).is_err());
        }
    }

    #[test]
    fn known_team_expansion_requires_high_risk_reviewers() {
        let (mut plan, mut requirements, now) = change_fixture();
        requirements["profile"] = "team_dual".into();
        requirements["minimum_humans"] = 2.into();
        requirements["required_roles"] = json!(["network_reviewer", "security_reviewer"]);
        requirements["author_may_approve"] = false.into();
        plan["approval_requirements_hash"] = hash(&requirements).unwrap().into();
        assert!(check(&plan, &requirements, now).is_ok());
        for relation in ["expanding", "mixed"] {
            plan["effect_summary"]["relation"] = relation.into();
            assert!(check(&plan, &requirements, now).is_err());
        }
        requirements["profile"] = "team_high_risk".into();
        requirements["minimum_humans"] = 3.into();
        requirements["required_roles"] =
            json!(["network_reviewer", "service_reviewer", "security_reviewer"]);
        plan["approval_requirements_hash"] = hash(&requirements).unwrap().into();
        assert!(check(&plan, &requirements, now).is_ok());
    }

    #[test]
    fn constructed_values_cannot_skip_size_depth_or_numeric_bounds() {
        let (mut plan, requirements, now) = fixtures();
        plan["oversized"] = "x".repeat(PLAN_LIMIT + 1).into();
        assert!(check(&plan, &requirements, now).is_err());
        let mut value = Value::Null;
        for _ in 0..fw_contracts::MAX_DEPTH {
            value = json!([value]);
        }
        assert!(bounded_canonical(&value, PLAN_LIMIT).is_err());
        assert!(bounded_canonical(&json!(1.5), PLAN_LIMIT).is_err());
        assert!(bounded_canonical(&json!(u64::MAX), PLAN_LIMIT).is_err());
    }
}
