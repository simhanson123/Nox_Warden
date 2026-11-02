//! Original-contract synthetic records for provenance tests; no production trust.
#![allow(dead_code)]

use fw_authority::CoreAccessProvenance;
use fw_contracts::{canonical_hash, hash_bytes};
use serde_json::{Value, json};

pub const NOW: i64 = 1_800_000_000;

pub fn at(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

pub fn requirements() -> Value {
    json!({"schema_version":"f.approval-requirements/v1","profile":"lab_owner",
        "minimum_humans":1,"required_roles":["owner"],"distinct_principals":true,
        "author_may_approve":true,"max_approval_age_seconds":300,"require_webauthn":true,
        "role_policy_hash":hash_bytes(b"core provenance test role policy")})
}

pub fn rehash(plan: &mut Value, provenance: &mut CoreAccessProvenance) {
    provenance.delegation.envelope_hash = canonical_hash(&provenance.envelope).unwrap();
    plan["request_hash"] = canonical_hash(&provenance.request).unwrap().into();
    plan["envelope_hash"] = canonical_hash(&provenance.envelope).unwrap().into();
    plan["delegation_hash"] = canonical_hash(&provenance.delegation).unwrap().into();
    plan["requested_policy_hashes"] = plan["requested_policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|policy| Value::String(canonical_hash(policy).unwrap()))
        .collect();
    plan["request_patch_hash"] = canonical_hash(&plan["requested_policies"]).unwrap().into();
}

pub fn fixture() -> (Value, CoreAccessProvenance) {
    fixture_at(NOW)
}

pub fn fixture_at(now: i64) -> (Value, CoreAccessProvenance) {
    let original: Value = serde_json::from_str(include_str!(
        "../../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap();
    let mut plan = original["plan"].clone();
    let mut provenance: CoreAccessProvenance = serde_json::from_value(json!({
        "schema_version":"fw.core-access-provenance/v1",
        "request_id":plan["request_id"],"request_revision":1,
        "lease_id":"00000000-0000-4000-8000-000000000060",
        "request":original["access_request"],"envelope":original["envelope"],
        "delegation":original["delegation"]
    }))
    .unwrap();
    provenance.request.lease_seconds = 3600;
    provenance.envelope.valid_from = at(now - 60);
    provenance.envelope.valid_until = at(now + 86_400);
    provenance.delegation.valid_from = at(now - 60);
    provenance.delegation.valid_until = at(now + 86_400);
    plan["created_at"] = at(now).into();
    plan["valid_until"] = at(now + 300).into();
    plan["workload_binding_valid_until"] = at(now + 7200).into();
    plan["rollback_authority"]["valid_until"] = at(now + 360).into();
    plan["requested_policies"][0]["lifetime"]["not_before"] = at(now + 60).into();
    plan["requested_policies"][0]["lifetime"]["expires_at"] = at(now + 1860).into();
    plan["approval_requirements_hash"] = canonical_hash(&requirements()).unwrap().into();
    rehash(&mut plan, &mut provenance);
    (plan, provenance)
}
