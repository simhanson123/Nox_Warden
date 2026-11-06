use super::*;
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use fw_domain::{Decision, Flow, Lifetime, Transport, evaluate, timestamp};
use serde_json::{Value, json};

const LEASE: &str = "00000000-0000-4000-8000-000000000060";
const OTHER: &str = "00000000-0000-4000-8000-000000000099";

fn original() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap()
}

fn policy() -> fw_domain::Policy {
    serde_json::from_value(original()["plan"]["requested_policies"][0].clone()).unwrap()
}

fn fixture(
    baseline_policies: Vec<fw_domain::Policy>,
    mut patch: Vec<fw_domain::Policy>,
) -> (Value, PolicyReviewEvidence) {
    let mut plan = original()["plan"].clone();
    let before = StateIr {
        schema_version: "f.state-ir/v1".into(),
        target_id: plan["target_id"].as_str().unwrap().into(),
        platform: "linux".into(),
        profile: "routed_gateway".into(),
        management_baseline_hash: hash_bytes(b"core review management"),
        associations: baseline_policies
            .iter()
            .map(|policy| PolicyAssociation {
                policy_hash: canonical_hash(policy).unwrap(),
                lease_id: (policy.action == Action::Allow).then(|| OTHER.into()),
                request_id: OTHER.into(),
                authority_basis_hash: hash_bytes(b"retained baseline authority"),
            })
            .collect(),
        policies: baseline_policies,
        tombstone_hashes: vec![hash_bytes(b"retained tombstone")],
        source_snapshot_hash: plan["source_snapshot_hash"].as_str().unwrap().into(),
        target_capability_hash: plan["target_capability_hash"].as_str().unwrap().into(),
        normalization_version: "f.normalize/nfc-v1".into(),
    }
    .normalized()
    .unwrap();
    patch.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
    plan["requested_policies"] = serde_json::to_value(&patch).unwrap();
    let mut hashes = patch
        .iter()
        .map(|policy| canonical_hash(policy).unwrap())
        .collect::<Vec<_>>();
    hashes.sort();
    plan["requested_policy_hashes"] = json!(hashes);
    plan["request_patch_hash"] = canonical_hash(&patch).unwrap().into();
    let basis = core_access_authority_basis_hash(&plan).unwrap();
    let associations = patch
        .iter()
        .map(|policy| PolicyAssociation {
            policy_hash: canonical_hash(policy).unwrap(),
            lease_id: Some(LEASE.into()),
            request_id: plan["request_id"].as_str().unwrap().into(),
            authority_basis_hash: basis.clone(),
        })
        .collect::<Vec<_>>();
    let after = compose_access_patch(&before, &patch, &associations, &BTreeSet::new())
        .unwrap()
        .state;
    let evidence = PolicyReviewEvidence { before, after };
    refresh(&mut plan, &evidence);
    (plan, evidence)
}

fn refresh(plan: &mut Value, evidence: &PolicyReviewEvidence) {
    plan["baseline_hash"] = evidence.before.state_hash().unwrap().into();
    plan["desired_state_hash"] = evidence.after.state_hash().unwrap().into();
    plan["effect_summary"] = serde_json::to_value(
        core_access_effect_summary(&evidence.before, &evidence.after).unwrap(),
    )
    .unwrap();
}

fn second_policy() -> fw_domain::Policy {
    let mut second = policy();
    second.policy_id = OTHER.into();
    second.scope.transport = Transport::Udp {
        destination_ports: vec![fw_domain::PortRange {
            start: 5432,
            end: 5432,
        }],
    };
    second
}

#[test]
fn core_review_binds_full_state_and_one_structural_lease_without_changing_evidence_bytes() {
    let (plan, evidence) = fixture(vec![], vec![policy()]);
    let verified = evidence.verify(&plan).unwrap();
    assert_eq!(verified.plan_hash(), canonical_hash(&plan).unwrap());
    assert_eq!(
        verified.canonical_bytes(),
        canonical_bytes(&evidence).unwrap()
    );
    assert_eq!(verified.evidence_hash(), canonical_hash(&evidence).unwrap());
    let binding = verified.core_binding().unwrap();
    assert_eq!(binding.lease_id(), LEASE);
    assert_eq!(binding.request_id(), plan["request_id"]);
    assert_eq!(
        binding.authority_basis_hash(),
        core_access_authority_basis_hash(&plan).unwrap()
    );
    assert_eq!(
        binding.not_before(),
        timestamp("2026-10-30T09:00:00Z").unwrap()
    );
    assert_eq!(
        binding.expires_at(),
        timestamp("2026-10-30T09:30:00Z").unwrap()
    );
    assert_eq!(binding.lease_seconds(), 1800);
    let bytes: Value = serde_json::from_slice(verified.canonical_bytes()).unwrap();
    assert_eq!(
        bytes
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["after", "before"]
    );
    for unsupported_core_field in ["operations", "candidate_state_ref"] {
        assert!(plan.get(unsupported_core_field).is_none());
    }
}

#[test]
fn exact_core_effect_has_independent_golden_counts_and_digest() {
    let (plan, evidence) = fixture(vec![], vec![policy()]);
    let summary = core_access_effect_summary(&evidence.before, &evidence.after).unwrap();
    assert_eq!(summary.newly_allowed_flow_count, 1);
    assert_eq!(summary.removed_flow_count, 0);
    // Independently calculated from the single canonical region tuple and an
    // empty removed-region array, using the documented versioned digest record.
    assert_eq!(
        summary.effect_hash,
        "sha256:d39479437e196371fb3d64e3b525e0114e3e31341922f8ae139c8a87c43e0637"
    );
    assert_eq!(
        plan["effect_summary"],
        serde_json::to_value(&summary).unwrap()
    );
    let reversed = core_access_effect_summary(&evidence.after, &evidence.before).unwrap();
    assert_eq!(reversed.newly_allowed_flow_count, 0);
    assert_eq!(reversed.removed_flow_count, 1);
    let old_diff =
        serde_json::to_value(semantic_diff(&evidence.before, &evidence.after, 4096).unwrap())
            .unwrap();
    assert_eq!(
        old_diff
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "complete",
            "evaluated_cells",
            "newly_allowed_region_hash",
            "reason",
            "relation",
            "removed_region_hash"
        ]
    );
}

#[test]
fn preserved_deny_blocks_new_allow_and_existing_other_lease_survives() {
    let mut deny = policy();
    deny.policy_id = "00000000-0000-4000-8000-000000000090".into();
    deny.action = Action::Deny;
    deny.lifetime = Lifetime::Review {
        not_before: "2026-10-30T09:00:00Z".into(),
        review_at: "2026-10-31T09:00:00Z".into(),
    };
    let mut old_allow = policy();
    old_allow.policy_id = "00000000-0000-4000-8000-000000000091".into();
    old_allow.scope.transport = Transport::Udp {
        destination_ports: vec![fw_domain::PortRange {
            start: 5432,
            end: 5432,
        }],
    };
    let (plan, evidence) = fixture(vec![deny.clone(), old_allow.clone()], vec![policy()]);
    evidence.verify(&plan).unwrap();
    assert_eq!(plan["effect_summary"]["newly_allowed_flow_count"], 0);
    assert!(evidence.after.policies.contains(&deny));
    assert!(evidence.after.policies.contains(&old_allow));
    assert_eq!(
        evidence.before.tombstone_hashes,
        evidence.after.tombstone_hashes
    );
    for association in &evidence.before.associations {
        assert!(evidence.after.associations.contains(association));
    }
    let p = policy();
    let flow = Flow {
        org_id: p.org_id,
        project_id: p.project_id,
        target_id: p.target_id,
        family: p.scope.family,
        direction: p.scope.direction,
        source: "10.20.1.10".parse().unwrap(),
        destination: "10.20.2.20".parse().unwrap(),
        protocol: fw_domain::Protocol::Tcp,
        destination_port: Some(5432),
        icmp_type: None,
        icmp_code: None,
        ingress_interface: Some("lan0".into()),
        egress_interface: Some("lan1".into()),
    };
    assert!(matches!(
        evaluate(
            &evidence.after.policies,
            &flow,
            timestamp("2026-10-30T09:10:00Z").unwrap()
        ),
        Decision::Deny(_)
    ));
}

#[test]
fn recomputed_hashes_cannot_hide_removed_baseline_policy_or_association_rebinding() {
    let mut retained = policy();
    retained.policy_id = OTHER.into();
    let (plan, evidence) = fixture(vec![retained], vec![policy()]);
    for change_association in [false, true] {
        let mut changed = evidence.clone();
        if change_association {
            changed
                .after
                .associations
                .iter_mut()
                .find(|a| a.request_id == OTHER)
                .unwrap()
                .request_id = LEASE.into();
        } else {
            changed
                .after
                .policies
                .retain(|policy| policy.policy_id != OTHER);
            changed.after.associations.retain(|a| a.request_id != OTHER);
        }
        changed.after = changed.after.normalized().unwrap();
        let mut rewritten = plan.clone();
        refresh(&mut rewritten, &changed);
        assert!(changed.verify(&rewritten).is_err());
    }
}

#[test]
fn core_associations_require_one_lease_request_and_exact_non_circular_basis() {
    let (plan, evidence) = fixture(vec![], vec![policy(), second_policy()]);
    evidence.verify(&plan).unwrap();
    for field in ["lease", "request", "basis"] {
        let mut changed = evidence.clone();
        let association = &mut changed.after.associations[0];
        match field {
            "lease" => association.lease_id = Some(OTHER.into()),
            "request" => association.request_id = OTHER.into(),
            _ => association.authority_basis_hash = hash_bytes(b"final approval is not the basis"),
        }
        changed.after = changed.after.normalized().unwrap();
        let mut rewritten = plan.clone();
        refresh(&mut rewritten, &changed);
        assert!(changed.verify(&rewritten).is_err(), "{field}");
    }
    let expected = canonical_hash(&json!({"schema_version":"f.policy-authority-basis/v1","approval_requirements_hash":plan["approval_requirements_hash"],"envelope_hash":plan["envelope_hash"],"delegation_hash":plan["delegation_hash"]})).unwrap();
    assert_eq!(core_access_authority_basis_hash(&plan).unwrap(), expected);
    let mut changed = plan;
    changed["envelope_hash"] = hash_bytes(b"another envelope").into();
    assert!(evidence.verify(&changed).is_err());
}

#[test]
fn every_requested_policy_has_the_same_absolute_start_and_end() {
    for (start, end) in [
        ("2026-10-30T09:01:00Z", "2026-10-30T09:30:00Z"),
        ("2026-10-30T09:01:00Z", "2026-10-30T09:31:00Z"),
        ("2026-10-30T09:00:00Z", "2026-10-30T09:29:00Z"),
    ] {
        let mut second = second_policy();
        second.lifetime = Lifetime::Lease {
            not_before: start.into(),
            expires_at: end.into(),
        };
        let (plan, evidence) = fixture(vec![], vec![policy(), second]);
        assert!(evidence.verify(&plan).is_err());
    }
}

#[test]
fn core_lease_cannot_use_the_general_allow_shortening_minimum() {
    let mut short = policy();
    short.lifetime = Lifetime::Lease {
        not_before: "2026-10-30T09:00:00Z".into(),
        expires_at: "2026-10-30T09:00:59Z".into(),
    };
    let (mut plan, evidence) = fixture(vec![], vec![short]);
    // Keep every other plan/policy bound valid so the core's 60-second request
    // minimum, rather than an unrelated plan-expiry check, causes refusal.
    plan["valid_until"] = "2026-10-30T09:00:00Z".into();
    assert!(evidence.verify(&plan).is_err());
}

#[test]
fn requested_policy_and_hash_arrays_have_exact_original_core_order() {
    let (plan, evidence) = fixture(vec![], vec![policy(), second_policy()]);
    for reverse_policies in [false, true] {
        let mut changed = plan.clone();
        if reverse_policies {
            changed["requested_policies"]
                .as_array_mut()
                .unwrap()
                .reverse();
            changed["request_patch_hash"] = canonical_hash(&changed["requested_policies"])
                .unwrap()
                .into();
        } else {
            changed["requested_policy_hashes"]
                .as_array_mut()
                .unwrap()
                .reverse();
        }
        assert!(evidence.verify(&changed).is_err());
    }
}

#[test]
fn core_effect_tampering_and_unavailable_context_never_become_verified() {
    let (plan, evidence) = fixture(vec![], vec![policy()]);
    for key in [
        "newly_allowed_flow_count",
        "removed_flow_count",
        "effect_hash",
    ] {
        let mut changed = plan.clone();
        changed["effect_summary"][key] = if key == "effect_hash" {
            hash_bytes(b"forged effect").into()
        } else {
            json!(99)
        };
        assert!(evidence.verify(&changed).is_err());
    }
    for key in ["management", "source", "capability", "tombstone"] {
        let mut changed = evidence.clone();
        match key {
            "management" => changed.after.management_baseline_hash = hash_bytes(b"different B"),
            "source" => changed.after.source_snapshot_hash = hash_bytes(b"different registry"),
            "capability" => {
                changed.after.target_capability_hash = hash_bytes(b"different capability")
            }
            _ => changed.after.tombstone_hashes.clear(),
        }
        assert!(core_access_effect_summary(&changed.before, &changed.after).is_err());
        let mut rewritten = plan.clone();
        rewritten["desired_state_hash"] = changed.after.state_hash().unwrap().into();
        assert!(changed.verify(&rewritten).is_err(), "{key}");
    }
}

#[test]
fn unsupported_protocol_and_policy_proof_budget_refuse_core_summaries() {
    let mut icmp = policy();
    icmp.scope.transport = Transport::Icmp {
        icmp_type: 8,
        code: 0,
    };
    let (_, mut evidence) = fixture(vec![], vec![policy()]);
    evidence.after.policies = vec![icmp.clone()];
    evidence.after.associations[0].policy_hash = canonical_hash(&icmp).unwrap();
    assert!(core_access_effect_summary(&evidence.before, &evidence.after).is_err());
    let many = (0..65)
        .map(|n| {
            let mut policy = policy();
            policy.policy_id = format!("00000000-0000-4000-8000-{n:012}");
            policy
        })
        .collect::<Vec<_>>();
    evidence.before.policies = many.clone();
    evidence.before.associations = many
        .iter()
        .map(|p| PolicyAssociation {
            policy_hash: canonical_hash(p).unwrap(),
            lease_id: Some(LEASE.into()),
            request_id: OTHER.into(),
            authority_basis_hash: hash_bytes(b"existing"),
        })
        .collect();
    evidence.before = evidence.before.normalized().unwrap();
    evidence.after = evidence.before.clone();
    assert_eq!(
        semantic_diff(&evidence.before, &evidence.after, 4096)
            .unwrap()
            .reason
            .as_deref(),
        Some("POLICY_PROOF_LIMIT")
    );
    assert!(core_access_effect_summary(&evidence.before, &evidence.after).is_err());
}

#[test]
fn direct_core_review_input_bounds_reject_before_unbounded_copying() {
    let (plan, evidence) = fixture(vec![], vec![policy()]);
    let mut oversized = plan.clone();
    oversized["untrusted"] = "x".repeat(MAX_POLICY_REVIEW_BYTES).into();
    assert!(evidence.verify(&oversized).is_err());
    let mut deep = Value::Null;
    for _ in 0..fw_contracts::MAX_DEPTH + 1 {
        deep = json!([deep]);
    }
    let mut nested = plan;
    nested["untrusted"] = deep;
    assert!(evidence.verify(&nested).is_err());
}
