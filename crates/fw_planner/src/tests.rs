use super::*;
use serde_json::{Value, json};
fn h(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn policy() -> Policy {
    let v = serde_json::from_str::<Value>(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap();
    serde_json::from_value(v["requested_policies"][0].clone()).unwrap()
}
fn association(p: &Policy) -> PolicyAssociation {
    PolicyAssociation {
        policy_hash: hash(p).unwrap(),
        lease_id: if p.action == Action::Allow {
            Some("00000000-0000-4000-8000-000000000061".into())
        } else {
            None
        },
        request_id: "00000000-0000-4000-8000-000000000031".into(),
        authority_basis_hash: h('b'),
    }
}
fn state() -> StateIr {
    let p = policy();
    StateIr {
        schema_version: "f.state-ir/v1".into(),
        target_id: p.target_id.clone(),
        platform: "linux".into(),
        profile: "host".into(),
        management_baseline_hash: h('a'),
        policies: vec![p.clone()],
        associations: vec![association(&p)],
        tombstone_hashes: vec![],
        source_snapshot_hash: h('c'),
        target_capability_hash: h('d'),
        normalization_version: "f.normalize/nfc-v1".into(),
    }
}
fn deny() -> Policy {
    let mut p = policy();
    p.policy_id = "00000000-0000-4000-8000-000000000099".into();
    p.action = Action::Deny;
    p.lifetime=serde_json::from_value(json!({"kind":"review","not_before":"2026-10-30T09:00:00Z","review_at":"2026-10-31T09:00:00Z"})).unwrap();
    p
}
#[test]
fn patch_preserves_existing_allow_and_denies() {
    let baseline = state();
    let d = deny();
    let result = compose_policy_change(
        &baseline,
        &[PolicyMutation::AddDeny {
            policy: Box::new(d.clone()),
        }],
        &[association(&d)],
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(result.state.policies.len(), 2);
    assert!(result.state.policies.contains(&baseline.policies[0]));
    assert_eq!(result.relation, Relation::Restricting);
    assert!(result.semantic_complete);
    assert_eq!(baseline.policies.len(), 1);
}
#[test]
fn add_deny_cannot_smuggle_allow() {
    let baseline = state();
    let mut p = policy();
    p.policy_id = "00000000-0000-4000-8000-000000000099".into();
    assert!(
        compose_policy_change(
            &baseline,
            &[PolicyMutation::AddDeny {
                policy: Box::new(p.clone())
            }],
            &[association(&p)],
            &BTreeSet::new()
        )
        .is_err()
    );
}
#[test]
fn stale_and_duplicate_patch_rejected() {
    let b = state();
    let p = &b.policies[0];
    let op = PolicyMutation::RemovePolicy {
        policy_id: p.policy_id.clone(),
        expected_revision: p.policy_revision,
        expected_policy_hash: h('f'),
    };
    assert!(compose_policy_change(&b, std::slice::from_ref(&op), &[], &BTreeSet::new()).is_err());
    assert!(compose_policy_change(&b, &[op.clone(), op], &[], &BTreeSet::new()).is_err());
}
#[test]
fn cannot_extend_allow_or_change_owner() {
    let b = state();
    let old = &b.policies[0];
    let mut p = old.clone();
    p.policy_revision += 1;
    p.owner_id = "00000000-0000-4000-8000-000000000099".into();
    let op = PolicyMutation::ReplacePolicy {
        policy_id: old.policy_id.clone(),
        expected_revision: old.policy_revision,
        expected_policy_hash: hash(old).unwrap(),
        replacement: Box::new(p.clone()),
    };
    assert!(compose_policy_change(&b, &[op], &[association(&p)], &BTreeSet::new()).is_err());
}
#[test]
fn tombstone_prevents_resurrection() {
    let b = state();
    let p = deny();
    let ids = BTreeSet::from([p.policy_id.clone()]);
    assert!(
        compose_policy_change(
            &b,
            &[PolicyMutation::AddDeny {
                policy: Box::new(p.clone())
            }],
            &[association(&p)],
            &ids
        )
        .is_err()
    );
}
#[test]
fn semantic_unknown_cannot_be_overridden_by_pass_gates() {
    let gates = [
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
    .map(|id| Gate {
        gate_id: id.into(),
        required: true,
        result: "PASS".into(),
        evidence_hash: h('a'),
    })
    .collect::<Vec<_>>();
    assert!(ensure_dispatchable(&gates, &Relation::Unknown, true).is_err());
    assert!(ensure_dispatchable(&gates, &Relation::Equivalent, true).is_ok());
    let mut duplicate = gates;
    duplicate[1].gate_id = "schema".into();
    assert!(ensure_dispatchable(&duplicate, &Relation::Equivalent, true).is_err());
}
#[test]
fn state_hash_stable_but_metadata_changes_bound() {
    let a = state();
    let mut b = a.clone();
    assert_eq!(a.state_hash().unwrap(), b.state_hash().unwrap());
    b.management_baseline_hash = h('f');
    assert_ne!(a.state_hash().unwrap(), b.state_hash().unwrap());
}

fn with_policies(mut state: StateIr, policies: Vec<Policy>) -> StateIr {
    state.associations = policies.iter().map(association).collect();
    state.policies = policies;
    state
}
#[test]
fn exact_semantics_empty_to_allow_is_expanding_and_inverse_restricting() {
    let after = state();
    let before = with_policies(after.clone(), vec![]);
    let forward = semantic_diff(&before, &after, 4096).unwrap();
    assert!(forward.complete);
    assert_eq!(forward.relation, Relation::Expanding);
    assert!(forward.evaluated_cells > 0);
    let backward = semantic_diff(&after, &before, 4096).unwrap();
    assert_eq!(backward.relation, Relation::Restricting);
    assert_eq!(
        forward.newly_allowed_region_hash,
        backward.removed_region_hash
    );
}
#[test]
fn deleting_deny_without_any_allow_is_equivalent() {
    let baseline = with_policies(state(), vec![deny()]);
    let after = with_policies(baseline.clone(), vec![]);
    let proof = semantic_diff(&baseline, &after, 4096).unwrap();
    assert!(proof.complete);
    assert_eq!(proof.relation, Relation::Equivalent);
}
#[test]
fn deny_removal_is_expanding_only_where_other_allows_exist() {
    let baseline = with_policies(state(), vec![policy(), deny()]);
    let after = state();
    let proof = semantic_diff(&baseline, &after, 4096).unwrap();
    assert!(proof.complete);
    assert_eq!(proof.relation, Relation::Expanding);
}
#[test]
fn replacing_allowed_destination_is_mixed() {
    let baseline = state();
    let mut p = policy();
    p.policy_revision += 1;
    p.scope.destination_cidrs = vec!["203.0.113.0/24".into()];
    let after = with_policies(baseline.clone(), vec![p]);
    let proof = semantic_diff(&baseline, &after, 4096).unwrap();
    assert!(proof.complete);
    assert_eq!(proof.relation, Relation::Mixed);
}
#[test]
fn shortening_absolute_lifetime_is_restricting() {
    let baseline = state();
    let mut p = policy();
    p.policy_revision += 1;
    if let fw_domain::Lifetime::Lease {
        ref not_before,
        ref mut expires_at,
    } = p.lifetime
    {
        assert_ne!(not_before, expires_at);
        *expires_at = "2026-10-30T09:10:00Z".into();
    }
    let after = with_policies(baseline.clone(), vec![p]);
    let proof = semantic_diff(&baseline, &after, 4096).unwrap();
    assert!(proof.complete);
    assert_eq!(proof.relation, Relation::Restricting);
}
#[test]
fn resource_bound_is_unknown_and_never_partial_pass() {
    let baseline = state();
    let after = with_policies(baseline.clone(), vec![]);
    let proof = semantic_diff(&baseline, &after, 1).unwrap();
    assert!(!proof.complete);
    assert_eq!(proof.relation, Relation::Unknown);
    assert_eq!(proof.reason.as_deref(), Some("CELL_PROOF_LIMIT"));
}
#[test]
fn ipv6_proof_includes_high_addresses_and_excludes_mapped_addresses() {
    let mut p = policy();
    p.scope.family = fw_domain::Family::Ipv6;
    p.scope.source_cidrs = vec!["::/0".into()];
    p.scope.destination_cidrs = vec!["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".into()];
    let after = with_policies(state(), vec![p]);
    let before = with_policies(after.clone(), vec![]);
    let proof = semantic_diff(&before, &after, 4096).unwrap();
    assert!(proof.complete);
    assert_eq!(proof.relation, Relation::Expanding);
}
#[test]
fn unsupported_icmp_proof_and_changed_context_stay_unknown() {
    let mut p = policy();
    p.scope.transport = fw_domain::Transport::Icmp {
        icmp_type: 8,
        code: 0,
    };
    let after = with_policies(state(), vec![p]);
    assert_eq!(
        semantic_diff(&after, &after, 4096).unwrap().relation,
        Relation::Unknown
    );
    let baseline = state();
    let mut changed = baseline.clone();
    changed.management_baseline_hash = h('f');
    assert!(!semantic_diff(&baseline, &changed, 4096).unwrap().complete);
}
#[test]
fn overlapping_allow_union_and_policy_reordering_are_equivalent() {
    let base = policy();
    let mut duplicate = base.clone();
    duplicate.policy_id = "00000000-0000-4000-8000-000000000088".into();
    let before = with_policies(state(), vec![base.clone(), duplicate.clone()]);
    let after = with_policies(state(), vec![duplicate, base]);
    let proof = semantic_diff(&before, &after, 4096).unwrap();
    assert!(proof.complete);
    assert_eq!(proof.relation, Relation::Equivalent);
}
