#![cfg(feature = "approval-proofs")]

#[path = "support/core_access_fixture.rs"]
mod support;

use fw_authority::{CoreAccessProvenance, MAX_CORE_ACCESS_PROVENANCE_BYTES};
use fw_contracts::{canonical_bytes, canonical_hash};
use serde_json::{Value, json};
use support::{NOW, at, fixture, rehash};

#[test]
fn original_cost_survives_shorter_policy_and_plan_windows() {
    let (plan, provenance) = fixture();
    let result = provenance.verify(&plan).unwrap();
    assert_eq!(result.lease_seconds(), 3600);
    assert_eq!(
        result.request_hash(),
        canonical_hash(&provenance.request).unwrap()
    );
    assert_eq!(result.request_id(), plan["request_id"]);
    assert_ne!(result.request_id(), result.idempotency_key());
    assert_eq!(result.lease_id(), provenance.lease_id);
    assert_eq!(result.root_id(), provenance.delegation.root_id);
    assert_eq!(
        result.canonical_bytes(),
        canonical_bytes(&provenance).unwrap()
    );
    assert_eq!(result.hash(), canonical_hash(&provenance).unwrap());
    assert_eq!(result.valid_from(), NOW - 60);
    assert_eq!(result.valid_until(), NOW + 86_400);
    let restored =
        CoreAccessProvenance::from_json(&serde_json::to_value(&provenance).unwrap()).unwrap();
    assert_eq!(restored.verify(&plan).unwrap().hash(), result.hash());
}

#[test]
fn original_array_order_is_hashed_but_accounting_destinations_are_sorted() {
    let (mut plan, mut provenance) = fixture();
    let extra = "00000000-0000-4000-8000-000000000012".to_string();
    provenance
        .request
        .destination_asset_ids
        .insert(0, extra.clone());
    provenance
        .envelope
        .scope
        .destination_asset_ids
        .push(extra.clone());
    provenance
        .delegation
        .destination_asset_ids
        .push(extra.clone());
    plan["requested_policies"][0]["scope"]["destination_asset_ids"]
        .as_array_mut()
        .unwrap()
        .push(extra.clone().into());
    rehash(&mut plan, &mut provenance);
    let result = provenance.verify(&plan).unwrap();
    assert_eq!(result.destination_asset_ids()[1], extra);
    assert_eq!(result.lease_seconds(), 3600);
    provenance.request.destination_asset_ids.reverse();
    assert!(
        provenance.verify(&plan).is_err(),
        "reordering originals changes their hash"
    );
    rehash(&mut plan, &mut provenance);
    assert_eq!(
        result.destination_asset_ids(),
        provenance.verify(&plan).unwrap().destination_asset_ids()
    );
}

#[test]
fn all_original_hashes_and_request_identity_are_exact() {
    for mutate in [
        |p: &mut CoreAccessProvenance| p.request.lease_seconds = 1800,
        |p: &mut CoreAccessProvenance| p.request.purpose.push('!'),
        |p: &mut CoreAccessProvenance| p.envelope.max_lease_seconds = 7200,
        |p: &mut CoreAccessProvenance| {
            p.delegation.root_id = "00000000-0000-4000-8000-000000000099".into()
        },
        |p: &mut CoreAccessProvenance| p.request_id = p.request.idempotency_key.clone(),
        |p: &mut CoreAccessProvenance| p.request_revision = 2,
    ] {
        let (plan, mut provenance) = fixture();
        mutate(&mut provenance);
        assert!(provenance.verify(&plan).is_err());
    }
}

#[test]
fn independently_hash_bound_originals_still_require_request_scope_membership() {
    for mutate in [
        |p: &mut CoreAccessProvenance| p.request.service_id = "outside-service".into(),
        |p: &mut CoreAccessProvenance| {
            p.delegation.allowed_principal_ids[0] = "00000000-0000-4000-8000-000000000099".into()
        },
        |p: &mut CoreAccessProvenance| {
            p.delegation.workload_binding_ids[0] = "00000000-0000-4000-8000-000000000099".into()
        },
        |p: &mut CoreAccessProvenance| {
            p.delegation.source_asset_ids[0] = "00000000-0000-4000-8000-000000000099".into()
        },
        |p: &mut CoreAccessProvenance| {
            p.delegation.destination_asset_ids[0] = "00000000-0000-4000-8000-000000000099".into()
        },
        |p: &mut CoreAccessProvenance| {
            p.delegation
                .allowed_tools
                .retain(|tool| tool != "request_access")
        },
        |p: &mut CoreAccessProvenance| {
            p.delegation
                .allowed_tools
                .retain(|tool| tool != "request_deployment")
        },
    ] {
        let (mut plan, mut provenance) = fixture();
        mutate(&mut provenance);
        rehash(&mut plan, &mut provenance);
        assert!(provenance.verify(&plan).is_err());
    }
}

#[test]
fn tenant_target_envelope_and_workload_cannot_be_substituted() {
    for key in [
        "org_id",
        "project_id",
        "target_id",
        "principal_id",
        "workload_binding_id",
    ] {
        let (mut plan, provenance) = fixture();
        plan[key] = "00000000-0000-4000-8000-000000000099".into();
        assert!(provenance.verify(&plan).is_err(), "{key}");
    }
    let (mut plan, mut provenance) = fixture();
    provenance.delegation.envelope_id = "00000000-0000-4000-8000-000000000099".into();
    rehash(&mut plan, &mut provenance);
    assert!(provenance.verify(&plan).is_err());
}

#[test]
fn shorter_policy_cannot_hide_an_excessive_original_duration() {
    for mutate in [
        |p: &mut CoreAccessProvenance| p.envelope.max_lease_seconds = 1800,
        |p: &mut CoreAccessProvenance| p.delegation.max_lease_seconds = 1800,
        |p: &mut CoreAccessProvenance| p.request.lease_seconds = 7200,
    ] {
        let (mut plan, mut provenance) = fixture();
        mutate(&mut provenance);
        rehash(&mut plan, &mut provenance);
        assert!(provenance.verify(&plan).is_err());
    }
}

#[test]
fn request_is_limited_by_the_intersection_of_independent_duration_ceilings() {
    let (mut plan, mut provenance) = fixture();
    provenance.delegation.max_lease_seconds = 7200;
    rehash(&mut plan, &mut provenance);
    assert_eq!(provenance.verify(&plan).unwrap().lease_seconds(), 3600);
    provenance.request.lease_seconds = 3601;
    rehash(&mut plan, &mut provenance);
    assert!(provenance.verify(&plan).is_err());
}

#[test]
fn a_policy_cannot_silently_drop_a_requested_asset() {
    let (mut plan, mut provenance) = fixture();
    let extra = "00000000-0000-4000-8000-000000000012".to_string();
    provenance.request.destination_asset_ids.push(extra.clone());
    provenance
        .envelope
        .scope
        .destination_asset_ids
        .push(extra.clone());
    provenance.delegation.destination_asset_ids.push(extra);
    rehash(&mut plan, &mut provenance);
    assert!(provenance.verify(&plan).is_err());
}

#[test]
fn separated_short_policies_cannot_span_more_than_one_original_lease() {
    let (mut plan, mut provenance) = fixture();
    let mut second = plan["requested_policies"][0].clone();
    second["policy_id"] = "00000000-0000-4000-8000-000000000021".into();
    second["lifetime"]["not_before"] = at(NOW + 3660).into();
    second["lifetime"]["expires_at"] = at(NOW + 5460).into();
    plan["requested_policies"]
        .as_array_mut()
        .unwrap()
        .push(second);
    rehash(&mut plan, &mut provenance);
    assert!(provenance.verify(&plan).is_err());
    plan["requested_policies"][1]["lifetime"]["not_before"] = at(NOW + 1860).into();
    plan["requested_policies"][1]["lifetime"]["expires_at"] = at(NOW + 3660).into();
    rehash(&mut plan, &mut provenance);
    assert_eq!(provenance.verify(&plan).unwrap().lease_seconds(), 3600);
}

#[test]
fn full_policy_window_is_bounded_by_original_lifetimes_and_workload_reference() {
    for mutate in [
        |p: &mut CoreAccessProvenance| p.envelope.valid_until = at(NOW + 1800),
        |p: &mut CoreAccessProvenance| p.delegation.valid_until = at(NOW + 1800),
        |p: &mut CoreAccessProvenance| p.envelope.valid_from = at(NOW + 1),
        |p: &mut CoreAccessProvenance| p.delegation.valid_from = at(NOW + 1),
    ] {
        let (mut plan, mut provenance) = fixture();
        mutate(&mut provenance);
        rehash(&mut plan, &mut provenance);
        assert!(provenance.verify(&plan).is_err());
    }
    let (mut plan, provenance) = fixture();
    plan["workload_binding_valid_until"] = at(NOW + 1800).into();
    assert!(provenance.verify(&plan).is_err());
}

#[test]
fn policy_packet_scope_and_exclusions_are_checked_not_only_asset_labels() {
    for (key, value) in [
        ("destination_cidrs", json!(["10.99.0.0/24"])),
        ("source_cidrs", json!(["10.99.0.0/24"])),
        (
            "transport",
            json!({"protocol":"tcp","destination_ports":[{"start":22,"end":22}]}),
        ),
        (
            "destination_asset_ids",
            json!(["00000000-0000-4000-8000-000000000099"]),
        ),
    ] {
        let (mut plan, mut provenance) = fixture();
        plan["requested_policies"][0]["scope"][key] = value;
        rehash(&mut plan, &mut provenance);
        assert!(provenance.verify(&plan).is_err(), "{key}");
    }
    let (mut plan, mut provenance) = fixture();
    provenance
        .envelope
        .excluded_destination_cidrs
        .push("10.20.2.0/24".into());
    rehash(&mut plan, &mut provenance);
    assert!(provenance.verify(&plan).is_err());
    provenance.envelope.excluded_destination_cidrs = vec!["10.99.0.0/24".into()];
    rehash(&mut plan, &mut provenance);
    provenance.verify(&plan).unwrap();
}

#[test]
fn exclusions_are_canonical_and_apply_only_to_the_matching_ip_family() {
    let (mut plan, mut provenance) = fixture();
    provenance
        .envelope
        .excluded_destination_cidrs
        .push("2001:db8::/32".into());
    rehash(&mut plan, &mut provenance);
    provenance.verify(&plan).unwrap();
    for bad in ["10.20.2.1/24", "2001:0db8::/32", "not-a-network"] {
        provenance.envelope.excluded_destination_cidrs = vec![bad.into()];
        rehash(&mut plan, &mut provenance);
        assert!(provenance.verify(&plan).is_err(), "{bad}");
    }
    provenance.envelope.excluded_destination_cidrs = vec!["10.20.2.20/32".into()];
    rehash(&mut plan, &mut provenance);
    assert!(provenance.verify(&plan).is_err());
}

#[test]
fn original_accounting_terms_and_non_delegation_are_closed() {
    for mutate in [
        |p: &mut CoreAccessProvenance| p.delegation.can_delegate = true,
        |p: &mut CoreAccessProvenance| p.delegation.budget_window.seconds = 3600,
        |p: &mut CoreAccessProvenance| {
            p.delegation.budget_window.lease_seconds_measure = "remaining-duration".into()
        },
        |p: &mut CoreAccessProvenance| p.delegation.max_active_leases = 0,
        |p: &mut CoreAccessProvenance| {
            p.request
                .destination_asset_ids
                .push(p.request.destination_asset_ids[0].clone())
        },
    ] {
        let (mut plan, mut provenance) = fixture();
        mutate(&mut provenance);
        rehash(&mut plan, &mut provenance);
        assert!(provenance.verify(&plan).is_err());
    }
    let (_, provenance) = fixture();
    let mut value = serde_json::to_value(provenance).unwrap();
    value["request"]["approved"] = true.into();
    assert!(CoreAccessProvenance::from_json(&value).is_err());
}

#[test]
fn oversized_and_deep_direct_inputs_are_rejected_before_copying() {
    let (mut plan, mut provenance) = fixture();
    provenance.request.purpose = "x".repeat(MAX_CORE_ACCESS_PROVENANCE_BYTES);
    assert!(provenance.verify(&plan).is_err());
    let (_, valid) = fixture();
    let mut deep = Value::Null;
    for _ in 0..(fw_contracts::MAX_DEPTH + 1) {
        deep = json!([deep]);
    }
    plan["untrusted_extra"] = deep.clone();
    assert!(valid.verify(&plan).is_err());
    assert!(CoreAccessProvenance::from_json(&deep).is_err());
    let mut value = serde_json::to_value(valid).unwrap();
    value["request"]["purpose"] = "x".repeat(MAX_CORE_ACCESS_PROVENANCE_BYTES).into();
    assert!(CoreAccessProvenance::from_json(&value).is_err());
}

#[test]
fn hash_valid_policy_substitution_must_still_be_normalized_allow_patch() {
    let (mut plan, mut provenance) = fixture();
    plan["requested_policies"][0]["action"] = "deny".into();
    rehash(&mut plan, &mut provenance);
    assert!(provenance.verify(&plan).is_err());
    let (mut plan, mut provenance) = fixture();
    plan["requested_policies"][0]["policy_revision"] = 2.into();
    rehash(&mut plan, &mut provenance);
    assert!(provenance.verify(&plan).is_err());
    let (mut plan, provenance) = fixture();
    plan["requested_policy_hashes"][0] = fw_contracts::hash_bytes(b"unrelated").into();
    assert!(provenance.verify(&plan).is_err());
}
