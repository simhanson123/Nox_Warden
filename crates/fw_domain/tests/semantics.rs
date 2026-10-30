use fw_contracts::{canonical_hash, parse_strict};
use fw_domain::*;
use serde_json::{json, Value};

fn policy() -> Policy {
    let bundle: Value = serde_json::from_str(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap();
    serde_json::from_value(bundle["requested_policies"][0].clone()).unwrap()
}
fn flow(p: &Policy) -> Flow {
    let source = p.scope.source_cidrs[0]
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let destination = p.scope.destination_cidrs[0]
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    Flow {
        org_id: p.org_id.clone(),
        project_id: p.project_id.clone(),
        target_id: p.target_id.clone(),
        family: p.scope.family,
        direction: p.scope.direction,
        source,
        destination,
        protocol: p.scope.transport.protocol(),
        destination_port: Some(p.scope.transport.ports().unwrap()[0].start),
        icmp_type: None,
        icmp_code: None,
        ingress_interface: p.scope.ingress_interfaces.first().cloned(),
        egress_interface: p.scope.egress_interfaces.first().cloned(),
    }
}
fn at(s: &str) -> i64 {
    timestamp(s).unwrap()
}
fn lifetime(p: &mut Policy, start: &str, end: &str) {
    p.lifetime = Lifetime::Lease {
        not_before: start.into(),
        expires_at: end.into(),
    };
}

#[test]
fn published_policy_is_wire_compatible_and_valid() {
    let p = policy();
    p.validate().unwrap();
    let value = serde_json::to_value(&p).unwrap();
    let bundle: Value = serde_json::from_str(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap();
    assert_eq!(value, bundle["requested_policies"][0]);
}

#[test]
fn s01_s02_half_open_lifetime_and_current_union() {
    let mut a = policy();
    lifetime(&mut a, "2026-10-30T00:00:00Z", "2026-10-30T00:00:12Z");
    let f = flow(&a);
    let t = at("2026-10-30T00:00:00Z");
    assert_eq!(
        evaluate(std::slice::from_ref(&a), &f, t - 1),
        Decision::DefaultDrop
    );
    assert!(matches!(
        evaluate(std::slice::from_ref(&a), &f, t),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate(std::slice::from_ref(&a), &f, t + 11),
        Decision::Allow(_)
    ));
    assert_eq!(
        evaluate(std::slice::from_ref(&a), &f, t + 12),
        Decision::DefaultDrop
    );
    let mut b = a.clone();
    b.policy_id = "10000000-0000-4000-8000-000000000002".into();
    lifetime(&mut b, "2026-10-30T00:00:00Z", "2026-10-30T00:00:30Z");
    let expected = Decision::Allow(vec![PolicyRevision {
        policy_id: b.policy_id.clone(),
        policy_revision: b.policy_revision,
    }]);
    assert_eq!(evaluate(&[a.clone(), b.clone()], &f, t + 13), expected);
    assert_eq!(evaluate(&[b, a], &f, t + 13), expected);
}

#[test]
fn s03_review_deadline_never_removes_deny() {
    let mut a = policy();
    lifetime(&mut a, "2026-10-30T00:00:00Z", "2026-10-30T01:00:00Z");
    let mut deny = a.clone();
    deny.policy_id = "10000000-0000-4000-8000-000000000003".into();
    deny.action = Action::Deny;
    deny.lifetime = Lifetime::Review {
        not_before: "2026-10-30T00:00:00Z".into(),
        review_at: "2026-10-30T00:00:10Z".into(),
    };
    let f = flow(&a);
    let t = at("2026-10-30T00:00:13Z");
    assert!(matches!(
        evaluate(&[a.clone(), deny.clone()], &f, t),
        Decision::Deny(_)
    ));
    assert_eq!(
        evaluate(&[a.clone(), deny.clone()], &f, t),
        evaluate(&[deny.clone(), a], &f, t)
    );
    assert!(matches!(
        evaluate(&[deny], &f, t + 365 * 86_400),
        Decision::Deny(_)
    ));
}

#[test]
fn s04_protocol_interface_and_tenant_cannot_reuse_permission() {
    let a = policy();
    let t = timestamp(a.lifetime.not_before()).unwrap();
    let base = flow(&a);
    let mut f = base.clone();
    f.protocol = Protocol::Udp;
    assert_eq!(
        evaluate(std::slice::from_ref(&a), &f, t),
        Decision::DefaultDrop
    );
    f = base.clone();
    f.org_id = "10000000-0000-4000-8000-000000000009".into();
    assert_eq!(
        evaluate(std::slice::from_ref(&a), &f, t),
        Decision::DefaultDrop
    );
    f = base;
    f.ingress_interface = Some("wrong0".into());
    assert_eq!(evaluate(&[a], &f, t), Decision::DefaultDrop);
}

#[test]
fn c05_scope_rejects_widening_cidr_and_bad_transport() {
    let mut s = policy().scope;
    s.source_cidrs = vec!["10.1.1.1/24".into()];
    assert!(s.validate().is_err());
    s.source_cidrs = vec!["10.1.1.0/24".into(), "10.1.1.128/25".into()];
    assert!(s.validate().is_err());
    s.source_cidrs = vec!["::ffff:192.0.2.0/120".into()];
    s.family = Family::Ipv6;
    assert!(s.validate().is_err());
    s = policy().scope;
    s.transport = Transport::Icmpv6 {
        icmp_type: 128,
        code: 0,
    };
    assert!(s.validate().is_err());
    s = policy().scope;
    s.transport = Transport::Tcp {
        destination_ports: vec![PortRange {
            start: 100,
            end: 90,
        }],
    };
    assert!(s.validate().is_err());
    s.transport = Transport::Tcp {
        destination_ports: vec![
            PortRange { start: 10, end: 20 },
            PortRange { start: 20, end: 30 },
        ],
    };
    assert!(s.validate().is_err());
    s = policy().scope;
    assert!(s.validate_interfaces(&[]).is_err());
}

#[test]
fn c06_normalization_only_orders_sets_and_owned_nfc_text() {
    let mut p = policy();
    p.reason = "Cafe\u{301}".into();
    p.scope.source_cidrs = vec!["10.2.0.0/24".into(), "10.1.0.0/24".into()];
    let normalized = p.normalized().unwrap();
    assert_eq!(normalized.reason, "Café");
    assert_eq!(
        normalized.scope.source_cidrs,
        vec!["10.1.0.0/24", "10.2.0.0/24"]
    );
    p.scope.source_cidrs.reverse();
    assert_eq!(
        canonical_hash(&normalized).unwrap(),
        canonical_hash(&p.normalized().unwrap()).unwrap()
    );
    p.scope.source_cidrs.push(p.scope.source_cidrs[0].clone());
    assert!(p.normalized().is_err());
}

#[test]
fn c10_allow_limits_and_tagged_lifetime_fields() {
    let mut p = policy();
    lifetime(&mut p, "2026-10-30T00:00:00Z", "2026-10-31T00:00:00Z");
    p.validate().unwrap();
    lifetime(&mut p, "2026-10-30T00:00:00Z", "2026-10-31T00:00:01Z");
    assert!(p.validate().is_err());
    p.action = Action::Deny;
    assert!(p.validate().is_err());
    let mut raw = serde_json::to_value(policy()).unwrap();
    raw["lifetime"]["review_at"] = json!("2026-10-31T00:00:00Z");
    assert!(parse_strict::<Policy>(&serde_json::to_vec(&raw).unwrap()).is_err());
    raw = serde_json::to_value(policy()).unwrap();
    raw["admin"] = json!(true);
    assert!(parse_strict::<Policy>(&serde_json::to_vec(&raw).unwrap()).is_err());
}

#[test]
fn scope_subset_understands_adjacent_union_and_intersections() {
    let mut parent = policy().scope;
    parent.source_cidrs = vec!["10.0.0.0/25".into(), "10.0.0.128/25".into()];
    parent.transport = Transport::Tcp {
        destination_ports: vec![
            PortRange { start: 10, end: 20 },
            PortRange { start: 21, end: 30 },
        ],
    };
    let mut child = parent.clone();
    child.source_cidrs = vec!["10.0.0.0/24".into()];
    child.transport = Transport::Tcp {
        destination_ports: vec![PortRange { start: 10, end: 30 }],
    };
    assert!(child.is_subset_of(&parent).unwrap());
    assert!(parent.is_subset_of(&child).unwrap());
    child.source_cidrs = vec!["10.0.1.0/24".into()];
    assert!(!child.is_subset_of(&parent).unwrap());
    assert!(!child.intersects(&parent).unwrap());
    child.source_cidrs = vec!["10.0.0.0/26".into()];
    let intersection = child.intersection(&parent).unwrap().unwrap();
    assert_eq!(intersection.source_cidrs, vec!["10.0.0.0/26"]);
    assert!(intersection.is_subset_of(&parent).unwrap());
}

#[test]
fn invalid_flow_and_duplicate_policy_fail_closed() {
    let p = policy();
    let mut f = flow(&p);
    let t = timestamp(p.lifetime.not_before()).unwrap();
    f.destination_port = None;
    assert!(matches!(
        evaluate(std::slice::from_ref(&p), &f, t),
        Decision::Invalid(_)
    ));
    assert!(matches!(
        evaluate(&[p.clone(), p.clone()], &flow(&p), t),
        Decision::Invalid(_)
    ));
}

#[test]
fn timestamps_require_valid_canonical_utc_integer_seconds() {
    for value in [
        "2026-02-30T00:00:00Z",
        "2026-10-30T00:00:00+00:00",
        "2026-10-30T00:00:00.0Z",
        "2026-10-30T00:00:60Z",
        "2026-1-01T00:00:00Z",
        "２０２６-10-30T00:00:00Z",
    ] {
        assert!(timestamp(value).is_err(), "{value}");
    }
    assert_eq!(timestamp("1970-01-01T00:00:00Z").unwrap(), 0);
}

#[test]
fn ipv6_icmp_has_separate_protocol_type_and_no_wildcard_port() {
    let mut p = policy();
    p.scope.family = Family::Ipv6;
    p.scope.source_cidrs = vec!["2001:db8:1::/64".into()];
    p.scope.destination_cidrs = vec!["2001:db8:2::/64".into()];
    p.scope.transport = Transport::Icmpv6 {
        icmp_type: 128,
        code: 0,
    };
    p.validate().unwrap();
    let mut f = Flow {
        org_id: p.org_id.clone(),
        project_id: p.project_id.clone(),
        target_id: p.target_id.clone(),
        family: Family::Ipv6,
        direction: p.scope.direction,
        source: "2001:db8:1::42".parse().unwrap(),
        destination: "2001:db8:2::42".parse().unwrap(),
        protocol: Protocol::Icmpv6,
        destination_port: None,
        icmp_type: Some(128),
        icmp_code: Some(0),
        ingress_interface: p.scope.ingress_interfaces.first().cloned(),
        egress_interface: p.scope.egress_interfaces.first().cloned(),
    };
    let t = timestamp(p.lifetime.not_before()).unwrap();
    assert!(matches!(
        evaluate(std::slice::from_ref(&p), &f, t),
        Decision::Allow(_)
    ));
    f.icmp_type = Some(129);
    assert_eq!(
        evaluate(std::slice::from_ref(&p), &f, t),
        Decision::DefaultDrop
    );
    f.icmp_type = Some(128);
    f.destination_port = Some(128);
    assert!(matches!(evaluate(&[p], &f, t), Decision::Invalid(_)));
}

#[test]
fn permutation_and_monotonicity_properties_across_time_and_ports() {
    let mut a = policy();
    lifetime(&mut a, "2026-10-30T00:00:00Z", "2026-10-30T00:00:12Z");
    a.scope.transport = Transport::Tcp {
        destination_ports: vec![PortRange { start: 10, end: 20 }],
    };
    let mut b = a.clone();
    b.policy_id = "10000000-0000-4000-8000-000000000002".into();
    lifetime(&mut b, "2026-10-30T00:00:05Z", "2026-10-30T00:00:30Z");
    b.scope.transport = Transport::Tcp {
        destination_ports: vec![PortRange { start: 15, end: 25 }],
    };
    let mut deny = a.clone();
    deny.policy_id = "10000000-0000-4000-8000-000000000003".into();
    deny.action = Action::Deny;
    deny.lifetime = Lifetime::Review {
        not_before: "2026-10-30T00:00:10Z".into(),
        review_at: "2026-10-30T00:00:15Z".into(),
    };
    deny.scope.transport = Transport::Tcp {
        destination_ports: vec![PortRange { start: 18, end: 19 }],
    };
    let policies = [a.clone(), b.clone(), deny.clone()];
    let mut f = flow(&a);
    let t = timestamp(a.lifetime.not_before()).unwrap();
    for second in -1..=31 {
        for port in 9..=26 {
            f.destination_port = Some(port);
            let expected = evaluate(&policies, &f, t + second);
            for order in [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ] {
                assert_eq!(
                    evaluate(&order.map(|i| policies[i].clone()), &f, t + second),
                    expected
                );
            }
            let without_deny = evaluate(&[a.clone(), b.clone()], &f, t + second);
            if matches!(expected, Decision::Allow(_)) {
                assert!(matches!(without_deny, Decision::Allow(_)));
            }
            let removed_allow = evaluate(&[b.clone(), deny.clone()], &f, t + second);
            if matches!(removed_allow, Decision::Allow(_)) {
                assert!(matches!(expected, Decision::Allow(_)));
            }
        }
    }
}
