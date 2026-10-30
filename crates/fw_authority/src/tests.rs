use super::*;
fn fixture() -> Value {
    serde_json::from_str::<Value>(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap()["grant"]["payload"]
        .clone()
}
fn context(p: &Value) -> GrantContext {
    GrantContext {
        org_id: p["org_id"].as_str().unwrap().into(),
        project_id: p["project_id"].as_str().unwrap().into(),
        target_id: p["target_id"].as_str().unwrap().into(),
        plan_hash: p["plan_hash"].as_str().unwrap().into(),
        artifact_hash: p["artifact_hash"].as_str().unwrap().into(),
        baseline_hash: p["baseline_hash"].as_str().unwrap().into(),
        desired_state_hash: p["desired_state_hash"].as_str().unwrap().into(),
        approval_set_hash: p["approval_set_hash"].as_str().unwrap().into(),
        authority_epoch: 1,
        now_unix: timestamp(p["issued_at"].as_str().unwrap()).unwrap(),
    }
}
// Synthetic test proof adapter only. No production adapter trusts these claims.
struct FixtureAuthority(GrantContext);
impl AuthorityEvidence for FixtureAuthority {
    fn verify_for_signing(&self, _: &Value, _: i64) -> Result<GrantContext> {
        Ok(self.0.clone())
    }
}
fn signed() -> (SignedGrant, TrustKey, GrantContext) {
    let p = fixture();
    let c = context(&p);
    let k = SigningKey::from_bytes(&[0x42; 32]);
    let g = sign_grant(
        p,
        "synthetic-test-key",
        &k,
        &FixtureAuthority(c.clone()),
        c.now_unix,
    )
    .unwrap();
    let t = TrustKey {
        key_id: "synthetic-test-key".into(),
        org_id: c.org_id.clone(),
        payload_type: CORE_GRANT_TYPE.into(),
        public_key: k.verifying_key().to_bytes(),
        not_before: c.now_unix - 1,
        not_after: c.now_unix + 3600,
        revoked: false,
    };
    (g, t, c)
}
#[test]
fn dsse_pae_uses_byte_lengths() {
    assert_eq!(pae("é", b"abc"), "DSSEv1 2 é 3 abc".as_bytes());
}
#[test]
fn verifies_exact_fixture_fields() {
    let (g, t, c) = signed();
    let v = verify_grant(&g, &t, &c).unwrap();
    assert_eq!(v.generation(), 7);
    assert_eq!(v.authority_epoch(), 1);
    assert_eq!(v.grant_hash(), canonical_hash(&g).unwrap());
    assert_eq!(v.project_id(), c.project_id);
    assert_eq!(v.approval_set_hash(), c.approval_set_hash);
    assert_eq!(
        canonical_bytes(v.signed_grant()).unwrap(),
        canonical_bytes(&g).unwrap()
    );
    assert_eq!(
        serde_json::to_value(v.rollback_authority()).unwrap(),
        g.payload["rollback_authority"]
    );
}

#[test]
fn recovery_rechecks_current_key_and_separate_signed_deadline() {
    let (g, trust, mut context) = signed();
    context.now_unix = timestamp(g.payload["not_after"].as_str().unwrap()).unwrap();
    assert!(verify_grant(&g, &trust, &context).is_err());
    let verified = verify_recovery_grant(&g, &trust, &context).unwrap();
    assert_eq!(verified.not_after(), context.now_unix);
    assert_eq!(verified.signed_grant().payload, g.payload);
    let mut revoked = trust.clone();
    revoked.revoked = true;
    assert!(verify_recovery_grant(&g, &revoked, &context).is_err());
    let mut expired = trust.clone();
    expired.not_after = context.now_unix;
    assert!(verify_recovery_grant(&g, &expired, &context).is_err());
    context.now_unix = verified.rollback_authority().valid_until_unix().unwrap();
    assert!(verify_recovery_grant(&g, &trust, &context).is_err());
}

#[test]
fn recovery_scope_artifact_and_deadline_are_signed_not_mutable_claims() {
    let (grant, trust, context) = signed();
    for key in [
        "scope_bound_hash",
        "artifact_hash",
        "valid_until",
        "profile",
    ] {
        let mut changed = grant.clone();
        changed.payload["rollback_authority"][key] = match key {
            "profile" => "preapproved-scope".into(),
            "valid_until" => "2026-10-30T09:10:00Z".into(),
            _ => format!("sha256:{}", "a".repeat(64)).into(),
        };
        changed.dsse.payload = STANDARD.encode(canonical_bytes(&changed.payload).unwrap());
        assert!(verify_recovery_grant(&changed, &trust, &context).is_err());
    }
}
#[test]
fn tampering_either_payload_or_envelope_fails() {
    let (mut g, t, c) = signed();
    g.payload["target_generation"] = "8".into();
    assert!(verify_grant(&g, &t, &c).is_err());
    g.dsse.payload = STANDARD.encode(canonical_bytes(&g.payload).unwrap());
    assert!(verify_grant(&g, &t, &c).is_err());
}
#[test]
fn tenant_plan_epoch_and_approval_bindings() {
    let (g, t, c) = signed();
    let mut bad = c.clone();
    bad.authority_epoch = 2;
    assert!(verify_grant(&g, &t, &bad).is_err());
    bad = c.clone();
    bad.org_id = "00000000-0000-0000-0000-000000000099".into();
    assert!(verify_grant(&g, &t, &bad).is_err());
    bad = c.clone();
    bad.approval_set_hash = format!("sha256:{}", "f".repeat(64));
    assert!(verify_grant(&g, &t, &bad).is_err());
    bad = c;
    bad.plan_hash = format!("sha256:{}", "e".repeat(64));
    assert!(verify_grant(&g, &t, &bad).is_err());
}
#[test]
fn expiry_and_revocation_are_strict() {
    let (g, mut t, mut c) = signed();
    c.now_unix = timestamp(g.payload["not_after"].as_str().unwrap()).unwrap();
    assert!(matches!(
        verify_grant(&g, &t, &c),
        Err(AuthorityError::Time)
    ));
    c.now_unix -= 1;
    t.revoked = true;
    assert!(verify_grant(&g, &t, &c).is_err());
}
#[test]
fn domain_separation_and_unknown_fields() {
    let (mut g, t, c) = signed();
    g.dsse.payload_type = POLICY_CHANGE_GRANT_TYPE.into();
    assert!(verify_grant(&g, &t, &c).is_err());
    g.dsse.payload_type = CORE_GRANT_TYPE.into();
    g.payload["approved"] = true.into();
    assert!(verify_grant(&g, &t, &c).is_err());
}
#[test]
fn overlong_grant_and_counter_forms_rejected() {
    let mut p = fixture();
    p["target_generation"] = "07".into();
    assert!(validate_payload(&p).is_err());
    p = fixture();
    p["not_after"] = "2026-10-30T09:05:01Z".into();
    assert!(validate_payload(&p).is_err());
}
#[test]
fn policy_change_payload_has_separate_domain() {
    let mut p = fixture();
    for k in [
        "lease_id",
        "request_id",
        "workload_binding_id",
        "requested_policy_hashes",
        "envelope_hash",
        "delegation_hash",
        "reservation",
    ] {
        p.as_object_mut().unwrap().remove(k);
    }
    p["schema_version"] = "f.policy-change-grant/v1".into();
    p["change_kind"] = "policy_change".into();
    p["dispatch_reservation_id"] = "00000000-0000-4000-8000-000000000062".into();
    assert_eq!(validate_payload(&p).unwrap(), POLICY_CHANGE_GRANT_TYPE);
}
