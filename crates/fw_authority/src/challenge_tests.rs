use super::*;

const NOW: i64 = 1_793_404_800;

fn id(value: u128) -> String {
    uuid::Uuid::from_u128(value).to_string()
}
fn hash(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}
fn verifier() -> WebAuthn {
    WebAuthn::new("http://localhost:8787").unwrap()
}
fn context() -> ApprovalChallengeContext {
    ApprovalChallengeContext {
        org_id: id(1),
        project_id: id(2),
        principal_id: id(3),
        subject: ApprovalChallengeSubject::Plan {
            plan_ref: ApprovalPlanRef {
                plan_kind: ApprovalPlanKind::PolicyChange,
                plan_id: id(4),
                plan_hash: hash('a'),
            },
        },
        requirements_hash: hash('b'),
        decision: ApprovalDecision::Approve,
        role: ApprovalRole::Owner,
        subject_valid_until: NOW + 900,
    }
}
fn fixed() -> ApprovalChallenge {
    ApprovalChallenge::with_material(
        &context(),
        &verifier(),
        NOW,
        id(5),
        std::array::from_fn(|i| i as u8),
    )
    .unwrap()
}
fn value(challenge: &ApprovalChallenge) -> Value {
    serde_json::to_value(challenge).unwrap()
}
fn decode(value: &Value) -> Result<ApprovalChallenge> {
    ApprovalChallenge::from_json(&serde_json::to_vec(value).unwrap())
}

#[test]
fn canonical_payload_and_domain_separated_challenge_match_independent_golden_vector() {
    // Generated independently with Python json(sort_keys=True,separators=(",",":"))
    // and hashlib.sha256, not by this module's hash implementation.
    let expected = concat!(
        "{\"challenge_id\":\"00000000-0000-0000-0000-000000000005\",\"decision\":\"approve\",",
        "\"expires_at\":\"2026-10-31T00:05:00Z\",\"issued_at\":\"2026-10-31T00:00:00Z\",",
        "\"nonce\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\",",
        "\"org_id\":\"00000000-0000-0000-0000-000000000001\",\"origin\":\"http://localhost:8787\",",
        "\"principal_id\":\"00000000-0000-0000-0000-000000000003\",",
        "\"project_id\":\"00000000-0000-0000-0000-000000000002\",",
        "\"requirements_hash\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
        "\"role\":\"owner\",\"rp_id\":\"localhost\",\"schema_version\":\"fw.approval-challenge-payload/v1\",",
        "\"subject\":{\"plan_ref\":{\"plan_hash\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
        "\"plan_id\":\"00000000-0000-0000-0000-000000000004\",\"plan_kind\":\"policy_change\"},\"subject_type\":\"plan\"},",
        "\"subject_valid_until\":\"2026-10-31T00:15:00Z\"}"
    );
    let challenge = fixed();
    assert_eq!(challenge.canonical_payload(), expected.as_bytes());
    assert_eq!(
        challenge.payload_hash(),
        "sha256:9d92918bac3ffec2d18b4e54b2fdbfad5f6e3679c65528e3c2bcebdaf9a00d01"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(challenge.challenge_bytes()),
        "73jkO3cI_GXmK2Q3r3HxjJuxCvDXEyw1qTd3twYHhIg"
    );
    assert_ne!(
        challenge.challenge_bytes().as_slice(),
        Sha256::digest(challenge.canonical_payload()).as_slice()
    );
}

#[test]
fn issue_generates_fresh_server_material_and_roundtrip_recomputes_private_caches() {
    let a = ApprovalChallenge::issue(&context(), &verifier(), NOW).unwrap();
    let b = ApprovalChallenge::issue(&context(), &verifier(), NOW).unwrap();
    assert_ne!(a.challenge_id(), b.challenge_id());
    assert_ne!(value(&a)["nonce"], value(&b)["nonce"]);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(value(&a)["nonce"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        uuid::Uuid::parse_str(a.challenge_id())
            .unwrap()
            .get_version_num(),
        4
    );
    let decoded = ApprovalChallenge::from_json(a.canonical_payload()).unwrap();
    assert_eq!(decoded.canonical_payload(), a.canonical_payload());
    assert_eq!(decoded.payload_hash(), a.payload_hash());
    assert_eq!(decoded.challenge_bytes(), a.challenge_bytes());
    let decoded: ApprovalChallenge = serde_json::from_value(value(&a)).unwrap();
    decoded
        .validate_context(&context(), &verifier(), NOW)
        .unwrap();
    assert_eq!(decoded.challenge_bytes(), a.challenge_bytes());
    assert!(value(&a).get("challenge_bytes").is_none());
    assert!(value(&a).get("canonical").is_none());
}

#[test]
fn changing_any_valid_bound_payload_field_changes_the_assertion_challenge() {
    let original = fixed();
    let patches = [
        ("/challenge_id", json!(id(6))),
        ("/nonce", json!(URL_SAFE_NO_PAD.encode([7u8; 32]))),
        ("/org_id", json!(id(7))),
        ("/project_id", json!(id(8))),
        ("/principal_id", json!(id(9))),
        ("/subject/plan_ref/plan_id", json!(id(10))),
        ("/subject/plan_ref/plan_hash", json!(hash('c'))),
        ("/subject/plan_ref/plan_kind", json!("add_access_lease")),
        ("/requirements_hash", json!(hash('d'))),
        ("/decision", json!("reject")),
        ("/role", json!("network_reviewer")),
        ("/origin", json!("http://localhost:8788")),
        ("/issued_at", json!(format_time(NOW + 1).unwrap())),
        ("/expires_at", json!(format_time(NOW + 299).unwrap())),
        (
            "/subject_valid_until",
            json!(format_time(NOW + 901).unwrap()),
        ),
    ];
    for (path, replacement) in patches {
        let mut altered = value(&original);
        *altered.pointer_mut(path).unwrap() = replacement;
        let changed = decode(&altered).unwrap();
        assert_ne!(
            changed.challenge_bytes(),
            original.challenge_bytes(),
            "{path}"
        );
        assert_ne!(changed.payload_hash(), original.payload_hash(), "{path}");
    }
}

#[test]
fn current_authority_context_and_exact_configured_origin_must_still_match() {
    let challenge = fixed();
    let original = context();
    let mut variants = Vec::new();
    let mut c = original.clone();
    c.org_id = id(11);
    variants.push(c);
    let mut c = original.clone();
    c.project_id = id(12);
    variants.push(c);
    let mut c = original.clone();
    c.principal_id = id(13);
    variants.push(c);
    let mut c = original.clone();
    c.requirements_hash = hash('c');
    variants.push(c);
    let mut c = original.clone();
    c.decision = ApprovalDecision::Reject;
    variants.push(c);
    let mut c = original.clone();
    c.role = ApprovalRole::SecurityReviewer;
    variants.push(c);
    let mut c = original.clone();
    c.subject_valid_until -= 1;
    variants.push(c);
    let mut c = original.clone();
    if let ApprovalChallengeSubject::Plan { ref mut plan_ref } = c.subject {
        plan_ref.plan_hash = hash('d');
    }
    variants.push(c);
    for changed in variants {
        assert!(matches!(
            challenge.validate_context(&changed, &verifier(), NOW),
            Err(AuthorityError::Binding)
        ));
    }
    assert!(matches!(
        challenge.validate_context(
            &original,
            &WebAuthn::new("http://localhost:8788").unwrap(),
            NOW
        ),
        Err(AuthorityError::Binding)
    ));
    challenge
        .validate_context(&original, &verifier(), NOW + 299)
        .unwrap();
    assert!(matches!(
        challenge.validate_context(&original, &verifier(), NOW + 300),
        Err(AuthorityError::Time)
    ));
}

#[test]
fn challenge_lifetime_never_outlives_subject_or_five_minutes_and_rejects_clock_rollback() {
    let challenge = fixed();
    assert_eq!(challenge.issued_at(), NOW);
    assert_eq!(challenge.expires_at(), NOW + 300);
    assert!(matches!(
        challenge.validate_now(NOW - 1),
        Err(AuthorityError::Time)
    ));
    assert!(matches!(
        challenge.validate_now(NOW + 300),
        Err(AuthorityError::Time)
    ));
    let mut c = context();
    c.subject_valid_until = NOW + 1;
    let short = ApprovalChallenge::issue(&c, &verifier(), NOW).unwrap();
    assert_eq!(short.expires_at(), NOW + 1);
    assert!(short.validate_now(NOW).is_ok());
    assert!(short.validate_now(NOW + 1).is_err());
    for end in [NOW, NOW - 1, -1, MAX_TIME + 1] {
        c.subject_valid_until = end;
        assert!(ApprovalChallenge::issue(&c, &verifier(), NOW).is_err());
    }
    c.subject_valid_until = MAX_TIME;
    let final_second = ApprovalChallenge::issue(&c, &verifier(), MAX_TIME - 1).unwrap();
    assert_eq!(final_second.expires_at(), MAX_TIME);
    assert!(ApprovalChallenge::issue(&c, &verifier(), MAX_TIME).is_err());
    assert!(ApprovalChallenge::issue(&c, &verifier(), i64::MAX).is_err());
}

#[test]
fn persisted_payload_rejects_oversized_expired_interval_and_noncanonical_values() {
    let original = value(&fixed());
    let invalids = [
        ("/schema_version", json!("fw.unknown/v1")),
        ("/challenge_id", json!("00000000000000000000000000000005")),
        ("/org_id", json!("not a uuid")),
        ("/project_id", json!("00000000-0000-0000-0000-00000000000A")),
        ("/principal_id", json!(true)),
        ("/nonce", json!(URL_SAFE_NO_PAD.encode([1u8; 31]))),
        ("/nonce", json!(URL_SAFE_NO_PAD.encode([1u8; 33]))),
        (
            "/nonce",
            json!(format!("{}=", original["nonce"].as_str().unwrap())),
        ),
        ("/nonce", json!("?".repeat(43))),
        ("/nonce", json!("A".repeat(9000))),
        (
            "/requirements_hash",
            json!(format!("sha256:{}", "A".repeat(64))),
        ),
        ("/role", json!("admin")),
        ("/decision", json!("approved")),
        ("/rp_id", json!("127.0.0.1")),
        ("/origin", json!("http://127.0.0.1:8787")),
        ("/origin", json!("https://localhost:8787")),
        ("/origin", json!("http://localhost:8787/")),
        ("/origin", json!("http://localhost:8787?x=1")),
        ("/issued_at", json!("2026-10-31T00:00:00+00:00")),
        ("/issued_at", json!(format_time(NOW - 1).unwrap())),
        ("/expires_at", json!(format_time(NOW).unwrap())),
        ("/expires_at", json!(format_time(NOW + 301).unwrap())),
        (
            "/subject_valid_until",
            json!(format_time(NOW + 299).unwrap()),
        ),
        ("/subject/plan_ref/plan_kind", json!("delegated")),
        ("/subject/plan_ref/plan_id", json!("plan 1")),
        ("/subject/plan_ref/plan_hash", json!("sha256:bad")),
    ];
    for (path, replacement) in invalids {
        let mut altered = original.clone();
        *altered.pointer_mut(path).unwrap() = replacement;
        assert!(decode(&altered).is_err(), "{path}: {altered}");
    }
}

#[test]
fn closed_duplicate_free_payload_cannot_accept_client_authority_or_cached_digest() {
    for path in ["", "/subject", "/subject/plan_ref"] {
        let mut altered = value(&fixed());
        altered
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("approved".into(), json!(true));
        assert!(decode(&altered).is_err());
    }
    let mut altered = value(&fixed());
    altered["challenge_bytes"] = json!("forged");
    assert!(decode(&altered).is_err());
    let valid = String::from_utf8(fixed().canonical_payload().to_vec()).unwrap();
    let duplicate = format!("{{\"principal_id\":\"{}\",{}", id(3), &valid[1..]);
    assert!(ApprovalChallenge::from_json(duplicate.as_bytes()).is_err());
    assert!(serde_json::from_str::<ApprovalChallenge>(&duplicate).is_err());
    let mut padded = vec![b' '; MAX_PAYLOAD_BYTES];
    padded.extend_from_slice(valid.as_bytes());
    assert!(ApprovalChallenge::from_json(&padded).is_err());
}

#[test]
fn bootstrap_subject_uses_owner_role_and_a_separate_domain_without_fake_plan_reference() {
    let mut c = context();
    c.subject = ApprovalChallengeSubject::AuthorityBootstrap {
        manifest_id: id(4),
        subject_hash: hash('a'),
    };
    let bootstrap = ApprovalChallenge::with_material(
        &c,
        &verifier(),
        NOW,
        id(5),
        std::array::from_fn(|i| i as u8),
    )
    .unwrap();
    assert!(bootstrap.plan_challenge_response().is_none());
    // Independent Python/hashlib vector for the distinct bootstrap domain.
    assert_eq!(
        URL_SAFE_NO_PAD.encode(bootstrap.challenge_bytes()),
        "w1NUfZBq5Z5OOuHCIxilAEMyYQyHyyqMHfDz5f9LJ44"
    );
    assert_ne!(bootstrap.challenge_bytes(), fixed().challenge_bytes());
    let mut wrong_domain = Sha256::new();
    wrong_domain.update(PLAN_DOMAIN);
    wrong_domain.update(bootstrap.canonical_payload());
    assert_ne!(
        bootstrap.challenge_bytes().as_slice(),
        wrong_domain.finalize().as_slice()
    );
    bootstrap.validate_context(&c, &verifier(), NOW).unwrap();
    let mut changed = c.clone();
    changed.subject = ApprovalChallengeSubject::AuthorityBootstrap {
        manifest_id: id(6),
        subject_hash: hash('a'),
    };
    assert!(matches!(
        bootstrap.validate_context(&changed, &verifier(), NOW),
        Err(AuthorityError::Binding)
    ));
    let mut changed = c.clone();
    changed.subject = ApprovalChallengeSubject::AuthorityBootstrap {
        manifest_id: id(4),
        subject_hash: hash('c'),
    };
    assert!(matches!(
        bootstrap.validate_context(&changed, &verifier(), NOW),
        Err(AuthorityError::Binding)
    ));
    for role in [
        ApprovalRole::NetworkReviewer,
        ApprovalRole::SecurityReviewer,
        ApprovalRole::ServiceReviewer,
    ] {
        c.role = role;
        assert!(ApprovalChallenge::issue(&c, &verifier(), NOW).is_err());
    }
}

#[test]
fn plan_response_retains_original_closed_schema_fields_without_serialized_server_state() {
    let challenge = fixed();
    let response = challenge.plan_challenge_response().unwrap();
    let original: Value =
        serde_json::from_str(include_str!("../../../docs/specs/F_확장계약_스키마.json")).unwrap();
    let required = original["$defs"]["ApprovalChallenge"]["required"]
        .as_array()
        .unwrap();
    assert_eq!(response.as_object().unwrap().len(), required.len());
    for name in required {
        assert!(response.get(name.as_str().unwrap()).is_some());
    }
    assert_eq!(
        response["plan_ref"],
        value(&challenge)["subject"]["plan_ref"]
    );
    assert_eq!(response["challenge_payload_hash"], challenge.payload_hash());
    assert!(response.get("principal_id").is_none());
    assert!(response.get("state").is_none());
}
