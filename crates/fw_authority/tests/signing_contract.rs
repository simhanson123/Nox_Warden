use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use fw_authority::*;
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use serde_json::{Value, json};

const JOB_ID: &str = "00000000-0000-4000-8000-000000000071";
const INTENT_ID: &str = "00000000-0000-4000-8000-000000000072";
const OTHER_ID: &str = "00000000-0000-4000-8000-000000000073";

fn payload() -> Value {
    serde_json::from_str::<Value>(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap()["grant"]["payload"]
        .clone()
}

fn policy_payload() -> Value {
    let mut p = payload();
    for key in [
        "lease_id",
        "request_id",
        "workload_binding_id",
        "requested_policy_hashes",
        "envelope_hash",
        "delegation_hash",
        "reservation",
    ] {
        p.as_object_mut().unwrap().remove(key);
    }
    p["schema_version"] = "f.policy-change-grant/v1".into();
    p["change_kind"] = "policy_change".into();
    p["dispatch_reservation_id"] = OTHER_ID.into();
    p
}

fn job(payload: Value) -> SigningJob {
    SigningJob {
        schema_version: SIGNING_JOB_SCHEMA.into(),
        job_id: JOB_ID.into(),
        intent_id: INTENT_ID.into(),
        payload_hash: canonical_hash(&payload).unwrap(),
        payload,
    }
}

fn context(p: &Value) -> GrantContext {
    let string = |key: &str| p[key].as_str().unwrap().to_owned();
    GrantContext {
        org_id: string("org_id"),
        project_id: string("project_id"),
        target_id: string("target_id"),
        plan_hash: string("plan_hash"),
        artifact_hash: string("artifact_hash"),
        baseline_hash: string("baseline_hash"),
        desired_state_hash: string("desired_state_hash"),
        approval_set_hash: string("approval_set_hash"),
        authority_epoch: p["authority_epoch"].as_str().unwrap().parse().unwrap(),
        now_unix: chrono::DateTime::parse_from_rfc3339(p["issued_at"].as_str().unwrap())
            .unwrap()
            .timestamp(),
    }
}

// Test-only raw Ed25519 signing deliberately supplies no AuthorityEvidence
// implementation. Its signature proves cryptography, not production eligibility.
fn signed(p: Value) -> (SignedGrant, TrustKey, GrantContext) {
    let context = context(&p);
    let kind = if p["schema_version"] == "f.grant/v1" {
        CORE_GRANT_TYPE
    } else {
        POLICY_CHANGE_GRANT_TYPE
    };
    let key = SigningKey::from_bytes(&[0x69; 32]);
    let bytes = canonical_bytes(&p).unwrap();
    let grant = SignedGrant {
        payload: p,
        dsse: DsseEnvelope {
            payload_type: kind.into(),
            payload: STANDARD.encode(&bytes),
            signatures: vec![DsseSignature {
                keyid: "synthetic-signing-contract-key".into(),
                sig: STANDARD.encode(key.sign(&pae(kind, &bytes)).to_bytes()),
            }],
        },
    };
    let trust = TrustKey {
        key_id: "synthetic-signing-contract-key".into(),
        org_id: context.org_id.clone(),
        payload_type: kind.into(),
        public_key: key.verifying_key().to_bytes(),
        not_before: context.now_unix - 1,
        not_after: context.now_unix + 3600,
        revoked: false,
    };
    (grant, trust, context)
}

fn result(job: &SigningJob, signed_grant: SignedGrant) -> SignerResult {
    SignerResult {
        schema_version: SIGNER_RESULT_SCHEMA.into(),
        job_id: job.job_id.clone(),
        intent_id: job.intent_id.clone(),
        payload_hash: job.payload_hash.clone(),
        signed_grant,
    }
}

#[test]
fn both_grant_domains_retain_exact_canonical_result_and_replay_identity() {
    for p in [payload(), policy_payload()] {
        let wire = job(p.clone());
        let prepared = parse_signing_job(&canonical_bytes(&wire).unwrap()).unwrap();
        let (grant, trust, context) = signed(p);
        let reply = result(&wire, grant.clone());
        let pretty = serde_json::to_vec_pretty(&reply).unwrap();
        let parsed = parse_signer_result(&pretty).unwrap();
        let first = verify_signer_result(&prepared, &parsed, &trust, &context).unwrap();
        let second = verify_signer_result(&prepared, &reply, &trust, &context).unwrap();
        assert_eq!(
            first.canonical_grant_bytes(),
            canonical_bytes(&grant).unwrap()
        );
        assert_eq!(
            first.grant_hash(),
            hash_bytes(first.canonical_grant_bytes())
        );
        assert_eq!(
            first.canonical_result_bytes(),
            second.canonical_result_bytes()
        );
        assert_eq!(first.verified_grant().generation(), 7);
        assert_eq!(
            prepared.canonical_job_bytes(),
            canonical_bytes(&wire).unwrap()
        );
        assert_eq!(
            prepared.payload_bytes(),
            canonical_bytes(&wire.payload).unwrap()
        );
    }
}

#[test]
fn a_valid_signature_for_another_generation_or_reservation_is_not_this_job() {
    let original = job(payload());
    let prepared = validate_signing_job(&original).unwrap();
    for field in ["target_generation", "grant_id", "reservation"] {
        let mut replacement = original.payload.clone();
        match field {
            "target_generation" => replacement[field] = "8".into(),
            "grant_id" => replacement[field] = OTHER_ID.into(),
            _ => replacement[field]["reservation_id"] = OTHER_ID.into(),
        }
        let (grant, trust, context) = signed(replacement);
        // All three replacements are cryptographically valid and satisfy the
        // generic context. The immutable job must independently reject them.
        verify_grant(&grant, &trust, &context).unwrap();
        let reply = result(&original, grant);
        assert!(matches!(
            verify_signer_result(&prepared, &reply, &trust, &context),
            Err(AuthorityError::Binding)
        ));
    }
}

#[test]
fn reply_cannot_rebind_the_intent_job_or_payload_digest() {
    let wire = job(payload());
    let prepared = validate_signing_job(&wire).unwrap();
    let (grant, trust, context) = signed(wire.payload.clone());
    let reply = result(&wire, grant);
    for field in ["job_id", "intent_id", "payload_hash"] {
        let mut changed = reply.clone();
        match field {
            "job_id" => changed.job_id = OTHER_ID.into(),
            "intent_id" => changed.intent_id = OTHER_ID.into(),
            _ => changed.payload_hash = format!("sha256:{}", "a".repeat(64)),
        }
        assert!(matches!(
            verify_signer_result(&prepared, &changed, &trust, &context),
            Err(AuthorityError::Binding)
        ));
    }
}

#[test]
fn current_key_and_authority_are_rechecked_for_each_reply() {
    let wire = job(payload());
    let prepared = validate_signing_job(&wire).unwrap();
    let (grant, trust, context) = signed(wire.payload.clone());
    let reply = result(&wire, grant);
    for case in [
        "revoked",
        "key",
        "purpose",
        "organization",
        "not_yet",
        "expired",
    ] {
        let mut changed = trust.clone();
        match case {
            "revoked" => changed.revoked = true,
            "key" => {
                changed.public_key = SigningKey::from_bytes(&[0x70; 32])
                    .verifying_key()
                    .to_bytes()
            }
            "purpose" => {
                changed.payload_type = "application/vnd.f.native-observation.v1+json".into()
            }
            "organization" => changed.org_id = OTHER_ID.into(),
            "not_yet" => changed.not_before = context.now_unix + 1,
            _ => changed.not_after = context.now_unix,
        }
        assert!(
            verify_signer_result(&prepared, &reply, &changed, &context).is_err(),
            "{case}"
        );
    }
    for case in ["epoch", "target", "approval", "baseline", "expiry"] {
        let mut changed = context.clone();
        match case {
            "epoch" => changed.authority_epoch += 1,
            "target" => changed.target_id = OTHER_ID.into(),
            "approval" => changed.approval_set_hash = format!("sha256:{}", "a".repeat(64)),
            "baseline" => changed.baseline_hash = format!("sha256:{}", "b".repeat(64)),
            _ => changed.now_unix += 300,
        }
        assert!(
            verify_signer_result(&prepared, &reply, &trust, &changed).is_err(),
            "{case}"
        );
    }
}

#[test]
fn payload_normalization_and_forged_signatures_are_rejected() {
    let wire = job(payload());
    let prepared = validate_signing_job(&wire).unwrap();
    let (grant, trust, context) = signed(wire.payload.clone());
    let reply = result(&wire, grant);
    let mut pretty_payload = reply.clone();
    let bytes = serde_json::to_vec_pretty(&wire.payload).unwrap();
    let key = SigningKey::from_bytes(&[0x69; 32]);
    pretty_payload.signed_grant.dsse.payload = STANDARD.encode(&bytes);
    pretty_payload.signed_grant.dsse.signatures[0].sig =
        STANDARD.encode(key.sign(&pae(CORE_GRANT_TYPE, &bytes)).to_bytes());
    assert!(verify_signer_result(&prepared, &pretty_payload, &trust, &context).is_err());
    let mut forged = reply;
    forged.signed_grant.dsse.signatures[0].sig = STANDARD.encode([0; 64]);
    assert!(verify_signer_result(&prepared, &forged, &trust, &context).is_err());
}

#[test]
fn strict_wire_admission_rejects_duplicate_unknown_and_over_budget_inputs() {
    let wire = job(payload());
    let json = canonical_bytes(&wire).unwrap();
    let duplicate = format!(
        "{{\"job_id\":\"{JOB_ID}\",{}",
        std::str::from_utf8(&json[1..]).unwrap()
    );
    assert!(parse_signing_job(duplicate.as_bytes()).is_err());
    let mut unknown = serde_json::to_value(&wire).unwrap();
    unknown["production_qualified"] = true.into();
    assert!(parse_signing_job(&canonical_bytes(&unknown).unwrap()).is_err());
    assert!(parse_signing_job(&vec![b' '; MAX_SIGNING_JOB_BYTES + 1]).is_err());
    let (grant, _, _) = signed(wire.payload.clone());
    let reply = result(&wire, grant);
    let bytes = canonical_bytes(&reply).unwrap();
    let duplicate = format!(
        "{{\"intent_id\":\"{INTENT_ID}\",{}",
        std::str::from_utf8(&bytes[1..]).unwrap()
    );
    assert!(parse_signer_result(duplicate.as_bytes()).is_err());
    let text = String::from_utf8(bytes).unwrap();
    let nested_duplicate =
        text.replacen("\"signatures\":[", "\"signatures\":[],\"signatures\":[", 1);
    assert!(parse_signer_result(nested_duplicate.as_bytes()).is_err());
    let mut unknown = serde_json::to_value(&reply).unwrap();
    unknown["signed_grant"]["dsse"]["qualified"] = true.into();
    assert!(parse_signer_result(&canonical_bytes(&unknown).unwrap()).is_err());
    assert!(parse_signer_result(&vec![b' '; MAX_SIGNER_RESULT_BYTES + 1]).is_err());
}

#[test]
fn constructed_payloads_are_bounded_before_canonicalization_and_cloning() {
    let original = job(payload());
    let mut too_large = original.clone();
    too_large.payload["principal_id"] = "x".repeat(MAX_SIGNING_JOB_BYTES * 2).into();
    assert!(validate_signing_job(&too_large).is_err());
    let mut deep = original.clone();
    let mut value = Value::Null;
    for _ in 0..40 {
        value = json!([value]);
    }
    deep.payload["principal_id"] = value;
    assert!(validate_signing_job(&deep).is_err());
    let prepared = validate_signing_job(&original).unwrap();
    let (grant, trust, context) = signed(original.payload.clone());
    let mut reply = result(&original, grant);
    reply.signed_grant.dsse.payload = "a".repeat(MAX_SIGNER_RESULT_BYTES + 1);
    assert!(verify_signer_result(&prepared, &reply, &trust, &context).is_err());
    reply.signed_grant.payload = deep.payload;
    assert!(verify_signer_result(&prepared, &reply, &trust, &context).is_err());
}

#[test]
fn immutable_job_rejects_noncanonical_counters_bad_hashes_and_unknown_payload_claims() {
    let original = job(payload());
    for field in ["schema", "job_id", "hash", "counter", "unknown"] {
        let mut changed = original.clone();
        match field {
            "schema" => changed.schema_version = "f.signer-result/v1".into(),
            "job_id" => changed.job_id = "not-a-uuid".into(),
            "hash" => changed.payload_hash = format!("sha256:{}", "a".repeat(64)),
            "counter" => changed.payload["target_generation"] = "07".into(),
            _ => changed.payload["qualified"] = true.into(),
        }
        assert!(validate_signing_job(&changed).is_err(), "{field}");
    }
    let mut mutable_source = original.clone();
    let prepared = validate_signing_job(&mutable_source).unwrap();
    mutable_source.payload["target_generation"] = "999".into();
    assert_eq!(prepared.job(), &original);
}

#[test]
fn canonical_u64_maximum_is_retained_without_truncation() {
    let mut p = policy_payload();
    p["target_generation"] = u64::MAX.to_string().into();
    p["authority_epoch"] = u64::MAX.to_string().into();
    let wire = job(p.clone());
    let prepared = validate_signing_job(&wire).unwrap();
    let (grant, trust, context) = signed(p);
    let verified =
        verify_signer_result(&prepared, &result(&wire, grant), &trust, &context).unwrap();
    assert_eq!(verified.verified_grant().generation(), u64::MAX);
    assert_eq!(verified.verified_grant().authority_epoch(), u64::MAX);
}
