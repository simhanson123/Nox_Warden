use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use fw_backend_linux::*;
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use fw_domain::{Action, Policy};
use fw_native_evidence::*;
use fw_planner::{
    PolicyAssociation, PolicyMutation, PolicyReviewEvidence, StateIr, compose_policy_change,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const NOW: i64 = 1_800_000_000;
const ORG: &str = "11111111-1111-4111-8111-111111111111";
const PROJECT: &str = "22222222-2222-4222-8222-222222222222";
const TARGET: &str = "33333333-3333-4333-8333-333333333333";
const OWNER: &str = "44444444-4444-4444-8444-444444444444";
const SOURCE: &str = "55555555-5555-4555-8555-555555555555";
const DEST: &str = "66666666-6666-4666-8666-666666666666";
const BOOT: &str = "77777777-7777-4777-8777-777777777777";
const SEED: [u8; 32] = [19; 32];

fn references() -> LabReferences {
    let scope = LabScope {
        schema_version: "fw.isolated-lab-scope/v1".into(),
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        network_namespace: "net:[12345]".into(),
        interfaces: vec!["lo".into()],
        conntrack_zone: 0,
    };
    let scope_hash = canonical_hash(&scope).unwrap();
    LabReferences {
        baseline: LabBaseline {
            schema_version: "fw.isolated-lab-baseline/v1".into(),
            scope_hash: scope_hash.clone(),
            management_paths: vec![],
            default_action: "drop".into(),
        },
        source_snapshot: LabSourceSnapshot {
            schema_version: "fw.isolated-lab-snapshot/v1".into(),
            scope_hash: scope_hash.clone(),
            assets: [SOURCE, DEST]
                .iter()
                .map(|id| LabAsset {
                    asset_id: (*id).into(),
                    cidrs: vec!["127.0.0.1/32".into()],
                })
                .collect(),
        },
        capability: LabCapability {
            schema_version: "fw.isolated-lab-capability/v1".into(),
            scope_hash,
            platform: "linux".into(),
            profile: "host-tcp-udp-lab".into(),
            production_qualified: false,
        },
        scope,
    }
}
fn policy(action: &str, n: u16) -> Policy {
    let lifetime = if action == "allow" {
        json!({"kind":"lease","not_before":timestamp(NOW-60).unwrap(),"expires_at":timestamp(NOW+120).unwrap()})
    } else {
        json!({"kind":"review","not_before":timestamp(NOW-60).unwrap(),"review_at":timestamp(NOW+3600).unwrap()})
    };
    serde_json::from_value(json!({"schema_version":"f.policy/v1","policy_id":format!("00000000-0000-4000-8000-{n:012}"),"policy_revision":1,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"owner_id":OWNER,"reason":"synthetic isolated evidence test","action":action,"log_mode":"none","lifetime":lifetime,"scope":{"family":"ipv4","direction":"input","source_asset_ids":[SOURCE],"destination_asset_ids":[DEST],"source_cidrs":["127.0.0.1/32"],"destination_cidrs":["127.0.0.1/32"],"transport":{"protocol":"tcp","destination_ports":[{"start":440+n,"end":440+n}]},"ingress_interfaces":["lo"],"egress_interfaces":[]}})).unwrap()
}
fn association(p: &Policy) -> PolicyAssociation {
    PolicyAssociation {
        policy_hash: canonical_hash(p).unwrap(),
        lease_id: (p.action == Action::Allow).then(|| BOOT.into()),
        request_id: OWNER.into(),
        authority_basis_hash: hash_bytes(b"synthetic basis"),
    }
}
fn fixture() -> (Value, PolicyReviewEvidence, LabReferences) {
    let refs = references();
    let allow = policy("allow", 1);
    let before = StateIr {
        schema_version: "f.state-ir/v1".into(),
        target_id: TARGET.into(),
        platform: "linux".into(),
        profile: "lab".into(),
        management_baseline_hash: canonical_hash(&refs.baseline).unwrap(),
        associations: vec![association(&allow)],
        policies: vec![allow],
        tombstone_hashes: vec![],
        source_snapshot_hash: canonical_hash(&refs.source_snapshot).unwrap(),
        target_capability_hash: canonical_hash(&refs.capability).unwrap(),
        normalization_version: "f.normalize/nfc-v1".into(),
    };
    let deny = policy("deny", 2);
    let a = association(&deny);
    let ops = vec![PolicyMutation::AddDeny {
        policy: Box::new(deny),
    }];
    let candidate = compose_policy_change(&before, &ops, &[a], &BTreeSet::new()).unwrap();
    let after = candidate.state;
    let plan = json!({"schema_version":"f.policy-change-plan/v1","change_kind":"policy_change","org_id":ORG,"project_id":PROJECT,"target_id":TARGET,
        "operations":ops,"baseline_hash":candidate.baseline_hash,"desired_state_hash":candidate.desired_state_hash,"request_patch_hash":candidate.request_patch_hash,
        "candidate_state_ref":{"object_hash":after.state_hash().unwrap(),"size_bytes":canonical_bytes(&after).unwrap().len()},
        "source_snapshot_hash":before.source_snapshot_hash,"target_capability_hash":before.target_capability_hash,
        "artifact_hash":compile_portable(&after,&refs).unwrap().artifact_hash().unwrap(),
        "effect_summary":{"relation":candidate.relation,"complete":true,"newly_allowed_region_hash":candidate.semantic_diff.newly_allowed_region_hash,"removed_region_hash":candidate.semantic_diff.removed_region_hash}});
    (plan, PolicyReviewEvidence { before, after }, refs)
}
fn snapshot(native: &Artifact) -> Value {
    let mut entries =
        vec![json!({"metainfo":{"version":"1.0.6","release_name":"test","json_schema_version":1}})];
    for (i, command) in native.nft_json["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let mut entry = command["add"].clone();
        let (_, object) = entry.as_object_mut().unwrap().iter_mut().next().unwrap();
        object["handle"] = json!(i + 1);
        if let Some(elements) = object.get_mut("elem") {
            for element in elements.as_array_mut().unwrap() {
                let timeout = element["elem"]["timeout"].as_u64().unwrap();
                element["elem"]["expires"] = json!(timeout - 1);
            }
        }
        entries.push(entry);
    }
    json!({"nftables":entries})
}
fn observation_fixture() -> (
    VerifiedCompilation,
    NativeObservationChallenge,
    NativeObservationPayload,
) {
    let (plan, review, refs) = fixture();
    let compilation = compile_evidence(&plan, &review, &refs).unwrap();
    let installation = bind_at(
        compilation.candidate(),
        &BindingContext {
            operation_id: OWNER.into(),
            grant_hash: hash_bytes(b"synthetic grant"),
            boot_id: BOOT.into(),
            network_namespace: refs.scope.network_namespace,
            wall_time_unix: NOW,
            monotonic_millis: 10_000,
            clock_uncertainty_seconds: 0,
            elapsed_seconds: 0,
            commit_budget_seconds: 2,
        },
    )
    .unwrap();
    let challenge = NativeObservationChallenge {
        schema_version: CHALLENGE_SCHEMA.into(),
        challenge_id: OWNER.into(),
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        observer_revision: "1".into(),
        observer_key_fingerprint: fingerprint(
            SigningKey::from_bytes(&SEED).verifying_key().as_bytes(),
        )
        .unwrap(),
        reference_revision: "1".into(),
        compilation_hash: compilation.evidence_hash().into(),
        metadata_receipt_hash: hash_bytes(b"separate metadata receipt"),
        metadata_report_hash: hash_bytes(b"f.target-capability/v1"),
        baseline_state_hash: compilation.baseline().desired_state_hash.clone(),
        expected_head: None,
        authority_epoch: "1".into(),
        generation: "2".into(),
        artifact_role: ArtifactRole::Candidate,
        artifact_hash: compilation.candidate().artifact_hash().unwrap(),
        installation_hash: canonical_hash(&installation).unwrap(),
        nonce: URL_SAFE_NO_PAD.encode([29; 32]),
        issued_at: timestamp(NOW).unwrap(),
        expires_at: timestamp(NOW + 300).unwrap(),
    };
    let payload = NativeObservationPayload {
        schema_version: PAYLOAD_SCHEMA.into(),
        production_qualified: false,
        readback: snapshot(&installation.native),
        installation,
        observation: ObservationContext {
            boot_id: BOOT.into(),
            network_namespace: "net:[12345]".into(),
            wall_time_unix: NOW + 1,
            monotonic_millis: 11_000,
        },
    };
    (compilation, challenge, payload)
}
fn verify(
    c: &NativeObservationChallenge,
    p: &SignedNativeObservation,
    artifact: &PortableArtifact,
) -> Result<VerifiedObservation> {
    verify_observation(
        c,
        p,
        SigningKey::from_bytes(&SEED).verifying_key().as_bytes(),
        artifact,
        NOW + 1,
        NOW + 200,
    )
}

#[test]
fn compilation_is_deterministic_and_binds_complete_plan_review_and_references() {
    let (plan, review, refs) = fixture();
    let first = compile_evidence(&plan, &review, &refs).unwrap();
    let second = compile_evidence(&plan, &review, &refs).unwrap();
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.evidence_hash(), hash_bytes(first.canonical_bytes()));
    assert_eq!(first.plan_hash(), canonical_hash(&plan).unwrap());
    assert_eq!(first.references_hash(), canonical_hash(&refs).unwrap());
    assert_eq!(
        first.candidate().artifact_hash().unwrap(),
        plan["artifact_hash"]
    );
    assert!(!first.candidate().production_qualified);
    let record: Value = serde_json::from_slice(first.canonical_bytes()).unwrap();
    assert_eq!(record["dispatch_allowed"], false);
}
#[test]
fn compilation_refuses_substituted_plan_artifact_tenant_references_and_supported_claim() {
    let (plan, review, refs) = fixture();
    for field in [
        "artifact_hash",
        "baseline_hash",
        "desired_state_hash",
        "target_capability_hash",
        "source_snapshot_hash",
    ] {
        let mut bad = plan.clone();
        bad[field] = json!(hash_bytes(b"wrong"));
        assert!(compile_evidence(&bad, &review, &refs).is_err(), "{field}");
    }
    let mut r = refs.clone();
    r.scope.org_id = OWNER.into();
    assert!(compile_evidence(&plan, &review, &r).is_err());
    let mut r = refs.clone();
    r.capability.production_qualified = true;
    assert!(compile_evidence(&plan, &review, &r).is_err());
    let mut r = refs.clone();
    r.source_snapshot.assets[0].cidrs = vec!["10.0.0.1/32".into()];
    assert!(compile_evidence(&plan, &review, &r).is_err());
}
#[test]
fn real_signature_and_native_correspondence_are_separate_recomputed_results() {
    let (compiled, c, p) = observation_fixture();
    let proof = sign_observation(&c, &p, &SEED, NOW + 1).unwrap();
    let verified = verify(&c, &proof, compiled.candidate()).unwrap();
    assert_eq!(verified.comparison(), Comparison::Match);
    assert_eq!(
        verified.observed_state_hash(),
        Some(compiled.candidate().desired_state_hash.as_str())
    );
    assert_eq!(verified.valid_until(), NOW + 200);
    assert_eq!(
        verified.payload_hash(),
        hash_bytes(verified.payload_bytes())
    );
    assert_eq!(
        verified.readback_hash(),
        canonical_hash(&p.readback).unwrap()
    );
    let roundtrip = SignedNativeObservation::parse(&proof.canonical_bytes().unwrap()).unwrap();
    assert_eq!(roundtrip.signature, proof.signature);
}
#[test]
fn signed_unknown_and_mismatch_captures_have_no_observed_state_hash() {
    let (compiled, c, p) = observation_fixture();
    let mut unknown = p.clone();
    unknown.readback["nftables"]
        .as_array_mut()
        .unwrap()
        .push(json!({"unsupported":{"private":"no interpretation"}}));
    let proof = sign_observation(&c, &unknown, &SEED, NOW + 1).unwrap();
    let result = verify(&c, &proof, compiled.candidate()).unwrap();
    assert_eq!(result.comparison(), Comparison::Unknown);
    assert_eq!(result.observed_state_hash(), None);
    let mut mismatch = p.clone();
    let entries = mismatch.readback["nftables"].as_array_mut().unwrap();
    let pos = entries
        .iter()
        .position(|x| x.get("rule").is_some())
        .unwrap();
    entries.remove(pos);
    let proof = sign_observation(&c, &mismatch, &SEED, NOW + 1).unwrap();
    let result = verify(&c, &proof, compiled.candidate()).unwrap();
    assert_eq!(result.comparison(), Comparison::Mismatch);
    assert_eq!(result.observed_state_hash(), None);
}
#[test]
fn wrong_boot_namespace_and_monotonic_regression_remain_unknown() {
    let (compiled, c, p) = observation_fixture();
    for n in 0..3 {
        let mut bad = p.clone();
        match n {
            0 => bad.observation.boot_id = OWNER.into(),
            1 => bad.observation.network_namespace = "net:[54321]".into(),
            _ => bad.observation.monotonic_millis = 9_999,
        };
        let proof = sign_observation(&c, &bad, &SEED, NOW + 1).unwrap();
        let result = verify(&c, &proof, compiled.candidate()).unwrap();
        assert_eq!(result.comparison(), Comparison::Unknown);
        assert_eq!(result.observed_state_hash(), None);
    }
}

#[test]
fn signed_token_refresh_cannot_extend_the_original_native_deadline() {
    let (compiled, c, mut p) = observation_fixture();
    // Original remaining lifetime is still reported after 100 elapsed seconds,
    // as after a refresh. The nft shape itself remains valid.
    p.observation.wall_time_unix = NOW + 100;
    p.observation.monotonic_millis = 110_000;
    let proof = sign_observation(&c, &p, &SEED, NOW + 100).unwrap();
    let result = verify_observation(
        &c,
        &proof,
        SigningKey::from_bytes(&SEED).verifying_key().as_bytes(),
        compiled.candidate(),
        NOW + 100,
        NOW + 200,
    )
    .unwrap();
    assert_eq!(result.comparison(), Comparison::Mismatch);
    assert_eq!(result.observed_state_hash(), None);
}

#[test]
fn baseline_role_requires_the_exact_baseline_state() {
    let (compiled, mut c, mut p) = observation_fixture();
    p.installation = bind_at(compiled.baseline(), &p.installation.manifest.binding).unwrap();
    p.readback = snapshot(&p.installation.native);
    c.artifact_role = ArtifactRole::Baseline;
    c.artifact_hash = compiled.baseline().artifact_hash().unwrap();
    c.installation_hash = canonical_hash(&p.installation).unwrap();
    let proof = sign_observation(&c, &p, &SEED, NOW + 1).unwrap();
    let result = verify(&c, &proof, compiled.baseline()).unwrap();
    assert_eq!(result.comparison(), Comparison::Match);
    c.baseline_state_hash = compiled.candidate().desired_state_hash.clone();
    let wrong = sign_observation(&c, &p, &SEED, NOW + 1).unwrap();
    assert!(verify(&c, &wrong, compiled.baseline()).is_err());
}
#[test]
fn every_authority_context_field_is_signature_bound() {
    let (compiled, c, p) = observation_fixture();
    let proof = sign_observation(&c, &p, &SEED, NOW + 1).unwrap();
    for field in [
        "challenge_id",
        "org_id",
        "project_id",
        "target_id",
        "observer_revision",
        "reference_revision",
        "compilation_hash",
        "metadata_receipt_hash",
        "metadata_report_hash",
        "baseline_state_hash",
        "expected_head",
        "authority_epoch",
        "generation",
        "artifact_role",
        "artifact_hash",
        "installation_hash",
        "nonce",
    ] {
        let mut value = serde_json::to_value(&c).unwrap();
        value[field] = match field {
            "observer_revision" | "reference_revision" | "authority_epoch" | "generation" => {
                json!("3")
            }
            "challenge_id" | "org_id" | "project_id" | "target_id" => json!(BOOT),
            "artifact_role" => json!("baseline"),
            "nonce" => json!(URL_SAFE_NO_PAD.encode([30; 32])),
            _ => json!(hash_bytes(b"substitute")),
        };
        let changed: NativeObservationChallenge = serde_json::from_value(value).unwrap();
        let mut altered = proof.clone();
        altered.challenge = changed.clone();
        assert!(
            verify(&changed, &altered, compiled.candidate()).is_err(),
            "{field}"
        );
    }
}
#[test]
fn wrong_key_tampered_signature_and_metadata_purpose_are_refused() {
    let (compiled, c, p) = observation_fixture();
    assert!(sign_observation(&c, &p, &[20; 32], NOW + 1).is_err());
    let proof = sign_observation(&c, &p, &SEED, NOW + 1).unwrap();
    assert!(
        verify_observation(
            &c,
            &proof,
            SigningKey::from_bytes(&[20; 32]).verifying_key().as_bytes(),
            compiled.candidate(),
            NOW + 1,
            NOW + 200
        )
        .is_err()
    );
    let mut bad = proof.clone();
    bad.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(verify(&c, &bad, compiled.candidate()).is_err());
    let mut bad = proof;
    bad.schema_version = "fw.target-metadata-proof/v1".into();
    assert!(verify(&c, &bad, compiled.candidate()).is_err());
}
#[test]
fn expiry_measurement_time_and_trust_deadlines_are_exclusive() {
    let (compiled, c, p) = observation_fixture();
    let proof = sign_observation(&c, &p, &SEED, NOW + 1).unwrap();
    let public = SigningKey::from_bytes(&SEED).verifying_key();
    for now in [NOW - 1, NOW + 300] {
        assert!(
            verify_observation(
                &c,
                &proof,
                public.as_bytes(),
                compiled.candidate(),
                now,
                NOW + 400
            )
            .is_err()
        );
    }
    assert!(
        verify_observation(
            &c,
            &proof,
            public.as_bytes(),
            compiled.candidate(),
            NOW + 1,
            NOW + 1
        )
        .is_err()
    );
    let mut stale = p.clone();
    stale.observation.wall_time_unix = NOW - 1;
    assert!(sign_observation(&c, &stale, &SEED, NOW + 1).is_err());
    let mut future = p;
    future.observation.wall_time_unix = NOW + 2;
    assert!(sign_observation(&c, &future, &SEED, NOW + 1).is_err());
}
#[test]
fn altered_installation_is_rejected_even_when_explicitly_signed() {
    let (compiled, mut c, mut p) = observation_fixture();
    p.installation.native.nft_json["nftables"][0]["add"]["table"]["name"] = json!("other");
    c.installation_hash = canonical_hash(&p.installation).unwrap();
    let proof = sign_observation(&c, &p, &SEED, NOW + 1).unwrap();
    assert!(verify(&c, &proof, compiled.candidate()).is_err());
}
#[test]
fn signed_noncanonical_payloads_are_rejected_after_crypto_verification() {
    let (compiled, c, p) = observation_fixture();
    let mut proof = sign_observation(&c, &p, &SEED, NOW + 1).unwrap();
    let mut bytes = p.canonical_bytes().unwrap();
    bytes.push(b' ');
    let body=canonical_bytes(&json!({"schema_version":PROOF_SCHEMA,"challenge":c,"challenge_hash":c.hash().unwrap(),"payload_hash":hash_bytes(&bytes),"payload_size":bytes.len()})).unwrap();
    let mut message = b"fw.lab-native-observation/ed25519/v1\0".to_vec();
    message.extend_from_slice(&body);
    proof.signature =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&SEED).sign(&message).to_bytes());
    proof.payload_base64 = URL_SAFE_NO_PAD.encode(bytes);
    assert!(verify(&c, &proof, compiled.candidate()).is_err());
}
#[test]
fn closed_wire_and_canonical_encoding_refuse_ambiguous_inputs() {
    let (_, c, p) = observation_fixture();
    let mut challenge = serde_json::to_value(&c).unwrap();
    challenge["extra"] = json!(true);
    assert!(NativeObservationChallenge::parse(&serde_json::to_vec(&challenge).unwrap()).is_err());
    let duplicate = format!(
        "{{\"nonce\":\"{}\",{}",
        c.nonce,
        String::from_utf8(c.canonical_bytes().unwrap())
            .unwrap()
            .trim_start_matches('{')
    );
    assert!(NativeObservationChallenge::parse(duplicate.as_bytes()).is_err());
    let mut bad = c.clone();
    bad.observer_revision = "01".into();
    assert!(bad.canonical_bytes().is_err());
    let mut bad = c;
    bad.nonce.push('=');
    assert!(bad.canonical_bytes().is_err());
    let mut promoted = p;
    promoted.production_qualified = true;
    assert!(promoted.canonical_bytes().is_err());
}
#[test]
fn oversized_and_deep_constructed_values_are_refused_before_signing() {
    let (_, c, mut p) = observation_fixture();
    p.readback = json!({"too_large":"x".repeat(MAX_PAYLOAD_BYTES)});
    assert!(sign_observation(&c, &p, &SEED, NOW + 1).is_err());
    let mut deep = Value::Null;
    for _ in 0..40 {
        deep = json!([deep]);
    }
    p.readback = deep;
    assert!(sign_observation(&c, &p, &SEED, NOW + 1).is_err());
    assert!(SignedNativeObservation::parse(&vec![b' '; MAX_PROOF_BYTES + 1]).is_err());
}
