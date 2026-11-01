//! Real cryptographic protocol tests. Synthetic keys identify test devices only;
//! a verified metadata report still supplies no native enforcement authority.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use fw_contracts::{canonical_bytes, hash_bytes};
use fw_target_evidence::{
    SignedMetadataReport, TargetMetadataChallenge, fingerprint, parse_time, sign_report, timestamp,
    verify_report,
};
use serde_json::{Value, json};

const NOW: i64 = 1_793_500_000;
const TARGET: &str = "11111111-1111-4111-8111-111111111111";
const OTHER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SEED: [u8; 32] = [42; 32];

fn public() -> [u8; 32] {
    SigningKey::from_bytes(&SEED).verifying_key().to_bytes()
}

fn challenge() -> TargetMetadataChallenge {
    TargetMetadataChallenge {
        schema_version: "fw.target-metadata-challenge/v1".into(),
        challenge_id: "22222222-2222-4222-8222-222222222222".into(),
        org_id: "33333333-3333-4333-8333-333333333333".into(),
        project_id: "44444444-4444-4444-8444-444444444444".into(),
        target_id: TARGET.into(),
        key_revision: "7".into(),
        key_fingerprint: fingerprint(&public()).unwrap(),
        certificate_fingerprint: hash_bytes(b"test certificate DER"),
        nonce: URL_SAFE_NO_PAD.encode([17; 32]),
        issued_at: timestamp(NOW).unwrap(),
        expires_at: timestamp(NOW + 300).unwrap(),
    }
}

fn report(at: i64) -> Value {
    let features = [
        "timed_allow",
        "persistent_deny",
        "strict_current_union",
        "atomic_apply",
        "semantic_readback",
        "writer_fencing",
        "independent_watchdog",
        "new_management_probe",
        "interface_scope",
        "process_binding",
        "independent_expiry",
        "boot_guard",
        "crash_fail_closed",
        "absolute_deadline_guard",
    ]
    .into_iter()
    .map(|name| {
        (
            name.to_owned(),
            json!({
                "state":"unverified", "reason_code":"CAPABILITY_NOT_QUALIFIED", "evidence_hash":null
            }),
        )
    })
    .collect::<serde_json::Map<_, _>>();
    json!({
        "schema_version":"f.target-capability/v1", "capability_version":"f.target-capability/v1",
        "target_id":TARGET, "platform":"linux", "enforcement_backend":"nftables",
        "os_version":"test kernel", "backend_version":"unavailable",
        "executor_build_hash":hash_bytes(b"test executable"),
        "checked_at":timestamp(at).unwrap(), "valid_until":timestamp(at+300).unwrap(),
        "profiles":[], "families":[], "directions":[], "protocols":[], "binding_kinds":[],
        "features":features, "max_policies":4096, "max_rules":100000,
        "max_artifact_bytes":16777216, "qualification_profiles":[], "interfaces":[]
    })
}

fn signed() -> (TargetMetadataChallenge, SignedMetadataReport, Vec<u8>) {
    let c = challenge();
    let bytes = canonical_bytes(&report(NOW + 5)).unwrap();
    let proof = sign_report(&c, &bytes, &SEED, NOW + 5).unwrap();
    (c, proof, bytes)
}

fn verify(c: &TargetMetadataChallenge, proof: &SignedMetadataReport) -> bool {
    verify_report(c, proof, &public(), "linux", NOW + 10, NOW + 900).is_ok()
}

fn signed_message(c: &TargetMetadataChallenge, bytes: &[u8]) -> Vec<u8> {
    let mut message = b"fw.target-metadata-proof/ed25519/v1\0".to_vec();
    message.extend(
        canonical_bytes(&json!({
            "schema_version":"fw.target-metadata-proof/v1", "challenge":c,
            "challenge_hash":c.hash().unwrap(), "report_hash":hash_bytes(bytes),
            "report_size":bytes.len()
        }))
        .unwrap(),
    );
    message
}

// An enrolled device holds its key and can sign arbitrary bytes. Bypass the
// convenience signer deliberately to test the verifier's independent admission.
fn adversarial_device_proof(c: &TargetMetadataChallenge, bytes: &[u8]) -> SignedMetadataReport {
    SignedMetadataReport {
        schema_version: "fw.target-metadata-proof/v1".into(),
        challenge: c.clone(),
        report_base64: URL_SAFE_NO_PAD.encode(bytes),
        signature: URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&SEED)
                .sign(&signed_message(c, bytes))
                .to_bytes(),
        ),
    }
}

#[test]
fn real_signature_retains_exact_report_and_conservative_deadline() {
    let (c, proof, bytes) = signed();
    let wire = proof.canonical_bytes().unwrap();
    let reopened = SignedMetadataReport::parse(&wire).unwrap();
    let verified = verify_report(&c, &reopened, &public(), "linux", NOW + 10, NOW + 900).unwrap();
    assert_eq!(verified.report_bytes(), bytes);
    assert_eq!(verified.report_hash(), hash_bytes(&bytes));
    assert_eq!(verified.challenge_hash(), c.hash().unwrap());
    assert_eq!(verified.checked_at(), NOW + 5);
    // The report's own deadline is NOW+305. A nonce cannot extend its original
    // authority-issued freshness window through a later measurement or retry.
    assert_eq!(verified.valid_until(), NOW + 300);
    assert!(verify_report(&c, &proof, &public(), "linux", NOW + 299, NOW + 900).is_ok());
    assert!(verify_report(&c, &proof, &public(), "linux", NOW + 300, NOW + 900).is_err());
    assert!(verify_report(&c, &proof, &public(), "linux", NOW - 1, NOW + 900).is_err());
    let short_trust = verify_report(&c, &proof, &public(), "linux", NOW + 10, NOW + 20).unwrap();
    assert_eq!(short_trust.valid_until(), NOW + 20);
    assert!(verify_report(&c, &proof, &public(), "linux", NOW + 20, NOW + 20).is_err());
    let openssl_key =
        openssl::pkey::PKey::public_key_from_raw_bytes(&public(), openssl::pkey::Id::ED25519)
            .unwrap();
    let mut openssl_verifier = openssl::sign::Verifier::new_without_digest(&openssl_key).unwrap();
    assert!(
        openssl_verifier
            .verify_oneshot(
                &URL_SAFE_NO_PAD.decode(&proof.signature).unwrap(),
                &signed_message(&c, &bytes)
            )
            .unwrap()
    );
}

#[test]
fn fingerprint_matches_openssl_enrollment_spki_and_rejects_weak_keys() {
    use openssl::pkey::{Id, PKey};
    let key = PKey::private_key_from_raw_bytes(&SEED, Id::ED25519).unwrap();
    assert_eq!(key.raw_public_key().unwrap(), public());
    assert_eq!(
        fingerprint(&public()).unwrap(),
        hash_bytes(&key.public_key_to_der().unwrap())
    );
    // A raw-key digest is a different identity from the existing enrollment SPKI.
    assert_ne!(fingerprint(&public()).unwrap(), hash_bytes(&public()));
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(fingerprint(&identity).is_err());
    assert!(fingerprint(&[0; 32]).is_err());
    // Compressed Ed25519 points encode y < 2^255-19. Some decoders reduce y
    // modulo p, creating a second byte identity for the same non-weak point.
    let mut strong_small_y = 0;
    for y in 0u8..19 {
        let mut canonical = [0; 32];
        canonical[0] = y;
        if ed25519_dalek::VerifyingKey::from_bytes(&canonical).is_ok_and(|key| !key.is_weak()) {
            strong_small_y += 1;
            assert!(fingerprint(&canonical).is_ok());
            let mut noncanonical = [0xff; 32];
            noncanonical[0] = 0xed + y;
            noncanonical[31] = 0x7f;
            assert!(fingerprint(&noncanonical).is_err());
        }
    }
    assert!(strong_small_y > 0);
}

#[test]
fn every_challenge_binding_is_covered_by_the_signature() {
    let (c, proof, _) = signed();
    for field in [
        "challenge_id",
        "org_id",
        "project_id",
        "target_id",
        "key_revision",
        "certificate_fingerprint",
        "nonce",
        "issued_at",
        "expires_at",
    ] {
        let mut changed = c.clone();
        match field {
            "challenge_id" => changed.challenge_id = OTHER.into(),
            "org_id" => changed.org_id = OTHER.into(),
            "project_id" => changed.project_id = OTHER.into(),
            "target_id" => changed.target_id = OTHER.into(),
            "key_revision" => changed.key_revision = "8".into(),
            "certificate_fingerprint" => {
                changed.certificate_fingerprint = hash_bytes(b"another certificate")
            }
            "nonce" => changed.nonce = URL_SAFE_NO_PAD.encode([18; 32]),
            "issued_at" => changed.issued_at = timestamp(NOW + 1).unwrap(),
            "expires_at" => changed.expires_at = timestamp(NOW + 299).unwrap(),
            _ => unreachable!(),
        }
        // The verifier's independent expectation matches the modified claims;
        // rejection must still occur because the original signature binds them.
        let mut altered = proof.clone();
        altered.challenge = changed.clone();
        assert!(!verify(&changed, &altered), "{field}");
        assert!(!verify(&changed, &proof), "expected mismatch: {field}");
    }
}

#[test]
fn different_device_key_or_signature_domain_cannot_authenticate_report() {
    let (c, proof, bytes) = signed();
    let other = SigningKey::from_bytes(&[43; 32]);
    assert!(
        verify_report(
            &c,
            &proof,
            &other.verifying_key().to_bytes(),
            "linux",
            NOW + 10,
            NOW + 900
        )
        .is_err()
    );
    assert!(sign_report(&c, &bytes, &[43; 32], NOW + 5).is_err());
    for message in [
        bytes.as_slice(),
        b"application/vnd.f.policy-change-grant.v1+json",
        b"fw.other-purpose/v1\0",
    ] {
        let mut wrong = proof.clone();
        wrong.signature =
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&SEED).sign(message).to_bytes());
        assert!(!verify(&c, &wrong));
    }
    // Adding the group order to S preserves the group equation but changes the
    // signature encoding. Strict Ed25519 must refuse this alternate signature.
    let order = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut high_s = proof.clone();
    let mut signature = URL_SAFE_NO_PAD.decode(&proof.signature).unwrap();
    let mut carry = 0u16;
    for (byte, increment) in signature[32..].iter_mut().zip(order) {
        let sum = u16::from(*byte) + increment + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    high_s.signature = URL_SAFE_NO_PAD.encode(signature);
    assert!(!verify(&c, &high_s));
    let mut changed = proof;
    let mut signature = URL_SAFE_NO_PAD.decode(&changed.signature).unwrap();
    signature[20] ^= 1;
    changed.signature = URL_SAFE_NO_PAD.encode(signature);
    assert!(!verify(&c, &changed));
}

#[test]
fn low_order_device_key_cannot_forge_a_signature_for_any_report() {
    let (_, mut proof, bytes) = signed();
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend(identity);
    let mut c = challenge();
    c.key_fingerprint = hash_bytes(&der);
    proof.challenge = c.clone();
    // R=identity and S=0 satisfy the weak-key group equation for every message;
    // strict verification must reject the low-order public key itself.
    let mut signature = [0; 64];
    signature[0] = 1;
    proof.signature = URL_SAFE_NO_PAD.encode(signature);
    proof.report_base64 = URL_SAFE_NO_PAD.encode(bytes);
    assert!(verify_report(&c, &proof, &identity, "linux", NOW + 10, NOW + 900).is_err());
}

#[test]
fn report_bytes_are_covered_and_cannot_be_reserialized_into_a_different_proof() {
    let (c, proof, bytes) = signed();
    let mut different = report(NOW + 5);
    different["os_version"] = "another measured kernel".into();
    let mut changed = proof.clone();
    changed.report_base64 = URL_SAFE_NO_PAD.encode(canonical_bytes(&different).unwrap());
    assert!(!verify(&c, &changed));
    let pretty = serde_json::to_vec_pretty(&report(NOW + 5)).unwrap();
    assert_ne!(pretty, bytes);
    assert!(sign_report(&c, &pretty, &SEED, NOW + 5).is_err());
    changed.report_base64 = URL_SAFE_NO_PAD.encode(pretty);
    assert!(!verify(&c, &changed));
    let mut truncated = bytes;
    truncated.pop();
    changed.report_base64 = URL_SAFE_NO_PAD.encode(truncated);
    assert!(!verify(&c, &changed));
}

#[test]
fn fresh_nonce_does_not_relabel_old_future_or_expired_measurements() {
    let c = challenge();
    for at in [NOW - 1, NOW + 11] {
        let bytes = canonical_bytes(&report(at)).unwrap();
        assert!(sign_report(&c, &bytes, &SEED, NOW + 10).is_err());
        assert!(!verify(&c, &adversarial_device_proof(&c, &bytes)));
    }
    for until in [NOW + 10, NOW + 311] {
        let mut r = report(NOW + 10);
        r["valid_until"] = timestamp(until).unwrap().into();
        let bytes = canonical_bytes(&r).unwrap();
        assert!(sign_report(&c, &bytes, &SEED, NOW + 10).is_err());
        assert!(!verify(&c, &adversarial_device_proof(&c, &bytes)));
    }
    let mut short = report(NOW + 5);
    short["valid_until"] = timestamp(NOW + 15).unwrap().into();
    let proof = sign_report(&c, &canonical_bytes(&short).unwrap(), &SEED, NOW + 5).unwrap();
    assert_eq!(
        verify_report(&c, &proof, &public(), "linux", NOW + 10, NOW + 900)
            .unwrap()
            .valid_until(),
        NOW + 15
    );
    assert!(verify_report(&c, &proof, &public(), "linux", NOW + 15, NOW + 900).is_err());
}

#[test]
fn authenticated_metadata_never_accepts_claimed_enforcement_qualification() {
    let c = challenge();
    for kind in [
        "supported",
        "profile",
        "qualification",
        "extra_boolean",
        "backend",
        "target",
    ] {
        let mut r = report(NOW + 5);
        match kind {
            "supported" => r["features"]["atomic_apply"]["state"] = "supported".into(),
            "profile" => r["profiles"] = json!(["common-host-v1"]),
            "qualification" => r["qualification_profiles"] = json!(["common-host-v1"]),
            "extra_boolean" => r["production_supported"] = true.into(),
            "backend" => r["enforcement_backend"] = "windows_wfp".into(),
            "target" => r["target_id"] = OTHER.into(),
            _ => unreachable!(),
        }
        let bytes = canonical_bytes(&r).unwrap();
        assert!(sign_report(&c, &bytes, &SEED, NOW + 5).is_err(), "{kind}");
        assert!(
            !verify(&c, &adversarial_device_proof(&c, &bytes)),
            "signed claim: {kind}"
        );
    }
    let (_, proof, _) = signed();
    assert!(verify_report(&c, &proof, &public(), "windows", NOW + 10, NOW + 900).is_err());
}

#[test]
fn challenge_parser_rejects_unknown_duplicate_noncanonical_and_unbounded_values() {
    let c = challenge();
    let bytes = c.canonical_bytes().unwrap();
    assert_eq!(TargetMetadataChallenge::parse(&bytes).unwrap(), c);
    let mut extra = serde_json::to_value(&c).unwrap();
    extra["controller_approved"] = true.into();
    assert!(TargetMetadataChallenge::parse(&canonical_bytes(&extra).unwrap()).is_err());
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen("{", "{\"key_revision\":\"7\",", 1);
    assert!(TargetMetadataChallenge::parse(duplicate.as_bytes()).is_err());
    assert!(TargetMetadataChallenge::parse(&vec![b' '; 4097]).is_err());
    for kind in [
        "schema",
        "revision",
        "uuid",
        "nonce",
        "fingerprint",
        "time",
        "lifetime",
        "empty_window",
    ] {
        let mut bad = c.clone();
        match kind {
            "schema" => bad.schema_version = "fw.authority-bootstrap/v1".into(),
            "revision" => bad.key_revision = "07".into(),
            "uuid" => bad.org_id = OTHER.to_uppercase(),
            "nonce" => bad.nonce.push('='),
            "fingerprint" => bad.key_fingerprint = "sha256:AA".into(),
            "time" => bad.issued_at = bad.issued_at.replace('Z', "+00:00"),
            "lifetime" => bad.expires_at = timestamp(NOW + 301).unwrap(),
            "empty_window" => bad.expires_at = bad.issued_at.clone(),
            _ => unreachable!(),
        }
        assert!(bad.validate(NOW).is_err(), "{kind}");
        assert!(
            TargetMetadataChallenge::parse(&canonical_bytes(&bad).unwrap()).is_err(),
            "parse {kind}"
        );
    }
    assert!(parse_time("2026-11-01T00:00:00.000Z").is_err());
    assert!(parse_time("2026-11-01T00:00:00+00:00").is_err());
}

#[test]
fn proof_parser_and_verifier_reject_alternate_encodings_and_unknown_claims() {
    let (c, proof, _) = signed();
    let wire = proof.canonical_bytes().unwrap();
    let duplicate =
        String::from_utf8(wire.clone())
            .unwrap()
            .replacen("{", "{\"signature\":\"bad\",", 1);
    assert!(SignedMetadataReport::parse(duplicate.as_bytes()).is_err());
    assert!(SignedMetadataReport::parse(&vec![b' '; 131073]).is_err());
    let mut extra = serde_json::to_value(&proof).unwrap();
    extra["authority_approved"] = true.into();
    assert!(SignedMetadataReport::parse(&canonical_bytes(&extra).unwrap()).is_err());
    for kind in [
        "purpose",
        "signature_padding",
        "signature_short",
        "report_padding",
        "report_large",
    ] {
        let mut bad = proof.clone();
        match kind {
            "purpose" => bad.schema_version = "fw.policy-signing-proof/v1".into(),
            "signature_padding" => bad.signature.push('='),
            "signature_short" => bad.signature = URL_SAFE_NO_PAD.encode([0; 63]),
            "report_padding" => bad.report_base64.push('='),
            "report_large" => bad.report_base64 = URL_SAFE_NO_PAD.encode(vec![0; 65537]),
            _ => unreachable!(),
        }
        assert!(!verify(&c, &bad), "{kind}");
    }
}

#[test]
fn strict_report_admission_rejects_duplicate_fields_floats_depth_and_limits() {
    let c = challenge();
    let bytes = canonical_bytes(&report(NOW + 5)).unwrap();
    let duplicate =
        String::from_utf8(bytes.clone())
            .unwrap()
            .replacen("{", "{\"max_rules\":100000,", 1);
    assert!(sign_report(&c, duplicate.as_bytes(), &SEED, NOW + 5).is_err());
    let float = String::from_utf8(bytes)
        .unwrap()
        .replace("\"max_rules\":100000", "\"max_rules\":1e5");
    assert!(sign_report(&c, float.as_bytes(), &SEED, NOW + 5).is_err());
    let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert!(sign_report(&c, deep.as_bytes(), &SEED, NOW + 5).is_err());
    assert!(sign_report(&c, &vec![b' '; 65537], &SEED, NOW + 5).is_err());
    let mut limits = report(NOW + 5);
    limits["max_rules"] = 100001.into();
    assert!(sign_report(&c, &canonical_bytes(&limits).unwrap(), &SEED, NOW + 5).is_err());
    limits = report(NOW + 5);
    limits["features"]["atomic_apply"]["reason_code"] = "lowercase_reason".into();
    assert!(sign_report(&c, &canonical_bytes(&limits).unwrap(), &SEED, NOW + 5).is_err());
}
