#![cfg(unix)]
use fw_enrollment::*;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    stack::Stack,
    x509::{
        X509, X509NameBuilder, X509Req,
        extension::{BasicConstraints, SubjectAlternativeName},
    },
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::TempDir;

const NOW: i64 = 1_793_318_400;
const ORG: &str = "11111111-1111-4111-8111-111111111111";
const PROJECT: &str = "22222222-2222-4222-8222-222222222222";
const TARGET: &str = "33333333-3333-4333-8333-333333333333";
const JOB: &str = "44444444-4444-4444-8444-444444444444";
const REQUEST: &str = "55555555-5555-4555-8555-555555555555";
fn fixture_pki() -> (TempDir, ControllerPki) {
    let dir = tempfile::tempdir().unwrap();
    let result = init_controller_pki(&dir.path().join("pki"), NOW).unwrap();
    (dir, result)
}
fn request(identity: &DeviceIdentity) -> EnrollmentRequest {
    EnrollmentRequest {
        schema_version: "f.enrollment-request/v1".into(),
        request_id: REQUEST.into(),
        token: random_token().unwrap(),
        csr_pem: identity.csr_pem.clone(),
        expected_key_fingerprint: identity.key_fingerprint.clone(),
        nonce: random_token().unwrap(),
        platform: "linux".into(),
        agent_version: "0.1.0".into(),
    }
}
fn issuance() -> Issuance {
    Issuance {
        request_id: REQUEST.into(),
        org_id: ORG.into(),
        project_id: PROJECT.into(),
        target_id: TARGET.into(),
        job_id: JOB.into(),
        issued_at: NOW,
        authority_epoch: 0,
    }
}
fn issue(authority: &CertificateAuthority, identity: &DeviceIdentity) -> EnrollmentResponse {
    let csr = validate_request(&request(identity)).unwrap();
    authority.issue(&csr, &issuance()).unwrap()
}

#[test]
fn real_csr_certificate_and_transport_identity_round_trip() {
    let (_dir, pki) = fixture_pki();
    let identity = generate_device_identity().unwrap();
    let response = issue(&pki.authority, &identity);
    let target = verify_enrollment_response(
        &response,
        &identity,
        pki.authority.ca_certificate_pem(),
        TARGET,
        NOW,
    )
    .unwrap();
    assert_eq!(target.org_id, ORG);
    assert_eq!(target.project_id, PROJECT);
    assert_eq!(target.target_id, TARGET);
    assert_eq!(target.key_fingerprint, identity.key_fingerprint);
    assert_eq!(target.expires_at - target.issued_at, 86_400);
    assert_eq!(response.mode, "observe");
    assert_eq!(response.authority_epoch, "0");
    assert_eq!(
        response.trust_bundle_hash,
        pki.authority.trust_bundle_hash()
    );
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("PRIVATE KEY")
    );
    let parsed: EnrollmentResponse =
        serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
    assert_eq!(parsed.certificate_chain_pem, response.certificate_chain_pem);
}

#[test]
fn bad_csr_signature_and_wrong_key_fingerprint_are_rejected() {
    let identity = generate_device_identity().unwrap();
    let other = generate_device_identity().unwrap();
    assert!(validate_csr(&identity.csr_pem, &other.key_fingerprint).is_err());
    let key = PKey::private_key_from_pem(identity.private_key_pem.as_bytes()).unwrap();
    let other_key = PKey::private_key_from_pem(other.private_key_pem.as_bytes()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "attacker").unwrap();
    let mut csr = X509Req::builder().unwrap();
    csr.set_version(0).unwrap();
    csr.set_subject_name(&name.build()).unwrap();
    csr.set_pubkey(&key).unwrap();
    csr.sign(&other_key, MessageDigest::null()).unwrap();
    assert!(
        validate_csr(
            &String::from_utf8(csr.build().to_pem().unwrap()).unwrap(),
            &identity.key_fingerprint
        )
        .is_err()
    );
    let original = X509Req::from_pem(identity.csr_pem.as_bytes()).unwrap();
    let mut bytes = original.to_der().unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let tampered = X509Req::from_der(&bytes).unwrap();
    assert!(
        validate_csr(
            &String::from_utf8(tampered.to_pem().unwrap()).unwrap(),
            &identity.key_fingerprint
        )
        .is_err()
    );
}

#[test]
fn csr_subject_roles_and_requested_sans_do_not_control_certificate() {
    let (_dir, pki) = fixture_pki();
    let identity = generate_device_identity().unwrap();
    let key = PKey::private_key_from_pem(identity.private_key_pem.as_bytes()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "owner/signer/admin")
        .unwrap();
    let mut csr = X509Req::builder().unwrap();
    csr.set_version(0).unwrap();
    csr.set_subject_name(&name.build()).unwrap();
    csr.set_pubkey(&key).unwrap();
    let mut extensions = Stack::new().unwrap();
    extensions
        .push(
            SubjectAlternativeName::new()
                .uri("urn:nox:signer:admin")
                .dns("attacker.example")
                .build(&csr.x509v3_context(None))
                .unwrap(),
        )
        .unwrap();
    extensions
        .push(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(10)
                .build()
                .unwrap(),
        )
        .unwrap();
    csr.add_extensions(&extensions).unwrap();
    csr.sign(&key, MessageDigest::null()).unwrap();
    let malicious_pem = String::from_utf8(csr.build().to_pem().unwrap()).unwrap();
    let csr = validate_csr(&malicious_pem, &identity.key_fingerprint).unwrap();
    let response = pki.authority.issue(&csr, &issuance()).unwrap();
    let leaf = X509::stack_from_pem(response.certificate_chain_pem.as_bytes())
        .unwrap()
        .remove(0);
    assert_eq!(
        leaf.subject_name()
            .entries()
            .next()
            .unwrap()
            .data()
            .to_string()
            .unwrap(),
        TARGET
    );
    let sans = leaf.subject_alt_names().unwrap();
    assert_eq!(sans.len(), 1);
    assert_eq!(
        sans.get(0).unwrap().uri(),
        Some(format!("urn:nox:target:{ORG}:{PROJECT}:{TARGET}").as_str())
    );
    assert_eq!(leaf.pathlen(), None);
    assert!(
        !String::from_utf8(leaf.to_text().unwrap())
            .unwrap()
            .contains("attacker.example")
    );
}

#[test]
fn unsupported_algorithms_versions_and_multiple_pem_objects_are_rejected() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "rsa").unwrap();
    let mut csr = X509Req::builder().unwrap();
    csr.set_version(0).unwrap();
    csr.set_subject_name(&name.build()).unwrap();
    csr.set_pubkey(&key).unwrap();
    csr.sign(&key, MessageDigest::sha256()).unwrap();
    let pem = String::from_utf8(csr.build().to_pem().unwrap()).unwrap();
    assert!(validate_csr(&pem, &hash_bytes(&key.public_key_to_der().unwrap())).is_err());
    let identity = generate_device_identity().unwrap();
    assert!(
        validate_csr(
            &format!("{}{}", identity.csr_pem, identity.csr_pem),
            &identity.key_fingerprint
        )
        .is_err()
    );
    assert!(
        validate_csr(
            &format!("{}{}", " ".repeat(16_384), identity.csr_pem),
            &identity.key_fingerprint
        )
        .is_err()
    );
    let mut der = X509Req::from_pem(identity.csr_pem.as_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    let version = der.windows(3).position(|bytes| bytes == [2, 1, 0]).unwrap();
    der[version + 2] = 1;
    // Some OpenSSL versions reject the invalid PKCS#10 version while decoding.
    if let Ok(csr) = X509Req::from_der(&der) {
        assert!(
            validate_csr(
                &String::from_utf8(csr.to_pem().unwrap()).unwrap(),
                &identity.key_fingerprint
            )
            .is_err()
        );
    }
}

#[test]
fn exact_issuance_retries_do_not_change_certificate_or_refresh_expiry() {
    let (_dir, pki) = fixture_pki();
    let identity = generate_device_identity().unwrap();
    let csr = validate_request(&request(&identity)).unwrap();
    let one = pki.authority.issue(&csr, &issuance()).unwrap();
    let two = pki.authority.issue(&csr, &issuance()).unwrap();
    assert_eq!(
        serde_json::to_value(&one).unwrap(),
        serde_json::to_value(&two).unwrap()
    );
    let mut different = issuance();
    different.job_id = "66666666-6666-4666-8666-666666666666".into();
    let changed = pki.authority.issue(&csr, &different).unwrap();
    assert_ne!(one.certificate_chain_pem, changed.certificate_chain_pem);
    assert_eq!(one.expires_at, changed.expires_at);
}

#[test]
fn response_rejects_wrong_root_target_key_mode_and_time_claims() {
    let (_dir, pki) = fixture_pki();
    let identity = generate_device_identity().unwrap();
    let good = issue(&pki.authority, &identity);
    let (_other_dir, other_pki) = fixture_pki();
    assert!(
        verify_enrollment_response(
            &good,
            &identity,
            other_pki.authority.ca_certificate_pem(),
            TARGET,
            NOW
        )
        .is_err()
    );
    let other_identity = generate_device_identity().unwrap();
    assert!(
        verify_enrollment_response(
            &good,
            &other_identity,
            pki.authority.ca_certificate_pem(),
            TARGET,
            NOW
        )
        .is_err()
    );
    assert!(
        verify_enrollment_response(
            &good,
            &identity,
            pki.authority.ca_certificate_pem(),
            PROJECT,
            NOW
        )
        .is_err()
    );
    for (field, value) in [
        ("mode", "active"),
        ("authority_epoch", "00"),
        ("issued_at", "2026-10-30T00:00:00.000Z"),
        ("expires_at", "2099-01-01T00:00:00Z"),
        ("renew_after", "2099-01-01T00:00:00Z"),
    ] {
        let mut json = serde_json::to_value(&good).unwrap();
        json[field] = value.into();
        let changed: EnrollmentResponse = serde_json::from_value(json).unwrap();
        assert!(
            verify_enrollment_response(
                &changed,
                &identity,
                pki.authority.ca_certificate_pem(),
                TARGET,
                NOW
            )
            .is_err(),
            "{field}"
        );
    }
    assert!(
        verify_enrollment_response(
            &good,
            &identity,
            pki.authority.ca_certificate_pem(),
            TARGET,
            NOW - 1
        )
        .is_err()
    );
    assert!(
        verify_enrollment_response(
            &good,
            &identity,
            pki.authority.ca_certificate_pem(),
            TARGET,
            NOW + 86_400
        )
        .is_err()
    );
    assert!(
        verify_enrollment_response(
            &good,
            &identity,
            pki.authority.ca_certificate_pem(),
            TARGET,
            NOW + 86_399
        )
        .is_ok()
    );
}

#[test]
fn malformed_request_and_secret_echo_fields_are_rejected() {
    let identity = generate_device_identity().unwrap();
    let good = request(&identity);
    for (field, value) in [
        ("schema_version", "wrong"),
        ("request_id", "not-a-uuid"),
        ("token", "short"),
        ("nonce", "00"),
        ("platform", "unknown"),
        ("agent_version", ""),
    ] {
        let mut json = serde_json::to_value(&good).unwrap();
        json[field] = value.into();
        let changed: EnrollmentRequest = serde_json::from_value(json).unwrap();
        assert!(validate_request(&changed).is_err(), "{field}");
    }
    let mut json = serde_json::to_value(&good).unwrap();
    json["role"] = "signer".into();
    assert!(serde_json::from_value::<EnrollmentRequest>(json).is_err());
    let (_dir, pki) = fixture_pki();
    let response = issue(&pki.authority, &identity);
    let mut json = serde_json::to_value(response).unwrap();
    json["token"] = good.token.into();
    assert!(serde_json::from_value::<EnrollmentResponse>(json).is_err());
}

#[test]
fn existing_key_must_match_csr_and_transport_certificate_has_no_policy_authority() {
    let identity = generate_device_identity().unwrap();
    let other = generate_device_identity().unwrap();
    assert!(load_device_identity(&identity.private_key_pem, &other.csr_pem).is_err());
    assert!(load_device_identity(&identity.private_key_pem, &identity.csr_pem).is_ok());
    let (_dir, pki) = fixture_pki();
    let response = issue(&pki.authority, &identity);
    let certs = X509::stack_from_pem(response.certificate_chain_pem.as_bytes()).unwrap();
    let text = String::from_utf8(certs[0].to_text().unwrap()).unwrap();
    assert!(text.contains("TLS Web Client Authentication"));
    assert!(!text.contains("TLS Web Server Authentication"));
    assert!(!text.contains("Certificate Sign"));
    let server = X509::stack_from_pem(pki.server_certificate_pem.as_bytes()).unwrap();
    assert!(certificate_identity(&server[0].to_der().unwrap()).is_err());
    let mut der = certs[0].to_der().unwrap();
    der.push(0);
    assert!(certificate_identity(&der).is_err());
}

#[test]
fn fixed_issuance_never_exceeds_ca_validity_or_accepted_counter_range() {
    let (_dir, pki) = fixture_pki();
    let identity = generate_device_identity().unwrap();
    let csr = validate_request(&request(&identity)).unwrap();
    let mut input = issuance();
    input.issued_at = NOW + 365 * 86_400 - 1;
    assert!(pki.authority.issue(&csr, &input).is_err());
    input.issued_at = i64::MAX;
    assert!(pki.authority.issue(&csr, &input).is_err());
    input.issued_at = 0;
    assert!(pki.authority.issue(&csr, &input).is_err());
    input = issuance();
    input.target_id = "arbitrary:user:admin".into();
    assert!(pki.authority.issue(&csr, &input).is_err());
}

#[test]
fn private_pki_files_are_durable_distinct_and_never_overwritten() {
    let (dir, pki) = fixture_pki();
    let path = dir.path().join("pki");
    let before = fs::read(path.join("ca.pem")).unwrap();
    assert!(init_controller_pki(&path, NOW).is_err());
    assert_eq!(before, fs::read(path.join("ca.pem")).unwrap());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for filename in ["ca.pem", "ca-key.pem", "server.pem", "server-key.pem"] {
        assert_eq!(
            fs::metadata(path.join(filename))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let loaded = load_controller_pki(&path, NOW).unwrap();
    assert_eq!(
        loaded.authority.trust_bundle_hash(),
        pki.authority.trust_bundle_hash()
    );
    let ca_key = PKey::private_key_from_pem(&fs::read(path.join("ca-key.pem")).unwrap()).unwrap();
    let server_key = PKey::private_key_from_pem(pki.server_private_key_pem.as_bytes()).unwrap();
    assert!(!ca_key.public_eq(&server_key));
    assert!(load_controller_pki(&path, NOW + 31 * 86_400).is_err());
}

#[test]
fn public_private_keys_symlinks_hardlinks_and_mismatched_keys_are_rejected() {
    let (dir, _pki) = fixture_pki();
    let path = dir.path().join("pki");
    let key = path.join("ca-key.pem");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_controller_pki(&path, NOW).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = dir.path().join("key-alias");
    fs::hard_link(&key, &alias).unwrap();
    assert!(load_controller_pki(&path, NOW).is_err());
    fs::remove_file(&alias).unwrap();
    let linked = dir.path().join("linked");
    symlink(&path, &linked).unwrap();
    assert!(load_controller_pki(&linked, NOW).is_err());
    let original = fs::read(&key).unwrap();
    fs::remove_file(&key).unwrap();
    symlink(path.join("server-key.pem"), &key).unwrap();
    assert!(load_controller_pki(&path, NOW).is_err());
    fs::remove_file(&key).unwrap();
    fs::write(&key, &original).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let other = generate_device_identity().unwrap();
    fs::write(&key, other.private_key_pem).unwrap();
    assert!(load_controller_pki(&path, NOW).is_err());
}
