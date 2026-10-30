use super::*;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

fn scratch() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn invitation(identity: &DeviceIdentity, now: i64) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema_version":"fw.enrollment-invitation/v1","api_origin":"http://127.0.0.1:8787","token":fw_enrollment::random_token().unwrap(),"idempotency_key":Uuid::new_v4(),"name":"Test device","platform":"linux","expected_key_fingerprint":identity.key_fingerprint,"target_id":Uuid::new_v4(),"token_id":Uuid::new_v4(),"expires_at":Utc.timestamp_opt(now+600,0).unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string()})).unwrap()
}
fn issued(
    identity: &DeviceIdentity,
    ca: &fw_enrollment::ControllerPki,
    now: i64,
) -> EnrollmentResponse {
    ca.authority
        .issue(
            &fw_enrollment::validate_csr(&identity.csr_pem, &identity.key_fingerprint).unwrap(),
            &fw_enrollment::Issuance {
                request_id: Uuid::new_v4().to_string(),
                org_id: Uuid::new_v4().to_string(),
                project_id: Uuid::new_v4().to_string(),
                target_id: Uuid::new_v4().to_string(),
                job_id: Uuid::new_v4().to_string(),
                issued_at: now,
                authority_epoch: 0,
            },
        )
        .unwrap()
}

#[test]
fn only_https_origins_are_accepted() {
    for value in [
        "http://127.0.0.1:8791",
        "https://user:pass@example.com",
        "https://example.com/path",
        "https://example.com/?token=secret",
        "https://example.com/#fragment",
        "https:///missing-host",
    ] {
        assert!(
            origin(value).is_err(),
            "unexpected accepted origin: {value}"
        );
    }
    assert_eq!(
        origin("https://127.0.0.1:8791/").unwrap(),
        "https://127.0.0.1:8791"
    );
    assert!(origin("https://[::1]:8791").is_ok());
}

#[test]
fn invalid_pin_is_rejected_before_identity_invitation_or_network_access() {
    let directory = scratch();
    let ca_path = directory.path().join("ca.pem");
    fs::write(&ca_path, "public certificate bytes").unwrap();
    let args = vec![
        "enroll".into(),
        "--state-dir".into(),
        directory.path().display().to_string(),
        "--controller".into(),
        "https://127.0.0.1:9".into(),
        "--ca-file".into(),
        ca_path.display().to_string(),
        "--trust-bundle-hash".into(),
        format!("sha256:{}", "0".repeat(64)),
        "--invitation-file".into(),
        directory
            .path()
            .join("never-created.json")
            .display()
            .to_string(),
    ];
    let error = run(args).unwrap_err().to_string();
    assert!(error.contains("explicitly supplied trust pin"));
    assert!(!directory.path().join("pending-enrollment.json").exists());
}

#[test]
fn invitations_require_controller_registration_key_binding_and_unexpired_lifetime() {
    let identity = fw_enrollment::generate_device_identity().unwrap();
    let now = Utc::now().timestamp();
    let bytes = invitation(&identity, now);
    assert!(invite(&bytes, &identity, now).is_ok());
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value.as_object_mut().unwrap().remove("target_id");
    assert!(invite(&serde_json::to_vec(&value).unwrap(), &identity, now).is_err());
    assert!(invite(&bytes, &identity, now + 600).is_err());
    let other = fw_enrollment::generate_device_identity().unwrap();
    assert!(invite(&bytes, &other, now).is_err());
    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen('{', "{\"name\":\"duplicate\",", 1);
    assert!(invite(duplicate.as_bytes(), &identity, now).is_err());
}

#[test]
fn pending_requests_survive_retry_without_copying_tokens_or_changing_nonce() {
    let scratch = scratch();
    let state = Directory::open(scratch.path(), false, true).unwrap();
    let identity = fw_enrollment::generate_device_identity().unwrap();
    let now = Utc::now().timestamp();
    let bytes = invitation(&identity, now);
    let invitation = invite(&bytes, &identity, now).unwrap();
    let digest = fw_enrollment::hash_bytes(&bytes);
    let trust = format!("sha256:{}", "a".repeat(64));
    let first = pending(
        &state,
        &invitation,
        &digest,
        &identity,
        "https://localhost:8791",
        &trust,
    )
    .unwrap();
    let second = pending(
        &state,
        &invitation,
        &digest,
        &identity,
        "https://localhost:8791",
        &trust,
    )
    .unwrap();
    assert_eq!(first.request_id, second.request_id);
    assert_eq!(first.nonce, second.nonce);
    let stored = text(state.read("pending-enrollment.json").unwrap()).unwrap();
    assert!(!stored.contains(&invitation.token));
    assert!(
        pending(
            &state,
            &invitation,
            &digest,
            &identity,
            "https://different.example",
            &trust
        )
        .is_err()
    );
    assert_eq!(
        stored,
        text(state.read("pending-enrollment.json").unwrap()).unwrap()
    );
}

#[test]
fn init_is_private_and_refuses_overwriting_an_existing_identity() {
    let scratch = scratch();
    let state = Directory::open(&scratch.path().join("device"), true, true).unwrap();
    let result = init(&state).unwrap();
    assert!(fingerprint(result["key_fingerprint"].as_str().unwrap()));
    assert_eq!(result["enforcement"], false);
    let key = state.read("key.pem").unwrap();
    assert!(init(&state).is_err());
    assert_eq!(state.read("key.pem").unwrap(), key);
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(state.path.join("key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn certificate_binding_and_controller_origin_cannot_be_changed() {
    let scratch = scratch();
    let now = Utc::now().timestamp();
    let ca = fw_enrollment::init_controller_pki(&scratch.path().join("pki"), now).unwrap();
    let identity = fw_enrollment::generate_device_identity().unwrap();
    let response = issued(&identity, &ca, now);
    let mut saved = Enrolled {
        schema_version: "fw.device-enrollment/v1".into(),
        controller_origin: "https://localhost:8791".into(),
        trust_bundle_hash: ca.authority.trust_bundle_hash(),
        response,
    };
    let pem = ca.authority.ca_certificate_pem();
    let pin = ca.authority.trust_bundle_hash();
    assert!(validate_saved(&saved, &identity, pem, "https://localhost:8791", &pin, now).is_ok());
    assert!(validate_saved(&saved, &identity, pem, "https://other.example", &pin, now).is_err());
    let other = fw_enrollment::generate_device_identity().unwrap();
    assert!(validate_saved(&saved, &other, pem, "https://localhost:8791", &pin, now).is_err());
    saved.response.target_id = Uuid::new_v4().to_string();
    assert!(validate_saved(&saved, &identity, pem, "https://localhost:8791", &pin, now).is_err());
}

#[test]
fn tls_uses_only_explicit_roots_and_tls13_suites() {
    let scratch = scratch();
    let now = Utc::now().timestamp();
    let ca = fw_enrollment::init_controller_pki(&scratch.path().join("pki"), now).unwrap();
    let agent = client(ca.authority.ca_certificate_pem(), None).unwrap();
    let tls = agent.config().tls_config();
    assert!(!tls.disable_verification());
    assert!(matches!(tls.root_certs(),RootCerts::Specific(roots) if roots.len()==1));
    let provider = tls.unversioned_rustls_crypto_provider().as_ref().unwrap();
    assert!(!provider.cipher_suites.is_empty());
    assert!(
        provider
            .cipher_suites
            .iter()
            .all(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3)
    );
}

#[test]
fn capability_reports_measure_identity_without_claiming_qualification() {
    let hash = binary_hash().unwrap();
    assert!(fingerprint(&hash));
    let target = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let value = capability(&target, now, "Linux test kernel", "unavailable", &hash).unwrap();
    assert_eq!(value["target_id"], target);
    assert_eq!(value["executor_build_hash"], hash);
    assert_eq!(value["qualification_profiles"], json!([]));
    assert_eq!(value["profiles"], json!([]));
    assert_eq!(value["features"].as_object().unwrap().len(), 14);
    for feature in value["features"].as_object().unwrap().values() {
        assert_eq!(feature["state"], "unverified");
        assert!(feature["evidence_hash"].is_null());
    }
    assert_eq!(
        time(value["valid_until"].as_str().unwrap()).unwrap()
            - time(value["checked_at"].as_str().unwrap()).unwrap(),
        300
    );
}

#[test]
#[cfg(unix)]
fn credential_aliases_public_modes_and_shared_ancestors_are_rejected() {
    let scratch = scratch();
    let state = Directory::open(&scratch.path().join("state"), true, true).unwrap();
    state.write("secret", b"preserved", false).unwrap();
    symlink(state.path.join("secret"), state.path.join("symlink")).unwrap();
    assert!(state.read("symlink").is_err());
    assert!(state.write("symlink", b"changed", true).is_err());
    fs::hard_link(state.path.join("secret"), state.path.join("alias")).unwrap();
    assert!(state.read("secret").is_err());
    assert!(state.write("secret", b"changed", true).is_err());
    assert_eq!(fs::read(state.path.join("alias")).unwrap(), b"preserved");
    fs::remove_file(state.path.join("alias")).unwrap();
    fs::set_permissions(state.path.join("secret"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(state.read("secret").is_err());
    let shared = scratch.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Directory::open(&shared.join("new"), true, true).is_err());
    let link = scratch.path().join("linked");
    symlink(&state.path, &link).unwrap();
    assert!(Directory::open(&link, false, true).is_err());
    assert!(Directory::open(&state.path.join(".."), false, true).is_err());
}

#[test]
#[cfg(unix)]
fn device_identity_lock_prevents_concurrent_enrollment_state_updates() {
    let scratch = scratch();
    let state = Directory::open(scratch.path(), false, true).unwrap();
    let lock = state.lock().unwrap();
    assert!(state.lock().is_err());
    drop(lock);
    assert!(state.lock().is_ok());
}
