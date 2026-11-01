#![cfg(target_os = "linux")]
//! Actual executable, certificate and Ed25519 proof checks; no firewall writes.
use chrono::{TimeZone, Utc};
use fw_target_evidence::{SignedMetadataReport, TargetMetadataChallenge, verify_report};
use openssl::pkey::PKey;
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process::{Command, Output},
};
use uuid::Uuid;

const CONTROLLER: &str = "https://127.0.0.1:9";
struct Fixture {
    _directory: tempfile::TempDir,
    state: PathBuf,
    ca: PathBuf,
    trust: String,
    challenge_file: PathBuf,
    challenge: TargetMetadataChallenge,
    output_file: PathBuf,
    public: [u8; 32],
    certificate_expires: i64,
}
fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn stamp(now: i64) -> String {
    Utc.timestamp_opt(now, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
impl Fixture {
    fn new() -> Self {
        Self::with_certificate_age(1)
    }
    fn with_certificate_age(age: i64) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("fw-agent-metadata-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let state = directory.path().join("device");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let identity = fw_enrollment::generate_device_identity().unwrap();
        write_private(&state.join("key.pem"), identity.private_key_pem.as_bytes());
        write_private(&state.join("csr.pem"), identity.csr_pem.as_bytes());
        let now = Utc::now().timestamp();
        let issued_at = now - age;
        let pki =
            fw_enrollment::init_controller_pki(&directory.path().join("pki"), issued_at).unwrap();
        let response = pki
            .authority
            .issue(
                &fw_enrollment::validate_csr(&identity.csr_pem, &identity.key_fingerprint).unwrap(),
                &fw_enrollment::Issuance {
                    request_id: Uuid::new_v4().to_string(),
                    org_id: Uuid::new_v4().to_string(),
                    project_id: Uuid::new_v4().to_string(),
                    target_id: Uuid::new_v4().to_string(),
                    job_id: Uuid::new_v4().to_string(),
                    issued_at,
                    authority_epoch: 0,
                },
            )
            .unwrap();
        let target = fw_enrollment::verify_enrollment_response(
            &response,
            &identity,
            pki.authority.ca_certificate_pem(),
            &response.target_id,
            issued_at,
        )
        .unwrap();
        let trust = pki.authority.trust_bundle_hash();
        let enrolled = json!({
            "schema_version":"fw.device-enrollment/v1",
            "controller_origin":CONTROLLER,
            "trust_bundle_hash":trust,
            "response":response
        });
        write_private(
            &state.join("enrollment.json"),
            &serde_json::to_vec(&enrolled).unwrap(),
        );
        let challenge: TargetMetadataChallenge = serde_json::from_value(json!({
            "schema_version":"fw.target-metadata-challenge/v1",
            "challenge_id":Uuid::new_v4(),
            "org_id":target.org_id,
            "project_id":target.project_id,
            "target_id":target.target_id,
            "key_revision":"1",
            "key_fingerprint":target.key_fingerprint,
            "certificate_fingerprint":target.certificate_fingerprint,
            "nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "issued_at":stamp(now),
            "expires_at":stamp(now+300)
        }))
        .unwrap();
        let challenge_file = directory.path().join("challenge.json");
        write_private(&challenge_file, &serde_json::to_vec(&challenge).unwrap());
        let public = PKey::private_key_from_pem(identity.private_key_pem.as_bytes())
            .unwrap()
            .raw_public_key()
            .unwrap()
            .try_into()
            .unwrap();
        Self {
            ca: directory.path().join("pki/ca.pem"),
            output_file: directory.path().join("proof.json"),
            certificate_expires: target.expires_at,
            _directory: directory,
            state,
            trust,
            challenge_file,
            challenge,
            public,
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fw_agent"));
        command.args([
            "sign-metadata",
            "--state-dir",
            self.state.to_str().unwrap(),
            "--controller",
            CONTROLLER,
            "--ca-file",
            self.ca.to_str().unwrap(),
            "--trust-bundle-hash",
            &self.trust,
            "--challenge-file",
            self.challenge_file.to_str().unwrap(),
            "--output-file",
            self.output_file.to_str().unwrap(),
        ]);
        command
    }
    fn run(&self) -> Output {
        self.command().output().unwrap()
    }
    fn replace_challenge(&mut self, mutate: impl FnOnce(&mut Value)) {
        let mut value = serde_json::to_value(&self.challenge).unwrap();
        mutate(&mut value);
        fs::write(&self.challenge_file, serde_json::to_vec(&value).unwrap()).unwrap();
    }
}

#[test]
fn actual_agent_signs_current_measurements_without_network_or_enforcement() {
    let f = Fixture::new();
    // Port 9 has no controller. Success exercises only local measurements/files.
    let result = f.run();
    assert!(
        result.status.success(),
        "{:?}",
        String::from_utf8_lossy(&result.stderr)
    );
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary["state"], "signed_metadata_not_admitted");
    assert_eq!(summary["enforcement"], false);
    assert!(summary.get("signature").is_none());
    assert!(summary.get("report_base64").is_none());
    assert!(summary.get("output_file").is_none());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("PRIVATE KEY"));
    let bytes = fs::read(&f.output_file).unwrap();
    let proof = SignedMetadataReport::parse(&bytes).unwrap();
    let verified = verify_report(
        &f.challenge,
        &proof,
        &f.public,
        "linux",
        Utc::now().timestamp(),
        f.certificate_expires,
    )
    .unwrap();
    assert_eq!(summary["report_hash"], verified.report_hash());
    let report: Value = serde_json::from_slice(verified.report_bytes()).unwrap();
    assert_eq!(report["profiles"], json!([]));
    assert_eq!(report["qualification_profiles"], json!([]));
    assert!(
        report["features"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v["state"] == "unverified")
    );
    assert_eq!(
        fs::metadata(&f.output_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let rerun = f.run();
    assert!(!rerun.status.success());
    assert_eq!(fs::read(&f.output_file).unwrap(), bytes);
}

#[test]
fn challenge_identity_and_time_mismatches_never_write_a_proof() {
    for field in [
        "org_id",
        "project_id",
        "target_id",
        "key_fingerprint",
        "certificate_fingerprint",
        "expires_at",
        "issued_at",
    ] {
        let mut f = Fixture::new();
        f.replace_challenge(|value| {
            value[field] = match field {
                "key_fingerprint" | "certificate_fingerprint" => {
                    format!("sha256:{}", "0".repeat(64)).into()
                }
                "expires_at" => stamp(Utc::now().timestamp()).into(),
                "issued_at" => stamp(Utc::now().timestamp() + 60).into(),
                _ => Uuid::new_v4().to_string().into(),
            };
        });
        let result = f.run();
        assert!(!result.status.success(), "{field}");
        assert!(!f.output_file.exists(), "{field}");
        assert!(!String::from_utf8_lossy(&result.stderr).contains(f.state.to_str().unwrap()));
    }
}

#[test]
fn signing_requires_existing_valid_enrollment_and_explicit_ca_pin() {
    for failure in [
        "missing_enrollment",
        "wrong_key",
        "wrong_pin",
        "expired_certificate",
    ] {
        let mut f = if failure == "expired_certificate" {
            Fixture::with_certificate_age(86_401)
        } else {
            Fixture::new()
        };
        match failure {
            "missing_enrollment" => fs::remove_file(f.state.join("enrollment.json")).unwrap(),
            "wrong_key" => {
                let other = fw_enrollment::generate_device_identity().unwrap();
                fs::write(f.state.join("key.pem"), other.private_key_pem).unwrap();
                fs::write(f.state.join("csr.pem"), other.csr_pem).unwrap();
            }
            "wrong_pin" => f.trust = format!("sha256:{}", "0".repeat(64)),
            "expired_certificate" => {}
            _ => unreachable!(),
        }
        assert!(!f.run().status.success(), "{failure}");
        assert!(!f.output_file.exists());
    }
}

#[test]
fn unsafe_input_and_output_aliases_are_refused_without_modifying_targets() {
    for failure in [
        "input_mode",
        "input_symlink",
        "input_hardlink",
        "input_too_large",
        "output_exists",
        "output_symlink",
        "output_hardlink",
        "output_shared",
        "output_key",
    ] {
        let mut f = Fixture::new();
        let sentinel = f._directory.path().join("sentinel");
        write_private(&sentinel, b"preserved");
        match failure {
            "input_mode" => {
                fs::set_permissions(&f.challenge_file, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "input_symlink" => {
                let original = f._directory.path().join("original.json");
                fs::rename(&f.challenge_file, &original).unwrap();
                symlink(original, &f.challenge_file).unwrap();
            }
            "input_hardlink" => {
                fs::hard_link(&f.challenge_file, f._directory.path().join("alias.json")).unwrap()
            }
            "input_too_large" => fs::write(&f.challenge_file, vec![b' '; 4097]).unwrap(),
            "output_exists" => write_private(&f.output_file, b"preserved"),
            "output_symlink" => symlink(&sentinel, &f.output_file).unwrap(),
            "output_hardlink" => fs::hard_link(&sentinel, &f.output_file).unwrap(),
            "output_shared" => {
                let shared = f._directory.path().join("shared");
                fs::create_dir(&shared).unwrap();
                fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
                f.output_file = shared.join("proof.json");
            }
            "output_key" => f.output_file = f.state.join("key.pem"),
            _ => unreachable!(),
        }
        let key_before = fs::read(f.state.join("key.pem")).unwrap();
        assert!(!f.run().status.success(), "{failure}");
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserved");
        assert_eq!(fs::read(f.state.join("key.pem")).unwrap(), key_before);
    }
}

#[test]
fn non_utf8_arguments_produce_fixed_errors_without_panics_or_input_echo() {
    let marker = "AGENT_PRIVATE_ARGUMENT_MARKER";
    let result = Command::new(env!("CARGO_BIN_EXE_fw_agent"))
        .arg("sign-metadata")
        .arg("--state-dir")
        .arg(OsString::from_vec([marker.as_bytes(), &[0xff]].concat()))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let diagnostic = String::from_utf8(result.stderr).unwrap();
    assert!(!diagnostic.contains(marker));
    assert!(!diagnostic.contains("panicked"));
    assert_eq!(
        serde_json::from_str::<Value>(&diagnostic).unwrap(),
        json!({"error":"COMMAND_ARGUMENT_ENCODING_INVALID"})
    );
}
