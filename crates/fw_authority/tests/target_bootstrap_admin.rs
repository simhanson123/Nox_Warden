#![cfg(all(feature = "approval-proofs", target_os = "linux"))]
//! Actual protected-local command processes. Synthetic pins are fixture inputs,
//! never evidence of target observation, human identity or qualification.
#[allow(dead_code)]
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/registry_fixture.rs"]
mod registry_fixture;
#[path = "support/target_bootstrap_fixture.rs"]
mod target_fixture;

use ed25519_dalek::SigningKey;
use fw_authority::{MAX_TARGET_BOOTSTRAP_BYTES, TargetBootstrapBundle, TargetBootstrapKeyPin};
use fw_backend_linux::{BOOTSTRAP_BASELINE_SCHEMA, BOOTSTRAP_CAPABILITY_SCHEMA, BOOTSTRAP_PROFILE};
use fw_contracts::{canonical_bytes, canonical_hash};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const TARGET: &str = "99999999-9999-4999-8999-999999999999";
const MANIFEST: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
fn at(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
struct Fixture {
    _directory: tempfile::TempDir,
    database: PathBuf,
    now: i64,
}
impl Fixture {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let fixture = Self {
            database: directory.path().join("authority.sqlite3"),
            _directory: directory,
            now: chrono::Utc::now().timestamp(),
        };
        assert!(fixture.run("init", &json!({})).status.success());
        assert!(fixture.run("init-project", &json!({})).status.success());
        fixture
    }
    fn command(&self, operation: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"));
        command.args([operation, "--database"]).arg(&self.database);
        if operation != "init" {
            command.args(["--org-id", ORG, "--project-id", PROJECT]);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
    fn run(&self, operation: &str, input: &Value) -> Output {
        execute(self.command(operation), &canonical_bytes(input).unwrap())
    }
    fn pin(&self, revision: &str) -> Value {
        serde_json::to_value(TargetBootstrapKeyPin {
            schema_version: "fw.target-bootstrap-key-pin/v1".into(),
            org_id: ORG.into(),
            project_id: PROJECT.into(),
            target_id: TARGET.into(),
            key_id: "independently-provisioned-fixture-target".into(),
            revision: revision.into(),
            public_key: SigningKey::from_bytes(&[73; 32]).verifying_key().to_bytes(),
            not_before: at(self.now - 60),
            not_after: at(self.now + 3600),
            profile: BOOTSTRAP_PROFILE.into(),
        })
        .unwrap()
    }
    fn read(&self) -> Value {
        success(self.run("read-target-bootstrap-status", &json!({"target_id":TARGET})))
    }
}
fn execute(mut command: Command, bytes: &[u8]) -> Output {
    let mut child = command.spawn().unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}
fn success(output: Output) -> Value {
    let result = canonical_output(output);
    assert_eq!(result["signing_allowed"], false);
    assert_eq!(result["dispatch_allowed"], false);
    result
}
fn canonical_output(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.stdout, canonical_bytes(&result).unwrap());
    result
}

#[test]
fn signed_target_receipt_import_recovers_output_loss_and_exact_retry_retains_one_head() {
    let directory = private_directory::private_directory();
    let now = chrono::Utc::now().timestamp() - 1;
    let mut registry = registry_fixture::Fixture::new(directory.path(), now);
    let target = target_fixture::TargetFixture::new(&mut registry);
    registry.approve(2);
    registry.authorize();
    let database = registry.path.clone();
    // This fixture uses the original contract tenant; the other negative tests
    // deliberately use a separate tenant. All calls still go through the CLI.
    let run = |operation: &str, input: &Value, full: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"));
        command
            .args([operation, "--database"])
            .arg(&database)
            .args([
                "--org-id",
                registry.tenant.org_id(),
                "--project-id",
                registry.tenant.project_id(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if full {
            command.stdout(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .unwrap(),
            );
        }
        execute(command, &canonical_bytes(input).unwrap())
    };
    success(run(
        "pin-target-bootstrap-key",
        &json!({"pin":target.pin,"expected_revision":null}),
        false,
    ));
    let bundle: TargetBootstrapBundle = serde_json::from_value(canonical_output(run(
        "challenge-target-bootstrap",
        &json!({"manifest_id":registry.manifest.manifest_id,"expected_target_revision":null,
            "baseline":target.baseline,"capability":target.capability}),
        false,
    )))
    .unwrap();
    let issued = chrono::DateTime::parse_from_rfc3339(&bundle.challenge.issued_at)
        .unwrap()
        .timestamp();
    let receipt = target.receipt(bundle.challenge, issued);
    // The synthetic observation's second boundary must precede the real CLI
    // admission clock. This bounded wait does not create native probe evidence.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while chrono::Utc::now().timestamp() < issued + 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture clock did not advance"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let input = serde_json::to_value(&receipt).unwrap();
    refused(
        run("import-target-bootstrap-confirmation", &input, true),
        "OUTPUT_FAILED",
    );
    let read = success(run(
        "read-target-bootstrap-status",
        &json!({"target_id":target.pin.target_id}),
        false,
    ));
    assert_eq!(
        read["status"]["confirmation_hash"],
        canonical_hash(&receipt).unwrap()
    );
    assert_eq!(read["status"]["confirmation_revision"], "1");
    assert_eq!(read["status"]["accepted_epoch"], "1");
    assert_eq!(read["status"]["current_confirmation_eligibility"], true);
    let retry = success(run("import-target-bootstrap-confirmation", &input, false));
    assert_eq!(retry["replayed"], true);
    assert_eq!(
        retry["confirmation_revision"],
        read["status"]["confirmation_revision"]
    );
    assert_eq!(
        retry["confirmation_hash"],
        read["status"]["confirmation_hash"]
    );
}
fn refused(output: Output, code: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("AUTHORITY_ADMIN code={code}\n").as_bytes()
    );
}

#[test]
fn independent_target_pin_is_not_accepted_epoch_history_and_rotations_require_cas() {
    let fixture = Fixture::new();
    assert!(fixture.read()["status"].is_null());
    let pin = fixture.pin("1");
    let request = json!({"pin":pin,"expected_revision":null});
    let first = success(fixture.run("pin-target-bootstrap-key", &request));
    assert_eq!(first["target_id"], TARGET);
    assert_eq!(first["current"], true);
    assert_eq!(first["revoked"], false);
    assert_eq!(first["pin_hash"], canonical_hash(&pin).unwrap());
    let retry = success(fixture.run("pin-target-bootstrap-key", &request));
    assert_eq!(retry["pin_hash"], first["pin_hash"]);
    assert_eq!(retry["pinned_at"], first["pinned_at"]);
    assert!(fixture.read()["status"].is_null());
    refused(
        fixture.run(
            "pin-target-bootstrap-key",
            &json!({"pin":fixture.pin("2"),"expected_revision":null}),
        ),
        "TARGET_BOOTSTRAP_KEY_REJECTED",
    );
    let revoked = success(fixture.run(
        "revoke-target-bootstrap-key",
        &json!({"target_id":TARGET,"revision":"1"}),
    ));
    assert_eq!(revoked["state"], "revoked");
    refused(
        fixture.run("pin-target-bootstrap-key", &request),
        "TARGET_BOOTSTRAP_KEY_REJECTED",
    );
    assert!(fixture.read()["status"].is_null());
}

#[test]
fn target_challenge_requires_retained_real_owner_authorization() {
    let fixture = Fixture::new();
    success(fixture.run(
        "pin-target-bootstrap-key",
        &json!({"pin":fixture.pin("1"),"expected_revision":null}),
    ));
    let baseline = json!({"schema_version":BOOTSTRAP_BASELINE_SCHEMA,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,
        "network_namespace":"net:[1]","interface_name":"fixture0","interface_index":1,
        "local_address":"192.0.2.1","peer_address":"192.0.2.2","prefix_length":30,
        "management_tcp_port":2222,"positive_udp_port":3333,"negative_udp_port":4444,
        "peer_probe_public_key":SigningKey::from_bytes(&[74;32]).verifying_key().to_bytes()});
    let capability = json!({"schema_version":BOOTSTRAP_CAPABILITY_SCHEMA,"platform":"linux","backend":"nftables",
        "profile":BOOTSTRAP_PROFILE,"kernel_release":"synthetic fixture","architecture":"x86_64","nft_version":"synthetic fixture"});
    let mut request = json!({"manifest_id":MANIFEST,"expected_target_revision":null,"baseline":baseline,"capability":capability});
    refused(
        fixture.run("challenge-target-bootstrap", &request),
        "TARGET_BOOTSTRAP_CHALLENGE_REJECTED",
    );
    request["owner_approved"] = json!(true);
    refused(
        fixture.run("challenge-target-bootstrap", &request),
        "TARGET_BOOTSTRAP_INPUT_REJECTED",
    );
    assert!(fixture.read()["status"].is_null());
}

#[test]
fn target_commands_reject_private_inline_unknown_duplicate_and_oversized_input() {
    let fixture = Fixture::new();
    for bytes in [
        format!("{{\"target_id\":\"{TARGET}\",\"target_id\":\"{TARGET}\"}}").into_bytes(),
        format!(
            "{{\"target_id\":\"{TARGET}\",\"qualified\":true,\"private_key\":\"never-echo-this\"}}"
        )
        .into_bytes(),
        vec![b' '; MAX_TARGET_BOOTSTRAP_BYTES + 1],
    ] {
        refused(
            execute(fixture.command("read-target-bootstrap-status"), &bytes),
            "TARGET_BOOTSTRAP_INPUT_REJECTED",
        );
    }
    for expected in ["0", "01", "18446744073709551616"] {
        refused(
            fixture.run(
                "pin-target-bootstrap-key",
                &json!({"pin":fixture.pin("1"),"expected_revision":expected}),
            ),
            "TARGET_BOOTSTRAP_INPUT_REJECTED",
        );
    }
    let mut inline = fixture.command("pin-target-bootstrap-key");
    inline.args(["--private-key", "never-accept-inline-private-material"]);
    refused(execute(inline, b"{}"), "ARGUMENTS_REJECTED");
}
