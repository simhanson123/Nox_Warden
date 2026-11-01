#![cfg(all(feature = "approval-proofs", target_os = "linux"))]
//! Actual local maintenance processes. Keys and certificates here are synthetic
//! fixture pins, never production enrollment or native qualification.
#[path = "support/native_fixture.rs"]
mod native_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;
use ed25519_dalek::SigningKey;
use fw_contracts::{canonical_bytes, hash_bytes};
use fw_target_evidence::{TargetMetadataChallenge, sign_report, timestamp};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const TARGET: &str = "44444444-4444-4444-8444-444444444444";
const SEED: [u8; 32] = [73; 32];
fn command(database: &Path, operation: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"));
    c.args([operation, "--database"]).arg(database);
    if operation != "init" {
        c.args(["--org-id", ORG, "--project-id", PROJECT]);
    }
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}
fn run(database: &Path, operation: &str, body: &Value) -> Output {
    let mut child = command(database, operation).spawn().unwrap();
    if let Err(error) = child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(body).unwrap())
    {
        // Argument/path refusals and init may finish before reading stdin.
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}
fn refused(output: Output, code: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("AUTHORITY_ADMIN code={code}\n")
    );
}
fn fixture(lifetime: i64) -> (tempfile::TempDir, PathBuf) {
    let directory = private_directory::private_directory();
    let db = directory.path().join("authority.sqlite3");
    success(run(&db, "init", &json!({})));
    success(run(&db, "init-project", &json!({})));
    let now = chrono::Utc::now().timestamp();
    let public = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    let pin = json!({"pin":{"target_id":TARGET,"public_key":public,"certificate_fingerprint":hash_bytes(b"fixture certificate"),"platform":"linux","not_before":now-1,"not_after":now+lifetime},"expected_revision":null});
    assert_eq!(success(run(&db, "pin-target", &pin))["key_revision"], "1");
    (directory, db)
}
fn proof(db: &Path) -> Value {
    let c = success(run(db, "challenge-target", &json!({"target_id":TARGET})));
    let challenge: TargetMetadataChallenge = serde_json::from_value(c).unwrap();
    let now = chrono::Utc::now().timestamp();
    let features = ["timed_allow","persistent_deny","strict_current_union","atomic_apply","semantic_readback","writer_fencing","independent_watchdog","new_management_probe","interface_scope","process_binding","independent_expiry","boot_guard","crash_fail_closed","absolute_deadline_guard"].into_iter().map(|name|(name.to_owned(),json!({"state":"unverified","reason_code":"CAPABILITY_NOT_QUALIFIED","evidence_hash":null}))).collect::<serde_json::Map<_,_>>();
    let report = json!({"schema_version":"f.target-capability/v1","capability_version":"f.target-capability/v1","target_id":TARGET,"platform":"linux","enforcement_backend":"nftables","os_version":"fixture kernel","backend_version":"unavailable","executor_build_hash":hash_bytes(b"fixture executable"),"checked_at":timestamp(now).unwrap(),"valid_until":timestamp(now+300).unwrap(),"profiles":[],"families":[],"directions":[],"protocols":[],"binding_kinds":[],"features":features,"max_policies":4096,"max_rules":100000,"max_artifact_bytes":16777216,"qualification_profiles":[],"interfaces":[]});
    serde_json::to_value(
        sign_report(&challenge, &canonical_bytes(&report).unwrap(), &SEED, now).unwrap(),
    )
    .unwrap()
}

#[test]
fn separate_admin_processes_retain_metadata_without_issuing_enforcement_authority() {
    let (_directory, db) = fixture(300);
    let input = proof(&db);
    let admitted = success(run(&db, "admit-target", &input));
    assert_eq!(admitted["replayed"], false);
    assert_eq!(admitted["dispatch_allowed"], false);
    let replay = success(run(&db, "admit-target", &input));
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["receipt"], admitted["receipt"]);
    let read = success(run(&db, "read-target", &json!({"target_id":TARGET})));
    assert_eq!(read["receipt"], admitted["receipt"]);
    assert_eq!(read["enforcement"], "unverified");
    let revoked = success(run(
        &db,
        "revoke-target",
        &json!({"target_id":TARGET,"expected_revision":"1"}),
    ));
    assert_eq!(revoked["status"], "revoked");
    let read = success(run(&db, "read-target", &json!({"target_id":TARGET})));
    assert!(read["receipt"].is_null());
    let historic = success(run(&db, "admit-target", &input));
    assert_eq!(historic["receipt"], admitted["receipt"]);
    assert_eq!(historic["dispatch_allowed"], false);
    refused(
        run(&db, "challenge-target", &json!({"target_id":TARGET})),
        "TARGET_CHALLENGE_REJECTED",
    );
}

#[test]
fn admin_rejects_aliases_missing_databases_and_private_input_diagnostics() {
    use std::os::unix::fs::symlink;
    let directory = private_directory::private_directory();
    let db = directory.path().join("authority.sqlite3");
    refused(
        run(&db, "read-target", &json!({"target_id":TARGET})),
        "DATABASE_REJECTED",
    );
    assert!(!db.exists());
    success(run(&db, "init", &json!({})));
    let before = fs::read(&db).unwrap();
    refused(run(&db, "init", &json!({})), "DATABASE_REJECTED");
    assert_eq!(before, fs::read(&db).unwrap());
    let alias = directory.path().join("alias.sqlite3");
    symlink(&db, &alias).unwrap();
    refused(
        run(&alias, "read-target", &json!({"target_id":TARGET})),
        "DATABASE_REJECTED",
    );
    refused(
        run(
            &db,
            "init-project",
            &json!({"private_marker":"DO_NOT_PRINT"}),
        ),
        "INPUT_REJECTED",
    );
    let mut c = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"));
    let result = c
        .arg("init")
        .arg("--database")
        .arg(std::ffi::OsString::from_vec(b"DO_NOT_PRINT\xff".to_vec()))
        .output()
        .unwrap();
    refused(result, "ARGUMENTS_REJECTED");
    let mut child = command(&db, "init-project").spawn().unwrap();
    let mut bytes = vec![b' '; 128 * 1024];
    bytes.extend_from_slice(b"{}");
    let _ = child.stdin.take().unwrap().write_all(&bytes);
    refused(child.wait_with_output().unwrap(), "INPUT_REJECTED");
}

#[test]
fn slow_stdin_does_not_use_command_start_time_to_accept_expired_proof() {
    let (_directory, db) = fixture(4);
    let input = proof(&db);
    let expires =
        fw_target_evidence::parse_time(input["challenge"]["expires_at"].as_str().unwrap()).unwrap();
    let mut child = command(&db, "admit-target").spawn().unwrap();
    // Confirm the actual executable reached its blocking input read before the
    // deadline; no fixed startup-delay assumption or product test clock is used.
    let waiting = PathBuf::from(format!("/proc/{}/wchan", child.id()));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let state = fs::read_to_string(&waiting).unwrap();
        if state.contains("pipe_read") {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "admin exited before input"
        );
        assert!(Instant::now() < deadline, "admin did not reach stdin");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(chrono::Utc::now().timestamp() < expires);
    while chrono::Utc::now().timestamp() <= expires {
        std::thread::sleep(Duration::from_millis(30));
    }
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    refused(child.wait_with_output().unwrap(), "TARGET_REPORT_REJECTED");
    let read = success(run(&db, "read-target", &json!({"target_id":TARGET})));
    assert!(read["receipt"].is_null());
}

#[test]
fn native_maintenance_requires_closed_typed_requests_and_preserves_existing_target() {
    let (_directory, db) = fixture(300);
    let input = proof(&db);
    let admitted = success(run(&db, "admit-target", &input));
    for operation in [
        "register-reviewed-plan",
        "pin-native-references",
        "pin-native-observer",
        "revoke-native-references",
        "revoke-native-observer",
        "compile-native",
        "challenge-native",
        "admit-native",
        "read-native",
    ] {
        refused(
            run(&db, operation, &json!({"private_marker":"DO_NOT_PRINT"})),
            "INPUT_REJECTED",
        );
    }
    // A valid metadata envelope is not a native observation proof, even when it
    // was accepted by its own protocol and target trust is current.
    refused(run(&db, "admit-native", &input), "INPUT_REJECTED");
    let current = success(run(&db, "read-target", &json!({"target_id":TARGET})));
    assert_eq!(current["receipt"], admitted["receipt"]);
    assert_eq!(current["dispatch_allowed"], false);
}

#[test]
fn native_maintenance_bounds_stdin_and_rejects_numeric_revision_aliases() {
    let (_directory, db) = fixture(300);
    refused(
        run(
            &db,
            "compile-native",
            &json!({"plan_id":TARGET,"expected_reference_revision":1}),
        ),
        "INPUT_REJECTED",
    );
    refused(
        run(
            &db,
            "compile-native",
            &json!({"plan_id":TARGET,"expected_reference_revision":"01"}),
        ),
        "INPUT_REJECTED",
    );
    let mut child = command(&db, "admit-native").spawn().unwrap();
    let mut bytes = vec![b' '; 4 * 1024 * 1024];
    bytes.extend_from_slice(b"{}");
    let _ = child.stdin.take().unwrap().write_all(&bytes);
    refused(child.wait_with_output().unwrap(), "INPUT_REJECTED");
}

#[test]
fn native_challenge_accepts_zero_epoch_and_generation_but_not_counter_aliases() {
    let directory = private_directory::private_directory();
    let database = directory.path().join("authority.sqlite3");
    let now = chrono::Utc::now().timestamp();
    let mut store = fw_authority::AuthorityStore::open(&database).unwrap();
    let (_, mut plan, requirements, evidence, references) = native_fixture::setup(&mut store, now);
    let plan_id = "77777777-7777-4777-8777-777777777778";
    plan["plan_id"] = json!(plan_id);
    plan["authority_epoch"] = json!("0");
    plan["target_generation"] = json!("0");
    let artifact = fw_backend_linux::compile_portable(&evidence.after, &references).unwrap();
    let installation = native_fixture::installation(&artifact, now);
    drop(store);

    // Exercise the actual executable against real pins and signed metadata,
    // then retain and independently compile the exact reviewed zero-counter plan.
    let registered = success(run(
        &database,
        "register-reviewed-plan",
        &json!({
            "plan":plan,"requirements":requirements,"evidence":evidence
        }),
    ));
    assert_eq!(registered["dispatch_allowed"], false);
    refused(
        run(
            &database,
            "compile-native",
            &json!({
                "plan_id":plan_id,"expected_reference_revision":"0"
            }),
        ),
        "INPUT_REJECTED",
    );
    let compilation = success(run(
        &database,
        "compile-native",
        &json!({
            "plan_id":plan_id,"expected_reference_revision":"1"
        }),
    ));
    assert_eq!(compilation["dispatch_allowed"], false);
    let request = json!({"plan_id":plan_id,"artifact_role":"candidate",
        "installation":installation,"expected_head":null,"authority_epoch":"0","generation":"0"});
    for field in ["authority_epoch", "generation"] {
        for alias in [
            json!("00"),
            json!("+0"),
            json!("-0"),
            json!("18446744073709551616"),
            json!(0),
        ] {
            let mut malformed = request.clone();
            malformed[field] = alias;
            refused(
                run(&database, "challenge-native", &malformed),
                "INPUT_REJECTED",
            );
        }
    }
    let challenge = success(run(&database, "challenge-native", &request));
    assert_eq!(challenge["authority_epoch"], "0");
    assert_eq!(challenge["generation"], "0");
    assert_eq!(challenge["reference_revision"], "1");
    assert_eq!(challenge["observer_revision"], "1");
    let parsed: fw_native_evidence::NativeObservationChallenge =
        serde_json::from_value(challenge).unwrap();
    parsed.validate(chrono::Utc::now().timestamp()).unwrap();
}
