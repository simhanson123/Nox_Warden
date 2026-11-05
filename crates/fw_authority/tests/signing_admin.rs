#![cfg(all(feature = "approval-proofs", target_os = "linux"))]
//! Real local administration processes. The signed native and approval fixtures
//! exercise cryptography; they do not qualify a production signer or host.
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/authority_legacy.rs"]
#[allow(dead_code)]
mod authority_legacy;
#[path = "support/native_fixture.rs"]
mod native_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;

use approval_authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_authority::{
    ApprovalDecision, ApprovalRole, AuthorityBasis, AuthorityStore, AuthorityTenant,
};
use fw_contracts::{canonical_bytes, canonical_hash};
use fw_native_evidence::ArtifactRole;
use fw_webauthn::WebAuthn;
use native_fixture::{ORG, PLAN, PROJECT};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const ROOT: &str = "88888888-8888-4888-8888-888888888888";
const REQUEST: &str = "66666666-6666-4666-8666-666666666666";
const OTHER: &str = "55555555-5555-4555-8555-555555555555";

fn command(db: &Path, operation: &str) -> Command {
    tenant_command(db, operation, ORG, PROJECT)
}

fn tenant_command(db: &Path, operation: &str, org: &str, project: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"));
    command.args([operation, "--database"]).arg(db);
    if operation != "init" {
        command.args(["--org-id", org, "--project-id", project]);
    }
    if matches!(
        operation,
        "read-signing-readiness" | "read-signing-readiness-v2" | "request-signing"
    ) {
        command.args(["--approval-origin", ORIGIN]);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn project_only_cutover_uses_cas_and_can_restore_only_the_original_root() {
    let fixture = Fixture::new();
    fixture.pin_quotas();
    let db = rusqlite::Connection::open(&fixture.db).unwrap();
    let retained: Vec<(i64, Vec<u8>)> = db
        .prepare("SELECT rowid,canonical_bytes FROM authority_signing_quota_pins ORDER BY rowid")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    drop(db);
    let mut cutover = fixture.quota.clone();
    cutover["schema_version"] = json!("fw.signing-project-quota-pin/v2");
    cutover["pin"].as_object_mut().unwrap().remove("root_id");
    refused(
        run(&fixture.db, "pin-signing-project-quota", &cutover),
        "SIGNING_QUOTA_REJECTED",
    );
    cutover["expected_revision"] = json!("1");
    assert_eq!(
        success(run(&fixture.db, "pin-signing-project-quota", &cutover))["revision"],
        "2"
    );
    let mut alternative = fixture.quota.clone();
    alternative["pin"]["root_id"] = json!(OTHER);
    success(run(&fixture.db, "pin-signing-root-quota", &alternative));
    alternative["expected_revision"] = json!("2");
    refused(
        run(&fixture.db, "pin-signing-project-quota", &alternative),
        "SIGNING_QUOTA_REJECTED",
    );
    let mut restore = fixture.quota.clone();
    restore["expected_revision"] = json!("2");
    assert_eq!(
        success(run(&fixture.db, "pin-signing-project-quota", &restore))["revision"],
        "3"
    );
    assert_eq!(fixture.readiness()["quota_configured"], true);
    let status = success(run(
        &fixture.db,
        "read-signing-readiness-v2",
        &json!({"plan_id":PLAN}),
    ));
    assert_eq!(status["quota_scope"], "root");
    assert_eq!(status["quota_root_id"], ROOT);
    let db = rusqlite::Connection::open(&fixture.db).unwrap();
    for (rowid, bytes) in retained {
        assert_eq!(
            db.query_row(
                "SELECT canonical_bytes FROM authority_signing_quota_pins WHERE rowid=?",
                [rowid],
                |row| row.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
            bytes
        );
    }
}

#[test]
fn project_only_quota_requires_an_explicit_version_and_keeps_production_closed() {
    let fixture = Fixture::new();
    let mut body = fixture.quota.clone();
    body["schema_version"] = json!("fw.signing-project-quota-pin/v2");
    body["pin"].as_object_mut().unwrap().remove("root_id");
    let pinned = success(run(&fixture.db, "pin-signing-project-quota", &body));
    assert_eq!(
        pinned,
        json!({"schema_version":"fw.signing-project-quota-pin/v2","quota_scope":"project","revision":"1","signing_allowed":false,"dispatch_allowed":false})
    );
    assert!(pinned.get("root_id").is_none());
    let before = signing_resources(&fixture.db);
    let audit_count = || {
        rusqlite::Connection::open(&fixture.db)
            .unwrap()
            .query_row("SELECT count(*) FROM authority_audit", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    };
    let audits = audit_count();
    let mut retry = body.clone();
    retry["expected_revision"] = json!("1");
    assert_eq!(
        success(run(&fixture.db, "pin-signing-project-quota", &retry)),
        pinned
    );
    assert_eq!(signing_resources(&fixture.db), before);
    assert_eq!(audit_count(), audits);
    let read = json!({"plan_id":PLAN});
    refused(
        run(&fixture.db, "read-signing-readiness", &read),
        "SIGNING_READINESS_REJECTED",
    );
    let readiness = success(run(&fixture.db, "read-signing-readiness-v2", &read));
    assert_eq!(readiness["schema_version"], "fw.signing-readiness/v2");
    assert_eq!(readiness["quota_scope"], "project");
    assert_eq!(readiness["quota_root_id"], Value::Null);
    assert_eq!(readiness["quota_configured"], true);
    assert_eq!(readiness["latest_dispatch_unknown_seen"], Value::Null);
    assert_eq!(readiness["signing_allowed"], false);
    assert_eq!(readiness["dispatch_allowed"], false);
    refused(
        run(&fixture.db, "request-signing", &fixture.request),
        "SIGNING_REQUEST_REJECTED",
    );
    assert_eq!(signing_resources(&fixture.db), before);
}

#[test]
fn project_quota_codecs_reject_partial_roots_and_unknown_versions_without_downgrade() {
    let fixture = Fixture::new();
    let before = signing_resources(&fixture.db);
    let mut rootless = fixture.quota.clone();
    rootless["pin"].as_object_mut().unwrap().remove("root_id");
    let mut null_root = fixture.quota.clone();
    null_root["pin"]["root_id"] = Value::Null;
    let mut unknown = rootless.clone();
    unknown["schema_version"] = json!("fw.signing-project-quota-pin/v3");
    let mut legacy_tag = fixture.quota.clone();
    legacy_tag["schema_version"] = json!("fw.signing-project-quota-pin/v1");
    let mut v2_root = fixture.quota.clone();
    v2_root["schema_version"] = json!("fw.signing-project-quota-pin/v2");
    let mut v2_null = null_root.clone();
    v2_null["schema_version"] = json!("fw.signing-project-quota-pin/v2");
    for body in [rootless, null_root, unknown, legacy_tag, v2_root, v2_null] {
        refused(
            run(&fixture.db, "pin-signing-project-quota", &body),
            "INPUT_REJECTED",
        );
    }
    assert_eq!(signing_resources(&fixture.db), before);
}

fn execute(mut command: Command, bytes: &[u8]) -> Output {
    let mut child = command.spawn().unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}

fn run(db: &Path, operation: &str, body: &Value) -> Output {
    execute(command(db, operation), &serde_json::to_vec(body).unwrap())
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.stdout, canonical_bytes(&value).unwrap());
    value
}

fn refused(output: Output, code: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("AUTHORITY_ADMIN code={code}\n").as_bytes()
    );
}

fn signing_resources(db: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    resources(db, false)
}

fn authority_resources(db: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    resources(db, true)
}

fn resources(db: &Path, all_authority: bool) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let connection = rusqlite::Connection::open(db).unwrap();
    let sql = if all_authority {
        "SELECT name FROM sqlite_schema WHERE type='table' AND name GLOB 'authority_*' ORDER BY name"
    } else {
        "SELECT name FROM sqlite_schema WHERE type='table' AND name GLOB 'authority_signing_*' AND name NOT LIKE '%clock%' ORDER BY name"
    };
    let mut statement = connection.prepare(sql).unwrap();
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!names.is_empty(), "signing schema must be present");
    names
        .into_iter()
        .map(|name| {
            let sql = format!(
                "SELECT * FROM \"{}\" ORDER BY rowid",
                name.replace('"', "\"\"")
            );
            let mut query = connection.prepare(&sql).unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get(i))
                        .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}

struct Fixture {
    _directory: tempfile::TempDir,
    db: PathBuf,
    request: Value,
    quota: Value,
    native_receipt: Value,
}

impl Fixture {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let db = directory.path().join("authority.sqlite3");
        success(run(&db, "init", &json!({})));
        let now = chrono::Utc::now().timestamp() - 2;
        let mut store = AuthorityStore::open(&db).unwrap();
        let (tenant, plan, requirements, review, references) =
            native_fixture::setup(&mut store, now);
        store
            .register_native_compilation(&tenant, PLAN, 1, now)
            .unwrap();
        let artifact = fw_backend_linux::compile_portable(&review.before, &references).unwrap();
        let installation = native_fixture::installation(&artifact, now);
        let challenge = store
            .challenge_native_observation(
                &tenant,
                PLAN,
                ArtifactRole::Baseline,
                &installation,
                None,
                1,
                1,
                now,
            )
            .unwrap();
        let readback = native_fixture::snapshot(&installation.native);
        let proof = native_fixture::proof(&challenge, installation, readback, now + 1);
        let observation = store
            .admit_native_observation(&tenant, &proof, now + 1)
            .unwrap();
        assert_eq!(observation.receipt.comparison, "match");
        assert!(!observation.receipt.production_qualified);

        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Signing review fixture", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        store
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://identity.example.test",
                "reviewer",
                now + 1,
            )
            .unwrap();
        store
            .pin_credential(&tenant, &credential, now, now + 3600, now + 1)
            .unwrap();
        let activation = store
            .begin_credential_activation(&tenant, &credential.id(), &verifier, now + 1)
            .unwrap();
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &key.assertion(&activation.options, 1, 0x05, ORIGIN),
                &verifier,
                now + 1,
            )
            .unwrap();
        store
            .grant_role(
                &tenant,
                PRINCIPAL,
                ApprovalRole::Owner,
                now,
                now + 3600,
                now + 1,
            )
            .unwrap();
        store
            .bind_human_identity(&tenant, PRINCIPAL, PRINCIPAL, now + 1)
            .unwrap();
        store
            .provision_authority_basis(
                &tenant,
                &AuthorityBasis {
                    epoch: 1,
                    role_policy_hash: requirements["role_policy_hash"].as_str().unwrap().into(),
                    not_before: now,
                    not_after: now + 3600,
                },
                now + 1,
            )
            .unwrap();
        let issued = store
            .issue_reviewed_challenge(
                &tenant,
                PRINCIPAL,
                &credential.id(),
                PLAN,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &verifier,
                now + 1,
            )
            .unwrap();
        store
            .admit_reviewed_decision(
                &tenant,
                PRINCIPAL,
                issued.challenge.challenge_id(),
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                &key.assertion(&issued.options, 2, 0x05, ORIGIN),
                &verifier,
                now + 1,
            )
            .unwrap();
        let approval = store
            .current_approval_set(&tenant, PLAN, &verifier, now + 1)
            .unwrap()
            .unwrap();
        let request = json!({
            "request_id":REQUEST,"plan_id":PLAN,"expected_plan_hash":canonical_hash(&plan).unwrap(),
            "expected_approval_set_hash":approval.hash()
        });
        let quota = json!({"pin":{
            "root_id":ROOT,"not_before":now,"not_after":now+3600,
            "limits":{"active_leases":2,"new_leases_per_day":4,"unique_destinations_per_day":8,
                "cumulative_seconds_per_day":3600,"concurrent_deployments":1}
        },"expected_revision":null});
        Self {
            _directory: directory,
            db,
            request,
            quota,
            native_receipt: serde_json::to_value(observation.receipt).unwrap(),
        }
    }

    fn pin_quotas(&self) {
        for operation in ["pin-signing-root-quota", "pin-signing-project-quota"] {
            let result = success(run(&self.db, operation, &self.quota));
            assert_eq!(result["revision"], "1");
            assert_eq!(result["signing_allowed"], false);
            assert_eq!(result["dispatch_allowed"], false);
        }
    }

    fn readiness(&self) -> Value {
        success(run(
            &self.db,
            "read-signing-readiness",
            &json!({"plan_id":PLAN}),
        ))
    }
}

#[test]
fn public_signing_request_cannot_promote_matching_lab_evidence_or_human_approval() {
    let fixture = Fixture::new();
    let before = fixture.readiness();
    assert_eq!(before["signing_allowed"], false);
    assert_eq!(before["dispatch_allowed"], false);
    assert_eq!(before["quota_configured"], false);
    assert!(
        before["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("QUOTA_CONFIGURATION_MISSING"))
    );
    assert!(
        !before["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("APPROVAL_SET_MISSING"))
    );
    assert!(
        !before["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("NATIVE_BASELINE_UNAVAILABLE"))
    );
    fixture.pin_quotas();
    let after = fixture.readiness();
    assert_eq!(after["signing_allowed"], false);
    assert_eq!(after["dispatch_allowed"], false);
    assert_eq!(after["quota_configured"], true);
    assert!(
        !after["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("QUOTA_CONFIGURATION_MISSING"))
    );
    for reason in [
        "PROTECTED_BOOTSTRAP_REQUIRED",
        "BUILD_IDENTITY_REQUIRED",
        "NATIVE_QUALIFICATION_REQUIRED",
        "PROTECTED_SIGNER_UNAVAILABLE",
    ] {
        assert!(
            after["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!(reason))
        );
    }
    let resources = signing_resources(&fixture.db);
    for (name, rows) in &resources {
        if !matches!(
            name.as_str(),
            "authority_signing_quota_pins"
                | "authority_signing_quota_heads"
                | "authority_signing_quota_revocations"
        ) {
            assert!(rows.is_empty(), "{name} must not exist before preparation");
        }
    }
    // Each request is a new process opening the durable store. Identical retries
    // do not manufacture an intent, signed grant or accepted-result receipt.
    for _ in 0..3 {
        refused(
            run(&fixture.db, "request-signing", &fixture.request),
            "SIGNING_REQUEST_REJECTED",
        );
    }
    let absent = success(run(
        &fixture.db,
        "read-signing-intent",
        &json!({"intent_id":REQUEST}),
    ));
    assert!(absent["intent"].is_null());
    assert_eq!(absent["signing_allowed"], false);
    assert_eq!(absent["dispatch_allowed"], false);
    assert_eq!(signing_resources(&fixture.db), resources);
}

#[test]
fn cancellation_rejects_missing_jobs_and_untrusted_input_without_creating_work() {
    let fixture = Fixture::new();
    fixture.pin_quotas();
    let before = signing_resources(&fixture.db);
    for job in [OTHER, "DO_NOT_PRINT_JOB"] {
        refused(
            run(&fixture.db, "cancel-signing-job", &json!({"job_id":job})),
            "SIGNING_CANCELLATION_REJECTED",
        );
    }
    for bytes in [
        b"{}".to_vec(),
        serde_json::to_vec(&json!({"job_id":OTHER,"force":true})).unwrap(),
        format!("{{\"job_id\":\"{OTHER}\",\"job_id\":\"{REQUEST}\"}}").into_bytes(),
        vec![b' '; 128 * 1024 + 1],
    ] {
        refused(
            execute(command(&fixture.db, "cancel-signing-job"), &bytes),
            "INPUT_REJECTED",
        );
    }
    let mut unexpected_option = command(&fixture.db, "cancel-signing-job");
    unexpected_option.args(["--approval-origin", "DO_NOT_PRINT_ORIGIN"]);
    refused(execute(unexpected_option, b"{}"), "ARGUMENTS_REJECTED");
    refused(
        execute(
            tenant_command(
                &fixture.db,
                "cancel-signing-job",
                "DO_NOT_PRINT_ORG",
                PROJECT,
            ),
            &serde_json::to_vec(&json!({"job_id":OTHER})).unwrap(),
        ),
        "TENANT_REJECTED",
    );
    assert_eq!(signing_resources(&fixture.db), before);
}

#[test]
fn trusted_root_quota_management_is_organization_scoped() {
    let fixture = Fixture::new();
    fixture.pin_quotas();
    let other_project = AuthorityTenant::new(ORG, OTHER).unwrap();
    let other_org = AuthorityTenant::new(OTHER, OTHER).unwrap();
    let mut store = AuthorityStore::open(&fixture.db).unwrap();
    let now = chrono::Utc::now().timestamp();
    for tenant in [&other_project, &other_org] {
        store
            .provision_target_metadata_project(tenant, now)
            .unwrap();
    }
    drop(store);
    let mut update = fixture.quota.clone();
    update["expected_revision"] = json!("1");
    update["pin"]["limits"]["concurrent_deployments"] = json!(2);
    let revised = success(execute(
        tenant_command(&fixture.db, "pin-signing-root-quota", ORG, OTHER),
        &serde_json::to_vec(&update).unwrap(),
    ));
    assert_eq!(revised["revision"], "2");
    update["expected_revision"] = json!("2");
    assert_eq!(
        success(run(&fixture.db, "pin-signing-root-quota", &update))["revision"],
        "2"
    );
    let before = signing_resources(&fixture.db);
    for (operation, body) in [
        ("pin-signing-root-quota", update),
        ("pin-signing-project-quota", fixture.quota.clone()),
        (
            "revoke-signing-root-quota",
            json!({"root_id":ROOT,"expected_revision":"2"}),
        ),
    ] {
        refused(
            execute(
                tenant_command(&fixture.db, operation, OTHER, OTHER),
                &serde_json::to_vec(&body).unwrap(),
            ),
            "SIGNING_QUOTA_REJECTED",
        );
    }
    assert_eq!(signing_resources(&fixture.db), before);
}

#[test]
fn quota_configuration_has_independent_cas_and_does_not_allow_root_rebinding() {
    let fixture = Fixture::new();
    fixture.pin_quotas();
    refused(
        run(&fixture.db, "pin-signing-root-quota", &fixture.quota),
        "SIGNING_QUOTA_REJECTED",
    );
    refused(
        run(&fixture.db, "pin-signing-project-quota", &fixture.quota),
        "SIGNING_QUOTA_REJECTED",
    );
    let mut next = fixture.quota.clone();
    next["expected_revision"] = json!("1");
    next["pin"]["limits"]["concurrent_deployments"] = json!(2);
    assert_eq!(
        success(run(&fixture.db, "pin-signing-root-quota", &next))["revision"],
        "2"
    );
    // Root update does not silently advance the independently pinned project.
    assert_eq!(
        success(run(&fixture.db, "pin-signing-project-quota", &next))["revision"],
        "2"
    );
    refused(
        run(
            &fixture.db,
            "revoke-signing-root-quota",
            &json!({"root_id":ROOT,"expected_revision":"1"}),
        ),
        "SIGNING_QUOTA_REJECTED",
    );
    refused(
        run(
            &fixture.db,
            "revoke-signing-project-quota",
            &json!({"expected_revision":"1"}),
        ),
        "SIGNING_QUOTA_REJECTED",
    );
    let mut alternative = fixture.quota.clone();
    alternative["pin"]["root_id"] = json!(OTHER);
    success(run(&fixture.db, "pin-signing-root-quota", &alternative));
    alternative["expected_revision"] = json!("2");
    refused(
        run(&fixture.db, "pin-signing-project-quota", &alternative),
        "SIGNING_QUOTA_REJECTED",
    );
    success(run(
        &fixture.db,
        "revoke-signing-project-quota",
        &json!({"expected_revision":"2"}),
    ));
    refused(
        run(&fixture.db, "request-signing", &fixture.request),
        "SIGNING_REQUEST_REJECTED",
    );
    success(run(
        &fixture.db,
        "revoke-signing-root-quota",
        &json!({"root_id":ROOT,"expected_revision":"2"}),
    ));
}

#[test]
fn signing_commands_reject_untrusted_authority_fields_and_bounded_input_aliases() {
    let fixture = Fixture::new();
    for operation in [
        "pin-signing-root-quota",
        "pin-signing-project-quota",
        "read-signing-project-quota",
        "revoke-signing-root-quota",
        "revoke-signing-project-quota",
        "read-signing-readiness",
        "request-signing",
        "read-signing-intent",
        "cancel-signing-job",
    ] {
        refused(
            run(
                &fixture.db,
                operation,
                &json!({"private_key":"DO_NOT_PRINT","production_qualified":true}),
            ),
            "INPUT_REJECTED",
        );
    }
    for revision in [
        json!(0),
        json!(1),
        json!("0"),
        json!("01"),
        json!("+1"),
        json!("18446744073709551616"),
    ] {
        let mut pin = fixture.quota.clone();
        pin["expected_revision"] = revision;
        refused(
            run(&fixture.db, "pin-signing-root-quota", &pin),
            "INPUT_REJECTED",
        );
    }
    let mut forged = fixture.request.clone();
    forged["quota"] = json!({"project_remaining":1000000});
    refused(
        run(&fixture.db, "request-signing", &forged),
        "INPUT_REJECTED",
    );
    refused(
        execute(
            command(&fixture.db, "read-signing-readiness"),
            format!("{{\"plan_id\":\"{PLAN}\",\"plan_id\":\"{OTHER}\"}}").as_bytes(),
        ),
        "INPUT_REJECTED",
    );
    let mut oversized = vec![b' '; 128 * 1024];
    oversized.extend_from_slice(b"{}");
    refused(
        execute(command(&fixture.db, "request-signing"), &oversized),
        "INPUT_REJECTED",
    );
    let mut missing_origin = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"));
    missing_origin
        .args(["read-signing-readiness", "--database"])
        .arg(&fixture.db)
        .args(["--org-id", ORG, "--project-id", PROJECT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    refused(execute(missing_origin, b"{}"), "ARGUMENTS_REJECTED");
    let mut invalid_origin = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"));
    invalid_origin
        .args(["read-signing-readiness", "--database"])
        .arg(&fixture.db)
        .args([
            "--org-id",
            ORG,
            "--project-id",
            PROJECT,
            "--approval-origin",
            "DO_NOT_PRINT_ORIGIN",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    refused(
        execute(
            invalid_origin,
            &serde_json::to_vec(&json!({"plan_id":PLAN})).unwrap(),
        ),
        "APPROVAL_ORIGIN_REJECTED",
    );
}

#[test]
fn lost_project_quota_output_recovers_rooted_and_project_only_revisions_without_writes() {
    let fixture = Fixture::new();
    let unconfigured = authority_resources(&fixture.db);
    let absent = success(run(&fixture.db, "read-signing-project-quota", &json!({})));
    assert_eq!(
        absent,
        json!({
            "schema_version":"fw.signing-project-quota-state/v1",
            "org_id":ORG,"project_id":PROJECT,"current_pin":null,
            "signing_allowed":false,"dispatch_allowed":false
        })
    );
    assert_eq!(authority_resources(&fixture.db), unconfigured);
    success(run(&fixture.db, "pin-signing-root-quota", &fixture.quota));
    let mut rootless = fixture.quota.clone();
    rootless["schema_version"] = json!("fw.signing-project-quota-pin/v2");
    rootless["pin"].as_object_mut().unwrap().remove("root_id");
    rootless["expected_revision"] = json!("1");
    for (input, revision, scope, pin_version) in [
        (
            &fixture.quota,
            "1",
            "root",
            "fw.signing-project-quota-pin/v1",
        ),
        (&rootless, "2", "project", "fw.signing-project-quota-pin/v2"),
    ] {
        let mut failed = command(&fixture.db, "pin-signing-project-quota");
        failed.stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        );
        refused(
            execute(failed, &serde_json::to_vec(input).unwrap()),
            "OUTPUT_FAILED",
        );
        let before = authority_resources(&fixture.db);
        let recovered = success(run(&fixture.db, "read-signing-project-quota", &json!({})));
        assert_eq!(
            recovered["schema_version"],
            "fw.signing-project-quota-state/v1"
        );
        assert_eq!(recovered["org_id"], ORG);
        assert_eq!(recovered["project_id"], PROJECT);
        assert_eq!(recovered["current_pin"]["revision"], revision);
        assert_eq!(recovered["current_pin"]["quota_scope"], scope);
        assert_eq!(recovered["current_pin"]["pin_schema_version"], pin_version);
        assert_eq!(recovered["current_pin"]["pin"], input["pin"]);
        assert_eq!(recovered["current_pin"]["revoked"], false);
        assert_eq!(recovered["signing_allowed"], false);
        assert_eq!(recovered["dispatch_allowed"], false);
        assert_eq!(authority_resources(&fixture.db), before);
        let mut failed_read = command(&fixture.db, "read-signing-project-quota");
        failed_read.stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        );
        refused(execute(failed_read, b"{}"), "OUTPUT_FAILED");
        assert_eq!(authority_resources(&fixture.db), before);
        let mut exact_retry = input.clone();
        exact_retry["expected_revision"] = recovered["current_pin"]["revision"].clone();
        assert_eq!(
            success(run(&fixture.db, "pin-signing-project-quota", &exact_retry))["revision"],
            revision
        );
    }
}

#[test]
fn project_quota_recovery_keeps_expired_revoked_heads_scoped_and_rejects_untrusted_input() {
    let directory = private_directory::private_directory();
    let db = directory.path().join("authority.sqlite3");
    success(run(&db, "init", &json!({})));
    let now = chrono::Utc::now().timestamp();
    let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
    let mut store = AuthorityStore::open(&db).unwrap();
    store
        .provision_target_metadata_project(&tenant, now - 120)
        .unwrap();
    let pin = fw_authority::SigningProjectQuotaPin {
        root_id: None,
        limits: fw_authority::SigningQuotaLimits {
            active_leases: 1,
            new_leases_per_day: 1,
            unique_destinations_per_day: 1,
            cumulative_seconds_per_day: 60,
            concurrent_deployments: 1,
        },
        not_before: now - 120,
        not_after: now - 60,
    };
    store
        .pin_signing_project_quota(&tenant, &pin, None, now - 120)
        .unwrap();
    let before_expired_read = authority_resources(&db);
    let expired = success(run(&db, "read-signing-project-quota", &json!({})));
    assert_eq!(expired["current_pin"]["revision"], "1");
    assert_eq!(expired["current_pin"]["pin"]["not_after"], now - 60);
    assert_eq!(expired["current_pin"]["revoked"], false);
    assert_eq!(authority_resources(&db), before_expired_read);
    store.revoke_signing_project_quota(&tenant, 1, now).unwrap();
    for other in [
        AuthorityTenant::new(ORG, OTHER).unwrap(),
        AuthorityTenant::new(OTHER, PROJECT).unwrap(),
    ] {
        store
            .provision_target_metadata_project(&other, now)
            .unwrap();
    }
    drop(store);
    let before = authority_resources(&db);
    let revoked = success(run(&db, "read-signing-project-quota", &json!({})));
    assert_eq!(revoked["current_pin"]["revision"], "1");
    assert_eq!(revoked["current_pin"]["revoked"], true);
    for (org, project) in [(ORG, OTHER), (OTHER, PROJECT)] {
        let hidden = success(execute(
            tenant_command(&db, "read-signing-project-quota", org, project),
            b"{}",
        ));
        assert_eq!(hidden["org_id"], org);
        assert_eq!(hidden["project_id"], project);
        assert_eq!(hidden["current_pin"], Value::Null);
    }
    refused(
        execute(
            tenant_command(&db, "read-signing-project-quota", ORG, REQUEST),
            b"{}",
        ),
        "SIGNING_QUOTA_REJECTED",
    );
    for bytes in [
        b"{\"project_id\":\"DO_NOT_PRINT\"}".to_vec(),
        b"{\"root_id\":null}".to_vec(),
        b"{\"expected_revision\":\"1\",\"expected_revision\":\"2\"}".to_vec(),
        b"[]".to_vec(),
        vec![b' '; 128 * 1024 + 1],
    ] {
        refused(
            execute(command(&db, "read-signing-project-quota"), &bytes),
            "INPUT_REJECTED",
        );
    }
    let mut unexpected_option = command(&db, "read-signing-project-quota");
    unexpected_option.args(["--approval-origin", "DO_NOT_PRINT"]);
    refused(execute(unexpected_option, b"{}"), "ARGUMENTS_REJECTED");
    assert_eq!(authority_resources(&db), before);
}

#[test]
fn lost_quota_pin_output_keeps_revision_and_never_grants_signing() {
    let fixture = Fixture::new();
    let mut failed = command(&fixture.db, "pin-signing-root-quota");
    failed.stdout(
        fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap(),
    );
    refused(
        execute(failed, &serde_json::to_vec(&fixture.quota).unwrap()),
        "OUTPUT_FAILED",
    );
    refused(
        run(&fixture.db, "pin-signing-root-quota", &fixture.quota),
        "SIGNING_QUOTA_REJECTED",
    );
    let mut next = fixture.quota.clone();
    next["expected_revision"] = json!("1");
    assert_eq!(
        success(run(&fixture.db, "pin-signing-root-quota", &next))["revision"],
        "1"
    );
    next["pin"]["limits"]["concurrent_deployments"] = json!(2);
    assert_eq!(
        success(run(&fixture.db, "pin-signing-root-quota", &next))["revision"],
        "2"
    );
    success(run(
        &fixture.db,
        "pin-signing-project-quota",
        &fixture.quota,
    ));
    assert_eq!(fixture.readiness()["signing_allowed"], false);
    refused(
        run(&fixture.db, "request-signing", &fixture.request),
        "SIGNING_REQUEST_REJECTED",
    );
}

#[test]
fn actual_migration_requires_backup_and_preserves_native_receipts_without_authority() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let native_before = success(run(&fixture.db, "read-native", &json!({"plan_id":PLAN})));
    authority_legacy::restore_v6(&fixture.db);
    refused(
        run(
            &fixture.db,
            "read-signing-readiness",
            &json!({"plan_id":PLAN}),
        ),
        "DATABASE_REJECTED",
    );
    let database_version = || {
        rusqlite::Connection::open(&fixture.db)
            .unwrap()
            .query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    };
    assert_eq!(database_version(), 6);
    let backup = fixture._directory.path().join("before-signing.sqlite3");
    let output = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"))
        .args(["migrate", "--database"])
        .arg(&fixture.db)
        .arg("--backup")
        .arg(&backup)
        .output()
        .unwrap();
    assert_eq!(success(output)["status"], "migrated");
    assert_eq!(database_version(), 14);
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(backup.with_extension("manifest.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let saved = rusqlite::Connection::open(&backup).unwrap();
    assert_eq!(
        saved
            .query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
            .unwrap(),
        6
    );
    let receipt: Vec<u8> = saved
        .query_row(
            "SELECT receipt_bytes FROM authority_native_observations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&receipt).unwrap(),
        fixture.native_receipt
    );
    let native_after = success(run(&fixture.db, "read-native", &json!({"plan_id":PLAN})));
    assert_eq!(native_after["observation"], native_before["observation"]);
    assert_eq!(native_after["compilation"], native_before["compilation"]);
    assert_eq!(native_after["production_qualified"], false);
    assert_eq!(native_after["dispatch_allowed"], false);
    assert!(
        signing_resources(&fixture.db)
            .iter()
            .all(|(_, rows)| rows.is_empty())
    );
    refused(
        run(&fixture.db, "request-signing", &fixture.request),
        "SIGNING_REQUEST_REJECTED",
    );
    assert!(
        signing_resources(&fixture.db)
            .iter()
            .all(|(_, rows)| rows.is_empty())
    );
}
