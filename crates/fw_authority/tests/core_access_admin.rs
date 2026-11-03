#![cfg(all(feature = "approval-proofs", target_os = "linux"))]
//! Real local processes retain original cost evidence without granting authority.
#[path = "support/authority_legacy.rs"]
#[allow(dead_code)]
mod authority_legacy;
#[path = "support/core_access_fixture.rs"]
mod core_access_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;

use fw_authority::{AuthorityStore, AuthorityTenant, CoreAccessProvenance};
use fw_contracts::{canonical_bytes, canonical_hash};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const REJECTED: &str = "CORE_ACCESS_PROVENANCE_REJECTED";
const OTHER: &str = "99999999-9999-4999-8999-999999999999";
const ANOTHER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn command(db: &Path, operation: &str, tenant: &AuthorityTenant) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"));
    command.args([operation, "--database"]).arg(db);
    if operation != "init" {
        command.args([
            "--org-id",
            tenant.org_id(),
            "--project-id",
            tenant.project_id(),
        ]);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn execute(mut command: Command, bytes: &[u8]) -> Output {
    let mut child = command.spawn().unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
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

fn stable_status(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("checked_at");
    value
}

type Rows = Vec<Vec<rusqlite::types::Value>>;

fn table_rows(db: &Path, table: &str) -> Rows {
    let connection = rusqlite::Connection::open(db).unwrap();
    let mut query = connection
        .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
        .unwrap();
    let columns = query.column_count();
    query
        .query_map([], |row| {
            (0..columns)
                .map(|i| row.get(i))
                .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn signing_rows(db: &Path) -> Vec<(String, Rows)> {
    let connection = rusqlite::Connection::open(db).unwrap();
    let mut query = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name GLOB 'authority_signing_*' ORDER BY name")
        .unwrap();
    let names = query
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!names.is_empty());
    names
        .into_iter()
        .map(|name| {
            let rows = table_rows(db, &name);
            (name, rows)
        })
        .collect()
}

fn database_rows(db: &Path) -> Vec<(String, Rows)> {
    let connection = rusqlite::Connection::open(db).unwrap();
    let mut query = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND lower(substr(name,1,7)) <> 'sqlite_' ORDER BY name")
        .unwrap();
    let names = query
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let rows = table_rows(db, &name);
            (name, rows)
        })
        .collect()
}

struct Fixture {
    directory: tempfile::TempDir,
    db: PathBuf,
    tenant: AuthorityTenant,
    plan: Value,
    provenance: CoreAccessProvenance,
    now: i64,
}

impl Fixture {
    fn new() -> Self {
        Self::at(chrono::Utc::now().timestamp() - 2)
    }

    fn at(now: i64) -> Self {
        let directory = private_directory::private_directory();
        let db = directory.path().join("authority.sqlite3");
        let (plan, provenance) = core_access_fixture::fixture_at(now);
        let tenant = AuthorityTenant::new(
            plan["org_id"].as_str().unwrap(),
            plan["project_id"].as_str().unwrap(),
        )
        .unwrap();
        success(execute(command(&db, "init", &tenant), b"{}"));
        let mut store = AuthorityStore::open(&db).unwrap();
        store
            .provision_target_metadata_project(&tenant, now)
            .unwrap();
        store
            .register_plan(&tenant, &plan, &core_access_fixture::requirements(), now)
            .unwrap();
        Self {
            directory,
            db,
            tenant,
            plan,
            provenance,
            now,
        }
    }

    fn request(&self) -> Value {
        json!({"plan_id":self.plan["plan_id"],"provenance":self.provenance})
    }

    fn run(&self, operation: &str, body: &Value) -> Output {
        execute(
            command(&self.db, operation, &self.tenant),
            &serde_json::to_vec(body).unwrap(),
        )
    }

    fn read(&self) -> Value {
        success(self.run(
            "read-core-access-provenance",
            &json!({"plan_id":self.plan["plan_id"]}),
        ))
    }

    fn audit(&self) -> fw_authority::AuthorityAuditVerification {
        AuthorityStore::open(&self.db)
            .unwrap()
            .verify_audit_chain(&self.tenant)
            .unwrap()
            .unwrap()
    }

    fn retained_rows(&self) -> Vec<Rows> {
        [
            "authority_projects",
            "authority_audit",
            "authority_audit_heads",
            "authority_core_access_requests",
            "authority_core_access_plan_bindings",
        ]
        .into_iter()
        .map(|table| table_rows(&self.db, table))
        .collect()
    }
}

#[test]
fn registration_read_and_exact_retry_retain_full_cost_without_audit_growth() {
    let fixture = Fixture::new();
    let before = fixture.audit();
    let signing_before = signing_rows(&fixture.db);
    assert!(fixture.read()["provenance"].is_null());
    let registered = success(fixture.run("register-core-access-provenance", &fixture.request()));
    assert_eq!(
        registered["schema_version"],
        "fw.core-access-provenance-status/v1"
    );
    assert_eq!(
        registered["plan_hash"],
        canonical_hash(&fixture.plan).unwrap()
    );
    assert_eq!(registered["request_id"], fixture.provenance.request_id);
    assert_eq!(registered["request_revision"], 1);
    assert_eq!(registered["request_hash"], fixture.plan["request_hash"]);
    assert_eq!(
        registered["provenance_hash"],
        canonical_hash(&fixture.provenance).unwrap()
    );
    assert_eq!(registered["root_id"], fixture.provenance.delegation.root_id);
    assert_eq!(registered["lease_id"], fixture.provenance.lease_id);
    assert_eq!(registered["lease_seconds"], 3600);
    assert_eq!(registered["current"], true);
    assert_eq!(registered["signing_allowed"], false);
    assert_eq!(registered["dispatch_allowed"], false);
    assert_eq!(
        registered["gates"],
        json!(["CORE_SIGNING_PROFILE_UNAVAILABLE"])
    );
    for omitted in [
        "request",
        "envelope",
        "delegation",
        "purpose",
        "workflow_id",
        "scope",
    ] {
        assert!(registered.get(omitted).is_none(), "raw field {omitted}");
    }
    let after = fixture.audit();
    assert_eq!(after.event_count, before.event_count + 1);
    let rows = fixture.retained_rows();
    let read = fixture.read();
    assert_eq!(read["schema_version"], "fw.core-access-provenance-query/v1");
    assert_eq!(
        stable_status(read["provenance"].clone()),
        stable_status(registered.clone())
    );
    assert_eq!(read["signing_allowed"], false);
    assert_eq!(read["dispatch_allowed"], false);
    let retry = success(fixture.run("register-core-access-provenance", &fixture.request()));
    assert_eq!(stable_status(retry), stable_status(registered));
    assert_eq!(fixture.audit(), after);
    assert_eq!(fixture.retained_rows(), rows);
    assert_eq!(signing_rows(&fixture.db), signing_before);
}

#[test]
fn wrong_tenant_hash_and_missing_plan_reject_without_disclosing_or_retaining_inputs() {
    let fixture = Fixture::new();
    let rows = fixture.retained_rows();
    for tenant in [
        AuthorityTenant::new(OTHER, fixture.tenant.project_id()).unwrap(),
        AuthorityTenant::new(fixture.tenant.org_id(), OTHER).unwrap(),
    ] {
        for (operation, body) in [
            ("register-core-access-provenance", fixture.request()),
            (
                "read-core-access-provenance",
                json!({"plan_id":fixture.plan["plan_id"]}),
            ),
        ] {
            refused(
                execute(
                    command(&fixture.db, operation, &tenant),
                    &serde_json::to_vec(&body).unwrap(),
                ),
                REJECTED,
            );
        }
    }
    for path in ["request", "envelope", "delegation"] {
        let mut body = fixture.request();
        match path {
            "request" => {
                body["provenance"][path]["purpose"] = json!("DO_NOT_PRINT_ALTERED_REQUEST")
            }
            "envelope" => {
                body["provenance"][path]["approval_hash"] =
                    json!(fw_contracts::hash_bytes(b"other envelope"))
            }
            _ => body["provenance"][path]["root_id"] = json!(OTHER),
        }
        refused(
            fixture.run("register-core-access-provenance", &body),
            REJECTED,
        );
    }
    let mut missing = fixture.request();
    missing["plan_id"] = json!(OTHER);
    refused(
        fixture.run("register-core-access-provenance", &missing),
        REJECTED,
    );
    refused(
        fixture.run("read-core-access-provenance", &json!({"plan_id":OTHER})),
        REJECTED,
    );
    assert_eq!(fixture.retained_rows(), rows);
}

#[test]
fn original_request_root_lease_and_idempotency_aliases_cannot_replace_retained_cost() {
    for alias in ["request", "root", "lease", "idempotency"] {
        let fixture = Fixture::new();
        success(fixture.run("register-core-access-provenance", &fixture.request()));
        let mut plan = fixture.plan.clone();
        let mut provenance = fixture.provenance.clone();
        plan["plan_id"] = json!(OTHER);
        match alias {
            "request" => provenance.lease_id = OTHER.into(),
            "root" => provenance.delegation.root_id = OTHER.into(),
            "lease" => {
                provenance.request_id = OTHER.into();
                provenance.request.idempotency_key = ANOTHER.into();
            }
            "idempotency" => {
                provenance.request_id = OTHER.into();
                provenance.lease_id = ANOTHER.into();
            }
            _ => unreachable!(),
        }
        plan["request_id"] = json!(provenance.request_id);
        core_access_fixture::rehash(&mut plan, &mut provenance);
        provenance.verify(&plan).unwrap();
        AuthorityStore::open(&fixture.db)
            .unwrap()
            .register_plan(
                &fixture.tenant,
                &plan,
                &core_access_fixture::requirements(),
                chrono::Utc::now().timestamp(),
            )
            .unwrap();
        let rows = fixture.retained_rows();
        refused(
            fixture.run(
                "register-core-access-provenance",
                &json!({"plan_id":OTHER,"provenance":provenance}),
            ),
            REJECTED,
        );
        assert_eq!(fixture.retained_rows(), rows, "alias {alias}");
        assert_eq!(
            fixture.read()["provenance"]["lease_id"],
            fixture.provenance.lease_id
        );
    }
}

#[test]
fn strict_closed_bounded_inputs_and_authority_overrides_have_fixed_diagnostics() {
    let fixture = Fixture::new();
    let rows = fixture.retained_rows();
    for field in [
        "private_key",
        "grant",
        "production_qualified",
        "approval_origin",
        "lease_seconds",
    ] {
        let mut input = fixture.request();
        input[field] = json!("DO_NOT_PRINT_PRIVATE_FIELD");
        refused(
            fixture.run("register-core-access-provenance", &input),
            REJECTED,
        );
    }
    for path in ["request", "envelope", "delegation"] {
        let mut input = fixture.request();
        input["provenance"][path]["unknown"] = json!("DO_NOT_PRINT_NESTED_FIELD");
        refused(
            fixture.run("register-core-access-provenance", &input),
            REJECTED,
        );
    }
    for revision in [json!(0), json!(2), json!("1"), json!(1.0)] {
        let mut input = fixture.request();
        input["provenance"]["request_revision"] = revision;
        refused(
            fixture.run("register-core-access-provenance", &input),
            REJECTED,
        );
    }
    for operation in [
        "register-core-access-provenance",
        "read-core-access-provenance",
    ] {
        let mut oversized =
            serde_json::to_vec(&if operation == "register-core-access-provenance" {
                fixture.request()
            } else {
                json!({"plan_id":fixture.plan["plan_id"]})
            })
            .unwrap();
        oversized.resize(128 * 1024 + 1, b' ');
        for bytes in [
            b"{\"plan_id\":\"DO_NOT_PRINT\",\"plan_id\":\"duplicate\"}".to_vec(),
            b"{\"plan_id\":\"DO_NOT_PRINT\",\"unknown\":true}".to_vec(),
            b"{\"plan_id\":".to_vec(),
            vec![0xff],
            oversized,
        ] {
            refused(
                execute(command(&fixture.db, operation, &fixture.tenant), &bytes),
                REJECTED,
            );
        }
        let mut forbidden = command(&fixture.db, operation, &fixture.tenant);
        forbidden.args(["--approval-origin", "DO_NOT_PRINT_ORIGIN"]);
        refused(execute(forbidden, b"{}"), "ARGUMENTS_REJECTED");
    }
    assert_eq!(fixture.retained_rows(), rows);
}

#[test]
fn complete_requests_at_the_stdin_limit_are_accepted_without_truncation() {
    let fixture = Fixture::new();
    let mut request = serde_json::to_vec(&fixture.request()).unwrap();
    request.resize(128 * 1024, b' ');
    let registered = success(execute(
        command(
            &fixture.db,
            "register-core-access-provenance",
            &fixture.tenant,
        ),
        &request,
    ));
    assert_eq!(registered["lease_seconds"], 3600);
    let rows = fixture.retained_rows();
    let mut read = serde_json::to_vec(&json!({"plan_id":fixture.plan["plan_id"]})).unwrap();
    read.resize(128 * 1024, b' ');
    let status = success(execute(
        command(&fixture.db, "read-core-access-provenance", &fixture.tenant),
        &read,
    ));
    assert_eq!(
        stable_status(status["provenance"].clone()),
        stable_status(registered)
    );
    assert_eq!(fixture.retained_rows(), rows);
}

#[test]
fn output_failures_preserve_import_and_exact_retry_adds_no_audit() {
    for destination in ["full", "read-only", "broken-pipe"] {
        let fixture = Fixture::new();
        let before = fixture.audit();
        let mut failed = command(
            &fixture.db,
            "register-core-access-provenance",
            &fixture.tenant,
        );
        match destination {
            "full" => {
                failed.stdout(
                    fs::OpenOptions::new()
                        .write(true)
                        .open("/dev/full")
                        .unwrap(),
                );
            }
            "read-only" => {
                failed.stdout(fs::File::open("/dev/null").unwrap());
            }
            "broken-pipe" => {
                let (reader, writer) = std::io::pipe().unwrap();
                drop(reader);
                failed.stdout(writer);
            }
            _ => unreachable!(),
        }
        refused(
            execute(failed, &serde_json::to_vec(&fixture.request()).unwrap()),
            "OUTPUT_FAILED",
        );
        let after = fixture.audit();
        assert_eq!(after.event_count, before.event_count + 1);
        let stored = fixture.read()["provenance"].clone();
        assert_eq!(stored["lease_seconds"], 3600);
        let retry = success(fixture.run("register-core-access-provenance", &fixture.request()));
        assert_eq!(stable_status(retry), stable_status(stored));
        assert_eq!(fixture.audit(), after);
    }
}

#[test]
fn writable_null_output_commits_and_read_output_failure_preserves_evidence() {
    let fixture = Fixture::new();
    let mut discard = command(
        &fixture.db,
        "register-core-access-provenance",
        &fixture.tenant,
    );
    discard.stdout(Stdio::null());
    let output = execute(discard, &serde_json::to_vec(&fixture.request()).unwrap());
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let rows = fixture.retained_rows();
    let mut failed = command(&fixture.db, "read-core-access-provenance", &fixture.tenant);
    failed.stdout(
        fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap(),
    );
    refused(
        execute(
            failed,
            &serde_json::to_vec(&json!({"plan_id":fixture.plan["plan_id"]})).unwrap(),
        ),
        "OUTPUT_FAILED",
    );
    assert_eq!(fixture.read()["provenance"]["lease_seconds"], 3600);
    assert_eq!(fixture.retained_rows(), rows);
}

#[test]
fn expired_plan_read_and_exact_retry_keep_historical_cost_without_restoring_authority() {
    let fixture = Fixture::at(chrono::Utc::now().timestamp() - 600);
    AuthorityStore::open(&fixture.db)
        .unwrap()
        .register_core_access_provenance(
            &fixture.tenant,
            fixture.plan["plan_id"].as_str().unwrap(),
            &fixture.provenance,
            fixture.now,
        )
        .unwrap();
    let rows = fixture.retained_rows();
    let read = fixture.read()["provenance"].clone();
    assert_eq!(read["current"], false);
    assert_eq!(read["lease_seconds"], 3600);
    assert_eq!(read["signing_allowed"], false);
    assert_eq!(read["dispatch_allowed"], false);
    assert!(
        read["gates"]
            .as_array()
            .unwrap()
            .contains(&json!("PLAN_EXPIRED"))
    );
    let retry = success(fixture.run("register-core-access-provenance", &fixture.request()));
    assert_eq!(stable_status(retry), stable_status(read));
    assert_eq!(fixture.retained_rows(), rows);
}

#[test]
fn actual_schema8_migration_preserves_plan_and_audit_without_invented_provenance() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let plans = table_rows(&fixture.db, "authority_plans");
    let audit = fixture.audit();
    let signing = signing_rows(&fixture.db);
    authority_legacy::restore_v8(&fixture.db);
    refused(
        fixture.run("register-core-access-provenance", &fixture.request()),
        "DATABASE_REJECTED",
    );
    let backup = fixture.directory.path().join("schema8.sqlite3");
    let output = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"))
        .args(["migrate", "--database"])
        .arg(&fixture.db)
        .arg("--backup")
        .arg(&backup)
        .output()
        .unwrap();
    assert_eq!(success(output)["status"], "migrated");
    for (path, version) in [(&fixture.db, 13), (&backup, 8)] {
        assert_eq!(
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            version
        );
    }
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(table_rows(&fixture.db, "authority_plans"), plans);
    assert_eq!(table_rows(&backup, "authority_plans"), plans);
    assert_eq!(fixture.audit(), audit);
    assert_eq!(signing_rows(&fixture.db), signing);
    assert!(fixture.read()["provenance"].is_null());
    success(fixture.run("register-core-access-provenance", &fixture.request()));
    assert_eq!(fixture.read()["provenance"]["lease_seconds"], 3600);
}

#[test]
fn actual_schema9_migration_preserves_original_provenance_bytes_and_exact_retries() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let registered = success(fixture.run("register-core-access-provenance", &fixture.request()));
    let audit = fixture.audit();
    let signing = signing_rows(&fixture.db);
    assert!(signing.iter().all(|(_, rows)| rows.is_empty()));
    authority_legacy::restore_v9(&fixture.db);
    let before = database_rows(&fixture.db);
    for name in [
        "authority_core_access_requests",
        "authority_core_access_plan_bindings",
    ] {
        assert_eq!(
            before
                .iter()
                .find(|(table, _)| table == name)
                .unwrap()
                .1
                .len(),
            1
        );
    }
    refused(
        fixture.run(
            "read-core-access-provenance",
            &json!({"plan_id":fixture.plan["plan_id"]}),
        ),
        "DATABASE_REJECTED",
    );
    let backup = fixture.directory.path().join("schema9.sqlite3");
    let output = Command::new(env!("CARGO_BIN_EXE_fw_authority_admin"))
        .args(["migrate", "--database"])
        .arg(&fixture.db)
        .arg("--backup")
        .arg(&backup)
        .output()
        .unwrap();
    assert_eq!(success(output)["status"], "migrated");
    for (path, version) in [(&fixture.db, 13), (&backup, 9)] {
        assert_eq!(
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            version
        );
    }
    let manifest_path = backup.with_extension("manifest.json");
    for path in [&backup, &manifest_path] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["database_schema"], 9);
    assert_eq!(
        manifest["database_hash"],
        fw_contracts::hash_bytes(&fs::read(&backup).unwrap())
    );
    assert_eq!(database_rows(&backup), before);
    let after = database_rows(&fixture.db);
    assert_eq!(after.len(), before.len() + 1);
    assert!(
        after
            .iter()
            .find(|(name, _)| name == "authority_signing_work_audits")
            .unwrap()
            .1
            .is_empty()
    );
    for (name, rows) in &before {
        let migrated = &after.iter().find(|(table, _)| table == name).unwrap().1;
        if name == "authority_schema_migrations" {
            assert!(migrated.starts_with(rows));
            assert_eq!(migrated.len(), 13);
        } else {
            assert_eq!(migrated, rows, "{name}");
        }
    }
    assert_eq!(
        stable_status(fixture.read()["provenance"].clone()),
        stable_status(registered.clone())
    );
    let retry = success(fixture.run("register-core-access-provenance", &fixture.request()));
    assert_eq!(stable_status(retry), stable_status(registered));
    assert_eq!(fixture.audit(), audit);
    assert_eq!(signing_rows(&fixture.db), signing);
    assert_eq!(database_rows(&fixture.db), after);
}
