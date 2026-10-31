//! Startup refusals identify a bounded stage without disclosing operator inputs.
#[allow(dead_code)]
#[path = "support/authenticator.rs"]
mod authenticator;
#[path = "../../fw_authority/tests/support/private_directory.rs"]
mod private_directory;
use authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_authority::{ApprovalRole, AuthorityStore, AuthorityTenant};
use fw_authority_service::Service;
use fw_webauthn::WebAuthn;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

struct Fixture {
    _directory: tempfile::TempDir,
    config: PathBuf,
    key: PathBuf,
    ui: PathBuf,
    value: Value,
}
fn write(path: &Path, bytes: &[u8]) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}
impl Fixture {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let root = directory.path();
        let database = root.join("private-database-marker.sqlite3");
        let mut store = AuthorityStore::open(&database).unwrap();
        let tenant = AuthorityTenant::new(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
        )
        .unwrap();
        let now = chrono::Utc::now().timestamp();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Private name marker", &[])
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
                "https://private-issuer-marker.test",
                "private-subject-marker",
                now,
            )
            .unwrap();
        store
            .pin_credential(&tenant, &credential, now, now + 7200, now)
            .unwrap();
        store
            .grant_role(
                &tenant,
                PRINCIPAL,
                ApprovalRole::Owner,
                now,
                now + 7200,
                now,
            )
            .unwrap();
        drop(store);
        let ui = root.join("private-ui-marker");
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&ui).unwrap();
        write(
            &ui.join("index.html"),
            b"<html><body>Authority fixture</body></html>",
        );
        let config = root.join("private-config-marker.json");
        let key_path = root.join("private-key-marker");
        write(&key_path, &[7; 32]);
        let value = json!({"origin":ORIGIN,"controller_origin":"http://localhost:8788","database":database,"ui_directory":ui,
            "profiles":{"owner":{"org_id":tenant.org_id(),"project_id":tenant.project_id(),"principal_id":PRINCIPAL,"credential_id":credential.id()}},"review_evidence":{}});
        write(&config, &serde_json::to_vec(&value).unwrap());
        Self {
            _directory: directory,
            config,
            key: key_path,
            ui,
            value,
        }
    }
    fn update(&self, value: &Value) {
        fs::write(&self.config, serde_json::to_vec(value).unwrap()).unwrap();
    }
    fn failure(&self) -> String {
        let error = Service::from_files(&self.config, &self.key)
            .err()
            .expect("fixture must be refused");
        let diagnostic = error.to_string();
        for secret in [
            "private-config-marker",
            "private-key-marker",
            "private-database-marker",
            "private-ui-marker",
            "private-subject-marker",
            PRINCIPAL,
        ] {
            assert!(!diagnostic.contains(secret));
        }
        assert!(diagnostic.len() < 160);
        assert_eq!(diagnostic.lines().count(), 1);
        diagnostic
    }
}
#[test]
fn startup_reports_config_key_origin_database_and_trust_without_raw_input() {
    for (stage, mutate) in [
        ("config", "config"),
        ("session_key", "session_key"),
        ("origin", "origin"),
        ("database", "database"),
        ("trust", "trust"),
    ] {
        let fixture = Fixture::new();
        match mutate {
            "config" => fs::write(&fixture.config, b"private-invalid-json-marker").unwrap(),
            "session_key" => fs::write(&fixture.key, b"private-invalid-key-marker").unwrap(),
            "origin" => {
                let mut value = fixture.value.clone();
                value["controller_origin"] = value["origin"].clone();
                fixture.update(&value);
            }
            "database" => {
                let mut value = fixture.value.clone();
                value["database"] = json!(fixture.ui.join("private-missing-db-marker"));
                fixture.update(&value);
            }
            "trust" => {
                let mut value = fixture.value.clone();
                value["profiles"]["owner"]["principal_id"] =
                    json!("99999999-9999-4999-8999-999999999999");
                fixture.update(&value);
            }
            _ => unreachable!(),
        }
        let diagnostic = fixture.failure();
        assert!(
            diagnostic.contains(&format!("stage={stage} ")),
            "{diagnostic}"
        );
    }
}
#[cfg(unix)]
#[test]
fn unsafe_ui_modes_are_refused_with_a_specific_bounded_stage() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    assert!(Service::from_files(&fixture.config, &fixture.key).is_ok());
    for mode in [0o646, 0o664, 0o777] {
        fs::set_permissions(
            fixture.ui.join("index.html"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert_eq!(
            fixture.failure(),
            "AUTHORITY_STARTUP stage=ui_assets code=AUTHORITY_UI_ASSETS_REJECTED"
        );
        assert_eq!(
            fs::metadata(fixture.ui.join("index.html"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            mode
        );
    }
}

#[test]
fn executable_argument_and_ui_diagnostics_are_safe() {
    let binary = env!("CARGO_BIN_EXE_fw_authority_service");
    let output = std::process::Command::new(binary)
        .arg("private-argument-marker")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "AUTHORITY_STARTUP stage=arguments code=AUTHORITY_ARGUMENTS_REJECTED\n"
    );
    let fixture = Fixture::new();
    let mut value = fixture.value.clone();
    value["ui_directory"] = json!(fixture.ui.join("private-missing-ui-marker"));
    fixture.update(&value);
    let output = std::process::Command::new(binary)
        .args([
            "--config",
            fixture.config.to_str().unwrap(),
            "--session-key-file",
            fixture.key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "AUTHORITY_STARTUP stage=ui_assets code=AUTHORITY_UI_ASSETS_REJECTED\n"
    );
}

#[test]
fn executable_bind_failure_has_a_closed_diagnostic() {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let fixture = Fixture::new();
    let mut value = fixture.value.clone();
    value["origin"] = json!(format!(
        "http://localhost:{}",
        listener.local_addr().unwrap().port()
    ));
    fixture.update(&value);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_fw_authority_service"))
        .args([
            "--config",
            fixture.config.to_str().unwrap(),
            "--session-key-file",
            fixture.key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "AUTHORITY_STARTUP stage=bind code=AUTHORITY_BIND_UNAVAILABLE\n"
    );
}

#[cfg(unix)]
#[test]
fn executable_non_utf8_arguments_do_not_panic_or_echo_bytes() {
    use std::os::unix::ffi::OsStringExt;
    let argument = std::ffi::OsString::from_vec(b"private-argument-marker-\xff".to_vec());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_fw_authority_service"))
        .arg(argument)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "AUTHORITY_STARTUP stage=arguments code=AUTHORITY_ARGUMENTS_REJECTED\n"
    );
}
