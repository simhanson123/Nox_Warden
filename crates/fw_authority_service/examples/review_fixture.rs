//! Explicit isolated browser fixture. Never provision production trust with this
//! software key. Private outputs are temporary and must never be committed.
#[allow(dead_code)]
#[path = "../tests/support/authenticator.rs"]
mod authenticator;
#[path = "../tests/support/plans.rs"]
mod plans;
use authenticator::{Authenticator, PRINCIPAL};
use fw_authority::{ApprovalRole, AuthorityBasis, AuthorityStore, AuthorityTenant};
use fw_webauthn::WebAuthn;
use serde_json::json;
use std::{fs, path::Path};
fn write(path: &Path, data: &[u8]) {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("create new private fixture file");
    file.write_all(data).unwrap();
    file.sync_all().unwrap();
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "review_fixture <new-private-directory> <absolute-dist-authority-directory>"
    );
    let directory = Path::new(&args[1]);
    assert!(!directory.exists(), "fixture requires a new directory");
    fs::create_dir(directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let directory = directory.canonicalize().unwrap();
    let ui = Path::new(&args[2]).canonicalize().unwrap();
    let origin = "http://localhost:8790";
    let verifier = WebAuthn::new(origin).unwrap();
    let key = Authenticator::new(PRINCIPAL);
    let registration = verifier
        .begin_registration(PRINCIPAL, "Isolated review fixture", &[])
        .unwrap();
    let credential = verifier
        .finish_registration(
            &registration.state,
            &key.registration_at(&registration.options, origin),
        )
        .unwrap();
    let tenant = AuthorityTenant::new(plans::ORG, plans::PROJECT).unwrap();
    let now = chrono::Utc::now().timestamp();
    let db = directory.join("authority.sqlite3");
    let mut store = AuthorityStore::open(&db).unwrap();
    store
        .provision_principal(
            &tenant,
            PRINCIPAL,
            "https://fixture.example.test",
            "isolated-review-owner",
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
    // Trusted, explicit fixture authority configuration. These values are not
    // imported from any plan, controller identity, browser claim or role label.
    store
        .provision_authority_basis(
            &tenant,
            &AuthorityBasis {
                epoch: 1,
                role_policy_hash: fw_contracts::hash_bytes(b"independently configured role policy"),
                not_before: now,
                not_after: now + 7200,
            },
            now,
        )
        .unwrap();
    store
        .bind_human_identity(
            &tenant,
            PRINCIPAL,
            "aaaaaaaa-0000-4000-8000-000000000001",
            now,
        )
        .unwrap();
    let (plan, requirements, bundle) = plans::complete_plan(now);
    store
        .register_plan(&tenant, &plan, &requirements, now)
        .unwrap();
    let reject_id = "55555555-5555-4555-8555-555555555555";
    let missing_id = "66666666-6666-4666-8666-666666666666";
    let stale_id = "77777777-7777-4777-8777-777777777777";
    for id in [reject_id, missing_id, stale_id] {
        let mut sibling = plan.clone();
        sibling["plan_id"] = json!(id);
        if id == stale_id {
            sibling["authority_epoch"] = json!("2");
        }
        store
            .register_plan(&tenant, &sibling, &requirements, now)
            .unwrap();
    }
    let bundle_path = directory.join("review.json");
    write(&bundle_path, &serde_json::to_vec(&bundle).unwrap());
    write(
        &directory.join("virtual_authenticator.json"),
        &serde_json::to_vec(&key.cdp_credential()).unwrap(),
    );
    let config = json!({"origin":origin,"controller_origin":"http://localhost:8787","database":db,"ui_directory":ui,
        "profiles":{"owner":{"org_id":plans::ORG,"project_id":plans::PROJECT,"principal_id":PRINCIPAL,"credential_id":credential.id()}},
        "review_evidence":{plans::PLAN:bundle_path,reject_id:bundle_path,stale_id:bundle_path}});
    write(
        &directory.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    );
    let mut session_key = [0; 32];
    openssl::rand::rand_bytes(&mut session_key).unwrap();
    write(&directory.join("session.key"), &session_key);
    write(&directory.join("fixture.json"),&serde_json::to_vec(&json!({"profile":"owner","plan_id":plans::PLAN,"reject_plan_id":reject_id,"missing_evidence_plan_id":missing_id,"stale_plan_id":stale_id})).unwrap());
    println!(
        "Created isolated authority fixture. No network policy or production authority was changed."
    );
}
