//! Disposable integration fixture. Never creates production trust or grants.
#[path = "../tests/support/approval_authenticator.rs"]
#[allow(dead_code)]
mod approval_authenticator;
#[path = "../tests/support/registry_fixture.rs"]
mod registry_fixture;
use approval_authenticator::{Authenticator, ORIGIN};
use ed25519_dalek::SigningKey;
use fw_authority::*;
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use fw_webauthn::WebAuthn;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
fn save(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

struct Operator<'a> {
    executable: &'a Path,
    database: &'a Path,
    tenant: &'a AuthorityTenant,
    commands: usize,
}
impl Operator<'_> {
    fn run(&mut self, operation: &str, input: &impl Serialize) -> Value {
        let mut command = Command::new(self.executable);
        command.args([operation, "--database"]).arg(self.database);
        if operation != "init" {
            command.args([
                "--org-id",
                self.tenant.org_id(),
                "--project-id",
                self.tenant.project_id(),
            ]);
        }
        if matches!(
            operation,
            "challenge-authority-credential"
                | "activate-authority-credential"
                | "challenge-bootstrap"
                | "admit-bootstrap-proof"
        ) {
            command.args(["--approval-origin", ORIGIN]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("operator process unavailable");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&canonical_bytes(input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        // Keep raw process output and every proof/key input out of diagnostics.
        assert!(
            output.status.success() && output.stderr.is_empty(),
            "operator command refused: {operation} exit={:?}",
            output.status.code()
        );
        self.commands += 1;
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn prepare_with_operator(directory: &Path, executable: &Path, now: i64) -> Value {
    let original: Value = serde_json::from_str(include_str!(
        "../../../docs/specs/F_기준자료/F_개발계약/F_계약_예제.json"
    ))
    .unwrap();
    let mut envelope: AccessEnvelope =
        serde_json::from_value(original["envelope"].clone()).unwrap();
    envelope.valid_from = registry_fixture::at(now - 60);
    envelope.valid_until = registry_fixture::at(now + 3600);
    let mut delegation: Delegation =
        serde_json::from_value(original["delegation"].clone()).unwrap();
    delegation.valid_from = envelope.valid_from.clone();
    delegation.valid_until = envelope.valid_until.clone();
    delegation.envelope_hash = canonical_hash(&envelope).unwrap();
    delegation.allowed_tools.sort();
    let tenant = AuthorityTenant::new(&envelope.org_id, &envelope.project_id).unwrap();
    let database = directory.join("authority.sqlite3");
    let mut operator = Operator {
        executable,
        database: &database,
        tenant: &tenant,
        commands: 0,
    };
    operator.run("init", &json!({}));
    operator.run("init-project", &json!({}));
    operator.run("provision-authority-principal",&json!({"principal_id":registry_fixture::OWNER,"issuer":"https://fixture.identity.example","subject":registry_fixture::OWNER}));
    let verifier = WebAuthn::new(ORIGIN).unwrap();
    let authenticator = Authenticator::new(registry_fixture::OWNER);
    let registration = verifier
        .begin_registration(registry_fixture::OWNER, "Synthetic owner", &[])
        .unwrap();
    let credential = verifier
        .finish_registration(
            &registration.state,
            &authenticator.registration(&registration.options),
        )
        .unwrap();
    assert_eq!(
        operator.run(
            "pin-authority-credential",
            &json!({"credential":credential,"not_before":now-60,"not_after":now+3600})
        )["status"],
        "pending"
    );
    let activation = operator.run(
        "challenge-authority-credential",
        &json!({"credential_id":credential.id()}),
    );
    assert_eq!(operator.run("activate-authority-credential",&json!({"activation_id":activation["activation_id"],"assertion":authenticator.assertion(&activation["options"],1,5,ORIGIN)}))["status"],"active");
    operator.run("grant-authority-role",&json!({"principal_id":registry_fixture::OWNER,"role":"owner","not_before":now-60,"not_after":now+3600}));
    operator.run(
        "bind-authority-human",
        &json!({"principal_id":registry_fixture::OWNER,"human_id":registry_fixture::OWNER}),
    );
    let issuer = SigningKey::from_bytes(&[41; 32]);
    let bootstrap = SigningKey::from_bytes(&[42; 32]);
    let pin = |key_id: &str, key: &SigningKey, payload_type: &str| RegistryTrustKey {
        key_id: key_id.into(),
        org_id: envelope.org_id.clone(),
        project_id: envelope.project_id.clone(),
        target_id: envelope.target_id.clone(),
        payload_type: payload_type.into(),
        public_key: key.verifying_key().to_bytes(),
        not_before: now - 60,
        not_after: now + 3600,
        revoked: false,
    };
    let issuer_pin = pin("fixture-workload-issuer", &issuer, WORKLOAD_BINDING_TYPE);
    let bootstrap_pin = pin(
        "fixture-bootstrap-signer",
        &bootstrap,
        BOOTSTRAP_AUTHORIZATION_TYPE,
    );
    operator.run("pin-registry-trust-key", &json!({"pin":issuer_pin}));
    operator.run("pin-registry-trust-key", &json!({"pin":bootstrap_pin}));
    let payload = WorkloadBindingPayload {
        schema_version: "f.workload-binding/v1".into(),
        binding_id: delegation.workload_binding_ids[0].clone(),
        org_id: envelope.org_id.clone(),
        project_id: envelope.project_id.clone(),
        principal_id: delegation.allowed_principal_ids[0].clone(),
        issuer_key_id: issuer_pin.key_id.clone(),
        workload_id: "synthetic-workload".into(),
        target_id: envelope.target_id.clone(),
        platform: "linux".into(),
        asset_ids: delegation.source_asset_ids.clone(),
        asset_revision_hashes: vec![hash_bytes(b"fixture immutable source asset")],
        addresses: vec![RegistryAssetAddress {
            family: "ipv4".into(),
            cidr: "10.20.1.0/24".into(),
            interface: None,
        }],
        isolation: WorkloadIsolation::Host {
            host_asset_id: delegation.source_asset_ids[0].clone(),
        },
        issued_at: registry_fixture::at(now - 1),
        not_before: registry_fixture::at(now - 1),
        expires_at: registry_fixture::at(now + 3600),
        binding_epoch: "1".into(),
        attestation_evidence: RegistryEvidenceRef {
            store_id: "fixture".into(),
            object_hash: hash_bytes(b"synthetic workload provenance, not attestation"),
            media_type: "application/json".into(),
            size_bytes: 51,
        },
        audience: "fw_controller".into(),
    };
    let workload = registry_fixture::sign_workload(payload, &issuer, &issuer_pin.key_id);
    assert_eq!(
        operator.run("import-workload-binding", &workload)["current"],
        true
    );
    assert_eq!(
        operator.run("import-access-envelope", &envelope)["state"],
        "staged"
    );
    assert_eq!(
        operator.run("import-delegation", &delegation)["state"],
        "staged"
    );
    let manifest = AuthorityBootstrapManifest {
        schema_version: "f.authority-bootstrap-manifest/v1".into(),
        manifest_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
        org_id: envelope.org_id.clone(),
        project_id: envelope.project_id.clone(),
        target_id: envelope.target_id.clone(),
        old_epoch: None,
        new_epoch: "1".into(),
        created_at: registry_fixture::at(now),
        expires_at: registry_fixture::at(now + 300),
        trust_root_hash: canonical_hash(&bootstrap_pin).unwrap(),
        management_baseline_hash: hash_bytes(
            b"staged synthetic baseline; target confirmation absent",
        ),
        envelope_hashes: vec![canonical_hash(&envelope).unwrap()],
        delegation_hashes: vec![canonical_hash(&delegation).unwrap()],
        capability_hash: hash_bytes(b"synthetic unqualified capabilities"),
        reason: "Synthetic isolated signer integration fixture".into(),
    };
    assert_eq!(
        operator.run("import-bootstrap-manifest", &manifest)["state"],
        "staged"
    );
    let challenge=operator.run("challenge-bootstrap",&json!({"principal_id":registry_fixture::OWNER,"credential_id":credential.id(),"manifest_id":manifest.manifest_id}));
    let admission=operator.run("admit-bootstrap-proof",&json!({"principal_id":registry_fixture::OWNER,"challenge_id":challenge["challenge"]["challenge_id"],"assertion":authenticator.assertion(&challenge["options"],2,5,ORIGIN)}));
    let proof: BootstrapApprovalProof = serde_json::from_value(admission["proof"].clone()).unwrap();
    let status = operator.run(
        "read-authority-registry",
        &json!({"object_kind":"bootstrap_manifest","object_id":manifest.manifest_id}),
    );
    assert_eq!(status["object"]["state"], "owner_approved");
    assert_eq!(status["signing_allowed"], false);
    assert_eq!(status["dispatch_allowed"], false);
    let seed_file = directory.join("bootstrap.seed");
    save(&seed_file, bootstrap.as_bytes());
    for (name, value) in [
        ("manifest.json", serde_json::to_value(&manifest).unwrap()),
        ("proof.json", serde_json::to_value(&proof).unwrap()),
        ("pin.json", serde_json::to_value(&bootstrap_pin).unwrap()),
    ] {
        save(&directory.join(name), &canonical_bytes(&value).unwrap());
    }
    json!({"database_path":database,"seed_file":seed_file,"manifest_id":manifest.manifest_id,"key_id":bootstrap_pin.key_id,"org_id":tenant.org_id(),"project_id":tenant.project_id(),"target_id":manifest.target_id,"webauthn_origin":ORIGIN,"created_at":now,"operator_cli_used":true,"operator_commands_executed":operator.commands})
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("verify") {
        let directory = Path::new(&args[1]);
        let manifest: AuthorityBootstrapManifest =
            serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap())
                .unwrap();
        let proof: BootstrapApprovalProof =
            serde_json::from_slice(&std::fs::read(directory.join("proof.json")).unwrap()).unwrap();
        let pin: RegistryTrustKey =
            serde_json::from_slice(&std::fs::read(directory.join("pin.json")).unwrap()).unwrap();
        let authorization: BootstrapAuthorization =
            serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
        let now = chrono::DateTime::parse_from_rfc3339(&authorization.payload.issued_at)
            .unwrap()
            .timestamp();
        let verified =
            verify_bootstrap_authorization(&authorization, &manifest, &[proof], &pin, now).unwrap();
        println!(
            "{}",
            json!({"verified":true,"authorization_hash":verified.hash(),"manifest_hash":verified.manifest_hash()})
        );
        return;
    }
    let directory = Path::new(&args[0]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if args.len() == 3 && args[1] == "--admin" {
        println!(
            "{}",
            prepare_with_operator(directory, Path::new(&args[2]), now)
        );
        return;
    }
    assert_eq!(args.len(), 1);
    let mut fixture = registry_fixture::Fixture::new(directory, now);
    let proof = fixture.approve(2);
    let seed_file = directory.join("bootstrap.seed");
    save(&seed_file, fixture.bootstrap_key.as_bytes());
    for (name, value) in [
        (
            "manifest.json",
            serde_json::to_value(&fixture.manifest).unwrap(),
        ),
        ("proof.json", serde_json::to_value(&proof.proof).unwrap()),
        (
            "pin.json",
            serde_json::to_value(&fixture.bootstrap_pin).unwrap(),
        ),
    ] {
        save(
            &directory.join(name),
            &fw_contracts::canonical_bytes(&value).unwrap(),
        );
    }
    println!(
        "{}",
        json!({"database_path":fixture.path,"seed_file":seed_file,"manifest_id":fixture.manifest.manifest_id,"key_id":fixture.bootstrap_pin.key_id,"org_id":fixture.tenant.org_id(),"project_id":fixture.tenant.project_id(),"target_id":fixture.manifest.target_id,"webauthn_origin":approval_authenticator::ORIGIN,"created_at":now,"operator_cli_used":false})
    );
}
