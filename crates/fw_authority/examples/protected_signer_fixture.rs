//! Disposable integration fixture. Never creates production trust or grants.
#[path = "../tests/support/approval_authenticator.rs"]
#[allow(dead_code)]
mod approval_authenticator;
#[path = "../tests/support/registry_fixture.rs"]
mod registry_fixture;
use approval_authenticator::{Authenticator, ORIGIN};
use ed25519_dalek::SigningKey;
use fw_authority::*;
use fw_backend_linux::{BootstrapCapabilitySnapshot, BootstrapManagementBaseline};
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use fw_webauthn::WebAuthn;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticOwnerCache {
    schema_version: String,
    principal_id: String,
    credential_id: String,
    next_counter: u32,
    authenticator: Value,
}

#[cfg(target_os = "linux")]
fn fixture_uid() -> u32 {
    // SAFETY: geteuid has no argument or memory preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn disposable_private_directory(directory: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    if !directory.is_absolute()
        || !directory.starts_with("/lab")
        || directory.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return false;
    }
    let Ok(meta) = fs::symlink_metadata(directory) else {
        return false;
    };
    if !meta.is_dir()
        || meta.uid() != fixture_uid()
        || meta.mode() & 0o077 != 0
        || fs::canonicalize(directory).ok().as_deref() != Some(directory)
    {
        return false;
    }
    let mounted = fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .is_some_and(|text| {
            text.lines().any(|line| {
                line.split_once(" - ").is_some_and(|(left, right)| {
                    left.split_whitespace().nth(4) == Some("/lab")
                        && right.split_whitespace().next() == Some("tmpfs")
                })
            })
        });
    mounted
        && fs::read("/lab/DISPOSABLE_TARGET_BOOTSTRAP_NAMESPACE")
            .is_ok_and(|bytes| bytes == b"fw-isolated-target-bootstrap-v1\n")
}

#[cfg(not(target_os = "linux"))]
fn disposable_private_directory(_directory: &Path) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn private_cache_read(directory: &Path) -> SyntheticOwnerCache {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    assert!(
        disposable_private_directory(directory),
        "disposable private cache required"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join("synthetic-owner.json"))
        .unwrap_or_else(|_| panic!("synthetic owner cache unavailable"));
    let metadata = file.metadata().unwrap();
    assert!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == fixture_uid()
            && metadata.mode() & 0o777 == 0o600
            && metadata.len() <= 16384,
        "synthetic owner cache rejected"
    );
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes).unwrap();
    fw_contracts::parse_strict_with_limit(&bytes, 16384)
        .unwrap_or_else(|_| panic!("synthetic owner cache rejected"))
}

#[cfg(not(target_os = "linux"))]
fn private_cache_read(_directory: &Path) -> SyntheticOwnerCache {
    panic!("disposable Linux cache required")
}

fn replace_private_cache(directory: &Path, cache: &SyntheticOwnerCache) {
    assert!(
        disposable_private_directory(directory),
        "disposable private cache required"
    );
    let temporary = directory.join(format!(".synthetic-owner-{}", uuid::Uuid::new_v4()));
    save(&temporary, &canonical_bytes(cache).unwrap());
    fs::rename(&temporary, directory.join("synthetic-owner.json")).unwrap();
    std::fs::File::open(directory).unwrap().sync_all().unwrap();
}
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetEvidence {
    baseline: BootstrapManagementBaseline,
    capability: BootstrapCapabilitySnapshot,
}
fn read_fixture<T: serde::de::DeserializeOwned>(path: &Path, maximum: usize) -> T {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap_or_else(|_| panic!("fixture input rejected"));
    let metadata = file.metadata().unwrap();
    assert!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "fixture input rejected"
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    fw_contracts::parse_strict_with_limit(&bytes, maximum)
        .unwrap_or_else(|_| panic!("fixture input rejected"))
}
fn target_evidence(path: &Path) -> TargetEvidence {
    let mut options = OpenOptions::new();
    options.read(true);
    let file = options.open(path).expect("target evidence unavailable");
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file() && metadata.len() <= MAX_TARGET_BOOTSTRAP_BYTES as u64);
    let mut bytes = Vec::new();
    file.take(MAX_TARGET_BOOTSTRAP_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    fw_contracts::parse_strict_with_limit(&bytes, MAX_TARGET_BOOTSTRAP_BYTES)
        .expect("target evidence rejected")
}
fn prepare_with_operator(
    directory: &Path,
    executable: &Path,
    now: i64,
    material: Option<&TargetEvidence>,
) -> Value {
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
    operator.run(
        "pin-bootstrap-approval-origin",
        &json!({"pin":{
        "schema_version":"fw.bootstrap-approval-origin-pin/v1",
        "org_id":tenant.org_id(),"project_id":tenant.project_id(),"revision":"1",
        "origin":ORIGIN,"rp_id":"localhost",
        "not_before":registry_fixture::at(now-60),"not_after":registry_fixture::at(now+3600)
    },"expected_revision":null}),
    );
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
    let (baseline_hash, capability_hash) = if let Some(material) = material {
        assert_eq!(material.baseline.org_id, envelope.org_id);
        assert_eq!(material.baseline.project_id, envelope.project_id);
        assert_eq!(material.baseline.target_id, envelope.target_id);
        (
            material.baseline.hash().expect("target baseline rejected"),
            material
                .capability
                .hash()
                .expect("target capability rejected"),
        )
    } else {
        (
            hash_bytes(b"staged synthetic baseline; target confirmation absent"),
            hash_bytes(b"synthetic unqualified capabilities"),
        )
    };
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
        management_baseline_hash: baseline_hash,
        envelope_hashes: vec![canonical_hash(&envelope).unwrap()],
        delegation_hashes: vec![canonical_hash(&delegation).unwrap()],
        capability_hash,
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
    if let Some(material) = material {
        save(
            &directory.join("baseline.json"),
            &canonical_bytes(&material.baseline).unwrap(),
        );
        save(
            &directory.join("capability.json"),
            &canonical_bytes(&material.capability).unwrap(),
        );
    }
    let retain_owner = material.is_some() && disposable_private_directory(directory);
    if retain_owner {
        save(
            &directory.join("synthetic-owner.json"),
            &canonical_bytes(&SyntheticOwnerCache {
                schema_version: "fw.disposable-bootstrap-owner/v1".into(),
                principal_id: registry_fixture::OWNER.into(),
                credential_id: credential.id(),
                next_counter: 3,
                authenticator: authenticator.private_test_cache(),
            })
            .unwrap(),
        );
        std::fs::File::open(directory).unwrap().sync_all().unwrap();
    }
    json!({"database_path":database,"seed_file":seed_file,"manifest_id":manifest.manifest_id,"key_id":bootstrap_pin.key_id,"org_id":tenant.org_id(),"project_id":tenant.project_id(),"target_id":manifest.target_id,"webauthn_origin":ORIGIN,"created_at":now,"operator_cli_used":true,"operator_commands_executed":operator.commands,"target_evidence_bound":material.is_some(),"synthetic_owner_cache_retained":retain_owner,"management_baseline_hash":manifest.management_baseline_hash,"capability_hash":manifest.capability_hash})
}

fn prepare_rotation(
    directory: &Path,
    executable: &Path,
    evidence: &TargetEvidence,
    previous_file: &Path,
    key_pin_file: &Path,
    now: i64,
) -> Value {
    let mut cache = private_cache_read(directory);
    assert!(
        cache.schema_version == "fw.disposable-bootstrap-owner/v1"
            && cache.principal_id == registry_fixture::OWNER
            && cache.next_counter >= 3
            && cache.next_counter < u32::MAX,
        "synthetic owner cache rejected"
    );
    assert!(
        cache.authenticator["principal_id"] == cache.principal_id
            && cache.authenticator["credential_id"] == cache.credential_id,
        "synthetic owner cache rejected"
    );
    let authenticator = Authenticator::from_private_test_cache(&cache.authenticator);
    let previous: SignedTargetBootstrapConfirmation =
        read_fixture(previous_file, MAX_TARGET_BOOTSTRAP_BYTES);
    let target_pin: TargetBootstrapKeyPin = read_fixture(key_pin_file, 8192);
    let baseline: BootstrapManagementBaseline =
        read_fixture(&directory.join("baseline.json"), MAX_TARGET_BOOTSTRAP_BYTES);
    let capability: BootstrapCapabilitySnapshot = read_fixture(
        &directory.join("capability.json"),
        MAX_TARGET_BOOTSTRAP_BYTES,
    );
    let historical =
        chrono::DateTime::parse_from_rfc3339(&previous.payload.observation_finished_at)
            .unwrap()
            .timestamp();
    let verified = verify_target_bootstrap_confirmation(
        &previous,
        &previous.payload.challenge,
        &target_pin,
        &baseline,
        &capability,
        historical,
    )
    .unwrap();
    assert_eq!(verified.highest_generation(), 0);
    let old = verified.accepted_epoch();
    let next = old.checked_add(1).expect("synthetic epoch exhausted");
    let tenant = AuthorityTenant::new(
        &previous.payload.challenge.org_id,
        &previous.payload.challenge.project_id,
    )
    .unwrap();
    let database = directory.join("authority.sqlite3");
    let mut operator = Operator {
        executable,
        database: &database,
        tenant: &tenant,
        commands: 0,
    };
    let status = operator.run(
        "read-target-bootstrap-status",
        &json!({"target_id":previous.payload.challenge.target_id}),
    );
    assert!(
        status["status"]["accepted_epoch"].as_str()
            == Some(previous.payload.accepted_epoch.as_str())
            && status["status"]["highest_generation"] == "0"
            && status["status"]["confirmation_hash"] == verified.hash(),
        "retained target predecessor mismatch"
    );
    let mut manifest: AuthorityBootstrapManifest = read_fixture(
        &directory.join("manifest.json"),
        MAX_AUTHORITY_REGISTRY_BYTES,
    );
    assert!(
        evidence.baseline.org_id == manifest.org_id
            && evidence.baseline.project_id == manifest.project_id
            && evidence.baseline.target_id == manifest.target_id,
        "target evidence scope rejected"
    );
    manifest.manifest_id = uuid::Uuid::new_v4().to_string();
    manifest.old_epoch = Some(old.to_string());
    manifest.new_epoch = next.to_string();
    manifest.created_at = registry_fixture::at(now);
    manifest.expires_at = registry_fixture::at(now + 90);
    manifest.management_baseline_hash = evidence.baseline.hash().unwrap();
    manifest.capability_hash = evidence.capability.hash().unwrap();
    manifest.reason = "Synthetic isolated target epoch rotation; fresh owner ceremony".into();
    assert_eq!(
        operator.run("import-bootstrap-manifest", &manifest)["state"],
        "staged"
    );
    let challenge=operator.run("challenge-bootstrap",&json!({"principal_id":cache.principal_id,"credential_id":cache.credential_id,"manifest_id":manifest.manifest_id}));
    let used_counter = cache.next_counter;
    let admission=operator.run("admit-bootstrap-proof",&json!({"principal_id":cache.principal_id,"challenge_id":challenge["challenge"]["challenge_id"],"assertion":authenticator.assertion(&challenge["options"],used_counter,5,ORIGIN)}));
    let proof: BootstrapApprovalProof = serde_json::from_value(admission["proof"].clone()).unwrap();
    let status_after = operator.run(
        "read-authority-registry",
        &json!({"object_kind":"bootstrap_manifest","object_id":manifest.manifest_id}),
    );
    assert!(
        status_after["object"]["state"] == "owner_approved"
            && status_after["signing_allowed"] == false
            && status_after["dispatch_allowed"] == false,
        "fresh owner ceremony rejected"
    );
    for (name, value) in [
        (
            "rotation-manifest.json",
            serde_json::to_value(&manifest).unwrap(),
        ),
        ("rotation-proof.json", serde_json::to_value(&proof).unwrap()),
        (
            "rotation-baseline.json",
            serde_json::to_value(&evidence.baseline).unwrap(),
        ),
        (
            "rotation-capability.json",
            serde_json::to_value(&evidence.capability).unwrap(),
        ),
    ] {
        save(&directory.join(name), &canonical_bytes(&value).unwrap());
    }
    cache.next_counter += 1;
    replace_private_cache(directory, &cache);
    json!({"database_path":database,"manifest_id":manifest.manifest_id,"old_epoch":old.to_string(),"new_epoch":next.to_string(),"created_at":manifest.created_at,"expires_at":manifest.expires_at,"previous_confirmation_hash":verified.hash(),"expected_target_revision":status["status"]["confirmation_revision"],"owner_assertion_counter":used_counter,"operator_cli_used":true,"operator_commands_executed":operator.commands,"signing_allowed":false,"dispatch_allowed":false,"management_baseline_hash":manifest.management_baseline_hash,"capability_hash":manifest.capability_hash})
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("prepare-rotation") {
        assert!(
            args.len() == 10
                && args[2] == "--admin"
                && args[4] == "--target-evidence"
                && args[6] == "--previous-confirmation"
                && args[8] == "--target-key-pin",
            "rotation fixture arguments rejected"
        );
        let now = chrono::Utc::now().timestamp();
        let evidence = target_evidence(Path::new(&args[5]));
        println!(
            "{}",
            prepare_rotation(
                Path::new(&args[1]),
                Path::new(&args[3]),
                &evidence,
                Path::new(&args[7]),
                Path::new(&args[9]),
                now
            )
        );
        return;
    }
    if matches!(
        args.first().map(String::as_str),
        Some("verify" | "verify-rotation")
    ) {
        assert!(args.len() == 3, "fixture verification arguments rejected");
        let directory = Path::new(&args[1]);
        let rotation = args[0] == "verify-rotation";
        let manifest: AuthorityBootstrapManifest = read_fixture(
            &directory.join(if rotation {
                "rotation-manifest.json"
            } else {
                "manifest.json"
            }),
            MAX_AUTHORITY_REGISTRY_BYTES,
        );
        let proof: BootstrapApprovalProof = read_fixture(
            &directory.join(if rotation {
                "rotation-proof.json"
            } else {
                "proof.json"
            }),
            MAX_AUTHORITY_REGISTRY_BYTES,
        );
        let pin: RegistryTrustKey = read_fixture(&directory.join("pin.json"), 8192);
        let authorization: BootstrapAuthorization =
            read_fixture(Path::new(&args[2]), MAX_AUTHORITY_REGISTRY_BYTES);
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
    if matches!(args.len(), 3 | 5) && args[1] == "--admin" {
        let material = if args.len() == 5 {
            assert_eq!(args[3], "--target-evidence");
            Some(target_evidence(Path::new(&args[4])))
        } else {
            None
        };
        println!(
            "{}",
            prepare_with_operator(directory, Path::new(&args[2]), now, material.as_ref())
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
