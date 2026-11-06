#![cfg(all(feature = "approval-proofs", target_os = "linux"))]
//! Real operator processes and real crypto with synthetic OOB identities.
//! These fixtures do not establish human presence or production qualification.
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/core_access_fixture.rs"]
mod core_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;

use approval_authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use fw_authority::*;
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use fw_webauthn::WebAuthn;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn id(n: u8) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn at(seconds: i64) -> String {
    core_fixture::at(seconds)
}
fn command(db: &Path, operation: &str, tenant: &AuthorityTenant, origin: &str) -> Command {
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
    if matches!(
        operation,
        "challenge-bootstrap"
            | "admit-bootstrap-proof"
            | "import-bootstrap-authorization"
            | "challenge-authority-credential"
            | "activate-authority-credential"
    ) {
        command.args(["--approval-origin", origin]);
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
    assert_eq!(value["signing_allowed"], false);
    assert_eq!(value["dispatch_allowed"], false);
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
fn sign<T: Serialize>(payload: &T, key: &SigningKey, pin: &RegistryTrustKey) -> DsseEnvelope {
    let bytes = canonical_bytes(payload).unwrap();
    DsseEnvelope {
        payload_type: pin.payload_type.clone(),
        payload: STANDARD.encode(&bytes),
        signatures: vec![DsseSignature {
            keyid: pin.key_id.clone(),
            sig: STANDARD.encode(key.sign(&pae(&pin.payload_type, &bytes)).to_bytes()),
        }],
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    db: PathBuf,
    tenant: AuthorityTenant,
    now: i64,
}
impl Fixture {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let db = directory.path().join("authority.sqlite3");
        let (_, provenance) = core_fixture::fixture();
        let tenant =
            AuthorityTenant::new(&provenance.envelope.org_id, &provenance.envelope.project_id)
                .unwrap();
        let output = execute(command(&db, "init", &tenant, ORIGIN), b"{}");
        assert!(output.status.success());
        let fixture = Self {
            _directory: directory,
            db,
            tenant,
            now: chrono::Utc::now().timestamp() - 1,
        };
        let initialized = fixture.run("init-project", &json!({}));
        assert!(initialized.status.success());
        fixture
    }
    fn run(&self, operation: &str, body: &impl Serialize) -> Output {
        self.run_at(operation, body, ORIGIN)
    }
    fn run_at(&self, operation: &str, body: &impl Serialize, origin: &str) -> Output {
        execute(
            command(&self.db, operation, &self.tenant, origin),
            &serde_json::to_vec(body).unwrap(),
        )
    }
    fn read(&self, kind: &str, identity: &str) -> Value {
        success(self.run(
            "read-authority-registry",
            &json!({"object_kind":kind,"object_id":identity}),
        ))["object"]
            .clone()
    }
    fn pin(&self, purpose: &str, seed: u8) -> (SigningKey, RegistryTrustKey) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let (_, provenance) = core_fixture::fixture_at(self.now);
        let pin = RegistryTrustKey {
            key_id: format!("oob-issuer-{seed}"),
            org_id: self.tenant.org_id().into(),
            project_id: self.tenant.project_id().into(),
            target_id: provenance.envelope.target_id,
            payload_type: purpose.into(),
            public_key: key.verifying_key().to_bytes(),
            not_before: self.now - 10,
            not_after: self.now + 3600,
            revoked: false,
        };
        (key, pin)
    }
    fn workload(&self, key: &SigningKey, pin: &RegistryTrustKey, epoch: u64) -> WorkloadBinding {
        let payload = WorkloadBindingPayload {
            schema_version: "f.workload-binding/v1".into(),
            binding_id: id(20 + epoch as u8),
            org_id: self.tenant.org_id().into(),
            project_id: self.tenant.project_id().into(),
            principal_id: PRINCIPAL.into(),
            issuer_key_id: pin.key_id.clone(),
            workload_id: "operator-workload".into(),
            target_id: pin.target_id.clone(),
            platform: "linux".into(),
            asset_ids: vec![id(11)],
            asset_revision_hashes: vec![hash_bytes(b"fixture asset revision")],
            addresses: vec![RegistryAssetAddress {
                family: "ipv4".into(),
                cidr: "192.0.2.1/32".into(),
                interface: None,
            }],
            isolation: WorkloadIsolation::Host {
                host_asset_id: id(11),
            },
            issued_at: at(self.now),
            not_before: at(self.now),
            expires_at: at(self.now + 1800),
            binding_epoch: epoch.to_string(),
            attestation_evidence: RegistryEvidenceRef {
                store_id: "fixture".into(),
                object_hash: hash_bytes(b"fixture attestation"),
                media_type: "application/json".into(),
                size_bytes: 64,
            },
            audience: "fw_controller".into(),
        };
        WorkloadBinding {
            dsse: sign(&payload, key, pin),
            payload,
        }
    }
    fn stage(&self) -> AuthorityBootstrapManifest {
        let (_, bootstrap_pin) = self.pin(BOOTSTRAP_AUTHORIZATION_TYPE, 82);
        success(self.run("pin-registry-trust-key", &json!({"pin":bootstrap_pin})));
        let (_, mut provenance) = core_fixture::fixture_at(self.now);
        provenance.delegation.allowed_tools.sort();
        let envelope = success(self.run("import-access-envelope", &provenance.envelope));
        let delegation = success(self.run("import-delegation", &provenance.delegation));
        assert_eq!(envelope["state"], "staged");
        assert_eq!(delegation["state"], "staged");
        let manifest = AuthorityBootstrapManifest {
            schema_version: "f.authority-bootstrap-manifest/v1".into(),
            manifest_id: id(40),
            org_id: self.tenant.org_id().into(),
            project_id: self.tenant.project_id().into(),
            target_id: provenance.envelope.target_id.clone(),
            old_epoch: None,
            new_epoch: "1".into(),
            created_at: at(self.now),
            expires_at: at(self.now + 1200),
            trust_root_hash: canonical_hash(&bootstrap_pin).unwrap(),
            management_baseline_hash: hash_bytes(b"fixture baseline"),
            envelope_hashes: vec![canonical_hash(&provenance.envelope).unwrap()],
            delegation_hashes: vec![canonical_hash(&provenance.delegation).unwrap()],
            capability_hash: hash_bytes(b"unqualified fixture capability"),
            reason: "OOB fixture authority bootstrap".into(),
        };
        assert_eq!(
            success(self.run("import-bootstrap-manifest", &manifest))["state"],
            "staged"
        );
        manifest
    }
    fn owner(&self, role: ApprovalRole, activate: bool) -> (Authenticator, String, String) {
        success(self.run(
            "provision-authority-principal",
            &json!({"principal_id":PRINCIPAL,
            "issuer":"https://fixture.identity.example","subject":"independently-enrolled-owner"}),
        ));
        let authenticator = Authenticator::new(PRINCIPAL);
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let registration = verifier
            .begin_registration(PRINCIPAL, "Fixture owner", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &authenticator.registration(&registration.options),
            )
            .unwrap();
        assert_eq!(
            success(self.run(
                "pin-authority-credential",
                &json!({"credential":credential,
            "not_before":self.now,"not_after":self.now+3600})
            ))["status"],
            "pending"
        );
        success(self.run(
            "bind-authority-human",
            &json!({"principal_id":PRINCIPAL,"human_id":PRINCIPAL}),
        ));
        let membership = success(self.run(
            "grant-authority-role",
            &json!({"principal_id":PRINCIPAL,"role":role,
            "not_before":self.now,"not_after":self.now+3600}),
        ))["membership_id"]
            .as_str()
            .unwrap()
            .to_owned();
        if activate {
            let challenge = success(self.run(
                "challenge-authority-credential",
                &json!({"credential_id":credential.id()}),
            ));
            let assertion = authenticator.assertion(&challenge["options"], 1, 5, ORIGIN);
            assert_eq!(
                success(self.run(
                    "activate-authority-credential",
                    &json!({"activation_id":challenge["activation_id"],
                "assertion":assertion})
                ))["status"],
                "active"
            );
        }
        (authenticator, credential.id(), membership)
    }
    fn challenge(&self, manifest: &AuthorityBootstrapManifest, credential: &str) -> Value {
        success(self.run(
            "challenge-bootstrap",
            &json!({"principal_id":PRINCIPAL,
            "credential_id":credential,"manifest_id":manifest.manifest_id}),
        ))
    }
    fn prove(
        &self,
        manifest: &AuthorityBootstrapManifest,
        authenticator: &Authenticator,
        credential: &str,
    ) -> Value {
        let challenge = self.challenge(manifest, credential);
        let assertion = authenticator.assertion(&challenge["options"], 2, 5, ORIGIN);
        let request = json!({"principal_id":PRINCIPAL,"challenge_id":challenge["challenge"]["challenge_id"],
            "assertion":assertion});
        let proof = success(self.run("admit-bootstrap-proof", &request));
        assert_eq!(proof["replayed"], false);
        let replay = success(self.run("admit-bootstrap-proof", &request));
        assert_eq!(replay["replayed"], true);
        assert_eq!(proof["proof_hash"], replay["proof_hash"]);
        proof
    }
}

#[test]
fn signed_workload_import_requires_independent_pin_and_tracks_original_current_history() {
    let fixture = Fixture::new();
    let (key, pin) = fixture.pin(WORKLOAD_BINDING_TYPE, 81);
    let first = fixture.workload(&key, &pin, 1);
    refused(
        fixture.run("import-workload-binding", &first),
        "WORKLOAD_BINDING_REJECTED",
    );
    success(fixture.run("pin-registry-trust-key", &json!({"pin":pin})));
    let admitted = success(fixture.run("import-workload-binding", &first));
    assert_eq!(admitted["state"], "current");
    assert_eq!(admitted["current"], true);
    assert_eq!(admitted["content_hash"], canonical_hash(&first).unwrap());
    let retry = success(fixture.run("import-workload-binding", &first));
    assert_eq!(retry["admitted_at"], admitted["admitted_at"]);
    let mut forged = first.clone();
    forged.dsse.signatures[0].sig = STANDARD.encode([0; 64]);
    refused(
        fixture.run("import-workload-binding", &forged),
        "WORKLOAD_BINDING_REJECTED",
    );
    let next = fixture.workload(&key, &pin, 2);
    success(fixture.run("import-workload-binding", &next));
    assert_eq!(
        fixture.read("workload_binding", &first.payload.binding_id)["state"],
        "historical"
    );
    assert_eq!(
        fixture.read("workload_binding", &next.payload.binding_id)["state"],
        "current"
    );
    success(fixture.run("revoke-registry-trust-key", &json!({"key_id":pin.key_id})));
    assert_eq!(
        fixture.read("workload_binding", &next.payload.binding_id)["current"],
        false
    );
}

#[test]
fn original_objects_are_immutable_staged_inputs_and_cannot_invent_owner_consent() {
    let fixture = Fixture::new();
    let manifest = fixture.stage();
    let (_, mut provenance) = core_fixture::fixture_at(fixture.now);
    provenance.envelope.max_lease_seconds -= 1;
    refused(
        fixture.run("import-access-envelope", &provenance.envelope),
        "REGISTRY_ENVELOPE_REJECTED",
    );
    let current = fixture.read("bootstrap_manifest", &manifest.manifest_id);
    assert_eq!(current["state"], "staged");
    assert_eq!(current["current"], false);
    refused(
        fixture.run(
            "admit-bootstrap-proof",
            &json!({"principal_id":PRINCIPAL,"challenge_id":id(41),
        "proof":{"subject_hash":manifest.hash().unwrap(),"approved":true}}),
        ),
        "REGISTRY_INPUT_REJECTED",
    );
    success(fixture.run(
        "revoke-authority-registry-object",
        &json!({"content_hash":manifest.hash().unwrap()}),
    ));
    assert_eq!(
        fixture.read("bootstrap_manifest", &manifest.manifest_id)["state"],
        "revoked"
    );
}

#[test]
fn signed_authorization_never_creates_missing_owner_consent() {
    let fixture = Fixture::new();
    let manifest = fixture.stage();
    let (key, pin) = fixture.pin(BOOTSTRAP_AUTHORIZATION_TYPE, 82);
    let payload = BootstrapAuthorizationPayload {
        schema_version: "f.bootstrap-authorization/v1".into(),
        manifest_hash: manifest.hash().unwrap(),
        approval_proof_hashes: vec![hash_bytes(
            b"caller-supplied proof hash is not owner consent",
        )],
        signer_key_id: pin.key_id.clone(),
        issued_at: at(chrono::Utc::now().timestamp()),
        not_after: at(fixture.now + 180),
    };
    let authorization = BootstrapAuthorization {
        schema_version: "f.bootstrap-authorization-envelope/v1".into(),
        dsse: sign(&payload, &key, &pin),
        payload,
    };
    refused(
        fixture.run(
            "import-bootstrap-authorization",
            &json!({"manifest_id":manifest.manifest_id,
        "authorization":authorization}),
        ),
        "BOOTSTRAP_AUTHORIZATION_REJECTED",
    );
    assert_eq!(
        fixture.read("bootstrap_manifest", &manifest.manifest_id)["state"],
        "staged"
    );
    assert!(
        fixture
            .read("bootstrap_authorization", &manifest.manifest_id)
            .is_null()
    );
}

#[test]
fn complete_operator_flow_rechecks_real_owner_proof_and_keeps_authorization_pending_target() {
    let fixture = Fixture::new();
    let manifest = fixture.stage();
    let (key, pin) = fixture.pin(BOOTSTRAP_AUTHORIZATION_TYPE, 82);
    success(fixture.run("pin-registry-trust-key", &json!({"pin":pin})));
    let (authenticator, credential, _) = fixture.owner(ApprovalRole::Owner, true);
    let proof = fixture.prove(&manifest, &authenticator, &credential);
    assert_eq!(
        fixture.read("bootstrap_manifest", &manifest.manifest_id)["state"],
        "owner_approved"
    );
    let payload = BootstrapAuthorizationPayload {
        schema_version: "f.bootstrap-authorization/v1".into(),
        manifest_hash: manifest.hash().unwrap(),
        approval_proof_hashes: vec![proof["proof_hash"].as_str().unwrap().into()],
        signer_key_id: pin.key_id.clone(),
        issued_at: at(chrono::Utc::now().timestamp()),
        not_after: at(fixture.now + 180),
    };
    let authorization = BootstrapAuthorization {
        schema_version: "f.bootstrap-authorization-envelope/v1".into(),
        dsse: sign(&payload, &key, &pin),
        payload,
    };
    let request = json!({"manifest_id":manifest.manifest_id,"authorization":authorization});
    refused(
        fixture.run_at(
            "import-bootstrap-authorization",
            &request,
            "http://localhost:9998",
        ),
        "BOOTSTRAP_AUTHORIZATION_REJECTED",
    );
    let admitted = success(fixture.run("import-bootstrap-authorization", &request));
    assert_eq!(admitted["state"], "authorized_pending_target_confirmation");
    assert_eq!(admitted["current"], false);
    assert_eq!(
        admitted["content_hash"],
        canonical_hash(&authorization).unwrap()
    );
    let read = fixture.read(
        "bootstrap_authorization",
        admitted["object_id"].as_str().unwrap(),
    );
    assert_eq!(read["state"], "authorized_pending_target_confirmation");
    let replay = success(fixture.run("import-bootstrap-authorization", &request));
    assert_eq!(replay["admitted_at"], admitted["admitted_at"]);
    let connection = rusqlite::Connection::open(&fixture.db).unwrap();
    for table in [
        "authority_signing_intents",
        "authority_signing_jobs",
        "authority_signing_reservations",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?)",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        if exists {
            assert_eq!(
                connection
                    .query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get(0))
                    .unwrap(),
                0
            );
        }
    }
}

#[test]
fn pending_nonowner_and_revoked_owner_cannot_issue_bootstrap_approval() {
    for (role, activate, revoke_role) in [
        (ApprovalRole::Owner, false, false),
        (ApprovalRole::NetworkReviewer, true, false),
        (ApprovalRole::Owner, true, true),
    ] {
        let fixture = Fixture::new();
        let manifest = fixture.stage();
        let (_, credential, membership) = fixture.owner(role, activate);
        if revoke_role {
            success(fixture.run(
                "revoke-authority-role",
                &json!({"membership_id":membership}),
            ));
        }
        refused(
            fixture.run(
                "challenge-bootstrap",
                &json!({"principal_id":PRINCIPAL,"credential_id":credential,
            "manifest_id":manifest.manifest_id}),
            ),
            "BOOTSTRAP_CHALLENGE_REJECTED",
        );
        assert_eq!(
            fixture.read("bootstrap_manifest", &manifest.manifest_id)["state"],
            "staged"
        );
    }
}

#[test]
fn origin_and_signature_substitution_cannot_admit_bootstrap_proof() {
    let fixture = Fixture::new();
    let manifest = fixture.stage();
    let (authenticator, credential, _) = fixture.owner(ApprovalRole::Owner, true);
    let challenge = fixture.challenge(&manifest, &credential);
    let wrong = authenticator.assertion(&challenge["options"], 2, 5, "http://localhost:9998");
    refused(
        fixture.run(
            "admit-bootstrap-proof",
            &json!({"principal_id":PRINCIPAL,
        "challenge_id":challenge["challenge"]["challenge_id"],"assertion":wrong}),
        ),
        "BOOTSTRAP_PROOF_REJECTED",
    );
    let mut forged = authenticator.assertion(&challenge["options"], 2, 5, ORIGIN);
    forged.response.signature = "private-proof-must-not-appear-in-diagnostics".into();
    refused(
        fixture.run(
            "admit-bootstrap-proof",
            &json!({"principal_id":PRINCIPAL,
        "challenge_id":challenge["challenge"]["challenge_id"],"assertion":forged}),
        ),
        "BOOTSTRAP_PROOF_REJECTED",
    );
    assert_eq!(
        fixture.read("bootstrap_manifest", &manifest.manifest_id)["state"],
        "staged"
    );
    success(fixture.run(
        "revoke-authority-credential",
        &json!({"credential_id":credential}),
    ));
    refused(
        fixture.run(
            "challenge-bootstrap",
            &json!({"principal_id":PRINCIPAL,
        "credential_id":credential,"manifest_id":manifest.manifest_id}),
        ),
        "BOOTSTRAP_CHALLENGE_REJECTED",
    );
}

#[test]
fn strict_bounded_stdin_rejects_duplicate_unknown_and_private_input_without_echoing_bytes() {
    let fixture = Fixture::new();
    for bytes in [
        b"{\"object_kind\":\"envelope\",\"object_kind\":\"delegation\",\"object_id\":\"x\"}"
            .as_slice(),
        b"{\"object_kind\":\"envelope\",\"object_id\":\"x\",\"private_key\":\"must-not-echo\"}",
        b"{\"object_kind\":\"unrecognized_authority\",\"object_id\":\"x\"}",
    ] {
        refused(
            execute(
                command(
                    &fixture.db,
                    "read-authority-registry",
                    &fixture.tenant,
                    ORIGIN,
                ),
                bytes,
            ),
            "REGISTRY_INPUT_REJECTED",
        );
    }
    let oversized =
        serde_json::to_vec(&json!({"key_id":"s".repeat(MAX_AUTHORITY_REGISTRY_BYTES)})).unwrap();
    refused(
        execute(
            command(
                &fixture.db,
                "revoke-registry-trust-key",
                &fixture.tenant,
                ORIGIN,
            ),
            &oversized,
        ),
        "REGISTRY_INPUT_REJECTED",
    );
    let mut inline = command(
        &fixture.db,
        "pin-registry-trust-key",
        &fixture.tenant,
        ORIGIN,
    );
    inline.args(["--private-key", "never-accept-inline-key-material"]);
    refused(execute(inline, b"{}"), "ARGUMENTS_REJECTED");
    let mut origin_in_stdin =
        json!({"principal_id":PRINCIPAL,"credential_id":"x","manifest_id":id(40)});
    origin_in_stdin["approval_origin"] = ORIGIN.into();
    refused(
        fixture.run("challenge-bootstrap", &origin_in_stdin),
        "REGISTRY_INPUT_REJECTED",
    );
}

#[test]
fn failed_stdout_preserves_exact_import_and_read_recovers_original_staged_status() {
    let fixture = Fixture::new();
    let (_, provenance) = core_fixture::fixture_at(fixture.now);
    let mut invocation = command(
        &fixture.db,
        "import-access-envelope",
        &fixture.tenant,
        ORIGIN,
    );
    invocation.stdout(
        fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap(),
    );
    refused(
        execute(invocation, &canonical_bytes(&provenance.envelope).unwrap()),
        "OUTPUT_FAILED",
    );
    let status = fixture.read(
        "envelope",
        &format!(
            "{}:{}",
            provenance.envelope.envelope_id, provenance.envelope.revision
        ),
    );
    assert_eq!(status["state"], "staged");
    assert_eq!(
        status["content_hash"],
        canonical_hash(&provenance.envelope).unwrap()
    );
    let replay = success(fixture.run("import-access-envelope", &provenance.envelope));
    assert_eq!(replay["admitted_at"], status["admitted_at"]);
}
