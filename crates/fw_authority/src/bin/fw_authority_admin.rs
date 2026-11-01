//! Explicit local authority maintenance, never a controller or network endpoint.
//! Operating-system access to the protected authority database is the trust
//! boundary. Inputs are public pins/proofs; this program accepts no private key.
use fw_authority::{
    AuthorityStore, AuthorityTenant, NativeObserverPin, NativeReferencePin, TargetTransportPin,
};
use fw_backend_linux::Installation;
use fw_contracts::{canonical_bytes, parse_strict_with_limit};
use fw_native_evidence::{ArtifactRole, SignedNativeObservation};
use fw_planner::PolicyReviewEvidence;
use fw_target_evidence::SignedMetadataReport;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
};

const HELP: &str = "fw_authority_admin init --database PATH\nfw_authority_admin migrate --database PATH --backup PATH\nfw_authority_admin init-project|pin-target|challenge-target|admit-target|read-target|revoke-target --database PATH --org-id UUID --project-id UUID\nfw_authority_admin register-reviewed-plan|pin-native-references|revoke-native-references|pin-native-observer|revoke-native-observer|compile-native|challenge-native|admit-native|read-native --database PATH --org-id UUID --project-id UUID\n\nTarget and native commands read one closed JSON request from stdin. Pinning is an explicit trusted local operation; controller enrollment does not authorize it. Challenge output is public JSON for the device. Protect redirected files with umask 077. No command signs a policy or changes a firewall.";
const INPUT_LIMIT: usize = 128 * 1024;
const NATIVE_INPUT_LIMIT: usize = 4 * 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

struct Arguments {
    command: String,
    values: BTreeMap<String, String>,
}
impl Arguments {
    fn parse() -> Result<Self> {
        let args = std::env::args_os()
            .skip(1)
            .map(|arg| arg.into_string().map_err(|_| "ARGUMENTS_REJECTED"))
            .collect::<Result<Vec<_>>>()?;
        let command = args.first().ok_or("ARGUMENTS_REJECTED")?.clone();
        let options: &[&str] = match command.as_str() {
            "init" => &["--database"],
            "migrate" => &["--database", "--backup"],
            "init-project"
            | "pin-target"
            | "challenge-target"
            | "admit-target"
            | "read-target"
            | "revoke-target"
            | "register-reviewed-plan"
            | "pin-native-references"
            | "revoke-native-references"
            | "pin-native-observer"
            | "revoke-native-observer"
            | "compile-native"
            | "challenge-native"
            | "admit-native"
            | "read-native" => &["--database", "--org-id", "--project-id"],
            _ => return Err("ARGUMENTS_REJECTED"),
        };
        if args.len() != 1 + options.len() * 2 {
            return Err("ARGUMENTS_REJECTED");
        }
        let mut values = BTreeMap::new();
        for pair in args[1..].as_chunks::<2>().0 {
            if !options.contains(&pair[0].as_str())
                || pair[1].is_empty()
                || values.insert(pair[0].clone(), pair[1].clone()).is_some()
            {
                return Err("ARGUMENTS_REJECTED");
            }
        }
        Ok(Self { command, values })
    }
    fn value(&self, name: &str) -> &str {
        &self.values[name]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRequest {
    pin: TargetTransportPin,
    expected_revision: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetRequest {
    target_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    target_id: String,
    expected_revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedPlanRequest {
    plan: Value,
    requirements: Value,
    evidence: PolicyReviewEvidence,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeReferenceRequest {
    pin: NativeReferencePin,
    expected_revision: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeObserverRequest {
    pin: NativeObserverPin,
    expected_revision: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCompilationRequest {
    plan_id: String,
    expected_reference_revision: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeChallengeRequest {
    plan_id: String,
    artifact_role: ArtifactRole,
    installation: Installation,
    expected_head: Option<String>,
    authority_epoch: String,
    generation: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeReadRequest {
    plan_id: String,
}

fn revision(value: &str) -> Result<u64> {
    let n = counter(value)?;
    if n == 0 {
        return Err("INPUT_REJECTED");
    }
    Ok(n)
}

fn counter(value: &str) -> Result<u64> {
    let n = value.parse::<u64>().map_err(|_| "INPUT_REJECTED")?;
    if n.to_string() != value {
        return Err("INPUT_REJECTED");
    }
    Ok(n)
}

fn request<T: DeserializeOwned>() -> Result<T> {
    request_with_limit(INPUT_LIMIT)
}

fn request_with_limit<T: DeserializeOwned>(limit: usize) -> Result<T> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "INPUT_REJECTED")?;
    parse_strict_with_limit(&bytes, limit).map_err(|_| "INPUT_REJECTED")
}

fn run() -> Result<Value> {
    let args = Arguments::parse()?;
    let database = Path::new(args.value("--database"));
    if !cfg!(unix) {
        return Err("PLATFORM_UNSUPPORTED");
    }
    if args.command == "init" {
        let parent = database
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let metadata = fs::symlink_metadata(parent).map_err(|_| "DATABASE_REJECTED")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("DATABASE_REJECTED");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            if metadata.mode() & 0o022 != 0 {
                return Err("DATABASE_REJECTED");
            }
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(database)
                .map_err(|_| "DATABASE_REJECTED")?;
            file.sync_all().map_err(|_| "DATABASE_REJECTED")?;
        }
        #[cfg(not(unix))]
        {
            return Err("PLATFORM_UNSUPPORTED");
        }
        AuthorityStore::open(database).map_err(|_| "DATABASE_REJECTED")?;
        return Ok(json!({"status":"initialized","dispatch_allowed":false}));
    }
    if args.command == "migrate" {
        AuthorityStore::migrate(database, Path::new(args.value("--backup")))
            .map_err(|_| "MIGRATION_REJECTED")?;
        return Ok(json!({"status":"migrated","dispatch_allowed":false}));
    }
    // Refuse implicit initialization by any target operation.
    if !fs::symlink_metadata(database).is_ok_and(|m| m.is_file() && m.len() > 0) {
        return Err("DATABASE_REJECTED");
    }
    let tenant = AuthorityTenant::new(args.value("--org-id"), args.value("--project-id"))
        .map_err(|_| "TENANT_REJECTED")?;
    let mut store = AuthorityStore::open(database).map_err(|_| "DATABASE_REJECTED")?;
    match args.command.as_str() {
        "init-project" => {
            let _: Empty = request()?;
            store
                .provision_target_metadata_project(&tenant, chrono::Utc::now().timestamp())
                .map_err(|_| "PROJECT_REJECTED")?;
            Ok(json!({"status":"project_initialized","dispatch_allowed":false}))
        }
        "pin-target" => {
            let input: PinRequest = request()?;
            let revision = store
                .pin_target_transport(
                    &tenant,
                    &input.pin,
                    input
                        .expected_revision
                        .as_deref()
                        .map(revision)
                        .transpose()?,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "TARGET_PIN_REJECTED")?;
            Ok(
                json!({"target_id":input.pin.target_id,"key_revision":revision.to_string(),"enforcement":"unverified","dispatch_allowed":false}),
            )
        }
        "challenge-target" => {
            let input: TargetRequest = request()?;
            let challenge = store
                .issue_target_report_challenge(
                    &tenant,
                    &input.target_id,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "TARGET_CHALLENGE_REJECTED")?;
            serde_json::to_value(challenge).map_err(|_| "OUTPUT_FAILED")
        }
        "admit-target" => {
            let input: SignedMetadataReport = request()?;
            let result = store
                .admit_target_report(&tenant, &input, chrono::Utc::now().timestamp())
                .map_err(|_| "TARGET_REPORT_REJECTED")?;
            Ok(
                json!({"receipt":result.receipt,"replayed":result.replayed,"enforcement":"unverified","dispatch_allowed":false}),
            )
        }
        "read-target" => {
            let input: TargetRequest = request()?;
            let metadata = store
                .current_target_metadata(&tenant, &input.target_id, chrono::Utc::now().timestamp())
                .map_err(|_| "TARGET_METADATA_REJECTED")?;
            Ok(
                json!({"target_id":input.target_id,"receipt":metadata.map(|m|m.receipt),"enforcement":"unverified","dispatch_allowed":false}),
            )
        }
        "revoke-target" => {
            let input: RevokeRequest = request()?;
            store
                .revoke_target_transport(
                    &tenant,
                    &input.target_id,
                    revision(&input.expected_revision)?,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "TARGET_REVOCATION_REJECTED")?;
            Ok(json!({"target_id":input.target_id,"status":"revoked","dispatch_allowed":false}))
        }
        "register-reviewed-plan" => {
            let input: ReviewedPlanRequest = request_with_limit(NATIVE_INPUT_LIMIT)?;
            store
                .register_reviewed_plan(
                    &tenant,
                    &input.plan,
                    &input.requirements,
                    &input.evidence,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "PLAN_REVIEW_REJECTED")?;
            Ok(json!({"status":"registered","production_qualified":false,"dispatch_allowed":false}))
        }
        "pin-native-references" => {
            let input: NativeReferenceRequest = request_with_limit(NATIVE_INPUT_LIMIT)?;
            let revision = store
                .pin_native_references(
                    &tenant,
                    &input.pin,
                    input
                        .expected_revision
                        .as_deref()
                        .map(revision)
                        .transpose()?,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "NATIVE_REFERENCES_REJECTED")?;
            Ok(
                json!({"target_id":input.pin.target_id,"reference_revision":revision.to_string(),"production_qualified":false,"dispatch_allowed":false}),
            )
        }
        "pin-native-observer" => {
            let input: NativeObserverRequest = request()?;
            let revision = store
                .pin_native_observer(
                    &tenant,
                    &input.pin,
                    input
                        .expected_revision
                        .as_deref()
                        .map(revision)
                        .transpose()?,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "NATIVE_OBSERVER_REJECTED")?;
            Ok(
                json!({"target_id":input.pin.target_id,"observer_revision":revision.to_string(),"production_qualified":false,"dispatch_allowed":false}),
            )
        }
        "revoke-native-references" | "revoke-native-observer" => {
            let input: RevokeRequest = request()?;
            let expected = revision(&input.expected_revision)?;
            let now = chrono::Utc::now().timestamp();
            if args.command == "revoke-native-references" {
                store
                    .revoke_native_references(&tenant, &input.target_id, expected, now)
                    .map_err(|_| "NATIVE_REFERENCES_REVOCATION_REJECTED")?;
            } else {
                store
                    .revoke_native_observer(&tenant, &input.target_id, expected, now)
                    .map_err(|_| "NATIVE_OBSERVER_REVOCATION_REJECTED")?;
            }
            Ok(
                json!({"target_id":input.target_id,"status":"revoked","production_qualified":false,"dispatch_allowed":false}),
            )
        }
        "compile-native" => {
            let input: NativeCompilationRequest = request()?;
            let receipt = store
                .register_native_compilation(
                    &tenant,
                    &input.plan_id,
                    revision(&input.expected_reference_revision)?,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "NATIVE_COMPILATION_REJECTED")?;
            Ok(json!({"receipt":receipt,"production_qualified":false,"dispatch_allowed":false}))
        }
        "challenge-native" => {
            let input: NativeChallengeRequest = request_with_limit(NATIVE_INPUT_LIMIT)?;
            let challenge = store
                .challenge_native_observation(
                    &tenant,
                    &input.plan_id,
                    input.artifact_role,
                    &input.installation,
                    input.expected_head.as_deref(),
                    counter(&input.authority_epoch)?,
                    counter(&input.generation)?,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "NATIVE_CHALLENGE_REJECTED")?;
            serde_json::to_value(challenge).map_err(|_| "OUTPUT_FAILED")
        }
        "admit-native" => {
            let input: SignedNativeObservation = request_with_limit(NATIVE_INPUT_LIMIT)?;
            let admission = store
                .admit_native_observation(&tenant, &input, chrono::Utc::now().timestamp())
                .map_err(|_| "NATIVE_OBSERVATION_REJECTED")?;
            Ok(
                json!({"receipt":admission.receipt,"receipt_hash":admission.receipt_hash,"replayed":admission.replayed,"production_qualified":false,"dispatch_allowed":false}),
            )
        }
        "read-native" => {
            let input: NativeReadRequest = request()?;
            let status = store
                .native_evidence_status(&tenant, &input.plan_id, chrono::Utc::now().timestamp())
                .map_err(|_| "NATIVE_EVIDENCE_REJECTED")?;
            serde_json::to_value(status).map_err(|_| "OUTPUT_FAILED")
        }
        _ => Err("ARGUMENTS_REJECTED"),
    }
}

fn main() {
    if std::env::args_os().skip(1).collect::<Vec<_>>() == [std::ffi::OsString::from("--help")] {
        println!("{HELP}");
        return;
    }
    let outcome = run().and_then(|value| {
        let bytes = canonical_bytes(&value).map_err(|_| "OUTPUT_FAILED")?;
        std::io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(|_| "OUTPUT_FAILED")
    });
    if let Err(code) = outcome {
        eprintln!("AUTHORITY_ADMIN code={code}");
        std::process::exit(1);
    }
}
