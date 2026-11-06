//! Trusted local target pins and authenticated isolated-target observations.
//! All public evidence arrives through bounded stdin; no command accepts a private key.
use super::{Arguments, Result, request_with_limit, revision};
use fw_authority::{
    AuthorityStore, AuthorityTenant, MAX_TARGET_BOOTSTRAP_BYTES, SignedTargetBootstrapConfirmation,
    TargetBootstrapKeyPin,
};
use fw_backend_linux::{BootstrapCapabilitySnapshot, BootstrapManagementBaseline};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub(super) const HELP: &str = "fw_authority_admin pin-target-bootstrap-key|revoke-target-bootstrap-key|challenge-target-bootstrap|import-target-bootstrap-confirmation|read-target-bootstrap-status --database PATH --org-id UUID --project-id UUID\n\nTarget bootstrap commands consume one strict JSON object on stdin (256 KiB maximum). Pin with {pin:TargetBootstrapKeyPin,expected_revision:null|string-u64}; revoke with {target_id,revision}. Challenge with {manifest_id,expected_target_revision:null|string-u64,baseline:BootstrapManagementBaseline,capability:BootstrapCapabilitySnapshot}; expected_target_revision is the accepted confirmation head, independently of key revision. The challenge returns the exact fw.target-bootstrap-bundle/v1 for the isolated executor. Import the exact SignedTargetBootstrapConfirmation envelope; read with {target_id}. Establish the public target key independently before import. A verified confirmation records accepted epoch history and current observation eligibility separately. Target confirmation alone never supplies build/native qualification, policy signing keys, workload attestation or production signing/dispatch. No caller-supplied success or qualification flag is accepted. Recover output loss by reading retained target status; an exact accepted receipt retry never creates a new head.";

pub(super) fn handles(command: &str) -> bool {
    matches!(
        command,
        "pin-target-bootstrap-key"
            | "revoke-target-bootstrap-key"
            | "challenge-target-bootstrap"
            | "import-target-bootstrap-confirmation"
            | "read-target-bootstrap-status"
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    pin: TargetBootstrapKeyPin,
    expected_revision: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    target_id: String,
    revision: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    manifest_id: String,
    expected_target_revision: Option<String>,
    baseline: BootstrapManagementBaseline,
    capability: BootstrapCapabilitySnapshot,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    target_id: String,
}
fn input<T: DeserializeOwned>() -> Result<T> {
    request_with_limit(MAX_TARGET_BOOTSTRAP_BYTES).map_err(|_| "TARGET_BOOTSTRAP_INPUT_REJECTED")
}
fn expected(value: Option<&str>) -> Result<Option<u64>> {
    value
        .map(revision)
        .transpose()
        .map_err(|_| "TARGET_BOOTSTRAP_INPUT_REJECTED")
}
fn output(value: impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| "OUTPUT_FAILED")
}
pub(super) fn run(
    args: &Arguments,
    store: &mut AuthorityStore,
    tenant: &AuthorityTenant,
) -> Result<Value> {
    match args.command.as_str() {
        "pin-target-bootstrap-key" => {
            let request: Pin = input()?;
            output(
                store
                    .pin_target_bootstrap_key(
                        tenant,
                        &request.pin,
                        expected(request.expected_revision.as_deref())?,
                        chrono::Utc::now().timestamp(),
                    )
                    .map_err(|_| "TARGET_BOOTSTRAP_KEY_REJECTED")?,
            )
        }
        "revoke-target-bootstrap-key" => {
            let request: Revocation = input()?;
            let number =
                revision(&request.revision).map_err(|_| "TARGET_BOOTSTRAP_INPUT_REJECTED")?;
            store
                .revoke_target_bootstrap_key(
                    tenant,
                    &request.target_id,
                    number,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "TARGET_BOOTSTRAP_KEY_REJECTED")?;
            Ok(
                json!({"schema_version":"fw.target-bootstrap-maintenance/v1",
                "target_id":request.target_id,"revision":request.revision,"state":"revoked",
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "challenge-target-bootstrap" => {
            let request: Challenge = input()?;
            output(
                store
                    .issue_target_bootstrap_challenge(
                        tenant,
                        &request.manifest_id,
                        expected(request.expected_target_revision.as_deref())?,
                        &request.baseline,
                        &request.capability,
                        chrono::Utc::now().timestamp(),
                    )
                    .map_err(|_| "TARGET_BOOTSTRAP_CHALLENGE_REJECTED")?,
            )
        }
        "import-target-bootstrap-confirmation" => {
            let request: SignedTargetBootstrapConfirmation = input()?;
            output(
                store
                    .admit_target_bootstrap_confirmation(
                        tenant,
                        &request,
                        chrono::Utc::now().timestamp(),
                    )
                    .map_err(|_| "TARGET_BOOTSTRAP_CONFIRMATION_REJECTED")?,
            )
        }
        "read-target-bootstrap-status" => {
            let request: Read = input()?;
            let status = store
                .read_target_bootstrap_status(
                    tenant,
                    &request.target_id,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "TARGET_BOOTSTRAP_STATUS_REJECTED")?;
            Ok(
                json!({"schema_version":"fw.target-bootstrap-query/v1","status":status,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        _ => Err("ARGUMENTS_REJECTED"),
    }
}
