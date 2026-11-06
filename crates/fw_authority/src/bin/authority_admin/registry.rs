//! Protected local registry imports and genuine owner WebAuthn ceremonies.
//! Input objects stay on bounded stdin; diagnostics never contain their bytes.
use super::{Arguments, Result, request_with_limit, revision};
use fw_authority::{
    AccessEnvelope, ApprovalRole, AuthorityBootstrapManifest, AuthorityStore, AuthorityTenant,
    BootstrapApprovalOriginPin, BootstrapAuthorization, Delegation, MAX_AUTHORITY_REGISTRY_BYTES,
    RegistryTrustKey, WorkloadBinding,
};
use fw_webauthn::{AuthenticationResponse, Credential, WebAuthn};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub(super) const HELP: &str = "fw_authority_admin pin-registry-trust-key|revoke-registry-trust-key|pin-bootstrap-approval-origin|read-bootstrap-approval-origin|import-workload-binding|import-access-envelope|import-delegation|import-bootstrap-manifest|read-authority-registry|revoke-authority-registry-object --database PATH --org-id UUID --project-id UUID\nfw_authority_admin challenge-bootstrap|admit-bootstrap-proof|import-bootstrap-authorization --database PATH --org-id UUID --project-id UUID --approval-origin ORIGIN\n\nRegistry commands read one strict JSON object from stdin (128 KiB maximum). Pin requests are {\"pin\":RegistryTrustKey}; revocation requests use key_id or content_hash. Workload bindings and original envelope/delegation/manifest imports use their exact contract objects. Read with {\"object_kind\":\"workload_binding|envelope|delegation|bootstrap_manifest|bootstrap_authorization\",\"object_id\":\"ID\"}; envelope/delegation IDs are UUID:revision. Challenge input is {\"principal_id\":UUID,\"credential_id\":ID,\"manifest_id\":UUID}; proof admission replaces credential_id/manifest_id with challenge_id and assertion. Authorization import is {\"manifest_id\":UUID,\"authorization\":BootstrapAuthorization}. Pin an approval origin independently with {\"pin\":BootstrapApprovalOriginPin,\"expected_revision\":null|string-u64}; read it with {}. Initial revision is 1; rotations require the current revision. The verifier --approval-origin must match that pin and never creates it. A trust key must be pinned independently before a signed import. Envelope and delegation imports remain staged; supplied proof hashes never create owner consent. Only an activated authority credential with a current owner role can approve the immutable manifest. Authorization remains authorized_pending_target_confirmation. Status current applies only to signed workload identity; no registry operation enables policy signing or dispatch. These commands accept no private signing key. Keep proof/authorization files private (umask 077), pass their contents through stdin, and recover committed imports after output failure with read-authority-registry.";

pub(super) const PROVISION_HELP: &str = "fw_authority_admin provision-authority-principal|pin-authority-credential|grant-authority-role|bind-authority-human|revoke-authority-credential|revoke-authority-role --database PATH --org-id UUID --project-id UUID\nfw_authority_admin challenge-authority-credential|activate-authority-credential --database PATH --org-id UUID --project-id UUID --approval-origin ORIGIN\n\nProtected OOB authority provisioning uses strict stdin: principal {principal_id,issuer,subject}; credential pin {credential,not_before,not_after}; role grant {principal_id,role,not_before,not_after}; independent human identity {principal_id,human_id}. Credential challenge/revocation use {credential_id}; activation uses {activation_id,assertion}; role revocation uses {membership_id}. Credential pin imports an independently enrolled public credential and leaves it pending until an actual WebAuthn possession ceremony succeeds. Controller credentials and caller-supplied human labels are not independent enrollment. The operator must establish principal/human identity and protect database access through the trusted local/OOB procedure. Granting a role or activating a credential alone never approves a manifest or permits policy signing/dispatch.";

pub(super) fn handles(command: &str) -> bool {
    matches!(
        command,
        "pin-registry-trust-key"
            | "revoke-registry-trust-key"
            | "pin-bootstrap-approval-origin"
            | "read-bootstrap-approval-origin"
            | "import-workload-binding"
            | "import-access-envelope"
            | "import-delegation"
            | "import-bootstrap-manifest"
            | "read-authority-registry"
            | "revoke-authority-registry-object"
            | "challenge-bootstrap"
            | "admit-bootstrap-proof"
            | "import-bootstrap-authorization"
            | "provision-authority-principal"
            | "pin-authority-credential"
            | "grant-authority-role"
            | "bind-authority-human"
            | "challenge-authority-credential"
            | "activate-authority-credential"
            | "revoke-authority-credential"
            | "revoke-authority-role"
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPin {
    pin: RegistryTrustKey,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginPin {
    pin: BootstrapApprovalOriginPin,
    expected_revision: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRevocation {
    key_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectRevocation {
    content_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ObjectKind {
    WorkloadBinding,
    Envelope,
    Delegation,
    BootstrapManifest,
    BootstrapAuthorization,
}
impl ObjectKind {
    fn name(&self) -> &'static str {
        match self {
            Self::WorkloadBinding => "workload_binding",
            Self::Envelope => "envelope",
            Self::Delegation => "delegation",
            Self::BootstrapManifest => "bootstrap_manifest",
            Self::BootstrapAuthorization => "bootstrap_authorization",
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectRead {
    object_kind: ObjectKind,
    object_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapChallenge {
    principal_id: String,
    credential_id: String,
    manifest_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAdmission {
    principal_id: String,
    challenge_id: String,
    assertion: AuthenticationResponse,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapImport {
    manifest_id: String,
    authorization: BootstrapAuthorization,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalProvision {
    principal_id: String,
    issuer: String,
    subject: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialPin {
    credential: Credential,
    not_before: i64,
    not_after: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    credential_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialActivation {
    activation_id: String,
    assertion: AuthenticationResponse,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleGrant {
    principal_id: String,
    role: ApprovalRole,
    not_before: i64,
    not_after: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleRevocation {
    membership_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanBinding {
    principal_id: String,
    human_id: String,
}

fn input<T: DeserializeOwned>() -> Result<T> {
    request_with_limit(MAX_AUTHORITY_REGISTRY_BYTES).map_err(|_| "REGISTRY_INPUT_REJECTED")
}
fn output(value: impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| "OUTPUT_FAILED")
}
fn verifier(args: &Arguments) -> Result<WebAuthn> {
    WebAuthn::new(args.value("--approval-origin")).map_err(|_| "APPROVAL_ORIGIN_REJECTED")
}

pub(super) fn run(
    args: &Arguments,
    store: &mut AuthorityStore,
    tenant: &AuthorityTenant,
) -> Result<Value> {
    // Sample admission time only after the entire bounded request is consumed.
    match args.command.as_str() {
        "pin-bootstrap-approval-origin" => {
            let request: OriginPin = input()?;
            let expected = request
                .expected_revision
                .as_deref()
                .map(revision)
                .transpose()
                .map_err(|_| "REGISTRY_INPUT_REJECTED")?;
            output(
                store
                    .pin_bootstrap_approval_origin(
                        tenant,
                        &request.pin,
                        expected,
                        chrono::Utc::now().timestamp(),
                    )
                    .map_err(|_| "BOOTSTRAP_ORIGIN_PIN_REJECTED")?,
            )
        }
        "read-bootstrap-approval-origin" => {
            let _: Empty = input()?;
            let pin = store
                .read_bootstrap_approval_origin(tenant, chrono::Utc::now().timestamp())
                .map_err(|_| "BOOTSTRAP_ORIGIN_STATUS_REJECTED")?;
            Ok(
                json!({"schema_version":"fw.bootstrap-approval-origin-query/v1","pin":pin,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "provision-authority-principal" => {
            let request: PrincipalProvision = input()?;
            store
                .provision_principal(
                    tenant,
                    &request.principal_id,
                    &request.issuer,
                    &request.subject,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "AUTHORITY_PRINCIPAL_REJECTED")?;
            Ok(
                json!({"status":"principal_provisioned","principal_id":request.principal_id,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "pin-authority-credential" => {
            let request: CredentialPin = input()?;
            store
                .pin_credential(
                    tenant,
                    &request.credential,
                    request.not_before,
                    request.not_after,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "AUTHORITY_CREDENTIAL_REJECTED")?;
            Ok(
                json!({"status":"pending","credential_id":request.credential.id(),
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "challenge-authority-credential" => {
            let request: CredentialRequest = input()?;
            let verifier = verifier(args)?;
            let challenge = store
                .begin_credential_activation(
                    tenant,
                    &request.credential_id,
                    &verifier,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "AUTHORITY_ACTIVATION_REJECTED")?;
            Ok(
                json!({"activation_id":challenge.activation_id,"options":challenge.options,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "activate-authority-credential" => {
            let request: CredentialActivation = input()?;
            let verifier = verifier(args)?;
            store
                .finish_credential_activation(
                    tenant,
                    &request.activation_id,
                    &request.assertion,
                    &verifier,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "AUTHORITY_ACTIVATION_REJECTED")?;
            Ok(
                json!({"status":"active","activation_id":request.activation_id,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "grant-authority-role" => {
            let request: RoleGrant = input()?;
            let membership = store
                .grant_role(
                    tenant,
                    &request.principal_id,
                    request.role,
                    request.not_before,
                    request.not_after,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "AUTHORITY_ROLE_REJECTED")?;
            Ok(json!({"status":"role_granted","membership_id":membership,
                "signing_allowed":false,"dispatch_allowed":false}))
        }
        "bind-authority-human" => {
            let request: HumanBinding = input()?;
            store
                .bind_human_identity(
                    tenant,
                    &request.principal_id,
                    &request.human_id,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "AUTHORITY_HUMAN_BINDING_REJECTED")?;
            Ok(
                json!({"status":"human_identity_bound","principal_id":request.principal_id,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "revoke-authority-credential" => {
            let request: CredentialRequest = input()?;
            store
                .revoke_credential(
                    tenant,
                    &request.credential_id,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "AUTHORITY_CREDENTIAL_REJECTED")?;
            Ok(
                json!({"status":"revoked","credential_id":request.credential_id,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "revoke-authority-role" => {
            let request: RoleRevocation = input()?;
            store
                .revoke_role(
                    tenant,
                    &request.membership_id,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "AUTHORITY_ROLE_REJECTED")?;
            Ok(
                json!({"status":"revoked","membership_id":request.membership_id,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "pin-registry-trust-key" => {
            let request: KeyPin = input()?;
            store
                .pin_registry_trust_key(tenant, &request.pin, chrono::Utc::now().timestamp())
                .map_err(|_| "REGISTRY_KEY_PIN_REJECTED")?;
            Ok(
                json!({"schema_version":"fw.authority-registry-maintenance/v1","key_id":request.pin.key_id,
                "status":"pinned","signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "revoke-registry-trust-key" => {
            let request: KeyRevocation = input()?;
            store
                .revoke_registry_trust_key(tenant, &request.key_id, chrono::Utc::now().timestamp())
                .map_err(|_| "REGISTRY_KEY_REVOCATION_REJECTED")?;
            Ok(
                json!({"schema_version":"fw.authority-registry-maintenance/v1","key_id":request.key_id,
                "status":"revoked","signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "import-workload-binding" => {
            let request: WorkloadBinding = input()?;
            output(
                store
                    .admit_workload_binding(tenant, &request, chrono::Utc::now().timestamp())
                    .map_err(|_| "WORKLOAD_BINDING_REJECTED")?,
            )
        }
        "import-access-envelope" => {
            let request: AccessEnvelope = input()?;
            output(
                store
                    .stage_access_envelope(tenant, &request, chrono::Utc::now().timestamp())
                    .map_err(|_| "REGISTRY_ENVELOPE_REJECTED")?,
            )
        }
        "import-delegation" => {
            let request: Delegation = input()?;
            output(
                store
                    .stage_delegation(tenant, &request, chrono::Utc::now().timestamp())
                    .map_err(|_| "REGISTRY_DELEGATION_REJECTED")?,
            )
        }
        "import-bootstrap-manifest" => {
            let request: AuthorityBootstrapManifest = input()?;
            output(
                store
                    .stage_bootstrap_manifest(tenant, &request, chrono::Utc::now().timestamp())
                    .map_err(|_| "BOOTSTRAP_MANIFEST_REJECTED")?,
            )
        }
        "read-authority-registry" => {
            let request: ObjectRead = input()?;
            let object = store
                .read_registry_object(
                    tenant,
                    request.object_kind.name(),
                    &request.object_id,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "REGISTRY_STATUS_REJECTED")?;
            Ok(
                json!({"schema_version":"fw.authority-registry-query/v1","object":object,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "revoke-authority-registry-object" => {
            let request: ObjectRevocation = input()?;
            store
                .revoke_registry_object(
                    tenant,
                    &request.content_hash,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "REGISTRY_OBJECT_REVOCATION_REJECTED")?;
            Ok(
                json!({"schema_version":"fw.authority-registry-maintenance/v1","content_hash":request.content_hash,
                "status":"revoked","signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "challenge-bootstrap" => {
            let request: BootstrapChallenge = input()?;
            let verifier = verifier(args)?;
            let issued = store
                .issue_bootstrap_challenge(
                    tenant,
                    &request.principal_id,
                    &request.credential_id,
                    &request.manifest_id,
                    &verifier,
                    chrono::Utc::now().timestamp(),
                )
                .map_err(|_| "BOOTSTRAP_CHALLENGE_REJECTED")?;
            Ok(
                json!({"schema_version":"fw.authority-bootstrap-challenge/v1",
                "challenge":issued.challenge,"options":issued.options,
                "signing_allowed":false,"dispatch_allowed":false}),
            )
        }
        "admit-bootstrap-proof" => {
            let request: BootstrapAdmission = input()?;
            let verifier = verifier(args)?;
            output(
                store
                    .admit_bootstrap_proof(
                        tenant,
                        &request.principal_id,
                        &request.challenge_id,
                        &request.assertion,
                        &verifier,
                        chrono::Utc::now().timestamp(),
                    )
                    .map_err(|_| "BOOTSTRAP_PROOF_REJECTED")?,
            )
        }
        "import-bootstrap-authorization" => {
            let request: BootstrapImport = input()?;
            let verifier = verifier(args)?;
            output(
                store
                    .admit_bootstrap_authorization(
                        tenant,
                        &request.manifest_id,
                        &request.authorization,
                        &verifier,
                        chrono::Utc::now().timestamp(),
                    )
                    .map_err(|_| "BOOTSTRAP_AUTHORIZATION_REJECTED")?,
            )
        }
        _ => Err("ARGUMENTS_REJECTED"),
    }
}
