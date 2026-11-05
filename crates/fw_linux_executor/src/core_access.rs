//! Additive, explicitly unqualified execution of original core access contracts.
//!
//! Structural provenance, fixture approval and quota ceilings are checked here.
//! They do not establish protected workload/delegation authority, human WebAuthn
//! approval, an independent signer or permission to dispatch a production host.
use crate::{ExecutionBundle, LabApproval, LabPlan, LabTrust, ProbeSpec};
use base64::{Engine, engine::general_purpose::STANDARD};
use fw_authority::{
    CORE_GRANT_TYPE, CoreAccessLeaseWindow, CoreAccessProvenance, GrantContext, SignedGrant,
    TrustKey, VerifiedCoreAccessLeaseWindow, VerifiedGrant, verify_grant, verify_recovery_grant,
};
use fw_backend_linux::{
    Installation, PortableArtifact, restrictive_recovery, validate_installation,
};
use fw_contracts::{canonical_hash, parse_strict_with_limit};
use fw_planner::{
    DEFAULT_MAX_CELLS, Gate, PolicyReviewEvidence, ensure_dispatchable, semantic_diff,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

pub const CORE_ACCESS_BUNDLE_SCHEMA: &str = "fw.isolated-core-access-execution-bundle/v1";
pub const CORE_ACCESS_RUNTIME_SCHEMA: &str = "fw.isolated-core-access-runtime-bundle/v1";

#[derive(Debug)]
pub struct CoreAccessBundleError;
impl fmt::Display for CoreAccessBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CORE_ACCESS_BUNDLE_REJECTED")
    }
}
impl std::error::Error for CoreAccessBundleError {}
type Result<T> = std::result::Result<T, CoreAccessBundleError>;
fn checked<T, E>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|_| CoreAccessBundleError)
}
fn diagnosed<T>(value: Result<T>, code: &'static str) -> Result<T> {
    value.inspect_err(|_| eprintln!("{code}"))
}
fn hash(value: &impl Serialize) -> Result<String> {
    checked(canonical_hash(value))
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or(CoreAccessBundleError)
}
fn time(value: &Value, key: &str) -> Result<i64> {
    let text = text(value, key)?;
    let parsed = checked(chrono::DateTime::parse_from_rfc3339(text))?;
    if parsed
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
        != text
    {
        return Err(CoreAccessBundleError);
    }
    Ok(parsed.timestamp())
}
fn counter(value: &str) -> Result<u64> {
    let n = checked(value.parse::<u64>())?;
    if n == 0 || n.to_string() != value {
        return Err(CoreAccessBundleError);
    }
    Ok(n)
}

/// The exact original objects survive conversion, journal replay and recovery.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAccessExecutionContext {
    pub plan: Value,
    pub review: PolicyReviewEvidence,
    pub provenance: CoreAccessProvenance,
    pub lease_window: CoreAccessLeaseWindow,
}
impl fmt::Debug for CoreAccessExecutionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreAccessExecutionContext")
            .field("plan_id", &self.plan["plan_id"])
            .finish_non_exhaustive()
    }
}

/// A real closed `f.plan/v1` with unmistakably synthetic lab approval/trust.
/// This schema is separate from the original lab plan and from production IPC.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAccessExecutionBundle {
    pub schema_version: String,
    pub operation_id: String,
    pub plan: Value,
    pub review: PolicyReviewEvidence,
    pub provenance: CoreAccessProvenance,
    pub lease_window: CoreAccessLeaseWindow,
    pub approval: LabApproval,
    pub probes: Vec<ProbeSpec>,
    pub grant: SignedGrant,
    pub previous: PortableArtifact,
    pub candidate: PortableArtifact,
    pub recovery: PortableArtifact,
    pub previous_installation: Installation,
}

impl CoreAccessExecutionBundle {
    /// Projection changes no signed object. The original plan/review/window are
    /// retained alongside the existing executor's runtime and recovery fields.
    pub fn into_execution_bundle(self) -> Result<ExecutionBundle> {
        if self.schema_version != CORE_ACCESS_BUNDLE_SCHEMA {
            return Err(CoreAccessBundleError);
        }
        let context = CoreAccessExecutionContext {
            plan: self.plan,
            review: self.review,
            provenance: self.provenance,
            lease_window: self.lease_window,
        };
        let plan = diagnosed(context.projection(self.probes), "CORE_BUNDLE_PROJECTION")?;
        let bundle = ExecutionBundle {
            schema_version: CORE_ACCESS_RUNTIME_SCHEMA.into(),
            operation_id: self.operation_id,
            plan,
            approval: self.approval,
            grant: self.grant,
            previous: self.previous,
            candidate: self.candidate,
            recovery: self.recovery,
            previous_installation: self.previous_installation,
            core_access: Some(context),
        };
        diagnosed(
            validate_core_access_material(&bundle),
            "CORE_BUNDLE_MATERIAL",
        )?;
        Ok(bundle)
    }
}

impl CoreAccessExecutionContext {
    fn verify(&self) -> Result<VerifiedCoreAccessLeaseWindow> {
        // These are the original Plan fields. No general-policy or native field
        // is silently added to its closed, signed wire representation.
        const KEYS: &[&str] = &[
            "schema_version",
            "plan_id",
            "request_id",
            "request_revision",
            "request_hash",
            "org_id",
            "project_id",
            "target_id",
            "principal_id",
            "workload_binding_id",
            "requested_policy_hashes",
            "desired_state_hash",
            "baseline_hash",
            "source_snapshot_hash",
            "guardrail_hash",
            "compiler_hash",
            "envelope_hash",
            "delegation_hash",
            "authority_epoch",
            "target_generation",
            "created_at",
            "valid_until",
            "gates",
            "normalization_version",
            "requested_policies",
            "target_capability_hash",
            "validator_hash",
            "artifact_hash",
            "validation_report_hash",
            "effect_summary",
            "probe_spec_hash",
            "approval_requirements_hash",
            "workload_binding_hash",
            "workload_binding_valid_until",
            "confirm_timeout_seconds",
            "rollback_authority",
            "change_kind",
            "request_patch_hash",
        ];
        let map = self.plan.as_object().ok_or(CoreAccessBundleError)?;
        if map.len() != KEYS.len()
            || KEYS.iter().any(|key| !map.contains_key(*key))
            || self.plan["schema_version"] != "f.plan/v1"
            || self.plan["change_kind"] != "add_access_lease"
            || self.plan["normalization_version"] != "f.normalize/nfc-v1"
            || self.plan["confirm_timeout_seconds"] != 60
        {
            return Err(CoreAccessBundleError);
        }
        for key in KEYS {
            if key.ends_with("_hash") {
                let raw = text(&self.plan, key)?;
                if !raw.strip_prefix("sha256:").is_some_and(|suffix| {
                    suffix.len() == 64
                        && suffix
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }) {
                    return Err(CoreAccessBundleError);
                }
            }
            if key.ends_with("_id") {
                let raw = text(&self.plan, key)?;
                if checked(uuid::Uuid::parse_str(raw))?.to_string() != raw {
                    return Err(CoreAccessBundleError);
                }
            }
        }
        counter(text(&self.plan, "authority_epoch")?)?;
        counter(text(&self.plan, "target_generation")?)?;
        for key in ["created_at", "valid_until", "workload_binding_valid_until"] {
            time(&self.plan, key)?;
        }
        let window = checked(
            self.lease_window
                .verify(&self.plan, &self.provenance, &self.review),
        )?;
        let gates: Vec<Gate> = checked(serde_json::from_value(self.plan["gates"].clone()))?;
        let diff = checked(semantic_diff(
            &self.review.before,
            &self.review.after,
            DEFAULT_MAX_CELLS,
        ))?;
        checked(ensure_dispatchable(&gates, &diff.relation, diff.complete))?;
        Ok(window)
    }
    fn projection(&self, probes: Vec<ProbeSpec>) -> Result<LabPlan> {
        let p = &self.plan;
        if p["probe_spec_hash"] != hash(&probes)? {
            return Err(CoreAccessBundleError);
        }
        Ok(LabPlan {
            schema_version: "fw.isolated-lab-plan/v1".into(),
            plan_id: text(p, "plan_id")?.into(),
            org_id: text(p, "org_id")?.into(),
            project_id: text(p, "project_id")?.into(),
            target_id: text(p, "target_id")?.into(),
            authority_epoch: text(p, "authority_epoch")?.into(),
            target_generation: text(p, "target_generation")?.into(),
            baseline_hash: text(p, "baseline_hash")?.into(),
            desired_state_hash: text(p, "desired_state_hash")?.into(),
            artifact_hash: text(p, "artifact_hash")?.into(),
            recovery_artifact_hash: text(&p["rollback_authority"], "artifact_hash")?.into(),
            recovery_scope_hash: text(&p["rollback_authority"], "scope_bound_hash")?.into(),
            valid_until_unix: time(p, "valid_until")?,
            probes,
        })
    }
}

/// Parse one bounded closed bundle; existing lab bytes keep their original shape.
pub fn parse_execution_bundle(bytes: &[u8]) -> Result<ExecutionBundle> {
    let value: Value = checked(parse_strict_with_limit(
        bytes,
        fw_contracts::MAX_INTERNAL_BYTES,
    ))?;
    if value["schema_version"] == CORE_ACCESS_BUNDLE_SCHEMA {
        checked(serde_json::from_value::<CoreAccessExecutionBundle>(value))?.into_execution_bundle()
    } else {
        // Even an explicit null would have been an unknown field in the old
        // closed input. The optional field exists only for retained runtime
        // material, never as an extension to the legacy external lab schema.
        if value.get("core_access").is_some() {
            return Err(CoreAccessBundleError);
        }
        let bundle: ExecutionBundle = checked(serde_json::from_value(value))?;
        if bundle.schema_version != "fw.isolated-execution-bundle/v1"
            || bundle.core_access.is_some()
        {
            return Err(CoreAccessBundleError);
        }
        Ok(bundle)
    }
}

fn validate_core_access_material(
    bundle: &ExecutionBundle,
) -> Result<VerifiedCoreAccessLeaseWindow> {
    let context = bundle.core_access.as_ref().ok_or(CoreAccessBundleError)?;
    let window = context.verify()?;
    if bundle.schema_version != CORE_ACCESS_RUNTIME_SCHEMA
        || hash(&context.projection(bundle.plan.probes.clone())?)? != hash(&bundle.plan)?
        || bundle.approval.schema_version != "fw.isolated-lab-approval/v1"
        || bundle.approval.kind != "synthetic_test_fixture"
        || bundle.approval.plan_hash != hash(&context.plan)?
        || context.plan["principal_id"] != bundle.approval.principal_id
        || bundle.plan.valid_until_unix > bundle.approval.valid_until_unix
        || bundle.plan.baseline_hash
            != context
                .review
                .before
                .state_hash()
                .map_err(|_| CoreAccessBundleError)?
        || bundle.plan.desired_state_hash
            != context
                .review
                .after
                .state_hash()
                .map_err(|_| CoreAccessBundleError)?
        || hash(&bundle.previous.state)? != hash(&context.review.before)?
        || hash(&bundle.candidate.state)? != hash(&context.review.after)?
        || bundle.plan.artifact_hash != checked(bundle.candidate.artifact_hash())?
        || bundle.plan.recovery_artifact_hash != checked(bundle.recovery.artifact_hash())?
        || bundle.plan.recovery_scope_hash != checked(bundle.recovery.scope_hash())?
        || hash(&checked(restrictive_recovery(
            &bundle.previous,
            &bundle.candidate,
        ))?)?
            != hash(&bundle.recovery)?
    {
        return Err(CoreAccessBundleError);
    }
    checked(validate_installation(
        &bundle.previous,
        &bundle.previous_installation,
    ))?;
    for artifact in [&bundle.previous, &bundle.candidate, &bundle.recovery] {
        checked(artifact.validate())?;
        if artifact.references != bundle.candidate.references
            || artifact.table != bundle.candidate.table
        {
            return Err(CoreAccessBundleError);
        }
    }
    Ok(window)
}

/// Independently verify exact core objects and crypto under explicitly lab-only
/// pinned trust. Neither this function nor its fixture approval opens the
/// production coordinator. Recovery uses its own signed historical window.
pub fn verify_core_access_execution(
    bundle: &ExecutionBundle,
    trust: &LabTrust,
    now: i64,
    recovery: bool,
) -> Result<VerifiedGrant> {
    let material = VerifiedCoreAccessMaterial::new(bundle)?;
    verify_current_core_access(&material, trust, now, recovery)
}

// This proof has no public constructor, clone, serialization or cross-call
// cache. Its borrow prevents the exact bundle from changing inside the call.
struct VerifiedCoreAccessMaterial<'a> {
    bundle: &'a ExecutionBundle,
    window: VerifiedCoreAccessLeaseWindow,
}
impl<'a> VerifiedCoreAccessMaterial<'a> {
    fn new(bundle: &'a ExecutionBundle) -> Result<Self> {
        let window = diagnosed(
            validate_core_access_material(bundle),
            "CORE_BUNDLE_MATERIAL",
        )?;
        Ok(Self { bundle, window })
    }
}

pub type CoreAccessCurrentVerifier<'a> = dyn Fn(&LabTrust, i64, bool) -> Result<VerifiedGrant> + 'a;

/// Validate immutable material once for one borrowed synchronous operation.
/// Each callback invocation still independently checks current pinned trust,
/// key purpose/revocation, DSSE signature and normal/recovery time. The private
/// proof and verifier cannot escape through the callback's independent return.
pub fn with_core_access_verifier<T, E>(
    bundle: &ExecutionBundle,
    operation: impl FnOnce(&CoreAccessCurrentVerifier<'_>) -> std::result::Result<T, E>,
) -> std::result::Result<T, E>
where
    E: From<CoreAccessBundleError>,
{
    let material = VerifiedCoreAccessMaterial::new(bundle).map_err(E::from)?;
    let verify = |trust: &LabTrust, now, recovery| {
        verify_current_core_access(&material, trust, now, recovery)
    };
    operation(&verify)
}

fn verify_current_core_access(
    material: &VerifiedCoreAccessMaterial<'_>,
    trust: &LabTrust,
    now: i64,
    recovery: bool,
) -> Result<VerifiedGrant> {
    let bundle = material.bundle;
    let window = &material.window;
    let context = bundle.core_access.as_ref().ok_or(CoreAccessBundleError)?;
    let p = &context.plan;
    let scope = &bundle.candidate.references.scope;
    let key = &trust.grant_key;
    let public_key: [u8; 32] = diagnosed(
        checked(STANDARD.decode(&key.public_key)),
        "CORE_BUNDLE_KEY_ENCODING",
    )?
    .try_into()
    .map_err(|_| CoreAccessBundleError)?;
    if trust.schema_version != "fw.isolated-lab-trust/v1"
        || trust.production_authorized
        || trust.org_id != scope.org_id
        || trust.project_id != scope.project_id
        || trust.target_id != scope.target_id
        || trust.network_namespace != scope.network_namespace
        || trust.boot_id != bundle.previous_installation.manifest.binding.boot_id
        || trust.grant_key.key_id == trust.confirm_key.key_id
        || trust.grant_key.public_key == trust.confirm_key.public_key
        || p["authority_epoch"] != trust.authority_epoch
    {
        eprintln!("CORE_BUNDLE_TRUST_SCOPE");
        return Err(CoreAccessBundleError);
    }
    if key.payload_type != CORE_GRANT_TYPE
        || key.revoked
        || now < key.not_before_unix
        || now >= key.not_after_unix
        || key.key_id.is_empty()
        || key.key_id.len() > 128
    {
        eprintln!("CORE_BUNDLE_KEY_WINDOW");
        return Err(CoreAccessBundleError);
    }
    if !recovery
        && (now < time(p, "created_at")?
            || now >= time(p, "valid_until")?
            || now < window.not_before())
    {
        eprintln!("CORE_BUNDLE_NORMAL_PLAN_WINDOW");
        return Err(CoreAccessBundleError);
    }
    let grant_context = GrantContext {
        org_id: trust.org_id.clone(),
        project_id: trust.project_id.clone(),
        target_id: trust.target_id.clone(),
        plan_hash: hash(p)?,
        artifact_hash: bundle.plan.artifact_hash.clone(),
        baseline_hash: bundle.plan.baseline_hash.clone(),
        desired_state_hash: bundle.plan.desired_state_hash.clone(),
        approval_set_hash: hash(&bundle.approval)?,
        authority_epoch: counter(&trust.authority_epoch)?,
        now_unix: now,
    };
    let trusted_key = TrustKey {
        key_id: key.key_id.clone(),
        org_id: trust.org_id.clone(),
        payload_type: CORE_GRANT_TYPE.into(),
        public_key,
        not_before: key.not_before_unix,
        not_after: key.not_after_unix,
        revoked: key.revoked,
    };
    let grant = checked(
        (if recovery {
            verify_recovery_grant(&bundle.grant, &trusted_key, &grant_context)
        } else {
            verify_grant(&bundle.grant, &trusted_key, &grant_context)
        })
        .inspect_err(|error| {
            eprintln!(
                "{}",
                match error {
                    fw_authority::AuthorityError::Time => "CORE_BUNDLE_GRANT_TIME",
                    fw_authority::AuthorityError::Signature => "CORE_BUNDLE_GRANT_SIGNATURE",
                    fw_authority::AuthorityError::Binding => "CORE_BUNDLE_GRANT_BINDING",
                    _ => "CORE_BUNDLE_GRANT_CONTRACT",
                }
            );
        }),
    )?;
    let payload = &bundle.grant.payload;
    for field in [
        "plan_id",
        "request_id",
        "principal_id",
        "workload_binding_id",
        "requested_policy_hashes",
        "authority_epoch",
        "target_generation",
        "envelope_hash",
        "delegation_hash",
        "artifact_hash",
        "baseline_hash",
        "confirm_timeout_seconds",
        "rollback_authority",
        "change_kind",
        "request_patch_hash",
        "desired_state_hash",
    ] {
        if payload[field] != p[field] {
            eprintln!("CORE_BUNDLE_GRANT_REFERENCE");
            return Err(CoreAccessBundleError);
        }
    }
    let quota = &payload["reservation"];
    let delegation = &context.provenance.delegation;
    for (field, maximum) in [
        ("projected_active_leases", delegation.max_active_leases),
        (
            "projected_new_leases_per_day",
            delegation.max_new_leases_per_day,
        ),
        (
            "projected_unique_destinations_per_day",
            delegation.max_unique_destinations_per_day,
        ),
        (
            "projected_cumulative_lease_seconds_per_day",
            delegation.max_cumulative_lease_seconds_per_day,
        ),
        (
            "projected_concurrent_deployments",
            delegation.max_concurrent_deployments,
        ),
    ] {
        if quota[field].as_u64().is_none_or(|n| n > maximum) {
            eprintln!("CORE_BUNDLE_QUOTA_CEILING");
            return Err(CoreAccessBundleError);
        }
    }
    if payload["lease_id"] != context.provenance.lease_id
        || quota["root_id"] != delegation.root_id
        || quota["projected_cumulative_lease_seconds_per_day"]
            .as_u64()
            .is_none_or(|n| n < context.provenance.request.lease_seconds)
        || quota["projected_unique_destinations_per_day"]
            .as_u64()
            .is_none_or(|n| n < context.provenance.request.destination_asset_ids.len() as u64)
        || grant.generation() != counter(&bundle.plan.target_generation)?
        || grant.not_after() > bundle.plan.valid_until_unix
        || grant.confirm_not_after() > bundle.plan.valid_until_unix
        || grant.confirm_not_after() > bundle.approval.valid_until_unix
        || grant.rollback_authority().profile != "preserve-current-restrictions"
    {
        eprintln!("CORE_BUNDLE_COST_OR_RECOVERY_BINDING");
        return Err(CoreAccessBundleError);
    }
    checked(uuid::Uuid::parse_str(&bundle.operation_id))?
        .to_string()
        .eq(&bundle.operation_id)
        .then_some(())
        .ok_or(CoreAccessBundleError)?;
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fw_contracts::canonical_bytes;
    use serde_json::json;

    // Shape-only codec input. No artifact validation, signature or native state
    // claim is made by parsing this legacy record.
    fn legacy_wire() -> Value {
        let id = "11111111-1111-4111-8111-111111111111";
        let hash = format!("sha256:{}", "1".repeat(64));
        let state = json!({"schema_version":"f.state-ir/v1","target_id":id,"platform":"linux","profile":"lab",
            "management_baseline_hash":hash,"policies":[],"associations":[],"tombstone_hashes":[],
            "source_snapshot_hash":hash,"target_capability_hash":hash,"normalization_version":"f.normalize/nfc-v1"});
        let references = json!({
            "scope":{"schema_version":"fw.isolated-lab-scope/v1","org_id":id,"project_id":id,"target_id":id,"network_namespace":"net:[123]","interfaces":["lo"],"conntrack_zone":0},
            "baseline":{"schema_version":"fw.isolated-lab-baseline/v1","scope_hash":hash,"management_paths":[],"default_action":"drop"},
            "source_snapshot":{"schema_version":"fw.isolated-lab-snapshot/v1","scope_hash":hash,"assets":[]},
            "capability":{"schema_version":"fw.isolated-lab-capability/v1","scope_hash":hash,"platform":"linux","profile":"host-tcp-udp-lab","production_qualified":false}});
        let artifact = json!({"schema_version":"fw.experimental-portable-nft/v1","compiler_version":"codec-fixture","binding_version":"fw.absolute-deadline-binding/v1",
            "production_qualified":false,"state":state,"references":references,"desired_state_hash":hash,"table":"fw_111111111111111111111111","nft_template":{},"tokens":[]});
        json!({"schema_version":"fw.isolated-execution-bundle/v1","operation_id":id,
            "plan":{"schema_version":"fw.isolated-lab-plan/v1","plan_id":id,"org_id":id,"project_id":id,"target_id":id,
                "authority_epoch":"1","target_generation":"1","baseline_hash":hash,"desired_state_hash":hash,"artifact_hash":hash,
                "recovery_artifact_hash":hash,"recovery_scope_hash":hash,"valid_until_unix":1800000100,"probes":[]},
            "approval":{"schema_version":"fw.isolated-lab-approval/v1","kind":"synthetic_test_fixture","plan_hash":hash,"principal_id":id,"valid_until_unix":1800000100},
            "grant":{"payload":{},"dsse":{"payloadType":CORE_GRANT_TYPE,"payload":"","signatures":[]}},
            "previous":artifact,"candidate":artifact,"recovery":artifact,
            "previous_installation":{"manifest":{"schema_version":"fw.experimental-installation/v1","portable_artifact_hash":hash,
                "desired_state_hash":hash,"native_artifact_hash":hash,"tokens":[],
                "binding":{"operation_id":id,"grant_hash":hash,"boot_id":id,"network_namespace":"net:[123]","wall_time_unix":1800000000,
                    "monotonic_millis":1000,"clock_uncertainty_seconds":0,"elapsed_seconds":0,"commit_budget_seconds":1}},
                "native":{"schema_version":"codec-fixture","compiler_version":"codec-fixture","profile":"lab","production_qualified":false,"table":"fw_111111111111111111111111","desired_state_hash":hash,"nft_json":{}}}})
    }

    #[test]
    fn additive_profile_preserves_legacy_canonical_bundle_bytes() {
        let original = canonical_bytes(&legacy_wire()).unwrap();
        let parsed = parse_execution_bundle(&original).unwrap();
        assert!(parsed.core_access.is_none());
        assert_eq!(canonical_bytes(&parsed).unwrap(), original);
    }

    #[test]
    fn legacy_external_bundle_cannot_gain_even_a_null_core_context() {
        let mut wire = legacy_wire();
        wire["core_access"] = Value::Null;
        assert!(parse_execution_bundle(&canonical_bytes(&wire).unwrap()).is_err());
        wire.as_object_mut().unwrap().remove("core_access");
        wire["schema_version"] = CORE_ACCESS_RUNTIME_SCHEMA.into();
        assert!(parse_execution_bundle(&canonical_bytes(&wire).unwrap()).is_err());
    }

    #[test]
    fn scoped_core_verifier_cannot_enter_operation_without_full_valid_material() {
        let bundle = parse_execution_bundle(&canonical_bytes(&legacy_wire()).unwrap()).unwrap();
        let mut entered = false;
        let result: Result<()> = with_core_access_verifier(&bundle, |_| {
            entered = true;
            Ok(())
        });
        assert!(result.is_err());
        assert!(!entered);
    }
}
