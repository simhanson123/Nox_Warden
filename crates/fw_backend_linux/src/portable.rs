//! Immutable, hash-resolved artifacts for the explicitly isolated Linux lab.
//!
//! These are not production capability or bootstrap attestations. The caller
//! authenticates the artifact and scope through its independently trusted grant.
//! No OS command is executed here. Runtime timeout binding is kept outside the
//! signed artifact, and every binding/readback rebuilds its deterministic shape.
use crate::{
    compile_inner, invalid, verify_readback, Artifact, Comparison, CompileContext, CompileError,
    ReadbackVerification,
};
use fw_contracts::canonical_hash;
use fw_domain::{timestamp, validate_uuid, Action, Direction, Family, Policy, Protocol};
use fw_planner::StateIr;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

pub const PORTABLE_SCHEMA: &str = "fw.experimental-portable-nft/v1";
pub const BINDING_VERSION: &str = "fw.absolute-deadline-binding/v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LabScope {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    /// Exact Linux /proc/self/ns/net link, independently checked by the driver.
    pub network_namespace: String,
    pub interfaces: Vec<String>,
    pub conntrack_zone: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LabBaseline {
    pub schema_version: String,
    pub scope_hash: String,
    /// Must be empty: the isolated fixture has no network management channel.
    pub management_paths: Vec<String>,
    pub default_action: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LabAsset {
    pub asset_id: String,
    pub cidrs: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LabSourceSnapshot {
    pub schema_version: String,
    pub scope_hash: String,
    pub assets: Vec<LabAsset>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LabCapability {
    pub schema_version: String,
    pub scope_hash: String,
    pub platform: String,
    pub profile: String,
    pub production_qualified: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LabReferences {
    pub scope: LabScope,
    pub baseline: LabBaseline,
    pub source_snapshot: LabSourceSnapshot,
    pub capability: LabCapability,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortableToken {
    pub policy_id: String,
    pub policy_revision: u32,
    pub policy_hash: String,
    pub lease_id: String,
    pub token_name: String,
    pub protocol_number: u8,
    pub not_before_unix: i64,
    pub expires_at_unix: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableArtifact {
    pub schema_version: String,
    pub compiler_version: String,
    pub binding_version: String,
    pub production_qualified: bool,
    pub state: StateIr,
    pub references: LabReferences,
    pub desired_state_hash: String,
    pub table: String,
    pub nft_template: Value,
    pub tokens: Vec<PortableToken>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindingContext {
    pub operation_id: String,
    pub grant_hash: String,
    pub boot_id: String,
    pub network_namespace: String,
    /// Conservative trusted wall-clock sample taken with monotonic_millis.
    /// Round fractional UTC upward, or include its quantization in uncertainty.
    pub wall_time_unix: i64,
    pub monotonic_millis: u64,
    pub clock_uncertainty_seconds: u64,
    /// Monotonic elapsed time since the sampled wall clock.
    pub elapsed_seconds: u64,
    pub commit_budget_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundToken {
    pub token_name: String,
    pub policy_hash: String,
    pub absolute_expiry_unix: i64,
    pub cutoff_unix: i64,
    pub timeout_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationManifest {
    pub schema_version: String,
    pub portable_artifact_hash: String,
    pub desired_state_hash: String,
    pub native_artifact_hash: String,
    pub binding: BindingContext,
    pub tokens: Vec<BoundToken>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub manifest: InstallationManifest,
    pub native: Artifact,
}

/// Trusted runtime samples read by the native driver, never request body fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationContext {
    pub boot_id: String,
    pub network_namespace: String,
    pub wall_time_unix: i64,
    pub monotonic_millis: u64,
}

fn hash<T: Serialize>(value: &T) -> Result<String, CompileError> {
    canonical_hash(value).map_err(invalid)
}
fn hash_valid(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn namespace_valid(value: &str) -> bool {
    value
        .strip_prefix("net:[")
        .and_then(|s| s.strip_suffix(']'))
        .is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 20
                && s.bytes().all(|c| c.is_ascii_digit())
                && s.parse::<u64>().is_ok_and(|n| n > 0 && n.to_string() == s)
        })
}
fn canonical_loopback_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(ip) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix_number) = prefix.parse::<u32>() else {
        return false;
    };
    if ip.to_string() != address || prefix_number.to_string() != prefix {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => {
            if !(8..=32).contains(&prefix_number) || !ip.is_loopback() {
                return false;
            }
            let mask = u32::MAX.checked_shl(32 - prefix_number).unwrap_or(0);
            u32::from(ip) & !mask == 0
        }
        IpAddr::V6(ip) => ip.is_loopback() && prefix_number == 128,
    }
}
fn validate_references(state: &StateIr, refs: &LabReferences) -> Result<(), CompileError> {
    state.validate().map_err(invalid)?;
    let scope = &refs.scope;
    if state.platform != "linux" || state.profile != "lab" || !state.tombstone_hashes.is_empty() {
        return Err(CompileError::Unsupported(
            "portable lab profile or unresolved tombstones",
        ));
    }
    for id in [&scope.org_id, &scope.project_id, &scope.target_id] {
        validate_uuid(id).map_err(invalid)?;
    }
    if scope.schema_version != "fw.isolated-lab-scope/v1"
        || scope.target_id != state.target_id
        || !namespace_valid(&scope.network_namespace)
        || scope.interfaces != ["lo"]
        || scope.conntrack_zone != 0
    {
        return Err(invalid("isolated scope binding"));
    }
    let scope_hash = hash(scope)?;
    if refs.baseline.schema_version != "fw.isolated-lab-baseline/v1"
        || refs.baseline.scope_hash != scope_hash
        || !refs.baseline.management_paths.is_empty()
        || refs.baseline.default_action != "drop"
        || hash(&refs.baseline)? != state.management_baseline_hash
    {
        return Err(invalid("resolved isolated baseline"));
    }
    if refs.capability.schema_version != "fw.isolated-lab-capability/v1"
        || refs.capability.scope_hash != scope_hash
        || refs.capability.platform != "linux"
        || refs.capability.profile != "host-tcp-udp-lab"
        || refs.capability.production_qualified
        || hash(&refs.capability)? != state.target_capability_hash
    {
        return Err(invalid("resolved unqualified capability"));
    }
    if refs.source_snapshot.schema_version != "fw.isolated-lab-snapshot/v1"
        || refs.source_snapshot.scope_hash != scope_hash
        || refs.source_snapshot.assets.len() > 512
        || hash(&refs.source_snapshot)? != state.source_snapshot_hash
    {
        return Err(invalid("resolved source snapshot"));
    }
    let mut assets = BTreeMap::new();
    let mut last_id: Option<&str> = None;
    for asset in &refs.source_snapshot.assets {
        validate_uuid(&asset.asset_id).map_err(invalid)?;
        if last_id.is_some_and(|id| id >= asset.asset_id.as_str())
            || asset.cidrs.is_empty()
            || asset.cidrs.len() > 256
            || asset.cidrs.iter().any(|c| !canonical_loopback_cidr(c))
            || asset.cidrs.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(invalid("canonical isolated asset snapshot"));
        }
        last_id = Some(&asset.asset_id);
        assets.insert(&asset.asset_id, &asset.cidrs);
    }
    for policy in &state.policies {
        if policy.org_id != scope.org_id
            || policy.project_id != scope.project_id
            || policy.target_id != scope.target_id
        {
            return Err(invalid("state scope tenant"));
        }
        policy
            .scope
            .validate_interfaces(&scope.interfaces)
            .map_err(invalid)?;
        if policy.scope.direction == Direction::Forward {
            return Err(CompileError::Unsupported("routed scope"));
        }
        for (ids, cidrs) in [
            (&policy.scope.source_asset_ids, &policy.scope.source_cidrs),
            (
                &policy.scope.destination_asset_ids,
                &policy.scope.destination_cidrs,
            ),
        ] {
            let mut resolved = BTreeSet::new();
            for id in ids {
                let current = assets.get(id).ok_or_else(|| invalid("unresolved asset"))?;
                for cidr in *current {
                    let family_matches = match policy.scope.family {
                        Family::Ipv4 => !cidr.contains(':'),
                        Family::Ipv6 => cidr.contains(':'),
                    };
                    if family_matches {
                        resolved.insert(cidr.as_str());
                    }
                }
            }
            if resolved != cidrs.iter().map(String::as_str).collect() {
                return Err(invalid("asset CIDR snapshot mismatch"));
            }
        }
    }
    Ok(())
}

impl PortableArtifact {
    /// Canonical hash is useful only after validation and independent grant trust.
    pub fn artifact_hash(&self) -> Result<String, CompileError> {
        self.validate()?;
        hash(self)
    }
    pub fn scope_hash(&self) -> Result<String, CompileError> {
        self.validate()?;
        hash(&self.references.scope)
    }
    pub fn validate(&self) -> Result<(), CompileError> {
        let rebuilt = compile_portable(&self.state, &self.references)?;
        if hash(self)? != hash(&rebuilt)? {
            return Err(invalid("portable artifact was altered"));
        }
        Ok(())
    }
}

/// Resolve all supported references and produce deterministic absolute-time bytes.
pub fn compile_portable(
    state: &StateIr,
    refs: &LabReferences,
) -> Result<PortableArtifact, CompileError> {
    let state = state.normalized().map_err(invalid)?;
    validate_references(&state, refs)?;
    let context = CompileContext {
        org_id: refs.scope.org_id.clone(),
        project_id: refs.scope.project_id.clone(),
        target_id: refs.scope.target_id.clone(),
        now_unix: 0,
        clock_uncertainty_seconds: 0,
        elapsed_seconds: 0,
        commit_budget_seconds: 0,
    };
    let template = compile_inner(&state.policies, &context, true)?;
    let mut tokens = Vec::new();
    for policy in &state.policies {
        if policy.action != Action::Allow {
            continue;
        }
        let policy_hash = hash(policy)?;
        let association = state
            .associations
            .iter()
            .find(|a| a.policy_hash == policy_hash)
            .ok_or_else(|| invalid("token association"))?;
        tokens.push(PortableToken {
            policy_id: policy.policy_id.clone(),
            policy_revision: policy.policy_revision,
            policy_hash: policy_hash.clone(),
            lease_id: association
                .lease_id
                .clone()
                .ok_or_else(|| invalid("token lease"))?,
            token_name: format!("fw_live_{}", &policy_hash[7..31]),
            protocol_number: match policy.scope.transport.protocol() {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
                _ => return Err(CompileError::Unsupported("portable protocol")),
            },
            not_before_unix: timestamp(policy.lifetime.not_before()).map_err(invalid)?,
            expires_at_unix: timestamp(
                policy
                    .lifetime
                    .expires_at()
                    .ok_or_else(|| invalid("token expiry"))?,
            )
            .map_err(invalid)?,
        });
    }
    let artifact = PortableArtifact {
        schema_version: PORTABLE_SCHEMA.into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        binding_version: BINDING_VERSION.into(),
        production_qualified: false,
        desired_state_hash: state.state_hash().map_err(invalid)?,
        state,
        references: refs.clone(),
        table: template.table,
        nft_template: template.nft_json,
        tokens,
    };
    if serde_json::to_vec(&artifact).map_err(invalid)?.len() > 16 * 1024 * 1024 {
        return Err(CompileError::Budget);
    }
    Ok(artifact)
}

/// Produce a fresh installation only for a newly authorized submission. Replays
/// and restart observations must use their saved Installation, never call this
/// to reinstall tokens. A caller must independently fence its native write.
pub fn bind_at(
    artifact: &PortableArtifact,
    binding: &BindingContext,
) -> Result<Installation, CompileError> {
    artifact.validate()?;
    validate_uuid(&binding.operation_id).map_err(invalid)?;
    validate_uuid(&binding.boot_id).map_err(invalid)?;
    if !hash_valid(&binding.grant_hash)
        || binding.network_namespace != artifact.references.scope.network_namespace
        || binding.wall_time_unix < 0
        || binding.clock_uncertainty_seconds > 2
        || binding.elapsed_seconds > 300
        || binding.commit_budget_seconds > 10
    {
        return Err(CompileError::Clock);
    }
    let context = CompileContext {
        org_id: artifact.references.scope.org_id.clone(),
        project_id: artifact.references.scope.project_id.clone(),
        target_id: artifact.references.scope.target_id.clone(),
        now_unix: binding.wall_time_unix,
        clock_uncertainty_seconds: binding.clock_uncertainty_seconds,
        elapsed_seconds: binding.elapsed_seconds,
        commit_budget_seconds: binding.commit_budget_seconds,
    };
    let mut native = compile_inner(&artifact.state.policies, &context, false)?;
    native.desired_state_hash = artifact.desired_state_hash.clone();
    let budget = binding
        .clock_uncertainty_seconds
        .checked_add(binding.elapsed_seconds)
        .and_then(|n| n.checked_add(binding.commit_budget_seconds))
        .ok_or(CompileError::Clock)?;
    let upper = binding
        .wall_time_unix
        .checked_add(i64::try_from(budget).map_err(|_| CompileError::Clock)?)
        .ok_or(CompileError::Clock)?;
    let tokens = artifact
        .tokens
        .iter()
        .filter(|t| t.expires_at_unix > upper)
        .map(|t| BoundToken {
            token_name: t.token_name.clone(),
            policy_hash: t.policy_hash.clone(),
            absolute_expiry_unix: t.expires_at_unix,
            cutoff_unix: t.expires_at_unix - binding.clock_uncertainty_seconds as i64,
            timeout_seconds: (t.expires_at_unix - upper) as u64,
        })
        .collect();
    let manifest = InstallationManifest {
        schema_version: "fw.experimental-installation/v1".into(),
        portable_artifact_hash: hash(artifact)?,
        desired_state_hash: artifact.desired_state_hash.clone(),
        native_artifact_hash: hash(&native)?,
        binding: binding.clone(),
        tokens,
    };
    Ok(Installation { manifest, native })
}

/// Validate persisted installation bytes without inventing a new observation or
/// refreshing timeouts. Uses the original binding only to verify deterministic
/// correspondence. The caller additionally checks actual boot/monotonic context.
pub fn validate_installation(
    artifact: &PortableArtifact,
    installation: &Installation,
) -> Result<(), CompileError> {
    let rebuilt = bind_at(artifact, &installation.manifest.binding)?;
    if hash(installation)? != hash(&rebuilt)? {
        return Err(invalid("installation was altered"));
    }
    Ok(())
}

pub fn verify_installation_readback(
    artifact: &PortableArtifact,
    installation: &Installation,
    readback: &Value,
    observed_at_unix: i64,
) -> ReadbackVerification {
    if validate_installation(artifact, installation).is_err()
        || observed_at_unix < installation.manifest.binding.wall_time_unix
    {
        return ReadbackVerification {
            schema_version: "fw.experimental-readback/v1",
            comparison: Comparison::Unknown,
            expected_state_hash: artifact.desired_state_hash.clone(),
            observed_semantic_hash: None,
            readback_hash: canonical_hash(readback).ok(),
            reason_code: Some("INVALID_INSTALLATION_BINDING"),
            rules_checked: 0,
            tokens_checked: 0,
            production_qualified: false,
        };
    }
    verify_readback(&installation.native, readback, observed_at_unix)
}

/// Native integration should use this variant. In addition to exact native
/// correspondence it checks the original boot/time context and remaining token
/// lifetime against the original monotonic deadline. Neither wall-clock rollback
/// nor a token refresh can extend this monotonic bound. It is not proof that no
/// shorter refresh occurred historically; a snapshot cannot establish history.
pub fn verify_installation_readback_at(
    artifact: &PortableArtifact,
    installation: &Installation,
    readback: &Value,
    observation: &ObservationContext,
) -> ReadbackVerification {
    let mut result =
        verify_installation_readback(artifact, installation, readback, observation.wall_time_unix);
    if result.reason_code == Some("INVALID_INSTALLATION_BINDING") {
        return result;
    }
    let binding = &installation.manifest.binding;
    let elapsed = observation
        .monotonic_millis
        .checked_sub(binding.monotonic_millis);
    let valid_clock = elapsed.is_some_and(|elapsed| {
        let elapsed_seconds = elapsed / 1000;
        let drift_allowance = binding.clock_uncertainty_seconds + 1; // whole-second UTC quantization
        i64::try_from(elapsed_seconds.saturating_sub(drift_allowance))
            .ok()
            .and_then(|n| binding.wall_time_unix.checked_add(n))
            .is_some_and(|minimum| observation.wall_time_unix >= minimum)
    });
    if observation.boot_id != binding.boot_id
        || observation.network_namespace != binding.network_namespace
        || !valid_clock
    {
        result.comparison = Comparison::Unknown;
        result.observed_semantic_hash = None;
        result.reason_code = Some("OBSERVATION_CLOCK_OR_BOOT_MISMATCH");
        return result;
    }
    if result.comparison != Comparison::Match {
        return result;
    }
    let lifetimes = match crate::readback::remaining_token_lifetimes(readback, &artifact.table) {
        Ok(v) => v,
        Err(()) => {
            result.comparison = Comparison::Unknown;
            result.observed_semantic_hash = None;
            result.reason_code = Some("UNSUPPORTED_TOKEN_OBSERVATION");
            return result;
        }
    };
    for token in &installation.manifest.tokens {
        let horizon = token
            .cutoff_unix
            .checked_sub(binding.wall_time_unix)
            .and_then(|n| u64::try_from(n).ok())
            .and_then(|seconds| seconds.checked_mul(1000))
            .and_then(|millis| binding.monotonic_millis.checked_add(millis));
        let maximum = horizon.map(|deadline| {
            deadline
                .saturating_sub(observation.monotonic_millis)
                .div_ceil(1000)
        });
        if maximum.is_none()
            || lifetimes
                .get(&token.token_name)
                .is_some_and(|remaining| remaining.is_some_and(|r| r > maximum.unwrap_or(0)))
        {
            result.comparison = Comparison::Mismatch;
            result.observed_semantic_hash = None;
            result.reason_code = Some("TOKEN_MONOTONIC_DEADLINE_EXCEEDED");
            return result;
        }
    }
    result
}

/// Only a grant that explicitly binds the returned artifact and scope authorizes
/// its use. This is a no-business-allow recovery projection, not restoration of
/// historical rules. Conflicting existing deny revisions are unsupported rather
/// than guessed; a permissive recovery profile is never synthesized.
pub fn restrictive_recovery(
    previous: &PortableArtifact,
    candidate: &PortableArtifact,
) -> Result<PortableArtifact, CompileError> {
    previous.validate()?;
    candidate.validate()?;
    if previous.references != candidate.references {
        return Err(invalid("recovery reference drift"));
    }
    let mut state = candidate.state.clone();
    let mut denies: BTreeMap<&str, &Policy> = BTreeMap::new();
    for policy in previous
        .state
        .policies
        .iter()
        .chain(&candidate.state.policies)
    {
        if policy.action != Action::Deny {
            continue;
        }
        if denies
            .get(policy.policy_id.as_str())
            .is_some_and(|old| *old != policy)
        {
            return Err(CompileError::Unsupported(
                "conflicting deny revisions in recovery",
            ));
        }
        denies.insert(&policy.policy_id, policy);
    }
    state.policies = denies.into_values().cloned().collect();
    let hashes: BTreeSet<String> = state.policies.iter().map(hash).collect::<Result<_, _>>()?;
    let mut associations = BTreeMap::new();
    for association in previous
        .state
        .associations
        .iter()
        .chain(&candidate.state.associations)
    {
        if !hashes.contains(&association.policy_hash) {
            continue;
        }
        if associations
            .get(&association.policy_hash)
            .is_some_and(|old| *old != association)
        {
            return Err(invalid("conflicting recovery association"));
        }
        associations.insert(&association.policy_hash, association);
    }
    state.associations = associations.into_values().cloned().collect();
    compile_portable(&state, &candidate.references)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fw_planner::PolicyAssociation;
    use serde_json::json;
    const NOW: i64 = 1_800_000_000;
    const ORG: &str = "11111111-1111-4111-8111-111111111111";
    const PROJECT: &str = "22222222-2222-4222-8222-222222222222";
    const TARGET: &str = "33333333-3333-4333-8333-333333333333";
    const OWNER: &str = "44444444-4444-4444-8444-444444444444";
    const SOURCE: &str = "55555555-5555-4555-8555-555555555555";
    const DEST: &str = "66666666-6666-4666-8666-666666666666";
    const LEASE: &str = "77777777-7777-4777-8777-777777777777";
    fn utc(t: i64) -> String {
        chrono::DateTime::from_timestamp(t, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }
    fn policy(action: &str, n: u8) -> Policy {
        let lifetime = if action == "allow" {
            json!({"kind":"lease","not_before":utc(NOW-60),"expires_at":utc(NOW+60)})
        } else {
            json!({"kind":"review","not_before":utc(NOW-60),"review_at":utc(NOW+3600)})
        };
        serde_json::from_value(json!({"schema_version":"f.policy/v1","policy_id":format!("00000000-0000-4000-8000-{n:012}"),"policy_revision":1,"org_id":ORG,"project_id":PROJECT,"target_id":TARGET,"owner_id":OWNER,"reason":"isolated portable fixture","action":action,"log_mode":"none","lifetime":lifetime,"scope":{"family":"ipv4","direction":"input","source_asset_ids":[SOURCE],"destination_asset_ids":[DEST],"source_cidrs":["127.0.0.1/32"],"destination_cidrs":["127.0.0.1/32"],"transport":{"protocol":"tcp","destination_ports":[{"start":440+n as u16,"end":440+n as u16}]},"ingress_interfaces":["lo"],"egress_interfaces":[]}})).unwrap()
    }
    fn references() -> LabReferences {
        let scope = LabScope {
            schema_version: "fw.isolated-lab-scope/v1".into(),
            org_id: ORG.into(),
            project_id: PROJECT.into(),
            target_id: TARGET.into(),
            network_namespace: "net:[12345]".into(),
            interfaces: vec!["lo".into()],
            conntrack_zone: 0,
        };
        let scope_hash = hash(&scope).unwrap();
        LabReferences {
            baseline: LabBaseline {
                schema_version: "fw.isolated-lab-baseline/v1".into(),
                scope_hash: scope_hash.clone(),
                management_paths: vec![],
                default_action: "drop".into(),
            },
            source_snapshot: LabSourceSnapshot {
                schema_version: "fw.isolated-lab-snapshot/v1".into(),
                scope_hash: scope_hash.clone(),
                assets: [SOURCE, DEST]
                    .iter()
                    .map(|id| LabAsset {
                        asset_id: (*id).into(),
                        cidrs: vec!["127.0.0.1/32".into(), "::1/128".into()],
                    })
                    .collect(),
            },
            capability: LabCapability {
                schema_version: "fw.isolated-lab-capability/v1".into(),
                scope_hash,
                platform: "linux".into(),
                profile: "host-tcp-udp-lab".into(),
                production_qualified: false,
            },
            scope,
        }
    }
    fn state(policies: Vec<Policy>, refs: &LabReferences) -> StateIr {
        StateIr {
            schema_version: "f.state-ir/v1".into(),
            target_id: TARGET.into(),
            platform: "linux".into(),
            profile: "lab".into(),
            management_baseline_hash: hash(&refs.baseline).unwrap(),
            associations: policies
                .iter()
                .map(|p| PolicyAssociation {
                    policy_hash: hash(p).unwrap(),
                    lease_id: (p.action == Action::Allow).then(|| LEASE.into()),
                    request_id: OWNER.into(),
                    authority_basis_hash: hash(&"synthetic fixture authority basis").unwrap(),
                })
                .collect(),
            policies,
            tombstone_hashes: vec![],
            source_snapshot_hash: hash(&refs.source_snapshot).unwrap(),
            target_capability_hash: hash(&refs.capability).unwrap(),
            normalization_version: "f.normalize/nfc-v1".into(),
        }
    }
    fn fixture() -> PortableArtifact {
        let refs = references();
        compile_portable(
            &state(vec![policy("allow", 1), policy("deny", 2)], &refs),
            &refs,
        )
        .unwrap()
    }
    fn binding() -> BindingContext {
        BindingContext {
            operation_id: OWNER.into(),
            grant_hash: hash(&"signed fixture grant").unwrap(),
            boot_id: LEASE.into(),
            network_namespace: "net:[12345]".into(),
            wall_time_unix: NOW,
            monotonic_millis: 10_000,
            clock_uncertainty_seconds: 0,
            elapsed_seconds: 0,
            commit_budget_seconds: 2,
        }
    }
    fn snapshot(native: &Artifact, elapsed: u64) -> Value {
        let mut entries = vec![
            json!({"metainfo":{"version":"1.0.6","release_name":"fixture","json_schema_version":1}}),
        ];
        for (index, command) in native.nft_json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let mut entry = command["add"].clone();
            let (_, object) = entry.as_object_mut().unwrap().iter_mut().next().unwrap();
            object["handle"] = json!(index + 1);
            if let Some(elements) = object.get_mut("elem") {
                for element in elements.as_array_mut().unwrap() {
                    let timeout = element["elem"]["timeout"].as_u64().unwrap();
                    element["elem"]["expires"] = json!(timeout.saturating_sub(elapsed));
                }
            }
            entries.push(entry);
        }
        json!({"nftables":entries})
    }
    #[test]
    fn portable_identity_is_full_state_and_has_no_relative_timeout_elements() {
        let artifact = fixture();
        assert_eq!(
            artifact.desired_state_hash,
            artifact.state.state_hash().unwrap()
        );
        let sets: Vec<_> = artifact.nft_template["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["add"].get("set"))
            .collect();
        assert_eq!(sets.len(), 1);
        assert!(sets[0].get("elem").is_none());
        let mut state = artifact.state.clone();
        state.associations[0].request_id = SOURCE.into();
        let changed = compile_portable(&state, &artifact.references).unwrap();
        assert_eq!(artifact.nft_template, changed.nft_template);
        assert_ne!(artifact.desired_state_hash, changed.desired_state_hash);
        assert_ne!(
            artifact.artifact_hash().unwrap(),
            changed.artifact_hash().unwrap()
        );
    }
    #[test]
    fn delayed_binding_shrinks_token_without_mutating_signed_artifact() {
        let artifact = fixture();
        let before = artifact.artifact_hash().unwrap();
        let first = bind_at(&artifact, &binding()).unwrap();
        let mut later = binding();
        later.wall_time_unix += 10;
        later.monotonic_millis += 10_000;
        let second = bind_at(&artifact, &later).unwrap();
        assert_eq!(first.manifest.tokens[0].timeout_seconds, 58);
        assert_eq!(second.manifest.tokens[0].timeout_seconds, 48);
        assert_eq!(
            first.manifest.tokens[0].cutoff_unix,
            second.manifest.tokens[0].cutoff_unix
        );
        assert_eq!(before, artifact.artifact_hash().unwrap());
        assert_ne!(hash(&first).unwrap(), hash(&second).unwrap());
    }
    #[test]
    fn elapsed_uncertainty_and_commit_budget_never_extend_expiry() {
        let artifact = fixture();
        let mut context = binding();
        context.clock_uncertainty_seconds = 2;
        context.elapsed_seconds = 4;
        context.commit_budget_seconds = 3;
        let installation = bind_at(&artifact, &context).unwrap();
        assert_eq!(installation.manifest.tokens[0].timeout_seconds, 51);
        assert_eq!(installation.manifest.tokens[0].cutoff_unix, NOW + 58);
        context.clock_uncertainty_seconds = 3;
        assert!(bind_at(&artifact, &context).is_err());
        context.clock_uncertainty_seconds = 0;
        context.elapsed_seconds = u64::MAX;
        assert!(bind_at(&artifact, &context).is_err());
    }
    #[test]
    fn expired_allows_are_absent_from_installation_but_state_history_stays_bound() {
        let artifact = fixture();
        let mut context = binding();
        context.wall_time_unix = NOW + 60;
        let installation = bind_at(&artifact, &context).unwrap();
        assert!(installation.manifest.tokens.is_empty());
        let text = serde_json::to_string(&installation.native).unwrap();
        assert!(!text.contains("accept"));
        assert!(text.contains("deny:"));
        assert_eq!(
            installation.native.desired_state_hash,
            artifact.desired_state_hash
        );
        assert_eq!(artifact.tokens.len(), 1);
    }
    #[test]
    fn forged_commands_hashes_and_policy_bytes_fail_rebuild() {
        let original = fixture();
        for field in ["template", "hash", "state", "scope"] {
            let mut artifact = original.clone();
            match field {
                "template" => artifact.nft_template["nftables"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"flush":{"ruleset":null}})),
                "hash" => artifact.desired_state_hash = hash(&"forged").unwrap(),
                "state" => artifact.state.policies[0].reason = "changed after approval".into(),
                _ => artifact.references.scope.network_namespace = "net:[54321]".into(),
            }
            assert!(bind_at(&artifact, &binding()).is_err(), "{field}");
        }
    }
    #[test]
    fn source_snapshot_tenant_baseline_capability_and_tombstones_are_resolved() {
        let original = fixture();
        for field in [
            "source",
            "tenant",
            "baseline",
            "capability",
            "tombstone",
            "profile",
        ] {
            let mut state = original.state.clone();
            let mut refs = original.references.clone();
            match field {
                "source" => {
                    refs.source_snapshot.assets[0].cidrs = vec!["127.0.0.2/32".into()];
                    state.source_snapshot_hash = hash(&refs.source_snapshot).unwrap();
                }
                "tenant" => state.policies[0].org_id = OWNER.into(),
                "baseline" => {
                    refs.baseline.management_paths = vec!["unapproved path".into()];
                    state.management_baseline_hash = hash(&refs.baseline).unwrap();
                }
                "capability" => {
                    refs.capability.production_qualified = true;
                    state.target_capability_hash = hash(&refs.capability).unwrap();
                }
                "tombstone" => state
                    .tombstone_hashes
                    .push(hash(&"unresolved tombstone").unwrap()),
                _ => state.profile = "host".into(),
            }
            assert!(compile_portable(&state, &refs).is_err(), "{field}");
        }
    }
    #[test]
    fn only_canonical_loopback_assets_and_sorted_unique_snapshots_are_admitted() {
        let original = fixture();
        for address in [
            "0.0.0.0/0",
            "192.0.2.1/32",
            "127.0.0.1/24",
            "::/0",
            "::ffff:127.0.0.1/128",
            "127.0.0.1/032",
        ] {
            let mut refs = original.references.clone();
            refs.source_snapshot.assets[0].cidrs = vec![address.into()];
            let mut state = original.state.clone();
            state.source_snapshot_hash = hash(&refs.source_snapshot).unwrap();
            assert!(compile_portable(&state, &refs).is_err(), "{address}");
        }
        let mut refs = original.references.clone();
        refs.source_snapshot.assets.reverse();
        let mut state = original.state.clone();
        state.source_snapshot_hash = hash(&refs.source_snapshot).unwrap();
        assert!(compile_portable(&state, &refs).is_err());
    }
    #[test]
    fn future_activation_wrong_namespace_or_tampered_installation_never_matches() {
        let artifact = fixture();
        let mut context = binding();
        context.wall_time_unix = NOW - 61;
        assert!(bind_at(&artifact, &context).is_err());
        context = binding();
        context.network_namespace = "net:[1]".into();
        assert!(bind_at(&artifact, &context).is_err());
        let mut installation = bind_at(&artifact, &binding()).unwrap();
        installation.manifest.tokens[0].timeout_seconds += 1;
        let report = verify_installation_readback(
            &artifact,
            &installation,
            &snapshot(&installation.native, 0),
            NOW,
        );
        assert_eq!(report.comparison, Comparison::Unknown);
        assert!(report.observed_semantic_hash.is_none());
    }
    #[test]
    fn original_installation_observed_with_real_shape_and_current_clock() {
        let artifact = fixture();
        let installation = bind_at(&artifact, &binding()).unwrap();
        let observation = ObservationContext {
            boot_id: LEASE.into(),
            network_namespace: "net:[12345]".into(),
            wall_time_unix: NOW + 10,
            monotonic_millis: 20_000,
        };
        let report = verify_installation_readback_at(
            &artifact,
            &installation,
            &snapshot(&installation.native, 10),
            &observation,
        );
        assert_eq!(report.comparison, Comparison::Match, "{report:?}");
        assert_eq!(
            report.observed_semantic_hash,
            Some(artifact.desired_state_hash)
        );
    }
    #[test]
    fn boot_change_monotonic_reversal_and_wall_clock_rollback_are_unknown() {
        let artifact = fixture();
        let installation = bind_at(&artifact, &binding()).unwrap();
        for scenario in ["boot", "mono", "wall"] {
            let mut observation = ObservationContext {
                boot_id: LEASE.into(),
                network_namespace: "net:[12345]".into(),
                wall_time_unix: NOW + 10,
                monotonic_millis: 20_000,
            };
            match scenario {
                "boot" => observation.boot_id = OWNER.into(),
                "mono" => observation.monotonic_millis = 9_999,
                _ => observation.wall_time_unix = NOW + 5,
            };
            let report = verify_installation_readback_at(
                &artifact,
                &installation,
                &snapshot(&installation.native, 10),
                &observation,
            );
            assert_eq!(
                report.comparison,
                Comparison::Unknown,
                "{scenario}: {report:?}"
            );
            assert!(report.observed_semantic_hash.is_none());
        }
    }
    #[test]
    fn refreshed_token_cannot_exceed_original_monotonic_deadline() {
        let artifact = fixture();
        let mut context = binding();
        context.commit_budget_seconds = 0;
        let installation = bind_at(&artifact, &context).unwrap();
        // UTC is one second behind monotonic elapsed: inside the clock
        // quantization allowance, but not permission to extend a live token.
        let observation = ObservationContext {
            boot_id: LEASE.into(),
            network_namespace: "net:[12345]".into(),
            wall_time_unix: NOW + 9,
            monotonic_millis: 20_000,
        };
        let actual = snapshot(&installation.native, 9);
        assert_eq!(
            verify_installation_readback(&artifact, &installation, &actual, NOW + 9).comparison,
            Comparison::Match
        );
        let report =
            verify_installation_readback_at(&artifact, &installation, &actual, &observation);
        assert_eq!(report.comparison, Comparison::Mismatch);
        assert_eq!(
            report.reason_code,
            Some("TOKEN_MONOTONIC_DEADLINE_EXCEEDED")
        );
        assert!(report.observed_semantic_hash.is_none());
    }
    #[test]
    fn malformed_persisted_time_bounds_fail_closed_without_arithmetic() {
        let artifact = fixture();
        let mut installation = bind_at(&artifact, &binding()).unwrap();
        installation.manifest.binding.clock_uncertainty_seconds = u64::MAX;
        let observation = ObservationContext {
            boot_id: LEASE.into(),
            network_namespace: "net:[12345]".into(),
            wall_time_unix: NOW,
            monotonic_millis: 10_000,
        };
        let report = verify_installation_readback_at(
            &artifact,
            &installation,
            &snapshot(&installation.native, 0),
            &observation,
        );
        assert_eq!(report.comparison, Comparison::Unknown);
        assert_eq!(report.reason_code, Some("INVALID_INSTALLATION_BINDING"));
        assert!(report.observed_semantic_hash.is_none());
    }
    #[test]
    fn restrictive_recovery_keeps_all_known_denies_and_associations() {
        let refs = references();
        let previous = compile_portable(&state(vec![policy("deny", 3)], &refs), &refs).unwrap();
        let candidate = fixture();
        let recovery = restrictive_recovery(&previous, &candidate).unwrap();
        assert_eq!(recovery.state.policies.len(), 2);
        assert_eq!(recovery.state.associations.len(), 2);
        assert!(recovery.tokens.is_empty());
        assert!(recovery
            .state
            .policies
            .iter()
            .all(|p| p.action == Action::Deny));
        assert!(!serde_json::to_string(&recovery.nft_template)
            .unwrap()
            .contains("accept"));
        assert_eq!(
            recovery.state.management_baseline_hash,
            candidate.state.management_baseline_hash
        );
        assert_eq!(
            recovery.scope_hash().unwrap(),
            candidate.scope_hash().unwrap()
        );
    }
    #[test]
    fn recovery_rejects_conflicting_deny_revision_or_snapshot_change() {
        let refs = references();
        let previous = compile_portable(&state(vec![policy("deny", 2)], &refs), &refs).unwrap();
        let mut modified = policy("deny", 2);
        modified.policy_revision = 2;
        let candidate = compile_portable(&state(vec![modified], &refs), &refs).unwrap();
        assert!(restrictive_recovery(&previous, &candidate).is_err());
        let mut refs = refs;
        refs.scope.network_namespace = "net:[2]".into();
        let scope_hash = hash(&refs.scope).unwrap();
        refs.baseline.scope_hash = scope_hash.clone();
        refs.capability.scope_hash = scope_hash.clone();
        refs.source_snapshot.scope_hash = scope_hash;
        let candidate = compile_portable(&state(vec![], &refs), &refs).unwrap();
        assert!(restrictive_recovery(&previous, &candidate).is_err());
    }
}
