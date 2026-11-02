//! Original request and prospective lease cost provenance, without authorization.
//!
//! Hash binding proves which original records supply accounting cost. It does
//! not verify envelope/delegation approval, workload signatures, current asset
//! resolution, native evidence, or permission to sign a grant.

use crate::{AuthorityError, Result, hash_ok, uuid_ok};
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use fw_domain::{Action, Policy, Scope};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, io::Write};

pub const CORE_ACCESS_PROVENANCE_SCHEMA: &str = "fw.core-access-provenance/v1";
pub const MAX_CORE_ACCESS_PROVENANCE_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    pub schema_version: String,
    pub idempotency_key: String,
    pub workflow_id: String,
    pub workload_binding_id: String,
    pub source_asset_ids: Vec<String>,
    pub destination_asset_ids: Vec<String>,
    pub service_id: String,
    pub lease_seconds: u64,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessEnvelope {
    pub schema_version: String,
    pub envelope_id: String,
    pub revision: u32,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub scope: Scope,
    pub excluded_destination_cidrs: Vec<String>,
    pub valid_from: String,
    pub valid_until: String,
    pub max_lease_seconds: u64,
    pub approval_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationBudgetWindow {
    pub kind: String,
    pub seconds: u64,
    pub interval: String,
    pub lease_seconds_measure: String,
    pub rounding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub schema_version: String,
    pub root_id: String,
    pub revision: u32,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub envelope_id: String,
    pub envelope_hash: String,
    pub allowed_principal_ids: Vec<String>,
    pub workload_binding_ids: Vec<String>,
    pub source_asset_ids: Vec<String>,
    pub destination_asset_ids: Vec<String>,
    pub service_ids: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub valid_from: String,
    pub valid_until: String,
    pub max_lease_seconds: u64,
    pub max_active_leases: u64,
    pub max_new_leases_per_day: u64,
    pub max_unique_destinations_per_day: u64,
    pub max_cumulative_lease_seconds_per_day: u64,
    pub approval_hash: String,
    pub can_delegate: bool,
    pub max_concurrent_deployments: u64,
    pub budget_window: DelegationBudgetWindow,
}

/// Trusted-local import content. Every field remains untrusted until verified;
/// even successful verification establishes provenance rather than authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAccessProvenance {
    pub schema_version: String,
    pub request_id: String,
    pub request_revision: u32,
    pub lease_id: String,
    pub request: AccessRequest,
    pub envelope: AccessEnvelope,
    pub delegation: Delegation,
}

/// Immutable structural/hash binding to one plan and the full original cost.
/// This type deliberately does not implement production authority evidence.
#[derive(Debug, Clone)]
pub struct VerifiedCoreAccessProvenance {
    original: CoreAccessProvenance,
    canonical: Vec<u8>,
    hash: String,
    request_hash: String,
    principal_id: String,
    destination_asset_ids: Vec<String>,
    valid_from: i64,
    valid_until: i64,
}

impl VerifiedCoreAccessProvenance {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }
    pub fn root_id(&self) -> &str {
        &self.original.delegation.root_id
    }
    pub fn lease_id(&self) -> &str {
        &self.original.lease_id
    }
    pub fn request_id(&self) -> &str {
        &self.original.request_id
    }
    pub fn request_revision(&self) -> u32 {
        self.original.request_revision
    }
    pub fn org_id(&self) -> &str {
        &self.original.envelope.org_id
    }
    pub fn project_id(&self) -> &str {
        &self.original.envelope.project_id
    }
    pub fn target_id(&self) -> &str {
        &self.original.envelope.target_id
    }
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }
    pub fn idempotency_key(&self) -> &str {
        &self.original.request.idempotency_key
    }
    pub fn lease_seconds(&self) -> i64 {
        self.original.request.lease_seconds as i64
    }
    pub fn destination_asset_ids(&self) -> &[String] {
        &self.destination_asset_ids
    }
    /// Intersection of original envelope/delegation validity, not a grant window.
    pub fn valid_from(&self) -> i64 {
        self.valid_from
    }
    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }
    /// Structural original limits; approval and current authority are not proven.
    pub fn delegation(&self) -> &Delegation {
        &self.original.delegation
    }
}

fn invalid() -> AuthorityError {
    AuthorityError::Invalid("core access provenance")
}
fn bound(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(AuthorityError::Binding)
    }
}
fn time(value: &str) -> Result<i64> {
    let result = fw_domain::timestamp(value).map_err(|_| AuthorityError::Time)?;
    if result < 0 {
        return Err(AuthorityError::Time);
    }
    Ok(result)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn count(value: u64, minimum: u64, maximum: u64) -> Result<()> {
    if !(minimum..=maximum).contains(&value) {
        return Err(invalid());
    }
    Ok(())
}
fn strings(values: &[String], minimum: usize, maximum: usize, ids: bool) -> Result<()> {
    if !(minimum..=maximum).contains(&values.len())
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
        || (ids && values.iter().any(|v| !uuid_ok(v)))
    {
        return Err(invalid());
    }
    Ok(())
}
fn short(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= maximum
}
fn subset(inner: &[String], outer: &[String]) -> bool {
    inner.iter().all(|v| outer.contains(v))
}
fn same_members(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && subset(left, right)
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    canonical_hash(value).map_err(|_| invalid())
}

// Bound direct Rust Values before serialization or cloning, including depth.
fn preflight(value: &Value, remaining: &mut usize, depth: usize) -> Result<()> {
    if depth >= fw_contracts::MAX_DEPTH {
        return Err(invalid());
    }
    let cost = match value {
        Value::String(s) => s.len().checked_mul(6).and_then(|n| n.checked_add(2)),
        Value::Array(a) => a.len().checked_add(2),
        Value::Object(o) => o.len().checked_mul(4).and_then(|n| n.checked_add(2)),
        _ => Some(24),
    }
    .ok_or_else(invalid)?;
    *remaining = remaining.checked_sub(cost).ok_or_else(invalid)?;
    match value {
        Value::Array(a) => {
            for v in a {
                preflight(v, remaining, depth + 1)?;
            }
        }
        Value::Object(o) => {
            for (key, v) in o {
                *remaining = remaining
                    .checked_sub(key.len().checked_mul(6).ok_or_else(invalid)?)
                    .ok_or_else(invalid)?;
                preflight(v, remaining, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// Fixed typed contracts have bounded nesting. A counting writer rejects large
// direct Rust strings/collections before constructing their canonical copies.
struct Budget(usize);
impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("provenance size limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn bounded<T: Serialize>(value: &T) -> Result<()> {
    serde_json::to_writer(Budget(MAX_CORE_ACCESS_PROVENANCE_BYTES), value).map_err(|_| invalid())
}

impl CoreAccessProvenance {
    pub fn from_json(value: &Value) -> Result<Self> {
        preflight(value, &mut (MAX_CORE_ACCESS_PROVENANCE_BYTES * 6), 0)?;
        bounded(value)?;
        serde_json::from_value(value.clone()).map_err(|_| invalid())
    }

    pub fn verify(&self, plan: &Value) -> Result<VerifiedCoreAccessProvenance> {
        bounded(self)?;
        preflight(plan, &mut (MAX_CORE_ACCESS_PROVENANCE_BYTES * 6), 0)?;
        bounded(plan)?;
        if self.schema_version != CORE_ACCESS_PROVENANCE_SCHEMA
            || self.request_revision != 1
            || !uuid_ok(&self.request_id)
            || !uuid_ok(&self.lease_id)
            || plan["schema_version"] != "f.plan/v1"
            || plan["change_kind"] != "add_access_lease"
        {
            return Err(invalid());
        }
        for key in [
            "plan_id",
            "request_id",
            "org_id",
            "project_id",
            "target_id",
            "principal_id",
            "workload_binding_id",
        ] {
            if !uuid_ok(text(plan, key)?) {
                return Err(invalid());
            }
        }
        let request = &self.request;
        if request.schema_version != "f.access-request/v1"
            || !uuid_ok(&request.idempotency_key)
            || !uuid_ok(&request.workload_binding_id)
            || !short(&request.workflow_id, 128)
            || !short(&request.service_id, 128)
            || !short(&request.purpose, 2000)
        {
            return Err(invalid());
        }
        strings(&request.source_asset_ids, 1, 16, true)?;
        strings(&request.destination_asset_ids, 1, 16, true)?;
        count(request.lease_seconds, 60, 86_400)?;
        let envelope = &self.envelope;
        let delegation = &self.delegation;
        for (schema, expected, revision, ids) in [
            (
                &envelope.schema_version,
                "f.access-envelope/v1",
                envelope.revision,
                [
                    &envelope.org_id,
                    &envelope.project_id,
                    &envelope.target_id,
                    &envelope.envelope_id,
                ],
            ),
            (
                &delegation.schema_version,
                "f.delegation/v1",
                delegation.revision,
                [
                    &delegation.org_id,
                    &delegation.project_id,
                    &delegation.target_id,
                    &delegation.root_id,
                ],
            ),
        ] {
            if schema != expected || ids.iter().any(|id| !uuid_ok(id)) {
                return Err(invalid());
            }
            count(u64::from(revision), 1, i32::MAX as u64)?;
        }
        if !uuid_ok(&delegation.envelope_id)
            || !hash_ok(&envelope.approval_hash)
            || !hash_ok(&delegation.approval_hash)
            || !hash_ok(&delegation.envelope_hash)
        {
            return Err(invalid());
        }
        envelope.scope.validate().map_err(|_| invalid())?;
        strings(&envelope.excluded_destination_cidrs, 0, 128, false)?;
        let excluded = envelope
            .excluded_destination_cidrs
            .iter()
            .map(|raw| {
                let network: IpNet = raw.parse().map_err(|_| invalid())?;
                if network.trunc() != network || network.to_string() != *raw {
                    return Err(invalid());
                }
                Ok(network)
            })
            .collect::<Result<Vec<_>>>()?;
        for ids in [
            &delegation.allowed_principal_ids,
            &delegation.workload_binding_ids,
            &delegation.source_asset_ids,
            &delegation.destination_asset_ids,
        ] {
            strings(ids, 1, 256, true)?;
        }
        strings(&delegation.service_ids, 1, 128, false)?;
        strings(&delegation.allowed_tools, 1, 6, false)?;
        if delegation.service_ids.iter().any(|s| !short(s, 128))
            || delegation.can_delegate
            || delegation.allowed_tools.iter().any(|tool| {
                ![
                    "request_access",
                    "get_plan",
                    "get_operation",
                    "request_deployment",
                    "release_access",
                    "get_capabilities",
                ]
                .contains(&tool.as_str())
            })
        {
            return Err(invalid());
        }
        let window = &delegation.budget_window;
        if window.kind != "rolling"
            || window.seconds != 86_400
            || window.interval != "(as_of-86400s,as_of]"
            || window.lease_seconds_measure != "approved-duration-per-lease"
            || window.rounding != "integer-seconds-no-rounding"
        {
            return Err(invalid());
        }
        count(envelope.max_lease_seconds, 60, 86_400)?;
        count(delegation.max_lease_seconds, 60, 86_400)?;
        count(delegation.max_active_leases, 1, 10_000)?;
        count(delegation.max_new_leases_per_day, 1, 100_000)?;
        count(delegation.max_unique_destinations_per_day, 1, 100_000)?;
        count(
            delegation.max_cumulative_lease_seconds_per_day,
            60,
            i32::MAX as u64,
        )?;
        count(delegation.max_concurrent_deployments, 1, 10_000)?;
        let request_hash = digest(request)?;
        let envelope_hash = digest(envelope)?;
        bound(
            plan["request_id"] == self.request_id
                && plan["request_revision"].as_u64() == Some(u64::from(self.request_revision))
                && plan["request_hash"] == request_hash
                && plan["envelope_hash"] == envelope_hash
                && plan["delegation_hash"] == digest(delegation)?
                && delegation.envelope_hash == envelope_hash
                && delegation.envelope_id == envelope.envelope_id
                && delegation.org_id == envelope.org_id
                && delegation.project_id == envelope.project_id
                && delegation.target_id == envelope.target_id
                && plan["org_id"] == envelope.org_id
                && plan["project_id"] == envelope.project_id
                && plan["target_id"] == envelope.target_id
                && plan["workload_binding_id"] == request.workload_binding_id,
        )?;
        let principal = text(plan, "principal_id")?;
        bound(
            delegation
                .allowed_principal_ids
                .iter()
                .any(|s| s == principal)
                && delegation
                    .workload_binding_ids
                    .contains(&request.workload_binding_id)
                && delegation.service_ids.contains(&request.service_id)
                && ["request_access", "request_deployment"]
                    .iter()
                    .all(|tool| delegation.allowed_tools.iter().any(|s| s == tool))
                && subset(&request.source_asset_ids, &delegation.source_asset_ids)
                && subset(
                    &request.destination_asset_ids,
                    &delegation.destination_asset_ids,
                )
                && subset(&request.source_asset_ids, &envelope.scope.source_asset_ids)
                && subset(
                    &request.destination_asset_ids,
                    &envelope.scope.destination_asset_ids,
                )
                && request.lease_seconds <= envelope.max_lease_seconds
                && request.lease_seconds <= delegation.max_lease_seconds,
        )?;
        let envelope_from = time(&envelope.valid_from)?;
        let envelope_until = time(&envelope.valid_until)?;
        let delegation_from = time(&delegation.valid_from)?;
        let delegation_until = time(&delegation.valid_until)?;
        let valid_from = envelope_from.max(delegation_from);
        let valid_until = envelope_until.min(delegation_until);
        let created = time(text(plan, "created_at")?)?;
        let until = time(text(plan, "valid_until")?)?;
        let workload_until = time(text(plan, "workload_binding_valid_until")?)?;
        if envelope_from >= envelope_until
            || delegation_from >= delegation_until
            || valid_from > created
            || created >= until
            || until > valid_until
            || workload_until < until
        {
            return Err(AuthorityError::Time);
        }
        if !hash_ok(text(plan, "workload_binding_hash")?) {
            return Err(invalid());
        }
        let policies = plan["requested_policies"].as_array().ok_or_else(invalid)?;
        if policies.is_empty() || policies.len() > 256 {
            return Err(invalid());
        }
        let mut first = i64::MAX;
        let mut last = i64::MIN;
        let mut prior_id: Option<String> = None;
        let mut policy_hashes = BTreeSet::new();
        for value in policies {
            let policy: Policy = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            if policy.normalized().map_err(|_| invalid())? != policy
                || policy.action != Action::Allow
                || policy.policy_revision != 1
                || prior_id.as_ref().is_some_and(|id| id >= &policy.policy_id)
            {
                return Err(invalid());
            }
            bound(
                policy.org_id == envelope.org_id
                    && policy.project_id == envelope.project_id
                    && policy.target_id == envelope.target_id
                    && same_members(&policy.scope.source_asset_ids, &request.source_asset_ids)
                    && same_members(
                        &policy.scope.destination_asset_ids,
                        &request.destination_asset_ids,
                    )
                    && policy
                        .scope
                        .is_subset_of(&envelope.scope)
                        .map_err(|_| invalid())?,
            )?;
            for destination in &policy.scope.destination_cidrs {
                let network: IpNet = destination.parse().map_err(|_| invalid())?;
                bound(!excluded.iter().any(|blocked| {
                    blocked.contains(&network.network()) || network.contains(&blocked.network())
                }))?;
            }
            let start = time(policy.lifetime.not_before())?;
            let end = time(policy.lifetime.expires_at().ok_or_else(invalid)?)?;
            if start < valid_from || end > valid_until || end > workload_until || end < until {
                return Err(AuthorityError::Time);
            }
            first = first.min(start);
            last = last.max(end);
            policy_hashes.insert(digest(value)?);
            prior_id = Some(policy.policy_id);
        }
        // All new policies fit one prospective lease. Several short policies
        // cannot extend the window or reduce the original accounting cost.
        if last - first > request.lease_seconds as i64 {
            return Err(AuthorityError::Time);
        }
        let expected_hashes = plan["requested_policy_hashes"]
            .as_array()
            .ok_or_else(invalid)?;
        if expected_hashes.len() != policies.len() {
            return Err(AuthorityError::Binding);
        }
        let expected_hashes = expected_hashes
            .iter()
            .map(|v| v.as_str().ok_or_else(invalid))
            .collect::<Result<BTreeSet<_>>>()?;
        bound(
            expected_hashes.len() == policies.len()
                && policy_hashes
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
                    == expected_hashes
                && plan["request_patch_hash"] == digest(&plan["requested_policies"])?,
        )?;
        let canonical = canonical_bytes(self).map_err(|_| invalid())?;
        let mut destination_asset_ids = request.destination_asset_ids.clone();
        destination_asset_ids.sort();
        Ok(VerifiedCoreAccessProvenance {
            original: self.clone(),
            hash: hash_bytes(&canonical),
            canonical,
            request_hash,
            principal_id: principal.into(),
            destination_asset_ids,
            valid_from,
            valid_until,
        })
    }
}
