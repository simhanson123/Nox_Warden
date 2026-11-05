//! One immutable absolute window for an original core access lease.
//! This structural evidence never authenticates a workload or delegation.
use crate::{AuthorityError, CoreAccessProvenance, Result, VerifiedCoreAccessProvenance};
use fw_contracts::{canonical_bytes, canonical_hash, parse_strict_with_limit};
use fw_planner::{PolicyReviewEvidence, VerifiedPolicyReview};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CORE_ACCESS_LEASE_WINDOW_SCHEMA: &str = "fw.core-access-lease-window/v1";
pub const MAX_CORE_ACCESS_LEASE_WINDOW_BYTES: usize = 4096;
pub const MAX_CORE_ACCESS_PLAN_REGISTRATION_BYTES: usize = 512 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAccessPlanRegistration {
    pub schema_version: String,
    pub plan: Value,
    pub requirements: Value,
    pub evidence: PolicyReviewEvidence,
    pub provenance: CoreAccessProvenance,
    pub window: CoreAccessLeaseWindow,
}
impl CoreAccessPlanRegistration {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let result: Self = parse_strict_with_limit(bytes, MAX_CORE_ACCESS_PLAN_REGISTRATION_BYTES)
            .map_err(|_| invalid())?;
        if result.schema_version != "fw.reviewed-core-access-plan/v1" {
            return Err(invalid());
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoreAccessLeaseWindow {
    pub schema_version: String,
    pub org_id: String,
    pub project_id: String,
    pub target_id: String,
    pub request_id: String,
    pub request_revision: u32,
    pub request_hash: String,
    pub provenance_hash: String,
    pub lease_id: String,
    pub not_before: String,
    pub expires_at: String,
}

#[derive(Debug)]
pub struct VerifiedCoreAccessLeaseWindow {
    canonical: Vec<u8>,
    hash: String,
    not_before: i64,
    expires_at: i64,
}
impl VerifiedCoreAccessLeaseWindow {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn not_before(&self) -> i64 {
        self.not_before
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub fn lease_seconds(&self) -> i64 {
        self.expires_at - self.not_before
    }
}

fn invalid() -> AuthorityError {
    AuthorityError::Invalid("core access lease window")
}
impl CoreAccessLeaseWindow {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        parse_strict_with_limit(bytes, MAX_CORE_ACCESS_LEASE_WINDOW_BYTES).map_err(|_| invalid())
    }
    /// Recompute full plan, original-cost and fixed-window correspondence.
    /// Success establishes structural evidence only, never production authority.
    pub fn verify(
        &self,
        plan: &Value,
        provenance: &CoreAccessProvenance,
        review: &PolicyReviewEvidence,
    ) -> Result<VerifiedCoreAccessLeaseWindow> {
        let original = provenance.verify(plan)?;
        let review = review.verify(plan).map_err(|_| invalid())?;
        self.verify_binding(plan, &original, &review)
    }
    pub(crate) fn verify_binding(
        &self,
        plan: &Value,
        original: &VerifiedCoreAccessProvenance,
        review: &VerifiedPolicyReview,
    ) -> Result<VerifiedCoreAccessLeaseWindow> {
        // Bound directly constructed Rust strings before canonical allocation.
        if [
            &self.schema_version,
            &self.org_id,
            &self.project_id,
            &self.target_id,
            &self.request_id,
            &self.request_hash,
            &self.provenance_hash,
            &self.lease_id,
            &self.not_before,
            &self.expires_at,
        ]
        .iter()
        .any(|s| s.len() > 128)
        {
            return Err(invalid());
        }
        let binding = review.core_binding().ok_or_else(invalid)?;
        let start = crate::timestamp(&self.not_before)?;
        let end = crate::timestamp(&self.expires_at)?;
        if self.schema_version != CORE_ACCESS_LEASE_WINDOW_SCHEMA
            || self.org_id != original.org_id()
            || self.project_id != original.project_id()
            || self.target_id != original.target_id()
            || self.request_id != original.request_id()
            || self.request_revision != original.request_revision()
            || self.request_hash != original.request_hash()
            || self.provenance_hash != original.hash()
            || self.lease_id != original.lease_id()
            || binding.lease_id() != self.lease_id
            || binding.request_id() != self.request_id
            || start != binding.not_before()
            || end != binding.expires_at()
            || end.checked_sub(start) != Some(original.lease_seconds())
            || binding.lease_seconds() != original.lease_seconds()
            || start < original.valid_from()
            || end > original.valid_until()
            || end > crate::timestamp(crate::string(plan, "workload_binding_valid_until")?)?
            || review.plan_hash() != canonical_hash(plan).map_err(|_| invalid())?
        {
            return Err(AuthorityError::Binding);
        }
        let basis = serde_json::json!({"schema_version":"f.policy-authority-basis/v1",
            "approval_requirements_hash":plan["approval_requirements_hash"],
            "envelope_hash":plan["envelope_hash"],"delegation_hash":plan["delegation_hash"]});
        if binding.authority_basis_hash() != canonical_hash(&basis).map_err(|_| invalid())? {
            return Err(AuthorityError::Binding);
        }
        let canonical = canonical_bytes(self).map_err(|_| invalid())?;
        if canonical.len() > MAX_CORE_ACCESS_LEASE_WINDOW_BYTES {
            return Err(invalid());
        }
        Ok(VerifiedCoreAccessLeaseWindow {
            hash: fw_contracts::hash_bytes(&canonical),
            canonical,
            not_before: start,
            expires_at: end,
        })
    }
}
