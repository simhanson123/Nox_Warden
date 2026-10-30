//! Immutable approval binding, downstream of a real WebAuthn proof verifier.
//! There is intentionally no permissive default implementation of ProofVerifier.
use crate::{AuthorityError, Result, closed, counter, hash_ok, string, timestamp, uuid_ok};
use fw_contracts::canonical_hash;
use serde_json::Value;
use std::collections::BTreeSet;

/// Implement in the independent authority against current role membership,
/// credential revocations and original WebAuthn assertions. A supplied boolean,
/// credential ID, evidence hash, or database `approved` field is not a proof.
pub trait ProofVerifier {
    fn verify_webauthn_and_current_role(&self, approval: &Value, now_unix: i64) -> Result<()>;
}
#[derive(Debug, Clone)]
pub struct ApprovalContext {
    pub org_id: String,
    pub project_id: String,
    pub author_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub plan_kind: String,
    pub plan_valid_until: i64,
    pub authority_epoch: u64,
    pub now_unix: i64,
}
/// Private content prevents approvals from being edited after verification.
#[derive(Debug, Clone)]
pub struct VerifiedApprovalSet {
    content: Value,
    hash: String,
    valid_until: i64,
}
impl VerifiedApprovalSet {
    pub fn content(&self) -> &Value {
        &self.content
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }
}

pub fn verify_human_approval_set(
    set: &Value,
    requirements: &Value,
    context: &ApprovalContext,
    proof: &impl ProofVerifier,
) -> Result<VerifiedApprovalSet> {
    closed(
        set,
        &[
            "schema_version",
            "approval_set_id",
            "org_id",
            "project_id",
            "plan_ref",
            "requirements_hash",
            "created_at",
            "valid_until",
            "authority_epoch",
            "kind",
            "approvals",
            "role_policy_hash",
        ],
    )?;
    closed(
        requirements,
        &[
            "schema_version",
            "profile",
            "minimum_humans",
            "required_roles",
            "distinct_principals",
            "author_may_approve",
            "max_approval_age_seconds",
            "require_webauthn",
            "role_policy_hash",
        ],
    )?;
    if set["schema_version"] != "f.approval-set/v1"
        || set["kind"] != "human"
        || requirements["schema_version"] != "f.approval-requirements/v1"
        || requirements["require_webauthn"] != true
    {
        return Err(AuthorityError::Invalid(
            "approval schema or proof requirement",
        ));
    }
    let profile = string(requirements, "profile")?;
    if !["lab_owner", "team_dual", "team_high_risk"].contains(&profile) {
        return Err(AuthorityError::Invalid("approval profile"));
    }
    let minimum = requirements["minimum_humans"]
        .as_u64()
        .filter(|n| (1..=3).contains(n))
        .ok_or(AuthorityError::Invalid("human count"))? as usize;
    let max_age = requirements["max_approval_age_seconds"]
        .as_i64()
        .filter(|n| (60..=86400).contains(n))
        .ok_or(AuthorityError::Invalid("approval age"))?;
    let distinct = requirements["distinct_principals"]
        .as_bool()
        .ok_or(AuthorityError::Invalid("independence"))?;
    let author_allowed = requirements["author_may_approve"]
        .as_bool()
        .ok_or(AuthorityError::Invalid("author approval"))?;
    if profile != "lab_owner" && (!distinct || author_allowed || minimum < 2) {
        return Err(AuthorityError::Invalid("team approval independence"));
    }
    if set["org_id"] != context.org_id
        || set["project_id"] != context.project_id
        || !uuid_ok(string(set, "approval_set_id")?)
        || counter(string(set, "authority_epoch")?)? != context.authority_epoch
    {
        return Err(AuthorityError::Binding);
    }
    let reference = &set["plan_ref"];
    closed(reference, &["plan_kind", "plan_id", "plan_hash"])?;
    if reference["plan_kind"] != context.plan_kind
        || reference["plan_id"] != context.plan_id
        || reference["plan_hash"] != context.plan_hash
    {
        return Err(AuthorityError::Binding);
    }
    let requirement_hash = canonical_hash(requirements)
        .map_err(|_| AuthorityError::Invalid("requirements canonicalization"))?;
    if set["requirements_hash"] != requirement_hash
        || set["role_policy_hash"] != requirements["role_policy_hash"]
        || !hash_ok(string(set, "role_policy_hash")?)
    {
        return Err(AuthorityError::Binding);
    }
    let now = context.now_unix;
    let created = timestamp(string(set, "created_at")?)?;
    let valid_until = timestamp(string(set, "valid_until")?)?;
    if created > now
        || valid_until <= now
        || valid_until > context.plan_valid_until
        || valid_until <= created
    {
        return Err(AuthorityError::Time);
    }
    let approvals = set["approvals"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 3)
        .ok_or(AuthorityError::Invalid("approvals"))?;
    let role_list = requirements["required_roles"]
        .as_array()
        .filter(|r| !r.is_empty() && r.len() <= 3)
        .ok_or(AuthorityError::Invalid("required roles"))?;
    let mut required = BTreeSet::new();
    for role in role_list {
        let r = role
            .as_str()
            .ok_or(AuthorityError::Invalid("required role"))?;
        if ![
            "owner",
            "network_reviewer",
            "service_reviewer",
            "security_reviewer",
        ]
        .contains(&r)
            || !required.insert(r)
        {
            return Err(AuthorityError::Invalid("duplicate or invalid role"));
        }
    }
    let profile_valid = match profile {
        "lab_owner" => minimum == 1 && required == BTreeSet::from(["owner"]),
        "team_dual" => {
            minimum == 2
                && required.len() == 2
                && required.contains("network_reviewer")
                && (required.contains("service_reviewer") || required.contains("security_reviewer"))
        }
        "team_high_risk" => {
            minimum == 3
                && required
                    == BTreeSet::from(["network_reviewer", "service_reviewer", "security_reviewer"])
        }
        _ => false,
    };
    if !profile_valid {
        return Err(AuthorityError::Invalid(
            "approval profile roles or cardinality",
        ));
    }
    let mut humans = BTreeSet::new();
    let mut roles = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut challenges = BTreeSet::new();
    for approval in approvals {
        closed(
            approval,
            &[
                "approval_id",
                "principal",
                "role",
                "decision",
                "plan_ref",
                "requirements_hash",
                "challenge_id",
                "assertion_evidence",
                "credential_registry_hash",
                "role_membership_hash",
                "created_at",
                "expires_at",
            ],
        )?;
        if approval["decision"] != "approve"
            || approval["plan_ref"] != *reference
            || approval["requirements_hash"] != requirement_hash
        {
            return Err(AuthorityError::Binding);
        }
        let principal = &approval["principal"];
        closed(
            principal,
            &["principal_id", "issuer", "subject", "authentication_time"],
        )?;
        let principal_id = string(principal, "principal_id")?;
        if !uuid_ok(principal_id) || (!author_allowed && principal_id == context.author_id) {
            return Err(AuthorityError::Binding);
        }
        if !humans.insert(principal_id) && distinct {
            return Err(AuthorityError::Invalid("independent humans required"));
        }
        let role = string(approval, "role")?;
        if ![
            "owner",
            "network_reviewer",
            "service_reviewer",
            "security_reviewer",
        ]
        .contains(&role)
        {
            return Err(AuthorityError::Invalid("role"));
        }
        roles.insert(role);
        let id = string(approval, "approval_id")?;
        let challenge = string(approval, "challenge_id")?;
        if !uuid_ok(id) || !uuid_ok(challenge) || !ids.insert(id) || !challenges.insert(challenge) {
            return Err(AuthorityError::Invalid("reused approval or challenge"));
        }
        let at = timestamp(string(approval, "created_at")?)?;
        let expiry = timestamp(string(approval, "expires_at")?)?;
        if at > created || at > now || now - at > max_age || expiry < valid_until || expiry <= now {
            return Err(AuthorityError::Time);
        }
        if !hash_ok(string(approval, "credential_registry_hash")?)
            || !hash_ok(string(approval, "role_membership_hash")?)
        {
            return Err(AuthorityError::Invalid("approval registry hashes"));
        }
        proof.verify_webauthn_and_current_role(approval, now)?;
    }
    if humans.len() < minimum || !required.is_subset(&roles) {
        return Err(AuthorityError::Invalid(
            "insufficient independent approvals or roles",
        ));
    }
    Ok(VerifiedApprovalSet {
        content: set.clone(),
        hash: canonical_hash(set)
            .map_err(|_| AuthorityError::Invalid("approval canonicalization"))?,
        valid_until,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct Reject;
    impl ProofVerifier for Reject {
        fn verify_webauthn_and_current_role(&self, _: &Value, _: i64) -> Result<()> {
            Err(AuthorityError::Signature)
        }
    }
    // Only the pure binding verifier is under test. This test double is not a WebAuthn implementation.
    struct FixtureProof;
    impl ProofVerifier for FixtureProof {
        fn verify_webauthn_and_current_role(&self, _: &Value, _: i64) -> Result<()> {
            Ok(())
        }
    }
    fn id(n: u128) -> String {
        uuid::Uuid::from_u128(n).to_string()
    }
    fn hash() -> String {
        format!("sha256:{}", "a".repeat(64))
    }
    fn fixture() -> (Value, Value, ApprovalContext) {
        let now = timestamp("2026-10-30T09:00:00Z").unwrap();
        let context = ApprovalContext {
            org_id: id(1),
            project_id: id(2),
            author_id: id(3),
            plan_id: id(4),
            plan_hash: hash(),
            plan_kind: "policy_change".into(),
            plan_valid_until: now + 300,
            authority_epoch: 1,
            now_unix: now,
        };
        let requirements = json!({"schema_version":"f.approval-requirements/v1","profile":"team_dual","minimum_humans":2,"required_roles":["network_reviewer","security_reviewer"],"distinct_principals":true,"author_may_approve":false,"max_approval_age_seconds":300,"require_webauthn":true,"role_policy_hash":hash()});
        let requirement_hash = canonical_hash(&requirements).unwrap();
        let reference = json!({"plan_kind":"policy_change","plan_id":id(4),"plan_hash":hash()});
        let approvals:Vec<_>=["network_reviewer","security_reviewer"].into_iter().enumerate().map(|(i,role)|json!({"approval_id":id(10+i as u128),"principal":{"principal_id":id(20+i as u128),"issuer":"https://issuer.example","subject":format!("reviewer-{i}"),"authentication_time":"2026-10-30T08:59:00Z"},"role":role,"decision":"approve","plan_ref":reference.clone(),"requirements_hash":requirement_hash,"challenge_id":id(30+i as u128),"assertion_evidence":{"restricted":true},"credential_registry_hash":hash(),"role_membership_hash":hash(),"created_at":"2026-10-30T08:59:00Z","expires_at":"2026-10-30T09:05:00Z"})).collect();
        let set = json!({"schema_version":"f.approval-set/v1","approval_set_id":id(50),"org_id":id(1),"project_id":id(2),"plan_ref":reference,"requirements_hash":requirement_hash,"created_at":"2026-10-30T09:00:00Z","valid_until":"2026-10-30T09:05:00Z","authority_epoch":"1","kind":"human","approvals":approvals,"role_policy_hash":hash()});
        (set, requirements, context)
    }
    #[test]
    fn verifies_immutable_binding_after_proof() {
        let (mut set, requirements, context) = fixture();
        let verified =
            verify_human_approval_set(&set, &requirements, &context, &FixtureProof).unwrap();
        let original = verified.hash().to_owned();
        set["plan_ref"]["plan_hash"] = format!("sha256:{}", "b".repeat(64)).into();
        assert_eq!(verified.hash(), original);
        assert!(verify_human_approval_set(&set, &requirements, &context, &FixtureProof).is_err());
    }
    #[test]
    fn unverified_or_revoked_proof_never_becomes_authority() {
        let (set, requirements, context) = fixture();
        assert!(matches!(
            verify_human_approval_set(&set, &requirements, &context, &Reject),
            Err(AuthorityError::Signature)
        ));
    }
    #[test]
    fn rejects_self_approval_and_duplicate_humans() {
        let (mut set, requirements, context) = fixture();
        set["approvals"][0]["principal"]["principal_id"] = context.author_id.clone().into();
        assert!(verify_human_approval_set(&set, &requirements, &context, &FixtureProof).is_err());
        set["approvals"][0]["principal"]["principal_id"] =
            set["approvals"][1]["principal"]["principal_id"].clone();
        assert!(verify_human_approval_set(&set, &requirements, &context, &FixtureProof).is_err());
    }
    #[test]
    fn rejects_stale_approval_epoch_and_requirement_substitution() {
        let (set, requirements, mut context) = fixture();
        context.authority_epoch = 2;
        assert!(verify_human_approval_set(&set, &requirements, &context, &FixtureProof).is_err());
        context.authority_epoch = 1;
        context.now_unix += 300;
        assert!(verify_human_approval_set(&set, &requirements, &context, &FixtureProof).is_err());
        context.now_unix -= 300;
        let mut changed = requirements;
        changed["minimum_humans"] = 3.into();
        assert!(verify_human_approval_set(&set, &changed, &context, &FixtureProof).is_err());
    }
    #[test]
    fn reject_decision_cannot_join_approval_set() {
        let (mut set, requirements, context) = fixture();
        set["approvals"][0]["decision"] = "reject".into();
        assert!(verify_human_approval_set(&set, &requirements, &context, &FixtureProof).is_err());
    }
    #[test]
    fn profiles_cannot_be_weakened() {
        for (profile, minimum, roles) in [
            ("lab_owner", 1, json!(["network_reviewer"])),
            ("team_dual", 2, json!(["owner", "security_reviewer"])),
            (
                "team_high_risk",
                2,
                json!(["network_reviewer", "security_reviewer"]),
            ),
            (
                "team_high_risk",
                3,
                json!(["owner", "network_reviewer", "security_reviewer"]),
            ),
        ] {
            let (mut set, mut requirements, context) = fixture();
            requirements["profile"] = profile.into();
            requirements["minimum_humans"] = minimum.into();
            requirements["required_roles"] = roles;
            let h = canonical_hash(&requirements).unwrap();
            set["requirements_hash"] = h.clone().into();
            for a in set["approvals"].as_array_mut().unwrap() {
                a["requirements_hash"] = h.clone().into();
            }
            assert!(
                verify_human_approval_set(&set, &requirements, &context, &FixtureProof).is_err()
            );
        }
    }
}
