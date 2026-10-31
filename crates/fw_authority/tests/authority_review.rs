#![cfg(feature = "approval-proofs")]

//! Real signatures against the durable authority transaction. These software
//! authenticators establish storage and verifier behavior, not human consent or
//! the deployment's operating-system trust boundary.
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;

use approval_authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_authority::{ApprovalRole, AuthorityStore, AuthorityTenant};
use fw_webauthn::{Credential, WebAuthn};
use serde_json::{Value, json};

use tempfile::TempDir;

const NOW: i64 = 1_700_000_000;
const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const PLAN: &str = "44444444-4444-4444-8444-444444444444";
const OTHER: &str = "99999999-9999-4999-8999-999999999999";

fn time(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn requirements() -> Value {
    json!({
        "schema_version": "f.approval-requirements/v1",
        "profile": "lab_owner", "minimum_humans": 1,
        "required_roles": ["owner"], "distinct_principals": true,
        "author_may_approve": true, "max_approval_age_seconds": 3600,
        "require_webauthn": true,
        "role_policy_hash": fw_contracts::hash_bytes(b"independently configured role policy")
    })
}

fn plan(requirements: &Value) -> Value {
    let hash = fw_contracts::hash_bytes(b"synthetic immutable plan evidence");
    let operations = json!([{
        "op": "remove_policy", "policy_id": OTHER, "expected_revision": 1,
        "expected_policy_hash": hash
    }]);
    let gates: Vec<Value> = [
        "schema",
        "identity",
        "scope",
        "quota",
        "semantic",
        "expiry",
        "capability",
        "baseline",
    ]
    .into_iter()
    .map(|gate| {
        json!({
            "gate_id": gate, "required": true, "result": "PASS", "evidence_hash": hash
        })
    })
    .collect();
    json!({
        "schema_version": "f.policy-change-plan/v1", "change_kind": "policy_change",
        "plan_id": PLAN, "request_id": OTHER, "request_revision": 1, "request_hash": hash,
        "org_id": ORG, "project_id": PROJECT, "target_id": OTHER, "principal_id": PRINCIPAL,
        "created_at": time(NOW), "valid_until": time(NOW + 3600),
        "request_patch_hash": fw_contracts::canonical_hash(&operations).unwrap(),
        "operations": operations,
        "baseline_hash": hash, "desired_state_hash": hash,
        "candidate_state_ref": {
            "store_id": "authority_test", "object_hash": hash,
            "media_type": "application/json", "size_bytes": 128
        },
        "source_snapshot_hash": hash, "target_capability_hash": hash,
        "guardrail_hash": hash, "compiler_hash": hash, "validator_hash": hash,
        "artifact_hash": hash, "validation_report_hash": hash,
        "effect_summary": {
            "relation": "restricting", "newly_allowed_region_hash": hash,
            "removed_region_hash": hash, "counterexample_hashes": [],
            "analysis_profile": "native-union-minus-deny/v1", "complete": true
        },
        "gates": gates,
        "approval_requirements_hash": fw_contracts::canonical_hash(requirements).unwrap(),
        "probe_spec_hash": hash, "authority_epoch": "1", "target_generation": "1",
        "confirm_timeout_seconds": 60,
        "rollback_authority": {
            "profile": "preserve-current-restrictions", "scope_bound_hash": hash,
            "baseline_hash": hash, "artifact_hash": hash, "valid_until": time(NOW + 3600)
        },
        "normalization_version": "f.normalize/nfc-v1"
    })
}

struct Fixture {
    _directory: TempDir,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    verifier: WebAuthn,
    key: Authenticator,
    credential: Credential,
    membership: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with_counter(1)
    }

    fn with_counter(counter: u32) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Authority test key", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        store
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://identity.example.test",
                "reviewer-alice",
                NOW,
            )
            .unwrap();
        store
            .pin_credential(&tenant, &credential, NOW, NOW + 7200, NOW)
            .unwrap();
        let activation = store
            .begin_credential_activation(&tenant, &credential.id(), &verifier, NOW)
            .unwrap();
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &key.assertion(&activation.options, counter, 0x05, ORIGIN),
                &verifier,
                NOW,
            )
            .unwrap();
        let membership = store
            .grant_role(
                &tenant,
                PRINCIPAL,
                ApprovalRole::Owner,
                NOW,
                NOW + 7200,
                NOW,
            )
            .unwrap();
        let requirements = requirements();
        store
            .register_plan(&tenant, &plan(&requirements), &requirements, NOW)
            .unwrap();
        Self {
            _directory: directory,
            store,
            tenant,
            verifier,
            key,
            credential,
            membership,
        }
    }
}

#[test]
fn login_verifies_pinned_key_updates_counter_and_current_roles() {
    let mut f = Fixture::new();
    let login = f
        .store
        .begin_review_login(
            &f.tenant,
            PRINCIPAL,
            &f.credential.id(),
            &f.verifier,
            NOW + 1,
        )
        .unwrap();
    let proof = f.key.assertion(&login.options, 2, 0x05, ORIGIN);
    f.store
        .finish_review_login(&f.tenant, &login, &proof, &f.verifier, NOW + 2)
        .unwrap();
    assert!(
        f.store
            .finish_review_login(&f.tenant, &login, &proof, &f.verifier, NOW + 2)
            .is_err()
    );
    let profile = f
        .store
        .review_profile(&f.tenant, PRINCIPAL, &f.credential.id(), NOW + 2)
        .unwrap();
    assert_eq!(profile.roles, vec![ApprovalRole::Owner]);
    let detail = f
        .store
        .review_plan(&f.tenant, PRINCIPAL, PLAN, NOW + 2)
        .unwrap();
    assert_eq!(detail.plan["plan_id"], PLAN);
    assert_eq!(detail.plan["operations"][0]["op"], "remove_policy");
    f.store
        .revoke_role(&f.tenant, &f.membership, NOW + 3)
        .unwrap();
    assert!(
        f.store
            .review_profile(&f.tenant, PRINCIPAL, &f.credential.id(), NOW + 3)
            .is_err()
    );
    assert!(
        f.store
            .review_plan(&f.tenant, PRINCIPAL, PLAN, NOW + 3)
            .is_err()
    );
}

#[test]
fn login_rejects_wrong_key_stale_snapshot_expiry_and_cross_tenant() {
    let mut f = Fixture::new();
    let login = f
        .store
        .begin_review_login(
            &f.tenant,
            PRINCIPAL,
            &f.credential.id(),
            &f.verifier,
            NOW + 1,
        )
        .unwrap();
    let bad = Authenticator::new(PRINCIPAL).assertion(&login.options, 2, 0x05, ORIGIN);
    assert!(
        f.store
            .finish_review_login(&f.tenant, &login, &bad, &f.verifier, NOW + 2)
            .is_err()
    );
    let connection =
        rusqlite::Connection::open(f._directory.path().join("authority.sqlite3")).unwrap();
    let failures: i64 = connection
        .query_row(
            "SELECT count(*) FROM authority_audit WHERE kind='review_login_failed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        failures, 1,
        "invalid active-key proof must retain an authentication failure event"
    );
    let proof = f.key.assertion(&login.options, 2, 0x05, ORIGIN);
    let other = AuthorityTenant::new(ORG, OTHER).unwrap();
    assert!(
        f.store
            .finish_review_login(&other, &login, &proof, &f.verifier, NOW + 2)
            .is_err()
    );
    assert!(
        f.store
            .finish_review_login(&f.tenant, &login, &proof, &f.verifier, NOW + 301)
            .is_err()
    );
    f.store
        .revoke_credential(&f.tenant, &f.credential.id(), NOW + 3)
        .unwrap();
    assert!(
        f.store
            .finish_review_login(&f.tenant, &login, &proof, &f.verifier, NOW + 3)
            .is_err()
    );
}
