//! Shared test-only mechanics fixture. Actual P-256 and Ed25519 verification,
//! synthetic native bytes and no production qualification or trusted host.
#![allow(dead_code)]

pub(super) use super::sets::budget_authenticator as authenticator;
#[path = "../../tests/support/native_fixture.rs"]
pub(super) mod native;
#[path = "../../tests/support/private_directory.rs"]
pub(super) mod private_directory;

use super::*;
use crate::{ApprovalDecision, ApprovalRole, AuthorityBasis};
use authenticator::{Authenticator, ORIGIN, PRINCIPAL};
use fw_backend_linux::LabReferences;
use fw_native_evidence::ArtifactRole;
use fw_planner::PolicyReviewEvidence;
use std::path::PathBuf;

pub(super) const NOW: i64 = 1_800_000_000;

pub(super) struct Fixture {
    pub now: i64,
    pub directory: tempfile::TempDir,
    pub path: PathBuf,
    pub store: AuthorityStore,
    pub tenant: AuthorityTenant,
    pub verifier: WebAuthn,
    pub plan: Value,
    pub requirements: Value,
    pub review: PolicyReviewEvidence,
    pub references: LabReferences,
    pub credential_id: String,
    pub membership_id: String,
    pub current_approval_hash: String,
    pub baseline_receipt_hash: String,
    pub principal_key: Authenticator,
    counter: u32,
}

impl Fixture {
    pub fn new() -> Self {
        Self::at(NOW)
    }

    pub fn at(now: i64) -> Self {
        let directory = private_directory::private_directory();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let (tenant, plan, requirements, review, references) = native::setup(&mut store, now);
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        store
            .provision_principal(
                &tenant,
                PRINCIPAL,
                "https://signing.fixture.example",
                PRINCIPAL,
                now,
            )
            .unwrap();
        let principal_key = Authenticator::new(PRINCIPAL);
        let registration = verifier
            .begin_registration(PRINCIPAL, "Signing fixture", &[])
            .unwrap();
        let credential = verifier
            .finish_registration(
                &registration.state,
                &principal_key.registration(&registration.options),
            )
            .unwrap();
        let credential_id = credential.id();
        store
            .pin_credential(&tenant, &credential, now, now + 7200, now)
            .unwrap();
        let activation = store
            .begin_credential_activation(&tenant, &credential_id, &verifier, now)
            .unwrap();
        store
            .finish_credential_activation(
                &tenant,
                &activation.activation_id,
                &principal_key.assertion(&activation.options, 1, 5, ORIGIN),
                &verifier,
                now,
            )
            .unwrap();
        let membership_id = store
            .grant_role(
                &tenant,
                PRINCIPAL,
                ApprovalRole::Owner,
                now,
                now + 7200,
                now,
            )
            .unwrap();
        store
            .bind_human_identity(&tenant, PRINCIPAL, PRINCIPAL, now)
            .unwrap();
        store
            .provision_authority_basis(
                &tenant,
                &AuthorityBasis {
                    epoch: 1,
                    role_policy_hash: requirements["role_policy_hash"].as_str().unwrap().into(),
                    not_before: now,
                    not_after: now + 7200,
                },
                now,
            )
            .unwrap();
        store
            .register_native_compilation(&tenant, native::PLAN, 1, now)
            .unwrap();
        let compilation =
            fw_native_evidence::compile_evidence(&plan, &review, &references).unwrap();
        let installation = native::installation(compilation.baseline(), now);
        let challenge = store
            .challenge_native_observation(
                &tenant,
                native::PLAN,
                ArtifactRole::Baseline,
                &installation,
                None,
                1,
                1,
                now,
            )
            .unwrap();
        let proof = native::proof(
            &challenge,
            installation.clone(),
            native::snapshot(&installation.native),
            now,
        );
        let observation = store
            .admit_native_observation(&tenant, &proof, now)
            .unwrap();
        assert_eq!(observation.receipt.comparison, "match");
        assert_eq!(
            observation.receipt.observed_state_hash.as_deref(),
            plan["baseline_hash"].as_str()
        );
        assert!(!observation.receipt.production_qualified);
        assert!(!observation.receipt.dispatch_allowed);
        let mut fixture = Self {
            now,
            directory,
            path,
            store,
            tenant,
            verifier,
            plan,
            requirements,
            review,
            references,
            credential_id,
            membership_id,
            current_approval_hash: String::new(),
            baseline_receipt_hash: observation.receipt_hash,
            principal_key,
            counter: 1,
        };
        fixture.current_approval_hash = fixture.approve(native::PLAN, now);
        fixture
    }

    pub fn approve(&mut self, plan_id: &str, now: i64) -> String {
        let challenge = self
            .store
            .issue_challenge(
                &self.tenant,
                PRINCIPAL,
                &self.credential_id,
                plan_id,
                ApprovalRole::Owner,
                ApprovalDecision::Approve,
                &self.verifier,
                now,
            )
            .unwrap();
        self.counter += 1;
        let assertion = self
            .principal_key
            .assertion(&challenge.options, self.counter, 5, ORIGIN);
        self.store
            .admit_decision(
                &self.tenant,
                PRINCIPAL,
                challenge.challenge.challenge_id(),
                &uuid::Uuid::from_u128(0x10000 + u128::from(self.counter)).to_string(),
                &assertion,
                &self.verifier,
                now,
            )
            .unwrap();
        self.store
            .current_approval_set(&self.tenant, plan_id, &self.verifier, now)
            .unwrap()
            .unwrap()
            .hash()
            .into()
    }

    pub fn reopen(&mut self) {
        self.store = AuthorityStore::open(&self.path).unwrap();
    }

    pub fn count(&self, table: &str) -> i64 {
        Connection::open(&self.path)
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }
}

#[test]
fn genuine_signed_fixture_retains_unqualified_baseline_and_current_human_approval() {
    let mut f = Fixture::new();
    f.reopen();
    assert_eq!(
        f.store
            .current_approval_set(&f.tenant, native::PLAN, &f.verifier, NOW)
            .unwrap()
            .unwrap()
            .hash(),
        f.current_approval_hash
    );
    let status = f
        .store
        .native_evidence_status(&f.tenant, native::PLAN, NOW)
        .unwrap();
    assert!(!status.production_qualified);
    assert!(!status.dispatch_allowed);
    assert_eq!(
        status.observation_head_hash.as_deref(),
        Some(f.baseline_receipt_hash.as_str())
    );
    let observation = status.observation.unwrap();
    assert!(observation.current);
    assert_eq!(observation.artifact_role, ArtifactRole::Baseline);
    assert_eq!(observation.comparison, "match");
}
