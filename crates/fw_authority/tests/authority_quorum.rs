#![cfg(feature = "approval-proofs")]
//! Real cryptographic decisions and complete atomic quorum admission. Software
//! authenticators verify mechanics; trusted human enrollment is fixture input.
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
use approval_authenticator::{Authenticator, ORIGIN, PRINCIPAL};
#[path = "support/authority_legacy.rs"]
mod authority_legacy;
use fw_authority::{
    AggregationOutcome, ApprovalDecision, ApprovalRole, AuthorityBasis, AuthorityStore,
    AuthorityTenant, DecisionResult, IssuedApproval,
};
use fw_webauthn::{AuthenticationResponse, Credential, WebAuthn};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};
const NOW: i64 = 1_700_000_000;
const ORG: &str = "22222222-2222-4222-8222-222222222222";
const PROJECT: &str = "33333333-3333-4333-8333-333333333333";
const PLAN: &str = "44444444-4444-4444-8444-444444444444";
const OTHER: &str = "99999999-9999-4999-8999-999999999999";
const AUTHOR: &str = PRINCIPAL;
const ALICE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CAROL: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const DAVE: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
fn time(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn requirements(profile: &str, roles: &[ApprovalRole]) -> Value {
    json!({
        "schema_version": "f.approval-requirements/v1",
        "profile": profile, "minimum_humans": roles.len(),
        "required_roles": roles, "distinct_principals": true,
        "author_may_approve": profile=="lab_owner", "max_approval_age_seconds": 180,
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
        "org_id": ORG, "project_id": PROJECT, "target_id": OTHER, "principal_id": AUTHOR,
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

struct Person {
    key: Authenticator,
    credential: Credential,
    counter: u32,
}
struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    verifier: WebAuthn,
    people: BTreeMap<String, Person>,
    memberships: BTreeMap<(String, String), String>,
    requirements: Value,
}
impl Fixture {
    fn new(profile: &str, roles: &[ApprovalRole], basis: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.sqlite3");
        let store = AuthorityStore::open(&path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        let verifier = WebAuthn::new(ORIGIN).unwrap();
        let req = requirements(profile, roles);
        let mut f = Self {
            _directory: directory,
            path,
            store,
            tenant,
            verifier,
            people: BTreeMap::new(),
            memberships: BTreeMap::new(),
            requirements: req,
        };
        f.add(AUTHOR, &[ApprovalRole::Owner], Some(AUTHOR));
        f.store
            .register_plan(&f.tenant, &plan(&f.requirements), &f.requirements, NOW)
            .unwrap();
        if basis {
            f.store
                .provision_authority_basis(&f.tenant, &f.basis(1), NOW)
                .unwrap();
        }
        f
    }
    fn basis(&self, epoch: u64) -> AuthorityBasis {
        AuthorityBasis {
            epoch,
            role_policy_hash: self.requirements["role_policy_hash"]
                .as_str()
                .unwrap()
                .into(),
            not_before: NOW,
            not_after: NOW + 3600,
        }
    }
    fn dual() -> Self {
        let mut f = Self::new(
            "team_dual",
            &[ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer],
            true,
        );
        f.add(ALICE, &[ApprovalRole::NetworkReviewer], Some(ALICE));
        f.add(BOB, &[ApprovalRole::ServiceReviewer], Some(BOB));
        f.add(CAROL, &[ApprovalRole::ServiceReviewer], Some(CAROL));
        f
    }
    fn add(&mut self, id: &str, roles: &[ApprovalRole], human: Option<&str>) {
        self.store
            .provision_principal(
                &self.tenant,
                id,
                "https://fixture.identity.example",
                id,
                NOW,
            )
            .unwrap();
        let key = Authenticator::new(id);
        let registration = self
            .verifier
            .begin_registration(id, "Fixture human", &[])
            .unwrap();
        let credential = self
            .verifier
            .finish_registration(
                &registration.state,
                &key.registration(&registration.options),
            )
            .unwrap();
        self.store
            .pin_credential(&self.tenant, &credential, NOW, NOW + 3600, NOW)
            .unwrap();
        let activation = self
            .store
            .begin_credential_activation(&self.tenant, &credential.id(), &self.verifier, NOW)
            .unwrap();
        self.store
            .finish_credential_activation(
                &self.tenant,
                &activation.activation_id,
                &key.assertion(&activation.options, 1, 5, ORIGIN),
                &self.verifier,
                NOW,
            )
            .unwrap();
        for role in roles {
            let membership = self
                .store
                .grant_role(&self.tenant, id, *role, NOW, NOW + 3600, NOW)
                .unwrap();
            self.memberships.insert(
                (id.into(), serde_json::to_string(role).unwrap()),
                membership,
            );
        }
        if let Some(human) = human {
            self.store
                .bind_human_identity(&self.tenant, id, human, NOW)
                .unwrap();
        }
        self.people.insert(
            id.into(),
            Person {
                key,
                credential,
                counter: 1,
            },
        );
    }
    fn prepare(
        &mut self,
        id: &str,
        role: ApprovalRole,
        decision: ApprovalDecision,
        now: i64,
    ) -> (IssuedApproval, AuthenticationResponse, String) {
        let person = self.people.get_mut(id).unwrap();
        let issued = self
            .store
            .issue_challenge(
                &self.tenant,
                id,
                &person.credential.id(),
                PLAN,
                role,
                decision,
                &self.verifier,
                now,
            )
            .unwrap();
        person.counter += 1;
        let response = person
            .key
            .assertion(&issued.options, person.counter, 5, ORIGIN);
        let idempotency = uuid::Uuid::from_u128(
            (person.counter as u128) << 64 | id.as_bytes()[0] as u128 | 0x1000,
        )
        .to_string();
        (issued, response, idempotency)
    }
    fn vote(
        &mut self,
        id: &str,
        role: ApprovalRole,
        decision: ApprovalDecision,
        now: i64,
    ) -> DecisionResult {
        let (issued, response, key) = self.prepare(id, role, decision, now);
        self.store
            .admit_decision(
                &self.tenant,
                id,
                issued.challenge.challenge_id(),
                &key,
                &response,
                &self.verifier,
                now,
            )
            .unwrap()
    }
    fn current(&mut self, now: i64) -> Option<Value> {
        self.store
            .current_approval_set(&self.tenant, PLAN, &self.verifier, now)
            .unwrap()
            .map(|s| s.content().clone())
    }
    fn count(&self, table: &str) -> i64 {
        Connection::open(&self.path)
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
}

#[test]
fn lab_owner_forms_one_immutable_set_with_the_original_contract() {
    let mut f = Fixture::new("lab_owner", &[ApprovalRole::Owner], true);
    let decision = f.vote(
        AUTHOR,
        ApprovalRole::Owner,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    let AggregationOutcome::Approved {
        approval_set_hash, ..
    } = decision.aggregation
    else {
        panic!("owner should satisfy explicit lab profile");
    };
    let set = f.current(NOW + 1).unwrap();
    assert_eq!(set["kind"], "human");
    assert_eq!(set["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(set["authority_epoch"], "1");
    assert_eq!(
        fw_contracts::canonical_hash(&set).unwrap(),
        approval_set_hash
    );
    assert_eq!(set["valid_until"], time(NOW + 181));
    println!(
        "QUORUM_SCHEMA_FIXTURE={}",
        serde_json::to_string(&set).unwrap()
    );
}

#[test]
fn decision_without_independent_epoch_basis_never_forms_quorum() {
    let mut f = Fixture::new("lab_owner", &[ApprovalRole::Owner], false);
    let decision = f.vote(
        AUTHOR,
        ApprovalRole::Owner,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    assert_eq!(
        decision.aggregation,
        AggregationOutcome::AuthorityUnavailable
    );
    assert!(f.current(NOW + 1).is_none());
    assert_eq!(f.count("authority_approval_sets"), 0);
    // A pinned epoch is independently checked; the plan cannot choose it.
    f.store
        .provision_authority_basis(&f.tenant, &f.basis(2), NOW + 2)
        .unwrap();
    let decision = f.vote(
        AUTHOR,
        ApprovalRole::Owner,
        ApprovalDecision::Approve,
        NOW + 3,
    );
    assert_eq!(decision.aggregation, AggregationOutcome::Stale);
    assert!(f.current(NOW + 3).is_none());
}

#[test]
fn dual_and_high_risk_profiles_require_all_distinct_current_roles() {
    for roles in [
        vec![ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer],
        vec![
            ApprovalRole::NetworkReviewer,
            ApprovalRole::SecurityReviewer,
        ],
        vec![
            ApprovalRole::NetworkReviewer,
            ApprovalRole::ServiceReviewer,
            ApprovalRole::SecurityReviewer,
        ],
    ] {
        let mut f = Fixture::new(
            if roles.len() == 2 {
                "team_dual"
            } else {
                "team_high_risk"
            },
            &roles,
            true,
        );
        for (id, role) in [ALICE, BOB, CAROL].iter().zip(&roles) {
            f.add(id, &[*role], Some(id));
        }
        for (position, (id, role)) in [ALICE, BOB, CAROL].iter().zip(&roles).enumerate() {
            let result = f.vote(
                id,
                *role,
                ApprovalDecision::Approve,
                NOW + 1 + position as i64,
            );
            if position + 1 < roles.len() {
                assert_eq!(result.aggregation, AggregationOutcome::Pending);
                assert!(f.current(NOW + 3).is_none());
            } else {
                assert!(matches!(
                    result.aggregation,
                    AggregationOutcome::Approved { .. }
                ));
            }
        }
        assert_eq!(
            f.current(NOW + 3).unwrap()["approvals"]
                .as_array()
                .unwrap()
                .len(),
            roles.len()
        );
        assert_eq!(f.count("authority_approval_sets"), 1);
    }
}

#[test]
fn credential_and_issuer_aliases_of_one_human_do_not_add_independent_people() {
    let mut f = Fixture::new(
        "team_dual",
        &[ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer],
        true,
    );
    f.add(ALICE, &[ApprovalRole::NetworkReviewer], Some(ALICE));
    f.add(BOB, &[ApprovalRole::ServiceReviewer], Some(ALICE));
    f.add(CAROL, &[ApprovalRole::ServiceReviewer], Some(CAROL));
    assert_eq!(
        f.vote(
            ALICE,
            ApprovalRole::NetworkReviewer,
            ApprovalDecision::Approve,
            NOW + 1
        )
        .aggregation,
        AggregationOutcome::Pending
    );
    assert_eq!(
        f.vote(
            BOB,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 2
        )
        .aggregation,
        AggregationOutcome::Pending
    );
    assert!(f.current(NOW + 2).is_none());
    assert!(matches!(
        f.vote(
            CAROL,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 3
        )
        .aggregation,
        AggregationOutcome::Approved { .. }
    ));
}

#[test]
fn author_alias_is_rejected_before_a_team_challenge_can_be_issued() {
    let mut f = Fixture::new(
        "team_dual",
        &[ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer],
        true,
    );
    f.add(ALICE, &[ApprovalRole::NetworkReviewer], Some(AUTHOR));
    assert!(
        f.store
            .issue_challenge(
                &f.tenant,
                ALICE,
                &f.people[ALICE].credential.id(),
                PLAN,
                ApprovalRole::NetworkReviewer,
                ApprovalDecision::Approve,
                &f.verifier,
                NOW + 1
            )
            .is_err()
    );
    assert_eq!(f.count("authority_challenges"), 0);
}

#[test]
fn role_matching_backtracks_when_one_human_can_fill_either_seat() {
    let mut f = Fixture::new(
        "team_dual",
        &[ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer],
        true,
    );
    f.add(
        ALICE,
        &[ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer],
        Some(ALICE),
    );
    f.add(BOB, &[ApprovalRole::NetworkReviewer], Some(BOB));
    f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    assert_eq!(
        f.vote(
            ALICE,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 2
        )
        .aggregation,
        AggregationOutcome::Pending
    );
    f.vote(
        BOB,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 3,
    );
    let set = f.current(NOW + 3).unwrap();
    let people: BTreeMap<_, _> = set["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["role"].as_str().unwrap(),
                a["principal"]["principal_id"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(people["network_reviewer"], BOB);
    assert_eq!(people["service_reviewer"], ALICE);
}

#[test]
fn signed_dissent_is_not_erased_by_key_revocation_expiry_or_a_later_approval() {
    let mut f = Fixture::dual();
    assert_eq!(
        f.vote(
            BOB,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Reject,
            NOW + 1
        )
        .aggregation,
        AggregationOutcome::BlockedByDissent
    );
    f.store
        .revoke_credential(&f.tenant, &f.people[BOB].credential.id(), NOW + 2)
        .unwrap();
    assert_eq!(
        f.vote(
            ALICE,
            ApprovalRole::NetworkReviewer,
            ApprovalDecision::Approve,
            NOW + 200
        )
        .aggregation,
        AggregationOutcome::BlockedByDissent
    );
    assert_eq!(
        f.vote(
            CAROL,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 201
        )
        .aggregation,
        AggregationOutcome::BlockedByDissent
    );
    assert!(f.current(NOW + 201).is_none());
    assert_eq!(f.count("authority_approval_sets"), 0);
}

#[test]
fn late_dissent_makes_a_previously_complete_set_stale_without_changing_it() {
    let mut f = Fixture::dual();
    f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    f.vote(
        BOB,
        ApprovalRole::ServiceReviewer,
        ApprovalDecision::Approve,
        NOW + 2,
    );
    let original = stored_sets(&f.path);
    assert_eq!(
        f.vote(
            CAROL,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Reject,
            NOW + 3
        )
        .aggregation,
        AggregationOutcome::BlockedByDissent
    );
    assert!(f.current(NOW + 3).is_none());
    assert_eq!(stored_sets(&f.path), original);
}

fn stored_sets(path: &std::path::Path) -> Vec<Vec<u8>> {
    Connection::open(path).unwrap().prepare("SELECT canonical_bytes FROM authority_approval_sets ORDER BY created_at,approval_set_id").unwrap()
        .query_map([],|r|r.get(0)).unwrap().collect::<Result<_,_>>().unwrap()
}

#[test]
fn fresh_votes_after_expiry_append_a_new_set_and_replays_keep_original_outcomes() {
    let mut f = Fixture::dual();
    let (issued, assertion, key) = f.prepare(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    let first = f
        .store
        .admit_decision(
            &f.tenant,
            ALICE,
            issued.challenge.challenge_id(),
            &key,
            &assertion,
            &f.verifier,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(first.aggregation, AggregationOutcome::Pending);
    f.vote(
        BOB,
        ApprovalRole::ServiceReviewer,
        ApprovalDecision::Approve,
        NOW + 2,
    );
    let old = stored_sets(&f.path);
    assert!(f.current(NOW + 181).is_none());
    assert_eq!(
        f.vote(
            ALICE,
            ApprovalRole::NetworkReviewer,
            ApprovalDecision::Approve,
            NOW + 182
        )
        .aggregation,
        AggregationOutcome::Pending
    );
    assert!(matches!(
        f.vote(
            BOB,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 183
        )
        .aggregation,
        AggregationOutcome::Approved { .. }
    ));
    assert_eq!(f.count("authority_approval_sets"), 2);
    assert_eq!(stored_sets(&f.path)[0], old[0]);
    let replay = f
        .store
        .admit_decision(
            &f.tenant,
            ALICE,
            issued.challenge.challenge_id(),
            &key,
            &assertion,
            &f.verifier,
            NOW + 184,
        )
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.aggregation, AggregationOutcome::Pending);
    assert_eq!(f.count("authority_approval_sets"), 2);
}

#[test]
fn revoked_member_cannot_authorize_current_set_but_new_person_can_supply_a_new_vote() {
    let mut f = Fixture::dual();
    f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    f.vote(
        BOB,
        ApprovalRole::ServiceReviewer,
        ApprovalDecision::Approve,
        NOW + 2,
    );
    let old = stored_sets(&f.path);
    f.store
        .revoke_credential(&f.tenant, &f.people[BOB].credential.id(), NOW + 3)
        .unwrap();
    assert!(f.current(NOW + 3).is_none());
    assert!(matches!(
        f.vote(
            CAROL,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 4
        )
        .aggregation,
        AggregationOutcome::Approved { .. }
    ));
    assert_eq!(stored_sets(&f.path)[0], old[0]);
    assert_eq!(f.count("authority_approval_sets"), 2);
    let membership = f.memberships[&(
        ALICE.into(),
        serde_json::to_string(&ApprovalRole::NetworkReviewer).unwrap(),
    )]
        .clone();
    f.store
        .revoke_role(&f.tenant, &membership, NOW + 5)
        .unwrap();
    assert!(f.current(NOW + 5).is_none());
}

#[test]
fn epoch_and_role_policy_changes_invalidate_sets_and_never_regress() {
    let mut f = Fixture::new("lab_owner", &[ApprovalRole::Owner], true);
    f.vote(
        AUTHOR,
        ApprovalRole::Owner,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    let before = stored_sets(&f.path);
    let mut changed = f.basis(1);
    changed.role_policy_hash = fw_contracts::hash_bytes(b"different trusted role policy");
    assert!(
        f.store
            .provision_authority_basis(&f.tenant, &changed, NOW + 2)
            .is_err()
    );
    changed.epoch = u64::MAX;
    f.store
        .provision_authority_basis(&f.tenant, &changed, NOW + 2)
        .unwrap();
    assert!(f.current(NOW + 2).is_none());
    assert_eq!(stored_sets(&f.path), before);
    assert!(
        f.store
            .provision_authority_basis(&f.tenant, &f.basis(1), NOW + 3)
            .is_err()
    );
}

#[test]
fn concurrent_final_reviewers_converge_on_one_set_under_the_same_transaction() {
    let mut f = Fixture::dual();
    f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    let approvals = [
        (
            BOB,
            f.prepare(
                BOB,
                ApprovalRole::ServiceReviewer,
                ApprovalDecision::Approve,
                NOW + 2,
            ),
        ),
        (
            CAROL,
            f.prepare(
                CAROL,
                ApprovalRole::ServiceReviewer,
                ApprovalDecision::Approve,
                NOW + 2,
            ),
        ),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let threads = approvals
        .into_iter()
        .map(|(person, (issued, assertion, key))| {
            let path = f.path.clone();
            let tenant = f.tenant.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                let verifier = WebAuthn::new(ORIGIN).unwrap();
                barrier.wait();
                store
                    .admit_decision(
                        &tenant,
                        person,
                        issued.challenge.challenge_id(),
                        &key,
                        &assertion,
                        &verifier,
                        NOW + 2,
                    )
                    .unwrap()
                    .aggregation
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results[0], results[1]);
    assert!(matches!(results[0], AggregationOutcome::Approved { .. }));
    assert_eq!(f.count("authority_approval_sets"), 1);
    assert_eq!(f.count("authority_decisions"), 3);
}

#[test]
fn simultaneous_rejection_and_final_approval_never_leave_current_authority() {
    let mut f = Fixture::dual();
    f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    let approvals = [
        (
            BOB,
            f.prepare(
                BOB,
                ApprovalRole::ServiceReviewer,
                ApprovalDecision::Approve,
                NOW + 2,
            ),
        ),
        (
            CAROL,
            f.prepare(
                CAROL,
                ApprovalRole::ServiceReviewer,
                ApprovalDecision::Reject,
                NOW + 2,
            ),
        ),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let threads = approvals
        .into_iter()
        .map(|(person, (issued, assertion, key))| {
            let path = f.path.clone();
            let tenant = f.tenant.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                let verifier = WebAuthn::new(ORIGIN).unwrap();
                barrier.wait();
                store
                    .admit_decision(
                        &tenant,
                        person,
                        issued.challenge.challenge_id(),
                        &key,
                        &assertion,
                        &verifier,
                        NOW + 2,
                    )
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    for task in threads {
        task.join().unwrap();
    }
    assert!(f.current(NOW + 3).is_none());
    assert_eq!(f.count("authority_decisions"), 3);
    assert!(f.count("authority_approval_sets") <= 1);
}

#[test]
fn trusted_identity_binding_does_not_itself_create_an_approval_set() {
    let mut f = Fixture::new(
        "team_dual",
        &[ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer],
        true,
    );
    f.add(ALICE, &[ApprovalRole::NetworkReviewer], Some(ALICE));
    f.add(DAVE, &[ApprovalRole::ServiceReviewer], None);
    f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    assert_eq!(
        f.vote(
            DAVE,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 2
        )
        .aggregation,
        AggregationOutcome::AuthorityUnavailable
    );
    f.store
        .bind_human_identity(&f.tenant, DAVE, DAVE, NOW + 3)
        .unwrap();
    assert_eq!(f.count("authority_approval_sets"), 0);
    assert!(matches!(
        f.vote(
            DAVE,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 4
        )
        .aggregation,
        AggregationOutcome::Approved { .. }
    ));
    assert!(
        f.store
            .bind_human_identity(&f.tenant, DAVE, ALICE, NOW + 5)
            .is_err()
    );
}

#[test]
fn review_status_reads_one_snapshot_without_creating_or_renewing_sets() {
    let mut f = Fixture::new("lab_owner", &[ApprovalRole::Owner], false);
    let read = |f: &mut Fixture, now| {
        let before = snapshot(&f.path);
        let result = f
            .store
            .approval_review_status(&f.tenant, PLAN, &f.verifier, now)
            .unwrap();
        assert_eq!(before, snapshot(&f.path));
        (result.0, result.1.map(|s| s.content().clone()))
    };
    assert_eq!(
        read(&mut f, NOW).0,
        AggregationOutcome::AuthorityUnavailable
    );
    f.store
        .provision_authority_basis(&f.tenant, &f.basis(1), NOW)
        .unwrap();
    assert_eq!(read(&mut f, NOW).0, AggregationOutcome::Pending);
    let accepted = f.vote(
        AUTHOR,
        ApprovalRole::Owner,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    let (status, content) = read(&mut f, NOW + 1);
    assert_eq!(status, accepted.aggregation);
    assert_eq!(content, f.current(NOW + 1));
    let expired = read(&mut f, NOW + 181);
    assert_eq!(expired.0, AggregationOutcome::Pending);
    assert!(expired.1.is_none());
    assert_eq!(f.count("authority_approval_sets"), 1);
    let original = content.unwrap();
    let original_bytes: Vec<u8> = Connection::open(&f.path)
        .unwrap()
        .query_row(
            "SELECT canonical_bytes FROM authority_approval_sets WHERE approval_set_id=?",
            [original["approval_set_id"].as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    let refreshed = f.vote(
        AUTHOR,
        ApprovalRole::Owner,
        ApprovalDecision::Approve,
        NOW + 182,
    );
    assert_eq!(read(&mut f, NOW + 182).0, refreshed.aggregation);
    assert_eq!(f.count("authority_approval_sets"), 2);
    assert_ne!(
        f.current(NOW + 182).unwrap()["approval_set_id"],
        original["approval_set_id"]
    );
    let retained_bytes: Vec<u8> = Connection::open(&f.path)
        .unwrap()
        .query_row(
            "SELECT canonical_bytes FROM authority_approval_sets WHERE approval_set_id=?",
            [original["approval_set_id"].as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(original_bytes, retained_bytes);
    f.vote(
        AUTHOR,
        ApprovalRole::Owner,
        ApprovalDecision::Reject,
        NOW + 183,
    );
    assert_eq!(
        read(&mut f, NOW + 183).0,
        AggregationOutcome::BlockedByDissent
    );
    assert_eq!(
        read(&mut f, NOW + 3600).0,
        AggregationOutcome::BlockedByDissent
    );

    let mut f = Fixture::new(
        "team_dual",
        &[ApprovalRole::NetworkReviewer, ApprovalRole::ServiceReviewer],
        true,
    );
    f.add(ALICE, &[ApprovalRole::NetworkReviewer], Some(ALICE));
    f.add(DAVE, &[ApprovalRole::ServiceReviewer], None);
    f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    f.vote(
        DAVE,
        ApprovalRole::ServiceReviewer,
        ApprovalDecision::Approve,
        NOW + 2,
    );
    assert_eq!(
        read(&mut f, NOW + 2).0,
        AggregationOutcome::AuthorityUnavailable
    );
    f.store
        .bind_human_identity(&f.tenant, DAVE, DAVE, NOW + 3)
        .unwrap();
    assert_eq!(read(&mut f, NOW + 3).0, AggregationOutcome::Pending);
    assert_eq!(f.count("authority_approval_sets"), 0);
    f.store
        .provision_authority_basis(&f.tenant, &f.basis(2), NOW + 4)
        .unwrap();
    assert_eq!(read(&mut f, NOW + 4).0, AggregationOutcome::Stale);
}

fn snapshot(path: &std::path::Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let db = Connection::open(path).unwrap();
    let names:Vec<String>=db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE 'authority_%' ORDER BY name").unwrap()
        .query_map([],|r|r.get(0)).unwrap().collect::<Result<_,_>>().unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut statement = db
                .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}

#[test]
fn every_set_write_failure_rolls_back_the_new_signature_counter_decision_and_audit() {
    for (table, kind, condition) in [
        ("authority_approval_sets", "INSERT", "1"),
        ("authority_approval_set_members", "INSERT", "NEW.position=1"),
        ("authority_set_heads", "INSERT", "1"),
        ("authority_admission_results", "INSERT", "1"),
        (
            "authority_audit",
            "INSERT",
            "NEW.kind='approval_set_recorded'",
        ),
        ("authority_audit_heads", "UPDATE", "1"),
    ] {
        let mut f = Fixture::dual();
        f.vote(
            ALICE,
            ApprovalRole::NetworkReviewer,
            ApprovalDecision::Approve,
            NOW + 1,
        );
        let (issued, assertion, key) = f.prepare(
            BOB,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 2,
        );
        let original = snapshot(&f.path);
        let db = Connection::open(&f.path).unwrap();
        db.execute_batch(&format!("CREATE TRIGGER fail_set_write BEFORE {kind} ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT,'injected write failure'); END;")).unwrap();
        assert!(
            f.store
                .admit_decision(
                    &f.tenant,
                    BOB,
                    issued.challenge.challenge_id(),
                    &key,
                    &assertion,
                    &f.verifier,
                    NOW + 2
                )
                .is_err(),
            "{table}"
        );
        assert_eq!(snapshot(&f.path), original, "{table}");
        db.execute_batch("DROP TRIGGER fail_set_write;").unwrap();
        drop(db);
        drop(f.store);
        f.store = AuthorityStore::open(&f.path).unwrap();
        let result = f
            .store
            .admit_decision(
                &f.tenant,
                BOB,
                issued.challenge.challenge_id(),
                &key,
                &assertion,
                &f.verifier,
                NOW + 3,
            )
            .unwrap();
        assert!(matches!(
            result.aggregation,
            AggregationOutcome::Approved { .. }
        ));
        assert_eq!(f.count("authority_approval_sets"), 1);
        assert_eq!(f.count("authority_decisions"), 2);
    }
}

#[test]
fn withdrawing_an_individual_vote_makes_existing_set_ineligible() {
    let mut f = Fixture::dual();
    let vote = f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    f.vote(
        BOB,
        ApprovalRole::ServiceReviewer,
        ApprovalDecision::Approve,
        NOW + 2,
    );
    let before = stored_sets(&f.path);
    f.store
        .revoke_decision(
            &f.tenant,
            vote.approval["approval_id"].as_str().unwrap(),
            AUTHOR,
            NOW + 3,
        )
        .unwrap();
    assert!(f.current(NOW + 3).is_none());
    assert_eq!(stored_sets(&f.path), before);
    assert!(
        f.store
            .verify_retained_decision(
                &f.tenant,
                vote.approval["approval_id"].as_str().unwrap(),
                &f.verifier,
                NOW + 3
            )
            .is_err()
    );
}

#[test]
fn set_bytes_members_and_head_are_guarded_and_tenant_bound() {
    let mut f = Fixture::dual();
    f.vote(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    f.vote(
        BOB,
        ApprovalRole::ServiceReviewer,
        ApprovalDecision::Approve,
        NOW + 2,
    );
    let db = Connection::open(&f.path).unwrap();
    db.pragma_update(None, "foreign_keys", "ON").unwrap();
    assert!(
        db.execute(
            "UPDATE authority_approval_sets SET valid_until=valid_until+1",
            []
        )
        .is_err()
    );
    assert!(
        db.execute("DELETE FROM authority_approval_set_members", [])
            .is_err()
    );
    assert!(
        db.execute("UPDATE authority_set_heads SET revision=revision+1", [])
            .is_err()
    );
    let other = AuthorityTenant::new(PROJECT, ORG).unwrap();
    assert!(
        f.store
            .current_approval_set(&other, PLAN, &f.verifier, NOW + 3)
            .unwrap()
            .is_none()
    );
    // Corruption outside the protected-store boundary must be detected rather
    // than making a retained set count a different person.
    db.execute_batch("DROP TRIGGER authority_approval_set_members_no_update; UPDATE authority_approval_set_members SET position=2 WHERE position=1;").unwrap();
    assert!(
        f.store
            .current_approval_set(&f.tenant, PLAN, &f.verifier, NOW + 3)
            .is_err()
    );
}

#[test]
fn bounded_candidate_lookup_fails_atomically_instead_of_silently_truncating() {
    let mut f = Fixture::dual();
    for _ in 0..64 {
        assert_eq!(
            f.vote(
                ALICE,
                ApprovalRole::NetworkReviewer,
                ApprovalDecision::Approve,
                NOW + 1
            )
            .aggregation,
            AggregationOutcome::Pending
        );
    }
    let (issued, assertion, key) = f.prepare(
        BOB,
        ApprovalRole::ServiceReviewer,
        ApprovalDecision::Approve,
        NOW + 2,
    );
    let original = snapshot(&f.path);
    assert!(matches!(
        f.store.admit_decision(
            &f.tenant,
            BOB,
            issued.challenge.challenge_id(),
            &key,
            &assertion,
            &f.verifier,
            NOW + 2
        ),
        Err(fw_authority::AuthorityError::Quota)
    ));
    assert_eq!(snapshot(&f.path), original);
    assert_eq!(f.count("authority_approval_sets"), 0);
}

#[test]
fn v2_migration_preserves_history_without_inventing_epoch_identity_or_quorum() {
    let mut f = Fixture::dual();
    let (issued, assertion, key) = f.prepare(
        ALICE,
        ApprovalRole::NetworkReviewer,
        ApprovalDecision::Approve,
        NOW + 1,
    );
    let historical = f
        .store
        .admit_decision(
            &f.tenant,
            ALICE,
            issued.challenge.challenge_id(),
            &key,
            &assertion,
            &f.verifier,
            NOW + 1,
        )
        .unwrap();
    drop(f.store);
    authority_legacy::restore_v2(&f.path);
    let original = snapshot(&f.path);
    assert!(matches!(
        AuthorityStore::open(&f.path),
        Err(fw_authority::AuthorityError::MigrationRequired {
            found: 2,
            required: 3
        })
    ));
    let backup = f.path.with_file_name("v2-private-backup.sqlite3");
    AuthorityStore::migrate(&f.path, &backup).unwrap();
    assert_eq!(snapshot(&backup), original);
    for previous in &original {
        let after = snapshot(&f.path);
        let current = after.iter().find(|r| r.0 == previous.0).unwrap();
        if previous.0 == "authority_schema_migrations" {
            assert!(current.1.starts_with(&previous.1));
            assert_eq!(current.1.len(), previous.1.len() + 1);
        } else {
            assert_eq!(current, previous);
        }
    }
    f.store = AuthorityStore::open(&f.path).unwrap();
    assert_eq!(f.count("authority_basis_pins"), 0);
    assert_eq!(f.count("authority_human_bindings"), 0);
    assert_eq!(f.count("authority_approval_sets"), 0);
    let replay = f
        .store
        .admit_decision(
            &f.tenant,
            ALICE,
            issued.challenge.challenge_id(),
            &key,
            &assertion,
            &f.verifier,
            NOW + 3,
        )
        .unwrap();
    assert_eq!(replay.approval, historical.approval);
    assert_eq!(replay.aggregation, AggregationOutcome::NotEvaluated);
    for id in [AUTHOR, ALICE, BOB, CAROL] {
        f.store
            .bind_human_identity(&f.tenant, id, id, NOW + 3)
            .unwrap();
    }
    f.store
        .provision_authority_basis(&f.tenant, &f.basis(1), NOW + 3)
        .unwrap();
    assert!(f.current(NOW + 3).is_none());
    assert!(matches!(
        f.vote(
            BOB,
            ApprovalRole::ServiceReviewer,
            ApprovalDecision::Approve,
            NOW + 4
        )
        .aggregation,
        AggregationOutcome::Approved { .. }
    ));
}

#[test]
fn concurrent_v2_migration_has_one_backup_and_one_complete_new_schema() {
    let f = Fixture::dual();
    drop(f.store);
    authority_legacy::restore_v2(&f.path);
    let barrier = Arc::new(Barrier::new(2));
    let tasks = (0..2)
        .map(|index| {
            let path = f.path.clone();
            let backup = f.path.with_file_name(format!("migration-{index}.sqlite3"));
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                AuthorityStore::migrate(&path, &backup).unwrap();
                backup.exists()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tasks
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
    AuthorityStore::open(&f.path).unwrap();
    assert_eq!(
        Connection::open(&f.path)
            .unwrap()
            .query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        3
    );
}

#[test]
fn migration_validation_failure_rolls_back_new_tables_and_version_switch() {
    let f = Fixture::dual();
    drop(f.store);
    authority_legacy::restore_v2(&f.path);
    let db = Connection::open(&f.path).unwrap();
    db.pragma_update(None, "foreign_keys", "OFF").unwrap();
    db.execute("INSERT INTO authority_principals VALUES(?,?,?,'https://fixture.identity.example','orphan',?)",rusqlite::params![PROJECT,ORG,DAVE,NOW]).unwrap();
    drop(db);
    let original = snapshot(&f.path);
    let backup = f.path.with_file_name("invalid-v2.sqlite3");
    assert!(AuthorityStore::migrate(&f.path, &backup).is_err());
    assert_eq!(snapshot(&f.path), original);
    assert_eq!(snapshot(&backup), original);
    assert_eq!(
        Connection::open(&f.path)
            .unwrap()
            .query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        2
    );
}
