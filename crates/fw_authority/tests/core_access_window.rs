#![cfg(feature = "approval-proofs")]
//! Trusted-local reviewed core imports; these tests never obtain signing authority.
#[allow(dead_code)]
#[path = "support/integrity_fixture.rs"]
mod integrity;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/core_access_review_fixture.rs"]
mod support;

use fw_authority::{
    AuthorityError, AuthorityStore, AuthorityTenant, CoreAccessLeaseWindow,
    CoreAccessLeaseWindowStatus, CoreAccessProvenance,
};
use fw_contracts::{canonical_bytes, canonical_hash};
use fw_planner::PolicyReviewEvidence;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
};
use support::NOW;

const OTHER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ANOTHER: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    plan: Value,
    requirements: Value,
    review: PolicyReviewEvidence,
    provenance: CoreAccessProvenance,
    window: CoreAccessLeaseWindow,
}

impl Fixture {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let (plan, requirements, review, provenance, window) = support::fixture();
        let tenant = AuthorityTenant::new(
            plan["org_id"].as_str().unwrap(),
            plan["project_id"].as_str().unwrap(),
        )
        .unwrap();
        store
            .provision_principal(
                &tenant,
                plan["principal_id"].as_str().unwrap(),
                "https://identity.example.test",
                "fixed-window-user",
                NOW,
            )
            .unwrap();
        Self {
            _directory: directory,
            path,
            store,
            tenant,
            plan,
            requirements,
            review,
            provenance,
            window,
        }
    }

    fn register(&mut self, now: i64) -> fw_authority::Result<CoreAccessLeaseWindowStatus> {
        self.store.register_reviewed_core_access_plan(
            &self.tenant,
            &self.plan,
            &self.requirements,
            &self.review,
            &self.provenance,
            &self.window,
            now,
        )
    }

    fn read(&mut self, now: i64) -> fw_authority::Result<Option<CoreAccessLeaseWindowStatus>> {
        self.store.read_core_access_lease_window(
            &self.tenant,
            self.plan["plan_id"].as_str().unwrap(),
            now,
        )
    }
}

fn count(path: &Path, table: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

// Durable observed-time floors may advance without adding authority or audits.
fn immutable_rows(path: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    integrity::rows(path)
        .into_iter()
        .filter(|(name, _)| name != "authority_signing_quota_clocks")
        .collect()
}

#[test]
fn exact_reviewed_import_retry_and_reopen_preserve_window_originals_and_no_signing_state() {
    let mut f = Fixture::new();
    let admitted = f.register(NOW + 1).unwrap();
    assert!(admitted.current);
    assert!(!admitted.signing_allowed && !admitted.dispatch_allowed);
    assert_eq!(admitted.plan_hash, canonical_hash(&f.plan).unwrap());
    assert_eq!(
        admitted.request_hash,
        canonical_hash(&f.provenance.request).unwrap()
    );
    assert_eq!(
        admitted.provenance_hash,
        canonical_hash(&f.provenance).unwrap()
    );
    assert_eq!(admitted.lease_seconds, 3600);
    assert_ne!(
        f.plan["requested_policies"][0]["scope"]["source_cidrs"],
        serde_json::to_value(&f.provenance.envelope.scope.source_cidrs).unwrap(),
        "the reviewed policy is narrower than its original envelope"
    );
    assert_eq!(admitted.not_before, support::core::at(NOW));
    assert_eq!(admitted.expires_at, support::core::at(NOW + 3600));
    let rows = immutable_rows(&f.path);
    f.store = AuthorityStore::open(&f.path).unwrap();
    f.register(NOW + 2).unwrap();
    f.read(NOW + 2).unwrap().unwrap();
    assert_eq!(immutable_rows(&f.path), rows);
    let verified = f
        .store
        .policy_review_evidence(&f.tenant, f.plan["plan_id"].as_str().unwrap(), NOW + 2)
        .unwrap()
        .unwrap();
    assert_eq!(
        verified.canonical_bytes(),
        canonical_bytes(&f.review).unwrap()
    );
    assert_eq!(
        verified.core_binding().unwrap().lease_id(),
        f.provenance.lease_id
    );
    for table in [
        "authority_signing_intents",
        "authority_signing_jobs",
        "authority_signing_results",
        "authority_signing_outbox",
        "authority_signing_quota_reservations",
        "authority_signing_quota_usage",
    ] {
        assert_eq!(count(&f.path, table), 0, "core review created {table}");
    }
    let output = serde_json::to_string(&admitted).unwrap();
    for private in [
        &f.provenance.request.purpose,
        &f.provenance.request.workflow_id,
    ] {
        assert!(!output.contains(private));
    }
    assert!(!output.contains("canonical_bytes") && !output.contains("excluded_destination_cidrs"));
}

#[test]
fn another_plan_cannot_refresh_the_original_absolute_window() {
    let mut f = Fixture::new();
    f.register(NOW + 1).unwrap();
    let before = immutable_rows(&f.path);
    let (mut shifted, _, shifted_review, provenance, window) = support::fixture_at(NOW, 1);
    shifted["plan_id"] = OTHER.into();
    assert!(matches!(
        f.store.register_reviewed_core_access_plan(
            &f.tenant,
            &shifted,
            &f.requirements,
            &shifted_review,
            &provenance,
            &window,
            NOW + 2,
        ),
        Err(AuthorityError::Conflict | AuthorityError::Binding)
    ));
    assert_eq!(
        immutable_rows(&f.path),
        before,
        "conflicting plan leaked partial records"
    );
    let mut compatible = f.plan.clone();
    compatible["plan_id"] = OTHER.into();
    f.store
        .register_reviewed_core_access_plan(
            &f.tenant,
            &compatible,
            &f.requirements,
            &f.review,
            &f.provenance,
            &f.window,
            NOW + 2,
        )
        .unwrap();
    let status = f
        .store
        .read_core_access_lease_window(&f.tenant, OTHER, NOW + 2)
        .unwrap()
        .unwrap();
    assert_eq!(status.not_before, support::core::at(NOW));
    assert_eq!(status.expires_at, support::core::at(NOW + 3600));
    assert_eq!(status.lease_id, f.provenance.lease_id);
}

#[test]
fn fixed_window_and_review_must_match_full_original_duration_and_identity() {
    for scenario in 0..10 {
        let mut f = Fixture::new();
        match scenario {
            0 => f.window.not_before = support::core::at(NOW + 1),
            1 => f.window.expires_at = support::core::at(NOW + 3601),
            2 => f.window.request_id = OTHER.into(),
            3 => f.window.request_revision = 2,
            4 => f.window.lease_id = OTHER.into(),
            5 => f.window.provenance_hash = fw_contracts::hash_bytes(b"unrelated provenance"),
            6 => f.window.request_hash = fw_contracts::hash_bytes(b"unrelated request"),
            7 => f.window.org_id = OTHER.into(),
            8 => f.window.project_id = OTHER.into(),
            _ => f.window.target_id = OTHER.into(),
        }
        let before = immutable_rows(&f.path);
        assert!(f.register(NOW + 1).is_err(), "scenario {scenario}");
        assert_eq!(immutable_rows(&f.path), before, "scenario {scenario}");
    }
    let mut f = Fixture::new();
    f.plan["requested_policies"][0]["lifetime"]["expires_at"] =
        support::core::at(NOW + 1800).into();
    support::core::rehash(&mut f.plan, &mut f.provenance);
    f.review = support::rebuild(&mut f.plan, &f.provenance);
    f.window = support::window(&f.plan, &f.provenance);
    assert!(
        f.review.verify(&f.plan).is_ok(),
        "shorter structural review is independently valid"
    );
    let before = immutable_rows(&f.path);
    assert!(
        f.register(NOW + 1).is_err(),
        "short policy window cannot discount or replace original duration"
    );
    assert_eq!(immutable_rows(&f.path), before);
}

#[test]
fn a_structurally_valid_review_cannot_substitute_an_unretained_lease() {
    let mut f = Fixture::new();
    for association in &mut f.review.after.associations {
        association.lease_id = Some(OTHER.into());
    }
    f.plan["desired_state_hash"] = f.review.after.state_hash().unwrap().into();
    assert!(
        f.review.verify(&f.plan).is_ok(),
        "the planner proves structure while authority must resolve the original lease"
    );
    let before = immutable_rows(&f.path);
    assert!(f.register(NOW + 1).is_err());
    assert_eq!(immutable_rows(&f.path), before);
}

#[test]
fn expired_or_retired_window_history_and_exact_retry_do_not_refresh_authority() {
    let mut f = Fixture::new();
    f.register(NOW + 1).unwrap();
    f.store
        .retire_plan(&f.tenant, f.plan["plan_id"].as_str().unwrap(), NOW + 2)
        .unwrap();
    let before = immutable_rows(&f.path);
    let status = f.read(NOW + 7200).unwrap().unwrap();
    assert!(!status.current && !status.signing_allowed && !status.dispatch_allowed);
    assert_eq!(status.not_before, support::core::at(NOW));
    assert_eq!(status.expires_at, support::core::at(NOW + 3600));
    let repeated = f.register(NOW + 7200).unwrap();
    assert!(!repeated.current);
    assert_eq!(immutable_rows(&f.path), before);
}

#[test]
fn other_tenant_cannot_read_or_import_a_registered_core_window() {
    let mut f = Fixture::new();
    f.register(NOW + 1).unwrap();
    let other = AuthorityTenant::new(OTHER, ANOTHER).unwrap();
    let before = immutable_rows(&f.path);
    assert!(
        f.store
            .read_core_access_lease_window(&other, f.plan["plan_id"].as_str().unwrap(), NOW + 2,)
            .is_err()
    );
    assert!(
        f.store
            .register_reviewed_core_access_plan(
                &other,
                &f.plan,
                &f.requirements,
                &f.review,
                &f.provenance,
                &f.window,
                NOW + 2,
            )
            .is_err()
    );
    assert_eq!(immutable_rows(&f.path), before);
}

#[test]
fn competing_first_windows_commit_only_one_original_interval() {
    let f = Fixture::new();
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for shift in 0..2 {
        let path = f.path.clone();
        let tenant = f.tenant.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let mut store = AuthorityStore::open(&path).unwrap();
            let (mut plan, requirements, review, provenance, window) =
                support::fixture_at(NOW, shift);
            if shift == 1 {
                plan["plan_id"] = OTHER.into();
            }
            barrier.wait();
            store.register_reviewed_core_access_plan(
                &tenant,
                &plan,
                &requirements,
                &review,
                &provenance,
                &window,
                NOW + 2,
            )
        }));
    }
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().any(|result| matches!(
        result,
        Err(AuthorityError::Conflict | AuthorityError::Binding)
    )));
    assert_eq!(count(&f.path, "authority_core_access_requests"), 1);
    assert_eq!(count(&f.path, "authority_core_access_plan_bindings"), 1);
    assert_eq!(count(&f.path, "authority_plan_review_evidence"), 1);
    assert_eq!(count(&f.path, "authority_signing_intents"), 0);
    AuthorityStore::open(&f.path).unwrap();
}

#[test]
fn closed_window_contract_rejects_unknown_and_duplicate_fields() {
    let f = Fixture::new();
    let mut changed = serde_json::to_value(&f.window).unwrap();
    changed["signing_allowed"] = json!(true);
    assert!(serde_json::from_value::<CoreAccessLeaseWindow>(changed).is_err());
    let wire = canonical_bytes(&f.window).unwrap();
    let duplicate = format!(
        "{{\"request_revision\":1,{}",
        std::str::from_utf8(&wire[1..]).unwrap()
    );
    assert!(
        fw_contracts::parse_strict_with_limit::<CoreAccessLeaseWindow>(duplicate.as_bytes(), 4096,)
            .is_err()
    );
}

#[test]
fn window_guards_refuse_updates_deletes_replace_identity_and_rowid_collisions() {
    let mut f = Fixture::new();
    f.register(NOW + 1).unwrap();
    let db = Connection::open(&f.path).unwrap();
    db.pragma_update(None, "foreign_keys", "ON").unwrap();
    db.pragma_update(None, "recursive_triggers", "OFF").unwrap();
    let before = immutable_rows(&f.path);
    for sql in [
        "UPDATE authority_core_access_lease_windows SET not_before=not_before+1",
        "UPDATE authority_core_access_lease_windows SET rowid=rowid+100",
        "DELETE FROM authority_core_access_lease_windows",
        "INSERT OR REPLACE INTO authority_core_access_lease_windows SELECT * FROM authority_core_access_lease_windows",
        "INSERT OR REPLACE INTO authority_core_access_lease_windows SELECT org_id,project_id,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',lease_id,provenance_hash,window_hash,not_before,expires_at,admitted_at,canonical_bytes FROM authority_core_access_lease_windows",
        "INSERT OR REPLACE INTO authority_core_access_lease_windows(rowid,org_id,project_id,request_id,lease_id,provenance_hash,window_hash,not_before,expires_at,admitted_at,canonical_bytes) SELECT rowid,org_id,project_id,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',provenance_hash,window_hash,not_before,expires_at,admitted_at,canonical_bytes FROM authority_core_access_lease_windows",
    ] {
        let error = db.execute(sql, []).unwrap_err();
        assert!(
            matches!(error, rusqlite::Error::SqliteFailure(error, _)
            if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER),
            "identity guard did not refuse {sql}"
        );
        assert_eq!(immutable_rows(&f.path), before);
    }
    assert!(db.execute(
        "INSERT INTO authority_core_access_lease_windows SELECT org_id,project_id,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',provenance_hash,window_hash,not_before,expires_at,admitted_at,canonical_bytes FROM authority_core_access_lease_windows",
        [],
    ).is_err(), "orphan window must fail its retained-request FK");
    assert_eq!(immutable_rows(&f.path), before);
}

#[test]
fn restored_guard_metadata_does_not_hide_corrupt_window_projections_or_canonical_bytes() {
    for corruption in [
        "not_before=not_before+1",
        "expires_at=expires_at+1",
        "window_hash=zeroblob(32)",
        "provenance_hash=zeroblob(32)",
        "canonical_bytes=X'7b7d'",
    ] {
        let mut f = Fixture::new();
        f.register(NOW + 1).unwrap();
        let db = Connection::open(&f.path).unwrap();
        db.pragma_update(None, "foreign_keys", "OFF").unwrap();
        let guard = integrity::trigger_sql(&db, "authority_core_access_lease_windows_no_update");
        db.execute_batch("DROP TRIGGER authority_core_access_lease_windows_no_update")
            .unwrap();
        db.execute_batch(&format!(
            "UPDATE authority_core_access_lease_windows SET {corruption}"
        ))
        .unwrap();
        db.execute_batch(&guard).unwrap();
        assert!(f.read(NOW + 2).is_err(), "live read accepted {corruption}");
        assert!(
            AuthorityStore::open(&f.path).is_err(),
            "reopen accepted {corruption}"
        );
    }
}

#[test]
fn observed_expiry_survives_backward_read_retry_and_reopen_without_current_resurrection() {
    let mut f = Fixture::new();
    assert!(f.register(NOW + 1).unwrap().current);
    let after = f.read(NOW + 7200).unwrap().unwrap();
    assert!(!after.current);
    let before = immutable_rows(&f.path);
    let rollback = f.read(NOW + 2).unwrap().unwrap();
    assert!(!rollback.current && !rollback.signing_allowed && !rollback.dispatch_allowed);
    assert_eq!(rollback.checked_at, support::core::at(NOW + 2));
    assert!(!f.register(NOW + 2).unwrap().current);
    let before_admission = f.read(NOW - 1).unwrap().unwrap();
    assert!(!before_admission.current);
    assert_eq!(before_admission.checked_at, support::core::at(NOW - 1));
    assert!(!f.register(NOW - 1).unwrap().current);
    f.store = AuthorityStore::open(&f.path).unwrap();
    assert!(!f.read(NOW + 2).unwrap().unwrap().current);
    assert!(!f.register(NOW + 2).unwrap().current);
    assert!(!f.read(NOW - 1).unwrap().unwrap().current);
    assert!(!f.register(NOW - 1).unwrap().current);
    assert_eq!(immutable_rows(&f.path), before);
    let db = Connection::open(&f.path).unwrap();
    let floor: i64 = db
        .query_row(
            "SELECT observed_at FROM authority_signing_quota_clocks WHERE bucket_kind='project'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(floor, NOW + 7200);
}

#[test]
fn legacy_import_cannot_escape_an_existing_fixed_request_window() {
    let mut f = Fixture::new();
    f.register(NOW + 1).unwrap();
    let (mut shifted, _, _, provenance, _) = support::fixture_at(NOW, 600);
    shifted["plan_id"] = OTHER.into();
    f.store
        .register_plan(&f.tenant, &shifted, &f.requirements, NOW + 2)
        .unwrap();
    let before = integrity::rows(&f.path);
    let result = f
        .store
        .register_core_access_provenance(&f.tenant, OTHER, &provenance, NOW + 2);
    assert!(
        result.is_err(),
        "legacy binding escaped the fixed window: {result:?}"
    );
    assert_eq!(integrity::rows(&f.path), before);
    assert_eq!(count(&f.path, "authority_core_access_lease_windows"), 1);
    assert_eq!(count(&f.path, "authority_core_access_plan_bindings"), 1);
    assert_eq!(count(&f.path, "authority_signing_quota_reservations"), 0);
    AuthorityStore::open(&f.path).unwrap();
}

#[test]
fn first_window_refuses_preexisting_outside_legacy_history_atomically() {
    let mut f = Fixture::new();
    let (mut shifted, _, _, provenance, _) = support::fixture_at(NOW, 600);
    shifted["plan_id"] = OTHER.into();
    f.store
        .register_plan(&f.tenant, &shifted, &f.requirements, NOW)
        .unwrap();
    f.store
        .register_core_access_provenance(&f.tenant, OTHER, &provenance, NOW)
        .unwrap();
    let before = immutable_rows(&f.path);
    assert!(
        f.register(NOW + 1).is_err(),
        "window hid conflicting legacy history"
    );
    assert_eq!(immutable_rows(&f.path), before);
    assert_eq!(count(&f.path, "authority_core_access_lease_windows"), 0);
    assert_eq!(count(&f.path, "authority_plan_review_evidence"), 0);
    AuthorityStore::open(&f.path).unwrap();
}

#[test]
fn malformed_closed_plan_never_commits_a_clock_observation() {
    let mut f = Fixture::new();
    f.plan["zz_unknown"] = json!(1);
    let before = integrity::rows(&f.path);
    assert!(f.register(NOW + 1).is_err());
    assert_eq!(
        integrity::rows(&f.path),
        before,
        "malformed input advanced a durable authority clock"
    );
}

#[test]
fn malformed_requirements_never_observe_time_but_expired_valid_attempts_do() {
    for scenario in 0..3 {
        let mut f = Fixture::new();
        match scenario {
            0 => f.requirements["zz_unknown"] = json!(1),
            1 => f.plan["rollback_authority"]["zz_unknown"] = json!(1),
            _ => f.plan["requested_policies"][0]["lifetime"]["zz_unknown"] = json!(1),
        }
        let before = integrity::rows(&f.path);
        assert!(f.register(NOW + 1).is_err(), "scenario {scenario}");
        assert_eq!(integrity::rows(&f.path), before, "scenario {scenario}");
    }
    let mut f = Fixture::new();
    let before = immutable_rows(&f.path);
    assert!(matches!(f.register(NOW + 3600), Err(AuthorityError::Time)));
    assert_eq!(immutable_rows(&f.path), before);
    assert_eq!(count(&f.path, "authority_signing_quota_clocks"), 1);
    let db = Connection::open(&f.path).unwrap();
    let floor: i64 = db
        .query_row(
            "SELECT observed_at FROM authority_signing_quota_clocks WHERE bucket_kind='project'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(floor, NOW + 3600);
    assert!(f.register(NOW + 1).is_err());
    AuthorityStore::open(&f.path).unwrap();
}

#[test]
fn contained_legacy_binding_preserves_bytes_and_cannot_gain_fresh_signing_readiness() {
    let mut f = Fixture::new();
    f.register(NOW + 1).unwrap();
    let (mut legacy, provenance) = support::core::fixture();
    legacy["plan_id"] = OTHER.into();
    let original = canonical_bytes(&provenance).unwrap();
    f.store
        .register_plan(&f.tenant, &legacy, &f.requirements, NOW + 2)
        .unwrap();
    let imported = f
        .store
        .register_core_access_provenance(&f.tenant, OTHER, &provenance, NOW + 2)
        .unwrap();
    assert!(imported.current);
    assert_eq!(imported.lease_seconds, 3600);
    assert_eq!(
        imported.provenance_hash,
        fw_contracts::hash_bytes(&original)
    );
    assert!(!imported.signing_allowed && !imported.dispatch_allowed);
    let ready = f
        .store
        .signing_readiness(
            &f.tenant,
            OTHER,
            &fw_webauthn::WebAuthn::new("http://localhost:8787").unwrap(),
            NOW + 2,
        )
        .unwrap();
    assert!(
        ready
            .reasons
            .iter()
            .any(|reason| reason == "CORE_REQUEST_BINDING_UNAVAILABLE")
    );
    assert!(!ready.signing_allowed && !ready.dispatch_allowed);
    let before = immutable_rows(&f.path);
    assert!(
        !f.store
            .read_core_access_provenance(&f.tenant, OTHER, NOW + 3600)
            .unwrap()
            .unwrap()
            .current
    );
    let rolled_back = f
        .store
        .read_core_access_provenance(&f.tenant, OTHER, NOW + 2)
        .unwrap()
        .unwrap();
    assert!(!rolled_back.current);
    assert!(
        rolled_back
            .gates
            .iter()
            .any(|gate| gate == "CORE_ACCESS_WINDOW_NOT_CURRENT")
    );
    assert!(
        !f.store
            .register_core_access_provenance(&f.tenant, OTHER, &provenance, NOW + 2)
            .unwrap()
            .current
    );
    f.store = AuthorityStore::open(&f.path).unwrap();
    assert!(
        !f.store
            .read_core_access_provenance(&f.tenant, OTHER, NOW + 2)
            .unwrap()
            .unwrap()
            .current
    );
    assert_eq!(immutable_rows(&f.path), before);
    let db = Connection::open(&f.path).unwrap();
    let retained: Vec<u8> = db
        .query_row(
            "SELECT canonical_bytes FROM authority_core_access_requests",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, original);
}

#[test]
fn compatible_legacy_can_upgrade_only_through_full_combined_review_validation() {
    let mut f = Fixture::new();
    f.store
        .register_plan(&f.tenant, &f.plan, &f.requirements, NOW)
        .unwrap();
    f.store
        .register_core_access_provenance(
            &f.tenant,
            f.plan["plan_id"].as_str().unwrap(),
            &f.provenance,
            NOW,
        )
        .unwrap();
    assert_eq!(count(&f.path, "authority_core_access_lease_windows"), 0);
    let original = canonical_bytes(&f.provenance).unwrap();
    assert!(f.register(NOW + 1).unwrap().current);
    assert_eq!(count(&f.path, "authority_core_access_requests"), 1);
    assert_eq!(count(&f.path, "authority_core_access_plan_bindings"), 1);
    assert_eq!(count(&f.path, "authority_core_access_lease_windows"), 1);
    let db = Connection::open(&f.path).unwrap();
    let retained: Vec<u8> = db
        .query_row(
            "SELECT canonical_bytes FROM authority_core_access_requests",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, original);
    AuthorityStore::open(&f.path).unwrap();
}

#[test]
fn restored_guards_cannot_hide_previously_accepted_outside_legacy_history() {
    let mut f = Fixture::new();
    f.register(NOW + 1).unwrap();
    let mut compatible = f.plan.clone();
    compatible["plan_id"] = OTHER.into();
    f.store
        .register_plan(&f.tenant, &compatible, &f.requirements, NOW + 2)
        .unwrap();
    f.store
        .register_core_access_provenance(&f.tenant, OTHER, &f.provenance, NOW + 2)
        .unwrap();
    let (mut outside, _, _, provenance, _) = support::fixture_at(NOW, 600);
    outside["plan_id"] = OTHER.into();
    provenance.verify(&outside).unwrap();
    let digest = canonical_hash(&outside).unwrap();
    let hash_bytes: Vec<u8> = (7..digest.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digest[offset..offset + 2], 16).unwrap())
        .collect();
    let db = Connection::open(&f.path).unwrap();
    let guards = [
        "authority_plans_no_update",
        "authority_core_access_plan_bindings_no_update",
    ]
    .map(|name| integrity::trigger_sql(&db, name));
    db.execute_batch("DROP TRIGGER authority_plans_no_update; DROP TRIGGER authority_core_access_plan_bindings_no_update").unwrap();
    db.execute(
        "UPDATE authority_plans SET plan_hash=?1,canonical_bytes=?2 WHERE plan_id=?3",
        rusqlite::params![hash_bytes, canonical_bytes(&outside).unwrap(), OTHER],
    )
    .unwrap();
    db.execute(
        "UPDATE authority_core_access_plan_bindings SET plan_hash=?1 WHERE plan_id=?2",
        rusqlite::params![hash_bytes, OTHER],
    )
    .unwrap();
    for guard in guards {
        db.execute_batch(&guard).unwrap();
    }
    assert_eq!(
        db.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert!(
        !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get::<_, bool>(0)
        )
        .unwrap()
    );
    let before = integrity::rows(&f.path);
    assert!(
        f.store
            .read_core_access_provenance(&f.tenant, OTHER, NOW + 3)
            .is_err()
    );
    assert!(
        f.read(NOW + 3).is_err(),
        "healthy reviewed plan hid another binding outside its window"
    );
    assert!(AuthorityStore::open(&f.path).is_err());
    assert_eq!(
        integrity::rows(&f.path),
        before,
        "validation repaired or rewrote old history"
    );
}

#[test]
fn fixed_window_keeps_original_request_revision_lease_and_alias_identity_closed() {
    for scenario in 0..4 {
        let mut f = Fixture::new();
        f.register(NOW + 1).unwrap();
        let mut plan = f.plan.clone();
        let mut provenance = f.provenance.clone();
        plan["plan_id"] = OTHER.into();
        match scenario {
            0 => provenance.lease_id = OTHER.into(),
            1 => {
                provenance.request_revision += 1;
                plan["request_revision"] = provenance.request_revision.into();
            }
            2 => {
                provenance.request_id = OTHER.into();
                provenance.request.idempotency_key = OTHER.into();
                plan["request_id"] = OTHER.into();
            }
            _ => {
                provenance.request_id = OTHER.into();
                provenance.lease_id = OTHER.into();
                plan["request_id"] = OTHER.into();
            }
        }
        support::core::rehash(&mut plan, &mut provenance);
        f.store
            .register_plan(&f.tenant, &plan, &f.requirements, NOW + 2)
            .unwrap();
        let before = immutable_rows(&f.path);
        assert!(
            f.store
                .register_core_access_provenance(&f.tenant, OTHER, &provenance, NOW + 3)
                .is_err(),
            "scenario {scenario}"
        );
        assert_eq!(immutable_rows(&f.path), before, "scenario {scenario}");
    }
}
