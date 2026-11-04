#![cfg(feature = "approval-proofs")]
//! Trusted-local cost provenance tests. No production signing authority.
#[path = "support/core_access_fixture.rs"]
mod core;
#[allow(dead_code)]
#[path = "support/integrity_fixture.rs"]
mod integrity_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;

use core::NOW;
use fw_authority::{AuthorityError, AuthorityStore, AuthorityTenant, CoreAccessProvenance};
use fw_contracts::{canonical_hash, hash_bytes};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const OTHER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ANOTHER: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    plan: Value,
    provenance: CoreAccessProvenance,
}
impl Fixture {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let path = directory.path().join("authority.sqlite3");
        let mut store = AuthorityStore::open(&path).unwrap();
        let (plan, provenance) = core::fixture();
        let tenant = tenant(&plan);
        provision(&mut store, &tenant, &plan);
        Self {
            _directory: directory,
            path,
            store,
            tenant,
            plan,
            provenance,
        }
    }
    fn register(&mut self) -> fw_authority::CoreAccessProvenanceStatus {
        self.store
            .register_core_access_provenance(
                &self.tenant,
                self.plan["plan_id"].as_str().unwrap(),
                &self.provenance,
                NOW + 1,
            )
            .unwrap()
    }
    fn read(
        &mut self,
        now: i64,
    ) -> fw_authority::Result<Option<fw_authority::CoreAccessProvenanceStatus>> {
        self.store.read_core_access_provenance(
            &self.tenant,
            self.plan["plan_id"].as_str().unwrap(),
            now,
        )
    }
}
fn tenant(plan: &Value) -> AuthorityTenant {
    AuthorityTenant::new(
        plan["org_id"].as_str().unwrap(),
        plan["project_id"].as_str().unwrap(),
    )
    .unwrap()
}
fn provision(store: &mut AuthorityStore, tenant: &AuthorityTenant, plan: &Value) {
    store
        .provision_principal(
            tenant,
            plan["principal_id"].as_str().unwrap(),
            "https://identity.example.test",
            "core-test-user",
            NOW,
        )
        .unwrap();
    store
        .register_plan(tenant, plan, &core::requirements(), NOW)
        .unwrap();
}
fn snapshot(path: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let db = Connection::open(path).unwrap();
    let mut query = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    let names = query
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut query = db
                .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                .unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}
fn count(path: &Path, table: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn exact_retry_and_reopen_preserve_original_cost_without_signing_side_effects() {
    let mut f = Fixture::new();
    assert!(f.read(NOW).unwrap().is_none());
    let admitted = f.register();
    assert_eq!(
        admitted.request_hash,
        canonical_hash(&f.provenance.request).unwrap()
    );
    assert_eq!(
        admitted.provenance_hash,
        canonical_hash(&f.provenance).unwrap()
    );
    assert_eq!(admitted.plan_hash, canonical_hash(&f.plan).unwrap());
    assert_eq!(admitted.lease_seconds, 3600); // plan300 and requested-policy1800 are not original cost.
    assert_eq!(
        admitted.destination_asset_ids,
        f.provenance.request.destination_asset_ids
    );
    assert!(admitted.current);
    assert!(!admitted.signing_allowed && !admitted.dispatch_allowed);
    assert_eq!(admitted.gates, ["CORE_SIGNING_PROFILE_UNAVAILABLE"]);
    let before = snapshot(&f.path);
    f.store = AuthorityStore::open(&f.path).unwrap();
    f.store
        .register_core_access_provenance(
            &f.tenant,
            f.plan["plan_id"].as_str().unwrap(),
            &f.provenance,
            NOW + 2,
        )
        .unwrap();
    f.read(NOW + 2).unwrap().unwrap();
    assert_eq!(snapshot(&f.path), before);
    for table in [
        "authority_signing_intents",
        "authority_signing_jobs",
        "authority_signing_results",
        "authority_signing_outbox",
        "authority_signing_quota_reservations",
        "authority_signing_quota_usage",
    ] {
        assert_eq!(count(&f.path, table), 0, "import changed {table}");
    }
    let db = Connection::open(&f.path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM authority_audit WHERE kind='core_access_provenance_registered'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
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
fn retained_status_and_retry_survive_expiry_and_retirement_without_restoring_authority() {
    let mut f = Fixture::new();
    f.register();
    f.store
        .retire_plan(&f.tenant, f.plan["plan_id"].as_str().unwrap(), NOW + 2)
        .unwrap();
    let before = snapshot(&f.path);
    let status = f.read(NOW + 86_400).unwrap().unwrap();
    assert!(!status.current && !status.signing_allowed && !status.dispatch_allowed);
    for gate in [
        "PLAN_RETIRED",
        "PLAN_EXPIRED",
        "CORE_ACCESS_PROVENANCE_EXPIRED",
    ] {
        assert!(status.gates.contains(&gate.into()));
    }
    let retried = f
        .store
        .register_core_access_provenance(
            &f.tenant,
            f.plan["plan_id"].as_str().unwrap(),
            &f.provenance,
            NOW + 86_400,
        )
        .unwrap();
    assert!(!retried.current);
    assert_eq!(snapshot(&f.path), before);
}

#[test]
fn fresh_import_rejects_expired_retired_future_and_negative_admission() {
    for scenario in 0..4 {
        let mut f = Fixture::new();
        if scenario == 1 {
            f.store
                .retire_plan(&f.tenant, f.plan["plan_id"].as_str().unwrap(), NOW)
                .unwrap();
        }
        let now = match scenario {
            0 => NOW + 300,
            1 => NOW,
            2 => NOW - 1,
            _ => -1,
        };
        let before = snapshot(&f.path);
        assert!(
            f.store
                .register_core_access_provenance(
                    &f.tenant,
                    f.plan["plan_id"].as_str().unwrap(),
                    &f.provenance,
                    now
                )
                .is_err()
        );
        assert_eq!(snapshot(&f.path), before);
    }
}

#[test]
fn identical_original_request_can_attach_to_later_compatible_plan() {
    let mut f = Fixture::new();
    f.register();
    let mut later = f.plan.clone();
    later["plan_id"] = json!(OTHER);
    // The original plan has expired; its immutable request can still support a
    // later compatible plan while the envelope and delegation remain current.
    later["created_at"] = json!(core::at(NOW + 400));
    later["valid_until"] = json!(core::at(NOW + 700));
    later["rollback_authority"]["valid_until"] = json!(core::at(NOW + 760));
    f.store
        .register_plan(&f.tenant, &later, &core::requirements(), NOW + 400)
        .unwrap();
    let status = f
        .store
        .register_core_access_provenance(&f.tenant, OTHER, &f.provenance, NOW + 401)
        .unwrap();
    assert_eq!(status.plan_id, OTHER);
    assert_eq!(status.lease_id, f.provenance.lease_id);
    assert_eq!(count(&f.path, "authority_core_access_requests"), 1);
    assert_eq!(count(&f.path, "authority_core_access_plan_bindings"), 2);
}

#[test]
fn immutable_original_request_cannot_change_bytes_root_or_lease_in_a_later_plan() {
    for change in 0..3 {
        let mut f = Fixture::new();
        f.register();
        let mut altered = f.provenance.clone();
        match change {
            0 => altered.request.purpose.push_str(" changed"),
            1 => altered.delegation.root_id = OTHER.into(),
            _ => altered.lease_id = OTHER.into(),
        }
        let mut plan = f.plan.clone();
        plan["plan_id"] = json!(OTHER);
        core::rehash(&mut plan, &mut altered);
        f.store
            .register_plan(&f.tenant, &plan, &core::requirements(), NOW + 2)
            .unwrap();
        let before = snapshot(&f.path);
        assert!(
            f.store
                .register_core_access_provenance(&f.tenant, OTHER, &altered, NOW + 3)
                .is_err()
        );
        assert_eq!(snapshot(&f.path), before);
    }
}

#[test]
fn request_identity_and_lease_aliases_are_rejected_before_any_rows_or_audit_change() {
    for same_lease in [false, true] {
        let mut f = Fixture::new();
        f.register();
        let mut altered = f.provenance.clone();
        altered.request_id = OTHER.into();
        if same_lease {
            altered.request.idempotency_key = OTHER.into();
        } else {
            altered.lease_id = OTHER.into();
        }
        let mut plan = f.plan.clone();
        plan["plan_id"] = json!(OTHER);
        plan["request_id"] = json!(OTHER);
        core::rehash(&mut plan, &mut altered);
        f.store
            .register_plan(&f.tenant, &plan, &core::requirements(), NOW + 2)
            .unwrap();
        let before = snapshot(&f.path);
        assert!(
            f.store
                .register_core_access_provenance(&f.tenant, OTHER, &altered, NOW + 3)
                .is_err()
        );
        assert_eq!(snapshot(&f.path), before);
    }
}

#[test]
fn lease_identity_is_unique_across_projects_but_tenant_reads_do_not_leak() {
    let mut f = Fixture::new();
    f.register();
    let mut altered = f.provenance.clone();
    let mut plan = f.plan.clone();
    altered.envelope.project_id = OTHER.into();
    altered.delegation.project_id = OTHER.into();
    altered.request.idempotency_key = OTHER.into();
    plan["project_id"] = json!(OTHER);
    plan["requested_policies"][0]["project_id"] = json!(OTHER);
    core::rehash(&mut plan, &mut altered);
    let other_tenant = tenant(&plan);
    // Read before registering any second-tenant plan cannot see the first plan.
    assert!(
        f.store
            .read_core_access_provenance(&other_tenant, plan["plan_id"].as_str().unwrap(), NOW + 1)
            .is_err()
    );
    provision(&mut f.store, &other_tenant, &plan);
    assert!(
        f.store
            .read_core_access_provenance(&other_tenant, plan["plan_id"].as_str().unwrap(), NOW + 2)
            .unwrap()
            .is_none()
    );
    let before = snapshot(&f.path);
    assert!(
        f.store
            .register_core_access_provenance(
                &other_tenant,
                plan["plan_id"].as_str().unwrap(),
                &altered,
                NOW + 2
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.path), before);
}

#[test]
fn altered_audit_schema_refuses_provenance_without_changing_rows_then_restores_retry() {
    let mut f = Fixture::new();
    let db = Connection::open(&f.path).unwrap();
    db.execute_batch("CREATE TRIGGER fail_core_audit BEFORE INSERT ON authority_audit WHEN NEW.kind='core_access_provenance_registered' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
    let before = snapshot(&f.path);
    // The added trigger is refused by complete schema validation before writes.
    assert!(matches!(
        f.store.register_core_access_provenance(
            &f.tenant,
            f.plan["plan_id"].as_str().unwrap(),
            &f.provenance,
            NOW + 1
        ),
        Err(AuthorityError::Invalid(_))
    ));
    assert_eq!(snapshot(&f.path), before);
    db.execute_batch("DROP TRIGGER fail_core_audit").unwrap();
    f.register();
}

#[test]
fn direct_mutation_and_deletion_are_blocked_for_both_record_kinds() {
    let mut f = Fixture::new();
    f.register();
    let db = Connection::open(&f.path).unwrap();
    for table in [
        "authority_core_access_requests",
        "authority_core_access_plan_bindings",
    ] {
        assert!(db.execute(&format!("DELETE FROM {table}"), []).is_err());
        assert!(
            db.execute(&format!("UPDATE {table} SET admitted_at=admitted_at+1"), [])
                .is_err()
        );
    }
}

#[test]
fn replace_cannot_rebind_original_identity_aliases_or_plan_binding_without_recursive_triggers() {
    let mut f = Fixture::new();
    f.register();
    let db = Connection::open(&f.path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF;")
        .unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA recursive_triggers", [], |r| r.get(0))
            .unwrap(),
        0
    );
    let before = snapshot(&f.path);
    for collision in 0..3 {
        let mut changed = f.provenance.clone();
        match collision {
            // Same original primary key, every other unique identity changed.
            0 => {
                changed.lease_id = OTHER.into();
                changed.request.idempotency_key = OTHER.into();
            }
            // Only organization/lease identity collides.
            1 => {
                changed.request_id = OTHER.into();
                changed.request.idempotency_key = OTHER.into();
            }
            // Only tenant/idempotency identity collides.
            _ => {
                changed.request_id = OTHER.into();
                changed.lease_id = OTHER.into();
            }
        }
        let canonical = fw_contracts::canonical_bytes(&changed).unwrap();
        let error = db.execute(
            "INSERT OR REPLACE INTO authority_core_access_requests VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            params![f.tenant.org_id(), f.tenant.project_id(), changed.request_id, changed.request_revision, changed.lease_id, changed.delegation.root_id, changed.request.idempotency_key, hex_hash(&canonical_hash(&changed.request).unwrap()), hex_hash(&hash_bytes(&canonical)), NOW + 2, canonical],
        ).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("immutable original access request identity"),
            "{error}"
        );
        assert_eq!(snapshot(&f.path), before);
    }
    let error = db.execute(
        "INSERT OR REPLACE INTO authority_core_access_plan_bindings SELECT org_id,project_id,plan_id,plan_hash,request_id,zeroblob(32),admitted_at+1 FROM authority_core_access_plan_bindings",
        [],
    ).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("immutable access plan binding identity"),
        "{error}"
    );
    assert_eq!(snapshot(&f.path), before);
    // API retries compare the immutable record before INSERT, and still work.
    f.store
        .register_core_access_provenance(
            &f.tenant,
            f.plan["plan_id"].as_str().unwrap(),
            &f.provenance,
            NOW + 2,
        )
        .unwrap();
    f.store = AuthorityStore::open(&f.path).unwrap();
    assert_eq!(
        f.read(NOW + 2).unwrap().unwrap().lease_id,
        f.provenance.lease_id
    );
    assert_eq!(snapshot(&f.path), before);
}

#[test]
fn explicit_rowid_replacement_cannot_delete_original_or_binding_with_fresh_visible_ids() {
    let mut f = Fixture::new();
    f.register();
    let mut later = f.plan.clone();
    later["plan_id"] = json!(OTHER);
    f.store
        .register_plan(&f.tenant, &later, &core::requirements(), NOW + 2)
        .unwrap();
    let db = Connection::open(&f.path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF;")
        .unwrap();
    let before = snapshot(&f.path);
    let error = db.execute(
        "INSERT OR REPLACE INTO authority_core_access_requests(rowid,org_id,project_id,request_id,request_revision,lease_id,root_id,idempotency_key,request_hash,provenance_hash,admitted_at,canonical_bytes) SELECT rowid,org_id,project_id,?,request_revision,?,root_id,?,request_hash,provenance_hash,admitted_at,canonical_bytes FROM authority_core_access_requests",
        params![OTHER, OTHER, OTHER],
    ).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("immutable original access request identity"),
        "{error}"
    );
    assert_eq!(snapshot(&f.path), before);
    let error = db.execute(
        "INSERT OR REPLACE INTO authority_core_access_plan_bindings(rowid,org_id,project_id,plan_id,plan_hash,request_id,provenance_hash,admitted_at) SELECT rowid,org_id,project_id,?,plan_hash,request_id,provenance_hash,admitted_at FROM authority_core_access_plan_bindings",
        params![OTHER],
    ).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("immutable access plan binding identity"),
        "{error}"
    );
    assert_eq!(snapshot(&f.path), before);
}

#[test]
fn read_rechecks_every_stored_request_and_binding_projection() {
    for (table, assignment) in [
        ("authority_core_access_requests", "request_revision=2"),
        (
            "authority_core_access_requests",
            "lease_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'",
        ),
        (
            "authority_core_access_requests",
            "root_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'",
        ),
        (
            "authority_core_access_requests",
            "idempotency_key='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'",
        ),
        (
            "authority_core_access_requests",
            "request_hash=zeroblob(32)",
        ),
        (
            "authority_core_access_requests",
            "provenance_hash=zeroblob(32)",
        ),
        (
            "authority_core_access_requests",
            "root_id=printf('%.*c',131073,'x')",
        ),
        (
            "authority_core_access_requests",
            "request_hash=zeroblob(131073)",
        ),
        ("authority_core_access_requests", "admitted_at=0"),
        ("authority_core_access_requests", "admitted_at=1800000002"),
        (
            "authority_core_access_plan_bindings",
            "plan_hash=zeroblob(32)",
        ),
        (
            "authority_core_access_plan_bindings",
            "provenance_hash=zeroblob(32)",
        ),
        (
            "authority_core_access_plan_bindings",
            "request_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'",
        ),
        (
            "authority_core_access_plan_bindings",
            "request_id=printf('%.*c',131073,'x')",
        ),
        ("authority_core_access_plan_bindings", "admitted_at=0"),
        (
            "authority_core_access_plan_bindings",
            "admitted_at=1800000300",
        ),
    ] {
        let mut f = Fixture::new();
        f.register();
        let db = Connection::open(&f.path).unwrap();
        let guard = integrity_fixture::trigger_sql(&db, &format!("{table}_no_update"));
        db.execute_batch(&format!("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON; DROP TRIGGER {table}_no_update; UPDATE {table} SET {assignment};")).unwrap();
        db.execute_batch(&guard).unwrap();
        let damaged = snapshot(&f.path);
        assert!(f.read(NOW + 5).is_err(), "trusted {table}: {assignment}");
        assert_eq!(snapshot(&f.path), damaged);
    }
}

#[test]
fn damaged_original_bytes_missing_rows_and_oversized_blobs_are_errors_not_absence() {
    for scenario in 0..4 {
        let mut f = Fixture::new();
        f.register();
        let db = Connection::open(&f.path).unwrap();
        let guards = [
            "authority_core_access_requests_no_update",
            "authority_core_access_requests_no_delete",
        ]
        .map(|name| integrity_fixture::trigger_sql(&db, name));
        db.execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER authority_core_access_requests_no_update; DROP TRIGGER authority_core_access_requests_no_delete; PRAGMA ignore_check_constraints=ON;").unwrap();
        match scenario {
            0 => {
                db.execute(
                    "UPDATE authority_core_access_requests SET canonical_bytes=zeroblob(131073)",
                    [],
                )
                .unwrap();
            }
            1 => {
                db.execute("DELETE FROM authority_core_access_requests", [])
                    .unwrap();
            }
            2 => {
                let mut altered = f.provenance.clone();
                altered.request.purpose.push_str(" corrupted");
                let bytes = fw_contracts::canonical_bytes(&altered).unwrap();
                let hash = hex_hash(&hash_bytes(&bytes));
                db.execute(
                    "UPDATE authority_core_access_requests SET canonical_bytes=?,provenance_hash=?",
                    params![bytes, hash],
                )
                .unwrap();
            }
            _ => {
                // Canonical digest matches, but duplicate JSON names remain invalid.
                let bytes = b"{\"schema_version\":\"x\",\"schema_version\":\"x\"}";
                db.execute(
                    "UPDATE authority_core_access_requests SET canonical_bytes=?,provenance_hash=?",
                    params![bytes.as_slice(), hex_hash(&hash_bytes(bytes))],
                )
                .unwrap();
            }
        }
        for guard in guards {
            db.execute_batch(&guard).unwrap();
        }
        let damaged = snapshot(&f.path);
        assert!(f.read(NOW + 2).is_err(), "scenario {scenario}");
        assert_eq!(snapshot(&f.path), damaged);
    }
}
fn hex_hash(hash: &str) -> Vec<u8> {
    (7..71)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hash[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn malformed_and_oversized_imports_leave_all_state_unchanged() {
    let mut f = Fixture::new();
    let before = snapshot(&f.path);
    for change in 0..4 {
        let mut evidence = f.provenance.clone();
        match change {
            0 => evidence.request.purpose = "x".repeat(131073),
            1 => evidence.request_revision = 2,
            2 => evidence.request_id = ANOTHER.into(),
            _ => evidence.envelope.project_id = OTHER.into(),
        }
        assert!(
            f.store
                .register_core_access_provenance(
                    &f.tenant,
                    f.plan["plan_id"].as_str().unwrap(),
                    &evidence,
                    NOW + 1
                )
                .is_err()
        );
        assert_eq!(snapshot(&f.path), before);
    }
}

#[test]
fn concurrent_exact_imports_create_one_original_binding_and_audit() {
    let f = Fixture::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = f.path.clone();
            let tenant = f.tenant.clone();
            let plan_id = f.plan["plan_id"].as_str().unwrap().to_owned();
            let evidence = f.provenance.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = AuthorityStore::open(path).unwrap();
                barrier.wait();
                store
                    .register_core_access_provenance(&tenant, &plan_id, &evidence, NOW + 1)
                    .unwrap()
            })
        })
        .collect();
    for handle in handles {
        assert!(handle.join().unwrap().current);
    }
    assert_eq!(count(&f.path, "authority_core_access_requests"), 1);
    assert_eq!(count(&f.path, "authority_core_access_plan_bindings"), 1);
    let db = Connection::open(&f.path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM authority_audit WHERE kind='core_access_provenance_registered'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
}
