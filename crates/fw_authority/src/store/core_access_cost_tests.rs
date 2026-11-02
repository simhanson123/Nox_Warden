use super::*;
#[path = "../../tests/support/core_access_fixture.rs"]
mod fixture;
use signing_test_support::private_directory;

struct CoreFixture {
    _directory: tempfile::TempDir,
    store: AuthorityStore,
    tenant: AuthorityTenant,
    plan: Value,
    provenance: crate::CoreAccessProvenance,
}
impl CoreFixture {
    fn new() -> Self {
        let directory = private_directory::private_directory();
        let mut store = AuthorityStore::open(directory.path().join("authority.sqlite3")).unwrap();
        let (plan, provenance) = fixture::fixture();
        let tenant = AuthorityTenant::new(
            plan["org_id"].as_str().unwrap(),
            plan["project_id"].as_str().unwrap(),
        )
        .unwrap();
        store
            .provision_target_metadata_project(&tenant, fixture::NOW)
            .unwrap();
        store
            .register_plan(&tenant, &plan, &fixture::requirements(), fixture::NOW)
            .unwrap();
        store
            .register_core_access_provenance(
                &tenant,
                plan["plan_id"].as_str().unwrap(),
                &provenance,
                fixture::NOW,
            )
            .unwrap();
        Self {
            _directory: directory,
            store,
            tenant,
            plan,
            provenance,
        }
    }
    fn pin(&self) -> SigningRootQuotaPin {
        let d = &self.provenance.delegation;
        SigningRootQuotaPin {
            root_id: d.root_id.clone(),
            limits: SigningQuotaLimits {
                active_leases: d.max_active_leases as i64,
                new_leases_per_day: d.max_new_leases_per_day as i64,
                unique_destinations_per_day: d.max_unique_destinations_per_day as i64,
                cumulative_seconds_per_day: d.max_cumulative_lease_seconds_per_day as i64,
                concurrent_deployments: d.max_concurrent_deployments as i64,
            },
            not_before: fixture::NOW,
            not_after: fixture::NOW + 3600,
        }
    }
    fn configure(&mut self, pin: &SigningRootQuotaPin) {
        self.store
            .pin_signing_root_quota(&self.tenant, pin, None, fixture::NOW)
            .unwrap();
        self.store
            .pin_signing_project_quota(&self.tenant, pin, None, fixture::NOW)
            .unwrap();
    }
    fn cost(&mut self, now: i64) -> Result<SigningQuotaCost> {
        let tx = self.store.connection.transaction().unwrap();
        cost_for_plan(
            &tx,
            &self.tenant,
            self.plan["plan_id"].as_str().unwrap(),
            now,
        )
    }
}

#[test]
fn core_cost_keeps_full_original_duration_and_destination_membership() {
    let mut f = CoreFixture::new();
    f.configure(&f.pin());
    let cost = f.cost(fixture::NOW + 299).unwrap();
    assert_eq!(cost.lease_seconds, 3600);
    assert_eq!(
        cost.lease_id.as_deref(),
        Some(f.provenance.lease_id.as_str())
    );
    let mut ids = f.provenance.request.destination_asset_ids.clone();
    ids.sort();
    assert_eq!(cost.destination_asset_ids, ids);
    assert_eq!(cost.plan_hash, canonical_hash(&f.plan).unwrap());
    let tx = f.store.connection.transaction().unwrap();
    let usage = account(
        &tx,
        &f.tenant,
        &f.provenance.delegation.root_id,
        true,
        fixture::NOW + 299,
        Some(&cost),
    )
    .unwrap();
    assert_eq!(usage.cumulative_seconds_per_day, 3600);
    assert_eq!(usage.new_leases_per_day, 1);
    assert_eq!(usage.active_leases, 1);
    assert_eq!(usage.unique_destinations_per_day, ids.len() as i64);
    assert_eq!(usage.concurrent_deployments, 1);
}

#[test]
fn shorter_plan_cannot_admit_full_request_through_smaller_budget() {
    let mut f = CoreFixture::new();
    let mut pin = f.pin();
    pin.limits.cumulative_seconds_per_day = 1800;
    f.configure(&pin);
    let cost = f.cost(fixture::NOW).unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert!(matches!(
        reserve(
            &tx,
            &f.tenant,
            "00000000-0000-4000-8000-000000000061",
            &cost,
            fixture::NOW + 300,
            fixture::NOW
        ),
        Err(AuthorityError::Quota)
    ));
    let count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM authority_signing_quota_reservations",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn core_cost_requires_current_matching_independent_root() {
    let mut f = CoreFixture::new();
    assert!(f.cost(fixture::NOW).is_err());
    let mut wrong = f.pin();
    wrong.root_id = "00000000-0000-4000-8000-000000000062".into();
    f.configure(&wrong);
    assert!(f.cost(fixture::NOW).is_err());
    let mut f = CoreFixture::new();
    f.configure(&f.pin());
    assert!(f.cost(fixture::NOW).is_ok());
    f.store
        .revoke_signing_root_quota(
            &f.tenant,
            &f.provenance.delegation.root_id,
            1,
            fixture::NOW + 1,
        )
        .unwrap();
    assert!(f.cost(fixture::NOW + 1).is_err());
    assert!(f.cost(fixture::NOW).is_err());
}

#[test]
fn core_cost_rejects_every_independently_pinned_limit_above_original_delegation() {
    for field in 0..5 {
        let mut f = CoreFixture::new();
        let mut pin = f.pin();
        let limits = &mut pin.limits;
        *match field {
            0 => &mut limits.active_leases,
            1 => &mut limits.new_leases_per_day,
            2 => &mut limits.unique_destinations_per_day,
            3 => &mut limits.cumulative_seconds_per_day,
            _ => &mut limits.concurrent_deployments,
        } += 1;
        f.configure(&pin);
        assert!(f.cost(fixture::NOW).is_err(), "limit {field}");
    }
}

#[test]
fn core_readiness_distinguishes_cost_binding_from_unavailable_signing_profile() {
    let mut f = CoreFixture::new();
    let verifier = WebAuthn::new("http://localhost:8787").unwrap();
    f.configure(&f.pin());
    let plan_id = f.plan["plan_id"].as_str().unwrap();
    let ready = f
        .store
        .signing_readiness(&f.tenant, plan_id, &verifier, fixture::NOW)
        .unwrap();
    assert!(!ready.signing_allowed && !ready.dispatch_allowed);
    assert!(ready.quota_configured);
    assert!(
        ready
            .reasons
            .iter()
            .any(|r| r == "CORE_SIGNING_PROFILE_UNAVAILABLE")
    );
    assert!(
        !ready
            .reasons
            .iter()
            .any(|r| r == "CORE_REQUEST_BINDING_UNAVAILABLE")
    );
    let request = SigningRequest {
        request_id: "00000000-0000-4000-8000-000000000063".into(),
        plan_id: plan_id.into(),
        expected_plan_hash: canonical_hash(&f.plan).unwrap(),
        expected_approval_set_hash: hash_bytes(b"provenance is not approval"),
    };
    assert!(
        f.store
            .prepare_signing_intent(&f.tenant, &verifier, &request, fixture::NOW)
            .is_err()
    );
    assert!(f.cost(fixture::NOW + 300).is_err());
    let expired = f
        .store
        .signing_readiness(&f.tenant, &request.plan_id, &verifier, fixture::NOW + 300)
        .unwrap();
    assert!(
        expired
            .reasons
            .iter()
            .any(|r| r == "CORE_REQUEST_BINDING_UNAVAILABLE")
    );
    assert!(expired.reasons.iter().any(|r| r == "PLAN_STALE"));
    for table in [
        "authority_signing_intents",
        "authority_signing_jobs",
        "authority_signing_quota_reservations",
        "authority_signing_outbox",
    ] {
        let count: i64 = f
            .store
            .connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}
