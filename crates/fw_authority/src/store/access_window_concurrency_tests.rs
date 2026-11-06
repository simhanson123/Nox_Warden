//! A peer can admit a first window between selection and the final snapshot.
//! The existing private test connection hook pauses only the reader's COMMIT;
//! the peer uses the real authority API, retained validation and released guards.
use super::super::core_access_review_fixture as fixture;
use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use signing_test_support::private_directory;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, Ordering},
};

#[test]
fn first_window_between_selection_and_final_snapshot_requires_a_fresh_observation() {
    for operation in 0..3 {
        let directory = private_directory::private_directory();
        let path = directory.path().join("authority.sqlite3");
        let mut reader = AuthorityStore::open(&path).unwrap();
        let (plan, requirements, review, provenance, window) = fixture::fixture();
        let tenant = AuthorityTenant::new(
            plan["org_id"].as_str().unwrap(),
            plan["project_id"].as_str().unwrap(),
        )
        .unwrap();
        let plan_id = plan["plan_id"].as_str().unwrap();
        reader
            .provision_target_metadata_project(&tenant, fixture::NOW)
            .unwrap();
        reader
            .register_plan(&tenant, &plan, &requirements, fixture::NOW)
            .unwrap();
        if operation != 1 {
            reader
                .register_core_access_provenance(&tenant, plan_id, &provenance, fixture::NOW)
                .unwrap();
        }
        let mut peer = AuthorityStore::open(&path).unwrap();
        let selected = Arc::new(Barrier::new(2));
        let admitted = Arc::new(Barrier::new(2));
        let paused = Arc::new(AtomicBool::new(false));
        let selected_hook = selected.clone();
        let admitted_hook = admitted.clone();
        let paused_hook = paused.clone();
        reader
            .connection
            .authorizer(Some(move |context: AuthContext<'_>| {
                if matches!(
                    context.action,
                    AuthAction::Transaction {
                        operation: TransactionOperation::Unknown
                    }
                ) && !paused_hook.swap(true, Ordering::SeqCst)
                {
                    selected_hook.wait();
                    admitted_hook.wait();
                }
                Authorization::Allow
            }));
        std::thread::scope(|scope| {
            let peer_tenant = &tenant;
            let peer_plan = &plan;
            let peer_requirements = &requirements;
            let peer_provenance = &provenance;
            let peer_review = &review;
            let peer_window = &window;
            let writer = scope.spawn(move || {
                selected.wait();
                let result = peer.register_reviewed_core_access_plan(
                    peer_tenant,
                    peer_plan,
                    peer_requirements,
                    peer_review,
                    peer_provenance,
                    peer_window,
                    fixture::NOW + 1,
                );
                admitted.wait();
                result.unwrap();
            });
            let result = match operation {
                0 => reader
                    .read_core_access_provenance(&tenant, plan_id, fixture::NOW + 3600)
                    .map(|_| ()),
                1 => reader
                    .register_core_access_provenance(
                        &tenant,
                        plan_id,
                        &provenance,
                        fixture::NOW + 3600,
                    )
                    .map(|_| ()),
                _ => reader
                    .read_core_access_lease_window(&tenant, plan_id, fixture::NOW + 3600)
                    .map(|_| ()),
            };
            writer.join().unwrap();
            assert!(
                matches!(result, Err(AuthorityError::Conflict)),
                "operation {operation}: {result:?}"
            );
        });
        assert!(paused.load(Ordering::SeqCst));
        reader = AuthorityStore::open(&path).unwrap();
        let expired = reader
            .read_core_access_provenance(&tenant, plan_id, fixture::NOW + 3600)
            .unwrap()
            .unwrap();
        assert!(!expired.current);
        assert!(
            !reader
                .read_core_access_lease_window(&tenant, plan_id, fixture::NOW + 2)
                .unwrap()
                .unwrap()
                .current
        );
        assert!(
            !reader
                .read_core_access_provenance(&tenant, plan_id, fixture::NOW + 2)
                .unwrap()
                .unwrap()
                .current
        );
    }
}
