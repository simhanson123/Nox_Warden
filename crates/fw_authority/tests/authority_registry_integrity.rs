#![cfg(feature = "approval-proofs")]
//! Public-API histories, then explicit out-of-band corruption with guards
//! restored. These fixtures do not establish protection from the DB owner.
#[path = "support/approval_authenticator.rs"]
#[allow(dead_code)]
mod approval_authenticator;
#[path = "support/core_access_review_fixture.rs"]
mod core_review_fixture;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/registry_fixture.rs"]
mod registry_fixture;
use fw_authority::AuthorityStore;
use fw_contracts::{canonical_bytes, canonical_hash};
use registry_fixture::{Fixture, NOW, sign_workload};
use rusqlite::{Connection, params};

fn id(n: u8) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn remove_guard(connection: &Connection, name: &str) -> String {
    let sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(&format!("DROP TRIGGER {name}"))
        .unwrap();
    sql
}
fn digest(hash: &str) -> Vec<u8> {
    hash.as_bytes()[7..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn advance_bootstrap(f: &mut Fixture, n: u8, old: u64, next: u64, counter: u32) {
    f.manifest.manifest_id = id(n);
    f.manifest.old_epoch = Some(old.to_string());
    f.manifest.new_epoch = next.to_string();
    f.store
        .stage_bootstrap_manifest(&f.tenant, &f.manifest, f.now)
        .unwrap();
    f.approve(counter);
    f.authorize();
}

#[test]
fn missing_one_workload_head_cannot_hide_behind_another_on_the_same_target() {
    let dir = private_directory::private_directory();
    let mut f = Fixture::new(dir.path(), NOW);
    let mut second = f.workload.payload.clone();
    second.binding_id = id(91);
    second.workload_id = "second-workload".into();
    let second = sign_workload(second, &f.issuer_key, &f.issuer_pin.key_id);
    f.store
        .admit_workload_binding(&f.tenant, &second, NOW)
        .unwrap();
    drop(f.store);
    let connection = Connection::open(&f.path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    let guard = remove_guard(&connection, "authority_workload_heads_no_delete");
    assert_eq!(
        connection
            .execute(
                "DELETE FROM authority_workload_heads WHERE workload_id='second-workload'",
                []
            )
            .unwrap(),
        1
    );
    connection.execute_batch(&guard).unwrap();
    drop(connection);
    assert!(AuthorityStore::open(&f.path).is_err());
}

#[test]
fn workload_epoch_head_preserves_unsigned_maximum_without_wrapping_or_refunding() {
    let dir = private_directory::private_directory();
    let mut f = Fixture::new(dir.path(), NOW);
    let mut payload = f.workload.payload.clone();
    payload.binding_id = id(92);
    payload.binding_epoch = u64::MAX.to_string();
    let newest = sign_workload(payload.clone(), &f.issuer_key, &f.issuer_pin.key_id);
    assert!(
        f.store
            .admit_workload_binding(&f.tenant, &newest, NOW)
            .unwrap()
            .current
    );
    payload.binding_id = id(93);
    payload.binding_epoch = "0".into();
    let wrapped = sign_workload(payload, &f.issuer_key, &f.issuer_pin.key_id);
    assert!(
        f.store
            .admit_workload_binding(&f.tenant, &wrapped, NOW)
            .is_err()
    );
    assert!(
        !f.store
            .read_registry_object(
                &f.tenant,
                "workload_binding",
                &f.workload.payload.binding_id,
                NOW
            )
            .unwrap()
            .unwrap()
            .current
    );
    drop(f.store);
    let mut store = AuthorityStore::open(&f.path).unwrap();
    assert!(
        store
            .read_registry_object(
                &f.tenant,
                "workload_binding",
                &newest.payload.binding_id,
                NOW
            )
            .unwrap()
            .unwrap()
            .current
    );
}

#[test]
fn duplicate_older_workload_epoch_is_rejected_even_when_a_later_head_exists() {
    let dir = private_directory::private_directory();
    let mut f = Fixture::new(dir.path(), NOW);
    let mut payload = f.workload.payload.clone();
    payload.binding_id = id(94);
    payload.binding_epoch = "2".into();
    let newest = sign_workload(payload, &f.issuer_key, &f.issuer_pin.key_id);
    f.store
        .admit_workload_binding(&f.tenant, &newest, NOW)
        .unwrap();
    let mut payload = f.workload.payload.clone();
    payload.binding_id = id(95);
    let duplicate = sign_workload(payload, &f.issuer_key, &f.issuer_pin.key_id);
    let canonical = canonical_bytes(&duplicate).unwrap();
    drop(f.store);
    let connection = Connection::open(&f.path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection
        .execute(
            "INSERT INTO authority_registry_objects VALUES(?,?,?,?,?,?,?,?)",
            params![
                f.tenant.org_id(),
                f.tenant.project_id(),
                "workload_binding",
                duplicate.payload.binding_id,
                digest(&canonical_hash(&duplicate).unwrap()),
                duplicate.payload.target_id,
                NOW,
                canonical
            ],
        )
        .unwrap();
    drop(connection);
    assert!(AuthorityStore::open(&f.path).is_err());
}

#[test]
fn retained_bootstrap_chain_cannot_skip_a_removed_middle_authorization() {
    let dir = private_directory::private_directory();
    let mut f = Fixture::new(dir.path(), NOW);
    f.approve(2);
    f.authorize();
    advance_bootstrap(&mut f, 96, 1, 2, 3);
    let middle = f.manifest.manifest_id.clone();
    advance_bootstrap(&mut f, 97, 2, 3, 4);
    drop(f.store);
    let connection = Connection::open(&f.path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    let guard = remove_guard(&connection, "authority_registry_objects_no_delete");
    assert_eq!(connection.execute("DELETE FROM authority_registry_objects WHERE object_kind='bootstrap_authorization' AND object_id=?",[middle]).unwrap(),1);
    connection.execute_batch(&guard).unwrap();
    drop(connection);
    assert!(AuthorityStore::open(&f.path).is_err());
}

#[test]
fn bootstrap_head_rewind_is_rejected_after_original_guard_is_restored() {
    let dir = private_directory::private_directory();
    let mut f = Fixture::new(dir.path(), NOW);
    f.approve(2);
    let first = f.authorize();
    let manifest_hash = f.manifest.hash().unwrap();
    let authorization_hash = canonical_hash(&first.authorization).unwrap();
    advance_bootstrap(&mut f, 98, 1, 2, 3);
    drop(f.store);
    let connection = Connection::open(&f.path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    let guard = remove_guard(&connection, "authority_bootstrap_pending_head_monotone");
    connection.execute("UPDATE authority_bootstrap_pending_heads SET authority_epoch=?,manifest_hash=?,authorization_hash=?",params![1u64.to_be_bytes().as_slice(),digest(&manifest_hash),digest(&authorization_hash)]).unwrap();
    connection.execute_batch(&guard).unwrap();
    drop(connection);
    assert!(AuthorityStore::open(&f.path).is_err());
}

#[test]
fn bootstrap_epoch_chain_accepts_a_monotonic_jump_to_unsigned_maximum() {
    let dir = private_directory::private_directory();
    let mut f = Fixture::new(dir.path(), NOW);
    f.approve(2);
    f.authorize();
    advance_bootstrap(&mut f, 99, 1, u64::MAX, 3);
    drop(f.store);
    let mut store = AuthorityStore::open(&f.path).unwrap();
    let status = store
        .read_registry_object(
            &f.tenant,
            "bootstrap_authorization",
            &f.manifest.manifest_id,
            NOW,
        )
        .unwrap()
        .unwrap();
    assert!(!status.current);
    assert!(!status.signing_allowed);
    assert!(!status.dispatch_allowed);
    assert_eq!(status.state, "authorized_pending_target_confirmation");
}

#[test]
fn core_bootstrap_matches_management_baseline_not_full_managed_state_hash() {
    for substitute_full_state_hash in [false, true] {
        let directory = private_directory::private_directory();
        let mut f = Fixture::new(directory.path(), NOW);
        let (mut plan, requirements, _, mut provenance, _) =
            core_review_fixture::fixture_at(NOW, 0);
        provenance.envelope = f.envelope.clone();
        provenance.delegation = f.delegation.clone();
        plan["workload_binding_hash"] = canonical_hash(&f.workload).unwrap().into();
        plan["workload_binding_valid_until"] = f.workload.payload.expires_at.clone().into();
        plan["authority_epoch"] = "1".into();
        core_review_fixture::core::rehash(&mut plan, &mut provenance);
        let review = core_review_fixture::rebuild(&mut plan, &provenance);
        let window = core_review_fixture::window(&plan, &provenance);
        assert_ne!(
            review.before.management_baseline_hash,
            plan["baseline_hash"]
        );
        let principal = plan["principal_id"].as_str().unwrap();
        if principal != registry_fixture::OWNER {
            f.store
                .provision_principal(
                    &f.tenant,
                    principal,
                    "https://fixture.workload.example",
                    principal,
                    NOW,
                )
                .unwrap();
        }
        f.store
            .register_reviewed_core_access_plan(
                &f.tenant,
                &plan,
                &requirements,
                &review,
                &provenance,
                &window,
                NOW,
            )
            .unwrap();
        f.manifest.manifest_id = id(100);
        f.manifest.capability_hash = plan["target_capability_hash"].as_str().unwrap().into();
        f.manifest.management_baseline_hash = if substitute_full_state_hash {
            plan["baseline_hash"].as_str().unwrap().into()
        } else {
            review.before.management_baseline_hash.clone()
        };
        f.store
            .stage_bootstrap_manifest(&f.tenant, &f.manifest, NOW)
            .unwrap();
        f.approve(2);
        let signed = f.authorize();
        let status = f
            .store
            .read_core_authority_status(&f.tenant, plan["plan_id"].as_str().unwrap(), NOW)
            .unwrap();
        if substitute_full_state_hash {
            assert!(status.bootstrap_authorization_hash.is_none());
        } else {
            assert_eq!(
                status.bootstrap_authorization_hash.as_deref(),
                Some(signed.status.content_hash.as_str())
            );
        }
        assert!(!status.signing_allowed && !status.dispatch_allowed);
    }
}
