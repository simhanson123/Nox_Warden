use super::*;

fn project_only(root: &SigningRootQuotaPin) -> SigningProjectQuotaPin {
    let mut pin: SigningProjectQuotaPin = root.clone().into();
    pin.root_id = None;
    pin
}

#[test]
fn version_one_pin_and_snapshot_bytes_round_trip_exactly_after_cutover() {
    let mut f = Fixture::new(limits(), limits());
    let saved = f.reserve(20, &change(1), NOW).unwrap();
    assert_eq!(saved.schema_version, "fw.signing-budget-reservation/v1");
    let (rowid,old):(i64,Vec<u8>)=f.store.connection.query_row("SELECT rowid,canonical_bytes FROM authority_signing_quota_pins WHERE bucket_kind='project' AND revision=1",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    let expected=bytes(&json!({"org_id":f.tenant.org_id,"bucket_kind":"project","bucket_id":f.tenant.project_id,"revision":"1","pinned_at":at(NOW).unwrap(),"pin":pin(limits())})).unwrap();
    assert_eq!(old, expected);
    let snapshot:Vec<u8>=f.store.connection.query_row("SELECT snapshot_bytes FROM authority_signing_quota_reservations WHERE reservation_id=?",[&id(20)],|r|r.get(0)).unwrap();
    assert_eq!(
        bytes(&decode::<Snapshot>(&snapshot).unwrap()).unwrap(),
        snapshot
    );
    f.store
        .pin_signing_project_quota(&f.tenant, &project_only(&pin(limits())), Some(1), NOW)
        .unwrap();
    let after:(i64,Vec<u8>)=f.store.connection.query_row("SELECT rowid,canonical_bytes FROM authority_signing_quota_pins WHERE bucket_kind='project' AND revision=1",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert_eq!(after, (rowid, old));
    let tx = f.store.connection.transaction().unwrap();
    let retained = read(&tx, &f.tenant, &id(20)).unwrap();
    assert_eq!(bytes(&retained).unwrap(), bytes(&saved).unwrap());
}

#[test]
fn retained_v1_full_lease_charge_and_occupancy_do_not_require_a_new_window() {
    // Primitive accounting only: no signer, target receipt or core authority is
    // fabricated. Fresh plan eligibility must not be imposed on saved ledgers.
    let mut f = Fixture::new(limits(), limits());
    let mut cost = lease(1, &[42, 43]);
    cost.lease_seconds = 3600;
    f.reserve(20, &cost, NOW).unwrap();
    f.finalize(20, NOW + 1).unwrap();
    let before: (Vec<u8>, Vec<u8>, i64) = f.store.connection.query_row("SELECT cost_bytes,snapshot_bytes,lease_seconds FROM authority_signing_quota_reservations WHERE reservation_id=?", [&id(20)], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(before.2, 3600);
    assert_eq!(
        decode::<Snapshot>(&before.1).unwrap().schema_version,
        "fw.signing-budget-reservation/v1"
    );
    assert_eq!(f.count("authority_core_access_lease_windows"), 0);
    let tx = f.store.connection.transaction().unwrap();
    let saved = read(&tx, &f.tenant, &id(20)).unwrap();
    assert_eq!(saved.state, "issued");
    assert_eq!(saved.cost.lease_seconds, 3600);
    let usage = account(
        &tx,
        &f.tenant,
        AccountingScope::Root(&id(10)),
        NOW + 7200,
        None,
    )
    .unwrap();
    assert_eq!(usage.cumulative_seconds_per_day, 3600);
    assert_eq!(usage.new_leases_per_day, 1);
    assert_eq!(usage.active_leases, 1);
    assert_eq!(usage.concurrent_deployments, 1);
    assert_eq!(usage.unique_destinations_per_day, 2);
    let after: (Vec<u8>, Vec<u8>, i64) = tx.query_row("SELECT cost_bytes,snapshot_bytes,lease_seconds FROM authority_signing_quota_reservations WHERE reservation_id=?", [&id(20)], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(after, before);
}

#[test]
fn project_cutover_preserves_initial_root_anchor_and_rejects_stale_cas() {
    let mut f = Fixture::new(limits(), limits());
    let rooted = pin(limits());
    let rootless = project_only(&rooted);
    assert_eq!(
        f.store
            .pin_signing_project_quota(&f.tenant, &rootless, Some(1), NOW)
            .unwrap(),
        2
    );
    assert!(matches!(
        f.store
            .pin_signing_project_quota(&f.tenant, &rootless, Some(1), NOW),
        Err(AuthorityError::Conflict)
    ));
    let mut other = rooted.clone();
    other.root_id = id(11);
    f.store
        .pin_signing_root_quota(&f.tenant, &other, None, NOW)
        .unwrap();
    assert!(matches!(
        f.store
            .pin_signing_project_quota(&f.tenant, &other, Some(2), NOW),
        Err(AuthorityError::Binding)
    ));
    assert_eq!(
        f.store
            .pin_signing_project_quota(&f.tenant, &rooted, Some(2), NOW)
            .unwrap(),
        3
    );
    assert_eq!(
        f.store
            .pin_signing_project_quota(&f.tenant, &rootless, Some(3), NOW)
            .unwrap(),
        4
    );
    assert!(
        f.store
            .pin_signing_project_quota(&f.tenant, &other, Some(4), NOW)
            .is_err()
    );
    let new_project = AuthorityTenant::new(&id(1), &id(3)).unwrap();
    f.store
        .provision_target_metadata_project(&new_project, NOW)
        .unwrap();
    f.store
        .pin_signing_project_quota(&new_project, &rootless, None, NOW)
        .unwrap();
    assert!(matches!(
        f.store
            .pin_signing_project_quota(&new_project, &rooted, Some(1), NOW),
        Err(AuthorityError::Binding)
    ));
}

#[test]
fn retained_project_pin_cannot_change_the_anchor_through_direct_sql() {
    let mut f = Fixture::new(limits(), limits());
    f.store
        .pin_signing_project_quota(&f.tenant, &project_only(&pin(limits())), Some(1), NOW)
        .unwrap();
    let mut other = pin(limits());
    other.root_id = id(11);
    f.store
        .pin_signing_root_quota(&f.tenant, &other, None, NOW)
        .unwrap();
    let record = PinRecord {
        schema_version: None,
        org_id: f.tenant.org_id.clone(),
        bucket_kind: "project".into(),
        bucket_id: f.tenant.project_id.clone(),
        revision: "3".into(),
        pinned_at: at(NOW).unwrap(),
        pin: other.clone().into(),
    };
    let canonical = bytes(&record).unwrap();
    let tx = f.store.connection.transaction().unwrap();
    tx.execute(
        "INSERT INTO authority_signing_quota_pins VALUES(?,?,?,?,?,?,?,?)",
        params![
            f.tenant.org_id,
            "project",
            f.tenant.project_id,
            3,
            other.root_id,
            NOW,
            hash(&hash_bytes(&canonical)).unwrap(),
            canonical
        ],
    )
    .unwrap();
    tx.execute(
        "UPDATE authority_signing_quota_heads SET revision=3 WHERE bucket_kind='project'",
        [],
    )
    .unwrap();
    assert!(configuration(&tx, &f.tenant, NOW).is_err());
}

#[test]
fn rootless_snapshots_have_no_root_metadata_and_reject_versions_nulls_and_partial_roots() {
    let mut f = Fixture::new(limits(), limits());
    f.store
        .pin_signing_project_quota(&f.tenant, &project_only(&pin(limits())), Some(1), NOW)
        .unwrap();
    let saved = f.reserve(20, &change(1), NOW).unwrap();
    assert_eq!(saved.schema_version, "fw.signing-budget-reservation/v2");
    assert!(saved.root_id.is_none());
    assert!(saved.root_revision.is_none());
    assert!(saved.root_pin_hash.is_none());
    assert!(saved.root_projected.is_none());
    let raw:Vec<u8>=f.store.connection.query_row("SELECT snapshot_bytes FROM authority_signing_quota_reservations WHERE reservation_id=?",[&id(20)],|r|r.get(0)).unwrap();
    let original: Value = decode(&raw).unwrap();
    for key in [
        "root_id",
        "root_revision",
        "root_pin_hash",
        "root_projected",
    ] {
        assert!(original.get(key).is_none());
    }
    let guard:String=f.store.connection.query_row("SELECT sql FROM sqlite_schema WHERE name='authority_signing_quota_reservations_immutable'",[],|r|r.get(0)).unwrap();
    for mutation in 0..8 {
        let mut malformed = original.clone();
        match mutation {
            0 => malformed["schema_version"] = "fw.signing-budget-reservation/v3".into(),
            1 => malformed["schema_version"] = "fw.signing-budget-reservation/v1".into(),
            2 => malformed["root_id"] = Value::Null,
            3 => malformed["root_id"] = id(10).into(),
            4 => malformed["root_revision"] = "1".into(),
            5 => malformed["root_pin_hash"] = hash_bytes(b"root").into(),
            6 => {
                malformed["root_projected"] = json!({"active_leases":0,"new_leases_per_day":0,"unique_destinations_per_day":0,"cumulative_seconds_per_day":0,"concurrent_deployments":1})
            }
            _ => malformed["unknown_field"] = true.into(),
        }
        let tx = f.store.connection.transaction().unwrap();
        tx.execute_batch("DROP TRIGGER authority_signing_quota_reservations_immutable")
            .unwrap();
        tx.execute("UPDATE authority_signing_quota_reservations SET snapshot_bytes=? WHERE reservation_id=?",params![bytes(&malformed).unwrap(),id(20)]).unwrap();
        tx.execute_batch(&guard).unwrap();
        assert!(
            read(&tx, &f.tenant, &id(20)).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn rootless_configuration_uses_only_project_clock_and_refuses_lease_costs() {
    let mut f = Fixture::new(limits(), limits());
    let rootless = project_only(&pin(limits()));
    f.store
        .pin_signing_project_quota(&f.tenant, &rootless, Some(1), NOW)
        .unwrap();
    f.store
        .observe_quota_bucket(&f.tenant, "root", &id(10), NOW + 100)
        .unwrap();
    f.store
        .observe_signing_quota_time(&f.tenant, NOW + 1)
        .unwrap();
    let tx = f.store.connection.transaction().unwrap();
    assert_eq!(
        quota_configuration_summary(&tx, &f.tenant, NOW + 1).unwrap(),
        Some((None, rootless.not_after))
    );
    assert!(matches!(
        reserve(&tx, &f.tenant, &id(20), &lease(1, &[1]), NOW + 301, NOW + 1),
        Err(AuthorityError::Binding)
    ));
    assert!(reserve(&tx, &f.tenant, &id(21), &change(1), NOW + 301, NOW + 1).is_ok());
}
