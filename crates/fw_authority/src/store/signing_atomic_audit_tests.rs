//! Independent reproductions against published schema12, followed by opposite
//! schema13 regressions. Legacy metadata is reconstructed around real lifecycle
//! evidence; these fixtures are not described as old-binary-created databases.
use super::super::signing_test_support::{Fixture, NOW};
use super::*;

const WORKER: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

// Exercise published SQL against deliberate legacy/unsafe connection settings
// without disabling the live store's connection-integrity boundary.
fn forensic_connection(fixture: &Fixture) -> Connection {
    let db = Connection::open(&fixture.path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
        .unwrap();
    db
}

fn assert_public_read_refused(fixture: &mut Fixture, job: &str) {
    let intent: String = fixture
        .store
        .connection
        .query_row(
            "SELECT intent_id FROM authority_signing_jobs WHERE job_id=?",
            [job],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        fixture
            .store
            .read_signing_intent(&fixture.tenant, &intent, NOW)
            .is_err()
    );
}

fn prepared() -> (Fixture, String) {
    let mut fixture = Fixture::new();
    let outcome = signing_intents::test_prepare(&mut fixture, NOW);
    (fixture, outcome.intent.job_id)
}

fn rows(db: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let mut query = db
        .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
        .unwrap();
    let columns = query.column_count();
    query
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn work_rows(db: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "authority_signing_work_events",
        "authority_signing_work_heads",
        "authority_signing_work_audits",
        "authority_signing_quota_reservations",
        "authority_signing_quota_transitions",
        "authority_signing_quota_transition_heads",
    ]
    .iter()
    .map(|table| rows(db, table))
    .collect()
}

fn audit_head(db: &Connection, tenant: &AuthorityTenant) -> (u64, Vec<u8>) {
    db.query_row(
        "SELECT sequence,event_hash FROM authority_audit_heads WHERE org_id=? AND project_id=?",
        params![tenant.org_id, tenant.project_id],
        |row| Ok((u64::from_be_bytes(row.get(0)?), row.get(1)?)),
    )
    .unwrap()
}

fn append_at(
    db: &Connection,
    tenant: &AuthorityTenant,
    sequence: u64,
    previous: &[u8],
    kind: &str,
    resource: &str,
) -> rusqlite::Result<usize> {
    let canonical = bytes(&json!({
        "schema_version":"fw.authority-audit/v1",
        "org_id":tenant.org_id,"project_id":tenant.project_id,
        "sequence":sequence.to_string(),"previous_hash":hash_string(previous).unwrap(),
        "kind":kind,"resource_id":resource,"recorded_at":at(NOW).unwrap()
    }))
    .unwrap();
    db.execute(
        "INSERT INTO authority_audit VALUES(?,?,?,?,?,?,?,?,?)",
        params![
            tenant.org_id,
            tenant.project_id,
            sequence.to_be_bytes().as_slice(),
            hash(&hash_bytes(&canonical)).unwrap(),
            previous,
            kind,
            resource,
            NOW,
            canonical
        ],
    )
}

fn append(db: &Connection, tenant: &AuthorityTenant, kind: &str, resource: &str) {
    let (sequence, previous) = audit_head(db, tenant);
    append_at(db, tenant, sequence + 1, &previous, kind, resource).unwrap();
    // Published schema12 required a separate projection statement. Schema13
    // projects the head as part of the audit INSERT itself.
    let version: i64 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    if version <= 12 {
        db.execute(
            "UPDATE authority_audit_heads SET sequence=?1,event_hash=(SELECT event_hash FROM authority_audit WHERE org_id=?2 AND project_id=?3 AND sequence=?1) WHERE org_id=?2 AND project_id=?3",
            params![(sequence + 1).to_be_bytes().as_slice(), tenant.org_id, tenant.project_id],
        )
        .unwrap();
    }
}

fn bind_claim(db: &Connection, tenant: &AuthorityTenant, job: &str) -> rusqlite::Result<usize> {
    db.execute(
        "INSERT INTO authority_signing_work_audits SELECT ?1,?2,?3,'signer',?4,'claimed',?5,sequence,event_hash FROM authority_audit_heads WHERE org_id=?1 AND project_id=?2",
        params![tenant.org_id, tenant.project_id, job, 2u64.to_be_bytes().as_slice(), NOW],
    )
}

fn raw_claim(db: &Connection, job: &str) -> rusqlite::Result<usize> {
    db.execute(
        "INSERT INTO authority_signing_work_events SELECT org_id,project_id,job_id,phase,'claimed',?1,?2,?3,?4,?5,1,available_at,updated_at,'claimed' FROM authority_signing_work_heads WHERE job_id=?6 AND phase='signer'",
        params![2u64.to_be_bytes().as_slice(),1u64.to_be_bytes().as_slice(),vec![1u8;32],WORKER,NOW+60,job],
    )
}

#[test]
fn published_schema12_accepts_a_canonical_audit_gap_without_advancing_its_head() {
    let (mut fixture, job) = prepared();
    migrations::legacy::restore_v12(&fixture.path);
    let mut db = forensic_connection(&fixture);
    let original = audit_head(&db, &fixture.tenant);
    append_at(
        &db,
        &fixture.tenant,
        original.0 + 2,
        &original.1,
        "fixture_gap",
        &job,
    )
    .unwrap();
    assert_eq!(audit_head(&db, &fixture.tenant), original);
    assert_public_read_refused(&mut fixture, &job);
    let tx = db.transaction().unwrap();
    assert!(audit_log::validate_retained_chains(&tx).is_err());
    assert!(audit_log::append_head(&tx, &fixture.tenant).is_err());
}

#[test]
fn published_schema12_commits_an_orphan_binding_then_consumes_it_after_another_audit() {
    let (mut fixture, job) = prepared();
    migrations::legacy::restore_v12(&fixture.path);
    let mut db = forensic_connection(&fixture);
    db.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA recursive_triggers=OFF")
        .unwrap();
    append(&db, &fixture.tenant, "signing_signer_claimed", &job);
    bind_claim(&db, &fixture.tenant, &job).unwrap();
    assert!(
        db.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )
        .unwrap()
    );
    assert_public_read_refused(&mut fixture, &job);
    let tx = db.transaction().unwrap();
    assert!(work_history(&tx, &fixture.tenant, &job, "signer").is_err());
    tx.commit().unwrap();
    append(&db, &fixture.tenant, "fixture_intervening", &job);
    raw_claim(&db, &job).unwrap();
    assert!(
        !db.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )
        .unwrap()
    );
    let tx = db.transaction().unwrap();
    assert_eq!(
        work_history(&tx, &fixture.tenant, &job, "signer")
            .unwrap()
            .current
            .unwrap()
            .revision,
        2
    );
    let consumed: Vec<u8> = tx.query_row(
        "SELECT audit_sequence FROM authority_signing_work_audits WHERE job_id=? AND revision=?",
        params![job, 2u64.to_be_bytes().as_slice()], |row| row.get(0),
    ).unwrap();
    assert!(u64::from_be_bytes(consumed.try_into().unwrap()) < audit_head(&tx, &fixture.tenant).0);
}

#[test]
fn audit_insert_requires_exact_successor_and_projects_its_head_atomically() {
    let (mut fixture, job) = prepared();
    let db = forensic_connection(&fixture);
    db.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA recursive_triggers=OFF")
        .unwrap();
    let original_head = audit_head(&db, &fixture.tenant);
    let original_events = rows(&db, "authority_audit");
    for (sequence, previous) in [
        (original_head.0 + 2, original_head.1.clone()),
        (original_head.0 + 1, vec![7u8; 32]),
        (0, original_head.1.clone()),
    ] {
        assert!(
            append_at(
                &db,
                &fixture.tenant,
                sequence,
                &previous,
                "fixture_invalid",
                &job
            )
            .is_err()
        );
        assert_eq!(audit_head(&db, &fixture.tenant), original_head);
        assert_eq!(rows(&db, "authority_audit"), original_events);
    }
    append(&db, &fixture.tenant, "fixture_exact", &job);
    assert_eq!(audit_head(&db, &fixture.tenant).0, original_head.0 + 1);
    fixture.reopen();
    fixture
        .store
        .verify_audit_chain(&fixture.tenant)
        .unwrap()
        .unwrap();
}

#[test]
fn failed_audit_head_projection_rolls_back_the_complete_insert_statement() {
    let (mut fixture, job) = prepared();
    let db = forensic_connection(&fixture);
    let before_events = rows(&db, "authority_audit");
    let before_heads = rows(&db, "authority_audit_heads");
    db.execute_batch("PRAGMA recursive_triggers=OFF; CREATE TRIGGER fixture_reject_audit_head BEFORE UPDATE ON authority_audit_heads BEGIN SELECT RAISE(ABORT,'fixture head failure'); END;").unwrap();
    let (sequence, previous) = audit_head(&db, &fixture.tenant);
    assert!(
        append_at(
            &db,
            &fixture.tenant,
            sequence + 1,
            &previous,
            "fixture_failure",
            &job
        )
        .is_err()
    );
    assert_eq!(rows(&db, "authority_audit"), before_events);
    assert_eq!(rows(&db, "authority_audit_heads"), before_heads);
    assert_public_read_refused(&mut fixture, &job);
}

#[test]
fn work_insert_consumes_only_current_audit_and_creates_binding_even_with_foreign_keys_off() {
    let (mut fixture, job) = prepared();
    let mut db = forensic_connection(&fixture);
    db.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA recursive_triggers=OFF")
        .unwrap();
    let original_work = work_rows(&db);
    let original_audits = rows(&db, "authority_audit");
    let original_heads = rows(&db, "authority_audit_heads");
    let tx = db.transaction().unwrap();
    append(&tx, &fixture.tenant, "signing_signer_claimed", &job);
    assert!(bind_claim(&tx, &fixture.tenant, &job).is_err());
    assert_eq!(work_rows(&tx), original_work);
    append(&tx, &fixture.tenant, "fixture_intervening", &job);
    assert!(raw_claim(&tx, &job).is_err());
    assert_eq!(work_rows(&tx), original_work);
    // Neither failed attempt may leave a committed work audit behind. Keep
    // those deliberate transient prefixes in a rolled-back transaction.
    tx.rollback().unwrap();
    assert_eq!(rows(&db, "authority_audit"), original_audits);
    assert_eq!(rows(&db, "authority_audit_heads"), original_heads);

    let tx = db.transaction().unwrap();
    append(&tx, &fixture.tenant, "signing_signer_claimed", &job);
    let expected = audit_head(&tx, &fixture.tenant);
    raw_claim(&tx, &job).unwrap();
    let actual: (Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT audit_sequence,audit_hash FROM authority_signing_work_audits WHERE job_id=? AND phase='signer' AND revision=?",
        params![job, 2u64.to_be_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(u64::from_be_bytes(actual.0.try_into().unwrap()), expected.0);
    assert_eq!(actual.1, expected.1);
    assert!(
        !tx.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )
        .unwrap()
    );
    tx.commit().unwrap();
    fixture.reopen();
    let tx = fixture.store.connection.transaction().unwrap();
    validate_work_histories(&tx).unwrap();
}

#[test]
fn failed_trigger_created_binding_rolls_back_event_and_work_head_with_recursive_triggers_off() {
    let (mut fixture, job) = prepared();
    let db = forensic_connection(&fixture);
    db.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA recursive_triggers=OFF")
        .unwrap();
    append(&db, &fixture.tenant, "signing_signer_claimed", &job);
    let before = work_rows(&db);
    db.execute_batch("CREATE TRIGGER fixture_reject_work_binding BEFORE INSERT ON authority_signing_work_audits BEGIN SELECT RAISE(ABORT,'fixture binding failure'); END;").unwrap();
    assert!(raw_claim(&db, &job).is_err());
    assert_eq!(work_rows(&db), before);
    assert_public_read_refused(&mut fixture, &job);
}

#[test]
fn audit_successor_sql_handles_every_nibble_carry_signed_boundary_and_u64_exhaustion() {
    let (fixture, job) = prepared();
    let mut db = forensic_connection(&fixture);
    let guards = [
        "authority_audit_heads_advance",
        "authority_audit_exact_next",
        "authority_audit_project_head",
    ]
    .map(|name| {
        db.query_row::<String, _, _>(
            "SELECT sql FROM sqlite_schema WHERE name=?",
            [name],
            |row| row.get(0),
        )
        .unwrap()
    });
    let tenant = AuthorityTenant::new(
        &fixture.tenant.org_id,
        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    )
    .unwrap();
    let mut seeds = vec![0, i64::MAX as u64, u64::MAX - 1, u64::MAX];
    seeds.extend((1..16).map(|nibbles| (1u64 << (nibbles * 4)) - 1));
    for old in seeds {
        // The seed is deliberately not a valid whole chain. It is confined to
        // a rolled-back transaction to exercise unsigned SQL arithmetic that
        // cannot be reached by constructing 2^63 real historical rows.
        let tx = db.transaction().unwrap();
        tx.execute(
            "INSERT INTO authority_projects VALUES(?,?,1)",
            params![tenant.org_id, tenant.project_id],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO authority_audit_heads VALUES(?,?,?,?)",
            params![
                tenant.org_id,
                tenant.project_id,
                0u64.to_be_bytes().as_slice(),
                vec![0u8; 32]
            ],
        )
        .unwrap();
        let previous = if old == 0 {
            vec![0u8; 32]
        } else {
            tx.execute_batch("DROP TRIGGER authority_audit_heads_advance; DROP TRIGGER authority_audit_exact_next; DROP TRIGGER authority_audit_project_head").unwrap();
            append_at(&tx, &tenant, old, &[0u8; 32], "fixture_seed", &job).unwrap();
            let digest: Vec<u8> = tx
                .query_row(
                    "SELECT event_hash FROM authority_audit WHERE org_id=? AND project_id=?",
                    params![tenant.org_id, tenant.project_id],
                    |row| row.get(0),
                )
                .unwrap();
            tx.execute("UPDATE authority_audit_heads SET sequence=?,event_hash=? WHERE org_id=? AND project_id=?", params![old.to_be_bytes().as_slice(), digest, tenant.org_id, tenant.project_id]).unwrap();
            for guard in &guards {
                tx.execute_batch(guard).unwrap();
            }
            digest
        };
        if let Some(next) = old.checked_add(1) {
            if let Some(gap) = next.checked_add(1) {
                assert!(
                    append_at(&tx, &tenant, gap, &previous, "fixture_boundary_gap", &job).is_err(),
                    "{old:016X} -> {gap:016X}"
                );
            }
            assert!(
                append_at(&tx, &tenant, next, &previous, "fixture_boundary", &job).is_ok(),
                "{old:016X} -> {next:016X}"
            );
            assert_eq!(audit_head(&tx, &tenant).0, next);
        } else {
            for wrapped in [0, 1, u64::MAX] {
                assert!(
                    append_at(&tx, &tenant, wrapped, &previous, "fixture_exhausted", &job).is_err()
                );
            }
            assert_eq!(audit_head(&tx, &tenant).0, u64::MAX);
        }
        tx.rollback().unwrap();
    }
}
