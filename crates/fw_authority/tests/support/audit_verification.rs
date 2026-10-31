use super::*;
use fw_contracts::canonical_bytes;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn database(directory: &TempDir) -> Connection {
    Connection::open(directory.path().join("authority.sqlite3")).unwrap()
}

// A database writer can bypass local immutable triggers. The verifier must
// detect inconsistent retained evidence, without pretending to anchor a full
// database against an attacker who rewrites every object consistently.
fn tamper(connection: &Connection, change: impl FnOnce(&Connection)) {
    let mut triggers = Vec::new();
    for name in ["authority_audit_no_update", "authority_audit_no_delete"] {
        triggers.push(
            connection
                .query_row("SELECT sql FROM sqlite_schema WHERE name=?", [name], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
        );
        connection
            .execute_batch(&format!("DROP TRIGGER {name}"))
            .unwrap();
    }
    change(connection);
    for trigger in triggers {
        connection.execute_batch(&trigger).unwrap();
    }
}

fn rewrite_last(connection: &Connection, edit: impl FnOnce(&mut Value)) {
    let bytes: Vec<u8> = connection.query_row("SELECT canonical_bytes FROM authority_audit WHERE org_id=? AND project_id=? ORDER BY sequence DESC LIMIT 1", params![ORG,PROJECT], |r| r.get(0)).unwrap();
    let mut event: Value = serde_json::from_slice(&bytes).unwrap();
    edit(&mut event);
    let bytes = canonical_bytes(&event).unwrap();
    let hash = Sha256::digest(&bytes).to_vec();
    let sequence: u64 = event["sequence"].as_str().unwrap().parse().unwrap();
    let recorded = chrono::DateTime::parse_from_rfc3339(event["recorded_at"].as_str().unwrap())
        .unwrap()
        .timestamp();
    let previous_text = event["previous_hash"].as_str().unwrap();
    let previous: Vec<u8> = (7..71)
        .step_by(2)
        .map(|index| u8::from_str_radix(&previous_text[index..index + 2], 16).unwrap())
        .collect();
    connection.execute("UPDATE authority_audit SET sequence=?,event_hash=?,previous_hash=?,recorded_at=?,canonical_bytes=? WHERE org_id=? AND project_id=? AND sequence=(SELECT max(sequence) FROM authority_audit WHERE org_id=? AND project_id=?)", params![sequence.to_be_bytes().as_slice(),hash,previous,recorded,bytes,ORG,PROJECT,ORG,PROJECT]).unwrap();
    connection.execute("UPDATE authority_audit_heads SET sequence=?,event_hash=? WHERE org_id=? AND project_id=?", params![sequence.to_be_bytes().as_slice(),hash,ORG,PROJECT]).unwrap();
}

#[test]
fn valid_history_reopens_and_exact_retry_does_not_append_or_move_time() {
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, FIRST, NOW);
    provision(&mut store, &tenant, SECOND, NOW + 100);
    let verified = store.verify_audit_chain(&tenant).unwrap().unwrap();
    assert_eq!(verified.event_count, 2);
    assert_eq!(verified.last_recorded_at, Some(NOW + 100));
    assert_eq!(verified.head_hash.len(), 71);
    provision(&mut store, &tenant, FIRST, NOW - 100);
    provision(&mut store, &tenant, SECOND, NOW + 1000);
    assert_eq!(
        store.verify_audit_chain(&tenant).unwrap().unwrap(),
        verified
    );
    drop(store);
    let mut reopened = AuthorityStore::open(directory.path().join("authority.sqlite3")).unwrap();
    assert_eq!(
        reopened.verify_audit_chain(&tenant).unwrap().unwrap(),
        verified
    );
}

#[test]
fn unknown_genesis_and_corrupt_missing_head_are_distinct() {
    let (directory, mut store, tenant) = fixture();
    assert_eq!(store.verify_audit_chain(&tenant).unwrap(), None);
    let connection = database(&directory);
    connection
        .execute(
            "INSERT INTO authority_projects VALUES(?,?,1)",
            params![ORG, PROJECT],
        )
        .unwrap();
    assert!(store.verify_audit_chain(&tenant).is_err());
    connection
        .execute(
            "INSERT INTO authority_audit_heads VALUES(?,?,?,?)",
            params![ORG, PROJECT, [0u8; 8].as_slice(), [0u8; 32].as_slice()],
        )
        .unwrap();
    let genesis = store.verify_audit_chain(&tenant).unwrap().unwrap();
    assert_eq!(genesis.event_count, 0);
    assert_eq!(genesis.last_recorded_at, None);
    assert_eq!(genesis.head_hash, format!("sha256:{}", "0".repeat(64)));
    connection
        .execute(
            "UPDATE authority_audit_heads SET event_hash=?",
            [[1u8; 32].as_slice()],
        )
        .unwrap();
    assert!(store.verify_audit_chain(&tenant).is_err());
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM authority_projects")
        .unwrap();
    assert!(store.verify_audit_chain(&tenant).is_err());
}

#[test]
fn canonical_hash_projection_and_row_bounds_are_all_verified() {
    for mutation in [
        "UPDATE authority_audit SET event_hash=zeroblob(32) WHERE sequence=x'0000000000000002'",
        "UPDATE authority_audit SET previous_hash=zeroblob(32) WHERE sequence=x'0000000000000002'",
        "UPDATE authority_audit SET kind='different-kind'",
        "UPDATE authority_audit SET resource_id='different-resource'",
        "UPDATE authority_audit SET recorded_at=recorded_at+1",
        "UPDATE authority_audit SET canonical_bytes=CAST(CAST(canonical_bytes AS TEXT)||' ' AS BLOB)",
        "UPDATE authority_audit SET canonical_bytes=x'7b7d'",
        "UPDATE authority_audit_heads SET event_hash=zeroblob(32)",
        "DELETE FROM authority_audit WHERE sequence=x'0000000000000001'",
        "DELETE FROM authority_audit",
        "PRAGMA ignore_check_constraints=ON; UPDATE authority_audit SET canonical_bytes=zeroblob(1000000)",
        "UPDATE authority_audit SET kind=printf('%1000000s','x')",
        "UPDATE authority_audit SET resource_id=printf('%1000000s','x')",
        "PRAGMA ignore_check_constraints=ON; UPDATE authority_audit_heads SET sequence=x'00'",
        "PRAGMA ignore_check_constraints=ON; UPDATE authority_audit_heads SET event_hash=zeroblob(1000000)",
        "PRAGMA ignore_check_constraints=ON; UPDATE authority_audit SET previous_hash=zeroblob(1000000)",
    ] {
        let (directory, mut store, tenant) = fixture();
        provision(&mut store, &tenant, FIRST, NOW);
        provision(&mut store, &tenant, SECOND, NOW + 1);
        tamper(&database(&directory), |connection| {
            connection.execute_batch(mutation).unwrap()
        });
        assert!(
            store.verify_audit_chain(&tenant).is_err(),
            "accepted {mutation}"
        );
    }
}

#[test]
fn valid_hashes_cannot_hide_sequence_gaps_wrong_links_or_tenant_transplants() {
    for (field, value) in [
        ("sequence", "3".to_owned()),
        ("previous_hash", format!("sha256:{}", "0".repeat(64))),
        ("org_id", SECOND.to_owned()),
        ("project_id", SECOND.to_owned()),
        ("schema_version", "fw.authority-audit/v2".to_owned()),
    ] {
        let (directory, mut store, tenant) = fixture();
        provision(&mut store, &tenant, FIRST, NOW);
        provision(&mut store, &tenant, SECOND, NOW + 1);
        tamper(&database(&directory), |connection| {
            rewrite_last(connection, |event| event[field] = value.into())
        });
        assert!(
            store.verify_audit_chain(&tenant).is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn legacy_backward_time_is_reported_without_rewriting_even_after_new_append() {
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, FIRST, NOW + 100);
    provision(&mut store, &tenant, SECOND, NOW + 200);
    let connection = database(&directory);
    tamper(&connection, |connection| {
        rewrite_last(connection, |event| {
            event["recorded_at"] = chrono::DateTime::from_timestamp(NOW + 50, 0)
                .unwrap()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
                .into()
        })
    });
    let before = snapshot(&connection);
    assert!(matches!(
        store.verify_audit_chain(&tenant),
        Err(AuthorityError::Invalid("authority audit time order"))
    ));
    assert_eq!(snapshot(&connection), before);
    // Appends only certify their immediate predecessor, not earlier history.
    provision(
        &mut store,
        &tenant,
        "66666666-6666-4666-8666-666666666666",
        NOW + 60,
    );
    assert!(store.verify_audit_chain(&tenant).is_err());
}

#[test]
fn verification_and_append_clock_are_scoped_by_both_tenant_components() {
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, FIRST, NOW + 100);
    for other in [
        AuthorityTenant::new(SECOND, PROJECT).unwrap(),
        AuthorityTenant::new(ORG, SECOND).unwrap(),
    ] {
        provision(&mut store, &other, FIRST, NOW);
        assert_eq!(
            store
                .verify_audit_chain(&other)
                .unwrap()
                .unwrap()
                .last_recorded_at,
            Some(NOW)
        );
    }
    let before = store.verify_audit_chain(&tenant).unwrap().unwrap();
    tamper(&database(&directory), |connection| {
        connection
            .execute(
                "UPDATE authority_audit SET event_hash=zeroblob(32) WHERE org_id=?",
                [SECOND],
            )
            .unwrap();
    });
    assert_eq!(store.verify_audit_chain(&tenant).unwrap().unwrap(), before);
    assert!(
        store
            .verify_audit_chain(&AuthorityTenant::new(SECOND, PROJECT).unwrap())
            .is_err()
    );
    assert!(
        store
            .verify_audit_chain(&AuthorityTenant::new(ORG, SECOND).unwrap())
            .is_ok()
    );
}

#[test]
fn corrupt_head_or_tail_and_sequence_overflow_cannot_extend_history() {
    for overflow in [false, true] {
        let (directory, mut store, tenant) = fixture();
        provision(&mut store, &tenant, FIRST, NOW);
        let connection = database(&directory);
        tamper(&connection, |connection| {
            if overflow {
                rewrite_last(connection, |event| {
                    event["sequence"] = u64::MAX.to_string().into()
                });
            } else {
                connection
                    .execute(
                        "UPDATE authority_audit_heads SET event_hash=zeroblob(32)",
                        [],
                    )
                    .unwrap();
            }
        });
        let before = snapshot(&connection);
        assert!(
            store
                .provision_principal(&tenant, SECOND, "local-oob", SECOND, NOW + 1)
                .is_err()
        );
        assert_eq!(snapshot(&connection), before);
    }
}

#[test]
fn concurrent_writer_and_verifier_observe_complete_snapshots() {
    let (directory, mut store, tenant) = fixture();
    provision(&mut store, &tenant, FIRST, NOW);
    let path = directory.path().join("authority.sqlite3");
    let writer = std::thread::spawn(move || {
        let mut store = AuthorityStore::open(path).unwrap();
        let tenant = AuthorityTenant::new(ORG, PROJECT).unwrap();
        for index in 1..=40 {
            provision(
                &mut store,
                &tenant,
                &format!("aaaaaaaa-aaaa-4aaa-8aaa-{index:012}"),
                NOW + index,
            );
        }
    });
    for _ in 0..40 {
        let result = store.verify_audit_chain(&tenant).unwrap().unwrap();
        assert!((1..=41).contains(&result.event_count));
        assert_eq!(
            result.last_recorded_at,
            Some(NOW + result.event_count as i64 - 1)
        );
    }
    writer.join().unwrap();
    assert_eq!(
        store
            .verify_audit_chain(&tenant)
            .unwrap()
            .unwrap()
            .event_count,
        41
    );
}
