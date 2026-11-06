#![cfg(feature = "approval-proofs")]
//! Released SQL guards must survive SQLite's real replacement semantics.
//! Trust, identities and proof history are seeded through public APIs; the raw
//! statements below are adversarial mutations, never imported authority.
#[allow(dead_code)]
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/registry_fixture.rs"]
mod registry_fixture;

use ed25519_dalek::SigningKey;
use fw_authority::{AuthorityError, AuthorityStore, AuthorityTenant, RegistryTrustKey};
use fw_contracts::{canonical_bytes, canonical_hash, hash_bytes};
use registry_fixture::{Fixture, NOW, OWNER, sign_workload};
use rusqlite::{Connection, params, params_from_iter, types::Value};
use std::path::PathBuf;

const TABLES: [&str; 9] = [
    "authority_registry_keys",
    "authority_registry_key_revocations",
    "authority_registry_objects",
    "authority_registry_object_revocations",
    "authority_registry_clocks",
    "authority_workload_heads",
    "authority_bootstrap_challenges",
    "authority_bootstrap_proofs",
    "authority_bootstrap_pending_heads",
];

#[derive(Debug, PartialEq)]
struct TableSnapshot {
    table: String,
    rows: Vec<Vec<Value>>,
}

struct MatrixFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    spare_key_id: String,
    spare_object_hash: Vec<u8>,
    spare_challenge_id: String,
    fresh_org: String,
    fresh_project: String,
}

fn seed() -> MatrixFixture {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let first_bootstrap_key = f.bootstrap_pin.key_id.clone();
    f.approve(2);
    f.approve(3);
    f.authorize();

    // A second current workload head uses the same target and principal but a
    // distinct immutable workload identity, without inventing an authority row.
    let mut workload = f.workload.payload.clone();
    workload.binding_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into();
    workload.workload_id = "matrix-second-workload".into();
    let workload = sign_workload(workload, &f.issuer_key, &f.issuer_pin.key_id);
    f.store
        .admit_workload_binding(&f.tenant, &workload, NOW)
        .unwrap();

    // A second target gets its own independently pinned bootstrap key, original
    // envelope/delegation, real bound owner assertion and signed authorization.
    let second_key = SigningKey::from_bytes(&[43; 32]);
    let mut second_pin = f.bootstrap_pin.clone();
    second_pin.key_id = "matrix-second-bootstrap".into();
    second_pin.target_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".into();
    second_pin.public_key = second_key.verifying_key().to_bytes();
    f.store
        .pin_registry_trust_key(&f.tenant, &second_pin, NOW)
        .unwrap();
    let mut envelope = f.envelope.clone();
    envelope.envelope_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1".into();
    envelope.target_id = second_pin.target_id.clone();
    f.store
        .stage_access_envelope(&f.tenant, &envelope, NOW)
        .unwrap();
    let mut delegation = f.delegation.clone();
    delegation.root_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2".into();
    delegation.target_id = second_pin.target_id.clone();
    delegation.envelope_id = envelope.envelope_id.clone();
    delegation.envelope_hash = canonical_hash(&envelope).unwrap();
    f.store
        .stage_delegation(&f.tenant, &delegation, NOW)
        .unwrap();
    let mut manifest = f.manifest.clone();
    manifest.manifest_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee3".into();
    manifest.target_id = second_pin.target_id.clone();
    manifest.trust_root_hash = canonical_hash(&second_pin).unwrap();
    manifest.envelope_hashes = vec![canonical_hash(&envelope).unwrap()];
    manifest.delegation_hashes = vec![canonical_hash(&delegation).unwrap()];
    f.store
        .stage_bootstrap_manifest(&f.tenant, &manifest, NOW)
        .unwrap();
    f.manifest = manifest;
    f.bootstrap_pin = second_pin;
    f.bootstrap_key = second_key;
    f.approve(4);
    f.authorize();

    // Two unused issued challenges make UPDATE OR REPLACE's source and victim
    // independently eligible for the otherwise valid attempts+1 transition.
    let mut spare_challenge_id = String::new();
    for _ in 0..2 {
        let issued = f
            .store
            .issue_bootstrap_challenge(
                &f.tenant,
                OWNER,
                &f.credential.id(),
                &f.manifest.manifest_id,
                &f.verifier,
                NOW,
            )
            .unwrap();
        spare_challenge_id = issued.challenge.challenge_id().into();
    }

    // A pinned but unrevoked key is a valid fresh FK for the rowid-only
    // revocation attack. Another project supplies a second clock projection.
    let spare_key = SigningKey::from_bytes(&[44; 32]);
    let spare_pin = RegistryTrustKey {
        key_id: "matrix-spare-unrevoked".into(),
        org_id: f.tenant.org_id().into(),
        project_id: f.tenant.project_id().into(),
        target_id: f.workload.payload.target_id.clone(),
        payload_type: fw_authority::WORKLOAD_BINDING_TYPE.into(),
        public_key: spare_key.verifying_key().to_bytes(),
        not_before: NOW - 60,
        not_after: NOW + 3600,
        revoked: false,
    };
    f.store
        .pin_registry_trust_key(&f.tenant, &spare_pin, NOW)
        .unwrap();
    let other = AuthorityTenant::new(
        "ffffffff-ffff-4fff-8fff-fffffffffff1",
        "ffffffff-ffff-4fff-8fff-fffffffffff2",
    )
    .unwrap();
    f.store
        .provision_target_metadata_project(&other, NOW)
        .unwrap();
    let mut other_pin = spare_pin.clone();
    other_pin.org_id = other.org_id().into();
    other_pin.project_id = other.project_id().into();
    other_pin.key_id = "matrix-other-project-key".into();
    other_pin.public_key = SigningKey::from_bytes(&[45; 32]).verifying_key().to_bytes();
    f.store
        .pin_registry_trust_key(&other, &other_pin, NOW)
        .unwrap();

    // This existing project deliberately has no clock yet; INSERT's fresh
    // natural identity therefore satisfies every FK without a PK collision.
    let fresh = AuthorityTenant::new(
        "ffffffff-ffff-4fff-8fff-fffffffffff3",
        "ffffffff-ffff-4fff-8fff-fffffffffff4",
    )
    .unwrap();
    f.store
        .provision_target_metadata_project(&fresh, NOW)
        .unwrap();
    f.store
        .revoke_registry_trust_key(&f.tenant, &f.issuer_pin.key_id, NOW)
        .unwrap();
    f.store
        .revoke_registry_trust_key(&f.tenant, &first_bootstrap_key, NOW)
        .unwrap();
    let first_workload_hash = canonical_hash(&f.workload).unwrap();
    let first_envelope_hash = canonical_hash(&f.envelope).unwrap();
    f.store
        .revoke_registry_object(&f.tenant, &first_workload_hash, NOW)
        .unwrap();
    f.store
        .revoke_registry_object(&f.tenant, &first_envelope_hash, NOW)
        .unwrap();
    let spare_object_hash = decode_hash(&canonical_hash(&f.delegation).unwrap());
    let path = f.path.clone();
    drop(f.store);
    // The complete public-API seed must pass the same full retained validator
    // used by a real authority before any hostile SQL is attempted.
    drop(AuthorityStore::open(&path).unwrap());
    MatrixFixture {
        _directory: directory,
        path,
        spare_key_id: spare_pin.key_id,
        spare_object_hash,
        spare_challenge_id,
        fresh_org: fresh.org_id().into(),
        fresh_project: fresh.project_id().into(),
    }
}

fn decode_hash(hash: &str) -> Vec<u8> {
    (7..71)
        .step_by(2)
        .map(|index| u8::from_str_radix(&hash[index..index + 2], 16).unwrap())
        .collect()
}

fn columns(db: &Connection, table: &str) -> Vec<(String, bool)> {
    db.prepare(&format!("PRAGMA table_info({table})"))
        .unwrap()
        .query_map([], |row| Ok((row.get(1)?, row.get::<_, i64>(5)? > 0)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn rows(db: &Connection, table: &str, unconsumed: bool) -> Vec<Vec<Value>> {
    let condition = if unconsumed {
        " WHERE consumed_at IS NULL"
    } else {
        ""
    };
    let mut query = db
        .prepare(&format!(
            "SELECT rowid,* FROM {table}{condition} ORDER BY rowid"
        ))
        .unwrap();
    let count = query.column_count();
    query
        .query_map([], |row| {
            (0..count)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn snapshot(db: &Connection) -> Vec<TableSnapshot> {
    let tables = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,10)='authority_' ORDER BY name").unwrap()
        .query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    tables
        .into_iter()
        .map(|table| TableSnapshot {
            rows: rows(db, &table, false),
            table,
        })
        .collect()
}

fn set(columns: &[(String, bool)], row: &mut [Value], column: &str, value: Value) {
    let index = columns.iter().position(|(name, _)| name == column).unwrap() + 1;
    row[index] = value;
}

fn get<'a>(columns: &[(String, bool)], row: &'a [Value], column: &str) -> &'a Value {
    &row[columns.iter().position(|(name, _)| name == column).unwrap() + 1]
}

fn transition(columns: &[(String, bool)], source: &[Value], table: &str) -> Vec<(String, Value)> {
    match table {
        "authority_registry_clocks" => {
            let Value::Integer(now) = get(columns, source, "observed_at") else {
                panic!("clock")
            };
            vec![("observed_at".into(), Value::Integer(now + 1))]
        }
        "authority_workload_heads" | "authority_bootstrap_pending_heads" => {
            let column = if table == "authority_workload_heads" {
                "binding_epoch"
            } else {
                "authority_epoch"
            };
            let Value::Blob(epoch) = get(columns, source, column) else {
                panic!("epoch")
            };
            let epoch = u64::from_be_bytes(epoch.as_slice().try_into().unwrap())
                .checked_add(1)
                .unwrap();
            vec![(column.into(), Value::Blob(epoch.to_be_bytes().to_vec()))]
        }
        "authority_bootstrap_challenges" => {
            let Value::Integer(attempts) = get(columns, source, "attempts") else {
                panic!("attempts")
            };
            assert_eq!(get(columns, source, "consumed_at"), &Value::Null);
            vec![("attempts".into(), Value::Integer(attempts + 1))]
        }
        _ => vec![],
    }
}

fn fresh_identity(
    f: &MatrixFixture,
    columns: &[(String, bool)],
    candidate: &mut [Value],
    table: &str,
) {
    match table {
        "authority_registry_keys" => {
            set(
                columns,
                candidate,
                "key_id",
                Value::Text("matrix-new-natural-key".into()),
            );
            set(
                columns,
                candidate,
                "key_fingerprint",
                Value::Blob(vec![0xf0; 32]),
            );
        }
        "authority_registry_key_revocations" => set(
            columns,
            candidate,
            "key_id",
            Value::Text(f.spare_key_id.clone()),
        ),
        "authority_registry_objects" => {
            set(
                columns,
                candidate,
                "object_id",
                Value::Text("99999999-9999-4999-8999-999999999991".into()),
            );
            set(
                columns,
                candidate,
                "content_hash",
                Value::Blob(vec![0xf1; 32]),
            );
        }
        "authority_registry_object_revocations" => set(
            columns,
            candidate,
            "content_hash",
            Value::Blob(f.spare_object_hash.clone()),
        ),
        "authority_registry_clocks" => {
            set(
                columns,
                candidate,
                "org_id",
                Value::Text(f.fresh_org.clone()),
            );
            set(
                columns,
                candidate,
                "project_id",
                Value::Text(f.fresh_project.clone()),
            );
        }
        "authority_workload_heads" => set(
            columns,
            candidate,
            "workload_id",
            Value::Text("matrix-new-natural-workload".into()),
        ),
        "authority_bootstrap_challenges" => set(
            columns,
            candidate,
            "challenge_id",
            Value::Text("99999999-9999-4999-8999-999999999992".into()),
        ),
        "authority_bootstrap_proofs" => {
            set(
                columns,
                candidate,
                "proof_id",
                Value::Text("99999999-9999-4999-8999-999999999993".into()),
            );
            set(
                columns,
                candidate,
                "challenge_id",
                Value::Text(f.spare_challenge_id.clone()),
            );
            set(
                columns,
                candidate,
                "proof_hash",
                Value::Blob(vec![0xf2; 32]),
            );
        }
        "authority_bootstrap_pending_heads" => set(
            columns,
            candidate,
            "target_id",
            Value::Text("99999999-9999-4999-8999-999999999994".into()),
        ),
        _ => panic!("unexpected registry table"),
    }
}

fn assert_rejected(
    db: &Connection,
    sql: &str,
    values: Vec<Value>,
    expected_message: &str,
    label: &str,
    original: &[TableSnapshot],
) {
    let error = db.execute(sql, params_from_iter(values)).expect_err(label);
    assert!(
        matches!(&error, rusqlite::Error::SqliteFailure(code,Some(message)) if code.extended_code==1811 && message==expected_message),
        "{label}: {error:?}"
    );
    assert_eq!(
        snapshot(db),
        original,
        "{label}: authority rows, rowids and bytes changed"
    );
}

fn positive_sql_control(
    db: &Connection,
    sql: &str,
    values: Vec<Value>,
    label: &str,
    original: &[TableSnapshot],
) {
    db.execute_batch("SAVEPOINT registry_legal_candidate")
        .unwrap();
    assert_eq!(
        db.execute(sql, params_from_iter(values)).expect(label),
        1,
        "{label}"
    );
    db.execute_batch("ROLLBACK TO registry_legal_candidate; RELEASE registry_legal_candidate")
        .unwrap();
    assert_eq!(
        snapshot(db),
        original,
        "{label}: rollback changed original rows"
    );
}

#[test]
fn every_registry_table_retains_rowid_and_natural_identity_across_sqlite_replacement_modes() {
    let f = seed();
    let db = Connection::open(&f.path).unwrap();
    let original = snapshot(&db);
    for foreign_keys in [false, true] {
        for recursive_triggers in [false, true] {
            db.pragma_update(None, "foreign_keys", foreign_keys)
                .unwrap();
            db.pragma_update(None, "recursive_triggers", recursive_triggers)
                .unwrap();
            assert_eq!(
                db.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, bool>(0))
                    .unwrap(),
                foreign_keys
            );
            assert_eq!(
                db.query_row("PRAGMA recursive_triggers", [], |row| row.get::<_, bool>(0))
                    .unwrap(),
                recursive_triggers
            );
            for table in TABLES {
                let columns = columns(&db, table);
                let selected = rows(&db, table, table == "authority_bootstrap_challenges");
                assert!(
                    selected.len() >= 2,
                    "{table}: seed needs distinct source and victim"
                );
                let victim = &selected[0];
                let source = &selected[1];
                assert_ne!(victim[0], source[0]);
                let insert_columns = std::iter::once("rowid")
                    .chain(columns.iter().map(|(name, _)| name.as_str()))
                    .collect::<Vec<_>>()
                    .join(",");
                let placeholders = (1..=source.len())
                    .map(|index| format!("?{index}"))
                    .collect::<Vec<_>>()
                    .join(",");
                let insert = format!(
                    "INSERT OR REPLACE INTO {table}({insert_columns}) VALUES({placeholders})"
                );
                let label = format!(
                    "{table}, foreign_keys={foreign_keys}, recursive_triggers={recursive_triggers}"
                );

                // Isolate hidden rowid: every natural/alternate unique identity
                // is fresh and all FKs still reference actual retained objects.
                let mut rowid_only = source.clone();
                rowid_only[0] = victim[0].clone();
                fresh_identity(&f, &columns, &mut rowid_only, table);
                // Prove that every natural/alternate key, FK and SQL CHECK is
                // satisfied independently of the protected hidden rowid.
                let mut unused_rowid = rowid_only.clone();
                unused_rowid[0] = Value::Integer(1_000_001);
                positive_sql_control(
                    &db,
                    &insert,
                    unused_rowid,
                    &format!("{label}: fresh rowid INSERT positive SQL control"),
                    &original,
                );
                assert_rejected(
                    &db,
                    &insert,
                    rowid_only,
                    "retained registry identity",
                    &format!("{label}: INSERT rowid-only"),
                    &original,
                );

                // Isolate natural identity: the replacement's hidden rowid is
                // unused, while its PK/alternate keys match the retained victim.
                let mut natural_only = victim.clone();
                natural_only[0] = Value::Integer(1_000_000);
                assert_rejected(
                    &db,
                    &insert,
                    natural_only,
                    "retained registry identity",
                    &format!("{label}: INSERT natural identity"),
                    &original,
                );

                let updates = transition(&columns, source, table);
                let expected = match table {
                    "authority_registry_clocks" => "registry clock regression",
                    "authority_workload_heads" => "workload epoch regression",
                    "authority_bootstrap_challenges" => "invalid bootstrap challenge transition",
                    "authority_bootstrap_pending_heads" => "bootstrap epoch regression",
                    _ => "immutable registry record",
                };
                if !updates.is_empty() {
                    let mut assignments = vec![];
                    let mut values = vec![];
                    for (column, value) in &updates {
                        values.push(value.clone());
                        assignments.push(format!("{column}=?{}", values.len()));
                    }
                    values.push(source[0].clone());
                    let ordinary = format!(
                        "UPDATE {table} SET {} WHERE rowid=?{}",
                        assignments.join(","),
                        values.len()
                    );
                    positive_sql_control(
                        &db,
                        &ordinary,
                        values,
                        &format!(
                            "{label}: unchanged identity forward-transition positive SQL control"
                        ),
                        &original,
                    );
                }
                // Mutable rows simultaneously perform an otherwise legal
                // forward transition; another condition must not mask rowid.
                let mut assignments = vec!["rowid=?1".to_string()];
                let mut values = vec![victim[0].clone()];
                for (column, value) in &updates {
                    values.push(value.clone());
                    assignments.push(format!("{column}=?{}", values.len()));
                }
                values.push(source[0].clone());
                let update = format!(
                    "UPDATE OR REPLACE {table} SET {} WHERE rowid=?{}",
                    assignments.join(","),
                    values.len()
                );
                assert_rejected(
                    &db,
                    &update,
                    values,
                    expected,
                    &format!("{label}: UPDATE rowid-only with forward transition"),
                    &original,
                );

                let mut assignments = vec![];
                let mut values = vec![];
                for (index, (column, primary)) in columns.iter().enumerate() {
                    if *primary {
                        values.push(victim[index + 1].clone());
                        assignments.push(format!("{column}=?{}", values.len()));
                    }
                }
                for (column, value) in updates {
                    values.push(value);
                    assignments.push(format!("{column}=?{}", values.len()));
                }
                values.push(source[0].clone());
                let update = format!(
                    "UPDATE OR REPLACE {table} SET {} WHERE rowid=?{}",
                    assignments.join(","),
                    values.len()
                );
                assert_rejected(
                    &db,
                    &update,
                    values,
                    expected,
                    &format!("{label}: UPDATE natural identity with forward transition"),
                    &original,
                );
            }
        }
    }
    drop(db);
    drop(AuthorityStore::open(&f.path).unwrap());
}

#[test]
fn hash_coherent_unsigned_registry_whitespace_is_not_accepted_as_canonical_history() {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let mut envelope = f.envelope.clone();
    envelope.envelope_id = "99999999-9999-4999-8999-999999999995".into();
    let admitted = f
        .store
        .stage_access_envelope(&f.tenant, &envelope, NOW)
        .unwrap();
    let mut noncanonical = b" ".to_vec();
    noncanonical.extend(canonical_bytes(&envelope).unwrap());
    let id = admitted.object_id;
    let org = f.tenant.org_id().to_owned();
    let project = f.tenant.project_id().to_owned();
    drop(f.store);
    let db = Connection::open(&f.path).unwrap();
    let guard: String = db
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='authority_registry_objects_no_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    db.execute_batch("DROP TRIGGER authority_registry_objects_no_update")
        .unwrap();
    db.execute("UPDATE authority_registry_objects SET canonical_bytes=?,content_hash=? WHERE org_id=? AND project_id=? AND object_kind='envelope' AND object_id=?", params![noncanonical,decode_hash(&hash_bytes(&noncanonical)),org,project,id]).unwrap();
    db.execute_batch(&guard).unwrap();
    drop(db);
    assert!(matches!(
        AuthorityStore::open(&f.path),
        Err(AuthorityError::Invalid("noncanonical authority record"))
    ));
}
