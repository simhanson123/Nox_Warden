#![cfg(feature = "approval-proofs")]
//! Schema16 identity retention under SQLite replacement semantics. The durable
//! seed uses public APIs and real software-owner/target/peer signatures. Small
//! SAVEPOINT-only SQL parents/candidates isolate structural guard behavior;
//! they are NOT authenticated authority and are never committed or opened.
#[allow(dead_code)]
#[path = "support/approval_authenticator.rs"]
mod approval_authenticator;
#[path = "support/private_directory.rs"]
mod private_directory;
#[path = "support/registry_fixture.rs"]
mod registry_fixture;
#[path = "support/target_bootstrap_fixture.rs"]
mod target_fixture;
use ed25519_dalek::SigningKey;
use fw_authority::*;
use fw_contracts::{canonical_hash, hash_bytes};
use registry_fixture::{Fixture, NOW, at};
use rusqlite::{Connection, params_from_iter, types::Value};
use std::path::PathBuf;
use target_fixture::TargetFixture;

const TABLES: [(&str, &str, Option<&str>); 9] = [
    (
        "authority_bootstrap_approval_origin_pins",
        "bootstrap approval origin pin",
        None,
    ),
    (
        "authority_bootstrap_approval_origin_heads",
        "bootstrap approval origin head",
        Some("bootstrap approval origin revision regression"),
    ),
    (
        "authority_bootstrap_challenge_origin_bindings",
        "bootstrap challenge origin binding",
        None,
    ),
    (
        "authority_target_bootstrap_key_pins",
        "target bootstrap key pin",
        None,
    ),
    (
        "authority_target_bootstrap_key_heads",
        "target bootstrap key head",
        Some("target bootstrap key revision regression"),
    ),
    (
        "authority_target_bootstrap_key_revocations",
        "target bootstrap key revocation",
        None,
    ),
    (
        "authority_target_bootstrap_challenges",
        "target bootstrap challenge",
        None,
    ),
    (
        "authority_target_bootstrap_confirmations",
        "target bootstrap confirmation",
        None,
    ),
    (
        "authority_target_bootstrap_confirmation_heads",
        "target bootstrap confirmation head",
        Some("target bootstrap confirmed authority regression"),
    ),
];
const FRESH_TARGET: &str = "99999999-9999-4999-8999-999999999991";
const FRESH_CHALLENGE: &str = "99999999-9999-4999-8999-999999999992";

struct MatrixFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    spare_manifest_id: String,
    spare_manifest_hash: Vec<u8>,
    spare_target_challenge: String,
    spare_target_challenge_hash: Vec<u8>,
    fresh: AuthorityTenant,
}
fn blob(hash: &str) -> Vec<u8> {
    (7..71)
        .step_by(2)
        .map(|index| u8::from_str_radix(&hash[index..index + 2], 16).unwrap())
        .collect()
}
fn digest(label: &str) -> Value {
    Value::Blob(blob(&hash_bytes(label.as_bytes())))
}
fn bytes_number(value: u64) -> Value {
    Value::Blob(value.to_be_bytes().to_vec())
}
fn origin(f: &Fixture, tenant: &AuthorityTenant, revision: u64) -> BootstrapApprovalOriginPin {
    BootstrapApprovalOriginPin {
        schema_version: "fw.bootstrap-approval-origin-pin/v1".into(),
        org_id: tenant.org_id().into(),
        project_id: tenant.project_id().into(),
        revision: revision.to_string(),
        origin: approval_authenticator::ORIGIN.into(),
        rp_id: f.verifier.rp_id().into(),
        not_before: at(NOW - 60),
        not_after: at(NOW + 3600),
    }
}
fn confirm(f: &mut Fixture, target: &TargetFixture) {
    let bundle = f
        .store
        .issue_target_bootstrap_challenge(
            &f.tenant,
            &f.manifest.manifest_id,
            None,
            &target.baseline,
            &target.capability,
            f.now,
        )
        .unwrap();
    let receipt = target.receipt(bundle.challenge, f.now);
    f.store
        .admit_target_bootstrap_confirmation(&f.tenant, &receipt, f.now + 1)
        .unwrap();
}
fn seed() -> MatrixFixture {
    let directory = private_directory::private_directory();
    let mut f = Fixture::new(directory.path(), NOW);
    let spare_manifest_id = f.manifest.manifest_id.clone();
    let spare_manifest_hash = blob(&f.manifest.hash().unwrap());
    let first = TargetFixture::new(&mut f);
    f.store
        .pin_target_bootstrap_key(&f.tenant, &first.pin, None, NOW)
        .unwrap();
    f.approve(2);
    f.authorize();
    confirm(&mut f, &first);

    // A separate target gets a separate bootstrap root, exact original input
    // objects, fresh real owner assertion, independent target key and receipt.
    f.now = NOW + 2;
    let root = SigningKey::from_bytes(&[43; 32]);
    let mut root_pin = f.bootstrap_pin.clone();
    root_pin.key_id = "matrix-second-bootstrap".into();
    root_pin.target_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".into();
    root_pin.public_key = root.verifying_key().to_bytes();
    f.store
        .pin_registry_trust_key(&f.tenant, &root_pin, f.now)
        .unwrap();
    let mut envelope = f.envelope.clone();
    envelope.envelope_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1".into();
    envelope.target_id = root_pin.target_id.clone();
    f.store
        .stage_access_envelope(&f.tenant, &envelope, f.now)
        .unwrap();
    let mut delegation = f.delegation.clone();
    delegation.root_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2".into();
    delegation.target_id = root_pin.target_id.clone();
    delegation.envelope_id = envelope.envelope_id.clone();
    delegation.envelope_hash = canonical_hash(&envelope).unwrap();
    f.store
        .stage_delegation(&f.tenant, &delegation, f.now)
        .unwrap();
    f.manifest.target_id = root_pin.target_id.clone();
    f.manifest.trust_root_hash = canonical_hash(&root_pin).unwrap();
    f.manifest.envelope_hashes = vec![canonical_hash(&envelope).unwrap()];
    f.manifest.delegation_hashes = vec![canonical_hash(&delegation).unwrap()];
    f.bootstrap_key = root;
    f.bootstrap_pin = root_pin;
    let mut second = TargetFixture::new(&mut f);
    second.target_key = SigningKey::from_bytes(&[74; 32]);
    second.pin.public_key = second.target_key.verifying_key().to_bytes();
    second.pin.key_id = "matrix-second-target".into();
    f.store
        .pin_target_bootstrap_key(&f.tenant, &second.pin, None, f.now)
        .unwrap();
    f.approve(3);
    f.authorize();
    confirm(&mut f, &second);

    // An actual unconsumed target challenge supplies a valid unused receipt FK.
    f.now = NOW + 4;
    second.stage(&mut f, Some(1), 2);
    f.approve(4);
    f.authorize();
    let spare = f
        .store
        .issue_target_bootstrap_challenge(
            &f.tenant,
            &f.manifest.manifest_id,
            Some(1),
            &second.baseline,
            &second.capability,
            f.now,
        )
        .unwrap();
    f.now = NOW + 6;
    for (target, seed) in [(&first, 75), (&second, 76)] {
        let mut pin = target.pin.clone();
        pin.revision = "2".into();
        pin.key_id.push_str("-rotated");
        pin.public_key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        f.store
            .pin_target_bootstrap_key(&f.tenant, &pin, Some(1), f.now)
            .unwrap();
        // Revoke only after receipt admission; old accepted history survives.
        f.store
            .revoke_target_bootstrap_key(&f.tenant, &target.pin.target_id, 1, f.now)
            .unwrap();
    }
    let other = AuthorityTenant::new(
        "ffffffff-ffff-4fff-8fff-fffffffffff1",
        "ffffffff-ffff-4fff-8fff-fffffffffff2",
    )
    .unwrap();
    f.store
        .provision_target_metadata_project(&other, f.now)
        .unwrap();
    let first_origin = origin(&f, &other, 1);
    f.store
        .pin_bootstrap_approval_origin(&other, &first_origin, None, f.now)
        .unwrap();
    let first_tenant = f.tenant.clone();
    for tenant in [&first_tenant, &other] {
        let next_origin = origin(&f, tenant, 2);
        f.store
            .pin_bootstrap_approval_origin(tenant, &next_origin, Some(1), f.now)
            .unwrap();
    }
    let fresh = AuthorityTenant::new(
        "ffffffff-ffff-4fff-8fff-fffffffffff3",
        "ffffffff-ffff-4fff-8fff-fffffffffff4",
    )
    .unwrap();
    f.store
        .provision_target_metadata_project(&fresh, f.now)
        .unwrap();
    let path = f.path.clone();
    drop(f.store);
    drop(AuthorityStore::open(&path).unwrap());
    MatrixFixture {
        _directory: directory,
        path,
        spare_manifest_id,
        spare_manifest_hash,
        spare_target_challenge: spare.challenge.challenge_id.clone(),
        spare_target_challenge_hash: blob(&spare.challenge.hash().unwrap()),
        fresh,
    }
}

type Columns = Vec<(String, bool)>;
type Snapshot = Vec<(String, Vec<Vec<Value>>)>;
type Schema = Vec<(String, String, String, Option<String>)>;
fn columns(db: &Connection, table: &str) -> Columns {
    db.prepare(&format!("PRAGMA table_info({table})"))
        .unwrap()
        .query_map([], |row| Ok((row.get(1)?, row.get::<_, i64>(5)? > 0)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn rows(db: &Connection, table: &str) -> Vec<Vec<Value>> {
    let mut query = db
        .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
        .unwrap();
    let count = query.column_count();
    query
        .query_map([], |row| {
            (0..count)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn snapshot(db: &Connection) -> Snapshot {
    let tables:Vec<String>=db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,10)='authority_' ORDER BY name").unwrap().query_map([],|row|row.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    tables
        .into_iter()
        .map(|table| {
            let values = rows(db, &table);
            (table, values)
        })
        .collect()
}
fn schema(db: &Connection) -> Schema {
    db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn get<'a>(columns: &Columns, row: &'a [Value], name: &str) -> &'a Value {
    &row[columns
        .iter()
        .position(|(column, _)| column == name)
        .unwrap()
        + 1]
}
fn set(columns: &Columns, row: &mut [Value], name: &str, value: Value) {
    let index = columns
        .iter()
        .position(|(column, _)| column == name)
        .unwrap()
        + 1;
    row[index] = value;
}
fn number(value: &Value) -> u64 {
    let Value::Blob(raw) = value else {
        panic!("counter blob")
    };
    u64::from_be_bytes(raw.as_slice().try_into().unwrap())
}
fn next_rowid(db: &Connection, table: &str) -> Value {
    Value::Integer(
        db.query_row(
            &format!("SELECT coalesce(max(rowid),0)+100 FROM {table}"),
            [],
            |row| row.get(0),
        )
        .unwrap(),
    )
}
fn insert_sql(table: &str, columns: &Columns) -> String {
    let names = std::iter::once("rowid")
        .chain(columns.iter().map(|(name, _)| name.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    let placeholders = (1..=columns.len() + 1)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("INSERT OR REPLACE INTO {table}({names}) VALUES({placeholders})")
}
fn insert_parent(db: &Connection, table: &str, mut row: Vec<Value>) {
    row[0] = next_rowid(db, table);
    assert_eq!(
        db.execute(
            &insert_sql(table, &columns(db, table)),
            params_from_iter(row)
        )
        .unwrap(),
        1
    );
}
fn parent_for_scope(
    db: &Connection,
    table: &str,
    head_columns: &Columns,
    head: &[Value],
) -> Vec<Value> {
    let columns = columns(db, table);
    rows(db, table)
        .into_iter()
        .find(|row| {
            ["org_id", "project_id", "revision"]
                .iter()
                .all(|name| get(&columns, row, name) == get(head_columns, head, name))
                && (!head_columns.iter().any(|(name, _)| name == "target_id")
                    || get(&columns, row, "target_id") == get(head_columns, head, "target_id"))
        })
        .unwrap()
}

// Only SQL constraints/identity guards are under test in these temporary rows.
// Signed/canonical payloads are deliberately not reissued or promoted; rollback
// restores every original row and the full authority is opened only afterward.
fn fresh_candidate(
    f: &MatrixFixture,
    db: &Connection,
    table: &str,
    columns: &Columns,
    source: &[Value],
) -> Vec<Value> {
    let mut row = source.to_vec();
    row[0] = next_rowid(db, table);
    match table {
        "authority_bootstrap_approval_origin_pins" => {
            set(columns, &mut row, "revision", bytes_number(9));
            set(columns, &mut row, "pin_hash", digest("new origin pin"));
        }
        "authority_bootstrap_approval_origin_heads" => {
            set(
                columns,
                &mut row,
                "org_id",
                Value::Text(f.fresh.org_id().into()),
            );
            set(
                columns,
                &mut row,
                "project_id",
                Value::Text(f.fresh.project_id().into()),
            );
            set(columns, &mut row, "revision", bytes_number(1));
            let table = "authority_bootstrap_approval_origin_pins";
            let pc = columns_for(db, table);
            let mut parent = parent_for_scope(db, table, columns, source);
            for field in ["org_id", "project_id", "revision"] {
                set(&pc, &mut parent, field, get(columns, &row, field).clone());
            }
            set(
                &pc,
                &mut parent,
                "pin_hash",
                digest("new origin head parent"),
            );
            insert_parent(db, table, parent);
        }
        "authority_bootstrap_challenge_origin_bindings" => {
            let parent_table = "authority_bootstrap_challenges";
            let pc = columns_for(db, parent_table);
            let mut parent = rows(db, parent_table)
                .into_iter()
                .find(|candidate| {
                    get(&pc, candidate, "challenge_id") == get(columns, source, "challenge_id")
                })
                .unwrap();
            set(
                &pc,
                &mut parent,
                "challenge_id",
                Value::Text(FRESH_CHALLENGE.into()),
            );
            insert_parent(db, parent_table, parent);
            set(
                columns,
                &mut row,
                "challenge_id",
                Value::Text(FRESH_CHALLENGE.into()),
            );
        }
        "authority_target_bootstrap_key_pins" => {
            set(columns, &mut row, "revision", bytes_number(9));
            fresh_key(columns, &mut row, "new target key");
        }
        "authority_target_bootstrap_key_heads" => {
            set(
                columns,
                &mut row,
                "target_id",
                Value::Text(FRESH_TARGET.into()),
            );
            set(columns, &mut row, "revision", bytes_number(1));
            let table = "authority_target_bootstrap_key_pins";
            let pc = columns_for(db, table);
            let mut parent = parent_for_scope(db, table, columns, source);
            set(
                &pc,
                &mut parent,
                "target_id",
                Value::Text(FRESH_TARGET.into()),
            );
            set(&pc, &mut parent, "revision", bytes_number(1));
            fresh_key(&pc, &mut parent, "new target head parent");
            insert_parent(db, table, parent);
        }
        "authority_target_bootstrap_key_revocations" => {
            set(columns, &mut row, "revision", bytes_number(2))
        }
        "authority_target_bootstrap_challenges" => {
            set(
                columns,
                &mut row,
                "challenge_id",
                Value::Text(FRESH_CHALLENGE.into()),
            );
            set(
                columns,
                &mut row,
                "manifest_id",
                Value::Text(f.spare_manifest_id.clone()),
            );
            set(
                columns,
                &mut row,
                "manifest_hash",
                Value::Blob(f.spare_manifest_hash.clone()),
            );
            set(
                columns,
                &mut row,
                "challenge_hash",
                digest("new target challenge"),
            );
        }
        "authority_target_bootstrap_confirmations" => {
            set(
                columns,
                &mut row,
                "confirmation_hash",
                digest("new target confirmation"),
            );
            set(
                columns,
                &mut row,
                "challenge_id",
                Value::Text(f.spare_target_challenge.clone()),
            );
            set(
                columns,
                &mut row,
                "challenge_hash",
                Value::Blob(f.spare_target_challenge_hash.clone()),
            );
        }
        "authority_target_bootstrap_confirmation_heads" => set(
            columns,
            &mut row,
            "target_id",
            Value::Text(FRESH_TARGET.into()),
        ),
        _ => panic!("unexpected schema16 table"),
    }
    row
}
// Disambiguate the columns helper from the borrowed columns argument.
fn columns_for(db: &Connection, table: &str) -> Columns {
    columns(db, table)
}
fn fresh_key(columns: &Columns, row: &mut [Value], label: &str) {
    let key = SigningKey::from_bytes(&[98; 32]).verifying_key().to_bytes();
    set(columns, row, "public_key", Value::Blob(key.to_vec()));
    set(
        columns,
        row,
        "key_fingerprint",
        Value::Blob(blob(&hash_bytes(&key))),
    );
    set(columns, row, "pin_hash", digest(label));
}

fn forward(
    db: &Connection,
    table: &str,
    columns: &Columns,
    identity: &[Value],
    minimum: u64,
) -> Vec<Value> {
    let mut row = identity.to_vec();
    let revision = number(get(columns, &row, "revision")).max(minimum) + 1;
    set(columns, &mut row, "revision", bytes_number(revision));
    let parent_table = match table {
        "authority_bootstrap_approval_origin_heads" => {
            Some("authority_bootstrap_approval_origin_pins")
        }
        "authority_target_bootstrap_key_heads" => Some("authority_target_bootstrap_key_pins"),
        _ => None,
    };
    if let Some(parent_table) = parent_table {
        let pc = columns_for(db, parent_table);
        let mut parent = parent_for_scope(db, parent_table, columns, identity);
        set(&pc, &mut parent, "revision", bytes_number(revision));
        set(
            &pc,
            &mut parent,
            "pin_hash",
            digest("forward projection parent"),
        );
        if parent_table == "authority_target_bootstrap_key_pins" {
            fresh_key(&pc, &mut parent, "forward target key parent");
        }
        insert_parent(db, parent_table, parent);
    } else {
        set(
            columns,
            &mut row,
            "accepted_epoch",
            bytes_number(number(get(columns, identity, "accepted_epoch")) + 1),
        );
        let Value::Integer(at) = get(columns, identity, "observed_at") else {
            panic!("observation integer")
        };
        set(columns, &mut row, "observed_at", Value::Integer(at + 1));
    }
    row
}
fn update_sql(table: &str, columns: &Columns, replace: bool) -> String {
    let fields = std::iter::once("rowid")
        .chain(columns.iter().map(|(name, _)| name.as_str()))
        .enumerate()
        .map(|(index, name)| format!("{name}=?{}", index + 1))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "UPDATE {}{table} SET {fields} WHERE rowid=?{}",
        if replace { "OR REPLACE " } else { "" },
        columns.len() + 2
    )
}
fn positive(db: &Connection, sql: &str, values: Vec<Value>, before: &Snapshot, label: &str) {
    db.execute_batch("SAVEPOINT positive_control").unwrap();
    assert_eq!(
        db.execute(sql, params_from_iter(values)).expect(label),
        1,
        "{label}"
    );
    db.execute_batch("ROLLBACK TO positive_control; RELEASE positive_control")
        .unwrap();
    assert_eq!(&snapshot(db), before, "{label}: positive control rollback");
}
fn rejected(
    db: &Connection,
    sql: &str,
    values: Vec<Value>,
    message: &str,
    before: &Snapshot,
    label: &str,
) {
    let error = db.execute(sql, params_from_iter(values)).expect_err(label);
    assert!(
        matches!(&error,rusqlite::Error::SqliteFailure(code,Some(text)) if code.extended_code==1811 && text==message),
        "{label}: {error:?}"
    );
    assert_eq!(
        &snapshot(db),
        before,
        "{label}: changed original authority rows/rowids/types/bytes"
    );
}
fn unique_keys(db: &Connection, table: &str) -> Vec<Vec<String>> {
    let indexes: Vec<String> = db
        .prepare(&format!("PRAGMA index_list({table})"))
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, bool>(2)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .into_iter()
        .filter_map(|(name, unique)| unique.then_some(name))
        .collect();
    indexes
        .into_iter()
        .map(|index| {
            db.prepare(&format!("PRAGMA index_info({index})"))
                .unwrap()
                .query_map([], |row| row.get(2))
                .unwrap()
                .collect::<rusqlite::Result<Vec<String>>>()
                .unwrap()
        })
        .collect()
}

#[test]
fn all_nine_schema16_tables_preserve_real_history_across_sqlite_identity_replacements() {
    let fixture = seed();
    let db = Connection::open(&fixture.path).unwrap();
    let original = snapshot(&db);
    let original_schema = schema(&db);
    let mut rejected_count = 0;
    let mut controls = 0;
    for foreign_keys in [false, true] {
        for recursive in [false, true] {
            db.pragma_update(None, "foreign_keys", foreign_keys)
                .unwrap();
            db.pragma_update(None, "recursive_triggers", recursive)
                .unwrap();
            assert_eq!(
                db.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, bool>(0))
                    .unwrap(),
                foreign_keys
            );
            assert_eq!(
                db.query_row("PRAGMA recursive_triggers", [], |row| row.get::<_, bool>(0))
                    .unwrap(),
                recursive
            );
            for (table, noun, mutable) in TABLES {
                let columns = columns(&db, table);
                let saved = rows(&db, table);
                assert!(saved.len() >= 2, "{table}: two real rows required");
                let source = &saved[0];
                let victim = &saved[1];
                assert_ne!(source[0], victim[0]);
                let label = format!("{table}: FK={foreign_keys}, recursive={recursive}");
                rejected(
                    &db,
                    &format!("DELETE FROM {table} WHERE rowid=?"),
                    vec![victim[0].clone()],
                    &format!("retained {noun}"),
                    &original,
                    &format!("{label}: DELETE"),
                );
                rejected_count += 1;

                db.execute_batch("SAVEPOINT replacement_case").unwrap();
                let candidate = fresh_candidate(&fixture, &db, table, &columns, source);
                let prepared = snapshot(&db);
                let insert = insert_sql(table, &columns);
                positive(
                    &db,
                    &insert,
                    candidate.clone(),
                    &prepared,
                    &format!("{label}: unused identities/FKs SQL positive control"),
                );
                controls += 1;
                let mut attack = candidate.clone();
                attack[0] = victim[0].clone();
                rejected(
                    &db,
                    &insert,
                    attack,
                    &format!("retained {noun} identity"),
                    &prepared,
                    &format!("{label}: INSERT OR REPLACE hidden rowid"),
                );
                rejected_count += 1;
                for keys in unique_keys(&db, table) {
                    let mut attack = candidate.clone();
                    for key in &keys {
                        set(
                            &columns,
                            &mut attack,
                            key,
                            get(&columns, victim, key).clone(),
                        );
                    }
                    rejected(
                        &db,
                        &insert,
                        attack,
                        &format!("retained {noun} identity"),
                        &prepared,
                        &format!("{label}: INSERT OR REPLACE unique {keys:?}"),
                    );
                    rejected_count += 1;
                }
                db.execute_batch("ROLLBACK TO replacement_case; RELEASE replacement_case")
                    .unwrap();
                assert_eq!(snapshot(&db), original);
                assert_eq!(schema(&db), original_schema);

                // Rowid and PK attacks against mutable heads include an otherwise
                // valid forward transition, so a <= check or missing FK cannot mask
                // the immutable identity condition. Controls are SQL-only.
                db.execute_batch("SAVEPOINT update_case").unwrap();
                let advanced = if mutable.is_some() {
                    forward(
                        &db,
                        table,
                        &columns,
                        source,
                        number(get(&columns, source, "revision")),
                    )
                } else {
                    source.clone()
                };
                let prepared = snapshot(&db);
                let message = mutable
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("immutable {noun}"));
                if mutable.is_some() {
                    let mut values = advanced.clone();
                    values.push(source[0].clone());
                    positive(
                        &db,
                        &update_sql(table, &columns, false),
                        values,
                        &prepared,
                        &format!("{label}: forward UPDATE SQL positive control"),
                    );
                    controls += 1;
                }
                for replace in [false, true] {
                    let mut attack = advanced.clone();
                    attack[0] = victim[0].clone();
                    attack.push(source[0].clone());
                    rejected(
                        &db,
                        &update_sql(table, &columns, replace),
                        attack,
                        &message,
                        &prepared,
                        &format!("{label}: UPDATE replace={replace} hidden rowid victim"),
                    );
                    rejected_count += 1;
                }
                db.execute_batch("ROLLBACK TO update_case; RELEASE update_case")
                    .unwrap();
                assert_eq!(snapshot(&db), original);

                db.execute_batch("SAVEPOINT pk_case").unwrap();
                let mut attack = if mutable.is_some() {
                    forward(
                        &db,
                        table,
                        &columns,
                        victim,
                        number(get(&columns, source, "revision")),
                    )
                } else {
                    victim.clone()
                };
                let prepared = snapshot(&db);
                if mutable.is_some() {
                    let mut values = attack.clone();
                    values.push(victim[0].clone());
                    positive(
                        &db,
                        &update_sql(table, &columns, false),
                        values,
                        &prepared,
                        &format!("{label}: victim-scope forward SQL positive control"),
                    );
                    controls += 1;
                }
                attack[0] = source[0].clone();
                attack.push(source[0].clone());
                rejected(
                    &db,
                    &update_sql(table, &columns, true),
                    attack,
                    &message,
                    &prepared,
                    &format!("{label}: UPDATE OR REPLACE primary-key victim"),
                );
                rejected_count += 1;
                db.execute_batch("ROLLBACK TO pk_case; RELEASE pk_case")
                    .unwrap();
                assert_eq!(snapshot(&db), original);

                if let Some(message) = mutable {
                    let revision = number(get(&columns, source, "revision"));
                    assert!(revision > 0);
                    rejected(
                        &db,
                        &format!("UPDATE {table} SET revision=? WHERE rowid=?"),
                        vec![bytes_number((revision - 1).max(1)), source[0].clone()],
                        message,
                        &original,
                        &format!("{label}: head revision rollback or nonadvance"),
                    );
                    rejected_count += 1;
                }
                assert_eq!(schema(&db), original_schema);
                assert_eq!(snapshot(&db), original);
                drop(AuthorityStore::open(&fixture.path).unwrap());
            }
        }
    }
    assert_eq!(rejected_count, 256);
    assert_eq!(controls, 60);
    eprintln!(
        "schema16 guard matrix: {rejected_count} rejected identity/destructive mutations, {controls} rolled-back structural SQL positive controls"
    );
}
